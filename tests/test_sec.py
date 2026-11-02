import copy
import io
import json
import os
import ssl
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.request import Request

from heltemes.sec import (MAX_RESPONSE_BYTES, SecClient, SecError, _StrictRedirect, _tls_context,
                          document_url, select_recent_filings, submissions_url,
                          validate_cik, validate_url, validate_user_agent)

FIXTURE = json.loads((Path(__file__).resolve().parents[1] / "examples/demo_submissions.json").read_text())
CONTACT = "HELTEMES Tests operator@heltemes.dev"


class Clock:
    def __init__(self):
        self.now = 100.0
        self.sleeps = []
    def __call__(self):
        return self.now
    def sleep(self, delay):
        self.sleeps.append(delay)
        self.now += delay


class Response(io.BytesIO):
    def __init__(self, body=b"ok", url=None, headers=None):
        super().__init__(body)
        self.url = url or submissions_url("1")
        self.headers = headers or {}
        self.status = 200
    def geturl(self):
        return self.url


class Opener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
    def open(self, req, timeout):
        self.calls.append((req, timeout))
        value = self.responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


class SecTests(unittest.TestCase):
    def client(self, responses):
        clock, opener = Clock(), Opener(responses)
        return SecClient(CONTACT, opener=opener, clock=clock, sleeper=clock.sleep), clock, opener

    def test_macos_missing_default_roots_uses_verified_system_bundle(self):
        with patch.dict(os.environ, {}, clear=True), patch("heltemes.sec.sys.platform", "darwin"), patch("heltemes.sec.ssl.get_default_verify_paths", return_value=SimpleNamespace(cafile=None, capath=None)), patch("heltemes.sec.os.path.isfile", return_value=True), patch("heltemes.sec.os.access", return_value=True), patch("heltemes.sec.ssl.create_default_context") as create:
            self.assertIs(_tls_context(), create.return_value)
            create.assert_called_once_with(cafile="/etc/ssl/cert.pem")

    def test_existing_macos_roots_and_linux_keep_default_context(self):
        for platform, roots in [("darwin", SimpleNamespace(cafile="existing.pem", capath=None)), ("linux", SimpleNamespace(cafile=None, capath=None))]:
            with self.subTest(platform=platform), patch.dict(os.environ, {}, clear=True), patch("heltemes.sec.sys.platform", platform), patch("heltemes.sec.ssl.get_default_verify_paths", return_value=roots), patch("heltemes.sec.ssl.create_default_context") as create:
                _tls_context()
                create.assert_called_once_with()

    def test_explicit_trust_paths_are_honored_without_platform_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            cafile = Path(directory) / "ca.pem"
            cafile.write_text("fixture only; context creation is mocked")
            for overrides in [{"SSL_CERT_FILE": str(cafile)}, {"SSL_CERT_DIR": directory}, {"SSL_CERT_FILE": str(cafile), "SSL_CERT_DIR": directory}]:
                with self.subTest(overrides=list(overrides)), patch.dict(os.environ, overrides, clear=True), patch("heltemes.sec.ssl.create_default_context") as create, patch("heltemes.sec.ssl.get_default_verify_paths") as defaults:
                    _tls_context()
                    create.assert_called_once_with(cafile=overrides.get("SSL_CERT_FILE"), capath=overrides.get("SSL_CERT_DIR"))
                    defaults.assert_not_called()

    def test_invalid_explicit_trust_configuration_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            bad_bundle = Path(directory) / "bad.pem"
            bad_bundle.write_text("not a certificate")
            overrides_list = [{"SSL_CERT_FILE": ""}, {"SSL_CERT_DIR": ""}, {"SSL_CERT_FILE": str(Path(directory) / "missing.pem")}, {"SSL_CERT_FILE": directory}, {"SSL_CERT_DIR": str(bad_bundle)}, {"SSL_CERT_FILE": str(bad_bundle)}]
            for overrides in overrides_list:
                with self.subTest(overrides=list(overrides)), patch.dict(os.environ, overrides, clear=True), patch("heltemes.sec.ssl.get_default_verify_paths") as defaults:
                    with self.assertRaises(SecError):
                        _tls_context()
                    defaults.assert_not_called()

    def test_injected_opener_does_not_construct_tls_context(self):
        with patch("heltemes.sec._tls_context") as context:
            self.client([Response()])
            context.assert_not_called()

    def test_certificate_verification_failure_is_actionable_without_retry(self):
        for error in [ssl.SSLCertVerificationError(1, "test certificate error"), URLError(ssl.SSLCertVerificationError(1, "test certificate error"))]:
            client, clock, opener = self.client([error])
            with self.assertRaisesRegex(SecError, "TLS certificate verification failed") as caught:
                client._get(submissions_url("1"))
            self.assertNotIn(CONTACT, str(caught.exception))
            self.assertEqual(len(opener.calls), 1)
            self.assertEqual(clock.sleeps, [])

    def test_url_and_identifier_allowlist(self):
        self.assertEqual(validate_cik("320193"), "0000320193")
        for bad in ["0", "12345678901", " 1", "1/2", "-1", "abc"]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                validate_cik(bad)
        for url in ["http://data.sec.gov/submissions/CIK0000000001.json", "https://data.sec.gov.evil/submissions/CIK0000000001.json", "https://data.sec.gov:443/submissions/CIK0000000001.json", "https://data.sec.gov/submissions/CIK0000000001.json?x=1", "https://www.sec.gov/Archives/edgar/data/1/000000000126000001/../secret"]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_url(url)
        for name in ["../secret", "a/secret", "x%2fsecret", "x?query", "x#f", "x..htm"]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                document_url("1", "0000000001-26-000001", name)

    def test_placeholder_contact_rejected(self):
        for contact in ["", "Project me@example.com", "Project me@test.invalid", "Project no-email", "Project\r\nX: y@example.org"]:
            with self.subTest(contact=contact), self.assertRaises(ValueError):
                validate_user_agent(contact)
        self.assertEqual(validate_user_agent(CONTACT), CONTACT)

    def test_submissions_and_request_headers(self):
        raw = json.dumps(FIXTURE).encode()
        client, _, opener = self.client([Response(raw)])
        parsed, preserved = client.submissions("1")
        self.assertEqual(parsed, FIXTURE)
        self.assertEqual(preserved, raw)
        self.assertEqual(opener.calls[0][0].get_header("User-agent"), CONTACT)
        self.assertEqual(opener.calls[0][1], 15)

    def test_response_cik_must_match_request(self):
        client, _, _ = self.client([Response(json.dumps(FIXTURE).encode(), url=submissions_url("2"))])
        with self.assertRaises(SecError):
            client.submissions("2")

    def test_requests_are_spaced(self):
        client, clock, opener = self.client([Response(), Response()])
        client._get(submissions_url("1"))
        client._get(submissions_url("1"))
        self.assertEqual(len(opener.calls), 2)
        self.assertGreaterEqual(sum(clock.sleeps), 1)

    def test_429_honors_short_retry_after(self):
        client, clock, opener = self.client([HTTPError(submissions_url("1"), 429, "slow", {"Retry-After": "5"}, None), Response()])
        self.assertEqual(client._get(submissions_url("1")), b"ok")
        self.assertEqual(len(opener.calls), 2)
        self.assertEqual(clock.sleeps, [5.0])

    def test_long_retry_after_stops_instead_of_retrying_early(self):
        client, clock, opener = self.client([HTTPError(submissions_url("1"), 429, "slow", {"Retry-After": "99999"}, None)])
        with self.assertRaisesRegex(SecError, "cooldown"):
            client._get(submissions_url("1"))
        self.assertEqual(len(opener.calls), 1)
        self.assertEqual(clock.sleeps, [])

    def test_slow_response_stops_after_elapsed_budget(self):
        client, clock, opener = self.client([])
        class SlowResponse(Response):
            def read1(self, count):
                clock.now += 16
                return b"x"
        opener.responses = [SlowResponse()]
        with self.assertRaisesRegex(SecError, "elapsed-time"):
            client._get(submissions_url("1"))

    def test_403_does_not_retry(self):
        client, _, opener = self.client([HTTPError(submissions_url("1"), 403, "denied", {}, None)])
        with self.assertRaisesRegex(SecError, "403"):
            client._get(submissions_url("1"))
        self.assertEqual(len(opener.calls), 1)

    def test_500_and_transport_retry_budgets(self):
        for responses in [[HTTPError(submissions_url("1"), 500, "error", {}, None) for _ in range(3)], [URLError("offline") for _ in range(3)]]:
            client, _, opener = self.client(responses)
            with self.assertRaises(SecError):
                client._get(submissions_url("1"))
            self.assertEqual(len(opener.calls), 3)

    def test_size_empty_truncated_and_malformed_responses(self):
        for response in [Response(b"", headers={}), Response(b"short", headers={"Content-Length": "99"}), Response(b"x", headers={"Content-Length": str(MAX_RESPONSE_BYTES + 1)}), Response(b"x" * (MAX_RESPONSE_BYTES + 1))]:
            client, _, _ = self.client([response])
            with self.assertRaises(SecError):
                client._get(submissions_url("1"))
        client, _, _ = self.client([Response(b"<html>blocked</html>")])
        with self.assertRaisesRegex(SecError, "JSON"):
            client.submissions("1")

    def test_redirects_never_trigger_a_second_request(self):
        handler = _StrictRedirect()
        req = Request(submissions_url("1"))
        for url in ["https://evil.example/data", submissions_url("2")]:
            with self.subTest(url=url), self.assertRaises((ValueError, SecError)):
                handler.redirect_request(req, None, 302, "redirect", {}, url)

    def test_amendments_are_explicit_distinct_records(self):
        rows = select_recent_filings(FIXTURE, ["10-Q", "10-Q/A"], 3)
        self.assertEqual([r["form"] for r in rows], ["10-Q/A", "10-Q"])
        self.assertNotEqual(rows[0]["accession"], rows[1]["accession"])
        self.assertNotIn("10-Q/A", [r["form"] for r in select_recent_filings(FIXTURE)])

    def test_malformed_arrays_and_selected_document_rejected(self):
        bad = copy.deepcopy(FIXTURE)
        bad["filings"]["recent"]["filingDate"].pop()
        with self.assertRaisesRegex(ValueError, "inconsistent"):
            select_recent_filings(bad)
        bad = copy.deepcopy(FIXTURE)
        bad["filings"]["recent"]["primaryDocument"][0] = "../../escape"
        with self.assertRaises(ValueError):
            select_recent_filings(bad, ["10-Q/A"])
        for limit in [0, 21, True, "3"]:
            with self.assertRaises(ValueError):
                select_recent_filings(FIXTURE, limit=limit)


if __name__ == "__main__":
    unittest.main()
