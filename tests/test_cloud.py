"""Offline adapter checks. They do not establish that AWS IAM or SEC access works."""

import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from cloud.handler import collect, configuration, handler, put_new
from heltemes.sec import SecClient
from scripts.package_lambda import package


class S3Error(Exception):
    def __init__(self, code):
        self.response = {"Error": {"Code": code}}


class FakeS3:
    def __init__(self):
        self.objects = {}
        self.calls = []

    def put_object(self, **kwargs):
        self.calls.append(kwargs)
        key = kwargs["Key"]
        if key in self.objects:
            raise S3Error("PreconditionFailed")
        self.objects[key] = kwargs["Body"]
        return {"ETag": "fake"}


class FakeSec:
    submissions_url = staticmethod(SecClient.submissions_url)
    document_url = staticmethod(SecClient.document_url)

    def __init__(self, fail_document=False, fail_submissions=False, no_match=False):
        self.fail_document = fail_document
        self.fail_submissions = fail_submissions
        self.no_match = no_match

    def submissions(self, cik):
        if self.fail_submissions:
            raise TimeoutError("Simulated SEC timeout")
        payload = {
            "cik": cik,
            "name": "Synthetic Cloud Test Company",
            "filings": {"recent": {
                "accessionNumber": ["0000320193-26-000001"],
                "filingDate": ["2026-08-01"],
                "acceptanceDateTime": ["2026-08-01T12:00:00Z"],
                "form": ["8-K" if self.no_match else "10-Q"],
                "reportDate": ["2026-06-30"],
                "primaryDocument": ["synthetic.htm"],
            }},
        }
        return payload, json.dumps(payload).encode()

    def primary_document(self, cik, accession, filename):
        if self.fail_document:
            raise TimeoutError("Simulated document timeout")
        return b"<html>SYNTHETIC TEST ONLY</html>"


class CloudTests(unittest.TestCase):
    def setUp(self):
        # A parse-valid address for configuration tests; no email or requests are sent.
        self.env = {"EVIDENCE_BUCKET": "heltemes-offline-test", "SEC_CIK": "320193", "SEC_USER_AGENT": "HELTEMES Offline Test tester@heltemescapital.dev"}
        self.config = configuration(self.env)
        self.s3 = FakeS3()

    def manifest(self, result):
        return json.loads(self.s3.objects[result["manifest_key"]])

    def test_success_preserves_raw_bytes_and_hash(self):
        result = collect(self.config, self.s3, FakeSec())
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["filings_saved"], 1)
        artifact = self.manifest(result)["filings"][0]["artifact"]
        self.assertEqual(hashlib.sha256(self.s3.objects[artifact["object_key"]]).hexdigest(), artifact["sha256"])
        for call in self.s3.calls:
            self.assertEqual(call["IfNoneMatch"], "*")
            self.assertEqual(call["ServerSideEncryption"], "AES256")

    def test_repeated_run_deduplicates_blobs_but_keeps_each_manifest(self):
        first = collect(self.config, self.s3, FakeSec())
        saved = dict(self.s3.objects)
        second = collect(self.config, self.s3, FakeSec())
        self.assertNotEqual(first["manifest_key"], second["manifest_key"])
        self.assertEqual(len(self.s3.objects), len(saved) + 1)
        self.assertFalse(self.manifest(second)["filings"][0]["artifact"]["object_created"])
        self.assertTrue(all(self.s3.objects[key] == body for key, body in saved.items()))

    def test_document_failure_is_partial_with_preserved_submissions(self):
        result = collect(self.config, self.s3, FakeSec(fail_document=True))
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["filings_saved"], 0)
        self.assertIn("submissions", self.manifest(result))
        self.assertEqual(self.manifest(result)["errors"][0]["type"], "TimeoutError")

    def test_submissions_failure_still_records_failed_run(self):
        result = collect(self.config, self.s3, FakeSec(fail_submissions=True))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(len(self.s3.objects), 1)

    def test_low_remaining_budget_defers_document_and_preserves_partial_manifest(self):
        sec = FakeSec()
        # Enough at start; after the submissions response, reserve the rest for
        # persistence instead of beginning another request/retry sequence.
        budgets = iter([180_000, 80_000, 80_000])
        with patch.object(sec, "primary_document", wraps=sec.primary_document) as document:
            result = collect(self.config, self.s3, sec, remaining_ms=lambda: next(budgets))
            document.assert_not_called()
        self.assertEqual(result["status"], "partial")
        self.assertEqual(self.manifest(result)["filings"][0]["status"], "deferred")
        self.assertEqual(self.manifest(result)["errors"][0]["type"], "CollectionBudgetExceeded")

    def test_lambda_low_budget_context_stops_before_request_and_records_failure(self):
        sec = FakeSec()
        modules = {
            "boto3": SimpleNamespace(client=lambda *args, **kwargs: self.s3),
            "botocore": SimpleNamespace(),
            "botocore.config": SimpleNamespace(Config=lambda **kwargs: kwargs),
        }
        context = SimpleNamespace(get_remaining_time_in_millis=lambda: 30_000)
        with patch.dict("sys.modules", modules), patch.dict("os.environ", self.env, clear=True), patch("cloud.handler.SecClient", return_value=sec), patch.object(sec, "submissions", wraps=sec.submissions) as submissions:
            with self.assertRaisesRegex(RuntimeError, "Collection failed"):
                handler({}, context)
            submissions.assert_not_called()
        manifests = [json.loads(body) for key, body in self.s3.objects.items() if "/runs/" in key]
        self.assertEqual(len(manifests), 1)
        self.assertEqual(manifests[0]["errors"][0]["type"], "CollectionBudgetExceeded")

    def test_no_matching_filings_is_explicit(self):
        result = collect(self.config, self.s3, FakeSec(no_match=True))
        self.assertEqual(result["status"], "complete")
        self.assertTrue(result["no_matching_filings"])

    def test_access_denial_not_mistaken_for_duplicate(self):
        with patch.object(self.s3, "put_object", side_effect=S3Error("AccessDenied")):
            with self.assertRaises(S3Error):
                put_new(self.s3, "bucket", "key", b"evidence", "text/plain")

    def test_manifest_failure_cannot_return_success(self):
        original = self.s3.put_object

        def fail_manifest(**kwargs):
            if "/runs/" in kwargs["Key"]:
                raise S3Error("ServiceUnavailable")
            return original(**kwargs)

        with patch.object(self.s3, "put_object", side_effect=fail_manifest):
            with self.assertRaises(S3Error):
                collect(self.config, self.s3, FakeSec())

    def test_configuration_bounds_and_placeholder_contact(self):
        for key, bad in [("SEC_FILING_LIMIT", "0"), ("SEC_FILING_LIMIT", "4"), ("SEC_CIK", "0"), ("SEC_FORMS", "*"), ("EVIDENCE_BUCKET", "https://attacker.invalid"), ("SEC_USER_AGENT", "Project you@example.com")]:
            with self.subTest(key=key, value=bad), self.assertRaises(ValueError):
                configuration({**self.env, key: bad})

    def test_lambda_raises_after_recording_partial_result_for_error_alarm(self):
        modules = {
            "boto3": SimpleNamespace(client=lambda *args, **kwargs: self.s3),
            "botocore": SimpleNamespace(),
            "botocore.config": SimpleNamespace(Config=lambda **kwargs: kwargs),
        }
        with patch.dict("sys.modules", modules), patch.dict("os.environ", self.env, clear=True), patch("cloud.handler.SecClient", return_value=FakeSec(fail_document=True)):
            with self.assertRaisesRegex(RuntimeError, "Collection partial"):
                handler({}, None)
        manifests = [json.loads(body) for key, body in self.s3.objects.items() if "/runs/" in key]
        self.assertEqual(len(manifests), 1)
        self.assertEqual(manifests[0]["status"], "partial")

    def test_lambda_event_cannot_override_collection_config(self):
        modules = {
            "boto3": SimpleNamespace(client=lambda *args, **kwargs: self.s3),
            "botocore": SimpleNamespace(),
            "botocore.config": SimpleNamespace(Config=lambda **kwargs: kwargs),
        }
        with patch.dict("sys.modules", modules), patch.dict("os.environ", self.env, clear=True), patch("cloud.handler.SecClient", return_value=FakeSec()):
            result = handler({"EVIDENCE_BUCKET": "attacker-bucket", "SEC_CIK": "123"}, None)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(self.manifest(result)["cik"], "0000320193")
        self.assertTrue(all(call["Bucket"] == self.env["EVIDENCE_BUCKET"] for call in self.s3.calls))

    def test_package_reproducible_and_contains_only_allowlisted_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            one = package(Path(temporary) / "one.zip").read_bytes()
            two_path = package(Path(temporary) / "two.zip")
            self.assertEqual(one, two_path.read_bytes())
            with zipfile.ZipFile(two_path) as archive:
                self.assertEqual(set(archive.namelist()), {"cloud/__init__.py", "cloud/handler.py", "heltemes/__init__.py", "heltemes/sec.py"})


if __name__ == "__main__":
    unittest.main()
