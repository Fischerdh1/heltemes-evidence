"""Bounded, read-only access to official SEC EDGAR endpoints.

No requests occur during construction. Supply your real project/contact User-Agent
before collecting. This client intentionally uses only the submissions *recent*
arrays, not historical pagination, XBRL, or an earnings calendar.
"""
from __future__ import annotations

import json
import os
import ssl
import sys
import re
import threading
import time
from datetime import datetime
from email.utils import parsedate_to_datetime
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

MAX_RESPONSE_BYTES = 10 * 1024 * 1024
_CIK = re.compile(r"[0-9]{1,10}\Z")
_ACCESSION = re.compile(r"[0-9]{10}-[0-9]{2}-[0-9]{6}\Z")
_FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,200}\Z")
_FORM = re.compile(r"[A-Z0-9][A-Z0-9 /.-]{0,19}\Z")


class SecError(RuntimeError):
    """A collection error safe to show in a local operational report."""


def validate_cik(cik: str | int) -> str:
    value = str(cik)
    if not _CIK.fullmatch(value) or int(value) == 0:
        raise ValueError("CIK must be a positive number containing 1 to 10 digits.")
    return value.zfill(10)


def validate_user_agent(user_agent: str) -> str:
    if not isinstance(user_agent, str) or not 12 <= len(user_agent) <= 240:
        raise ValueError("Set a project name and real contact email as the SEC User-Agent.")
    if any(ord(c) < 32 or ord(c) > 126 for c in user_agent):
        raise ValueError("SEC User-Agent must contain printable ASCII characters only.")
    match = re.search(r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b", user_agent)
    if not match or not user_agent[:match.start()].strip():
        raise ValueError("SEC User-Agent needs a project name followed by a real contact email.")
    domain = match.group(1).lower()
    if domain in {"example.com", "example.org", "example.net", "test.com"} or domain.endswith((".invalid", ".example", ".test", ".localhost")):
        raise ValueError("Replace the placeholder SEC contact with your own real email.")
    return user_agent


def submissions_url(cik: str | int) -> str:
    return f"https://data.sec.gov/submissions/CIK{validate_cik(cik)}.json"


def document_url(cik: str | int, accession: str, filename: str) -> str:
    normalized = validate_cik(cik)
    if not isinstance(accession, str) or not _ACCESSION.fullmatch(accession):
        raise ValueError("Invalid SEC accession number.")
    if not isinstance(filename, str) or not _FILENAME.fullmatch(filename) or ".." in filename:
        raise ValueError("Unsafe or unsupported SEC primary-document filename.")
    return f"https://www.sec.gov/Archives/edgar/data/{int(normalized)}/{accession.replace('-', '')}/{filename}"


def validate_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.port or parsed.query or parsed.fragment:
        raise ValueError("Only canonical HTTPS SEC URLs without query strings are permitted.")
    if parsed.netloc == "data.sec.gov" and re.fullmatch(r"/submissions/CIK[0-9]{10}\.json", parsed.path):
        return url
    if parsed.netloc == "www.sec.gov" and re.fullmatch(r"/Archives/edgar/data/[0-9]{1,10}/[0-9]{18}/[A-Za-z0-9][A-Za-z0-9._-]{0,200}", parsed.path) and ".." not in parsed.path:
        return url
    raise ValueError("URL is outside the supported official SEC endpoints.")


class _StrictRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl)
        if urlsplit(newurl).netloc != urlsplit(req.full_url).netloc:
            raise SecError("SEC redirected to a different host; collection stopped.")
        # Do not follow even same-host redirects automatically: each physical
        # request must remain within the explicit rate and retry budget.
        raise SecError("SEC returned a redirect; collection stopped for review.")


class _RateLimiter:
    def __init__(self):
        self.lock = threading.Lock()
        self.last = None

    def wait(self, clock, sleeper):
        with self.lock:
            now = clock()
            if self.last is not None and now - self.last < 1.0:
                sleeper(1.0 - (now - self.last))
            self.last = clock()


_SHARED_LIMITER = _RateLimiter()


def _tls_context() -> ssl.SSLContext:
    """Use verified platform trust, never bypass a broken explicit override.

    Some python.org macOS installations lack their OpenSSL CA bundle until a
    separate certificate setup step. Use the installed system PEM bundle only
    when both default paths are absent. Other platforms keep Python defaults.
    """
    file_override = os.environ.get("SSL_CERT_FILE")
    dir_override = os.environ.get("SSL_CERT_DIR")
    has_override = "SSL_CERT_FILE" in os.environ or "SSL_CERT_DIR" in os.environ
    try:
        if has_override:
            if "SSL_CERT_FILE" in os.environ and (not file_override or not os.path.isfile(file_override) or not os.access(file_override, os.R_OK)):
                raise SecError("SSL_CERT_FILE must name a readable CA certificate bundle; TLS setup stopped.")
            if "SSL_CERT_DIR" in os.environ and (not dir_override or not os.path.isdir(dir_override) or not os.access(dir_override, os.R_OK | os.X_OK)):
                raise SecError("SSL_CERT_DIR must name a readable CA certificate directory; TLS setup stopped.")
            return ssl.create_default_context(cafile=file_override, capath=dir_override)
        defaults = ssl.get_default_verify_paths()
        if sys.platform == "darwin" and not defaults.cafile and not defaults.capath:
            system_bundle = "/etc/ssl/cert.pem"
            if not os.path.isfile(system_bundle) or not os.access(system_bundle, os.R_OK):
                raise SecError("Python could not locate a trusted CA bundle. Configure SSL_CERT_FILE with a valid bundle before collecting.")
            return ssl.create_default_context(cafile=system_bundle)
        return ssl.create_default_context()
    except (ssl.SSLError, OSError) as error:
        raise SecError("Could not load the configured trusted CA certificates. Check SSL_CERT_FILE/SSL_CERT_DIR or Python's certificate setup; TLS verification remains enabled.") from error


_TLS_VERIFY_ERROR = "TLS certificate verification failed. Check Python's trusted CA bundle or SSL_CERT_FILE/SSL_CERT_DIR; certificate verification remains enabled."


class SecClient:
    """One request/second process-wide; at most three attempts per resource.

    ``opener`` and time functions are injectable for offline tests. The default
    opener rejects redirects outside the supported HTTPS host/path allowlist.
    """
    submissions_url = staticmethod(submissions_url)
    document_url = staticmethod(document_url)

    def __init__(self, user_agent: str, *, opener=None, clock=None, sleeper=None, timeout: float = 15.0):
        self.user_agent = validate_user_agent(user_agent)
        if not 1 <= timeout <= 30:
            raise ValueError("Timeout must be between 1 and 30 seconds.")
        self.timeout = timeout
        self.opener = opener if opener is not None else build_opener(_StrictRedirect(), HTTPSHandler(context=_tls_context()))
        self.clock = clock or time.monotonic
        self.sleeper = sleeper or time.sleep
        # Isolated fake clocks prevent tests from interfering with the real global limiter.
        self.limiter = _SHARED_LIMITER if clock is None else _RateLimiter()

    def _get(self, url: str) -> bytes:
        validate_url(url)
        for attempt in range(3):
            self.limiter.wait(self.clock, self.sleeper)
            request = Request(url, headers={"User-Agent": self.user_agent, "Accept": "application/json,text/html,text/plain,application/xml;q=0.8", "Accept-Encoding": "identity"})
            request_started = self.clock()
            try:
                with self.opener.open(request, timeout=self.timeout) as response:
                    final_url = response.geturl()
                    validate_url(final_url)
                    if urlsplit(final_url).netloc != urlsplit(url).netloc:
                        raise SecError("Unexpected SEC response host.")
                    if getattr(response, "status", 200) != 200:
                        raise SecError("SEC returned a non-success response.")
                    length = response.headers.get("Content-Length")
                    if length is not None:
                        try:
                            if int(length) < 0 or int(length) > MAX_RESPONSE_BYTES:
                                raise SecError("SEC response exceeds the 10 MiB limit.")
                        except ValueError as error:
                            raise SecError("Invalid SEC response length.") from error
                    chunks, total = [], 0
                    reader = getattr(response, "read1", response.read)
                    while True:
                        if self.clock() - request_started > self.timeout:
                            raise SecError("SEC response exceeded its elapsed-time budget.")
                        chunk = reader(min(65536, MAX_RESPONSE_BYTES + 1 - total))
                        if self.clock() - request_started > self.timeout:
                            raise SecError("SEC response exceeded its elapsed-time budget.")
                        if not chunk:
                            break
                        chunks.append(chunk)
                        total += len(chunk)
                        if total > MAX_RESPONSE_BYTES:
                            raise SecError("SEC response exceeds the 10 MiB limit.")
                    body = b"".join(chunks)
                    if length is not None and len(body) != int(length):
                        raise SecError("SEC response body is incomplete.")
                    if not body:
                        raise SecError("SEC returned an empty response.")
                    return body
            except HTTPError as error:
                code = error.code
                retry_after = error.headers.get("Retry-After", "") if error.headers else ""
                error.close()
                if code == 403:
                    raise SecError("SEC denied access (403). Check the real contact User-Agent and SEC access guidance; collection stopped.") from error
                if code not in {429, 500, 502, 503, 504} or attempt == 2:
                    raise SecError(f"SEC request failed with HTTP {code} after {attempt + 1} attempt(s).") from error
                delay = float(2 ** attempt)
                requested_delay = 0.0
                if retry_after.isdigit():
                    requested_delay = float(retry_after)
                elif retry_after:
                    try:
                        requested_delay = parsedate_to_datetime(retry_after).timestamp() - time.time()
                    except (ValueError, TypeError, OverflowError):
                        pass
                if requested_delay > 30.0:
                    raise SecError("SEC requested a longer cooldown; collection stopped instead of retrying early.") from error
                self.sleeper(max(delay, requested_delay))
            except ssl.SSLCertVerificationError as error:
                raise SecError(_TLS_VERIFY_ERROR) from error
            except (URLError, TimeoutError, OSError) as error:
                if isinstance(error, URLError) and isinstance(error.reason, ssl.SSLCertVerificationError):
                    raise SecError(_TLS_VERIFY_ERROR) from error
                if attempt == 2:
                    raise SecError(f"SEC connection failed after {attempt + 1} attempts ({type(error).__name__}).") from error
                self.sleeper(float(2 ** attempt))
        raise SecError("SEC request exhausted its retry budget.")

    def submissions(self, cik: str | int) -> tuple[dict, bytes]:
        normalized = validate_cik(cik)
        raw = self._get(submissions_url(normalized))
        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeDecodeError) as error:
            raise SecError("SEC submissions response was not valid JSON.") from error
        if not isinstance(payload, dict):
            raise SecError("SEC submissions response must be a JSON object.")
        if validate_cik(payload.get("cik", "")) != normalized:
            raise SecError("SEC response CIK does not match the requested company.")
        return payload, raw

    def primary_document(self, cik: str | int, accession: str, filename: str) -> bytes:
        return self._get(document_url(cik, accession, filename))


def _date(value, label: str, *, optional=False) -> str:
    if optional and value == "":
        return ""
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
        raise ValueError(f"Invalid SEC {label}.")
    datetime.strptime(value, "%Y-%m-%d")
    return value


def select_recent_filings(payload: dict, forms: list[str] | None = None, limit: int = 3) -> list[dict]:
    """Validate aligned recent arrays and select the first matching records.

    No conclusion about earnings dates or historical completeness is implied.
    Amendments retain their distinct accession numbers.
    """
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 20:
        raise ValueError("Collection limit must be an integer from 1 to 20.")
    chosen = ["10-Q", "10-K", "8-K"] if forms is None else forms
    if not isinstance(chosen, list) or not 1 <= len(chosen) <= 10 or any(not isinstance(f, str) or not _FORM.fullmatch(f) for f in chosen):
        raise ValueError("Provide 1 to 10 exact SEC form types, such as 10-Q or 10-Q/A.")
    if not isinstance(payload, dict):
        raise ValueError("SEC submissions must be an object.")
    cik = validate_cik(payload.get("cik", ""))
    company = payload.get("name")
    if not isinstance(company, str) or not company.strip() or len(company) > 250 or any(ord(c) < 32 for c in company):
        raise ValueError("SEC response has an invalid company name.")
    recent = payload.get("filings", {}).get("recent") if isinstance(payload.get("filings"), dict) else None
    keys = ("accessionNumber", "filingDate", "acceptanceDateTime", "form", "reportDate", "primaryDocument")
    if not isinstance(recent, dict) or any(not isinstance(recent.get(k), list) for k in keys):
        raise ValueError("SEC recent-filings arrays are missing or malformed.")
    lengths = {len(recent[k]) for k in keys}
    if len(lengths) != 1 or next(iter(lengths)) > 10000:
        raise ValueError("SEC recent-filings arrays have inconsistent or excessive lengths.")
    rows = []
    for i in range(len(recent["form"])):
        form = recent["form"][i]
        if not isinstance(form, str) or not _FORM.fullmatch(form):
            raise ValueError("Invalid SEC form type.")
        if form not in chosen:
            continue
        accession = recent["accessionNumber"][i]
        filename = recent["primaryDocument"][i]
        url = document_url(cik, accession, filename)
        accepted = recent["acceptanceDateTime"][i]
        if not isinstance(accepted, str) or len(accepted) > 40:
            raise ValueError("Invalid SEC acceptance time.")
        try:
            parsed = datetime.fromisoformat(accepted.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError("SEC acceptance time must include a timezone.")
        except ValueError as error:
            raise ValueError("Invalid SEC acceptance time.") from error
        rows.append({"company": company, "cik": cik, "form": form, "accession": accession,
                     "filed_at": _date(recent["filingDate"][i], "filing date"), "accepted_at": accepted,
                     "report_date": _date(recent["reportDate"][i], "report date", optional=True),
                     "primary_document": filename, "source_url": url})
        if len(rows) >= limit:
            break
    return rows
