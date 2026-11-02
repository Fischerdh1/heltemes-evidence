"""Single-user loopback dashboard. It is deliberately not a public web server."""
from __future__ import annotations

import json
import hashlib
import os
import re
import secrets
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .core import Repository
from . import __version__
from .protection import repository_lock, verify_protection, default_trust_dir
from .config import configured, user_agent

WEB = Path(__file__).parent / "web"
MAX_BODY = 16_384
CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, data_dir):
        from .local_accounts import require_role
        require_role(data_dir, "collector")
        if address[0] not in ("127.0.0.1", "localhost"):
            raise ValueError("The dashboard supports loopback access only.")
        self.repo = Repository(Path(data_dir))
        self.data_dir = Path(data_dir).resolve()
        self.token = secrets.token_urlsafe(32)
        self.operation_lock = threading.Lock()
        self.last_verify = None
        super().__init__(address, Handler)

    @property
    def hosts(self):
        return {f"127.0.0.1:{self.server_port}", f"localhost:{self.server_port}"}


class Handler(BaseHTTPRequestHandler):
    server: DashboardServer

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, fmt, *args):
        # Omit query strings and headers, which can contain user data.
        print(f"dashboard {self.command} {urlsplit(self.path).path} {args[1] if len(args)>1 else ''}", flush=True)

    def send_data(self, status, body, content_type="application/json; charset=utf-8", attachment=None, checkpoint=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Referrer-Policy", "no-referrer")
        if attachment:
            self.send_header("Content-Disposition", f'attachment; filename="{attachment}"')
        if checkpoint:
            self.send_header("X-Heltemes-Checkpoint", checkpoint)
        self.end_headers()
        self.wfile.write(body)

    def valid_host(self):
        if self.headers.get("Host", "") not in self.server.hosts:
            self.send_data(403, {"error": "Use the local dashboard address."})
            return False
        origin = self.headers.get("Origin")
        if origin and origin not in {f"http://{host}" for host in self.server.hosts}:
            self.send_data(403, {"error": "Cross-origin access is disabled."})
            return False
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            self.send_data(403, {"error": "Cross-site access is disabled."})
            return False
        return True

    def do_GET(self):
        if not self.valid_host():
            return
        path = urlsplit(self.path).path
        query = parse_qs(urlsplit(self.path).query)
        try:
            if path == "/api/session":
                self.send_data(200, {"token": self.server.token})
            elif path == "/api/health":
                self.send_data(200, {"status": "ok", "version": __version__, "scope": "local", "data_dir": str(self.server.data_dir)})
            elif path == "/api/state":
                state = self.server.repo.dashboard()
                state["integrity"] = self.server.last_verify
                state["runtime"] = {"mode": "local", "sec_configured": configured(self.server.data_dir), "cloud_deployed": False}
                self.send_data(200, state)
            elif path == "/api/filings":
                self.send_data(200, self.server.repo.list_filings(q=query.get("q", [""])[0][:200], form=query.get("form", [""])[0][:20], mode=query.get("mode", ["all"])[0]))
            elif path.startswith("/api/filings/"):
                filing = self.server.repo.get_filing(path.rsplit("/", 1)[1])
                self.send_data(200 if filing else 404, filing or {"error": "Filing not found."})
            elif path.startswith("/api/document/"):
                with repository_lock(self.server.data_dir):
                    self.download(path.rsplit("/", 1)[1])
            elif path == "/api/protection/receipt":
                with repository_lock(self.server.data_dir):
                    protection = verify_protection(self.server.data_dir)
                    if not protection["ok"] or protection["status"] == "unconfigured":
                        self.send_data(409, {"error": "A valid signed checkpoint is required before exporting its public trust receipt."})
                        return
                    receipt = (default_trust_dir(self.server.data_dir) / "anchor.json").read_bytes()
                    self.send_data(200, receipt, "application/json", "heltemes-trust-receipt.json")
            elif path == "/api/lessons":
                self.send_data(200, (WEB / "lessons.json").read_bytes())
            elif path in ("/", "/index.html", "/app.js", "/styles.css"):
                name = "index.html" if path == "/" else path[1:]
                types = {"index.html": "text/html; charset=utf-8", "app.js": "text/javascript; charset=utf-8", "styles.css": "text/css; charset=utf-8"}
                self.send_data(200, (WEB / name).read_bytes(), types[name])
            else:
                self.send_data(404, {"error": "Not found."})
        except (ValueError, OSError) as exc:
            self.send_data(400, {"error": str(exc)[:500]})
        except Exception:
            self.send_data(500, {"error": "The request failed. Check the local terminal for diagnostics."})
            import traceback
            traceback.print_exc()

    def download(self, filing_id):
        filing = self.server.repo.get_filing(filing_id)
        if not filing:
            self.send_data(404, {"error": "Filing not found."})
            return
        relative = filing.get("document_path") or filing.get("raw_path")
        if not relative:
            self.send_data(404, {"error": "No preserved document is available."})
            return
        original_path = self.server.data_dir / relative
        path = original_path.resolve()
        has_symlink = any(part.is_symlink() for part in [original_path, *original_path.parents] if part != self.server.data_dir and part.is_relative_to(self.server.data_dir))
        if has_symlink or not path.is_relative_to(self.server.data_dir) or not path.is_file():
            self.send_data(404, {"error": "Preserved file is unavailable."})
            return
        content = path.read_bytes()
        # Capture first, verify second, and never reread a writable reference after
        # verification. The response bytes must match THIS captured signed row.
        verified = self.server.repo.verify_integrity()
        protection = verify_protection(self.server.data_dir, include_filing_hashes=True)
        if not verified["ok"] or not protection["ok"]:
            self.send_data(409, {"error": "Evidence verification failed. Download blocked; inspect Security & recovery."})
            return
        sealed_hash = protection.get("sealed_filing_hashes", {}).get(str(filing["id"]))
        if sealed_hash:
            captured = {key: value for key, value in filing.items() if key != "observations"}
            row_hash = hashlib.sha256(json.dumps(captured, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()).hexdigest()
            if row_hash != sealed_hash:
                self.send_data(409, {"error": "Captured filing differs from its signed reference. Download blocked."})
                return
        expected = filing.get("document_sha256") if filing.get("document_path") else filing.get("sha256")
        if not expected or hashlib.sha256(content).hexdigest() != expected:
            self.send_data(409, {"error": "Evidence checksum mismatch. Run integrity verification before using this file."})
            return
        # Never execute issuer HTML inside the trusted dashboard origin.
        state = "sealed" if sealed_hash else ("unconfigured" if protection["status"] == "unconfigured" else "pending")
        self.send_data(200, content, "application/octet-stream", "preserved-evidence.bin", checkpoint=state)

    def do_POST(self):
        if not self.valid_host():
            return
        token = self.headers.get("X-Heltemes-Token", "")
        if not secrets.compare_digest(token, self.server.token):
            self.send_data(403, {"error": "Refresh the dashboard before making changes."})
            return
        if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
            self.send_data(415, {"error": "JSON body required."})
            return
        if self.headers.get("Transfer-Encoding"):
            self.send_data(400, {"error": "Transfer encoding is not supported."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_BODY:
                raise ValueError("Request body is missing or too large.")
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise ValueError("JSON object required.")
        except (ValueError, json.JSONDecodeError) as exc:
            self.send_data(400, {"error": str(exc)})
            return
        if not self.server.operation_lock.acquire(blocking=False):
            self.send_data(409, {"error": "Another operation is running. Please wait."})
            return
        try:
            path = urlsplit(self.path).path
            if path == "/api/demo":
                self.server.last_verify = None
                result = self.server.repo.seed_demo()
                self.send_data(200, {"ok": True, "result": result})
            elif path == "/api/collect":
                cik = str(payload.get("cik", "")).strip()
                if not re.fullmatch(r"\d{1,10}", cik):
                    raise ValueError("Enter a valid SEC CIK: 1–10 digits.")
                limit = payload.get("limit", 3)
                if type(limit) is not int or not 1 <= limit <= 10:
                    raise ValueError("Choose between 1 and 10 filings.")
                forms = payload.get("forms", ["10-Q"])
                allowed = {"10-Q", "10-K", "8-K", "10-Q/A", "10-K/A", "8-K/A", "20-F", "6-K"}
                if not isinstance(forms, list) or not forms or any(not isinstance(f, str) or f not in allowed for f in forms):
                    raise ValueError("Choose supported filing forms.")
                contact = user_agent(self.server.data_dir)
                if not contact:
                    self.send_data(409, {"error": "Live collection needs your SEC contact email. Run Configure SEC.command or python3 -m heltemes configure, then refresh. Sample mode is ready now."})
                    return
                self.server.last_verify = None
                result = self.server.repo.collect(cik, contact, forms=forms, limit=limit)
                self.send_data(200, {"ok": result.get("status") == "success", "result": result})
            elif path == "/api/verify":
                self.server.last_verify = self.server.repo.verify_integrity()
                self.send_data(200, self.server.last_verify)
            elif path == "/api/backup":
                stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
                dest = self.server.data_dir.parent / "backups" / f"heltemes-{stamp}.zip"
                dest.parent.mkdir(parents=True, exist_ok=True)
                result = self.server.repo.backup(dest)
                self.send_data(200, {"ok": True, "path": str(result)})
            else:
                self.send_data(404, {"error": "Not found."})
        except (ValueError, OSError) as exc:
            self.send_data(400, {"error": str(exc)[:500]})
        except Exception as exc:
            self.send_data(500, {"error": f"Operation failed: {str(exc)[:350]}"})
        finally:
            self.server.operation_lock.release()


def serve(data_dir, port=8765):
    server = DashboardServer(("127.0.0.1", port), data_dir)
    print(f"HELTEMES Evidence is running at http://127.0.0.1:{server.server_port}", flush=True)
    print("Local access only. Press Ctrl+C to stop.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
