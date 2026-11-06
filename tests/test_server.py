"""Integration checks for the local trust boundary and user operations."""
import json
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path
from unittest.mock import Mock, patch

from heltemes.server import DashboardServer, Handler


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.server = DashboardServer(('127.0.0.1', 0), Path(cls.temp.name) / 'data')
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.temp.cleanup()

    def req(self, path, body=None, headers=None, *, wait_for_idle=True):
        conn = HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        h = headers or {}
        if body is not None:
            h = {'Content-Type':'application/json','X-Heltemes-Token':self.server.token, **h}
        conn.request('GET' if body is None else 'POST', path, None if body is None else json.dumps(body), h)
        r = conn.getresponse()
        result = r.status, dict(r.getheaders()), r.read()
        conn.close()
        if wait_for_idle:
            # A complete response can arrive before do_POST's finally releases
            # its operation lock. Sequential tests wait for that boundary.
            acquired = self.server.operation_lock.acquire(timeout=5)
            self.assertTrue(acquired, 'The previous dashboard operation did not finish.')
            self.server.operation_lock.release()
        return result

    def test_local_health_and_response_headers(self):
        status, headers, body = self.req('/api/health')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['scope'], 'local')
        self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')
        self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
        self.assertNotIn('Access-Control-Allow-Origin', headers)

    def test_host_origin_and_cross_site_requests_denied(self):
        for h in ({'Host':'attacker.invalid'}, {'Origin':'https://attacker.invalid'}, {'Sec-Fetch-Site':'cross-site'}):
            self.assertEqual(self.req('/api/state', headers=h)[0], 403)

    def test_state_changes_require_token_and_json(self):
        self.assertEqual(self.req('/api/demo', {}, {'X-Heltemes-Token':'wrong'})[0], 403)
        self.assertEqual(self.req('/api/demo', {}, {'Content-Type':'text/plain'})[0], 415)
        self.assertEqual(self.req('/api/demo', [1,2])[0], 400)

    def test_static_paths_do_not_expose_local_files(self):
        for path in ('/.env', '/../heltemes/core.py', '/data/data.sqlite3', '/%2e%2e/server.py'):
            self.assertEqual(self.req(path)[0], 404)

    def test_demo_inspection_download_and_integrity(self):
        self.assertEqual(self.req('/api/demo', {})[0], 200)
        state = json.loads(self.req('/api/state')[2])
        filing = state['filings'][0]
        self.assertEqual(filing['mode'], 'demo')
        self.assertEqual(self.req('/api/filings/'+str(filing['id']))[0], 200)
        status, headers, body = self.req('/api/document/'+str(filing['id']))
        self.assertEqual(status, 200)
        self.assertTrue(body)
        self.assertEqual(headers['Content-Type'], 'application/octet-stream')
        self.assertIn('attachment', headers['Content-Disposition'])
        result = json.loads(self.req('/api/verify', {})[2])
        self.assertTrue(result['ok'])
        self.assertGreater(result['checked'], 0)

    def test_corrupted_document_is_not_delivered_as_valid_evidence(self):
        self.server.repo.seed_demo()
        filing=self.server.repo.list_filings()[0]
        path=self.server.data_dir/filing['document_path']
        original=path.read_bytes()
        path.chmod(0o600)  # Same-account tampering can override this accident-prevention control.
        try:
            path.write_bytes(b'changed evidence')
            self.assertEqual(self.req('/api/document/'+str(filing['id']))[0],409)
        finally:
            path.write_bytes(original)
            path.chmod(0o400)

    def test_live_collection_requires_contact_and_valid_inputs(self):
        with patch.dict('os.environ', {}, clear=True):
            self.assertEqual(self.req('/api/collect', {'cik':'320193','forms':['10-Q'],'limit':1})[0], 409)
        for body in ({'cik':'https://evil.test'}, {'cik':'320193','limit':100}, {'cik':'320193','forms':['bad']}, {'cik':'320193','limit':True}):
            self.assertEqual(self.req('/api/collect', body)[0], 400)

    def test_busy_operation_rejected(self):
        with self.server.operation_lock:
            self.assertEqual(self.req('/api/verify', {}, wait_for_idle=False)[0], 409)

    def test_sequential_requests_wait_for_handler_lock_release_after_response(self):
        written, waiting, release, finished = (threading.Event() for _ in range(4))
        results, errors = [], []
        original_send, original_lock = Handler.send_data, self.server.operation_lock
        observed_lock = Mock(wraps=original_lock)

        def acquire(*args, **kwargs):
            if kwargs.get('timeout') == 5:
                waiting.set()
            return original_lock.acquire(*args, **kwargs)

        def delayed_send(handler, status, body, *args, **kwargs):
            original_send(handler, status, body, *args, **kwargs)
            if status == 409 and isinstance(body, dict) and body.get('error', '').startswith('Live collection needs'):
                written.set()
                if not release.wait(5):
                    errors.append('Handler release deadline exceeded.')

        def collect():
            try:
                results.append(self.req('/api/collect', {'cik': '320193', 'forms': ['10-Q'], 'limit': 1}))
            except BaseException as error:
                errors.append(error)
            finally:
                finished.set()

        observed_lock.acquire.side_effect = acquire
        thread = threading.Thread(target=collect, daemon=True)
        with patch.dict('os.environ', {}, clear=True), patch.object(Handler, 'send_data', delayed_send), \
             patch.object(self.server, 'operation_lock', observed_lock):
            try:
                thread.start()
                self.assertTrue(written.wait(2), 'The handler did not send its response.')
                self.assertTrue(waiting.wait(2), 'The request helper did not reach the completion boundary.')
                self.assertTrue(original_lock.locked())
                self.assertFalse(finished.is_set(), 'Reading the response incorrectly finished the sequential request.')
                release.set()
                self.assertTrue(finished.wait(2), 'The request did not finish after the handler was released.')
                self.assertEqual(errors, [])
                self.assertEqual(results[0][0], 409)
                self.assertEqual(self.req('/api/collect', {'cik': 'https://evil.test'})[0], 400)
            finally:
                release.set()
                thread.join(timeout=5)
        self.assertFalse(thread.is_alive(), 'The bounded test client did not finish.')

    def test_non_loopback_binding_refused(self):
        with self.assertRaises(ValueError):
            DashboardServer(('0.0.0.0', 0), Path(self.temp.name)/'unsafe')


if __name__ == '__main__':
    unittest.main()
