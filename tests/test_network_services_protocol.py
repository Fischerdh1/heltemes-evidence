"""DNS wire validation and disposable TLS loopback checks; no namespace changes."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import struct
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch

from scripts import network_services_protocol as protocol


class DNSWireTests(unittest.TestCase):
    def test_exact_a_reply_and_nxdomain_round_trip(self):
        for name in protocol.DNS_NAMES:
            query = protocol.make_dns_query(name, 3210)
            parsed = protocol.parse_dns_query(query)
            self.assertEqual(parsed["transaction_id"], 3210)
            self.assertEqual(parsed["name"], name)
            reply = protocol.make_dns_response(query)
            result = protocol.parse_dns_response(reply, 3210, name)
            if name == protocol.HOSTNAME:
                self.assertEqual(result, {"outcome": "response", "rcode": 0, "address": protocol.SERVER})
            else:
                self.assertEqual(result, {"outcome": "nxdomain", "rcode": 3})

    def test_reject_wrong_transaction_question_flags_and_counts(self):
        reply = protocol.make_dns_response(protocol.make_dns_query(protocol.HOSTNAME, 3210))
        altered = [b"\0\x01" + reply[2:], reply[:2] + b"\x01\0" + reply[4:],
                   reply[:2] + b"\x87\0" + reply[4:], reply[:4] + b"\0\x02" + reply[6:],
                   reply[:8] + b"\0\x01" + reply[10:], reply.replace(b"evidence", b"evidencf")]
        for payload in altered:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                protocol.parse_dns_response(payload, 3210, protocol.HOSTNAME)

    def test_reject_wrong_answer_owner_type_class_ttl_address_and_length(self):
        reply = protocol.make_dns_response(protocol.make_dns_query(protocol.HOSTNAME, 3210))
        bad_tail = [b"\xc0\x00" + reply[-14:], reply[-16:-14] + struct.pack("!HHIH", 28, 1, 60, 4) + reply[-4:],
                    reply[-16:-14] + struct.pack("!HHIH", 1, 3, 60, 4) + reply[-4:],
                    reply[-16:-14] + struct.pack("!HHIH", 1, 1, 10, 4) + reply[-4:],
                    reply[-16:-4] + socket.inet_aton("192.0.2.1")]
        for tail in bad_tail:
            with self.subTest(tail=tail), self.assertRaises(ValueError):
                protocol.parse_dns_response(reply[:-16] + tail, 3210, protocol.HOSTNAME)
        for payload in (reply[:-1], reply + b"\0", b"x" * 513):
            with self.subTest(length=len(payload)), self.assertRaises(ValueError):
                protocol.parse_dns_response(payload, 3210, protocol.HOSTNAME)

    def test_nxdomain_cannot_hide_answers_or_claim_existing_fixture_missing(self):
        missing = protocol.make_dns_response(protocol.make_dns_query("unknown.test", 77))
        positive = protocol.make_dns_response(protocol.make_dns_query(protocol.HOSTNAME, 77))
        for payload, name in ((missing + b"\0", "unknown.test"),
                              (missing[:6] + b"\0\x01" + missing[8:], "unknown.test"),
                              (positive[:2] + b"\x85\x03" + positive[4:], protocol.HOSTNAME)):
            with self.subTest(name=name), self.assertRaises(ValueError):
                protocol.parse_dns_response(payload, 77, name)

    def test_queries_reject_truncation_compression_foreign_names_and_extra_sections(self):
        query = protocol.make_dns_query(protocol.HOSTNAME, 77)
        invalid = [query[:8], query[:-1], query + b"\0", query[:12] + b"\xc0\x0c\0\x01\0\x01",
                   query[:10] + b"\0\x01" + query[12:], query.replace(b"evidence", b"external")]
        for payload in invalid:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                protocol.parse_dns_query(payload)
        with self.assertRaises(ValueError):
            protocol.make_dns_query("example.com", 1)
        with self.assertRaises(ValueError):
            protocol.make_dns_query(protocol.HOSTNAME, 65536)

    def test_dns_probe_connects_to_exact_endpoint_and_rejects_forged_reply(self):
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.recv.return_value = protocol.make_dns_response(protocol.make_dns_query(protocol.HOSTNAME, 99))
        with patch.object(protocol.socket, "socket", return_value=connection):
            result = protocol.dns_probe(protocol.HOSTNAME, 41001, transaction_id=98)
        self.assertEqual(result["outcome"], "malformed")
        connection.bind.assert_called_once_with(("", 41001))
        connection.connect.assert_called_once_with((protocol.SERVER, 53))
        self.assertEqual(result["transaction_id"], 98)

    def test_dns_timeout_and_refusal_do_not_become_nxdomain(self):
        for error, outcome in ((TimeoutError(), "timeout"), (ConnectionRefusedError(61, "refused"), "socket_error")):
            connection = MagicMock()
            connection.__enter__.return_value = connection
            connection.recv.side_effect = error
            with patch.object(protocol.socket, "socket", return_value=connection):
                result = protocol.dns_probe(protocol.HOSTNAME, 41001)
            self.assertEqual(result["outcome"], outcome)
            self.assertNotIn("rcode", result)


class TLSFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.openssl = shutil.which("openssl")
        if not cls.openssl:
            raise unittest.SkipTest("OpenSSL is required for fresh disposable certificate fixtures")
        cls.temporary = tempfile.TemporaryDirectory(prefix="heltemes-services-protocol-")
        cls.base = Path(cls.temporary.name).resolve()
        cls.pki = cls.base / "pki"
        cls.metadata = protocol.create_pki(cls.pki, cls.openssl)
        cls.used_source_ports = set()

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def source_port(self, kind=socket.SOCK_STREAM):
        for _ in range(100):
            with socket.socket(socket.AF_INET, kind) as connection:
                connection.bind(("127.0.0.1", 0))
                port = connection.getsockname()[1]
            if port not in self.used_source_ports:
                self.used_source_ports.add(port)
                return port
        self.fail("Could not reserve a fresh loopback test source port")

    def start_server(self, server):
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        def stop():
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
        self.addCleanup(stop)
        return server.server_address[1]

    def test_fresh_pki_is_private_and_public_metadata_contains_no_private_key(self):
        self.assertEqual(self.pki.stat().st_mode & 0o777, 0o700)
        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in self.pki.iterdir()))
        self.assertNotIn("PRIVATE KEY", json.dumps(self.metadata))
        self.assertNotIn(str(self.base), json.dumps(self.metadata))
        self.assertNotEqual(self.metadata["trusted_ca_sha256"], self.metadata["untrusted_ca_sha256"])
        der = ssl.PEM_cert_to_DER_cert((self.pki / "server.pem").read_text())
        self.assertEqual(hashlib.sha256(der).hexdigest(), self.metadata["server_certificate_sha256"])

    def test_existing_and_linked_pki_paths_are_refused_without_replacement(self):
        before = (self.pki / "server.key").read_bytes()
        with self.assertRaises(FileExistsError):
            protocol.create_pki(self.pki, self.openssl)
        link = self.base / "linked"
        link.symlink_to(self.pki, target_is_directory=True)
        with self.assertRaises(ValueError):
            protocol.create_pki(link / "new", self.openssl)
        self.assertEqual(before, (self.pki / "server.key").read_bytes())

    def test_context_keeps_ca_and_san_checks_without_environment_key_logging(self):
        keylog = self.base / "must-not-exist.keys"
        with patch.dict(os.environ, {"SSLKEYLOGFILE": str(keylog)}):
            context = protocol.client_context(self.pki / "ca.pem")
        self.assertTrue(context.check_hostname)
        self.assertFalse(context.hostname_checks_common_name)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.verify_flags & ssl.VERIFY_X509_STRICT)
        self.assertIsNone(context.keylog_filename)
        self.assertFalse(keylog.exists())
        self.assertEqual(context.cert_store_stats()["x509_ca"], 1)

    def test_real_tls_success_wrong_name_wrong_ca_then_repaired_success(self):
        server = protocol.make_tls_server(self.pki, address="127.0.0.1", port=0)
        port = self.start_server(server)
        probes = []
        for name, ca in ((protocol.HOSTNAME, "ca.pem"), ("wrong.test", "ca.pem"),
                         (protocol.HOSTNAME, "untrusted-ca.pem"), (protocol.HOSTNAME, "ca.pem")):
            probes.append(protocol.tls_probe("127.0.0.1", name, self.pki / ca, self.source_port(), port=port))
        for positive in (probes[0], probes[3]):
            self.assertEqual(positive["outcome"], "response", positive)
            self.assertEqual(positive["payload"], protocol.TLS_PAYLOAD)
            self.assertEqual(positive["peer_certificate_sha256"], self.metadata["server_certificate_sha256"])
            self.assertIn(positive["tls_version"], ("TLSv1.2", "TLSv1.3"))
        self.assertEqual(probes[1]["outcome"], "certificate_error", probes[1])
        self.assertEqual(probes[1]["verify_code"], 62)
        self.assertEqual(probes[2]["outcome"], "certificate_error", probes[2])
        self.assertIn(probes[2]["verify_code"], (20, 21))

    def test_real_dns_fixture_answers_a_and_explicit_nxdomain(self):
        server = protocol.DNSFixture(("127.0.0.1", 0), protocol.DNSHandler)
        port = self.start_server(server)
        for name, outcome in ((protocol.HOSTNAME, "response"), ("unknown.test", "nxdomain")):
            response = protocol.dns_probe(name, self.source_port(socket.SOCK_DGRAM), address="127.0.0.1", port=port)
            self.assertEqual(response["outcome"], outcome, response)
            self.assertEqual(response["rcode"], 0 if outcome == "response" else 3)

    def test_tls_timeouts_preserve_layer_and_never_disable_verification(self):
        for stage, expected in (("connect", "connect_timeout"), ("handshake", "handshake_timeout"), ("read", "read_timeout")):
            connection, secured, context = MagicMock(), MagicMock(), MagicMock()
            connection.__enter__.return_value = connection
            secured.__enter__.return_value = secured
            context.wrap_socket.return_value = secured
            secured.version.return_value = "TLSv1.3"
            secured.cipher.return_value = ("SYNTHETIC", "TLSv1.3", 256)
            secured.getpeercert.return_value = b"synthetic public certificate"
            if stage == "connect":
                connection.connect.side_effect = TimeoutError()
            elif stage == "handshake":
                context.wrap_socket.side_effect = TimeoutError()
            else:
                secured.recv.side_effect = TimeoutError()
            with patch.object(protocol, "client_context", return_value=context), patch.object(protocol.socket, "socket", return_value=connection):
                result = protocol.tls_probe(protocol.SERVER, protocol.HOSTNAME, self.pki / "ca.pem", 41000)
            self.assertEqual(result["outcome"], expected)
            if stage != "connect":
                context.wrap_socket.assert_called_once_with(connection, server_hostname=protocol.HOSTNAME)

    def test_probe_targets_cannot_escape_the_fixture(self):
        for address in ("example.com", "192.0.2.1", "::1"):
            with self.assertRaises(ValueError):
                protocol.tls_probe(address, protocol.HOSTNAME, self.pki / "ca.pem", 41001)
            with self.assertRaises(ValueError):
                protocol.dns_probe(protocol.HOSTNAME, 41001, address=address)


if __name__ == "__main__":
    unittest.main()
