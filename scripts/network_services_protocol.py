"""Bounded DNS and authenticated TLS fixtures for the disposable network lab.

The DNS fixture deliberately implements only one uncompressed IN A question and
one exact answer format. It is not a recursive or general-purpose DNS resolver.
"""
from __future__ import annotations

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import socket
import socketserver
import ssl
import struct
import subprocess
import threading

SERVER = "10.203.2.2"
DNS_PORT = 53
TLS_PORT = 8443
HOSTNAME = "evidence.test"
DNS_NAMES = (HOSTNAME, "unknown.test", "wrong.test")
TLS_PAYLOAD = {"synthetic": True, "service": "tls", "hostname": HOSTNAME}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def encoded_name(name):
    require(isinstance(name, str) and name in DNS_NAMES, "Name is outside the synthetic DNS fixture.")
    return b"".join(bytes((len(label),)) + label.encode("ascii") for label in name.split(".")) + b"\0"


def make_dns_query(name, transaction_id):
    require(isinstance(transaction_id, int) and 0 <= transaction_id <= 65535, "Invalid DNS transaction ID.")
    return struct.pack("!6H", transaction_id, 0x0100, 1, 0, 0, 0) + encoded_name(name) + struct.pack("!HH", 1, 1)


def parse_dns_query(payload):
    require(12 < len(payload) <= 512, "DNS query length is invalid.")
    transaction_id, flags, questions, answers, authority, additional = struct.unpack("!6H", payload[:12])
    require((flags, questions, answers, authority, additional) == (0x0100, 1, 0, 0, 0), "DNS query header is invalid.")
    position, labels = 12, []
    while True:
        require(position < len(payload), "DNS question is truncated.")
        size = payload[position]
        position += 1
        if size == 0:
            break
        require(0 < size <= 63 and position + size < len(payload), "DNS label is invalid or truncated.")
        try:
            label = payload[position:position + size].decode("ascii")
        except UnicodeDecodeError as error:
            raise ValueError("DNS label is not ASCII.") from error
        require(label and all(character.isalnum() or character == "-" for character in label), "DNS label contains invalid characters.")
        labels.append(label)
        position += size
    name = ".".join(labels)
    require(name in DNS_NAMES and payload[12:position] == encoded_name(name), "DNS question is outside the fixture.")
    require(len(payload) == position + 4 and payload[position:] == struct.pack("!HH", 1, 1), "DNS question must be exactly one IN A query.")
    return {"transaction_id": transaction_id, "name": name, "question": payload[12:]}


def make_dns_response(query):
    parsed = parse_dns_query(query)
    exists = parsed["name"] == HOSTNAME
    header = struct.pack("!6H", parsed["transaction_id"], 0x8500 if exists else 0x8503, 1, int(exists), 0, 0)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(SERVER) if exists else b""
    return header + parsed["question"] + answer


def parse_dns_response(payload, transaction_id, name):
    question = make_dns_query(name, transaction_id)[12:]
    require(12 < len(payload) <= 512, "DNS response length is invalid.")
    identity, flags, questions, answers, authority, additional = struct.unpack("!6H", payload[:12])
    require(identity == transaction_id, "DNS response transaction does not match.")
    require(flags in (0x8500, 0x8503) and (questions, authority, additional) == (1, 0, 0), "DNS response flags or counts are invalid.")
    require(payload[12:12 + len(question)] == question, "DNS response question does not match.")
    remainder = payload[12 + len(question):]
    rcode = flags & 15
    if rcode == 3:
        require(answers == 0 and not remainder and name != HOSTNAME, "NXDOMAIN response is inconsistent with the fixture.")
        return {"outcome": "nxdomain", "rcode": 3}
    require(answers == 1 and name == HOSTNAME and len(remainder) == 16, "DNS A response is inconsistent with the fixture.")
    require(remainder[:12] == b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4), "DNS answer owner, type, class, TTL, or size is invalid.")
    address = socket.inet_ntoa(remainder[12:])
    require(address == SERVER, "DNS answer address is outside the lab.")
    return {"outcome": "response", "rcode": 0, "address": address}


def _target(address, port, source_port):
    require(address in (SERVER, "127.0.0.1"), "Probe address is outside the lab or loopback test fixture.")
    require(isinstance(port, int) and 1 <= port <= 65535, "Invalid fixture port.")
    require(isinstance(source_port, int) and 1024 <= source_port <= 65535, "Invalid explicit source port.")


def dns_probe(name, source_port, *, address=SERVER, port=DNS_PORT, transaction_id=None):
    _target(address, port, source_port)
    transaction_id = secrets.randbelow(65536) if transaction_id is None else transaction_id
    query = make_dns_query(name, transaction_id)
    result = {"source_port": source_port, "transaction_id": transaction_id, "name": name}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.settimeout(1.2)
            connection.bind(("", source_port))
            # Connected UDP restricts replies to this exact fixture address/port.
            connection.connect((address, port))
            connection.send(query)
            response = connection.recv(513)
            result.update(parse_dns_response(response, transaction_id, name))
    except TimeoutError:
        result["outcome"] = "timeout"
    except ValueError as error:
        result.update(outcome="malformed", error=str(error))
    except OSError as error:
        result.update(outcome="socket_error", errno=error.errno)
    return result


def client_context(ca_file):
    # Unlike create_default_context, this constructor never reads SSLKEYLOGFILE.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.hostname_checks_common_name = False
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    context.load_verify_locations(cafile=str(ca_file))
    require(context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
            and context.keylog_filename is None, "TLS verification policy is not strict.")
    return context


def tls_probe(address, hostname, ca_file, source_port, *, port=TLS_PORT):
    _target(address, port, source_port)
    require(hostname in (HOSTNAME, "wrong.test"), "TLS hostname is outside the fixture.")
    context = client_context(ca_file)
    result = {"source_port": source_port, "hostname": hostname, "address": address}
    stage = "connect"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(1.2)
            connection.bind(("", source_port))
            connection.connect((address, port))
            stage = "handshake"
            with context.wrap_socket(connection, server_hostname=hostname) as secured:
                result.update(tls_version=secured.version(), cipher=secured.cipher()[0],
                              peer_certificate_sha256=hashlib.sha256(secured.getpeercert(binary_form=True)).hexdigest())
                stage = "read"
                secured.sendall(f"GET /synthetic HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n".encode("ascii"))
                raw = bytearray()
                while True:
                    part = secured.recv(4097 - len(raw))
                    if not part:
                        break
                    raw.extend(part)
                    require(len(raw) <= 4096, "Synthetic HTTPS response exceeds its bound.")
                header, body = bytes(raw).split(b"\r\n\r\n", 1)
                status = int(header.split(b"\r\n", 1)[0].split()[1])
                payload = json.loads(body)
                require(status == 200 and payload == TLS_PAYLOAD, "Unexpected synthetic HTTPS response.")
                result.update(outcome="response", status=status, payload=payload)
    except ssl.SSLCertVerificationError as error:
        result.update(outcome="certificate_error", verify_code=error.verify_code, verify_message=error.verify_message)
    except TimeoutError:
        result["outcome"] = {"connect": "connect_timeout", "handshake": "handshake_timeout", "read": "read_timeout"}[stage]
    except ssl.SSLError:
        result["outcome"] = "handshake_error" if stage == "handshake" else "tls_error"
    except OSError as error:
        result.update(outcome="socket_error", errno=error.errno)
    except (ValueError, IndexError):
        result["outcome"] = "protocol_error"
    return result


def create_pki(path, openssl_tool):
    path = Path(path).absolute()
    require(".." not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)), "PKI path must avoid traversal and symbolic links.")
    path.mkdir(mode=0o700)
    original_umask = os.umask(0o077)
    try:
        def command(*arguments):
            process = subprocess.run([str(openssl_tool), *map(str, arguments)], capture_output=True, timeout=30)
            require(process.returncode == 0, "Disposable certificate generation or verification failed.")
            return process.stdout
        for prefix, title in (("ca", "HELTEMES Disposable Lab CA"), ("untrusted-ca", "HELTEMES Untrusted Fixture CA")):
            config = path / (prefix + ".cnf")
            config.write_text("[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ca\n"
                              f"[dn]\nCN={title}\n[ca]\nbasicConstraints=critical,CA:true,pathlen:0\n"
                              "keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n")
            command("req", "-new", "-newkey", "rsa:2048", "-nodes", "-x509", "-sha256", "-days", "2",
                    "-config", config, "-keyout", path / (prefix + ".key"), "-out", path / (prefix + ".pem"))
        leaf_config = path / "server.cnf"
        leaf_config.write_text("[req]\nprompt=no\ndistinguished_name=dn\n[dn]\nCN=evidence.test\n"
                               "[server]\nbasicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                               "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:evidence.test\n"
                               "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n")
        command("req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256", "-config", leaf_config,
                "-keyout", path / "server.key", "-out", path / "server.csr")
        command("x509", "-req", "-in", path / "server.csr", "-CA", path / "ca.pem", "-CAkey", path / "ca.key",
                "-set_serial", str(secrets.randbits(128) or 1), "-days", "2", "-sha256", "-extfile", leaf_config,
                "-extensions", "server", "-out", path / "server.pem")
        command("verify", "-CAfile", path / "ca.pem", path / "server.pem")
        public = {name: (path / (name + ".pem")).read_text() for name in ("ca", "untrusted-ca", "server")}
        fingerprints = {name: hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest() for name, pem in public.items()}
        for child in path.iterdir():
            child.chmod(0o600)
        return {"synthetic_only": True, "server_hostname": HOSTNAME, "configured_validity_days": 2,
                "trusted_ca_sha256": fingerprints["ca"], "untrusted_ca_sha256": fingerprints["untrusted-ca"],
                "server_certificate_sha256": fingerprints["server"], "public_certificates_pem": public,
                "server_certificate_details": command("x509", "-in", path / "server.pem", "-noout", "-subject", "-issuer", "-dates").decode().splitlines()}
    finally:
        os.umask(original_umask)


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, connection = self.request
        try:
            reply = make_dns_response(data)
        except ValueError:
            return
        connection.sendto(reply, self.client_address)


class DNSFixture(socketserver.UDPServer):
    max_packet_size = 513


class HTTPSHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(TLS_PAYLOAD).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *arguments):
        pass


class TLSFixture(ThreadingHTTPServer):
    def __init__(self, address, context):
        self.context = context
        super().__init__(address, HTTPSHandler)

    def get_request(self):
        connection, address = self.socket.accept()
        connection.settimeout(1.2)
        try:
            return self.context.wrap_socket(connection, server_side=True), address
        except BaseException:
            connection.close()
            raise


def make_tls_server(pki_dir, *, address=SERVER, port=TLS_PORT):
    require(address in (SERVER, "127.0.0.1"), "Server address is outside the fixture.")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(Path(pki_dir) / "server.pem"), str(Path(pki_dir) / "server.key"))
    return TLSFixture((address, port), context)


def serve(pki_dir):
    with DNSFixture((SERVER, DNS_PORT), DNSHandler) as dns, make_tls_server(pki_dir) as https:
        thread = threading.Thread(target=dns.serve_forever, daemon=True)
        thread.start()
        try:
            https.serve_forever()
        finally:
            dns.shutdown()
            thread.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    server = commands.add_parser("serve")
    server.add_argument("--pki", required=True)
    dns = commands.add_parser("dns")
    dns.add_argument("--name", choices=DNS_NAMES, required=True)
    dns.add_argument("--source-port", type=int, required=True)
    tls = commands.add_parser("tls")
    tls.add_argument("--address", choices=(SERVER,), required=True)
    tls.add_argument("--hostname", choices=(HOSTNAME, "wrong.test"), required=True)
    tls.add_argument("--ca", required=True)
    tls.add_argument("--source-port", type=int, required=True)
    args = parser.parse_args()
    if args.operation == "serve":
        serve(args.pki)
    elif args.operation == "dns":
        print(json.dumps(dns_probe(args.name, args.source_port)))
    else:
        print(json.dumps(tls_probe(args.address, args.hostname, args.ca, args.source_port)))


if __name__ == "__main__":
    main()
