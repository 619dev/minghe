"""Loopback TLS/SIP integration test. Does not implement or test voice media.

Build minghe, set MINGHE_BINARY to its absolute path, then run this test.
Only ephemeral test identities and certificates are used.
"""
import hashlib
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
import time
import unittest
import uuid

from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
import e2ee_client as e


class SipClient:
    def __init__(self, port, cert, extension):
        context = ssl.create_default_context(cafile=str(cert))
        self.sock = context.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5), server_hostname="127.0.0.1")
        self.sock.settimeout(5)
        self.extension, self.sequence, self.buffer = extension, 0, b""

    def read(self):
        while b"\r\n\r\n" not in self.buffer:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise RuntimeError("TLS connection closed")
            self.buffer += chunk
        header, _, body = self.buffer.partition(b"\r\n\r\n")
        lines = header.decode().split("\r\n")
        headers = {line.split(":", 1)[0].lower(): line.split(":", 1)[1].strip() for line in lines[1:]}
        length = int(headers.get("content-length", "0"))
        if not 0 <= length <= 65536:
            raise ValueError("invalid SIP length")
        total = len(header) + 4 + length
        while len(self.buffer) < total:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise RuntimeError("TLS connection closed")
            self.buffer += chunk
        body = self.buffer[len(header) + 4:total]
        self.buffer = self.buffer[total:]
        return lines[0], headers, body

    def send(self, method, body=b"", content_type=None, extra=None, call_id=None, target="1002"):
        self.sequence += 1
        uri = "sip:127.0.0.1" if method == "REGISTER" else f"sip:{target}@127.0.0.1"
        headers = {
            "Via": f"SIP/2.0/TLS 127.0.0.1;branch=z9hG4bK{uuid.uuid4().hex}",
            "From": f"<sip:{self.extension}@127.0.0.1>;tag=sender",
            "To": f"<sip:{self.extension if method == 'REGISTER' else target}@127.0.0.1>",
            "Call-ID": call_id or uuid.uuid4().hex, "CSeq": f"{self.sequence} {method}",
            "Contact": f"<sip:{self.extension}@127.0.0.1;transport=tls>",
            "Content-Length": str(len(body)), "Max-Forwards": "70",
        }
        if content_type:
            headers["Content-Type"] = content_type
        headers.update(extra or {})
        frame = f"{method} {uri} SIP/2.0\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n"
        self.sock.sendall(frame.encode() + body)

    def register(self, password):
        self.send("REGISTER", target=self.extension)
        first, headers, _ = self.read()
        assert first.startswith("SIP/2.0 401 ")
        challenge = headers["www-authenticate"]
        assert "algorithm=SHA-256" in challenge
        nonce = re.search(r'nonce="([^"]+)"', challenge).group(1)
        h = lambda value: hashlib.sha256(value.encode()).hexdigest()
        cnonce = uuid.uuid4().hex
        response = h(f'{h(f"{self.extension}:127.0.0.1:{password}")}:{nonce}:00000001:{cnonce}:auth:{h("REGISTER:sip:127.0.0.1")}')
        auth = f'Digest username="{self.extension}", realm="127.0.0.1", nonce="{nonce}", uri="sip:127.0.0.1", response="{response}", algorithm=SHA-256, qop=auth, nc=00000001, cnonce="{cnonce}"'
        self.send("REGISTER", extra={"Authorization": auth}, target=self.extension)
        assert self.read()[0].startswith("SIP/2.0 200 ")


@unittest.skipUnless(os.environ.get("MINGHE_BINARY"), "set MINGHE_BINARY to the compiled server")
class TransportTests(unittest.TestCase):
    def test_real_tls_registration_offline_ciphertext_and_signed_call_routing(self):
        binary = Path(os.environ["MINGHE_BINARY"]).resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix="minghe-transport-") as root:
            root = Path(root)
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            password = "test-only-random-" + uuid.uuid4().hex
            config = root / "config.toml"
            e.write_new(config, f'[server]\nlisten_addr="127.0.0.1"\nsip_port={port}\nhost="127.0.0.1"\n[extensions]\nrange_start=1000\nrange_end=2000\ndefault_password="{password}"\n[tls]\ncert_path=""\nkey_path=""\n'.encode(), 0o600)
            with (root / "server.log").open("wb") as log:
                process = subprocess.Popen([str(binary), "-c", str(config)], cwd=root, stdout=log, stderr=subprocess.STDOUT)
                clients = []
                try:
                    cert = root / "certs/server.crt"
                    for _ in range(100):
                        if process.poll() is not None:
                            self.fail("test server exited before opening its TLS listener")
                        if cert.exists():
                            try:
                                alice = SipClient(port, cert, "1001")
                                clients.append(alice)
                                break
                            except (ConnectionError, OSError):
                                pass
                        time.sleep(0.05)
                    else:
                        self.fail("test server did not start")
                    alice.register(password)
                    a_sign, b_sign = ed25519.Ed25519PrivateKey.generate(), ed25519.Ed25519PrivateKey.generate()
                    a_rsa = rsa.generate_private_key(public_exponent=65537, key_size=3072)
                    b_rsa = rsa.generate_private_key(public_exponent=65537, key_size=3072)
                    a_pub = e.public_bundle("1001", a_rsa.public_key(), a_sign.public_key())
                    b_pub = e.public_bundle("1002", b_rsa.public_key(), b_sign.public_key())
                    a_pin, b_pin = e.bundle_fingerprint(a_pub), e.bundle_fingerprint(b_pub)
                    token = e.encrypt_message("1001", a_sign, b_pub, b_pin, "offline E2EE test")
                    alice.send("MESSAGE", token.encode(), "application/jose")
                    self.assertTrue(alice.read()[0].startswith("SIP/2.0 200 "))
                    alice.send("MESSAGE", b"plaintext must be rejected", "text/plain")
                    self.assertTrue(alice.read()[0].startswith("SIP/2.0 415 "))
                    bob = SipClient(port, cert, "1002")
                    clients.append(bob)
                    bob.register(password)
                    first, headers, body = bob.read()
                    self.assertTrue(first.startswith("MESSAGE "))
                    self.assertEqual(headers["content-type"], "application/jose")
                    self.assertEqual(body.decode(), token)
                    self.assertNotIn("authorization", headers)
                    replay = str(root / "received.sqlite3")
                    self.assertEqual(e.decrypt_message("1002", b_rsa, a_pub, a_pin, token, replay), "offline E2EE test")
                    # Server can replay a valid ciphertext; the endpoint still rejects it.
                    alice.send("MESSAGE", token.encode(), "application/jose")
                    self.assertTrue(alice.read()[0].startswith("SIP/2.0 200 "))
                    self.assertEqual(bob.read()[2].decode(), token)
                    with self.assertRaisesRegex(ValueError, "replayed"):
                        e.decrypt_message("1002", b_rsa, a_pub, a_pin, token, replay)
                    call_id = uuid.uuid4().hex
                    offer = ("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"
                             "m=audio 4000 UDP/TLS/RTP/SAVPF 111\r\na=rtcp-mux\r\na=setup:actpass\r\na=fingerprint:sha-256 "
                             + ":".join(["AB"] * 32) + "\r\n").encode()
                    identity = e.sign_sdp("1001", a_sign, "1002", call_id, "offer", offer)
                    alice.send("INVITE", offer, "application/sdp", {"X-Minghe-Identity": identity}, call_id)
                    self.assertTrue(alice.read()[0].startswith("SIP/2.0 100 "))
                    first, headers, body = bob.read()
                    self.assertTrue(first.startswith("INVITE "))
                    self.assertEqual(body, offer)
                    self.assertTrue(e.verify_sdp(a_pub, a_pin, "1002", call_id, "offer", body, headers["x-minghe-identity"]))
                    answer = offer.replace(b"actpass", b"active").replace(b"AB:", b"CD:")
                    identity = e.sign_sdp("1002", b_sign, "1001", call_id, "answer", answer)
                    response = (f'SIP/2.0 200 OK\r\nVia: {headers["via"]}\r\nFrom: {headers["from"]}\r\n'
                                f'To: {headers["to"]};tag=receiver\r\nCall-ID: {call_id}\r\nCSeq: {headers["cseq"]}\r\n'
                                f'Contact: <sip:1002@127.0.0.1;transport=tls>\r\nContent-Type: application/sdp\r\n'
                                f'X-Minghe-Identity: {identity}\r\nContent-Length: {len(answer)}\r\n\r\n').encode() + answer
                    bob.sock.sendall(response)
                    first, headers, body = alice.read()
                    self.assertTrue(first.startswith("SIP/2.0 200 "))
                    self.assertEqual(body, answer)
                    self.assertTrue(e.verify_sdp(b_pub, b_pin, "1001", call_id, "answer", body, headers["x-minghe-identity"]))
                    alice.send("BYE", call_id=call_id, extra={"To": "<sip:1002@127.0.0.1>;tag=receiver"})
                    self.assertTrue(alice.read()[0].startswith("SIP/2.0 200 "))
                    self.assertTrue(bob.read()[0].startswith("BYE "))
                finally:
                    for client in clients:
                        client.sock.close()
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
            self.assertNotIn("offline E2EE test", (root / "server.log").read_text())
            self.assertNotIn(password, (root / "server.log").read_text())


if __name__ == "__main__":
    unittest.main()
