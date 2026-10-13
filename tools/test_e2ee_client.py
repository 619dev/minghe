"""Real endpoint crypto tests, including a malicious signaling server."""
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

import e2ee_client as e


class E2eeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alice_rsa = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        cls.bob_rsa = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        cls.alice_sign = ed25519.Ed25519PrivateKey.generate()
        cls.bob_sign = ed25519.Ed25519PrivateKey.generate()
        cls.alice = e.public_bundle("1001", cls.alice_rsa.public_key(), cls.alice_sign.public_key())
        cls.bob = e.public_bundle("1002", cls.bob_rsa.public_key(), cls.bob_sign.public_key())
        cls.alice_pin = e.bundle_fingerprint(cls.alice)
        cls.bob_pin = e.bundle_fingerprint(cls.bob)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = str(Path(self.tmp.name) / "replay.sqlite3")

    def encrypt(self, text="端到端加密消息", **kwargs):
        return e.encrypt_message("1001", self.alice_sign, self.bob, self.bob_pin, text, now=1000, **kwargs)

    def decrypt(self, token, **kwargs):
        return e.decrypt_message("1002", self.bob_rsa, self.alice, self.alice_pin, token, self.db, now=1001, **kwargs)

    def test_real_crypto_roundtrip_and_durable_replay_rejection(self):
        token = self.encrypt()
        self.assertNotIn("端到端加密消息", token)
        self.assertEqual(self.decrypt(token), "端到端加密消息")
        self.assertEqual(Path(self.db).stat().st_mode & 0o777, 0o600)
        # A second call opens a new database connection, as after a restart.
        with self.assertRaisesRegex(ValueError, "replayed"):
            self.decrypt(token)

    def test_randomized_encryption_and_recipient_binding(self):
        a, b = self.encrypt(), self.encrypt()
        self.assertNotEqual(a, b)
        self.assertNotEqual(a.split(".")[2], b.split(".")[2])
        with self.assertRaises(Exception):
            e.decrypt_message("1003", self.bob_rsa, self.alice, self.alice_pin, a, self.db, now=1001)
        with self.assertRaises(Exception):
            e.decrypt_message("1001", self.alice_rsa, self.alice, self.alice_pin, a, self.db, now=1001)
        self.assertEqual(self.decrypt(a), "端到端加密消息")

    def test_server_cannot_forge_sender_or_replace_recipient_key(self):
        attacker = ed25519.Ed25519PrivateKey.generate()
        forged = e.encrypt_message("1001", attacker, self.bob, self.bob_pin, "forged", now=1000)
        with self.assertRaises(Exception):
            self.decrypt(forged)
        altered_peer = dict(self.bob, signing_key=e.b64(e.spki(attacker.public_key())))
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            e.encrypt_message("1001", self.alice_sign, altered_peer, self.bob_pin, "secret", now=1000)

    def test_every_jwe_component_is_authenticated(self):
        token = self.encrypt()
        for index in range(5):
            parts = token.split(".")
            raw = bytearray(e.unb64(parts[index]))
            raw[-1] ^= 1
            parts[index] = e.b64(raw)
            with self.subTest(component=index), self.assertRaises(Exception):
                self.decrypt(".".join(parts))
        self.assertEqual(self.decrypt(token), "端到端加密消息")

    def test_expiry_clock_and_format_fail_closed(self):
        expired = self.encrypt(ttl=1)
        with self.assertRaisesRegex(ValueError, "timestamp"):
            self.decrypt(expired)
        future = e.encrypt_message("1001", self.alice_sign, self.bob, self.bob_pin, "future", now=2000)
        with self.assertRaisesRegex(ValueError, "timestamp"):
            self.decrypt(future)
        with self.assertRaises(ValueError):
            e.parse_json(b'{"alg":"none","alg":"EdDSA"}')
        with self.assertRaises(ValueError):
            e.unb64("AB")
        with self.assertRaises(ValueError):
            self.encrypt("a" * 1801)

    def test_signed_sdp_rejects_fingerprint_replacement_and_cross_call_replay(self):
        sdp = b"v=0\r\nm=audio 4000 UDP/TLS/RTP/SAVPF 111\r\na=fingerprint:sha-256 AA:BB\r\n"
        token = e.sign_sdp("1001", self.alice_sign, "1002", "call-1", "offer", sdp, now=1000)
        self.assertTrue(e.verify_sdp(self.alice, self.alice_pin, "1002", "call-1", "offer", sdp, token, now=1001))
        for changed_sdp, call_id, role, recipient, now in [
            (sdp.replace(b"AA:BB", b"CC:DD"), "call-1", "offer", "1002", 1001),
            (sdp, "call-2", "offer", "1002", 1001),
            (sdp, "call-1", "answer", "1002", 1001),
            (sdp, "call-1", "offer", "1003", 1001),
            (sdp, "call-1", "offer", "1002", 1120),
        ]:
            with self.assertRaises(ValueError):
                e.verify_sdp(self.alice, self.alice_pin, recipient, call_id, role, changed_sdp, token, now=now)
        # Re-signing modified SDP with the server's key also fails pinned verification.
        forged = e.sign_sdp("1001", self.bob_sign, "1002", "call-1", "offer", sdp, now=1000)
        with self.assertRaises(ValueError):
            e.verify_sdp(self.alice, self.alice_pin, "1002", "call-1", "offer", sdp, forged, now=1001)

    def test_key_files_are_exclusive_and_passphrase_encrypted(self):
        key = Path(self.tmp.name) / "identity.json"
        password = b"test-only-long-password"
        from cryptography.hazmat.primitives import serialization
        private = {"version": 1, "extension": "1001"}
        for name, value in (("encryption_key", self.alice_rsa), ("signing_key", self.alice_sign)):
            private[name] = value.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.BestAvailableEncryption(password)).decode()
        e.write_new(key, e.canonical(private), 0o600)
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        self.assertEqual(e.load_private(key, password)[0], "1001")
        with self.assertRaises(Exception):
            e.load_private(key, b"wrong-password")
        with self.assertRaises(FileExistsError):
            e.write_new(key, b"overwrite", 0o600)


if __name__ == "__main__":
    unittest.main()
