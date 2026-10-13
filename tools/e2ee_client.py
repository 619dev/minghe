#!/usr/bin/env python3
"""Endpoint reference implementation. No SIP transport or media stack.

Private keys and replay state live ONLY on clients. Public bundles must be
exchanged and their fingerprints confirmed outside the SIP server. This is
a single-device profile; it does not implement a forward-secret message ratchet.
"""
import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import time
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_BODY = 4096
MAX_TTL = 86400


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("invalid base64url")
    result = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if b64(result) != value:
        raise ValueError("noncanonical base64url")
    return result


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def parse_json(data):
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("duplicate JSON field")
            obj[key] = value
        return obj
    obj = json.loads(data, object_pairs_hook=unique)
    if not isinstance(obj, dict):
        raise ValueError("JSON object required")
    return obj


def spki(key):
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def key_id(key):
    return hashlib.sha256(spki(key)).hexdigest()


def public_bundle(extension, encryption_key, signing_key):
    if not re.fullmatch(r"[1-9][0-9]{0,9}", extension):
        raise ValueError("canonical extension required")
    return {"version": 1, "extension": extension,
            "encryption_key": b64(spki(encryption_key)), "signing_key": b64(spki(signing_key))}


def bundle_fingerprint(bundle):
    return hashlib.sha256(canonical(bundle)).hexdigest()


def trusted_peer(bundle, expected_fingerprint):
    if set(bundle) != {"version", "extension", "encryption_key", "signing_key"} or bundle["version"] != 1:
        raise ValueError("unsupported public bundle")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_fingerprint) or not hmac.compare_digest(
            bundle_fingerprint(bundle), expected_fingerprint):
        raise ValueError("peer fingerprint changed or was not independently verified")
    encryption = serialization.load_der_public_key(unb64(bundle["encryption_key"]))
    signing = serialization.load_der_public_key(unb64(bundle["signing_key"]))
    if not isinstance(encryption, rsa.RSAPublicKey) or encryption.key_size not in (3072, 4096):
        raise ValueError("RSA 3072/4096 recipient key required")
    if encryption.public_numbers().e != 65537 or not isinstance(signing, ed25519.Ed25519PublicKey):
        raise ValueError("unsupported peer keys")
    public_bundle(bundle["extension"], encryption, signing)
    return encryption, signing


def sign_jws(signing, claims, typ):
    header = {"alg": "EdDSA", "typ": typ, "kid": key_id(signing.public_key())}
    signed = b64(canonical(header)) + "." + b64(canonical(claims))
    return signed + "." + b64(signing.sign(signed.encode("ascii")))


def verify_jws(token, signing, typ):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("signed compact JWS required")
    header = parse_json(unb64(parts[0]))
    if header != {"alg": "EdDSA", "typ": typ, "kid": key_id(signing)}:
        raise ValueError("incorrect signature algorithm, type or pinned sender key")
    signing.verify(unb64(parts[2]), (parts[0] + "." + parts[1]).encode("ascii"))
    return parse_json(unb64(parts[1]))


def verify_context(claims, sender, recipient, max_ttl, now):
    if claims.get("iss") != sender or claims.get("aud") != recipient:
        raise ValueError("sender/recipient mismatch")
    issued, expires = claims.get("iat"), claims.get("exp")
    if type(issued) is not int or type(expires) is not int or not (
            issued >= 0 and issued <= now + 30 and now < expires and 0 < expires - issued <= max_ttl):
        raise ValueError("expired or invalid timestamp")


def encrypt_message(extension, signing, peer, pin, text, ttl=MAX_TTL, now=None):
    encryption, _ = trusted_peer(peer, pin)
    now = int(time.time()) if now is None else now
    if not 0 < ttl <= MAX_TTL or not text.strip():
        raise ValueError("nonempty message and TTL 1..86400 required")
    if len(text.encode()) > 1800:
        raise ValueError("plaintext limit is 1800 UTF-8 bytes")
    claims = {"iss": extension, "aud": peer["extension"], "jti": str(uuid.uuid4()),
              "iat": now, "exp": now + ttl, "text": text}
    inner = sign_jws(signing, claims, "JWT").encode("ascii")
    protected = b64(canonical({"alg": "RSA-OAEP-256", "enc": "A256GCM", "cty": "JWT", "kid": key_id(encryption)}))
    content_key, nonce = os.urandom(32), os.urandom(12)
    encrypted_key = encryption.encrypt(content_key, padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    encrypted = AESGCM(content_key).encrypt(nonce, inner, protected.encode("ascii"))
    result = ".".join([protected, b64(encrypted_key), b64(nonce), b64(encrypted[:-16]), b64(encrypted[-16:])])
    if len(result) > MAX_BODY:
        raise ValueError("encrypted MESSAGE exceeds 4096 bytes; shorten the text")
    return result


def decrypt_message(extension, encryption, peer, pin, token, replay_db, now=None):
    _, signing = trusted_peer(peer, pin)
    now = int(time.time()) if now is None else now
    if len(token) > MAX_BODY or len(token.split(".")) != 5:
        raise ValueError("invalid JWE size or format")
    protected, wrapped_key, nonce, ciphertext, tag = token.split(".")
    header = parse_json(unb64(protected))
    if header != {"alg": "RSA-OAEP-256", "enc": "A256GCM", "cty": "JWT", "kid": key_id(encryption.public_key())}:
        raise ValueError("unsupported JWE header or recipient key")
    nonce, ciphertext, tag = unb64(nonce), unb64(ciphertext), unb64(tag)
    if len(nonce) != 12 or len(tag) != 16:
        raise ValueError("invalid nonce or tag")
    content_key = encryption.decrypt(unb64(wrapped_key), padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    if len(content_key) != 32:
        raise ValueError("invalid content key")
    inner = AESGCM(content_key).decrypt(nonce, ciphertext + tag, protected.encode("ascii")).decode("ascii")
    claims = verify_jws(inner, signing, "JWT")
    if set(claims) != {"iss", "aud", "jti", "iat", "exp", "text"}:
        raise ValueError("unexpected message claims")
    verify_context(claims, peer["extension"], extension, MAX_TTL, now)
    if not isinstance(claims["text"], str) or not claims["text"].strip() or len(claims["text"].encode()) > 1800:
        raise ValueError("invalid text")
    message_id = uuid.UUID(claims["jti"])
    if message_id.version != 4 or str(message_id) != claims["jti"]:
        raise ValueError("invalid message ID")
    # Durable, transactional replay protection. Fail closed on DB errors.
    # Commit before returning plaintext, including across process restarts.
    fd = os.open(replay_db, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    os.fchmod(fd, 0o600)
    os.close(fd)
    with sqlite3.connect(replay_db) as db:
        db.execute("CREATE TABLE IF NOT EXISTS seen (sender TEXT, recipient TEXT, id TEXT, expires INTEGER, PRIMARY KEY(sender,recipient,id))")
        db.execute("DELETE FROM seen WHERE expires <= ?", (now,))
        try:
            db.execute("INSERT INTO seen VALUES (?,?,?,?)", (claims["iss"], extension, claims["jti"], claims["exp"]))
        except sqlite3.IntegrityError as error:
            raise ValueError("replayed message") from error
    return claims["text"]


def sign_sdp(extension, signing, recipient, call_id, role, sdp, now=None):
    now = int(time.time()) if now is None else now
    if role not in ("offer", "answer") or not call_id or len(call_id) > 128:
        raise ValueError("invalid call context")
    return sign_jws(signing, {"iss": extension, "aud": recipient, "call_id": call_id,
        "role": role, "sdp_sha256": hashlib.sha256(sdp).hexdigest(), "iat": now, "exp": now + 120}, "minghe-sdp+jwt")


def verify_sdp(peer, pin, recipient, call_id, role, sdp, token, now=None):
    _, signing = trusted_peer(peer, pin)
    claims = verify_jws(token, signing, "minghe-sdp+jwt")
    if set(claims) != {"iss", "aud", "call_id", "role", "sdp_sha256", "iat", "exp"}:
        raise ValueError("unexpected SDP claims")
    verify_context(claims, peer["extension"], recipient, 120, int(time.time()) if now is None else now)
    if role not in ("offer", "answer") or claims["call_id"] != call_id or claims["role"] != role or not hmac.compare_digest(
            claims["sdp_sha256"], hashlib.sha256(sdp).hexdigest()):
        raise ValueError("tampered SDP, call or direction")
    # The SIP client must ALSO compare the live DTLS certificate to the signed
    # SDP fingerprint, validate the SDP profile, and reject reused call contexts.
    return True


def write_new(path, data, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as file:
        file.write(data)


def load_private(path, passphrase):
    bundle = parse_json(Path(path).read_bytes())
    if set(bundle) != {"version", "extension", "encryption_key", "signing_key"} or bundle["version"] != 1:
        raise ValueError("unsupported private bundle")
    encryption = serialization.load_pem_private_key(bundle["encryption_key"].encode(), passphrase)
    signing = serialization.load_pem_private_key(bundle["signing_key"].encode(), passphrase)
    if not isinstance(encryption, rsa.RSAPrivateKey) or encryption.key_size not in (3072, 4096) or not isinstance(signing, ed25519.Ed25519PrivateKey):
        raise ValueError("unsupported local identity keys")
    public_bundle(bundle["extension"], encryption.public_key(), signing.public_key())
    return bundle["extension"], encryption, signing


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("keygen")
    create.add_argument("--extension", required=True)
    create.add_argument("--private", required=True)
    create.add_argument("--public", required=True)
    for command in ("encrypt", "decrypt", "sign-sdp", "verify-sdp"):
        cmd = sub.add_parser(command)
        cmd.add_argument("--private", required=True)
        cmd.add_argument("--peer", required=True)
        cmd.add_argument("--peer-fingerprint", required=True)
        if command == "decrypt":
            cmd.add_argument("--replay-db", required=True)
        if command.endswith("sdp"):
            cmd.add_argument("--sdp", required=True)
            cmd.add_argument("--call-id", required=True)
            cmd.add_argument("--role", choices=("offer", "answer"), required=True)
    args = parser.parse_args()
    password = getpass.getpass("Local private-key passphrase: ").encode()
    if args.command == "keygen":
        if len(password) < 12 or password != getpass.getpass("Confirm passphrase: ").encode():
            raise ValueError("matching passphrase of at least 12 bytes required")
        encryption = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        signing = ed25519.Ed25519PrivateKey.generate()
        pub = public_bundle(args.extension, encryption.public_key(), signing.public_key())
        private = {"version": 1, "extension": args.extension}
        for name, key in (("encryption_key", encryption), ("signing_key", signing)):
            private[name] = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.BestAvailableEncryption(password)).decode()
        write_new(args.private, canonical(private), 0o600)
        write_new(args.public, canonical(pub), 0o644)
        print(bundle_fingerprint(pub))
        return
    extension, encryption, signing = load_private(args.private, password)
    peer = parse_json(Path(args.peer).read_bytes())
    trusted_peer(peer, args.peer_fingerprint)
    if args.command == "encrypt":
        result = encrypt_message(extension, signing, peer, args.peer_fingerprint, sys.stdin.read(1801))
    elif args.command == "decrypt":
        # Exactly one terminal newline is allowed by the CLI. Wire bodies have none.
        result = decrypt_message(extension, encryption, peer, args.peer_fingerprint,
                                 sys.stdin.read(MAX_BODY + 2).removesuffix("\n"), args.replay_db)
    else:
        sdp = Path(args.sdp).read_bytes()
        if args.command == "sign-sdp":
            result = sign_sdp(extension, signing, peer["extension"], args.call_id, args.role, sdp)
        else:
            verify_sdp(peer, args.peer_fingerprint, extension, args.call_id, args.role, sdp,
                       sys.stdin.read(2050).removesuffix("\n"))
            result = "Verified"
    print(result)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # No decrypted plaintext, key material or detailed oracle errors in logs.
        print("Rejected: key, identity, ciphertext, replay state or input validation failed.", file=sys.stderr)
        sys.exit(1)
