# MingHe (鸣鹤)

A Rust SIP/TLS signaling router for clients implementing end-to-end encrypted calls and messages.

[中文](README.md) · [E2EE integration specification](E2EE_EN.md) · [Security](SECURITY_EN.md) · [Deployment and migration](DEPLOYMENT_EN.md)

**Current source requires a new client protocol profile. The server has no media keys or decryption relay and rejects plaintext messages. Existing SDES-only phones cannot continue unchanged. This repository does not include a complete softphone: actual clients must integrate identity signatures, DTLS-SRTP and encrypted messaging.**

## Features

- SIP over TLS on TCP 5061; clients must verify the server certificate.
- SHA-256 Digest `qop=auth`, identity/connection-bound nonces, expiry and replay protection. MD5 and omitted algorithms are rejected.
- Unmodified SDP transport with mandatory DTLS-SRTP, SHA-256 fingerprints, RTCP mux and a signed identity envelope. SDES and plaintext downgrade are rejected.
- Encrypted `application/jose` MESSAGE delivery and offline storage. Digest headers are removed before forwarding or queueing.
- Endpoint reference tool: RSA-OAEP-256 / AES-256-GCM, Ed25519 signatures, independently pinned public bundles, encrypted private keys and persistent replay detection.
- Connection authentication, dialog ownership checks, bounded frames/queues, rate limits and timeouts.
- Renewable self-signed certificates, TLS reload and non-root Docker deployment.

## Required client security

Endpoints generate and retain their own private keys. Users must independently confirm public bundle fingerprints and pin them to identities. The receiver verifies signed SDP using the pinned peer key, then compares the actual DTLS certificate with that signed fingerprint before sending media. For messages, verify the AEAD tag, inner signature, sender, recipient, timestamps and durable replay state before displaying plaintext.

Server authentication and envelope checks cannot replace these endpoint checks. The server still sees identities, IPs, timing and ciphertext lengths and can block communication. Static RSA message encryption does not provide forward secrecy or post-compromise recovery. There is no multi-device or group protocol, key revocation service or message ratchet. See [E2EE_EN.md](E2EE_EN.md) for exact wire formats and runnable endpoint helper commands.

## Setup

Complete client integration and fingerprint verification first. Do not put user content keys on this server.

```bash
mkdir -p config
cp config.template.toml config/config.toml
chmod 600 config/config.toml
# Replace host and ALL enabled password placeholders.
```

Passwords must be random, at least 12 bytes. Use a different password for every extension; a shared default allows its holder to log in to every account using it.

Rust 1.88+:

```bash
cargo build --release --locked
./target/release/minghe -c config/config.toml
```

Build Docker from current source:

```bash
docker compose up -d --build
docker compose logs -f
```

Configuration must be readable by container UID 10001; host-owned 0600 files need explicit access on Linux bind mounts. See [deployment and migration](DEPLOYMENT_EN.md) for port variables, certificate volumes and release behavior.

Compose builds `minghe:local` and persists certificates in a named volume. Only the fixed SIP/TLS TCP port is exposed. No RTP UDP ports are allocated. A legacy `[media]` configuration is read for migration compatibility but is ignored with a warning. Clients need ICE/STUN and, where required, an independent TURN service forwarding encrypted DTLS/SRTP. MingHe does not provide TURN.

Use a trusted CA certificate in production. For self-signed deployments, import `certs/server.crt` into client trust and keep certificate verification enabled; update trust after renewal. Trust in the SIP server certificate is separate from trust in the peer identity.

The Docker Hub `latest` image has not been published as part of these source changes.

## Methods and limits

REGISTER, INVITE, ACK, BYE, CANCEL, OPTIONS and MESSAGE are supported. Initial INVITE requires signed SDP. Only one active audio stream with RTCP mux is supported. Offerless calls, re-INVITE, video and SDP in ACK are unsupported.

At most 2 calls per caller and 256 calls globally. Pending calls expire after 120 seconds, established calls after 4 hours. Registration lasts at most 1 hour; a connection binds only one account.

MESSAGE body: 4 KiB; complete request: 8 KiB. Offline ciphertext is retained in memory for 24 hours, capped at 100 messages per recipient and 10000 globally. Each sender may queue at most 120 per minute and hold 500 pending messages. A 200 response acknowledges server admission, not recipient authentication or decryption. Restarting loses pending messages.

## Development

```bash
cargo test --locked
cargo clippy --locked --all-targets
cargo fmt --check
# Within the endpoint tool Python environment:
python -m unittest discover -s tools -p 'test_e2ee_client.py' -v
```

`src/sip/e2ee.rs` contains admission policy; the router preserves signed SDP; the message service transports ciphertext; the registrar handles authentication. `tools/e2ee_client.py` is the endpoint reference implementation, not a softphone. Old media crypto and SDP rewrite helpers compile only for historical regression tests, never into the production server.

Loopback TLS/SIP tests verify registration, offline ciphertext delivery, endpoint decryption and signed SDP routing. Actual client interoperability, cross-NAT audio and container execution still require deployment validation. Tests are not a complete independent security audit.

## License

[Apache License 2.0](LICENSE). Copyright 2026 MingHe Contributors.
