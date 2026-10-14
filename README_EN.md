# MingHe (鸣鹤)

A Rust SIP/TLS extension service supporting Bria SRTP media relay and an endpoint-integrated E2EE profile.

[中文](README.md) · [Bria deployment](BRIA_EN.md) · [E2EE integration specification](E2EE_EN.md) · [Security](SECURITY_EN.md) · [Deployment and migration](DEPLOYMENT_EN.md)

**Two explicit call profiles are supported. Without `[media]`, clients use signed SDP and DTLS-SRTP. With `[media]`, Bria-compatible TLS + SDES-SRTP media relay is enabled: the server decrypts and re-encrypts audio, so this profile is not E2EE. Existing `[media]` settings are honored again. Plaintext RTP and plaintext MESSAGE are rejected. See [Bria deployment](BRIA_EN.md).**

## Features

- SIP over TLS on TCP 5061; clients must verify the server certificate.
- SHA-256 Digest `qop=auth`, identity/connection-bound nonces, expiry and replay protection. MD5 and omitted algorithms are rejected.
- In the default E2EE profile: unmodified SDP transport with mandatory DTLS-SRTP, SHA-256 fingerprints, RTCP mux and a signed identity envelope. SDES and plaintext downgrade are rejected.
- Bria profile: rewrite SDP to server media addresses/ports, decrypt and re-encrypt SRTP with separate keys, and learn NAT destinations from authenticated packets.
- Encrypted `application/jose` MESSAGE delivery and offline storage. Digest headers are removed before forwarding or queueing.
- Endpoint reference tool: RSA-OAEP-256 / AES-256-GCM, Ed25519 signatures, independently pinned public bundles, encrypted private keys and persistent replay detection.
- Connection authentication, dialog ownership checks, bounded frames/queues, rate limits and timeouts.
- Renewable self-signed certificates, TLS reload and non-root Docker deployment.

## Profile selection

| Configuration | Media path | Client requirements | Encryption boundary |
| --- | --- | --- | --- |
| Keep `[media]` | Server SRTP relay | SIP/TLS, SHA-256 Digest and SDES-SRTP; intended for Bria | Server can decrypt audio; not E2EE |
| Omit `[media]` | Endpoint ICE/DTLS connection | Signed SDP, DTLS-SRTP and peer identity checks | Endpoints establish media keys; server does not decrypt |

Both profiles require JWE MESSAGE; ordinary Bria text messages are unsupported. The template comments out `[media]`; Bria users must enable it and supply a reachable public IPv4. Startup configuration selects the profile, with no automatic per-call fallback.

## Required E2EE client security

Endpoints generate and retain their own private keys. Users must independently confirm public bundle fingerprints and pin them to identities. The receiver verifies signed SDP using the pinned peer key, then compares the actual DTLS certificate with that signed fingerprint before sending media. For messages, verify the AEAD tag, inner signature, sender, recipient, timestamps and durable replay state before displaying plaintext.

Server authentication and envelope checks cannot replace these endpoint checks. The server still sees identities, IPs, timing and ciphertext lengths and can block communication. Static RSA message encryption does not provide forward secrecy or post-compromise recovery. There is no multi-device or group protocol, key revocation service or message ratchet. See [E2EE_EN.md](E2EE_EN.md) for exact wire formats and runnable endpoint helper commands.

## Setup

For Bria, follow [BRIA_EN.md](BRIA_EN.md) and restore `[media]`. For E2EE, complete client integration and fingerprint verification first. Do not put user content keys on this server.

```bash
mkdir -p config
cp config.template.toml config/config.toml
chmod 600 config/config.toml
# Replace host and ALL enabled password placeholders.
```

For the full configuration example, use [config.template.toml](config.template.toml). For Bria, add the `[media]` section documented in [BRIA_EN.md](BRIA_EN.md).

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

Compose builds the configured image from local source and persists certificates in a named volume. SIP/TLS TCP and UDP 20000–20020 are mapped; the UDP mapping must match `[media]`. Media ports are allocated only in the compatibility profile.

Use a trusted CA certificate in production. For self-signed deployments, import `certs/server.crt` into client trust and keep certificate verification enabled; update trust after renewal. Trust in the SIP server certificate is separate from trust in the peer identity.

The Docker Hub `latest` image has not been published as part of these source changes.

## Methods and limits

REGISTER, INVITE, ACK, BYE, CANCEL, OPTIONS and MESSAGE are supported. Initial INVITE requires SDP. The E2EE profile requires signed SDP and RTCP mux; the Bria profile requires SDES-SRTP. Both accept one active audio stream. Offerless calls, re-INVITE, video and SDP in ACK are unsupported.

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

`src/sip/e2ee.rs` contains admission policy; `router.rs` selects the profile and preserves signed SDP; `sdes_router.rs` handles Bria calls and SRTP relay; the message service transports ciphertext; the registrar handles authentication. `tools/e2ee_client.py` is the endpoint reference implementation, not a softphone. The SRTP relay and SDP rewrite helpers run only when `[media]` explicitly selects the Bria compatibility profile.

The current fix passed 116 Rust regression tests, release build, Clippy, formatting and diff checks; Clippy retains unused-code/style warnings. The new test sends real UDP SRTP packets through INVITE, 200, ACK, bidirectional AES-CM/GCM decryption/re-encryption and BYE. Existing TLS/SIP integration tests cover registration, offline ciphertext delivery, endpoint decryption and signed SDP routing. Actual Bria cross-network calls and container startup still require deployment validation; see [the security record](SECURITY_EN.md).

## License

[Apache License 2.0](LICENSE). Copyright 2026 MingHe Contributors.
