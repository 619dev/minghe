# Security mechanisms and verification record

**Profile scope:** The E2EE guarantees below apply only without `[media]`. With `[media]`, the restored Bria SDES-SRTP relay holds media keys and decrypts/re-encrypts audio; it is not E2EE. SIP authentication, dialog ownership and JWE MESSAGE restrictions remain. See [BRIA_EN.md](BRIA_EN.md).

[中文](SECURITY.md) · [E2EE specification](E2EE_EN.md) · [Deployment and migration](DEPLOYMENT_EN.md)

Updated 2026-10-14. This record covers repository source, endpoint helpers and local tests. It does not establish published-image behavior, production deployment or an independent cryptographic audit.

## Encryption boundary

Without `[media]`, the server routes signaling and encrypted MESSAGE only. The explicit Bria profile includes SDES key negotiation and SRTP decryption/re-encryption. Media crypto dependencies are runtime dependencies. Docker maps UDP 20000–20020 for that profile.

In the E2EE profile, endpoints establish DTLS-SRTP. Signed SDP binds identities, Call-ID, offer/answer role, exact SDP bytes and time. Server envelope admission is not signature verification: endpoints must independently pin peer keys, verify signatures and match actual DTLS certificates to the signed fingerprints. Missing or failed checks must stop the call.

Messages use RSA-OAEP-256 / AES-256-GCM JWE containing an Ed25519-signed JWT. Endpoints generate private keys, content keys and nonces locally. They verify AEAD, signatures, identities, expiration and durable replay state before showing plaintext. The server cannot validate the encrypted inner signature. See [the full integration specification](E2EE_EN.md); this repository does not contain a complete softphone.

## Implemented controls

| Control | Behavior |
| --- | --- |
| E2EE downgrade rejection | Offers and SDP-bearing early/final answers require DTLS-SRTP, SHA-256 fingerprint, setup, RTCP mux and identity envelopes; reject plaintext, SDES and SDP keys |
| E2EE key isolation | The E2EE profile starts no media decryption contexts or relay tasks; server configuration contains no endpoint private keys |
| Bria relay boundary | Explicit `[media]` enables SDES-SRTP decryption/re-encryption with separate keys, authenticated NAT destination learning and SRTP replay checks; signed E2EE offers and plaintext RTP are rejected |
| E2EE negotiation binding | Preserve SDP and identity signatures; bind envelopes to accounts, calls, roles, hashes and time; endpoint verifies cryptography |
| Rejected-call cleanup | Cancel incompatible early responses using the INVITE branch; ACK/BYE invalid final answers with valid callee dialog tags |
| Message admission | Require restricted five-segment JWE; reject plaintext, signature-only messages, weak algorithms, compression, key URLs and duplicate/unknown JOSE fields |
| Endpoint integrity/replay | Verify GCM, Ed25519, identities, UUID v4 and time; transactionally persist SQLite replay state before output, reject database failures and repeats after restart |
| Endpoint key storage | Password-encrypted PKCS#8, exclusively created 0600 private files, independently verified public bundles, no silent replacement |
| Registration | SHA-256 Digest `qop=auth`; reject MD5, missing algorithms and malformed responses; account/connection-bound nonces expire in 5 minutes; atomic increasing nonce counts |
| Identity/dialog ownership | REGISTER first; From matches authenticated account; dialog methods bind original connections and direction; validate callee CSeq; replacement/expiration invalidates old identity |
| Framing/credentials | Reject duplicate critical headers (including compact Content-Type), folding and control characters; reject unverified dialog bodies; remove Digest credentials and forged From before delivery/storage |
| Passwords/TLS | Reject placeholder or sub-12-byte passwords; write self-signed private keys with 0600 permissions and atomic replacement; clients must verify TLS |
| Capacity/deployment | Bound connections, frames, queues, rates and calls; check call quotas (the E2EE profile also rechecks on insertion); non-root container, read-only root, dropped capabilities and no privilege escalation |

## Limits

- 256 TCP/TLS connections; handshake 10 seconds; unauthenticated idle 120 seconds, authenticated idle 3600 seconds; incomplete frames 15 seconds; request processing/writes 10 seconds.
- 300 SIP messages per connection per minute; 60 REGISTER requests per source IP per minute, including challenges/retries. Evaluate shared-NAT capacity.
- 16 KiB headers, 64 KiB frames, 16 queued outbound frames, at most 10000 extension numbers.
- Registration at most 3600 seconds and one account per connection; 2 calls per caller, 256 globally; pending timeout 120 seconds, established timeout 4 hours, cleanup every 30 seconds.
- MESSAGE body 4 KiB, request 8 KiB; offline TTL 24 hours, 100 per recipient (evict oldest when full), 10000 globally; each sender may queue 120 per minute and hold 500 pending. Queues are memory-only; 200 does not acknowledge recipient decryption.
- One active audio stream; RTCP mux is required in the E2EE profile; no offerless, video, re-INVITE or media negotiation in ACK. E2EE endpoints provide ICE/STUN and independent TURN where needed. Bria instead needs a reachable relay IPv4 and matching UDP mappings/firewall rules.

## Remaining boundaries

The server sees metadata and SDP and can drop, delay or replay traffic. Endpoint compromise can expose plaintext. SIP credentials and server TLS certificates do not establish peer identity.

Static RSA messaging has **no forward secrecy, post-compromise recovery or Double Ratchet**. Later recipient-key compromise can expose recorded ciphertext. Multi-device, groups, automated rotation/revocation, recovery and encrypted backups are unimplemented. Keep replay databases and peer trust persistent; do not reuse completed call contexts.

TURN must not terminate DTLS. Do not disable TLS, signature or AEAD checks for compatibility. Tests do not establish absence of vulnerabilities. Actual clients, cross-NAT audio and container startup still need validation; deployment firewalls and upstream rate controls are needed where stronger traffic protection is required.

## Verification and release

The Bria fix passed 116 Rust regression tests, release build, Clippy, formatting and diff checks; `docker compose config --quiet` also passed. A new Rust test sends actual local UDP SRTP packets through INVITE, 200, ACK, bidirectional AES-CM/GCM decryption/re-encryption and BYE, and verifies that signed offers do not enter the relay. The earlier E2EE implementation recorded 7 endpoint cryptography tests and 1 loopback TLS/SIP integration test; these Python tests were not rerun for the Bria fix or this documentation update. Reproduce with:

```bash
cargo test --locked
cargo build --release --locked
cargo clippy --locked --all-targets
cargo fmt --check
git diff --check
docker compose config --quiet
# Targeted regression; requires permission to bind local UDP sockets:
cargo test --locked bria_profile -- --nocapture
python -m unittest discover -s tools -p 'test_e2ee_client.py' -v
MINGHE_BINARY=/absolute/path/to/target/release/minghe \
  python -m unittest discover -s tools -p 'test_e2ee_transport.py' -v
```

Install `tools/requirements-e2ee.txt` in the endpoint Python environment first. The transport test listens only on loopback, uses temporary identities/configuration/certificates and checks TLS verification, SHA-256 registration, offline ciphertext delivery, endpoint replay rejection and real signed SDP routing. It sends no audio.

Clippy retains unused-code/style warnings. Compose configuration validation is not a container startup test. Container execution and RustSec dependency auditing were not performed for the Bria fix. The old 2026-09-29 audit cannot establish this revision's status. Run a fresh dependency audit, validate real clients and cross-NAT media, and obtain independent review before release.

No image publication or production deployment was performed. Compose sets `build: .` and `image: facilisvelox/minghe:latest`; `up --build` builds and tags local source without publishing. A remote `latest` is not evidence that this fix is included.
