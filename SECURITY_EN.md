# Security boundaries and validation

[中文](SECURITY.md) · [Home](README_EN.md) · [Deployment](DEPLOYMENT_EN.md)

Updated 2026-10-14. Applies to current source and reference tools, not a published image, production deployment or independent cryptographic audit.

## Profile boundaries

| Profile | Server media capabilities | Required endpoint verification |
| --- | --- | --- |
| ZRTP: `[media] mode = "zrtp"` | Forwards handshake/media unchanged; holds no media keys; cannot distinguish plaintext/ciphertext RTP payloads or verify SRTP/SRTCP tags | Require ZRTP, authenticate media, compare SAS; see [ZRTP_EN.md](ZRTP_EN.md) |
| SDES: `[media] mode = "sdes"` or mode omitted | Holds per-leg keys and decrypts/re-encrypts audio; not end-to-end encrypted | TLS certificate verification and SDES-SRTP |
| Signed DTLS: no `[media]` | Routes SDP unchanged with no media relay; checks identity envelope admission only | Pin peer public keys, verify Ed25519 signatures and actual DTLS fingerprints; see [E2EE_EN.md](E2EE_EN.md) |

ZRTP Hello hashes associate media sources with SIP sessions; they do not replace SAS or prove completed key exchange. A server can modify signaling. Server login authentication is not peer identity authentication. The relay offers no encryption fallback, but endpoints must prohibit plaintext media.

MESSAGE in every profile accepts only restricted RSA-OAEP-256 / AES-256-GCM JWE. Only receiving endpoints can verify the inner Ed25519 signature and plaintext; the server checks the outer envelope. Endpoints must verify AEAD, signatures, identities, validity and persistent replay state before display. Ordinary SIP text and unrelated native chat protocols are incompatible.

## Shared protections and media restrictions

- SIP/TLS with client certificate verification; self-signed keys use 0600 permissions, automatic renewal and TLS reload.
- Digest `qop=auth` defaults to SHA-256 and rejects MD5/omitted algorithms. Only explicit `[server] digest_algorithm = "md5"` enables MD5; algorithm omission then means MD5. No automatic downgrade. Nonces bind accounts/connections, expire in five minutes and require increasing nc values.
- Register before use; From matches authenticated identity. Dialog actions bind original TLS channels and direction, responses check CSeq, and expired/replaced registrations revoke old identities.
- Duplicate critical headers, folded headers and control characters rejected; Digest credentials removed before delivery/queueing; forged From handled.
- Invalid early SDP cancels the outbound INVITE; invalid 200 answers trigger ACK/BYE for valid peer dialogs and cleanup.
- ZRTP RTP sources pin only after Hello matches SDP. At most one initial Hello is cached per side. Other sources cannot replace addresses. Separate RTCP sources must share the RTP source IP; endpoints still authenticate SRTCP. Address changes require redialing.
- SDES learns NAT addresses from authenticated SRTP and checks replay. AES-CM/GCM supported; separate RTCP forwarding unavailable.
- Signed DTLS rejects SDES, SDP keys, plaintext profiles and missing identities. SDP/signatures remain unchanged; endpoints independently verify signatures.
- Endpoint tools generate keys locally, use encrypted PKCS#8, exclusive 0600 files and persistent SQLite replay state; no SIP dialing or media implementation.
- Non-root containers, read-only root filesystems, no capabilities/privilege escalation; placeholder passwords and passwords shorter than 12 bytes rejected.

## Capacity

| Resource | Limit |
| --- | --- |
| TCP/TLS | 256 connections; 10-second handshake; unauthenticated/authenticated idle limits 120/3600 seconds |
| Frames/processing | Headers 16 KiB, frame 64 KiB; incomplete frame 15 seconds; processing/writes 10 seconds; queue 16 items |
| Rates | 300 SIP messages/minute/connection; 60 REGISTER requests/minute/source IP, including challenges/retries |
| Extensions/registration | 10000 extensions; one account/connection; registration up to 3600 seconds |
| Calls | Two/caller, 256 globally; pending 120 seconds, established four hours; 30-second cleanup cycle; media pool may impose lower limits |
| MESSAGE | Body 4 KiB, request 8 KiB; offline TTL 24 hours, 100/recipient, 10000 globally |
| Offline sender quotas | 120/minute and 500 concurrently/sender; full recipient queues evict oldest entries |

Offline queues are in memory and lost at restart. 200 means server acceptance, not endpoint verification/decryption. Assess source-IP limits for large shared NAT deployments.

Every profile supports one active audio stream, without video, offerless calls, re-INVITE or media negotiation in ACK. Signed DTLS requires RTCP mux and endpoint ICE/separate TURN when needed. ZRTP disables ICE and supports mux/separate RTCP; SDES uses the server relay. See [deployment](DEPLOYMENT_EN.md) for port pool capacity.

## Guarantees not provided

The server observes accounts, addresses, SDP, call times and ciphertext lengths and can block, delay or replay traffic. Metadata anonymity and network availability are not provided. Compromised endpoints or private keys can expose content.

Static RSA message encapsulation lacks forward secrecy, post-compromise recovery and Double Ratchet. A future recipient private-key compromise can decrypt recorded messages. Multi-device support, groups, automatic rotation/revocation and encrypted backups are absent. Replay state and identity trust must persist.

Separate TURN must not terminate DTLS. Malicious same-IP sources or attackers observing ZRTP handshakes can still cause denial of service. Source tests cannot replace real-client acceptance, dependency auditing or independent security review.

## Validation and reproduction

The current code passed 124 Rust tests, Release build, Clippy, formatting and diff checks. Existing unused-code/style warnings remain. Tests send actual local UDP packets: bidirectional Bria AES-CM/GCM decrypt/re-encrypt; ZRTP hashes and handshake byte forwarding; unchanged SRTP forwarding with independent endpoint keys and endpoint decryption; RTCP byte forwarding; downgrade, bind-failure and early hash-change rejection; resource cleanup.

ZRTP Hello and RTCP packets are constructed fixtures. Tests do not perform a real ZRTP key exchange, SAS check or cryptographic SRTCP verification. The voice changes did not rerun Python client/TLS tests, container operation or Cargo Audit, publish images or modify deployment configuration. Real audio, cross-network interoperability and mandatory endpoint encryption need acceptance. Historical audits do not establish current dependency safety.

```bash
cargo test --locked
cargo build --release --locked
cargo clippy --locked --all-targets
cargo fmt --check
git diff --check
# Both focused tests require local UDP bind permissions.
cargo test --locked bria_profile -- --nocapture
cargo test --locked zrtp_profile -- --nocapture
docker compose config --quiet
# After installing endpoint tool dependencies:
python -m unittest discover -s tools -p 'test_e2ee_client.py' -v
MINGHE_BINARY=/absolute/path/to/target/release/minghe \
  python -m unittest discover -s tools -p 'test_e2ee_transport.py' -v
# Install cargo-audit separately and refresh the audit before release.
cargo audit
```

Dependencies are in `tools/requirements-e2ee.txt`. TLS/SIP integration uses temporary identities, certificates and configuration on 127.0.0.1 to check registration, offline ciphertext delivery, replay rejection and signed SDP routing; it sends no audio. See [E2EE_EN.md](E2EE_EN.md) for protocol and tool usage.

MD5 compatibility tests cover the standard Digest vector, configuration defaults, algorithm isolation, registration, wrong passwords, connection/identity binding, required qop and replay rejection. MD5 is used only for SIP login, not ZRTP, DTLS, SRTP or JWE. Authentication is weaker than SHA-256; use strong random passwords and keep TLS verification enabled. Real Bria Mobile registration still requires deployment acceptance.
