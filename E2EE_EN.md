# End-to-end encryption integration specification

[中文](E2EE.md) · [Security](SECURITY_EN.md) · [Deployment and migration](DEPLOYMENT_EN.md)

MingHe routes signaling and encrypted messages. It does not exchange media keys or run a UDP decryption relay. SDES-SRTP, plaintext RTP and plaintext MESSAGE are rejected without a downgrade switch.

**This repository provides server admission rules and an endpoint cryptographic reference tool, not a complete softphone. Clients must implement identity verification, DTLS-SRTP and the message profile below. Updating the server alone does not adapt existing Bria or Linkvil configurations.**

## Identity and key trust

Each endpoint generates its own RSA-3072/4096 message encryption key and Ed25519 signing key. Never upload private keys to the server, generate them there or derive them from SIP passwords. The reference generator creates RSA-3072 keys.

A public bundle contains exactly `version` (1), `extension`, `encryption_key` and `signing_key`. Keys are unpadded base64url SPKI DER. Its fingerprint is SHA-256 over canonical UTF-8 JSON with sorted keys and no extra whitespace. Independently compare this fingerprint over an already trusted channel and persist the identity binding. Automatically trusting a bundle supplied by this server does not protect against a malicious server.

Key replacement, identity changes and additional devices require renewed verification. SIP authentication is separate from peer identity trust. The reference tool writes password-encrypted PKCS#8 private keys to exclusively created 0600 files and refuses overwrites. Production clients need a system key store and a device/recovery/revocation design.

## Calls

Endpoints implement [DTLS-SRTP negotiation (RFC 5763)](https://www.rfc-editor.org/rfc/rfc5763.html) and [key establishment (RFC 5764)](https://www.rfc-editor.org/rfc/rfc5764.html). Only one active audio stream is accepted:

```sdp
v=0
o=- 1 1 IN IP4 192.0.2.1
s=-
c=IN IP4 192.0.2.1
t=0 0
m=audio 4000 UDP/TLS/RTP/SAVPF 111
a=fingerprint:sha-256 AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB
a=setup:actpass
a=rtcp-mux
```

Actual SDP uses CRLF, including the final line. Replace the example fingerprint with the endpoint certificate's SHA-256 fingerprint. Supported protocols are `UDP/TLS/RTP/SAVP` and `UDP/TLS/RTP/SAVPF`; offer setup is `actpass`, answer setup is `active` or `passive`. Session-level fingerprint/setup and media-level overrides are supported. Duplicate attributes within one scope, SHA-1 or all-zero fingerprints, SDES `a=crypto`, SDP `k=`, plaintext protocols, multiple streams, zero ports and missing media RTCP mux are rejected. Initial INVITE must contain an offer; offerless calls, re-INVITE, video and SDP in ACK are unsupported.

Every offer, early answer (such as 183) and final answer carries:

```text
Content-Type: application/sdp
X-Minghe-Identity: <compact JWS>
```

The Ed25519 JWS protected header contains exactly `alg=EdDSA`, `typ=minghe-sdp+jwt`, and `kid` (lowercase hexadecimal SHA-256 of the signing public key SPKI DER). Its payload contains exactly:

| Field | Value |
| --- | --- |
| `iss`, `aud` | Sender and recipient extension strings |
| `call_id` | SIP Call-ID |
| `role` | `offer` or `answer` |
| `sdp_sha256` | Lowercase hexadecimal SHA-256 of exact SDP bytes |
| `iat`, `exp` | Integer Unix seconds; lifetime at most 120 seconds |

The server checks envelope structure, identities, direction, Call-ID, byte hash and time, then preserves the SDP and signature. **It does not verify the Ed25519 signature.** The receiver must verify it with the independently pinned peer key and check all expected claims before using the SDP. Allow at most 30 seconds of future clock skew and reject expired envelopes. Do not reuse completed call contexts; registration must not reset peer trust.

Before sending media, compare the actual DTLS handshake certificate fingerprint against the verified SDP. Use modern DTLS with ephemeral key exchange, reject weak SRTP suites and plaintext fallback, and enable SRTP replay protection. Both signature verification and DTLS certificate binding are required.

Endpoints handle ICE/STUN and, if necessary, an independent TURN service. TURN must forward encrypted DTLS/SRTP without terminating DTLS. MingHe supplies neither TURN nor media ports. Connectivity failure must fail the call rather than fall back to a decryption relay.

Invalid early SDP yields 488 and cancellation of the callee INVITE transaction. Invalid 200 answers yield 488; where a valid callee dialog tag exists, the server sends ACK/BYE and releases the call. Endpoints still handle errors and timeouts themselves.

## Messages

Use [JWE Compact Serialization (RFC 7516)](https://www.rfc-editor.org/rfc/rfc7516.html): five unpadded base64url segments, no line breaks, with `Content-Type: application/jose`. This is a client integration profile, not automatic compatibility with existing SIP text clients.

The protected header contains exactly:

```json
{"alg":"RSA-OAEP-256","enc":"A256GCM","cty":"JWT","kid":"lowercase SHA-256 of recipient encryption SPKI DER"}
```

Generate a fresh random 256-bit content key and 96-bit nonce per message. Wrap the content key with RSA OAEP using SHA-256 and MGF1-SHA-256. AES-256-GCM authenticates the encoded protected header as AAD and produces a 128-bit tag. Wrapped keys are 384 or 512 bytes. Reject `RSA1_5`, `dir`, compression, remote key URLs, duplicate/unknown header fields and algorithm fallback.

Before encryption, sign an inner JWT with Ed25519. Its protected header contains exactly `alg=EdDSA`, `typ=JWT`, and signing-key `kid`. Claims are exactly `iss`, `aud`, `jti` (UUID v4), `iat`, `exp`, and `text`. Lifetime is at most 24 hours; sender time may lead the receiver by at most 30 seconds and expiration must be strictly later than current time. The inner signature establishes sender identity; the server's From header does not.

The receiver verifies the expected local recipient key and GCM tag, verifies the inner signature with the pinned sender key, checks identities and time, then transactionally persists `(sender, recipient, jti)` before exposing plaintext. Reject repeats, invalid data and database failures. Keep replay state across restarts and avoid returning detailed decryption errors to the server.

The server only checks the outer envelope: structural acceptance cannot prove cryptographic validity. Forwarding and offline storage preserve ciphertext and remove Digest credentials and forged From information. Limits remain 4 KiB body, 8 KiB request, 24-hour offline TTL and bounded queues. A 200 response means server admission, not successful recipient decryption.

The helper accepts nonempty text up to 1800 UTF-8 bytes and checks the final ciphertext against 4096 bytes. RSA-4096 and JSON escaping can require shorter text.

## Endpoint reference tool

`tools/e2ee_client.py` uses pyca/cryptography. It generates keys, encrypts/decrypts messages and signs/verifies SDP. It does not send SIP, negotiate ICE/DTLS or play audio. Run on each endpoint's own device; do not create real user private keys in the server deployment directory.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r tools/requirements-e2ee.txt
mkdir -p e2ee-keys
.venv/bin/python tools/e2ee_client.py keygen --extension 1001 \
  --private e2ee-keys/1001.private.json --public e2ee-keys/1001.public.json
```

The command interactively reads and confirms a private-key password of at least 12 bytes and prints the public bundle fingerprint. Generate extension 1002 independently on its device. Exchange only public bundles, independently verify fingerprints and preserve them. Replace the quoted placeholders below before running:

```bash
# On 1001: stdin is plaintext; stdout becomes MESSAGE body.
.venv/bin/python tools/e2ee_client.py encrypt \
  --private e2ee-keys/1001.private.json --peer e2ee-keys/1002.public.json \
  --peer-fingerprint 'VERIFIED_1002_FINGERPRINT'

# On 1002: stdin is received JWE; retain this replay database.
.venv/bin/python tools/e2ee_client.py decrypt \
  --private e2ee-keys/1002.private.json --peer e2ee-keys/1001.public.json \
  --peer-fingerprint 'VERIFIED_1001_FINGERPRINT' --replay-db e2ee-keys/received.sqlite3

# Sign the endpoint's actual CRLF SDP; stdout becomes X-Minghe-Identity.
.venv/bin/python tools/e2ee_client.py sign-sdp \
  --private e2ee-keys/1001.private.json --peer e2ee-keys/1002.public.json \
  --peer-fingerprint 'VERIFIED_1002_FINGERPRINT' \
  --sdp offer.sdp --call-id 'CURRENT_CALL_ID' --role offer

# Verify before DTLS; stdin is the received identity header value.
.venv/bin/python tools/e2ee_client.py verify-sdp \
  --private e2ee-keys/1002.private.json --peer e2ee-keys/1001.public.json \
  --peer-fingerprint 'VERIFIED_1001_FINGERPRINT' \
  --sdp received-offer.sdp --call-id 'EXPECTED_CALL_ID' --role offer
```

End stdin with EOF. Strip the CLI's terminal output newline when placing values into SIP headers/bodies; Content-Length counts final body bytes. Client integrations may call module functions and replace file storage with a trusted local key store.

## Remaining boundaries

The server sees accounts, online status, IPs, SDP, timing and ciphertext sizes and can block, delay, replay or drop traffic. This profile does not provide metadata anonymity or availability guarantees. Endpoint compromise can reveal content.

**Static RSA message wrapping provides neither forward secrecy nor post-compromise recovery.** Later compromise of a recipient private key can decrypt previously recorded messages. This is not equivalent to Signal; a prekey/Double Ratchet protocol requires a separate audited implementation.

The reference implementation is single-device, with no groups, device synchronization, automatic rotation/revocation, trusted key directory or encrypted backup. Protect persistent identity and replay state. SIP server certificate trust does not replace peer identity verification.

Tests cover real encryption, tampering, identity replacement, expiration, persistent replay, SDP direction/Call-ID binding and loopback TLS/SIP transport. Actual softphone interoperability, cross-NAT connectivity and real audio remain unverified. Complete endpoint integration and independent security review before production use.
