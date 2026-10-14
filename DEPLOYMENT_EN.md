# Deployment, migration and release

[中文](DEPLOYMENT.md) · [Home](README_EN.md) · [E2EE profile](E2EE_EN.md) · [Security record](SECURITY_EN.md)

## Bria compatibility profile

For existing Bria users, keep or restore `[media]`, set a reachable public IPv4 and expose the matching UDP range. Follow [BRIA_EN.md](BRIA_EN.md). This explicitly enables TLS + SDES-SRTP relay, where the server terminates media encryption. The migration instructions below apply to the default E2EE profile without `[media]`.

## Migrating to the E2EE profile

The E2EE profile is incompatible with unadapted Bria/SDES clients. First integrate SHA-256 Digest `qop=auth`, signed SDP, DTLS-SRTP and JWE MESSAGE on two actual endpoints and independently verify peer bundle fingerprints. The reference helper does not implement dialing or media. Generate and retain user private keys only on endpoints, never in server configuration, images or volumes.

When selecting E2EE, remove the entire `[media]` section and remove the server relay UDP mapping/firewall rules. Keeping `[media]` selects Bria relay instead. Endpoints configure ICE/STUN and independent TURN that does not terminate DTLS. Never disable certificate verification or accept SDES/plaintext fallback to restore compatibility.

Back up server configuration and TLS certificates; protect endpoint identities, pinned fingerprints and durable replay databases. Offline ciphertext queues are memory-only and are lost on restart. Rolling back restores the older security boundary and cannot preserve the current encryption claims.

## Configuration and startup

For a fresh deployment, copy [config.template.toml](config.template.toml) to `config/config.toml`, replace host and all enabled password placeholders. Root [config.toml](config.toml) is another example, not the default deployment path. Use random passwords of at least 12 bytes, preferably distinct for every extension.

For upgrades, edit the existing deployment configuration; do not overwrite credentials, certificates or `[media]` with the template. Bria media ports default to UDP 20000–20020; this is a Compose mapping, not an environment variable. Custom TOML ranges must also be mapped in Compose and allowed by the firewall.

Source startup requires Rust 1.88+:

```bash
mkdir -p config
cp config.template.toml config/config.toml
chmod 600 config/config.toml
# Edit configuration and replace placeholders.
cargo build --release --locked
./target/release/minghe -c config/config.toml
```

Compose builds `facilisvelox/minghe:latest` from current source:

```bash
docker compose up -d --build
docker compose logs -f
docker compose down
```

The container uses UID/GID 10001. On Linux, bind-mounted configuration needs directory traversal and file read permissions for this UID; a host-user-owned 0600 file usually cannot be read directly. Grant minimal read access through ownership, a dedicated group or ACL, keeping the mount read-only. External certificates/private keys also need read access; certificate renewal needs a writable certificate directory. The default named volume persists `/app/certs`; do not delete it just to restart.

| Compose variable | Default | Purpose |
| --- | --- | --- |
| `SIP_PORT` | `5061` | Host TCP port; container target remains 5061 |
| `RUST_LOG` | `info` | Log level |
| `TZ` | `Asia/Shanghai` | Time zone |
| `CPU_LIMIT` | `1.0` | CPU limit |
| `MEM_LIMIT` | `512M` | Memory limit |

These variables do not replace account, password, host or certificate TOML settings. Changing TOML `sip_port` also requires updating the container target in the port mapping. In the E2EE profile expose SIP/TLS TCP; in the Bria profile also expose the configured UDP media ports; configure independent TURN separately. Health checks confirm process liveness, not registration, peer trust or media operation.

Use trusted CA certificates publicly, setting both `cert_path` and `key_path`. Self-signed mode generates `certs/server.crt` and its private key; in Docker these reside in the certificate volume. Safely export only the public certificate for client trust. Update trust after renewal and keep verification enabled. Server certificate trust and endpoint identity trust are separate.

## Image builds and publication

[build-and-push.sh](build-and-push.sh) supports Depot and Docker Buildx. **It defaults to `PUSH=1`; a non-latest TAG also updates latest.** Documentation changes and local checks do not require publishing.

```bash
# Build and load one local platform without pushing; select your architecture.
PUSH=0 BUILDER=buildx PLATFORM=linux/amd64 TAG=media-review ./build-and-push.sh

# After release validation, push to your own repository; also updates its latest.
REPO=YOUR_DOCKER_HUB_USER TAG=YOUR_RELEASE_TAG ./build-and-push.sh
```

Buildx with `PUSH=0` and multiple platforms only validates the build without loading locally. Depot uses its `--load` behavior. Compose includes `build: .` and `image: facilisvelox/minghe:latest`; `up --build` builds local source and tags the result locally without pushing. To deploy a published tag, explicitly update image/build configuration or use the printed docker run command, retaining container restrictions, read-only configuration and persistent certificates. These source changes have not published an image.

## Validation and troubleshooting

Before release, run [the security-record commands](SECURITY_EN.md), install endpoint dependencies, perform a fresh Cargo Audit and validate actual clients, bidirectional audio, cross-NAT/TURN connectivity, certificate trust, key-substitution rejection, replay rejection and container execution. The Rust Bria regression sends real bidirectional UDP SRTP packets with AES-CM/GCM endpoints. The separate Python TLS/SIP test checks signaling and encrypted messages without audio. Neither verifies actual cross-NAT Bria calls.

| Symptom | Check |
| --- | --- |
| Configuration rejected | host, password placeholders/length, extension range, paired certificate paths |
| Container cannot read files | UID 10001 read/traversal permissions and mount locations |
| Registration fails | TLS trust, SHA-256/qop=auth, credentials, connection binding and source-IP rate limits |
| Bria call returns 488 | Ensure `[media]` is enabled and both clients offer a supported SDES-SRTP suite; plaintext RTP, DTLS fingerprints and signed E2EE offers are rejected in this profile |
| E2EE call returns 488 | SDP protocol, RTCP mux, setup, fingerprint, identity envelope and exact signed SDP bytes |
| Bria connects without audio | Public IPv4 in `media_addr`, matching UDP port range in TOML/Compose/firewall, both endpoints sending SRTP, and first-packet forwarding logs in both directions |
| E2EE signaling succeeds without audio | Endpoint signature verification, actual DTLS fingerprint, ICE and independent TURN |
| MESSAGE returns 415 | application/jose restricted five-segment JWE, plaintext or accidental CLI newline |
| Endpoint rejects message | Pinned fingerprint, GCM/signature, identities, clock and replay state; keep verification enabled |
| Offline messages vanish on restart | Queues are memory-only; 200 does not acknowledge endpoint decryption |

Share only redacted troubleshooting logs. Do not share passwords, Digest Authorization, endpoint private keys or message plaintext.
