# Deployment, upgrades and publishing

[中文](DEPLOYMENT.md) · [Home](README_EN.md) · [ZRTP setup](ZRTP_EN.md) · [Security and validation](SECURITY_EN.md)

## Configuration and profiles

For a new installation, copy `config.template.toml` to `config/config.toml` and set host, passwords of at least 12 bytes and individual extension passwords. Edit existing configuration during upgrades; do not replace accounts or certificate settings with the template. The source binary defaults to root `config.toml` without `-c`; commands here and Docker explicitly use `config/config.toml`.

| Profile | Configuration | Networking and endpoints |
| --- | --- | --- |
| ZRTP | `[media] mode = "zrtp"` | Public IPv4 and UDP relay; require ZRTP, disable ICE, compare SAS; see [ZRTP_EN.md](ZRTP_EN.md) |
| Bria SDES | `[media] mode = "sdes"` or mode omitted | Public IPv4 and UDP relay; SDES-SRTP; server can decrypt audio |
| Signed DTLS | Remove the entire `[media]` table | Adapt clients to [E2EE_EN.md](E2EE_EN.md), with endpoint ICE/STUN and separate TURN if needed |

Profiles are selected at startup, with no automatic fallback. Confirm both clients support the target profile before migration. Back up configuration and TLS certificates; signed DTLS endpoints must also protect identities, pinned fingerprints and replay databases. Restarting loses undelivered in-memory messages.

Example relay configuration; replace the address with the server's real public IPv4 reachable by both endpoints:

```toml
[media]
mode = "sdes" # Use "zrtp" for ZRTP endpoints.
rtp_port_start = 20000
rtp_port_end = 20020
media_addr = "203.0.113.10"
```

The pool includes its start and excludes its end, allocating even RTP ports. SDES uses two ports per call; ZRTP uses two RTP ports plus two odd RTCP ports and requires even start/end values. Either default relay pool supports five calls. Compose maps UDP `20000-20020`. Keep TOML, Compose, security groups and firewalls consistent when changing ranges. Do not advertise container addresses, `0.0.0.0` or phone addresses.

Signed DTLS does not use this server's UDP media ports; remove those mappings if desired. Manage separate TURN ports independently. Do not disable certificate checks or allow plaintext fallback to fix connectivity.

## Bria Digest compatibility

For clients unable to answer SHA-256 challenges, add this to the existing `[server]` table:

```toml
[server]
digest_algorithm = "md5"
# Keep existing listen_addr, sip_port and host.
```

Omission or `"sha256"` selects the default SHA-256 profile. `"md5"` explicitly selects MD5 challenges, without multiple algorithms or automatic downgrade. TLS, `qop=auth`, cnonce, increasing nc and connection binding remain required. MD5 clients may omit algorithm, interpreted as MD5. This server-wide setting affects all extensions and is weaker than SHA-256; use strong random passwords and verify TLS certificates.

Rebuild/restart and confirm the explicit MD5 startup log. Successful registration is an initial 401, a retry with Authorization and server 200. This does not change `[media]`: Bria audio still uses SDES; ZRTP/signed DTLS media and JWE messaging remain unchanged.

## Running from source

Requires Rust 1.88+:

```bash
mkdir -p config
cp config.template.toml config/config.toml
chmod 600 config/config.toml
# Edit placeholders and select a call profile.
cargo build --release --locked
./target/release/minghe -c config/config.toml
```

## Docker and upgrades

Current Compose contains only `image`, not `build`. Build local source before recreating the container:

```bash
docker build -t facilisvelox/minghe:latest .
docker compose up -d --force-recreate
docker compose logs -f
```

To deploy a published image, verify its version first, then pull and start. Pulling after a local build replaces that image:

```bash
# For published-image deployments only.
docker compose pull
docker compose up -d --force-recreate
```

Pin production image tags or digests to an accepted version. Source validation does not prove remote `latest` contents; this work did not publish the ZRTP changes. `docker compose down` stops services while retaining the certificate volume; do not delete it with `down -v`.

The container runs as UID/GID 10001. Linux bind mount directories must be traversable and configuration plus external certificate/key files readable by that UID. Host-owned 0600 files usually need ownership, a dedicated group or ACL adjustments. Keep configuration mounts read-only. The default `/app/certs` named volume persists certificates and permits renewal writes.

| Compose variable | Default | Purpose |
| --- | --- | --- |
| `SIP_PORT` | `5061` | Host TCP port; container target remains 5061 |
| `RUST_LOG` | `info` | Logging level |
| `TZ` | `Asia/Shanghai` | Timezone |
| `CPU_LIMIT` | `1.0` | CPU limit |
| `MEM_LIMIT` | `512M` | Memory limit |

Environment variables do not replace TOML accounts, passwords, host or certificates. Changing TOML `sip_port` also requires changing the container target mapping. Health checks establish process liveness, not registration or media availability.

## TLS and endpoints

Use a trusted CA certificate publicly and set both `cert_path` and `key_path`. Empty paths generate a self-signed `certs/server.crt`, inside the certificate volume with Docker. Import the public certificate into client trust and update trust after renewal; never distribute the private key. Server TLS trust and peer identity authentication are separate.

Bria requires SIP/TLS, Digest `qop=auth` matching the server configuration, SDES-SRTP and certificate verification. Confirm version support. Both clients must send SRTP to establish NAT return paths; only authenticated SRTP packets update addresses. Supported suites are AES_CM_128_HMAC_SHA1_80 and AEAD_AES_128_GCM. Separate RTCP/SRTCP forwarding is unavailable in this profile. It is not end-to-end encrypted.

ZRTP settings and SAS acceptance are maintained in [ZRTP_EN.md](ZRTP_EN.md). All profiles accept only MingHe JWE MESSAGE, not Bria text chat; signed DTLS and messaging tools are documented in [E2EE_EN.md](E2EE_EN.md).

## Publishing images

[build-and-push.sh](build-and-push.sh) supports Depot and Docker Buildx. Default `PUSH=1` publishes remotely; a non-latest TAG also updates latest. Documentation edits do not require publishing.

```bash
# Local single-platform build/load; no push. Select the deployment architecture.
PUSH=0 BUILDER=buildx PLATFORM=linux/amd64 TAG=media-review ./build-and-push.sh

# Publish after acceptance; also updates latest.
REPO=YOUR_DOCKER_HUB_USER TAG=YOUR_RELEASE_TAG ./build-and-push.sh
```

Buildx multi-platform `PUSH=0` builds do not load local images; Depot uses `--load`. Update Compose image when using a custom repository or tag. Before publishing, run [security checks](SECURITY_EN.md) and accept real endpoints, cross-network calls and container operation.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Configuration rejected | Placeholder/short passwords, host, extension range, paired certificate paths, mode and media range |
| Container cannot read files | UID 10001 read/traverse permissions and mount paths |
| Registration fails | TLS trust, digest_algorithm / qop=auth, credentials and source-IP limits |
| Bria call returns 488 | SDES profile and supported suites; DTLS fingerprints, signed identity offers and plaintext profiles are rejected |
| ZRTP call returns 488 | Hello hash, ZRTP 1.10, ICE disabled, audio only, available relay ports |
| Signed DTLS call returns 488 | Exact SDP bytes, identity envelope, fingerprint, setup and RTCP mux |
| Relay call connects without audio | Public IPv4, all UDP mappings, firewall, media/Hello from both endpoints and completed ZRTP handshake |
| Signed DTLS has no audio | Signature checks, actual DTLS fingerprint, ICE candidates and TURN connectivity |
| MESSAGE returns 415 | application/jose, restricted five-part JWE, CLI newline or incompatible native chat protocol |
| Client rejects messages | Pinned fingerprint, GCM/signature, identities, clock and replay database |
| Offline messages lost after restart | Queue is in memory; 200 does not mean successful endpoint decryption |

Share redacted logs only: hide passwords, Digest Authorization, SDES keys, endpoint private keys and message plaintext.

## TLS login diagnostics

`Illegal SNI extension: ignoring IP address presented as hostname` means the client sent an IP in SNI and rustls ignored it. This alone does not establish handshake failure. Check subsequent handshake success/errors and REGISTER responses for the same connection. 401 is a normal authentication challenge; 400/403 or repeated 401 requires checking Digest and account configuration.

The client address must match certificate SAN. Connecting to a public IP requires that IP SAN; a certificate generated for `minghe.local` does not cover the public IP. Changing host does not immediately replace an unexpired certificate in the volume. Inspect it first, then plan replacement and update endpoint trust. Do not delete the volume or disable verification to address the SNI warning.

```bash
docker compose logs --tail=200 minghe
# Inspect public certificate identity/validity without reading the private key.
docker compose exec -T minghe cat /app/certs/server.crt | \
  openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

For external certificates substitute the actual cert_path. Confirm Android apps themselves trust the certificate; system installation alone may not establish app trust. When using a trusted domain certificate with the correct DNS SAN, configure that domain in clients.
