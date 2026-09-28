# MingHe (鸣鹤)

**Minimal Secure SIP Voice Communication Server** — Written in Pure Rust

[中文文档](README.md)

---

## Features

- 🔒 **TLS Signaling Encryption** — SIP over TLS (SIPS) on port 5061, TLS 1.2/1.3
- 🎵 **SRTP Media Encryption** — AES_CM_128_HMAC_SHA1_80 / AEAD_AES_128_GCM (RFC 7714) with SDES key exchange
- 🔑 **SIP Digest Authentication** — MD5 `qop=auth`, expiring nonces and replay protection, with per-extension passwords
- 📡 **RTP Media Relay** — Server-side decryption and re-encryption; learns addresses only from authenticated SRTP packets
- 💬 **Extension Instant Messaging** — SIP MESSAGE text exchange; messages are queued while offline and auto-delivered on registration
- 📱 **Internal Extensions** — 1000–2000 range (configurable), INVITE/BYE/CANCEL/ACK
- 🌐 **IP Certificates** — No domain required; auto-generates IP-based TLS certificates
- 🔄 **Auto Cert Renewal** — Self-signed certs auto-renew 30 days before expiry with hot-reload
- 🐳 **Docker Ready** — Multi-arch images (amd64/arm64), one-command compose deployment
- 🦀 **Pure Rust** — Async high-performance (tokio), memory-safe, zero GC

## Quick Start

### Docker / VPS Deployment (Recommended)

```bash
# 1. Prepare configuration
mkdir -p config
cp config.template.toml config/config.toml

# 2. Edit config (set host, media_addr, default_password and any enabled per-extension passwords)
vim config/config.toml

# 3. Start
docker compose up -d

# 4. View logs
docker compose logs -f
```

> Docker Compose uses a named volume for self-signed certificates by default, so you do not need to create a local `certs` directory.

> ⚠️ This project no longer ships a Zeabur template. SIP signaling uses TCP/TLS, but audio media uses SRTP/UDP. The configured UDP port range must be reachable from clients on the same public port numbers advertised in SDP. Platforms that only support HTTP/TCP forwarding, random external ports, or no UDP port ranges are not suitable for direct deployment.

### Build from Source

```bash
# Requirements: Rust 1.88+
cargo build --release --locked

# Prepare local configuration; keep real passwords out of Git
mkdir -p config
cp config.template.toml config/config.toml
chmod 600 config/config.toml
# Set host, media_addr and all enabled passwords before running
./target/release/minghe -c config/config.toml
```

## Configuration

Configuration is in TOML format. See [`config.template.toml`](config.template.toml) for the full template.

### Minimal Configuration

```toml
[server]
listen_addr = "0.0.0.0"
sip_port = 5061
host = "192.168.1.100"          # Your server IP or domain

[extensions]
range_start = 1000
range_end = 2000
default_password = "CHANGE_ME_TO_A_STRONG_PASSWORD"

[tls]
cert_path = ""                   # Empty = auto-generate self-signed cert
key_path = ""

[media]
rtp_port_start = 20000
rtp_port_end = 20020
media_addr = "192.168.1.100"     # Required: media IP reachable by clients
```

> Replace every enabled `CHANGE_ME…` value with a real random password of at least 12 bytes. `media_addr` must be a valid IP reachable by clients; empty values and domain names are rejected at startup.

> Each call uses two even UDP ports by default, for example `20000/UDP` and `20002/UDP` for the first call. Firewalls, cloud security groups, and container port mappings must allow both.

> The default `20000-20020/udp` range supports about 5 concurrent calls and is friendly to small VPS instances. For more concurrency, expand `config.toml`, Docker port mappings, and firewall/security-group rules together. Do not map `20000-30000/udp` by default on small hosts; Docker may stall while creating thousands of UDP mappings.

### Platform Requirements

| Item | Requirement |
|:-----|:------------|
| SIP signaling | Fixed public TCP port, default `5061/tcp` |
| SRTP media | Fixed public UDP port range, default `20000-20020/udp` |
| Port mapping | External ports must match the ports advertised in SDP |
| Media address | `media_addr` must be a public or LAN IP reachable by clients |

If the platform cannot expose a fixed UDP port range, the usual symptom is: extensions register, calls connect, calls can be answered, but both sides have no audio.

### Per-Extension Passwords

Use a different random password for each extension in `[passwords]`. Unlisted extensions use `default_password`; anyone who knows that shared password can log in to those extensions. Replace the placeholders below:

```toml
[passwords]
1001 = "CHANGE_ME_EXTENSION_1001"
1002 = "CHANGE_ME_EXTENSION_1002"
```

### TLS Certificates

| Mode | Config | Description |
|:-----|:-------|:------------|
| **Self-signed** | `cert_path = ""` | Auto-generated, auto-renewed 30 days before expiry |
| **IP Certificate** | `host = "1.2.3.4"` | Auto-detects IP, generates IP SAN certificate |
| **Domain Certificate** | `host = "sip.example.com"` | Auto-detects domain, generates DNS SAN certificate |
| **External Certificate** | `cert_path = "/path/to/cert.pem"` | Use Let's Encrypt or other external certs |

## Security and upgrades

See [SECURITY_EN.md](SECURITY_EN.md) ([中文](SECURITY.md)) for the security review and full limits.

- Clients must support Digest `qop=auth` and register on the same TLS connection used for calls and messages. Expired nonces receive a new 401 challenge.
- Registrations last at most one hour. Each connection binds one account; reconnect to switch accounts. Disconnecting cleans up associated calls.
- Each caller may initiate up to two concurrent calls; the default media pool supports five calls. Pending calls expire after 120 seconds and established calls after four hours, with cleanup every 30 seconds.
- Both endpoints must send valid SRTP packets before the server learns their media destinations. Receive-only endpoints need adaptation.
- Each source IP may send 60 REGISTER requests per minute, including challenges and retries. Each connection may send 300 SIP messages per minute. Evaluate these limits when many devices share a NAT address.
- The relay decrypts and re-encrypts media, so the server is inside the trust boundary. Media is not end-to-end encrypted.

Updating the source does not publish a new Docker Hub `latest` image. Build from the current source to use these fixes immediately.

## Client Configuration

Recommended clients:

- iOS / Android: Bria Mobile app
- Desk phones: Fanvil Linkvil W610W / W620W

Other clients should support SIP over TLS, SDES-SRTP (`AES_CM_128_HMAC_SHA1_80` or `AEAD_AES_128_GCM`), and configurable self-signed certificate verification behavior.

| Setting | Value |
|:--------|:------|
| Server | Your server IP or domain |
| Port | `5061` |
| Transport | **TLS** |
| Username | Extension number (e.g. `1001`) |
| Password | Corresponding password |
| Domain/Realm | Same as `host` in config |

> ⚠️ When using self-signed certificates, import `certs/server.crt` as a trusted certificate and keep TLS verification enabled. Renewed certificates need to be trusted again; use a trusted CA certificate for public deployments.

## Message storage and delivery

Message bodies are limited to 4 KiB and complete MESSAGE requests to 8 KiB. Offline messages stay in memory for up to 24 hours: 100 per recipient (oldest messages are evicted when full) and 10,000 globally. Each sender may queue 120 messages per minute and hold 500 outstanding offline messages. Capacity or rate exhaustion returns 503. A 200 response means server acceptance, not recipient acknowledgement. Delivery resumes after registration and as the write queue drains; restarting the server loses pending messages.

## Architecture

```
┌──────────┐     SIP/TLS     ┌───────────────────────┐     SIP/TLS     ┌──────────┐
│          │◄───────────────►│                       │◄───────────────►│          │
│  Ext     │    TCP:5061     │   MingHe SIP Server    │    TCP:5061     │  Ext     │
│  1001    │                 │                       │                 │  1002    │
│          │     SRTP        │  ┌─────────────────┐  │      SRTP       │          │
│          │◄───────────────►│  │  Media Relay    │  │◄───────────────►│          │
└──────────┘  UDP:20000+     │  │  RTP Relay      │  │   UDP:20000+    └──────────┘
                             │  └─────────────────┘  │
                             │                       │
                             │  ┌─────────────────┐  │
                             │  │  Registrar      │  │
                             │  │  Auth + Digest  │  │
                             │  └─────────────────┘  │
                             │                       │
                             │  ┌─────────────────┐  │
                             │  │  Router         │  │
                             │  │  Call Routing   │  │
                             │  └─────────────────┘  │
                             └───────────────────────┘
```

## Supported SIP Methods

| Method | Description |
|:-------|:------------|
| `REGISTER` | Extension registration/unregistration with Digest auth |
| `INVITE` | Initiate voice call, SDP negotiation, SRTP key allocation |
| `ACK` | Confirm call establishment |
| `BYE` | End call, release media resources |
| `CANCEL` | Cancel unanswered call |
| `OPTIONS` | Keepalive / capability query |
| `MESSAGE` | Extension-to-extension instant messaging; queued while offline and auto-delivered on registration |

## Project Structure

```
minghe/
├── Cargo.toml                # Project manifest
├── config.toml               # Example config; replace passwords and media IP
├── config.template.toml      # Config template (with detailed comments)
├── Dockerfile                # Multi-stage build
├── docker-compose.yml        # Container orchestration
├── build-and-push.sh         # Multi-arch image build script
├── SECURITY.md / SECURITY_EN.md # Security review and upgrade notes
├── .env                      # Local Compose variables (Git-ignored)
└── src/
    ├── main.rs               # Entry point, CLI, graceful shutdown
    ├── config.rs             # Config loading and validation
    ├── tls.rs                # TLS management, auto-renewal, hot-reload
    ├── sip/
    │   ├── mod.rs
    │   ├── server.rs         # TLS listener, connection management, routing
    │   ├── parser.rs         # SIP message parsing and building
    │   ├── registrar.rs      # Digest authentication, registration management
    │   ├── router.rs         # INVITE/ACK/BYE/CANCEL call routing
    │   ├── message.rs        # Messaging, offline queues and quotas
    │   └── transaction.rs    # Transaction tracking and timeout cleanup
    └── media/
        ├── mod.rs
        ├── srtp.rs           # RFC 3711 / RFC 7714 SRTP implementation (AES-CM / AES-GCM)
        └── relay.rs          # UDP media relay
```

## Docker

### Using Pre-built Image

```bash
docker pull facilisvelox/minghe:latest

# If you bind-mount a host certificate directory, make it writable by the in-container minghe user first.
mkdir -p config certs
sudo chown -R 10001:10001 certs

docker run -d \
  --name minghe-sip \
  --read-only --cap-drop ALL --security-opt no-new-privileges=true \
  -p 5061:5061/tcp \
  -p 20000-20020:20000-20020/udp \
  -v $(pwd)/config:/app/config:ro \
  -v $(pwd)/certs:/app/certs \
  facilisvelox/minghe:latest
```

### Build from Source

```bash
docker build -t minghe .
```

### Multi-Arch Build & Push

```bash
# Requires Depot CLI or Docker Buildx; the script prefers Depot
# Build and push latest
./build-and-push.sh

# Build specific version
TAG=v0.1.0 ./build-and-push.sh

# Build only (no push)
PUSH=0 ./build-and-push.sh
```

## Development

```bash
# Build
cargo build --locked

# Test
cargo test --locked

# Debug mode (verbose logging)
RUST_LOG=debug cargo run --locked -- -c config/config.toml

# Release build
cargo build --release --locked
```

## Environment Variables

| Variable | Default | Description |
|:---------|:--------|:------------|
| `RUST_LOG` | `info` | Log level: `error` / `warn` / `info` / `debug` / `trace` |
| `SIP_PORT` | `5061` | SIP TLS port mapping |
| `RTP_PORT_START` | `20000` | RTP port range start |
| `RTP_PORT_END` | `20020` | RTP port range end, supports about 5 concurrent calls by default |
| `CPU_LIMIT` | `1.0` | Docker Compose CPU limit; works on 1-core VPS by default, can be increased on larger hosts |
| `MEM_LIMIT` | `512M` | Docker Compose memory limit |
| `TZ` | `Asia/Shanghai` | Container timezone |

These variables configure Compose mappings and the runtime environment; they do not override TOML settings. Keep SIP/media configuration, port mappings and firewall rules in sync; use matching internal and external SIP ports.


## License

This project is licensed under the [Apache License 2.0](LICENSE).

Copyright 2026 MingHe Contributors
