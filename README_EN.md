# MingHe (鸣鹤)

**Minimal Secure SIP Voice Communication Server** — Written in Pure Rust

[中文文档](README.md)

---

## Features

- 🔒 **TLS Signaling Encryption** — SIP over TLS (SIPS) on port 5061, TLS 1.2/1.3
- 🎵 **SRTP Media Encryption** — AES_CM_128_HMAC_SHA1_80 with SDES key exchange
- 🔑 **SIP Digest Authentication** — MD5 digest auth with default and per-extension passwords
- 📡 **RTP Media Relay** — Transparent server-side relay with address learning
- 📱 **Internal Extensions** — 1000–2000 range (configurable), INVITE/BYE/CANCEL/ACK
- 🌐 **IP Certificates** — No domain required; auto-generates IP-based TLS certificates
- 🔄 **Auto Cert Renewal** — Self-signed certs auto-renew 30 days before expiry with hot-reload
- 🐳 **Docker Ready** — Multi-arch images (amd64/arm64), one-command compose deployment
- 🦀 **Pure Rust** — Async high-performance (tokio), memory-safe, zero GC

## Quick Start

### Zeabur One-Click Deploy

```bash
npx zeabur@latest template deploy -f zeabur-template.yaml
```

Or import [`zeabur-template.yaml`](zeabur-template.yaml) in the Zeabur dashboard.

### Docker Deployment (Recommended)

```bash
# 1. Prepare configuration
mkdir -p config certs
cp config.template.toml config/config.toml

# 2. Edit config (at minimum, change host and default_password)
vim config/config.toml

# 3. Start
docker compose up -d

# 4. View logs
docker compose logs -f
```

### Build from Source

```bash
# Requirements: Rust 1.75+
cargo build --release

# Run
./target/release/minghe -c config.toml
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
default_password = "YourPassword123"

[tls]
cert_path = ""                   # Empty = auto-generate self-signed cert
key_path = ""

[media]
rtp_port_start = 20000
rtp_port_end = 30000
media_addr = ""                  # Empty = auto-detect
```

### Per-Extension Passwords

Set individual passwords in `[passwords]`. Extensions not listed use `default_password`:

```toml
[passwords]
1001 = "velox@2026"
1002 = "alice@2026"
```

### TLS Certificates

| Mode | Config | Description |
|:-----|:-------|:------------|
| **Self-signed** | `cert_path = ""` | Auto-generated, auto-renewed 30 days before expiry |
| **IP Certificate** | `host = "1.2.3.4"` | Auto-detects IP, generates IP SAN certificate |
| **Domain Certificate** | `host = "sip.example.com"` | Auto-detects domain, generates DNS SAN certificate |
| **External Certificate** | `cert_path = "/path/to/cert.pem"` | Use Let's Encrypt or other external certs |

## Client Configuration

Any SIP softphone supporting SIP over TLS can be used (Onesip, Onesip, Onesip, Onesip, etc.).

| Setting | Value |
|:--------|:------|
| Server | Your server IP or domain |
| Port | `5061` |
| Transport | **TLS** |
| Username | Extension number (e.g. `1001`) |
| Password | Corresponding password |
| Domain/Realm | Same as `host` in config |

> ⚠️ When using self-signed certificates, you must either **disable TLS certificate verification** in your client or import `certs/server.crt` as a trusted certificate.

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

## Project Structure

```
minghe/
├── Cargo.toml                # Project manifest
├── config.toml               # Default configuration
├── config.template.toml      # Config template (with detailed comments)
├── Dockerfile                # Multi-stage build
├── docker-compose.yml        # Container orchestration
├── build-and-push.sh         # Multi-arch image build script
├── zeabur-template.yaml     # Zeabur one-click deploy template
├── .env                      # Docker Compose environment variables
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
    │   └── transaction.rs    # Transaction tracking and timeout cleanup
    └── media/
        ├── mod.rs
        ├── srtp.rs           # RFC 3711 SRTP implementation
        └── relay.rs          # UDP media relay
```

## Docker

### Using Pre-built Image

```bash
docker pull facilisvelox/minghe:latest

docker run -d \
  --name minghe-sip \
  -p 5061:5061/tcp \
  -p 20000-30000:20000-30000/udp \
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
# Requires depot CLI
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
cargo build

# Test
cargo test

# Debug mode (verbose logging)
RUST_LOG=debug cargo run

# Release build
cargo build --release
```

## Environment Variables

| Variable | Default | Description |
|:---------|:--------|:------------|
| `RUST_LOG` | `info` | Log level: `error` / `warn` / `info` / `debug` / `trace` |
| `SIP_PORT` | `5061` | SIP TLS port mapping |
| `RTP_PORT_START` | `20000` | RTP port range start |
| `RTP_PORT_END` | `30000` | RTP port range end |
| `TZ` | `Asia/Shanghai` | Container timezone |

## License

This project is licensed under the [Apache License 2.0](LICENSE).

Copyright 2026 MingHe Contributors
