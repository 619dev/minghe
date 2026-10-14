# MingHe (鸣鹤)

A Rust SIP/TLS voice service with an opaque ZRTP relay, a Bria-compatible SDES-SRTP relay, and signed SDP / DTLS-SRTP routing.

[中文](README.md) · [Deployment](DEPLOYMENT_EN.md) · [ZRTP setup](ZRTP_EN.md) · [Signed DTLS and messaging](E2EE_EN.md) · [Security and validation](SECURITY_EN.md)

## Call profiles

| Configuration | Endpoint requirements | Media path and encryption boundary |
| --- | --- | --- |
| `[media] mode = "zrtp"` | ZRTP 1.10 and Hello hashes; mandatory encryption, ICE disabled, SAS comparison | Server forwards ZRTP / SRTP / SRTCP unchanged; endpoints hold media keys |
| `[media] mode = "sdes"`, or `[media]` with mode omitted | SIP/TLS, SHA-256 Digest and SDES-SRTP, such as compatible Bria versions | Server decrypts and re-encrypts audio; not end-to-end encrypted |
| No `[media]` | MingHe signed SDP, peer identity verification and DTLS-SRTP | SDP forwarded unchanged; endpoints connect using ICE and a separate TURN relay if needed |

The profile is selected at startup and never falls back automatically. Both endpoints must support the selected profile. Omitting `[media]` requires adapted clients; ordinary softphones do not automatically implement signed SDP.

Every profile requires TLS certificate verification and SHA-256 Digest `qop=auth`. MESSAGE accepts only MingHe JWE ciphertext, not ordinary SIP text. A ZRTP client's native encrypted chat protocol is not automatically compatible with MingHe JWE.

## Quick start

For a new installation, copy the template and set the hostname or public IP, strong passwords and individual extension passwords:

```bash
mkdir -p config
cp config.template.toml config/config.toml
chmod 600 config/config.toml
# Edit configuration first. Requires Rust 1.88+.
cargo build --release --locked
./target/release/minghe -c config/config.toml
```

For ZRTP, enable this table and replace the example public address:

```toml
[media]
mode = "zrtp"
rtp_port_start = 20000
rtp_port_end = 20020
media_addr = "203.0.113.10"
```

Require ZRTP on both endpoints, disable ICE, and compare SAS after connecting. See [ZRTP_EN.md](ZRTP_EN.md) for requirements and acceptance checks. Existing Bria clients use `mode = "sdes"`; migrate both clients before switching to ZRTP.

Compose currently references an image and **has no `build` configuration**. Build the local source first:

```bash
docker build -t facilisvelox/minghe:latest .
docker compose up -d --force-recreate
docker compose logs -f
```

On Linux, grant container UID 10001 read access to configuration. See [deployment](DEPLOYMENT_EN.md) for UDP mappings, certificates, upgrades and published images. Source validation does not establish what is included in remote `latest`.

## Features and limitations

- TLS signaling, SHA-256 registration, connection and dialog ownership checks, bounded queues, rates and timeouts.
- ZRTP Hello hashes associate media sources with call legs; UDP addresses are pinned. RTCP mux and separate RTCP ports are supported. Endpoints enforce encryption and verify media authentication tags.
- SDES relay supports AES-CM / AES-GCM and learns NAT addresses only from authenticated SRTP packets.
- Signed DTLS preserves SDP and identity envelopes; receiving clients independently verify signatures and actual DTLS fingerprints.
- JWE online delivery and in-memory offline queues. Reference tools encrypt messages, sign identities and detect replay; they do not dial or handle audio.
- Automatic self-signed certificate renewal, TLS reload and non-root containers.

Supports REGISTER, INVITE, ACK, BYE, CANCEL, OPTIONS and MESSAGE with one active audio stream. Initial INVITE requires SDP. Video, offerless calls, re-INVITE and media negotiation in ACK are unsupported. ZRTP network address changes require a new call.

The default media pool supports five relay calls. See [SECURITY_EN.md](SECURITY_EN.md) for other limits and security boundaries. 121 Rust tests passed, including bidirectional Bria SRTP and opaque ZRTP forwarding; no real ZRTP endpoint handshake was performed. Real audio, SAS and cross-network interoperability still require deployment acceptance.

## Documentation and development

- [DEPLOYMENT_EN.md](DEPLOYMENT_EN.md): configuration, builds, publishing, Bria setup and troubleshooting.
- [ZRTP_EN.md](ZRTP_EN.md): endpoint requirements, networking and real-call acceptance.
- [E2EE_EN.md](E2EE_EN.md): custom signed DTLS-SRTP / JWE protocols and endpoint reference tools.
- [SECURITY_EN.md](SECURITY_EN.md): security boundaries, capacity, test commands and validation scope.

See [config.template.toml](config.template.toml) for configuration fields. Core code lives in `src/sip/` and `src/media/`; endpoint tools live in `tools/`. Test commands are maintained in the security guide.

If this project helps you, consider buying me a cola.

<img width="30%" src="请我喝可乐.jpg" alt="qrcode">

## License

[Apache License 2.0](LICENSE), Copyright 2026 MingHe Contributors.
