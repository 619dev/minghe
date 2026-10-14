# Bria cross-network audio repair and deployment

[中文](BRIA.md) · [Home](README_EN.md) · [Deployment and release](DEPLOYMENT_EN.md) · [Security boundary](SECURITY_EN.md)

A recent version removed the server SRTP relay, breaking the media path required by existing cross-NAT Bria deployments. This fix restores the explicit `[media]` compatibility profile and Docker UDP mapping. Without `[media]`, the server still uses signed SDP / DTLS-SRTP; there is no automatic per-call fallback.

## Configuration

Edit the deployment's `config/config.toml`, retaining other settings, and restore the previous `[media]` section. If it was deleted, append the following with your actual public IPv4; do not duplicate table headers:

```toml
[media]
rtp_port_start = 20000
rtp_port_end = 20020
media_addr = "YOUR_SERVER_PUBLIC_IPV4"
```

`media_addr` must be a server IPv4 reachable by both clients, not a container IP, `0.0.0.0` or either phone's address. Docker maps UDP 20000–20020 by default. Custom media ranges must match Compose mappings, security groups, firewall rules and any server-side NAT port forwarding.

Both profiles require SHA-256 Digest `qop=auth` registration; MD5 and omitted algorithms are rejected. Confirm support in your Bria version. Retain the SIP/TLS account configuration, enable SDES-SRTP (Secure RTP), and verify the server TLS certificate. TLS/login credentials do not replace SRTP settings. Both endpoints must send media to establish NAT mappings; the relay learns return destinations only from authenticated SRTP packets.

## Build and startup

Run in the project directory containing the fix:

```bash
docker compose up -d --build --force-recreate
docker compose logs -f minghe
```

Compose includes `build: .`, so this builds local source. Pulling remote `latest` alone does not obtain an unpublished fix. Preserve the certificate volume.

Startup should log `已启用 Bria 兼容 SRTP 中继`. After answering, look for `媒体中继已启动` and `SRTP 首包已成功解密、重加密并转发` in both directions. Successful signaling or a relay-start log alone does not establish bidirectional UDP reachability.

## Troubleshooting silent audio

| Symptom | Check |
| --- | --- |
| No compatibility startup log | The active file is `config/config.toml`, `[media]` is uncommented, and the container was rebuilt |
| Call returns 488 | Use SDES-SRTP and a supported key suite; this profile rejects DTLS fingerprints and signed E2EE offers |
| Relay starts without forwarding logs | UDP mappings, security groups, firewall, public IPv4, and both clients actively sending SRTP |
| Only one direction forwards | NAT, audio input/output, SRTP negotiation and network path on the silent side |
| Media port allocation fails | Port pool exhaustion; expand TOML, Docker and firewall ranges together |

Do not publish SDP `a=crypto`, configuration passwords or Digest Authorization.

## Capacity and limits

Each call consumes two even UDP ports. Allocation includes `rtp_port_start` and excludes `rtp_port_end`. The default `20000..20020` provides ten even ports for at most five simultaneous relay calls, also subject to two calls per caller and 256 globally. Expand all three ranges together for greater concurrency. Only one active audio stream is supported; no video, offerless calls, re-INVITE or media negotiation in ACK. The relay handles SRTP audio and does not provide separate RTCP/SRTCP forwarding.

## Verification and encryption boundary

The regression follows INVITE → 200 → ACK → bidirectional UDP SRTP → BYE, using private-address SDP and real dynamic UDP source addresses. It verifies decryption/re-encryption between AES-CM and GCM endpoints and rejects signed offers entering the relay. It does not replace acceptance testing with two Bria clients on actual different networks.

The compatibility profile uses TLS + SDES-SRTP. The server holds each leg's media keys and decrypts/re-encrypts audio, so **it is not end-to-end encryption**. Plaintext RTP is still rejected; registration and dialog ownership checks remain. MESSAGE still requires JWE and is incompatible with ordinary Bria text messages. For signed SDP / DTLS-SRTP E2EE, remove the entire `[media]` section and use endpoints implementing [E2EE_EN.md](E2EE_EN.md).
