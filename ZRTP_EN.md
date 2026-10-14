# ZRTP end-to-end voice setup

[中文](ZRTP.md) · [Home](README_EN.md) · [Deployment](DEPLOYMENT_EN.md) · [Security and validation](SECURITY_EN.md)

With explicit `mode = "zrtp"`, endpoints perform ZRTP key agreement and SRTP/SRTCP encryption/decryption. The server forwards handshake and media packets unchanged without generating or holding media keys. The symmetric relay provides NAT return paths without requiring public phone addresses.

Linphone supports ZRTP; see its [official feature list](https://www.linphone.org/en/features/). The selected version must also support SIP/TLS, SHA-256 Digest `qop=auth` and the SDP requirements below. Automated tests did not run real Linphone endpoints and do not establish compatibility with every version.

## Server configuration

Set this profile in the deployment's `config/config.toml`, retaining actual public address and port settings. Do not duplicate table headers:

```toml
[media]
mode = "zrtp"
rtp_port_start = 20000
rtp_port_end = 20020
media_addr = "203.0.113.10" # Replace with the server's real public IPv4.
```

Omitting mode or choosing `"sdes"` retains Bria compatibility. Removing the entire `[media]` table selects signed SDP / DTLS-SRTP. Profiles are chosen at startup without per-call fallback. ZRTP rejects SDES, DTLS and missing Hello hashes; migrate old Bria clients before switching.

Builds, Docker commands, port mappings and upgrades are maintained in [DEPLOYMENT_EN.md](DEPLOYMENT_EN.md). Startup logs should indicate the ZRTP opaque relay. Each default call uses four ports; the pool supports five calls. Allow the complete UDP range, including odd RTCP ports.

## Both endpoints

1. Configure each MingHe SIP account, SIP/TLS and SHA-256 Digest; verify the server certificate.
2. Select **ZRTP** and require media encryption. Do not allow plaintext after negotiation failure. A client without mandatory ZRTP support is unsuitable for this security profile.
3. Disable ICE/STUN/TURN media negotiation and use the SDP relay address. This symmetric relay is not an ICE agent; SDP with ICE attributes receives 488.
4. Enable audio only and a shared codec such as PCMU/PCMA. Use RTP/AVP or RTP/AVPF, ZRTP 1.10, with media-level `a=zrtp-hash:1.10 <64 hexadecimal SHA-256 digits>`. RTCP mux and separate SRTCP ports are supported.
5. Confirm both clients report encrypted ZRTP, compare SAS values and mark them verified only when identical. Hang up if they differ.

Setting names vary by version. SDK applications must enforce both encryption selection and mandatory encryption; server SDP checks are insufficient. Do not transmit unencrypted audio before negotiation. The client must stop the call and report handshake failure, timeout or SAS mismatch.

## Acceptance and troubleshooting

Test real devices first on one network, then on separate Wi-Fi/mobile networks:

- Register, ring, answer, sustain bidirectional speech and hang up; both endpoints show ZRTP and identical SAS.
- Check that SDP contains no `a=crypto` and server media forwarding contains endpoint handshake/ciphertext. Do not log media keys, SAS or content.
- Disable ZRTP, select SDES or provide an invalid Hello hash on one endpoint: reject the call or terminate it at the client, without continuing plaintext speech.
- Introduce temporary packet loss and restore connectivity; verify handshake retries and audio recovery. Endpoints need jitter buffers and loss handling.
- Confirm port release after hangup. Blocked UDP must cause an endpoint timeout/error; SIP 200 alone does not prove media availability.

488 usually indicates an incompatible SDP: check hashes, ICE, video and encryption settings. For silent calls, check public IPv4, all UDP ports and Hello transmission. The relay learns/pins RTP sources only from Hello messages matching SDP hashes. Invalid Hellos and other sources cannot replace pinned addresses. A network change affecting UDP source addresses requires hanging up and redialing; address migration and re-INVITE are unsupported.

## Security boundary

This is transparent ZRTP forwarding, not server-side key agreement. SDP declarations and Hello hashes prove neither completed key exchange nor encryption of each RTP packet. Without media keys, the server cannot distinguish plaintext/ciphertext payloads or verify SRTP/SRTCP tags. Endpoints must require encryption and authenticate media. The server offers no SDES or plaintext fallback.

Hello hashes associate NAT sources with authenticated SIP sessions, not peer identities. The signaling server can modify SDP, block calls and observe metadata. SAS comparison is essential against an active intermediary. Separate RTCP sources must share the pinned RTP source IP; endpoints still verify SRTCP. Malicious same-IP sources or attackers observing handshakes may still cause denial of service.

The server caches at most one hash-matched initial Hello per side and forwards it once the other source is pinned; endpoints retransmit other lost handshake packets. In-call address migration is unsupported.

See [SECURITY_EN.md](SECURITY_EN.md) for test commands, coverage and limits. Local simulated tests do not execute a real ZRTP key exchange, SAS check or audio playback. Complete real-endpoint acceptance as described above.
