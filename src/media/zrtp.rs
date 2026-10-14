//! Opaque ZRTP/SRTP relay. Only endpoints implement the key exchange and SRTP.
//! SDP Hello hashes bind each UDP source to its TLS-authenticated call leg.
//! This does not authenticate the peer against a malicious signaling server:
//! endpoints must require ZRTP, verify SAS, and authenticate all received media.
use std::net::SocketAddr;
use tokio::{net::UdpSocket, sync::watch};

pub type HelloHashes = Vec<[u8; 32]>;

/// Deliberately narrow profile: one IPv4 audio stream, no SDES/DTLS or ICE.
/// ICE must be disabled since this is a symmetric relay, not an ICE agent.
pub fn validate_sdp(sdp: &str) -> Option<HelloHashes> {
    if !sdp.starts_with("v=0\r\n") {
        return None;
    }
    let mut audio = false;
    let mut hashes = Vec::new();
    for line in sdp.lines() {
        if line.starts_with("m=") {
            if audio {
                return None;
            }
            let f: Vec<_> = line.split_whitespace().collect();
            if f.len() < 4
                || f[0] != "m=audio"
                || f[1].parse::<u16>().ok()? == 0
                || !matches!(f[2], "RTP/AVP" | "RTP/AVPF")
            {
                return None;
            }
            audio = true;
        } else if let Some(value) = line.strip_prefix("a=zrtp-hash:") {
            if !audio {
                return None;
            }
            let f: Vec<_> = value.split_whitespace().collect();
            if f.len() != 2 || f[0] != "1.10" {
                return None;
            }
            let bytes = hex::decode(f[1]).ok()?;
            hashes.push(bytes.try_into().ok()?);
            if hashes.len() > 4 {
                return None;
            }
        } else if line.starts_with("a=crypto:")
            || line.starts_with("k=")
            || line.starts_with("a=fingerprint:")
            || line.starts_with("a=setup:")
            || line.starts_with("a=ice-")
            || line.starts_with("a=candidate:")
            || line.starts_with("a=remote-candidates:")
            || line.starts_with("a=group:")
            || line.starts_with("a=rtcp-mux-only")
        {
            return None;
        }
    }
    (audio && !hashes.is_empty()).then_some(hashes)
}

/// Retain endpoint Hello hashes, codecs and RTP profile. Rewrite transport only.
pub fn rewrite_sdp(sdp: &str, address: &str, port: u16) -> String {
    let mux = sdp.lines().any(|l| l == "a=rtcp-mux");
    let mut lines = Vec::new();
    for line in sdp.lines() {
        if line.starts_with("c=") {
            continue;
        }
        if line.starts_with("a=rtcp:") {
            continue;
        }
        if line.starts_with("m=audio ") {
            let mut fields: Vec<_> = line.split_whitespace().map(str::to_owned).collect();
            fields[1] = port.to_string();
            lines.push(fields.join(" "));
            lines.push(format!("c=IN IP4 {address}"));
            lines.push(format!(
                "a=rtcp:{} IN IP4 {address}",
                if mux { port } else { port + 1 }
            ));
        } else {
            lines.push(line.to_owned());
        }
    }
    lines.join("\r\n") + "\r\n"
}

/// Four sockets, including separate RTCP for clients without rtcp-mux.
pub async fn bind(caller: u16, callee: u16) -> std::io::Result<[UdpSocket; 4]> {
    Ok([
        UdpSocket::bind(("0.0.0.0", caller)).await?,
        UdpSocket::bind(("0.0.0.0", callee)).await?,
        UdpSocket::bind(("0.0.0.0", caller + 1)).await?,
        UdpSocket::bind(("0.0.0.0", callee + 1)).await?,
    ])
}

fn message(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < 28
        || packet[0..2] != [0x10, 0]
        || &packet[4..8] != b"ZRTP"
        || packet[12..14] != [0x50, 0x5a]
    {
        return None;
    }
    let size = u16::from_be_bytes([packet[14], packet[15]]) as usize * 4;
    if size < 12 || packet.len() != size + 16 {
        return None;
    }
    Some(&packet[12..12 + size])
}

fn is_hello(packet: &[u8], hashes: &HelloHashes) -> bool {
    let Some(msg) = message(packet) else {
        return false;
    };
    if msg.len() < 88 || &msg[4..12] != b"Hello   " || &msg[12..16] != b"1.10" {
        return false;
    }
    let digest = ring::digest::digest(&ring::digest::SHA256, msg);
    hashes.iter().any(|h| h.as_slice() == digest.as_ref())
}

/// Pin RTP source only after its Hello matches SDP. No SDP destinations or arbitrary
/// first-packet learning, no source migration. Endpoints retransmit lost handshakes.
/// UDP rebinding requires a fresh call; BYE/CANCEL/timeout stop all four sockets.
pub async fn run(
    sockets: [UdpSocket; 4],
    hashes: [HelloHashes; 2],
    mut shutdown: watch::Receiver<bool>,
) {
    let mut peers = [None::<SocketAddr>; 4];
    let mut pending_hellos: [Option<Vec<u8>>; 2] = [None, None];
    let mut buffers = [[0u8; 4096]; 4];
    loop {
        if *shutdown.borrow() {
            break;
        }
        let [a, b, c, d] = &sockets;
        let [ab, bb, cb, db] = &mut buffers;
        let (leg, received) = tokio::select! {
            r = a.recv_from(ab) => (0, r),
            r = b.recv_from(bb) => (1, r),
            r = c.recv_from(cb) => (2, r),
            r = d.recv_from(db) => (3, r),
            _ = shutdown.changed() => break,
        };
        let Ok((n, source)) = received else {
            break;
        };
        if n == 0 || n == buffers[leg].len() {
            continue;
        }
        let packet = &buffers[leg][..n];
        if peers[leg].is_none() {
            if leg < 2 {
                if !is_hello(packet, &hashes[leg]) {
                    continue;
                }
            } else {
                // RTCP may only latch on the IP of the already pinned RTP endpoint.
                if peers[leg - 2].is_none_or(|p| p.ip() != source.ip())
                    || packet.len() < 8
                    || packet[0] >> 6 != 2
                    || !(192..=223).contains(&packet[1])
                {
                    continue;
                }
            }
            peers[leg] = Some(source);
            if leg < 2 {
                let opposite = leg ^ 1;
                if peers[opposite].is_none() {
                    // At most one hash-validated Hello per side, bounded by buffer size.
                    pending_hellos[leg] = Some(packet.to_vec());
                }
                if let Some(hello) = pending_hellos[opposite].take() {
                    let _ = sockets[leg].send_to(&hello, source).await;
                }
            }
        }
        if peers[leg] != Some(source) {
            continue;
        }
        // The relay cannot distinguish encrypted RTP payloads from plaintext.
        // Mandatory encryption and authentication are enforced by the endpoints.
        if message(packet).is_none() && (packet.len() < 8 || packet[0] >> 6 != 2) {
            continue;
        }
        let opposite = leg ^ 1;
        if let Some(destination) = peers[opposite] {
            let _ = sockets[opposite].send_to(packet, destination).await;
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub fn hello(seed: u8) -> (Vec<u8>, String) {
        let mut msg = vec![seed; 88];
        msg[..4].copy_from_slice(&[0x50, 0x5a, 0, 22]);
        msg[4..12].copy_from_slice(b"Hello   ");
        msg[12..16].copy_from_slice(b"1.10");
        let hash = hex::encode(ring::digest::digest(&ring::digest::SHA256, &msg));
        let mut packet = vec![0x10, 0, 0, 1, b'Z', b'R', b'T', b'P', 0, 0, 0, seed];
        packet.extend(msg);
        packet.extend([0; 4]); // fixture framing; CRC verification belongs to endpoint
        (packet, hash)
    }
    #[test]
    fn policy_and_transport_rewrite() {
        let (hello, hash) = hello(1);
        let sdp = format!(
            "v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 4000 RTP/AVP 0\r\na=zrtp-hash:1.10 {hash}\r\n"
        );
        let hashes = validate_sdp(&sdp).unwrap();
        assert!(is_hello(&hello, &hashes));
        let mut altered = hello.clone();
        altered[50] ^= 1;
        assert!(!is_hello(&altered, &hashes));
        for suffix in [
            "a=crypto:1 bad\r\n",
            "a=ice-ufrag:abc\r\n",
            "m=video 4002 RTP/AVP 96\r\n",
            "k=clear:secret\r\n",
        ] {
            assert!(validate_sdp(&(sdp.clone() + suffix)).is_none());
        }
        assert!(validate_sdp(&sdp.replace(&hash, "abcd")).is_none());
        assert!(validate_sdp(&sdp.replace("a=zrtp-hash:", "a=unknown:")).is_none());
        let rewritten = rewrite_sdp(&sdp, "203.0.113.1", 20000);
        assert!(rewritten.contains("m=audio 20000 RTP/AVP 0"));
        assert!(rewritten.contains("a=rtcp:20001 IN IP4 203.0.113.1"));
        assert!(rewritten.contains(&hash));
        assert!(!rewritten.contains("10.0.0.1"));
    }
}
