//! Server-side admission policy, not endpoint cryptography.
//!
//! Peers perform DTLS-SRTP and verify independently trusted identities. MESSAGE
//! carries a compact JWE. This server never generates or receives content keys.
//! Envelope validation cannot prove encryption or authenticate its sender;
//! recipients must verify AEAD, the inner signature and replay metadata.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;

#[derive(Clone, Copy)]
pub enum SdpRole {
    Offer,
    Answer,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityHeader {
    alg: String,
    typ: String,
    kid: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityClaims {
    iss: String,
    aud: String,
    call_id: String,
    role: String,
    sdp_sha256: String,
    iat: u64,
    exp: u64,
}

/// Admission checks only. Endpoints MUST verify the Ed25519 signature against an
/// independently pinned peer key before using this SDP. A server cannot be the
/// trust anchor for protecting a call against that same server.
pub fn validate_identity(
    token: &str,
    sdp: &str,
    sender: &str,
    recipient: &str,
    call_id: &str,
    role: SdpRole,
) -> Result<(), &'static str> {
    let parts: Vec<_> = token.split('.').collect();
    if token.len() > 2048 || parts.len() != 3 {
        return Err("signed SDP identity required");
    }
    let header: IdentityHeader = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|_| "invalid identity header")?,
    )
    .map_err(|_| "invalid identity header")?;
    let claims: IdentityClaims = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| "invalid identity claims")?,
    )
    .map_err(|_| "invalid identity claims")?;
    let signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| "invalid identity signature")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "invalid clock")?
        .as_secs();
    let expected_role = match role {
        SdpRole::Offer => "offer",
        SdpRole::Answer => "answer",
    };
    if header.alg != "EdDSA"
        || header.typ != "minghe-sdp+jwt"
        || header.kid.len() != 64
        || !header
            .kid
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || signature.len() != 64
        || claims.iss != sender
        || claims.aud != recipient
        || claims.call_id != call_id
        || claims.role != expected_role
        || claims.sdp_sha256
            != hex::encode(ring::digest::digest(&ring::digest::SHA256, sdp.as_bytes()))
        || claims.exp <= now
        || claims.iat > now.saturating_add(30)
        || claims.exp <= claims.iat
        || claims.exp - claims.iat > 120
    {
        return Err("identity does not bind this SDP and call");
    }
    Ok(())
}

#[derive(Default)]
struct Attributes<'a> {
    fingerprint: Option<&'a str>,
    setup: Option<&'a str>,
    rtcp_mux: bool,
}

fn set_once<'a>(slot: &mut Option<&'a str>, value: &'a str) -> Result<(), &'static str> {
    if slot.replace(value).is_some() {
        return Err("ambiguous DTLS attribute");
    }
    Ok(())
}

fn valid_fingerprint(value: &str) -> bool {
    let mut parts = value.split_whitespace();
    let Some(algorithm) = parts.next() else {
        return false;
    };
    if !algorithm.eq_ignore_ascii_case("sha-256") {
        return false;
    }
    let Some(digest) = parts.next() else {
        return false;
    };
    let octets: Vec<_> = digest.split(':').collect();
    parts.next().is_none()
        && octets.len() == 32
        && octets
            .iter()
            .all(|s| s.len() == 2 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        && octets.iter().any(|s| *s != "00")
}

/// A deliberately narrow profile: one active audio stream with RTCP mux.
/// Accept session attributes or media overrides; reject all key-bearing SDP.
/// Keep SDP bytes untouched, including ICE, codecs and certificate fingerprints.
pub fn validate_sdp(sdp: &str, role: SdpRole) -> Result<(), &'static str> {
    let mut session = Attributes::default();
    let mut media = Attributes::default();
    let mut saw_audio = false;
    if !sdp.starts_with("v=0\r\n") {
        return Err("invalid SDP version/framing");
    }
    for line in sdp.lines() {
        let line = line.trim();
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("k=") || lower.starts_with("a=crypto") {
            return Err("SDES and SDP keys are forbidden");
        }
        if let Some(value) = line.strip_prefix("m=") {
            if saw_audio {
                return Err("multiple media streams are not supported");
            }
            let fields: Vec<_> = value.split_whitespace().collect();
            if fields.len() < 4
                || fields[0] != "audio"
                || !matches!(fields[2], "UDP/TLS/RTP/SAVP" | "UDP/TLS/RTP/SAVPF")
                || !fields[1].parse::<u16>().is_ok_and(|port| port != 0)
            {
                return Err("active DTLS-SRTP audio required");
            }
            saw_audio = true;
        } else {
            let attrs = if saw_audio { &mut media } else { &mut session };
            if let Some(value) = line.strip_prefix("a=fingerprint:") {
                if !valid_fingerprint(value) {
                    return Err("SHA-256 certificate fingerprint required");
                }
                set_once(&mut attrs.fingerprint, value)?;
            } else if let Some(value) = line.strip_prefix("a=setup:") {
                set_once(&mut attrs.setup, value)?;
            } else if line == "a=rtcp-mux" {
                attrs.rtcp_mux = true;
            }
        }
    }
    if !saw_audio || media.fingerprint.or(session.fingerprint).is_none() || !media.rtcp_mux {
        return Err("audio, fingerprint and media RTCP mux required");
    }
    match (role, media.setup.or(session.setup)) {
        (SdpRole::Offer, Some("actpass")) | (SdpRole::Answer, Some("active" | "passive")) => Ok(()),
        _ => Err("invalid DTLS offer/answer role"),
    }
}

// Unknown parameters, duplicate fields and remotely supplied key references are
// rejected by serde. The allowlist intentionally excludes RSA1_5, dir, zip,
// crit, jku, x5u and jwk. No server-side key lookup is performed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedHeader {
    alg: String,
    enc: String,
    cty: String,
    kid: String,
}

/// Validate RFC 7516 compact serialization without decrypting it.
/// Required profile: RSA-OAEP-256 (3072/4096 bit key), A256GCM,
/// signed inner JWS (cty=JWT). Authentication occurs only at the endpoint.
pub fn validate_message(content_type: &str, body: &str) -> Result<(), &'static str> {
    if !content_type.trim().eq_ignore_ascii_case("application/jose") {
        return Err("encrypted application/jose required");
    }
    let parts: Vec<_> = body.split('.').collect();
    if parts.len() != 5 || parts.iter().any(|s| s.is_empty()) {
        return Err("compact JWE must have five nonempty parts");
    }
    let decoded: Vec<_> = parts.iter().map(|s| URL_SAFE_NO_PAD.decode(s)).collect();
    let decoded: Vec<Vec<u8>> = decoded
        .into_iter()
        .collect::<Result<_, _>>()
        .map_err(|_| "invalid JWE base64url")?;
    let header: ProtectedHeader =
        serde_json::from_slice(&decoded[0]).map_err(|_| "invalid or unsupported JWE header")?;
    if header.alg != "RSA-OAEP-256"
        || header.enc != "A256GCM"
        || header.cty != "JWT"
        || header.kid.len() != 64
        || !header
            .kid
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("unsupported JWE algorithm or recipient key ID");
    }
    if !matches!(decoded[1].len(), 384 | 512)
        || decoded[2].len() != 12
        || decoded[3].is_empty()
        || decoded[4].len() != 16
    {
        return Err("invalid JWE encrypted key, nonce, ciphertext or tag size");
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn test_jwe(ciphertext: &str) -> String {
    // Structural fixture only; these bytes are not cryptographically valid.
    [
        URL_SAFE_NO_PAD
            .encode(br#"{"alg":"RSA-OAEP-256","enc":"A256GCM","cty":"JWT","kid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#),
        URL_SAFE_NO_PAD.encode([1u8; 384]),
        URL_SAFE_NO_PAD.encode([2u8; 12]),
        URL_SAFE_NO_PAD.encode(ciphertext.as_bytes()),
        URL_SAFE_NO_PAD.encode([3u8; 16]),
    ]
    .join(".")
}

#[cfg(test)]
pub(crate) fn test_sdp(setup: &str) -> String {
    format!("v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\nm=audio 4000 UDP/TLS/RTP/SAVPF 111\r\na=fingerprint:sha-256 {}\r\na=setup:{}\r\na=rtcp-mux\r\na=ice-ufrag:peer\r\na=ice-pwd:peer-password-for-testing\r\n", vec!["AB";32].join(":"), setup)
}

#[cfg(test)]
pub(crate) fn test_identity(
    sdp: &str,
    sender: &str,
    recipient: &str,
    call_id: &str,
    role: &str,
) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    [
        URL_SAFE_NO_PAD.encode(serde_json::json!({"alg":"EdDSA","typ":"minghe-sdp+jwt","kid":"a".repeat(64)}).to_string()),
        URL_SAFE_NO_PAD.encode(serde_json::json!({"iss":sender,"aud":recipient,"call_id":call_id,"role":role,
            "sdp_sha256":hex::encode(ring::digest::digest(&ring::digest::SHA256,sdp.as_bytes())),"iat":now,"exp":now+120}).to_string()),
        URL_SAFE_NO_PAD.encode([0u8;64]),
    ].join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_real_jwe_generated_by_reference_endpoint() {
        // Real RSA-OAEP-256 / A256GCM envelope produced with pyca/cryptography.
        // Private fixture keys are discarded; endpoint tests cover decryption.
        assert!(validate_message(
            "application/jose",
            include_str!("../../tools/fixtures/message.jwe")
        )
        .is_ok());
    }

    #[test]
    fn requires_dtls_with_strong_fingerprint_and_correct_role() {
        let sdp = test_sdp("actpass");
        assert!(validate_sdp(&sdp, SdpRole::Offer).is_ok());
        assert!(validate_sdp(&sdp, SdpRole::Answer).is_err());
        assert!(validate_sdp(&test_sdp("active"), SdpRole::Answer).is_ok());
        assert!(validate_sdp(&test_sdp("passive"), SdpRole::Answer).is_ok());
        for invalid in [
            sdp.replace("UDP/TLS/RTP/SAVPF", "RTP/AVP"),
            sdp.replace("UDP/TLS/RTP/SAVPF", "RTP/SAVP"),
            sdp.replace("sha-256", "sha-1"),
            sdp.replace("m=audio 4000", "m=audio 0"),
            sdp.replace("a=rtcp-mux\r\n", ""),
            format!("{sdp}a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:SECRET\r\n"),
            format!("{sdp}k=clear:SECRET\r\n"),
            format!("{sdp}a=setup:active\r\n"),
            format!("{sdp}m=video 5000 RTP/AVP 96\r\n"),
        ] {
            assert!(validate_sdp(&invalid, SdpRole::Offer).is_err());
        }
    }

    #[test]
    fn accepts_session_fingerprint_but_rejects_malformed_or_duplicate_digest() {
        let sdp = test_sdp("actpass");
        let fingerprint = sdp
            .lines()
            .find(|l| l.starts_with("a=fingerprint:"))
            .unwrap();
        let session = sdp.replace(&format!("{fingerprint}\r\n"), "").replacen(
            "m=audio",
            &format!("{fingerprint}\r\nm=audio"),
            1,
        );
        assert!(validate_sdp(&session, SdpRole::Offer).is_ok());
        assert!(validate_sdp(&format!("{sdp}{fingerprint}\r\n"), SdpRole::Offer).is_err());
        assert!(validate_sdp(&sdp.replace("AB:", "GG:"), SdpRole::Offer).is_err());
        assert!(validate_sdp(&sdp.replace("AB", "00"), SdpRole::Offer).is_err());
    }

    #[test]
    fn rejects_plaintext_signed_only_and_malformed_envelopes() {
        let jwe = test_jwe("ciphertext");
        assert!(validate_message("application/jose", &jwe).is_ok());
        assert!(validate_message("text/plain", &jwe).is_err());
        for invalid in [
            "hello",
            "a.b.c",
            "a.b.c.d.e",
            &format!("{jwe}.extra"),
            &format!("{jwe}\n"),
        ] {
            assert!(validate_message("application/jose", invalid).is_err());
        }
        let mut parts: Vec<_> = jwe.split('.').map(str::to_string).collect();
        for header in [
            r#"{"alg":"RSA1_5","enc":"A256GCM","cty":"JWT","kid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
            r#"{"alg":"RSA-OAEP-256","enc":"A128CBC-HS256","cty":"JWT","kid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
            r#"{"alg":"RSA-OAEP-256","alg":"RSA-OAEP-256","enc":"A256GCM","cty":"JWT","kid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
            r#"{"alg":"RSA-OAEP-256","enc":"A256GCM","cty":"JWT","kid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","jku":"https://attacker.invalid/"}"#,
        ] {
            parts[0] = URL_SAFE_NO_PAD.encode(header);
            assert!(validate_message("application/jose", &parts.join(".")).is_err());
        }
        parts = jwe.split('.').map(str::to_string).collect();
        parts[2] = URL_SAFE_NO_PAD.encode([0u8; 8]);
        assert!(validate_message("application/jose", &parts.join(".")).is_err());
    }

    #[test]
    fn signed_identity_binds_sdp_peers_call_and_role() {
        let sdp = test_sdp("actpass");
        let identity = test_identity(&sdp, "1001", "1002", "call-1", "offer");
        assert!(
            validate_identity(&identity, &sdp, "1001", "1002", "call-1", SdpRole::Offer).is_ok()
        );
        for (sender, recipient, call_id, role, body) in [
            ("1003", "1002", "call-1", SdpRole::Offer, sdp.clone()),
            ("1001", "1003", "call-1", SdpRole::Offer, sdp.clone()),
            ("1001", "1002", "call-2", SdpRole::Offer, sdp.clone()),
            ("1001", "1002", "call-1", SdpRole::Answer, sdp.clone()),
            (
                "1001",
                "1002",
                "call-1",
                SdpRole::Offer,
                sdp.replace("AB", "CD"),
            ),
        ] {
            assert!(validate_identity(&identity, &body, sender, recipient, call_id, role).is_err());
        }
        let mut parts: Vec<_> = identity.split('.').map(str::to_string).collect();
        let mut claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&parts[1]).unwrap()).unwrap();
        claims["exp"] = serde_json::json!(0);
        parts[1] = URL_SAFE_NO_PAD.encode(claims.to_string());
        assert!(validate_identity(
            &parts.join("."),
            &sdp,
            "1001",
            "1002",
            "call-1",
            SdpRole::Offer
        )
        .is_err());
    }
}
