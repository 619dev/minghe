//! SRTP 加解密实现 — 基于 SDES 密钥交换
//!
//! 实现 RFC 3711 SRTP 协议，使用 AES_CM_128_HMAC_SHA1_80 加密套件。
//! 支持从 SDP `a=crypto` 属性解析和生成 SDES 密钥。

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;
use std::collections::HashMap;
use std::fmt;

/// HMAC-SHA1 类型别名
type HmacSha1 = Hmac<Sha1>;

/// SRTP 认证标签长度（80 位 = 10 字节）
const AUTH_TAG_LEN: usize = 10;

/// GCM 认证标签长度（128 位 = 16 字节）
const GCM_AUTH_TAG_LEN: usize = 16;

/// SRTP 加密套件类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrtpSuite {
    /// AES-128-CM 载荷加密 + HMAC-SHA1-80 认证（RFC 3711 标准套件）
    AesCm128HmacSha180,
    /// AES-128-GCM AEAD 认证加密（RFC 7714）
    AeadAes128Gcm,
}

impl SrtpSuite {
    /// SDP `a=crypto` 属性中的套件名称
    pub fn sdp_name(&self) -> &'static str {
        match self {
            SrtpSuite::AesCm128HmacSha180 => "AES_CM_128_HMAC_SHA1_80",
            SrtpSuite::AeadAes128Gcm => "AEAD_AES_128_GCM",
        }
    }

    /// 认证标签长度（字节）
    pub fn auth_tag_len(&self) -> usize {
        match self {
            SrtpSuite::AesCm128HmacSha180 => AUTH_TAG_LEN,
            SrtpSuite::AeadAes128Gcm => GCM_AUTH_TAG_LEN,
        }
    }

    /// 主盐值长度（字节）
    ///
    /// - AES_CM_128_HMAC_SHA1_80：112 位（14 字节，RFC 3711）
    /// - AEAD_AES_128_GCM：96 位（12 字节，RFC 7714）
    ///
    /// SDES `inline:` 密钥总长度为 `主密钥(16) + 盐值`，即 AES_CM 为 30 字节、GCM 为 28 字节。
    pub fn salt_len(&self) -> usize {
        match self {
            SrtpSuite::AesCm128HmacSha180 => MASTER_SALT_LEN,
            SrtpSuite::AeadAes128Gcm => GCM_SALT_LEN,
        }
    }

    /// 根据 SDP 套件名称解析
    pub fn from_sdp_name(name: &str) -> Option<SrtpSuite> {
        match name.to_ascii_uppercase().as_str() {
            "AES_CM_128_HMAC_SHA1_80" => Some(SrtpSuite::AesCm128HmacSha180),
            "AEAD_AES_128_GCM" => Some(SrtpSuite::AeadAes128Gcm),
            _ => None,
        }
    }
}

/// 主密钥长度（128 位 = 16 字节）
const MASTER_KEY_LEN: usize = 16;

/// 主盐值长度（112 位 = 14 字节，RFC 3711 AES_CM_128_HMAC_SHA1_80）
const MASTER_SALT_LEN: usize = 14;

/// AEAD_AES_128_GCM 盐值长度（96 位 = 12 字节，RFC 7714）
const GCM_SALT_LEN: usize = 12;

/// 会话密钥长度
const SESSION_KEY_LEN: usize = 16;

/// 会话盐值长度
const SESSION_SALT_LEN: usize = 14;

/// 会话认证密钥长度（160 位 = 20 字节）
const SESSION_AUTH_KEY_LEN: usize = 20;

/// RTP 固定头部最小长度
const RTP_HEADER_MIN_LEN: usize = 12;

/// KDF 标签：加密密钥
const LABEL_CIPHER_KEY: u8 = 0x00;

/// KDF 标签：认证密钥
const LABEL_AUTH_KEY: u8 = 0x01;

/// KDF 标签：盐值
const LABEL_SALT: u8 = 0x02;

/// SRTP 加密套件错误类型
#[derive(Debug)]
pub enum SrtpError {
    /// SDES 密钥格式无效
    InvalidSdesKey(String),
    /// RTP 数据包格式无效
    InvalidRtpPacket(String),
    /// SRTP 认证失败
    AuthenticationFailed,
    /// 加密操作失败
    EncryptionFailed(String),
    /// Base64 解码失败
    Base64DecodeError(String),
    /// 加密属性解析失败
    CryptoAttributeParseError(String),
}

impl fmt::Display for SrtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SrtpError::InvalidSdesKey(msg) => write!(f, "无效的 SDES 密钥: {}", msg),
            SrtpError::InvalidRtpPacket(msg) => write!(f, "无效的 RTP 数据包: {}", msg),
            SrtpError::AuthenticationFailed => write!(f, "SRTP 认证失败"),
            SrtpError::EncryptionFailed(msg) => write!(f, "SRTP 加密失败: {}", msg),
            SrtpError::Base64DecodeError(msg) => write!(f, "Base64 解码失败: {}", msg),
            SrtpError::CryptoAttributeParseError(msg) => {
                write!(f, "加密属性解析失败: {}", msg)
            }
        }
    }
}

impl std::error::Error for SrtpError {}

/// SRTP 加密套件结果类型
pub type Result<T> = std::result::Result<T, SrtpError>;

/// SRTP 加密套件 — AES_CM_128_HMAC_SHA1_80
///
/// 实现 RFC 3711 中定义的 SRTP 加解密，包括：
/// - AES-128-CM 载荷加解密
/// - HMAC-SHA1-80 认证标签
/// - SDES 密钥交换格式
#[derive(Clone)]
pub struct SrtpCryptoSuite {
    /// 加密套件类型
    suite: SrtpSuite,
    /// 主密钥（128 位）
    master_key: [u8; MASTER_KEY_LEN],
    /// 主盐值（112 位）
    master_salt: [u8; MASTER_SALT_LEN],
    /// 会话加密密钥（从主密钥派生）
    session_key: [u8; SESSION_KEY_LEN],
    /// 会话盐值（从主密钥派生）
    session_salt: [u8; SESSION_SALT_LEN],
    /// 会话认证密钥（从主密钥派生）
    session_auth_key: [u8; SESSION_AUTH_KEY_LEN],
    /// 每个 SSRC 的 ROC 状态
    stream_states: HashMap<u32, SrtpStreamState>,
}

#[derive(Clone, Copy, Debug, Default)]
struct SrtpStreamState {
    roc: u32,
    highest_sequence: Option<u16>,
    replay_window: u64,
}

impl SrtpCryptoSuite {
    /// 创建新的加密套件，随机生成主密钥和盐值
    pub fn new() -> Self {
        Self::new_with_suite(SrtpSuite::AesCm128HmacSha180)
    }

    /// 创建指定套件的加密套件，随机生成主密钥和盐值
    pub fn new_with_suite(suite: SrtpSuite) -> Self {
        let mut master_key = [0u8; MASTER_KEY_LEN];
        let mut master_salt = [0u8; MASTER_SALT_LEN];

        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut master_key);
        // GCM 使用 96 位盐值（RFC 7714），其余字节保持为 0
        rng.fill_bytes(&mut master_salt[..suite.salt_len()]);

        let mut suite_inst = Self {
            suite,
            master_key,
            master_salt,
            session_key: [0u8; SESSION_KEY_LEN],
            session_salt: [0u8; SESSION_SALT_LEN],
            session_auth_key: [0u8; SESSION_AUTH_KEY_LEN],
            stream_states: HashMap::new(),
        };
        suite_inst.derive_session_keys();
        suite_inst
    }

    /// 从 SDES inline 密钥（Base64 编码的 key||salt）创建加密套件
    ///
    /// 输入格式：Base64 编码数据，长度为 `主密钥(16) + 盐值`。
    /// - AES_CM_128_HMAC_SHA1_80：30 字节（16 字节密钥 + 14 字节盐值）
    /// - AEAD_AES_128_GCM：28 字节（16 字节密钥 + 12 字节盐值，RFC 7714）
    pub fn from_sdes(base64_key_salt: &str) -> Result<Self> {
        Self::from_sdes_with_suite(SrtpSuite::AesCm128HmacSha180, base64_key_salt)
    }

    /// 从 SDES inline 密钥创建指定套件的加密套件
    pub fn from_sdes_with_suite(suite: SrtpSuite, base64_key_salt: &str) -> Result<Self> {
        let decoded = BASE64
            .decode(base64_key_salt.trim())
            .map_err(|e| SrtpError::Base64DecodeError(e.to_string()))?;

        let expected_len = MASTER_KEY_LEN + suite.salt_len();
        if decoded.len() != expected_len {
            return Err(SrtpError::InvalidSdesKey(format!(
                "期望 {} 字节（套件 {}），实际 {} 字节",
                expected_len,
                suite.sdp_name(),
                decoded.len()
            )));
        }

        let mut master_key = [0u8; MASTER_KEY_LEN];
        let mut master_salt = [0u8; MASTER_SALT_LEN];
        master_key.copy_from_slice(&decoded[..MASTER_KEY_LEN]);
        master_salt[..suite.salt_len()].copy_from_slice(&decoded[MASTER_KEY_LEN..]);

        let mut suite_inst = Self {
            suite,
            master_key,
            master_salt,
            session_key: [0u8; SESSION_KEY_LEN],
            session_salt: [0u8; SESSION_SALT_LEN],
            session_auth_key: [0u8; SESSION_AUTH_KEY_LEN],
            stream_states: HashMap::new(),
        };
        suite_inst.derive_session_keys();
        Ok(suite_inst)
    }

    /// 获取加密套件类型
    pub fn suite(&self) -> SrtpSuite {
        self.suite
    }

    /// 获取 SDP 套件名称
    pub fn suite_name(&self) -> &'static str {
        self.suite.sdp_name()
    }

    /// 获取 SDES inline 密钥（Base64 编码的 key||salt，不含前缀与生命周期参数）
    ///
    /// 输出长度按套件而定：AES_CM 为 30 字节（key 16 + salt 14），GCM 为 28 字节（key 16 + salt 12）。
    pub fn to_sdes_key(&self) -> String {
        let salt_len = self.suite.salt_len();
        let mut key_salt = Vec::with_capacity(MASTER_KEY_LEN + salt_len);
        key_salt.extend_from_slice(&self.master_key);
        key_salt.extend_from_slice(&self.master_salt[..salt_len]);
        BASE64.encode(&key_salt)
    }

    /// 生成 SDES `a=crypto` 属性值
    ///
    /// 返回格式：`a=crypto:1 <SUITE> inline:<base64>`
    pub fn to_sdes_attribute(&self) -> String {
        format!(
            "a=crypto:1 {} inline:{}",
            self.suite.sdp_name(),
            self.to_sdes_key()
        )
    }

    /// 生成 SDP crypto 行
    ///
    /// 返回格式：`a=crypto:<tag> <SUITE> inline:<base64>`
    pub fn to_sdp_crypto_line(&self, tag: u32) -> String {
        format!(
            "a=crypto:{} {} inline:{}",
            tag,
            self.suite.sdp_name(),
            self.to_sdes_key()
        )
    }

    /// 获取主密钥的引用
    pub fn master_key(&self) -> &[u8; MASTER_KEY_LEN] {
        &self.master_key
    }

    /// 获取主盐值的引用
    pub fn master_salt(&self) -> &[u8; MASTER_SALT_LEN] {
        &self.master_salt
    }

    /// RFC 3711 密钥派生函数（KDF）
    ///
    /// 从主密钥和主盐值派生会话密钥、会话盐值和会话认证密钥。
    /// 使用 AES-CM 伪随机函数（PRF）。
    ///
    /// - label 0x00 → 会话加密密钥（128 位）
    /// - label 0x01 → 会话认证密钥（160 位，仅 AES-CM 套件需要）
    /// - label 0x02 → 会话盐值（112 位；GCM 套件只使用前 96 位）
    fn derive_session_keys(&mut self) {
        self.session_key = self.prf_derive(LABEL_CIPHER_KEY, SESSION_KEY_LEN);
        // 盐值只有 14 字节，先派生 16 字节再截断
        let salt_full: [u8; SESSION_KEY_LEN] = self.prf_derive(LABEL_SALT, SESSION_KEY_LEN);
        self.session_salt
            .copy_from_slice(&salt_full[..SESSION_SALT_LEN]);
        // 仅 AES-CM 套件需要 HMAC 认证密钥；GCM 为 AEAD 模式，认证由 GCM 标签完成
        if self.suite == SrtpSuite::AesCm128HmacSha180 {
            // 认证密钥需要 20 字节，可能需要多个 AES 块
            self.session_auth_key = self.prf_derive_auth(LABEL_AUTH_KEY, SESSION_AUTH_KEY_LEN);
        }
    }

    /// AES-CM PRF 派生函数 — 派生最多 16 字节的密钥材料
    ///
    /// 按照 RFC 3711 Section 4.3.1:
    /// 输入 x = label || r (其中 r = key_derivation_rate，默认为 0)
    /// IV = (master_salt XOR (label << 48)) 左填充到 16 字节
    /// 输出 = AES_CM(master_key, IV)
    fn prf_derive<const N: usize>(&self, label: u8, _len: usize) -> [u8; N] {
        let cipher =
            Aes128::new_from_slice(&self.master_key).expect("AES-128 密钥长度必须为 16 字节");

        // 构造 x = label || 0^48 的 key_id。
        // RFC 3711 将 112-bit master salt 放在 AES-CM 输入的高 112 位，
        // 低 16 位留给 block counter。
        let mut iv = [0u8; 16];
        iv[..MASTER_SALT_LEN].copy_from_slice(&self.master_salt);
        // label 放在第 7 字节位置（从左起，对应 label << 48 在 112 位盐值空间中）
        iv[7] ^= label;

        let mut result = [0u8; N];
        let mut offset = 0;
        let mut counter: u16 = 0;

        while offset < N {
            // 构造当前计数器块
            let mut block = iv;
            // 在最后两字节放置计数器
            block[14] ^= (counter >> 8) as u8;
            block[15] ^= (counter & 0xFF) as u8;

            // AES-ECB 加密（AES-CM 本质上是用 AES-ECB 加密计数器值）
            let mut aes_block = aes::Block::clone_from_slice(&block);
            cipher.encrypt_block(&mut aes_block);

            let copy_len = std::cmp::min(16, N - offset);
            result[offset..offset + copy_len].copy_from_slice(&aes_block[..copy_len]);
            offset += copy_len;
            counter += 1;
        }

        result
    }

    /// AES-CM PRF 派生函数 — 派生认证密钥（20 字节，需要多个 AES 块）
    fn prf_derive_auth(&self, label: u8, len: usize) -> [u8; SESSION_AUTH_KEY_LEN] {
        let cipher =
            Aes128::new_from_slice(&self.master_key).expect("AES-128 密钥长度必须为 16 字节");

        let mut iv = [0u8; 16];
        iv[..MASTER_SALT_LEN].copy_from_slice(&self.master_salt);
        iv[7] ^= label;

        let mut result = [0u8; SESSION_AUTH_KEY_LEN];
        let mut offset = 0;
        let mut counter: u16 = 0;

        while offset < len {
            let mut block = iv;
            block[14] ^= (counter >> 8) as u8;
            block[15] ^= (counter & 0xFF) as u8;

            let mut aes_block = aes::Block::clone_from_slice(&block);
            cipher.encrypt_block(&mut aes_block);

            let copy_len = std::cmp::min(16, len - offset);
            result[offset..offset + copy_len].copy_from_slice(&aes_block[..copy_len]);
            offset += copy_len;
            counter += 1;
        }

        result
    }

    /// 加密 RTP 数据包为 SRTP 数据包
    ///
    /// 步骤：
    /// 1. 解析 RTP 头部（至少 12 字节）
    /// 2. 按套件处理：
    ///    - AES_CM_128_HMAC_SHA1_80：AES-CM 加密载荷 + HMAC-SHA1-80 认证标签（10 字节）
    ///    - AEAD_AES_128_GCM：AES-128-GCM 认证加密载荷 + 16 字节认证标签（RFC 7714）
    ///
    /// 输入：完整的 RTP 数据包
    /// 输出：SRTP 数据包 = RTP头部 + 加密载荷 + 认证标签
    pub fn protect_rtp(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        if packet.len() < RTP_HEADER_MIN_LEN {
            return Err(SrtpError::InvalidRtpPacket(format!(
                "数据包太短: {} 字节，最少需要 {} 字节",
                packet.len(),
                RTP_HEADER_MIN_LEN
            )));
        }

        // 解析 RTP 头部
        let header = RtpHeader::parse(packet)?;
        let header_len = header.total_header_len();

        if packet.len() < header_len {
            return Err(SrtpError::InvalidRtpPacket(
                "数据包长度小于 RTP 头部长度".to_string(),
            ));
        }

        let payload = &packet[header_len..];

        // 计算 packet index = ROC * 65536 + seq
        let snapshot = self
            .stream_states
            .get(&header.ssrc)
            .copied()
            .unwrap_or_default();
        if !self.stream_states.contains_key(&header.ssrc) && self.stream_states.len() >= 64 {
            return Err(SrtpError::AuthenticationFailed);
        }
        let roc = estimate_roc(snapshot, header.sequence_number);
        let index = ((roc as u64) << 16) | header.sequence_number as u64;
        if let Some(seq) = snapshot.highest_sequence {
            let highest = ((snapshot.roc as u64) << 16) | seq as u64;
            if index <= highest {
                let delta = highest - index;
                if delta >= 64 || snapshot.replay_window & (1u64 << delta) != 0 {
                    return Err(SrtpError::AuthenticationFailed);
                }
            }
        }
        let packet_index: u64 = (roc as u64) * 65536 + header.sequence_number as u64;

        let srtp_packet = match self.suite {
            SrtpSuite::AesCm128HmacSha180 => {
                // AES-CM 加密载荷
                let encrypted_payload = self.aes_cm_encrypt(header.ssrc, packet_index, payload);

                // 组装 SRTP 数据包（头部不变 + 加密载荷）
                let mut srtp_packet = Vec::with_capacity(packet.len() + AUTH_TAG_LEN);
                srtp_packet.extend_from_slice(&packet[..header_len]); // 原始头部
                srtp_packet.extend_from_slice(&encrypted_payload); // 加密载荷

                // 计算 HMAC-SHA1-80 认证标签
                // 认证范围：SRTP 头部 + 加密载荷 + ROC（4 字节，网络字节序）
                let auth_tag = self.compute_auth_tag(&srtp_packet, roc);
                srtp_packet.extend_from_slice(&auth_tag);
                srtp_packet
            }
            SrtpSuite::AeadAes128Gcm => {
                // AES-128-GCM 认证加密（AAD = RTP 头部，输出密文 + 16 字节标签）
                let encrypted = self.gcm_encrypt_payload(
                    header.ssrc,
                    roc,
                    header.sequence_number,
                    &packet[..header_len],
                    payload,
                )?;
                let mut srtp_packet = Vec::with_capacity(packet.len() + GCM_AUTH_TAG_LEN);
                srtp_packet.extend_from_slice(&packet[..header_len]); // 原始头部
                srtp_packet.extend_from_slice(&encrypted); // 密文 + 16 字节标签
                srtp_packet
            }
        };

        let state = self.stream_state_mut(header.ssrc);
        update_stream_state_after_success(state, header.sequence_number, roc);

        Ok(srtp_packet)
    }

    /// 解密 SRTP 数据包为 RTP 数据包
    ///
    /// 步骤：
    /// 1. 验证认证标签（HMAC-SHA1-80 或 GCM 认证）
    /// 2. 解密载荷
    ///
    /// 输入：完整的 SRTP 数据包
    /// 输出：RTP 数据包 = RTP头部 + 明文载荷
    pub fn unprotect_rtp(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        let tag_len = self.suite.auth_tag_len();
        if packet.len() < RTP_HEADER_MIN_LEN + tag_len {
            return Err(SrtpError::InvalidRtpPacket(format!(
                "SRTP 数据包太短: {} 字节",
                packet.len()
            )));
        }

        // 分离认证标签
        let auth_tag_start = packet.len() - tag_len;
        let authenticated_portion = &packet[..auth_tag_start];
        let received_tag = &packet[auth_tag_start..];

        // 解析 RTP 头部
        let header = RtpHeader::parse(authenticated_portion)?;
        let header_len = header.total_header_len();

        if authenticated_portion.len() < header_len {
            return Err(SrtpError::InvalidRtpPacket(
                "数据包长度小于 RTP 头部长度".to_string(),
            ));
        }

        let snapshot = self
            .stream_states
            .get(&header.ssrc)
            .copied()
            .unwrap_or_default();
        if !self.stream_states.contains_key(&header.ssrc) && self.stream_states.len() >= 64 {
            return Err(SrtpError::AuthenticationFailed);
        }
        let roc = estimate_roc(snapshot, header.sequence_number);
        let index = ((roc as u64) << 16) | header.sequence_number as u64;
        if let Some(seq) = snapshot.highest_sequence {
            let highest = ((snapshot.roc as u64) << 16) | seq as u64;
            if index <= highest {
                let delta = highest - index;
                if delta >= 64 || snapshot.replay_window & (1u64 << delta) != 0 {
                    return Err(SrtpError::AuthenticationFailed);
                }
            }
        }

        let rtp_packet = match self.suite {
            SrtpSuite::AesCm128HmacSha180 => {
                // 验证认证标签
                let computed_tag = self.compute_auth_tag(authenticated_portion, roc);
                if !constant_time_eq(&computed_tag, received_tag) {
                    return Err(SrtpError::AuthenticationFailed);
                }

                let encrypted_payload = &authenticated_portion[header_len..];

                // 计算 packet index
                let packet_index: u64 = (roc as u64) * 65536 + header.sequence_number as u64;

                // AES-CM 解密（加解密操作相同）
                let decrypted_payload =
                    self.aes_cm_encrypt(header.ssrc, packet_index, encrypted_payload);

                // 组装 RTP 数据包
                let mut rtp_packet = Vec::with_capacity(header_len + decrypted_payload.len());
                rtp_packet.extend_from_slice(&authenticated_portion[..header_len]);
                rtp_packet.extend_from_slice(&decrypted_payload);
                rtp_packet
            }
            SrtpSuite::AeadAes128Gcm => {
                // AES-128-GCM 解密并验证认证标签（AAD = RTP 头部）。
                // 注意：GCM 的认证标签必须随密文一起传入 decrypt（与 AES_CM
                // 的独立 HMAC 标签不同），因此这里直接使用完整 packet 而不分离标签。
                let plaintext = self.gcm_decrypt_payload(
                    header.ssrc,
                    roc,
                    header.sequence_number,
                    &packet[..header_len],
                    &packet[header_len..],
                )?;

                // 组装 RTP 数据包
                let mut rtp_packet = Vec::with_capacity(header_len + plaintext.len());
                rtp_packet.extend_from_slice(&packet[..header_len]);
                rtp_packet.extend_from_slice(&plaintext);
                rtp_packet
            }
        };

        let state = self.stream_state_mut(header.ssrc);
        update_stream_state_after_success(state, header.sequence_number, roc);

        Ok(rtp_packet)
    }

    /// AES-CM（Counter Mode）加解密
    ///
    /// RFC 3711 Section 4.1.1:
    /// IV = (k_s XOR (SSRC || packet_index)) 左填充到 16 字节
    ///
    /// 由于 CTR 模式加密和解密操作完全相同，此函数同时用于加密和解密。
    fn aes_cm_encrypt(&self, ssrc: u32, packet_index: u64, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        }

        let cipher = Aes128::new_from_slice(&self.session_key).expect("会话密钥长度必须为 16 字节");

        // 构造 IV（16 字节）。RFC 3711 AES_CM 使用：
        // (session_salt << 16) XOR (SSRC << 64) XOR (packet_index << 16)
        // 低 16 位保留给 block counter。
        let mut iv = [0u8; 16];
        // SSRC 在字节 4-7
        iv[4..8].copy_from_slice(&ssrc.to_be_bytes());
        // packet_index 在字节 8-13（48 位 = 6 字节）
        let pi_bytes = packet_index.to_be_bytes(); // 8 字节
        iv[8..14].copy_from_slice(&pi_bytes[2..8]); // 取低 48 位

        // 与 session_salt 异或（session_salt 是 14 字节，放在 iv[0..14]）
        for i in 0..SESSION_SALT_LEN {
            iv[i] ^= self.session_salt[i];
        }

        // AES-CM：逐块加密计数器值，然后与明文异或
        let mut result = Vec::with_capacity(data.len());
        let block_count = (data.len() + 15) / 16;

        for block_idx in 0..block_count {
            let mut counter_block = iv;
            // 计数器值放在最后 2 字节
            let counter = block_idx as u16;
            counter_block[14] ^= (counter >> 8) as u8;
            counter_block[15] ^= (counter & 0xFF) as u8;

            let mut aes_block = aes::Block::clone_from_slice(&counter_block);
            cipher.encrypt_block(&mut aes_block);

            let start = block_idx * 16;
            let end = std::cmp::min(start + 16, data.len());
            for i in start..end {
                result.push(data[i] ^ aes_block[i - start]);
            }
        }

        result
    }

    /// RFC 7714 §8.1 GCM 套件：构造 96 位 IV
    ///
    /// 先拼接 2 字节 0x0000 || SSRC(4) || ROC(4) || SEQ(2)，共 12 字节，
    /// 再与 96 位 session salt 逐字节异或，得到 12 字节 IV。
    /// 布局与 RFC 7714 Figure 1 及 libsrtp 的 srtp_calc_aead_iv 完全一致。
    fn gcm_iv(&self, ssrc: u32, roc: u32, sequence: u16) -> [u8; 12] {
        let mut iv = [0u8; 12]; // iv[0..2] = 00 00（RFC 7714 要求的前缀）
        iv[2..6].copy_from_slice(&ssrc.to_be_bytes());
        iv[6..10].copy_from_slice(&roc.to_be_bytes());
        iv[10..12].copy_from_slice(&sequence.to_be_bytes());
        for i in 0..12 {
            iv[i] ^= self.session_salt[i];
        }
        iv
    }

    /// AES-128-GCM 认证加密载荷并附加 16 字节认证标签
    ///
    /// AAD = RTP 头部（不加密但参与认证），ROC 通过 IV 隐式认证。
    fn gcm_encrypt_payload(
        &self,
        ssrc: u32,
        roc: u32,
        sequence: u16,
        aad: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let cipher = <Aes128Gcm as aes_gcm::aead::KeyInit>::new_from_slice(&self.session_key)
            .map_err(|_| SrtpError::InvalidRtpPacket("无效的 GCM 会话密钥".to_string()))?;
        let iv = self.gcm_iv(ssrc, roc, sequence);
        let nonce = Nonce::from_slice(&iv);
        let payload = aes_gcm::aead::Payload { msg: payload, aad };
        cipher
            .encrypt(nonce, payload)
            .map_err(|e| SrtpError::EncryptionFailed(e.to_string()))
    }

    /// AES-128-GCM 解密载荷并验证 16 字节认证标签
    ///
    /// 输入为密文 + 16 字节认证标签，AAD = RTP 头部。
    fn gcm_decrypt_payload(
        &self,
        ssrc: u32,
        roc: u32,
        sequence: u16,
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> Result<Vec<u8>> {
        let cipher = <Aes128Gcm as aes_gcm::aead::KeyInit>::new_from_slice(&self.session_key)
            .map_err(|_| SrtpError::InvalidRtpPacket("无效的 GCM 会话密钥".to_string()))?;
        let iv = self.gcm_iv(ssrc, roc, sequence);
        let nonce = Nonce::from_slice(&iv);
        let payload = aes_gcm::aead::Payload {
            msg: ciphertext_with_tag,
            aad,
        };
        cipher
            .decrypt(nonce, payload)
            .map_err(|_| SrtpError::AuthenticationFailed)
    }

    /// 计算 HMAC-SHA1-80 认证标签
    ///
    /// 输入：已认证部分（SRTP 头部 + 加密载荷）+ ROC（4 字节）
    /// 输出：截断到 80 位（10 字节）的 HMAC-SHA1 值
    fn compute_auth_tag(&self, authenticated_portion: &[u8], roc: u32) -> [u8; AUTH_TAG_LEN] {
        let mut mac = <HmacSha1 as Mac>::new_from_slice(&self.session_auth_key)
            .expect("HMAC-SHA1 接受任意长度密钥");

        mac.update(authenticated_portion);
        mac.update(&roc.to_be_bytes());

        let hmac_result = mac.finalize().into_bytes();
        let mut tag = [0u8; AUTH_TAG_LEN];
        tag.copy_from_slice(&hmac_result[..AUTH_TAG_LEN]);
        tag
    }

    fn stream_state_mut(&mut self, ssrc: u32) -> &mut SrtpStreamState {
        self.stream_states.entry(ssrc).or_default()
    }
}

fn estimate_roc(state: SrtpStreamState, sequence: u16) -> u32 {
    let Some(highest_sequence) = state.highest_sequence else {
        return state.roc;
    };

    if highest_sequence < 32768 {
        if u32::from(sequence) > u32::from(highest_sequence) + 32768 {
            state.roc.saturating_sub(1)
        } else {
            state.roc
        }
    } else if highest_sequence.wrapping_sub(32768) > sequence {
        state.roc.wrapping_add(1)
    } else {
        state.roc
    }
}

fn update_stream_state_after_success(state: &mut SrtpStreamState, sequence: u16, guessed_roc: u32) {
    let Some(highest_sequence) = state.highest_sequence else {
        state.roc = guessed_roc;
        state.highest_sequence = Some(sequence);
        state.replay_window = 1;
        return;
    };

    let current_index = ((state.roc as u64) << 16) | highest_sequence as u64;
    let guessed_index = ((guessed_roc as u64) << 16) | sequence as u64;
    if guessed_index > current_index {
        let delta = guessed_index - current_index;
        state.replay_window = if delta >= 64 {
            1
        } else {
            (state.replay_window << delta) | 1
        };
        state.roc = guessed_roc;
        state.highest_sequence = Some(sequence);
    } else if current_index - guessed_index < 64 {
        state.replay_window |= 1u64 << (current_index - guessed_index);
    }
}

impl Default for SrtpCryptoSuite {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SrtpCryptoSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SrtpCryptoSuite")
            .field("suite", &self.suite)
            .field("master_key", &"[REDACTED]")
            .field("stream_states", &self.stream_states.len())
            .finish()
    }
}

/// 解析 SDP `a=crypto` 属性行
///
/// 输入格式：`a=crypto:TAG SUITE inline:KEY` 或不带 `a=` 前缀的版本
///
/// 返回 (tag, suite_name, base64_key)
///
/// # 示例
///
/// ```
/// let line = "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR";
/// let (tag, suite, key) = parse_crypto_attribute(line).unwrap();
/// assert_eq!(tag, 1);
/// assert_eq!(suite, "AES_CM_128_HMAC_SHA1_80");
/// ```
pub fn parse_crypto_attribute(line: &str) -> Result<(u32, String, String)> {
    let line = line.trim();

    // 去掉可能的 "a=" 前缀
    let content = if line.starts_with("a=") {
        &line[2..]
    } else {
        line
    };

    // 期望格式: crypto:TAG SUITE inline:KEY[|params]
    if !content.starts_with("crypto:") {
        return Err(SrtpError::CryptoAttributeParseError(
            "缺少 'crypto:' 前缀".to_string(),
        ));
    }

    let rest = &content[7..]; // 跳过 "crypto:"
    let parts: Vec<&str> = rest.splitn(3, ' ').collect();

    if parts.len() < 3 {
        return Err(SrtpError::CryptoAttributeParseError(
            "格式不完整，期望 TAG SUITE inline:KEY".to_string(),
        ));
    }

    let tag: u32 = parts[0].parse().map_err(|e| {
        SrtpError::CryptoAttributeParseError(format!("无效的 tag 值 '{}': {}", parts[0], e))
    })?;

    let suite = parts[1].to_string();

    // 解析 inline:KEY — 可能包含 |lifetime 等附加参数
    let key_part = parts[2];
    if !key_part.starts_with("inline:") {
        return Err(SrtpError::CryptoAttributeParseError(
            "缺少 inline 前缀".to_string(),
        ));
    }

    let key_with_params = &key_part[7..]; // 跳过 "inline:"
                                          // 密钥可能包含 |lifetime|mki 等参数，只取第一部分
    let key = key_with_params.split('|').next().unwrap_or("").to_string();

    if key.is_empty() {
        return Err(SrtpError::CryptoAttributeParseError("密钥为空".to_string()));
    }

    Ok((tag, suite, key))
}

/// 常量时间比较两个字节切片（防止时序攻击）
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// RTP 头部解析辅助结构
struct RtpHeader {
    /// RTP 版本（应为 2）
    #[allow(dead_code)]
    version: u8,
    /// 填充标志
    #[allow(dead_code)]
    padding: bool,
    /// 扩展头标志
    extension: bool,
    /// CSRC 计数
    csrc_count: u8,
    /// 序列号
    sequence_number: u16,
    /// 时间戳
    #[allow(dead_code)]
    timestamp: u32,
    /// 同步源标识符
    ssrc: u32,
    /// 扩展头长度（如果有，以 32 位字为单位）
    extension_length: Option<u16>,
}

impl RtpHeader {
    /// 从字节切片解析 RTP 头部
    fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < RTP_HEADER_MIN_LEN {
            return Err(SrtpError::InvalidRtpPacket(format!(
                "数据包太短: {} 字节",
                data.len()
            )));
        }

        let first_byte = data[0];
        let version = (first_byte >> 6) & 0x03;
        let padding = (first_byte >> 5) & 0x01 != 0;
        let extension = (first_byte >> 4) & 0x01 != 0;
        let csrc_count = first_byte & 0x0F;

        if version != 2 {
            return Err(SrtpError::InvalidRtpPacket(format!(
                "不支持的 RTP 版本: {}",
                version
            )));
        }

        let sequence_number = u16::from_be_bytes([data[2], data[3]]);
        let timestamp = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ssrc = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        // 检查 CSRC 列表是否完整
        let csrc_end = RTP_HEADER_MIN_LEN + (csrc_count as usize) * 4;
        if data.len() < csrc_end {
            return Err(SrtpError::InvalidRtpPacket("CSRC 列表不完整".to_string()));
        }

        // 解析扩展头
        let extension_length = if extension {
            let ext_start = csrc_end;
            if data.len() < ext_start + 4 {
                return Err(SrtpError::InvalidRtpPacket("扩展头不完整".to_string()));
            }
            // 扩展头前 2 字节是 profile-specific，后 2 字节是长度（32 位字为单位）
            let ext_len = u16::from_be_bytes([data[ext_start + 2], data[ext_start + 3]]);
            Some(ext_len)
        } else {
            None
        };

        Ok(Self {
            version,
            padding,
            extension,
            csrc_count,
            sequence_number,
            timestamp,
            ssrc,
            extension_length,
        })
    }

    /// 计算完整 RTP 头部长度（包括固定头部、CSRC 列表和扩展头）
    fn total_header_len(&self) -> usize {
        let mut len = RTP_HEADER_MIN_LEN;
        len += (self.csrc_count as usize) * 4;
        if self.extension {
            // 4 字节扩展头固定部分 + 扩展数据
            if let Some(ext_len) = self.extension_length {
                len += 4 + (ext_len as usize) * 4;
            }
        }
        len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rtp_packet(ssrc: u32, sequence: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.push(0x80);
        packet.push(0x00);
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&(sequence as u32 * 160).to_be_bytes());
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(payload);
        packet
    }

    fn suite_with_same_key_as(suite: &SrtpCryptoSuite) -> SrtpCryptoSuite {
        let attr = suite.to_sdes_attribute();
        let key = attr.split("inline:").nth(1).unwrap();
        SrtpCryptoSuite::from_sdes(key).unwrap()
    }

    /// 测试创建新的加密套件

    #[test]
    fn reordered_packets_after_rollover_use_current_roc() {
        for suite in [SrtpSuite::AesCm128HmacSha180, SrtpSuite::AeadAes128Gcm] {
            let mut sender = SrtpCryptoSuite::new_with_suite(suite);
            let mut receiver = sender.clone();
            let last = sender
                .protect_rtp(&make_rtp_packet(1, 65535, b"last"))
                .unwrap();
            let zero = sender.protect_rtp(&make_rtp_packet(1, 0, b"zero")).unwrap();
            let one = sender.protect_rtp(&make_rtp_packet(1, 1, b"one")).unwrap();
            receiver.unprotect_rtp(&last).unwrap();
            receiver.unprotect_rtp(&one).unwrap();
            receiver.unprotect_rtp(&zero).unwrap();
            assert!(receiver.unprotect_rtp(&zero).is_err());
        }
    }

    #[test]
    fn replay_window_and_failed_authentication_for_both_suites() {
        for suite in [SrtpSuite::AesCm128HmacSha180, SrtpSuite::AeadAes128Gcm] {
            let mut sender = SrtpCryptoSuite::new_with_suite(suite);
            let mut receiver = sender.clone();
            let first = sender.protect_rtp(&make_rtp_packet(1, 1, b"one")).unwrap();
            let second = sender.protect_rtp(&make_rtp_packet(1, 2, b"two")).unwrap();
            let mut forged = second.clone();
            forged[8..12].copy_from_slice(&99u32.to_be_bytes());
            assert!(receiver.unprotect_rtp(&forged).is_err());
            assert!(receiver.stream_states.is_empty());
            receiver.unprotect_rtp(&second).unwrap();
            receiver.unprotect_rtp(&first).unwrap(); // valid out-of-order packet
            assert!(receiver.unprotect_rtp(&first).is_err());
            let later = sender
                .protect_rtp(&make_rtp_packet(1, 100, b"later"))
                .unwrap();
            receiver.unprotect_rtp(&later).unwrap();
            assert!(receiver.unprotect_rtp(&second).is_err());
            assert!(sender
                .protect_rtp(&make_rtp_packet(1, 100, b"nonce reuse"))
                .is_err());
        }
    }

    #[test]
    fn test_new_crypto_suite() {
        let suite = SrtpCryptoSuite::new();
        // 验证密钥已生成（不全为零）
        assert!(suite.master_key.iter().any(|&b| b != 0));
        assert!(suite.master_salt.iter().any(|&b| b != 0));
    }

    /// 测试 SDES 编解码往返
    #[test]
    fn test_sdes_roundtrip() {
        let original = SrtpCryptoSuite::new();
        let sdes_attr = original.to_sdes_attribute();

        // 从属性中提取 base64 密钥
        let (tag, suite_name, key) = parse_crypto_attribute(&sdes_attr).unwrap();
        assert_eq!(tag, 1);
        assert_eq!(suite_name, "AES_CM_128_HMAC_SHA1_80");

        let restored = SrtpCryptoSuite::from_sdes(&key).unwrap();
        assert_eq!(original.master_key, restored.master_key);
        assert_eq!(original.master_salt, restored.master_salt);
    }

    /// 测试 SDP crypto 行生成
    #[test]
    fn test_sdp_crypto_line() {
        let suite = SrtpCryptoSuite::new();
        let line = suite.to_sdp_crypto_line(2);
        assert!(line.starts_with("a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:"));
    }

    /// 测试 RTP 加密解密往返
    #[test]
    fn test_protect_unprotect_roundtrip() {
        let mut suite = SrtpCryptoSuite::new();

        // 构造一个简单的 RTP 数据包
        // Version=2, Padding=0, Extension=0, CSRC Count=0
        // Marker=0, Payload Type=0 (PCMU)
        // Sequence Number=1
        // Timestamp=160
        // SSRC=0x12345678
        // Payload="Hello, SRTP!"
        let mut rtp_packet = Vec::new();
        rtp_packet.push(0x80); // V=2, P=0, X=0, CC=0
        rtp_packet.push(0x00); // M=0, PT=0
        rtp_packet.extend_from_slice(&1u16.to_be_bytes()); // Seq=1
        rtp_packet.extend_from_slice(&160u32.to_be_bytes()); // Timestamp
        rtp_packet.extend_from_slice(&0x12345678u32.to_be_bytes()); // SSRC
        rtp_packet.extend_from_slice(b"Hello, SRTP!"); // Payload

        // 加密
        let mut receiver = suite.clone();
        let srtp_packet = suite.protect_rtp(&rtp_packet).unwrap();

        // SRTP 包应该比 RTP 包多 10 字节（认证标签）
        assert_eq!(srtp_packet.len(), rtp_packet.len() + AUTH_TAG_LEN);

        // 加密后的载荷应该不同于原始载荷
        assert_ne!(
            &srtp_packet[12..srtp_packet.len() - AUTH_TAG_LEN],
            b"Hello, SRTP!"
        );

        // 解密
        let decrypted = receiver.unprotect_rtp(&srtp_packet).unwrap();
        assert_eq!(decrypted, rtp_packet);
    }

    /// 测试 GCM 加密解密往返
    #[test]
    fn test_gcm_roundtrip() {
        let mut suite = SrtpCryptoSuite::new_with_suite(SrtpSuite::AeadAes128Gcm);

        let rtp_packet = make_rtp_packet(0x12345678, 1, b"Hello, GCM SRTP!");

        let mut receiver = suite.clone();
        let srtp_packet = suite.protect_rtp(&rtp_packet).unwrap();

        // GCM 认证标签 16 字节
        assert_eq!(srtp_packet.len(), rtp_packet.len() + GCM_AUTH_TAG_LEN);

        let decrypted = receiver.unprotect_rtp(&srtp_packet).unwrap();
        assert_eq!(decrypted, rtp_packet);
    }

    /// 测试 GCM 不同密钥无法解密
    #[test]
    fn test_gcm_different_keys_fail() {
        let mut suite1 = SrtpCryptoSuite::new_with_suite(SrtpSuite::AeadAes128Gcm);
        let mut suite2 = SrtpCryptoSuite::new_with_suite(SrtpSuite::AeadAes128Gcm);

        let rtp = make_rtp_packet(0x11111111, 5, b"key mismatch");
        let srtp = suite1.protect_rtp(&rtp).unwrap();
        assert!(suite2.unprotect_rtp(&srtp).is_err());
    }

    /// 测试 GCM 认证标签篡改检测
    #[test]
    fn test_gcm_auth_tag_tamper_detection() {
        let mut suite = SrtpCryptoSuite::new_with_suite(SrtpSuite::AeadAes128Gcm);

        let rtp = make_rtp_packet(0x22222222, 7, b"tamper test");
        let mut srtp = suite.protect_rtp(&rtp).unwrap();
        let last = srtp.len() - 1;
        srtp[last] ^= 0xFF;
        assert!(suite.unprotect_rtp(&srtp).is_err());
    }

    /// 测试 GCM 套件的 SDES 属性生成与解析
    #[test]
    fn test_gcm_sdes_attribute() {
        let suite = SrtpCryptoSuite::new_with_suite(SrtpSuite::AeadAes128Gcm);
        let attr = suite.to_sdes_attribute();
        assert!(attr.contains("AEAD_AES_128_GCM"));

        let (tag, suite_name, key) = parse_crypto_attribute(&attr).unwrap();
        assert_eq!(tag, 1);
        assert_eq!(suite_name, "AEAD_AES_128_GCM");

        let restored =
            SrtpCryptoSuite::from_sdes_with_suite(SrtpSuite::AeadAes128Gcm, &key).unwrap();
        assert_eq!(restored.master_key, suite.master_key);
        assert_eq!(restored.master_salt, suite.master_salt);
    }

    /// 测试 RFC 7714 标准的 28 字节 GCM SDES 密钥（16 字节 key + 12 字节 salt）可解析
    ///
    /// 使用标准格式的 28 字节 key（与主流客户端 offer 中的 GCM key 一致）。
    /// 修复前服务器误按 AES_CM 的 30 字节校验，导致 GCM 密钥被拒绝、
    /// answer 与 offer 的 crypto tag 不匹配，对端 SRTP 协商失败立即挂断。
    #[test]
    fn test_gcm_sdes_28_byte_key_roundtrip() {
        let key_b64 = "T0iUsU5QGv2+xlg/kQvFyiymq969VLNgWOjf+w==";
        assert_eq!(
            BASE64.decode(key_b64).unwrap().len(),
            MASTER_KEY_LEN + GCM_SALT_LEN
        );

        let restored =
            SrtpCryptoSuite::from_sdes_with_suite(SrtpSuite::AeadAes128Gcm, key_b64).unwrap();
        // GCM 盐值只有 12 字节，其余字节必须保持为 0
        assert_eq!(
            &restored.master_salt[GCM_SALT_LEN..],
            &[0u8; MASTER_SALT_LEN - GCM_SALT_LEN]
        );

        // 生成侧输出也必须是 28 字节，往返一致
        let gen = SrtpCryptoSuite::new_with_suite(SrtpSuite::AeadAes128Gcm);
        let gen_key = gen.to_sdes_key();
        assert_eq!(
            BASE64.decode(&gen_key).unwrap().len(),
            MASTER_KEY_LEN + GCM_SALT_LEN
        );
        let gen_restored =
            SrtpCryptoSuite::from_sdes_with_suite(SrtpSuite::AeadAes128Gcm, &gen_key).unwrap();
        assert_eq!(gen_restored.master_key, gen.master_key);
        assert_eq!(gen_restored.master_salt, gen.master_salt);
    }

    /// 测试 GCM 与 AES_CM 套件互不兼容（跨套件解密必须失败）
    #[test]
    fn test_gcm_and_aes_cm_incompatible() {
        let mut gcm = SrtpCryptoSuite::new_with_suite(SrtpSuite::AeadAes128Gcm);
        let mut aes = SrtpCryptoSuite::new();

        let rtp = make_rtp_packet(0x33333333, 9, b"cross suite");
        let gcm_srtp = gcm.protect_rtp(&rtp).unwrap();
        assert!(aes.unprotect_rtp(&gcm_srtp).is_err());

        let aes_srtp = aes.protect_rtp(&rtp).unwrap();
        assert!(gcm.unprotect_rtp(&aes_srtp).is_err());
    }

    /// 测试 GCM IV 构造（RFC 7714 §8.1：IV = 00 00 || SSRC || ROC || SEQ，
    /// 再与 96 位 salt 逐字节 XOR——与 libsrtp 等标准实现一致）
    #[test]
    fn test_gcm_iv_construction() {
        let suite = SrtpCryptoSuite {
            suite: SrtpSuite::AeadAes128Gcm,
            master_key: [0u8; MASTER_KEY_LEN],
            master_salt: [0u8; MASTER_SALT_LEN],
            session_key: [0u8; SESSION_KEY_LEN],
            session_salt: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
            session_auth_key: [0u8; SESSION_AUTH_KEY_LEN],
            stream_states: HashMap::new(),
        };

        let ssrc = 0x11223344u32;
        let roc = 0x55667788u32;
        let seq = 0x99AAu16;

        let iv = suite.gcm_iv(ssrc, roc, seq);

        // 期望：先构造 00 00 || SSRC || ROC || SEQ（12 字节），再与 12 字节 salt 异或
        let mut expected = [0u8; 12]; // 前 2 字节为 00 00
        expected[2..6].copy_from_slice(&ssrc.to_be_bytes());
        expected[6..10].copy_from_slice(&roc.to_be_bytes());
        expected[10..12].copy_from_slice(&seq.to_be_bytes());
        for i in 0..12 {
            expected[i] ^= suite.session_salt[i];
        }
        assert_eq!(&iv[..], &expected[..]);

        // 显式断言：IV[0..2] 即 00 00 与 salt 异或；SSRC 位于 IV[2..6]、ROC 位于 IV[6..10]、
        // SEQ 位于 IV[10..12]
        assert_eq!(iv[0], suite.session_salt[0]);
        assert_eq!(iv[1], suite.session_salt[1]);
        assert_eq!(iv[2], suite.session_salt[2] ^ ((ssrc >> 24) as u8));
        assert_eq!(iv[5], suite.session_salt[5] ^ (ssrc as u8));
        assert_eq!(iv[6], suite.session_salt[6] ^ ((roc >> 24) as u8));
        assert_eq!(iv[9], suite.session_salt[9] ^ (roc as u8));
        assert_eq!(iv[10], suite.session_salt[10] ^ ((seq >> 8) as u8));
        assert_eq!(iv[11], suite.session_salt[11] ^ (seq as u8));
    }

    /// 与 libsrtp / RFC 7714 一致的 IV 构造验证
    ///
    /// libsrtp 的 srtp_calc_aead_iv（注释直接引用 RFC 7714 §8.1 Figure 1）：
    /// 先拼接 00 00 || SSRC || ROC || SEQ 共 12 字节，再与 12 字节 salt 逐字节 XOR。
    #[test]
    fn test_gcm_iv_matches_libsrtp_layout() {
        let suite = SrtpCryptoSuite {
            suite: SrtpSuite::AeadAes128Gcm,
            master_key: [0u8; MASTER_KEY_LEN],
            master_salt: [0u8; MASTER_SALT_LEN],
            session_key: [0u8; SESSION_KEY_LEN],
            session_salt: [
                0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0, 0,
            ],
            session_auth_key: [0u8; SESSION_AUTH_KEY_LEN],
            stream_states: HashMap::new(),
        };

        let ssrc = 0xDEADBEEFu32;
        let roc = 0x00000001u32;
        let seq = 0x1234u16;

        let iv = suite.gcm_iv(ssrc, roc, seq);

        // 期望：IV = (00 00 || SSRC || ROC || SEQ) XOR salt
        let mut expected = [0u8; 12]; // 前 2 字节为 00 00 前缀
        expected[0] = 0x00 ^ 0xA0;
        expected[1] = 0x00 ^ 0xA1;
        expected[2..6].copy_from_slice(&(ssrc ^ 0xA2A3A4A5u32).to_be_bytes());
        expected[6..10].copy_from_slice(&(roc ^ 0xA6A7A8A9u32).to_be_bytes());
        expected[10] = (seq >> 8) as u8 ^ 0xAA; // SEQ 高字节
        expected[11] = (seq & 0xFF) as u8 ^ 0xAB; // SEQ 低字节
        assert_eq!(iv, expected);
    }

    /// 测试 SDP 套件名称解析
    #[test]
    fn test_suite_from_sdp_name() {
        assert_eq!(
            SrtpSuite::from_sdp_name("AES_CM_128_HMAC_SHA1_80"),
            Some(SrtpSuite::AesCm128HmacSha180)
        );
        assert_eq!(
            SrtpSuite::from_sdp_name("AEAD_AES_128_GCM"),
            Some(SrtpSuite::AeadAes128Gcm)
        );
        assert_eq!(
            SrtpSuite::from_sdp_name("aead_aes_128_gcm"),
            Some(SrtpSuite::AeadAes128Gcm)
        );
        assert_eq!(SrtpSuite::from_sdp_name("AES_CM_128_HMAC_SHA1_32"), None);
    }

    #[test]
    fn test_aes_cm_iv_uses_left_aligned_session_salt() {
        let suite = SrtpCryptoSuite {
            suite: SrtpSuite::AesCm128HmacSha180,
            master_key: [0u8; MASTER_KEY_LEN],
            master_salt: [0u8; MASTER_SALT_LEN],
            session_key: [0u8; SESSION_KEY_LEN],
            session_salt: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
            session_auth_key: [0u8; SESSION_AUTH_KEY_LEN],
            stream_states: HashMap::new(),
        };

        let ssrc = 0x11223344u32;
        let sequence = 0x5566u16;
        let mut rtp_packet = Vec::new();
        rtp_packet.push(0x80);
        rtp_packet.push(0x00);
        rtp_packet.extend_from_slice(&sequence.to_be_bytes());
        rtp_packet.extend_from_slice(&160u32.to_be_bytes());
        rtp_packet.extend_from_slice(&ssrc.to_be_bytes());
        rtp_packet.extend_from_slice(&[0u8; 16]);

        let encrypted_payload = suite.aes_cm_encrypt(ssrc, sequence as u64, &rtp_packet[12..]);

        let mut expected_iv = [0u8; 16];
        expected_iv[..SESSION_SALT_LEN].copy_from_slice(&suite.session_salt);
        expected_iv[4..8]
            .iter_mut()
            .zip(ssrc.to_be_bytes())
            .for_each(|(dst, src)| *dst ^= src);
        let packet_index = (sequence as u64).to_be_bytes();
        expected_iv[8..14]
            .iter_mut()
            .zip(&packet_index[2..8])
            .for_each(|(dst, src)| *dst ^= *src);

        let cipher = Aes128::new_from_slice(&suite.session_key).unwrap();
        let mut aes_block = aes::Block::clone_from_slice(&expected_iv);
        cipher.encrypt_block(&mut aes_block);

        assert_eq!(&encrypted_payload[..16], &aes_block[..]);
    }

    #[test]
    fn test_kdf_iv_uses_left_aligned_master_salt() {
        let mut suite = SrtpCryptoSuite {
            suite: SrtpSuite::AesCm128HmacSha180,
            master_key: [0u8; MASTER_KEY_LEN],
            master_salt: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
            session_key: [0u8; SESSION_KEY_LEN],
            session_salt: [0u8; SESSION_SALT_LEN],
            session_auth_key: [0u8; SESSION_AUTH_KEY_LEN],
            stream_states: HashMap::new(),
        };
        suite.derive_session_keys();

        let mut expected_iv = [0u8; 16];
        expected_iv[..MASTER_SALT_LEN].copy_from_slice(&suite.master_salt);

        let cipher = Aes128::new_from_slice(&suite.master_key).unwrap();
        let mut aes_block = aes::Block::clone_from_slice(&expected_iv);
        cipher.encrypt_block(&mut aes_block);

        assert_eq!(&suite.session_key[..], &aes_block[..]);
    }

    #[test]
    fn test_kdf_uses_rfc3711_srtp_labels() {
        let mut suite = SrtpCryptoSuite {
            suite: SrtpSuite::AesCm128HmacSha180,
            master_key: [0u8; MASTER_KEY_LEN],
            master_salt: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
            session_key: [0u8; SESSION_KEY_LEN],
            session_salt: [0u8; SESSION_SALT_LEN],
            session_auth_key: [0u8; SESSION_AUTH_KEY_LEN],
            stream_states: HashMap::new(),
        };
        suite.derive_session_keys();

        let expected_auth_key: [u8; SESSION_AUTH_KEY_LEN] =
            suite.prf_derive_auth(0x01, SESSION_AUTH_KEY_LEN);
        let expected_salt_full: [u8; SESSION_KEY_LEN] = suite.prf_derive(0x02, SESSION_KEY_LEN);

        assert_eq!(suite.session_auth_key, expected_auth_key);
        assert_eq!(
            &suite.session_salt[..],
            &expected_salt_full[..SESSION_SALT_LEN]
        );
    }

    /// 测试认证标签篡改检测
    #[test]
    fn test_auth_tag_tamper_detection() {
        let mut suite = SrtpCryptoSuite::new();

        let mut rtp_packet = Vec::new();
        rtp_packet.push(0x80);
        rtp_packet.push(0x00);
        rtp_packet.extend_from_slice(&1u16.to_be_bytes());
        rtp_packet.extend_from_slice(&160u32.to_be_bytes());
        rtp_packet.extend_from_slice(&0x12345678u32.to_be_bytes());
        rtp_packet.extend_from_slice(b"Tamper test");

        let mut srtp_packet = suite.protect_rtp(&rtp_packet).unwrap();

        // 篡改认证标签的最后一个字节
        let last = srtp_packet.len() - 1;
        srtp_packet[last] ^= 0xFF;

        // 解密应该失败
        let result = suite.unprotect_rtp(&srtp_packet);
        assert!(matches!(result, Err(SrtpError::AuthenticationFailed)));
    }

    /// 测试解析加密属性
    #[test]
    fn test_parse_crypto_attribute() {
        let line =
            "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR";
        let (tag, suite, key) = parse_crypto_attribute(line).unwrap();
        assert_eq!(tag, 1);
        assert_eq!(suite, "AES_CM_128_HMAC_SHA1_80");
        assert_eq!(key, "PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR");
    }

    /// 测试解析带生命周期参数的加密属性
    #[test]
    fn test_parse_crypto_attribute_with_lifetime() {
        let line =
            "crypto:2 AES_CM_128_HMAC_SHA1_80 inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|2^31";
        let (tag, suite, key) = parse_crypto_attribute(line).unwrap();
        assert_eq!(tag, 2);
        assert_eq!(suite, "AES_CM_128_HMAC_SHA1_80");
        assert_eq!(key, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    }

    /// 测试无效的加密属性
    #[test]
    fn test_parse_invalid_crypto_attribute() {
        assert!(parse_crypto_attribute("invalid").is_err());
        assert!(parse_crypto_attribute("a=crypto:").is_err());
        assert!(parse_crypto_attribute("a=crypto:abc SUITE inline:KEY").is_err());
    }

    /// 测试不同密钥无法解密
    #[test]
    fn test_different_keys_fail() {
        let mut suite1 = SrtpCryptoSuite::new();
        let mut suite2 = SrtpCryptoSuite::new();

        let mut rtp_packet = Vec::new();
        rtp_packet.push(0x80);
        rtp_packet.push(0x00);
        rtp_packet.extend_from_slice(&1u16.to_be_bytes());
        rtp_packet.extend_from_slice(&160u32.to_be_bytes());
        rtp_packet.extend_from_slice(&0x12345678u32.to_be_bytes());
        rtp_packet.extend_from_slice(b"Key mismatch test");

        let srtp_packet = suite1.protect_rtp(&rtp_packet).unwrap();

        // 使用不同的密钥解密应该失败（认证标签不匹配）
        let result = suite2.unprotect_rtp(&srtp_packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_sequence_rollover_advances_roc() {
        let mut sender = SrtpCryptoSuite::new();
        let mut receiver = suite_with_same_key_as(&sender);
        let ssrc = 0x214e342d;

        for sequence in [65534, 65535, 0, 1, 2] {
            let rtp = make_rtp_packet(ssrc, sequence, b"rollover");
            let srtp = sender.protect_rtp(&rtp).unwrap();
            let decrypted = receiver.unprotect_rtp(&srtp).unwrap();
            assert_eq!(decrypted, rtp);
        }
    }

    #[test]
    fn test_new_ssrc_starts_with_independent_roc() {
        let mut sender = SrtpCryptoSuite::new();
        let mut receiver = suite_with_same_key_as(&sender);

        for sequence in [65534, 65535, 0, 1] {
            let rtp = make_rtp_packet(0x11111111, sequence, b"first stream");
            let srtp = sender.protect_rtp(&rtp).unwrap();
            assert_eq!(receiver.unprotect_rtp(&srtp).unwrap(), rtp);
        }

        let new_stream_rtp = make_rtp_packet(0x22222222, 0, b"new stream");
        let new_stream_srtp = sender.protect_rtp(&new_stream_rtp).unwrap();
        assert_eq!(
            receiver.unprotect_rtp(&new_stream_srtp).unwrap(),
            new_stream_rtp
        );
    }
}
