//! SRTP 加解密实现 — 基于 SDES 密钥交换
//!
//! 实现 RFC 3711 SRTP 协议，使用 AES_CM_128_HMAC_SHA1_80 加密套件。
//! 支持从 SDP `a=crypto` 属性解析和生成 SDES 密钥。

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;
use std::fmt;

/// HMAC-SHA1 类型别名
type HmacSha1 = Hmac<Sha1>;

/// SRTP 认证标签长度（80 位 = 10 字节）
const AUTH_TAG_LEN: usize = 10;

/// 主密钥长度（128 位 = 16 字节）
const MASTER_KEY_LEN: usize = 16;

/// 主盐值长度（112 位 = 14 字节）
const MASTER_SALT_LEN: usize = 14;

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

/// KDF 标签：盐值
const LABEL_SALT: u8 = 0x01;

/// KDF 标签：认证密钥
const LABEL_AUTH_KEY: u8 = 0x02;

/// SRTP 加密套件错误类型
#[derive(Debug)]
pub enum SrtpError {
    /// SDES 密钥格式无效
    InvalidSdesKey(String),
    /// RTP 数据包格式无效
    InvalidRtpPacket(String),
    /// SRTP 认证失败
    AuthenticationFailed,
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
    /// 翻转计数器（Rollover Counter）
    roc: u32,
}

impl SrtpCryptoSuite {
    /// 创建新的 SRTP 加密套件，随机生成主密钥和盐值
    pub fn new() -> Self {
        let mut master_key = [0u8; MASTER_KEY_LEN];
        let mut master_salt = [0u8; MASTER_SALT_LEN];

        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut master_key);
        rng.fill_bytes(&mut master_salt);

        let mut suite = Self {
            master_key,
            master_salt,
            session_key: [0u8; SESSION_KEY_LEN],
            session_salt: [0u8; SESSION_SALT_LEN],
            session_auth_key: [0u8; SESSION_AUTH_KEY_LEN],
            roc: 0,
        };
        suite.derive_session_keys();
        suite
    }

    /// 从 SDES inline 密钥（Base64 编码的 key||salt）创建加密套件
    ///
    /// 输入格式：Base64 编码的 30 字节数据（16 字节密钥 + 14 字节盐值）
    pub fn from_sdes(base64_key_salt: &str) -> Result<Self> {
        let decoded = BASE64
            .decode(base64_key_salt.trim())
            .map_err(|e| SrtpError::Base64DecodeError(e.to_string()))?;

        if decoded.len() != MASTER_KEY_LEN + MASTER_SALT_LEN {
            return Err(SrtpError::InvalidSdesKey(format!(
                "期望 {} 字节，实际 {} 字节",
                MASTER_KEY_LEN + MASTER_SALT_LEN,
                decoded.len()
            )));
        }

        let mut master_key = [0u8; MASTER_KEY_LEN];
        let mut master_salt = [0u8; MASTER_SALT_LEN];
        master_key.copy_from_slice(&decoded[..MASTER_KEY_LEN]);
        master_salt.copy_from_slice(&decoded[MASTER_KEY_LEN..]);

        let mut suite = Self {
            master_key,
            master_salt,
            session_key: [0u8; SESSION_KEY_LEN],
            session_salt: [0u8; SESSION_SALT_LEN],
            session_auth_key: [0u8; SESSION_AUTH_KEY_LEN],
            roc: 0,
        };
        suite.derive_session_keys();
        Ok(suite)
    }

    /// 生成 SDES `a=crypto` 属性值
    ///
    /// 返回格式：`a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:<base64>`
    pub fn to_sdes_attribute(&self) -> String {
        let mut key_salt = Vec::with_capacity(MASTER_KEY_LEN + MASTER_SALT_LEN);
        key_salt.extend_from_slice(&self.master_key);
        key_salt.extend_from_slice(&self.master_salt);
        let encoded = BASE64.encode(&key_salt);
        format!("a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{}", encoded)
    }

    /// 生成 SDP crypto 行
    ///
    /// 返回格式：`a=crypto:<tag> AES_CM_128_HMAC_SHA1_80 inline:<base64>`
    pub fn to_sdp_crypto_line(&self, tag: u32) -> String {
        let mut key_salt = Vec::with_capacity(MASTER_KEY_LEN + MASTER_SALT_LEN);
        key_salt.extend_from_slice(&self.master_key);
        key_salt.extend_from_slice(&self.master_salt);
        let encoded = BASE64.encode(&key_salt);
        format!(
            "a=crypto:{} AES_CM_128_HMAC_SHA1_80 inline:{}",
            tag, encoded
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
    /// - label 0x01 → 会话盐值（112 位）
    /// - label 0x02 → 会话认证密钥（160 位）
    fn derive_session_keys(&mut self) {
        self.session_key = self.prf_derive(LABEL_CIPHER_KEY, SESSION_KEY_LEN);
        // 盐值只有 14 字节，先派生 16 字节再截断
        let salt_full: [u8; SESSION_KEY_LEN] = self.prf_derive(LABEL_SALT, SESSION_KEY_LEN);
        self.session_salt
            .copy_from_slice(&salt_full[..SESSION_SALT_LEN]);
        // 认证密钥需要 20 字节，可能需要多个 AES 块
        self.session_auth_key = self.prf_derive_auth(LABEL_AUTH_KEY, SESSION_AUTH_KEY_LEN);
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

        // 构造 x = label || 0^48 的 key_id
        // IV = master_salt XOR (label << 48)，填充到 16 字节
        let mut iv = [0u8; 16];
        // 将 master_salt（14 字节）放入 iv[2..16]，即右对齐留出 2 字节前缀
        iv[2..16].copy_from_slice(&self.master_salt);
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
        iv[2..16].copy_from_slice(&self.master_salt);
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
    /// 2. 使用 AES-CM 加密载荷
    /// 3. 计算并附加 HMAC-SHA1-80 认证标签（10 字节）
    ///
    /// 输入：完整的 RTP 数据包
    /// 输出：SRTP 数据包 = RTP头部 + 加密载荷 + 认证标签
    pub fn protect_rtp(&self, packet: &[u8]) -> Result<Vec<u8>> {
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
        let packet_index: u64 = (self.roc as u64) * 65536 + header.sequence_number as u64;

        // AES-CM 加密载荷
        let encrypted_payload = self.aes_cm_encrypt(header.ssrc, packet_index, payload);

        // 组装 SRTP 数据包（头部不变 + 加密载荷）
        let mut srtp_packet = Vec::with_capacity(packet.len() + AUTH_TAG_LEN);
        srtp_packet.extend_from_slice(&packet[..header_len]); // 原始头部
        srtp_packet.extend_from_slice(&encrypted_payload); // 加密载荷

        // 计算 HMAC-SHA1-80 认证标签
        // 认证范围：SRTP 头部 + 加密载荷 + ROC（4 字节，网络字节序）
        let auth_tag = self.compute_auth_tag(&srtp_packet, self.roc);
        srtp_packet.extend_from_slice(&auth_tag);

        Ok(srtp_packet)
    }

    /// 解密 SRTP 数据包为 RTP 数据包
    ///
    /// 步骤：
    /// 1. 验证 HMAC-SHA1-80 认证标签
    /// 2. 使用 AES-CM 解密载荷
    ///
    /// 输入：完整的 SRTP 数据包
    /// 输出：RTP 数据包 = RTP头部 + 明文载荷
    pub fn unprotect_rtp(&self, packet: &[u8]) -> Result<Vec<u8>> {
        if packet.len() < RTP_HEADER_MIN_LEN + AUTH_TAG_LEN {
            return Err(SrtpError::InvalidRtpPacket(format!(
                "SRTP 数据包太短: {} 字节",
                packet.len()
            )));
        }

        // 分离认证标签
        let auth_tag_start = packet.len() - AUTH_TAG_LEN;
        let authenticated_portion = &packet[..auth_tag_start];
        let received_tag = &packet[auth_tag_start..];

        // 验证认证标签
        let computed_tag = self.compute_auth_tag(authenticated_portion, self.roc);
        if !constant_time_eq(&computed_tag, received_tag) {
            return Err(SrtpError::AuthenticationFailed);
        }

        // 解析 RTP 头部
        let header = RtpHeader::parse(authenticated_portion)?;
        let header_len = header.total_header_len();

        if authenticated_portion.len() < header_len {
            return Err(SrtpError::InvalidRtpPacket(
                "数据包长度小于 RTP 头部长度".to_string(),
            ));
        }

        let encrypted_payload = &authenticated_portion[header_len..];

        // 计算 packet index
        let packet_index: u64 = (self.roc as u64) * 65536 + header.sequence_number as u64;

        // AES-CM 解密（加解密操作相同）
        let decrypted_payload = self.aes_cm_encrypt(header.ssrc, packet_index, encrypted_payload);

        // 组装 RTP 数据包
        let mut rtp_packet = Vec::with_capacity(header_len + decrypted_payload.len());
        rtp_packet.extend_from_slice(&authenticated_portion[..header_len]);
        rtp_packet.extend_from_slice(&decrypted_payload);

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

        // 构造 IV（16 字节）
        // IV 格式（RFC 3711）：
        // 字节 0-3:   0x00000000
        // 字节 4-7:   SSRC (网络字节序)
        // 字节 8-13:  packet_index (48 位，网络字节序)
        // 字节 14-15: block_counter (每块递增)
        //
        // 然后将 IV 与 session_salt（14 字节，左填充到 16 字节）异或
        let mut iv = [0u8; 16];
        // SSRC 在字节 4-7
        iv[4..8].copy_from_slice(&ssrc.to_be_bytes());
        // packet_index 在字节 8-13（48 位 = 6 字节）
        let pi_bytes = packet_index.to_be_bytes(); // 8 字节
        iv[8..14].copy_from_slice(&pi_bytes[2..8]); // 取低 48 位

        // 与 session_salt 异或（session_salt 是 14 字节，放在 iv[2..16]）
        for i in 0..SESSION_SALT_LEN {
            iv[2 + i] ^= self.session_salt[i];
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
}

impl Default for SrtpCryptoSuite {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SrtpCryptoSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SrtpCryptoSuite")
            .field("master_key", &"[REDACTED]")
            .field("roc", &self.roc)
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
        return Err(SrtpError::CryptoAttributeParseError(format!(
            "格式不完整，期望 TAG SUITE inline:KEY，实际: '{}'",
            rest
        )));
    }

    let tag: u32 = parts[0].parse().map_err(|e| {
        SrtpError::CryptoAttributeParseError(format!("无效的 tag 值 '{}': {}", parts[0], e))
    })?;

    let suite = parts[1].to_string();

    // 解析 inline:KEY — 可能包含 |lifetime 等附加参数
    let key_part = parts[2];
    if !key_part.starts_with("inline:") {
        return Err(SrtpError::CryptoAttributeParseError(format!(
            "缺少 'inline:' 前缀: '{}'",
            key_part
        )));
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

    /// 测试创建新的加密套件
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
        let suite = SrtpCryptoSuite::new();

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
        let srtp_packet = suite.protect_rtp(&rtp_packet).unwrap();

        // SRTP 包应该比 RTP 包多 10 字节（认证标签）
        assert_eq!(srtp_packet.len(), rtp_packet.len() + AUTH_TAG_LEN);

        // 加密后的载荷应该不同于原始载荷
        assert_ne!(
            &srtp_packet[12..srtp_packet.len() - AUTH_TAG_LEN],
            b"Hello, SRTP!"
        );

        // 解密
        let decrypted = suite.unprotect_rtp(&srtp_packet).unwrap();
        assert_eq!(decrypted, rtp_packet);
    }

    /// 测试认证标签篡改检测
    #[test]
    fn test_auth_tag_tamper_detection() {
        let suite = SrtpCryptoSuite::new();

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
        let suite1 = SrtpCryptoSuite::new();
        let suite2 = SrtpCryptoSuite::new();

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
}
