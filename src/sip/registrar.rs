//! SIP 注册服务模块
//!
//! 管理分机的注册状态，实现 SIP Digest 认证。
//! 支持 REGISTER 请求的完整处理流程：认证挑战 → 验证 → 注册/注销。

use md5::{Md5, Digest};
use rand::Rng;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use super::parser;

/// 注册条目，记录分机的注册信息
#[derive(Debug, Clone)]
pub struct Registration {
    /// 分机号码（字符串形式，如 "1001"）
    pub extension: String,
    /// 联系地址（Contact URI）
    pub contact: String,
    /// 注册过期时间戳（Unix 秒）
    pub expires_at: u64,
    /// 来源传输地址
    pub transport_addr: SocketAddr,
}

/// Digest 认证参数
#[derive(Debug)]
struct DigestParams {
    username: String,
    realm: String,
    nonce: String,
    uri: String,
    response: String,
    /// qop 值（如 "auth"），客户端可能不发送
    qop: Option<String>,
    /// nonce 计数器（十六进制字符串，如 "00000001"）
    nc: Option<String>,
    /// 客户端随机数
    cnonce: Option<String>,
}

/// 注册服务
///
/// 线程安全的内存注册表，处理 REGISTER 请求并实现 Digest 认证。
pub struct RegistrarService {
    /// 分机号码 -> 注册信息的映射
    registrations: RwLock<HashMap<String, Registration>>,
    /// 服务器域名或 IP（用于 Digest realm）
    domain: String,
    /// 所有分机的默认密码
    default_password: String,
    /// 分机独立密码（分机号 -> 密码）
    passwords: HashMap<String, String>,
    /// 分机号码范围
    range_start: u32,
    range_end: u32,
}

impl RegistrarService {
    /// 创建新的注册服务
    pub fn new(
        domain: String,
        default_password: String,
        passwords: HashMap<String, String>,
        range_start: u32,
        range_end: u32,
    ) -> Self {
        if !passwords.is_empty() {
            tracing::info!("已配置 {} 个分机独立密码", passwords.len());
        }
        Self {
            registrations: RwLock::new(HashMap::new()),
            domain,
            default_password,
            passwords,
            range_start,
            range_end,
        }
    }

    /// 获取指定分机的密码
    ///
    /// 优先返回独立密码，未配置则返回默认密码
    fn get_password(&self, extension: &str) -> &str {
        if let Some(pwd) = self.passwords.get(extension) {
            pwd
        } else {
            &self.default_password
        }
    }

    /// 处理 REGISTER 请求
    ///
    /// 完整流程：
    /// 1. 从 To/From URI 提取分机号
    /// 2. 验证分机号在有效范围内
    /// 3. 检查 Authorization 头部
    ///    - 无：返回 401 + WWW-Authenticate 挑战
    ///    - 有：验证 Digest 响应
    ///      - 成功：注册/注销，返回 200 OK
    ///      - 失败：返回 403 Forbidden
    pub fn handle_register(&self, request_text: &str, from_addr: SocketAddr) -> Vec<u8> {
        // 提取分机号
        let extension = if let Some(uri) = parser::extract_uri_from_header(request_text, "To") {
            parser::extract_extension(&uri)
        } else if let Some(uri) = parser::extract_uri_from_header(request_text, "From") {
            parser::extract_extension(&uri)
        } else {
            None
        };

        let extension = match extension {
            Some(ext) => ext,
            None => {
                tracing::warn!("REGISTER 请求缺少有效的分机号");
                return parser::build_response(request_text, 400, "Bad Request");
            }
        };

        // 验证分机号范围
        let ext_num: u32 = match extension.parse() {
            Ok(n) => n,
            Err(_) => {
                tracing::warn!("无效的分机号格式: {}", extension);
                return parser::build_response(request_text, 403, "Forbidden");
            }
        };

        if ext_num < self.range_start || ext_num > self.range_end {
            tracing::warn!(
                "分机号 {} 不在有效范围 {}-{} 内",
                extension, self.range_start, self.range_end
            );
            return parser::build_response(request_text, 403, "Forbidden");
        }

        // 检查 Authorization 头部
        let auth_header = parser::extract_header_value(request_text, "Authorization");

        match auth_header {
            None => {
                // 无认证信息，返回 401 挑战
                let nonce = generate_nonce();
                let www_auth = format!(
                    "Digest realm=\"{}\", nonce=\"{}\", algorithm=MD5, qop=\"auth\"",
                    self.domain, nonce
                );
                tracing::debug!("向分机 {} 发送 Digest 挑战", extension);
                parser::build_response_with_headers(
                    request_text,
                    401,
                    "Unauthorized",
                    &[("WWW-Authenticate", &www_auth)],
                )
            }
            Some(auth_value) => {
                // 解析并验证 Digest 认证
                let params = match parse_authorization(&auth_value) {
                    Some(p) => p,
                    None => {
                        tracing::warn!("无法解析 Authorization 头部: {}", auth_value);
                        return parser::build_response(request_text, 400, "Bad Request");
                    }
                };

                // 获取请求 URI（用于 Digest 计算）
                let _request_uri = parser::extract_request_uri(request_text)
                    .unwrap_or_else(|| format!("sip:{}", self.domain));

                let password = self.get_password(&extension);
                if !validate_digest(
                    &params.username,
                    &params.realm,
                    password,
                    &params.nonce,
                    &params.uri,
                    "REGISTER",
                    &params.response,
                    params.qop.as_deref(),
                    params.nc.as_deref(),
                    params.cnonce.as_deref(),
                ) {
                    tracing::warn!("分机 {} 认证失败（来自 {}）", extension, from_addr);
                    return parser::build_response(request_text, 403, "Forbidden");
                }

                // 认证成功
                tracing::info!("分机 {} 认证成功（来自 {}）", extension, from_addr);

                // 检查 Expires
                let expires = parser::extract_expires(request_text).unwrap_or(3600);

                if expires == 0 {
                    // 注销
                    self.unregister(&extension);
                    tracing::info!("分机 {} 已注销", extension);
                    return parser::build_response_with_headers(
                        request_text,
                        200,
                        "OK",
                        &[("Expires", "0")],
                    );
                }

                // 注册
                let contact = parser::extract_contact_uri(request_text)
                    .unwrap_or_else(|| format!("sip:{}@{}", extension, from_addr));

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let reg = Registration {
                    extension: extension.clone(),
                    contact: contact.clone(),
                    expires_at: now + expires,
                    transport_addr: from_addr,
                };

                self.register(reg);

                let contact_header = format!("<{}>;expires={}", contact, expires);
                parser::build_response_with_headers(
                    request_text,
                    200,
                    "OK",
                    &[("Contact", &contact_header), ("Expires", &expires.to_string())],
                )
            }
        }
    }

    /// 注册或更新分机
    fn register(&self, reg: Registration) {
        let ext = reg.extension.clone();
        let mut map = self.registrations.write().unwrap();
        tracing::info!("分机 {} 注册成功，联系地址: {}", ext, reg.contact);
        map.insert(ext, reg);
    }

    /// 注销分机
    pub fn unregister(&self, extension: &str) {
        let mut map = self.registrations.write().unwrap();
        if map.remove(extension).is_some() {
            tracing::info!("分机 {} 已注销", extension);
        }
    }

    /// 查找分机的注册信息
    pub fn lookup(&self, extension: &str) -> Option<Registration> {
        let map = self.registrations.read().unwrap();
        let reg = map.get(extension)?;
        // 检查是否过期
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if reg.expires_at > now {
            Some(reg.clone())
        } else {
            None
        }
    }

    /// 检查分机是否在线（已注册且未过期）
    pub fn is_registered(&self, extension: &str) -> bool {
        self.lookup(extension).is_some()
    }

    /// 获取当前在线分机数量
    pub fn online_count(&self) -> usize {
        let map = self.registrations.read().unwrap();
        map.len()
    }

    /// 清理过期的注册
    pub fn cleanup_expired(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut map = self.registrations.write().unwrap();
        let before = map.len();
        map.retain(|ext, reg| {
            if reg.expires_at <= now {
                tracing::debug!("分机 {} 注册已过期，自动清理", ext);
                false
            } else {
                true
            }
        });
        let removed = before - map.len();
        if removed > 0 {
            tracing::info!("清理了 {} 个过期注册", removed);
        }
    }

    /// 启动后台清理任务
    pub fn start_cleanup_task(self: &Arc<Self>) {
        let svc = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                svc.cleanup_expired();
            }
        });
    }
}

// ============================================================
// Digest 认证辅助函数
// ============================================================

/// 生成随机 nonce（32 字节十六进制字符串）
fn generate_nonce() -> String {
    let bytes: [u8; 16] = rand::thread_rng().gen();
    hex::encode(bytes)
}

/// 解析 Authorization 头部值
///
/// 输入格式：`Digest username="1001", realm="minghe.local", nonce="xxx", uri="sip:minghe.local", response="yyy"`
fn parse_authorization(header_value: &str) -> Option<DigestParams> {
    let value = header_value.trim();
    let value = if let Some(rest) = value.strip_prefix("Digest") {
        rest.trim()
    } else {
        value
    };

    let mut username = String::new();
    let mut realm = String::new();
    let mut nonce = String::new();
    let mut uri = String::new();
    let mut response = String::new();
    let mut qop: Option<String> = None;
    let mut nc: Option<String> = None;
    let mut cnonce: Option<String> = None;

    // 解析 key="value" 对
    // 需要处理值中可能包含逗号的情况（如 URI）
    for param in split_digest_params(value) {
        let param = param.trim();
        if let Some((key, val)) = param.split_once('=') {
            let key = key.trim().to_lowercase();
            let val = val.trim().trim_matches('"').to_string();
            match key.as_str() {
                "username" => username = val,
                "realm" => realm = val,
                "nonce" => nonce = val,
                "uri" => uri = val,
                "response" => response = val,
                "qop" => qop = Some(val),
                "nc" => nc = Some(val),
                "cnonce" => cnonce = Some(val),
                _ => {} // 忽略其他参数 (algorithm 等)
            }
        }
    }

    if username.is_empty() || nonce.is_empty() || response.is_empty() {
        return None;
    }

    Some(DigestParams {
        username,
        realm,
        nonce,
        uri,
        response,
        qop,
        nc,
        cnonce,
    })
}

/// 分割 Digest 参数（处理引号内的逗号）
fn split_digest_params(input: &str) -> Vec<String> {
    let mut params = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in input.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            ',' if !in_quotes => {
                if !current.trim().is_empty() {
                    params.push(current.clone());
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        params.push(current);
    }
    params
}

/// 验证 Digest 认证响应
///
/// 支持两种算法：
/// - RFC 2069（无 qop）：response = MD5(HA1:nonce:HA2)
/// - RFC 2617（qop=auth）：response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
///
/// ```text
/// HA1 = MD5(username:realm:password)
/// HA2 = MD5(method:uri)
/// ```
fn validate_digest(
    username: &str,
    realm: &str,
    password: &str,
    nonce: &str,
    uri: &str,
    method: &str,
    response: &str,
    qop: Option<&str>,
    nc: Option<&str>,
    cnonce: Option<&str>,
) -> bool {
    let ha1 = md5_hex(&format!("{}:{}:{}", username, realm, password));
    let ha2 = md5_hex(&format!("{}:{}", method, uri));

    let expected = match qop {
        Some("auth") => {
            // RFC 2617 qop=auth: response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
            let nc = nc.unwrap_or("00000001");
            let cnonce = cnonce.unwrap_or("");
            md5_hex(&format!("{}:{}:{}:{}:auth:{}", ha1, nonce, nc, cnonce, ha2))
        }
        _ => {
            // RFC 2069（无 qop）：response = MD5(HA1:nonce:HA2)
            md5_hex(&format!("{}:{}:{}", ha1, nonce, ha2))
        }
    };

    tracing::debug!(
        "Digest 验证: username={}, realm={}, qop={:?}, HA1={}, HA2={}, expected={}, received={}",
        username, realm, qop, ha1, ha2, expected, response
    );

    expected.to_lowercase() == response.to_lowercase()
}

/// 计算 MD5 哈希并返回小写十六进制字符串
fn md5_hex(input: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5_hex() {
        // MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
        assert_eq!(md5_hex("abc"), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn test_digest_validation_no_qop() {
        // RFC 2069（无 qop）:
        // HA1 = MD5("1001:minghe.local:minghe@2024")
        // HA2 = MD5("REGISTER:sip:minghe.local")
        // expected = MD5(HA1:testnonce:HA2)
        let ha1 = md5_hex("1001:minghe.local:minghe@2024");
        let ha2 = md5_hex("REGISTER:sip:minghe.local");
        let response = md5_hex(&format!("{}:testnonce:{}", ha1, ha2));

        assert!(validate_digest(
            "1001",
            "minghe.local",
            "minghe@2024",
            "testnonce",
            "sip:minghe.local",
            "REGISTER",
            &response,
            None,
            None,
            None,
        ));
    }

    #[test]
    fn test_digest_validation_qop_auth() {
        // RFC 2617（qop=auth）:
        // response = MD5(HA1:nonce:nc:cnonce:auth:HA2)
        let ha1 = md5_hex("1001:minghe.local:minghe@2024");
        let ha2 = md5_hex("REGISTER:sip:minghe.local");
        let response = md5_hex(&format!("{}:testnonce:00000001:clientnonce:auth:{}", ha1, ha2));

        assert!(validate_digest(
            "1001",
            "minghe.local",
            "minghe@2024",
            "testnonce",
            "sip:minghe.local",
            "REGISTER",
            &response,
            Some("auth"),
            Some("00000001"),
            Some("clientnonce"),
        ));
    }

    #[test]
    fn test_digest_validation_wrong_password() {
        let ha1 = md5_hex("1001:minghe.local:wrongpassword");
        let ha2 = md5_hex("REGISTER:sip:minghe.local");
        let response = md5_hex(&format!("{}:testnonce:{}", ha1, ha2));

        assert!(!validate_digest(
            "1001",
            "minghe.local",
            "minghe@2024",
            "testnonce",
            "sip:minghe.local",
            "REGISTER",
            &response,
            None,
            None,
            None,
        ));
    }

    #[test]
    fn test_parse_authorization() {
        let header = r#"Digest username="1001", realm="minghe.local", nonce="abc123", uri="sip:minghe.local", response="deadbeef""#;
        let params = parse_authorization(header).unwrap();
        assert_eq!(params.username, "1001");
        assert_eq!(params.realm, "minghe.local");
        assert_eq!(params.nonce, "abc123");
        assert_eq!(params.uri, "sip:minghe.local");
        assert_eq!(params.response, "deadbeef");
    }

    #[test]
    fn test_generate_nonce() {
        let nonce = generate_nonce();
        assert_eq!(nonce.len(), 32); // 16 bytes = 32 hex chars
    }
}
