//! SIP 消息解析与构建辅助函数
//!
//! 提供 SIP 消息的解析、序列化、URI 提取、头部生成等功能。
//! 在严格的消息帧校验后提取头部并构建 SIP 文本。

use rand::Rng;
use uuid::Uuid;

/// 从 SIP URI 中提取用户部分（分机号）
///
/// 支持格式：
/// - `sip:1001@domain`
/// - `sips:1001@domain`
/// - `<sip:1001@domain>`
/// - `"Display" <sip:1001@domain>;tag=xxx`
pub fn extract_extension(uri_str: &str) -> Option<String> {
    // 尝试从尖括号中提取 URI
    let uri_part = if let Some(start) = uri_str.find('<') {
        if let Some(end) = uri_str[start + 1..].find('>').map(|i| start + 1 + i) {
            &uri_str[start + 1..end]
        } else {
            uri_str
        }
    } else {
        uri_str
    };

    // 去掉 sip:、sips: 或 tel: 前缀。URI scheme 大小写不敏感。
    let lower_uri = uri_part.to_ascii_lowercase();
    let without_scheme = if lower_uri.starts_with("sip:") {
        &uri_part[4..]
    } else if lower_uri.starts_with("sips:") {
        &uri_part[5..]
    } else if lower_uri.starts_with("tel:") {
        &uri_part[4..]
    } else {
        uri_part
    };

    // 提取 @ 之前的用户部分
    if let Some(at_pos) = without_scheme.find('@') {
        let user = without_scheme[..at_pos].split(';').next().unwrap_or("");
        if !user.is_empty() {
            Some(user.to_string())
        } else {
            None
        }
    } else {
        // 没有 @ 的情况，可能是纯数字分机
        let user = without_scheme.split(';').next().unwrap_or("");
        if !user.is_empty() && user.chars().all(|c| c.is_ascii_digit()) {
            Some(user.to_string())
        } else {
            None
        }
    }
}

/// 生成 Via 分支参数
///
/// 格式：z9hG4bK + 随机十六进制字符串
/// RFC 3261 要求分支参数以 "z9hG4bK" 开头
pub fn generate_branch() -> String {
    let random_part: String = hex::encode(rand::thread_rng().gen::<[u8; 8]>());
    format!("z9hG4bK{}", random_part)
}

/// 生成随机标签（用于 From/To 头部的 tag 参数）
pub fn generate_tag() -> String {
    hex::encode(rand::thread_rng().gen::<[u8; 8]>())
}

/// 生成唯一的 Call-ID
pub fn generate_call_id() -> String {
    Uuid::new_v4().to_string()
}

/// 从 SIP 请求构建响应
///
/// 复制原始请求的 Via、From、To、Call-ID、CSeq 头部，
/// 并设置指定的状态码和原因短语。
pub fn build_response(request: &str, status_code: u16, reason: &str) -> Vec<u8> {
    let mut via_headers = Vec::new();
    let mut from_header = String::new();
    let mut to_header = String::new();
    let mut call_id_header = String::new();
    let mut cseq_header = String::new();

    for line in request.lines() {
        let line_trimmed = line.trim();
        if line_trimmed.is_empty() {
            break; // 头部结束
        }
        let lower = line_trimmed.to_ascii_lowercase();
        if lower.starts_with("via:") || lower.starts_with("v:") {
            via_headers.push(line_trimmed.to_string());
        } else if lower.starts_with("from:") || lower.starts_with("f:") {
            from_header = line_trimmed.to_string();
        } else if lower.starts_with("to:") || lower.starts_with("t:") {
            to_header = line_trimmed.to_string();
        } else if lower.starts_with("call-id:") || lower.starts_with("i:") {
            call_id_header = line_trimmed.to_string();
        } else if lower.starts_with("cseq:") {
            cseq_header = line_trimmed.to_string();
        }
    }

    // 如果 To 头部没有 tag 参数，添加一个（用于非 100 响应）
    if status_code > 100 && !to_header.to_ascii_lowercase().contains("tag=") {
        to_header = format!("{};tag={}", to_header, generate_tag());
    }

    let mut response = format!("SIP/2.0 {} {}\r\n", status_code, reason);
    for via in &via_headers {
        response.push_str(via);
        response.push_str("\r\n");
    }
    response.push_str(&from_header);
    response.push_str("\r\n");
    response.push_str(&to_header);
    response.push_str("\r\n");
    response.push_str(&call_id_header);
    response.push_str("\r\n");
    response.push_str(&cseq_header);
    response.push_str("\r\n");
    response.push_str("Content-Length: 0\r\n");
    response.push_str("\r\n");

    response.into_bytes()
}

/// 从 SIP 请求构建带有额外头部的响应
pub fn build_response_with_headers(
    request: &str,
    status_code: u16,
    reason: &str,
    extra_headers: &[(&str, &str)],
) -> Vec<u8> {
    let mut via_headers = Vec::new();
    let mut from_header = String::new();
    let mut to_header = String::new();
    let mut call_id_header = String::new();
    let mut cseq_header = String::new();

    for line in request.lines() {
        let line_trimmed = line.trim();
        if line_trimmed.is_empty() {
            break;
        }
        let lower = line_trimmed.to_ascii_lowercase();
        if lower.starts_with("via:") || lower.starts_with("v:") {
            via_headers.push(line_trimmed.to_string());
        } else if lower.starts_with("from:") || lower.starts_with("f:") {
            from_header = line_trimmed.to_string();
        } else if lower.starts_with("to:") || lower.starts_with("t:") {
            to_header = line_trimmed.to_string();
        } else if lower.starts_with("call-id:") || lower.starts_with("i:") {
            call_id_header = line_trimmed.to_string();
        } else if lower.starts_with("cseq:") {
            cseq_header = line_trimmed.to_string();
        }
    }

    if status_code > 100 && !to_header.to_ascii_lowercase().contains("tag=") {
        to_header = format!("{};tag={}", to_header, generate_tag());
    }

    let mut response = format!("SIP/2.0 {} {}\r\n", status_code, reason);
    for via in &via_headers {
        response.push_str(via);
        response.push_str("\r\n");
    }
    response.push_str(&from_header);
    response.push_str("\r\n");
    response.push_str(&to_header);
    response.push_str("\r\n");
    response.push_str(&call_id_header);
    response.push_str("\r\n");
    response.push_str(&cseq_header);
    response.push_str("\r\n");

    for (name, value) in extra_headers {
        response.push_str(&format!("{}: {}\r\n", name, value));
    }

    response.push_str("Content-Length: 0\r\n");
    response.push_str("\r\n");

    response.into_bytes()
}

/// 从 SIP 请求构建带有消息体的响应
pub fn build_response_with_body(
    request: &str,
    status_code: u16,
    reason: &str,
    extra_headers: &[(&str, &str)],
    body: &str,
) -> Vec<u8> {
    let mut via_headers = Vec::new();
    let mut from_header = String::new();
    let mut to_header = String::new();
    let mut call_id_header = String::new();
    let mut cseq_header = String::new();

    for line in request.lines() {
        let line_trimmed = line.trim();
        if line_trimmed.is_empty() {
            break;
        }
        let lower = line_trimmed.to_ascii_lowercase();
        if lower.starts_with("via:") || lower.starts_with("v:") {
            via_headers.push(line_trimmed.to_string());
        } else if lower.starts_with("from:") || lower.starts_with("f:") {
            from_header = line_trimmed.to_string();
        } else if lower.starts_with("to:") || lower.starts_with("t:") {
            to_header = line_trimmed.to_string();
        } else if lower.starts_with("call-id:") || lower.starts_with("i:") {
            call_id_header = line_trimmed.to_string();
        } else if lower.starts_with("cseq:") {
            cseq_header = line_trimmed.to_string();
        }
    }

    if status_code > 100 && !to_header.to_ascii_lowercase().contains("tag=") {
        to_header = format!("{};tag={}", to_header, generate_tag());
    }

    let body_bytes = body.as_bytes();
    let mut response = format!("SIP/2.0 {} {}\r\n", status_code, reason);
    for via in &via_headers {
        response.push_str(via);
        response.push_str("\r\n");
    }
    response.push_str(&from_header);
    response.push_str("\r\n");
    response.push_str(&to_header);
    response.push_str("\r\n");
    response.push_str(&call_id_header);
    response.push_str("\r\n");
    response.push_str(&cseq_header);
    response.push_str("\r\n");

    for (name, value) in extra_headers {
        response.push_str(&format!("{}: {}\r\n", name, value));
    }

    if !body.is_empty() {
        response.push_str("Content-Type: application/sdp\r\n");
    }
    response.push_str(&format!("Content-Length: {}\r\n", body_bytes.len()));
    response.push_str("\r\n");

    if !body.is_empty() {
        response.push_str(body);
    }

    response.into_bytes()
}

/// 提取 Contact 头部的 URI
///
/// 从 SIP 请求文本中提取 Contact 头部的 URI 值
pub fn extract_contact_uri(request: &str) -> Option<String> {
    for line in request.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("contact:") || lower.starts_with("m:") {
            let value = if lower.starts_with("contact:") {
                trimmed[8..].trim()
            } else {
                trimmed[2..].trim()
            };
            // 提取尖括号中的 URI
            if let Some(start) = value.find('<') {
                if let Some(end) = value[start + 1..].find('>').map(|i| start + 1 + i) {
                    return Some(value[start + 1..end].to_string());
                }
            }
            // 没有尖括号时，保留 URI 参数（例如 ;transport=tls），只去掉
            // Contact 头自身的 expires/q 等参数以及逗号后的其它 Contact。
            let first_contact = value.split(',').next().unwrap_or(value).trim();
            let lower_contact = first_contact.to_ascii_lowercase();
            let mut end = first_contact.len();
            for marker in [";expires=", ";q="] {
                if let Some(pos) = lower_contact.find(marker) {
                    end = end.min(pos);
                }
            }
            return Some(first_contact[..end].trim().to_string());
        }
    }
    None
}

/// 从 SIP 消息中提取 Call-ID
pub fn extract_call_id(msg: &str) -> Option<String> {
    for line in msg.lines().take_while(|line| !line.trim().is_empty()) {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("call-id:") {
            return Some(trimmed[8..].trim().to_string());
        } else if lower.starts_with("i:") {
            return Some(trimmed[2..].trim().to_string());
        }
    }
    None
}

/// 通用头部值提取
///
/// 根据头部名称从 SIP 请求文本中提取对应的值
pub fn extract_header_value(msg: &str, name: &str) -> Option<String> {
    let name_lower = name.to_ascii_lowercase();
    let search_prefix = format!("{}:", name_lower);
    for line in msg.lines().take_while(|line| !line.trim().is_empty()) {
        let trimmed = line.trim();
        if trimmed.to_ascii_lowercase().starts_with(&search_prefix) {
            let value = trimmed[name.len() + 1..].trim();
            return Some(value.to_string());
        }
    }
    None
}

/// 提取 SIP 方法名
///
/// 从 SIP 消息的第一行提取方法（REGISTER, INVITE, BYE 等）
/// 如果是响应消息，返回 None
pub fn extract_method(msg: &str) -> Option<String> {
    let first_line = msg.lines().next()?;
    let trimmed = first_line.trim();

    // 响应以 SIP/2.0 开头
    if trimmed.starts_with("SIP/2.0") {
        return None;
    }

    // 请求格式: METHOD URI SIP/2.0
    let method = trimmed.split_whitespace().next()?;
    Some(method.to_uppercase())
}

/// 提取请求 URI
///
/// 从 SIP 请求的第一行提取 Request-URI
pub fn extract_request_uri(msg: &str) -> Option<String> {
    let first_line = msg.lines().next()?;
    let trimmed = first_line.trim();

    if trimmed.starts_with("SIP/2.0") {
        return None;
    }

    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.len() >= 2 {
        Some(parts[1].to_string())
    } else {
        None
    }
}

/// 提取响应状态码
///
/// 从 SIP 响应消息的第一行提取状态码
pub fn extract_status_code(msg: &str) -> Option<u16> {
    let first_line = msg.lines().next()?;
    let trimmed = first_line.trim();

    if !trimmed.starts_with("SIP/2.0") {
        return None;
    }

    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.len() >= 2 {
        parts[1].parse().ok()
    } else {
        None
    }
}

/// 提取 Via 分支参数
pub fn extract_via_branch(msg: &str) -> Option<String> {
    for line in msg.lines().take_while(|line| !line.trim().is_empty()) {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("via:") || lower.starts_with("v:") {
            // 在 Via 头部中查找 branch= 参数
            if let Some(branch_pos) = lower.find("branch=") {
                let after_branch = &trimmed[branch_pos + 7..];
                let branch = after_branch
                    .split(|c: char| c == ';' || c == ',' || c.is_whitespace())
                    .next()
                    .unwrap_or("");
                if !branch.is_empty() {
                    return Some(branch.to_string());
                }
            }
        }
    }
    None
}

/// 提取 From 头部中的 tag 参数
pub fn extract_from_tag(msg: &str) -> Option<String> {
    for line in msg.lines().take_while(|line| !line.trim().is_empty()) {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("from:") || lower.starts_with("f:") {
            if let Some(tag_pos) = lower.find("tag=") {
                let after_tag = &trimmed[tag_pos + 4..];
                let tag = after_tag
                    .split(|c: char| c == ';' || c == ',' || c.is_whitespace())
                    .next()
                    .unwrap_or("");
                if !tag.is_empty() {
                    return Some(tag.to_string());
                }
            }
        }
    }
    None
}

/// 提取 To 头部中的 tag 参数
pub fn extract_to_tag(msg: &str) -> Option<String> {
    for line in msg.lines().take_while(|line| !line.trim().is_empty()) {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("to:") || lower.starts_with("t:") {
            if let Some(tag_pos) = lower.find("tag=") {
                let after_tag = &trimmed[tag_pos + 4..];
                let tag = after_tag
                    .split(|c: char| c == ';' || c == ',' || c.is_whitespace())
                    .next()
                    .unwrap_or("");
                if !tag.is_empty() {
                    return Some(tag.to_string());
                }
            }
        }
    }
    None
}

/// 提取 CSeq 头部中的方法名
pub fn extract_cseq_method(msg: &str) -> Option<String> {
    for line in msg.lines().take_while(|line| !line.trim().is_empty()) {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("cseq:") {
            let value = trimmed[5..].trim();
            // CSeq 格式: <序号> <方法>
            let parts: Vec<&str> = value.split_whitespace().collect();
            if parts.len() >= 2 {
                return Some(parts[1].to_uppercase());
            }
        }
    }
    None
}

/// 提取 Expires 头部值
pub fn extract_expires(msg: &str) -> Option<u64> {
    // 先检查 Expires 头部
    for line in msg.lines().take_while(|line| !line.trim().is_empty()) {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("expires:") {
            let value = trimmed[8..].trim();
            return value.parse().ok();
        }
    }

    // 再检查 Contact 头部中的 expires 参数
    for line in msg.lines().take_while(|line| !line.trim().is_empty()) {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("contact:") || lower.starts_with("m:") {
            if let Some(pos) = lower.find("expires=") {
                let after = &trimmed[pos + 8..];
                let val = after
                    .split(|c: char| c == ';' || c == ',' || c.is_whitespace() || c == '>')
                    .next()
                    .unwrap_or("");
                return val.parse().ok();
            }
        }
    }

    None
}

/// 提取 SIP 消息体（SDP）
pub fn extract_body(msg: &str) -> Option<String> {
    if let Some(pos) = msg.find("\r\n\r\n") {
        let body = &msg[pos + 4..];
        if !body.is_empty() {
            return Some(body.to_string());
        }
    }
    None
}

/// TCP 消息帧分界
///
/// 在 TCP 缓冲区中查找完整的 SIP 消息边界。
/// SIP over TCP 使用 Content-Length 头部来确定消息体长度。
///
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SipFrameResult {
    Complete(usize),
    Incomplete,
    Invalid,
}

/// 返回完整、尚未接收完整或协议错误。非法/冲突的 Content-Length 不能按 0
/// 处理，否则其消息体会被误当成下一条 SIP 请求。
pub fn frame_sip_message(buf: &[u8]) -> SipFrameResult {
    // 查找头部结束标记 \r\n\r\n
    let header_end_marker = b"\r\n\r\n";
    let mut header_end_pos = None;

    if buf.len() < 4 {
        return SipFrameResult::Incomplete;
    }

    for i in 0..=(buf.len() - 4) {
        if &buf[i..i + 4] == header_end_marker {
            header_end_pos = Some(i);
            break;
        }
    }

    let Some(header_end) = header_end_pos else {
        return if buf.len() > 16384 {
            SipFrameResult::Invalid
        } else {
            SipFrameResult::Incomplete
        };
    };
    let headers_with_separator = header_end + 4; // 包括 \r\n\r\n

    if header_end > 16384 {
        return SipFrameResult::Invalid;
    }
    // 解析 Content-Length 头部
    let Ok(header_text) = std::str::from_utf8(&buf[..header_end]) else {
        return SipFrameResult::Invalid;
    };
    let mut seen = std::collections::HashSet::new();
    for line in header_text.split("\r\n").skip(1) {
        if line.starts_with([' ', '\t']) || line.bytes().any(|b| b < 32 && b != b'\t' || b == 127) {
            return SipFrameResult::Invalid;
        }
        let Some((name, _)) = line.split_once(':') else {
            return SipFrameResult::Invalid;
        };
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return SipFrameResult::Invalid;
        }
        let name = name.to_ascii_lowercase();
        let canonical = match name.as_str() {
            "f" => "from",
            "t" => "to",
            "i" => "call-id",
            "m" => "contact",
            "l" => "content-length",
            other => other,
        };
        if matches!(
            canonical,
            "from"
                | "to"
                | "call-id"
                | "contact"
                | "cseq"
                | "authorization"
                | "content-length"
                | "expires"
        ) && !seen.insert(canonical.to_string())
        {
            return SipFrameResult::Invalid;
        }
    }
    let mut content_length: Option<usize> = None;

    for line in header_text.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("content-length:") || lower.starts_with("l:") {
            let value = if lower.starts_with("content-length:") {
                trimmed[15..].trim()
            } else {
                trimmed[2..].trim()
            };
            let Ok(parsed) = value.parse::<usize>() else {
                return SipFrameResult::Invalid;
            };
            if content_length.is_some_and(|existing| existing != parsed) {
                return SipFrameResult::Invalid;
            }
            content_length = Some(parsed);
        }
    }

    let Some(total_length) = headers_with_separator.checked_add(content_length.unwrap_or(0)) else {
        return SipFrameResult::Invalid;
    };

    if total_length > 65536 {
        return SipFrameResult::Invalid;
    }
    // 检查缓冲区中是否有足够的数据
    if buf.len() >= total_length {
        SipFrameResult::Complete(total_length)
    } else {
        SipFrameResult::Incomplete
    }
}

/// 判断消息是否为 SIP 请求
pub fn is_request(msg: &str) -> bool {
    let first_line = match msg.lines().next() {
        Some(line) => line.trim(),
        None => return false,
    };
    !first_line.starts_with("SIP/2.0")
}

/// 判断消息是否为 SIP 响应
pub fn is_response(msg: &str) -> bool {
    let first_line = match msg.lines().next() {
        Some(line) => line.trim(),
        None => return false,
    };
    first_line.starts_with("SIP/2.0")
}

/// 从 From/To 头部提取 URI
///
/// 支持标准格式和 SIP 紧凑格式：
/// - From / f:
/// - To / t:
/// - Contact / m:
pub fn extract_uri_from_header(msg: &str, header_name: &str) -> Option<String> {
    let search = format!("{}:", header_name.to_ascii_lowercase());
    // SIP 紧凑格式映射
    let compact = match header_name.to_ascii_lowercase().as_str() {
        "from" => Some("f:"),
        "to" => Some("t:"),
        "contact" => Some("m:"),
        "via" => Some("v:"),
        "call-id" => Some("i:"),
        _ => None,
    };

    for line in msg.lines().take_while(|line| !line.trim().is_empty()) {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();

        let value_opt = if lower.starts_with(&search) {
            Some(&trimmed[header_name.len() + 1..])
        } else if let Some(c) = compact {
            if lower.starts_with(c) {
                Some(&trimmed[c.len()..])
            } else {
                None
            }
        } else {
            None
        };

        if let Some(value) = value_opt {
            // 尝试从尖括号中提取
            if let Some(start) = value.find('<') {
                if let Some(end) = value[start + 1..].find('>').map(|i| start + 1 + i) {
                    return Some(value[start + 1..end].to_string());
                }
            }
            // 没有尖括号
            let uri = value.trim().split(';').next().unwrap_or("").trim();
            if !uri.is_empty() {
                return Some(uri.to_string());
            }
        }
    }
    None
}

/// 要注入 SDP 的 crypto 行描述（SDES）
#[derive(Debug, Clone)]
pub struct SdpCrypto {
    /// crypto tag（同一媒体段内必须唯一）
    pub tag: u32,
    /// 加密套件名称（如 `AES_CM_128_HMAC_SHA1_80`、`AEAD_AES_128_GCM`）
    pub suite: String,
    /// Base64 编码的 SDES key||salt（不含 `inline:` 前缀与生命周期参数）
    pub key_b64: String,
}

impl SdpCrypto {
    /// 生成 `a=crypto:TAG SUITE inline:KEY` 行
    pub fn to_line(&self) -> String {
        format!(
            "a=crypto:{} {} inline:{}",
            self.tag, self.suite, self.key_b64
        )
    }
}

/// 修改 SDP 中的媒体地址和端口，并注入指定的 SDES crypto key
///
/// 将 SDP 中的 c= 行替换为服务器中继地址，
/// 将 m=audio 行的端口替换为中继端口，并将 RTP/AVP 规范化为 RTP/SAVP。
/// 服务器作为媒体 B2BUA，每一侧使用独立的 SDES 密钥。
pub fn rewrite_sdp(sdp: &str, relay_addr: &str, relay_port: u16, crypto_key_b64: &str) -> String {
    rewrite_sdp_with_crypto(sdp, relay_addr, relay_port, Some(crypto_key_b64))
}

/// 修改 SDP 中的媒体地址和端口，可选注入 SDES crypto key
///
/// 单密钥版本：以 tag 1 + `AES_CM_128_HMAC_SHA1_80` 注入。
pub fn rewrite_sdp_with_crypto(
    sdp: &str,
    relay_addr: &str,
    relay_port: u16,
    crypto_key_b64: Option<&str>,
) -> String {
    let cryptos: Vec<SdpCrypto> = crypto_key_b64
        .map(|key| {
            vec![SdpCrypto {
                tag: 1,
                suite: "AES_CM_128_HMAC_SHA1_80".to_string(),
                key_b64: key.to_string(),
            }]
        })
        .unwrap_or_default();
    rewrite_sdp_with_cryptos(sdp, relay_addr, relay_port, &cryptos)
}

/// 修改 SDP 中的媒体地址和端口，注入多行 SDES crypto key
///
/// 向 m=audio 段注入多个 `a=crypto` 行（不同 tag），供对端选择其支持的加密套件，
/// 例如同时提供 `AES_CM_128_HMAC_SHA1_80` 与 `AEAD_AES_128_GCM`。
pub fn rewrite_sdp_with_cryptos(
    sdp: &str,
    relay_addr: &str,
    relay_port: u16,
    cryptos: &[SdpCrypto],
) -> String {
    let mut result = Vec::new();
    let mut in_audio = false;
    let mut found_audio = false;
    let mut crypto_inserted = false;
    let has_crypto = !cryptos.is_empty();

    for line in sdp.lines() {
        if line.starts_with("m=") {
            if in_audio && !crypto_inserted && has_crypto {
                push_crypto_lines(&mut result, cryptos);
            }
            in_audio = line.starts_with("m=audio");
            crypto_inserted = false;
        }

        if line.starts_with("c=") {
            // 替换连接信息为服务器中继地址
            result.push(format!("c=IN IP4 {}", relay_addr));
        } else if line.starts_with("m=audio") {
            // 替换媒体端口
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                // m=audio <port> <proto> <formats...>
                let proto = if has_crypto {
                    "RTP/SAVP".to_string()
                } else {
                    parts[2].to_string()
                };
                let formats: Vec<&str> = parts[3..].to_vec();
                result.push(format!(
                    "m=audio {} {} {}",
                    relay_port,
                    proto,
                    formats.join(" ")
                ));
                found_audio = true;
            } else {
                result.push(line.to_string());
            }
        } else {
            if has_crypto && should_strip_for_sdes_srtp(line) {
                continue;
            }

            if in_audio && line.starts_with("a=crypto") {
                if !crypto_inserted {
                    push_crypto_lines(&mut result, cryptos);
                    crypto_inserted = true;
                }
                continue;
            }
            result.push(line.to_string());
        }
    }

    if in_audio && found_audio && !crypto_inserted && has_crypto {
        push_crypto_lines(&mut result, cryptos);
    }

    // RFC 4566 要求每行（含最后一行）以 CRLF 结束。部分客户端严格的 SDP 解析器
    // 对最后一行缺少结尾换行的 SDP 会在最后一行处提前终止解析——
    // 当最后一行恰好是 a=crypto 时，crypto 丢失导致对端判定 answer 不兼容而挂断。
    let mut sdp = result.join("\r\n");
    sdp.push_str("\r\n");
    sdp
}

fn push_crypto_lines(result: &mut Vec<String>, cryptos: &[SdpCrypto]) {
    for crypto in cryptos {
        result.push(crypto.to_line());
    }
}

fn should_strip_for_sdes_srtp(line: &str) -> bool {
    let lower = line.trim().to_ascii_lowercase();
    matches!(
        lower.as_str(),
        value
            if value.starts_with("a=crypto:")
                || value.starts_with("a=fingerprint:")
                || value.starts_with("a=setup:")
                || value.starts_with("a=connection:")
                || value.starts_with("a=key-mgmt:")
                || value.starts_with("a=ice-ufrag:")
                || value.starts_with("a=ice-pwd:")
                || value.starts_with("a=ice-options:")
                || value.starts_with("a=candidate:")
                || value.starts_with("a=end-of-candidates")
                || value.starts_with("a=remote-candidates:")
                || value.starts_with("a=rtcp:")
                || value.starts_with("a=rtcp-mux")
                || value.starts_with("a=rtcp-rsize")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_ambiguous_and_oversized_frames() {
        for headers in [
            "From: a\r\nf: b",
            "Content-Length: 0\r\nl: 0",
            " Content-Length: 0",
            "Content-Length : 0",
            "X: bad\nFrom: injected",
            "Content-Length: 999999999",
        ] {
            let message = format!("OPTIONS sip:example.com SIP/2.0\r\n{headers}\r\n\r\n");
            assert_eq!(
                frame_sip_message(message.as_bytes()),
                SipFrameResult::Invalid,
                "{headers}"
            );
        }
    }

    #[test]
    fn malformed_brackets_and_unicode_never_panic_or_read_body_headers() {
        for value in [
            ">sip:1001@example.com<",
            "İİ<sip:1001@example.com>",
            "><",
            "😀<>",
        ] {
            let msg = format!("REGISTER sip:example.com SIP/2.0\r\nContact: {value}\r\nFrom: {value};tag=test\r\n\r\nAuthorization: stolen");
            let _ = extract_extension(value);
            let _ = extract_uri_from_header(&msg, "From");
            let _ = extract_contact_uri(&msg);
            let _ = extract_from_tag(&msg);
            assert!(extract_header_value(&msg, "Authorization").is_none());
        }
    }

    #[test]
    fn test_extract_extension_basic() {
        assert_eq!(
            extract_extension("sip:1001@example.com"),
            Some("1001".to_string())
        );
    }

    #[test]
    fn test_extract_extension_with_brackets() {
        assert_eq!(
            extract_extension("<sip:1001@example.com>"),
            Some("1001".to_string())
        );
    }

    #[test]
    fn test_extract_extension_with_display_name() {
        assert_eq!(
            extract_extension("\"Alice\" <sip:1001@example.com>;tag=abc123"),
            Some("1001".to_string())
        );
    }

    #[test]
    fn test_extract_extension_sips() {
        assert_eq!(
            extract_extension("sips:1002@example.com"),
            Some("1002".to_string())
        );
    }

    #[test]
    fn test_extract_extension_case_insensitive_scheme() {
        assert_eq!(
            extract_extension("SIP:1002@example.com"),
            Some("1002".to_string())
        );
        assert_eq!(
            extract_extension("SIPS:1003@example.com"),
            Some("1003".to_string())
        );
    }

    #[test]
    fn test_extract_extension_with_user_param_before_host() {
        assert_eq!(
            extract_extension("sip:1002;user=phone@example.com"),
            Some("1002".to_string())
        );
    }

    #[test]
    fn test_extract_extension_tel_uri() {
        assert_eq!(extract_extension("tel:1002"), Some("1002".to_string()));
    }

    #[test]
    fn test_generate_branch() {
        let branch = generate_branch();
        assert!(branch.starts_with("z9hG4bK"));
        assert!(branch.len() > 7);
    }

    #[test]
    fn test_generate_tag() {
        let tag = generate_tag();
        assert_eq!(tag.len(), 16); // 8 bytes = 16 hex chars
    }

    #[test]
    fn test_frame_sip_message_complete() {
        let msg = b"REGISTER sip:example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(frame_sip_message(msg), SipFrameResult::Complete(msg.len()));
    }

    #[test]
    fn test_frame_sip_message_with_body() {
        let msg = b"INVITE sip:1001@example.com SIP/2.0\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(frame_sip_message(msg), SipFrameResult::Complete(msg.len()));
    }

    #[test]
    fn test_frame_sip_message_incomplete() {
        let msg = b"INVITE sip:1001@example.com SIP/2.0\r\nContent-Length: 100\r\n\r\nhello";
        assert_eq!(frame_sip_message(msg), SipFrameResult::Incomplete);
    }

    #[test]
    fn test_frame_sip_message_no_headers_end() {
        let msg = b"REGISTER sip:example.com SIP/2.0\r\nContent-Length: 0\r\n";
        assert_eq!(frame_sip_message(msg), SipFrameResult::Incomplete);
    }

    #[test]
    fn test_frame_sip_message_rejects_invalid_content_length() {
        let msg = b"MESSAGE sip:1001@example.com SIP/2.0\r\nContent-Length: nope\r\n\r\nbody";
        assert_eq!(frame_sip_message(msg), SipFrameResult::Invalid);
    }

    #[test]
    fn test_frame_sip_message_rejects_conflicting_content_lengths() {
        let msg = b"MESSAGE sip:1001@example.com SIP/2.0\r\nContent-Length: 4\r\nl: 5\r\n\r\nhello";
        assert_eq!(frame_sip_message(msg), SipFrameResult::Invalid);
    }

    #[test]
    fn test_extract_method() {
        assert_eq!(
            extract_method("REGISTER sip:example.com SIP/2.0\r\n"),
            Some("REGISTER".to_string())
        );
        assert_eq!(
            extract_method("INVITE sip:1001@example.com SIP/2.0\r\n"),
            Some("INVITE".to_string())
        );
        assert_eq!(extract_method("SIP/2.0 200 OK\r\n"), None);
    }

    #[test]
    fn test_extract_status_code() {
        assert_eq!(extract_status_code("SIP/2.0 200 OK\r\n"), Some(200));
        assert_eq!(extract_status_code("SIP/2.0 404 Not Found\r\n"), Some(404));
        assert_eq!(
            extract_status_code("REGISTER sip:example.com SIP/2.0\r\n"),
            None
        );
    }

    #[test]
    fn test_is_request_response() {
        assert!(is_request("REGISTER sip:example.com SIP/2.0\r\n"));
        assert!(!is_request("SIP/2.0 200 OK\r\n"));
        assert!(is_response("SIP/2.0 200 OK\r\n"));
        assert!(!is_response("REGISTER sip:example.com SIP/2.0\r\n"));
    }

    #[test]
    fn test_extract_call_id() {
        let msg = "REGISTER sip:example.com SIP/2.0\r\nCall-ID: abc123@host\r\n\r\n";
        assert_eq!(extract_call_id(msg), Some("abc123@host".to_string()));
    }

    #[test]
    fn test_extract_contact_uri_preserves_transport_param() {
        let msg = concat!(
            "REGISTER sip:example.com SIP/2.0\r\n",
            "Contact: sip:1002@192.0.2.10:5061;transport=tls;expires=600\r\n",
            "Content-Length: 0\r\n\r\n"
        );

        assert_eq!(
            extract_contact_uri(msg),
            Some("sip:1002@192.0.2.10:5061;transport=tls".to_string())
        );
    }

    #[test]
    fn test_rewrite_sdp_normalizes_srtp_and_replaces_crypto() {
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 192.168.1.10\r\n",
            "c=IN IP4 192.168.1.10\r\n",
            "m=audio 4000 RTP/AVP 0 8 101\r\n",
            "a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:CLIENTKEY\r\n"
        );

        let rewritten = rewrite_sdp(sdp, "203.0.113.10", 20000, "SERVERKEY");

        assert!(rewritten.contains("c=IN IP4 203.0.113.10"));
        assert!(rewritten.contains("m=audio 20000 RTP/SAVP 0 8 101"));
        assert!(rewritten.contains("a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:SERVERKEY"));
        assert!(!rewritten.contains("CLIENTKEY"));
    }

    #[test]
    fn test_rewrite_sdp_strips_dtls_ice_and_rtcp_for_sdes_srtp() {
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 192.168.1.10\r\n",
            "c=IN IP4 192.168.1.10\r\n",
            "a=ice-ufrag:abc\r\n",
            "a=ice-pwd:def\r\n",
            "a=fingerprint:sha-256 00:11:22\r\n",
            "a=setup:actpass\r\n",
            "m=audio 4000 RTP/SAVPF 0 8 101\r\n",
            "a=rtcp:4001 IN IP4 192.168.1.10\r\n",
            "a=rtcp-mux\r\n",
            "a=candidate:1 1 UDP 2130706431 192.168.1.10 4000 typ host\r\n",
            "a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:CLIENTKEY\r\n",
            "a=rtpmap:0 PCMU/8000\r\n"
        );

        let rewritten = rewrite_sdp(sdp, "203.0.113.10", 20000, "SERVERKEY");

        assert!(rewritten.contains("m=audio 20000 RTP/SAVP 0 8 101"));
        assert!(rewritten.contains("c=IN IP4 203.0.113.10"));
        assert!(rewritten.contains("a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:SERVERKEY"));
        assert!(rewritten.contains("a=rtpmap:0 PCMU/8000"));
        assert!(!rewritten.contains("RTP/SAVPF"));
        assert!(!rewritten.contains("CLIENTKEY"));
        assert!(!rewritten.contains("a=ice-ufrag"));
        assert!(!rewritten.contains("a=ice-pwd"));
        assert!(!rewritten.contains("a=fingerprint"));
        assert!(!rewritten.contains("a=setup"));
        assert!(!rewritten.contains("a=rtcp"));
        assert!(!rewritten.contains("a=candidate"));
    }

    #[test]
    fn test_rewrite_sdp_strips_session_level_crypto() {
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 192.168.1.10\r\n",
            "c=IN IP4 192.168.1.10\r\n",
            "a=crypto:9 AES_CM_128_HMAC_SHA1_80 inline:SESSIONKEY\r\n",
            "m=audio 4000 RTP/SAVP 0 8 101\r\n",
            "a=rtpmap:0 PCMU/8000\r\n"
        );

        let rewritten = rewrite_sdp(sdp, "203.0.113.10", 20000, "SERVERKEY");

        assert!(rewritten.contains("a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:SERVERKEY"));
        assert!(!rewritten.contains("SESSIONKEY"));
        assert_eq!(rewritten.matches("a=crypto:").count(), 1);
    }

    #[test]
    fn test_rewrite_sdp_with_multiple_cryptos() {
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 192.168.1.10\r\n",
            "c=IN IP4 192.168.1.10\r\n",
            "m=audio 4000 RTP/AVP 0 8 101\r\n",
            "a=rtpmap:0 PCMU/8000\r\n"
        );

        let cryptos = vec![
            SdpCrypto {
                tag: 1,
                suite: "AES_CM_128_HMAC_SHA1_80".to_string(),
                key_b64: "KEY_AES_CM".to_string(),
            },
            SdpCrypto {
                tag: 2,
                suite: "AEAD_AES_128_GCM".to_string(),
                key_b64: "KEY_GCM".to_string(),
            },
        ];

        let rewritten = rewrite_sdp_with_cryptos(sdp, "203.0.113.10", 20000, &cryptos);

        assert!(rewritten.contains("c=IN IP4 203.0.113.10"));
        assert!(rewritten.contains("m=audio 20000 RTP/SAVP 0 8 101"));
        assert!(rewritten.contains("a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:KEY_AES_CM"));
        assert!(rewritten.contains("a=crypto:2 AEAD_AES_128_GCM inline:KEY_GCM"));
        assert!(rewritten.contains("a=rtpmap:0 PCMU/8000"));
        assert_eq!(rewritten.matches("a=crypto:").count(), 2);
    }

    #[test]
    fn test_rewrite_sdp_without_crypto_keeps_protocol() {
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 192.168.1.10\r\n",
            "c=IN IP4 192.168.1.10\r\n",
            "m=audio 4000 RTP/AVP 0 8\r\n"
        );

        let rewritten = rewrite_sdp_with_cryptos(sdp, "203.0.113.10", 20000, &[]);

        assert!(rewritten.contains("m=audio 20000 RTP/AVP 0 8"));
        assert!(!rewritten.contains("a=crypto"));
    }

    #[test]
    fn test_rewrite_sdp_ends_with_crlf() {
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 192.168.1.10\r\n",
            "c=IN IP4 192.168.1.10\r\n",
            "m=audio 4000 RTP/AVP 0 8\r\n"
        );

        let rewritten = rewrite_sdp_with_cryptos(sdp, "203.0.113.10", 20000, &[]);

        // 最后一行必须以 CRLF 结束，否则严格客户端的 SDP 解析器解析最后一行失败
        assert!(rewritten.ends_with("\r\n"), "SDP 必须以 CRLF 结尾");
        assert!(!rewritten.ends_with("\r\n\r\n"), "不应有多余空行");
    }
}
