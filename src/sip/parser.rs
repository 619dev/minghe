//! SIP 消息解析与构建辅助函数
//!
//! 提供 SIP 消息的解析、序列化、URI 提取、头部生成等功能。
//! 由于 rsip crate 的 API 在构建响应时较为复杂，
//! 本模块采用手动构建 SIP 文本的方式，更加可靠灵活。

use anyhow::{anyhow, Result};
use rand::Rng;
use uuid::Uuid;

/// 解析原始字节为 SIP 消息文本
///
/// 将原始 TCP 字节流中的数据转换为 UTF-8 字符串，
/// 然后尝试解析为 rsip::SipMessage。
pub fn parse_sip_message(data: &[u8]) -> Result<rsip::SipMessage> {
    let text = std::str::from_utf8(data)
        .map_err(|e| anyhow!("SIP 消息 UTF-8 解码失败: {}", e))?;
    let msg: rsip::SipMessage = text
        .to_string()
        .try_into()
        .map_err(|e: rsip::Error| anyhow!("SIP 消息解析失败: {}", e))?;
    Ok(msg)
}

/// 将 SIP 消息序列化为字节
pub fn serialize_message(msg: &rsip::SipMessage) -> Vec<u8> {
    msg.to_string().into_bytes()
}

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
        if let Some(end) = uri_str.find('>') {
            &uri_str[start + 1..end]
        } else {
            uri_str
        }
    } else {
        uri_str
    };

    // 去掉 sip: 或 sips: 前缀
    let without_scheme = if let Some(rest) = uri_part.strip_prefix("sip:") {
        rest
    } else if let Some(rest) = uri_part.strip_prefix("sips:") {
        rest
    } else {
        uri_part
    };

    // 提取 @ 之前的用户部分
    if let Some(at_pos) = without_scheme.find('@') {
        let user = &without_scheme[..at_pos];
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
        let lower = line_trimmed.to_lowercase();
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
    if status_code > 100 && !to_header.to_lowercase().contains("tag=") {
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
        let lower = line_trimmed.to_lowercase();
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

    if status_code > 100 && !to_header.to_lowercase().contains("tag=") {
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
        let lower = line_trimmed.to_lowercase();
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

    if status_code > 100 && !to_header.to_lowercase().contains("tag=") {
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
        let lower = trimmed.to_lowercase();
        if lower.starts_with("contact:") || lower.starts_with("m:") {
            let value = if lower.starts_with("contact:") {
                trimmed[8..].trim()
            } else {
                trimmed[2..].trim()
            };
            // 提取尖括号中的 URI
            if let Some(start) = value.find('<') {
                if let Some(end) = value.find('>') {
                    return Some(value[start + 1..end].to_string());
                }
            }
            // 没有尖括号，取分号之前的部分
            let uri = value.split(';').next().unwrap_or(value).trim();
            return Some(uri.to_string());
        }
    }
    None
}

/// 从 SIP 消息中提取 Call-ID
pub fn extract_call_id(msg: &str) -> Option<String> {
    for line in msg.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_lowercase();
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
    let name_lower = name.to_lowercase();
    let search_prefix = format!("{}:", name_lower);
    for line in msg.lines() {
        let trimmed = line.trim();
        if trimmed.to_lowercase().starts_with(&search_prefix) {
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
    for line in msg.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_lowercase();
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
    for line in msg.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_lowercase();
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
    for line in msg.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_lowercase();
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
    for line in msg.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_lowercase();
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
    for line in msg.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_lowercase();
        if lower.starts_with("expires:") {
            let value = trimmed[8..].trim();
            return value.parse().ok();
        }
    }

    // 再检查 Contact 头部中的 expires 参数
    for line in msg.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_lowercase();
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
/// 返回完整消息的总字节长度（头部 + 空行 + 消息体），
/// 如果缓冲区中没有完整消息则返回 None。
pub fn frame_sip_message(buf: &[u8]) -> Option<usize> {
    // 查找头部结束标记 \r\n\r\n
    let header_end_marker = b"\r\n\r\n";
    let mut header_end_pos = None;

    if buf.len() < 4 {
        return None;
    }

    for i in 0..=(buf.len() - 4) {
        if &buf[i..i + 4] == header_end_marker {
            header_end_pos = Some(i);
            break;
        }
    }

    let header_end = header_end_pos?;
    let headers_with_separator = header_end + 4; // 包括 \r\n\r\n

    // 解析 Content-Length 头部
    let header_text = std::str::from_utf8(&buf[..header_end]).ok()?;
    let mut content_length: usize = 0;

    for line in header_text.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_lowercase();
        if lower.starts_with("content-length:") || lower.starts_with("l:") {
            let value = if lower.starts_with("content-length:") {
                trimmed[15..].trim()
            } else {
                trimmed[2..].trim()
            };
            content_length = value.parse().unwrap_or(0);
            break;
        }
    }

    let total_length = headers_with_separator + content_length;

    // 检查缓冲区中是否有足够的数据
    if buf.len() >= total_length {
        Some(total_length)
    } else {
        None
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
    let search = format!("{}:", header_name.to_lowercase());
    // SIP 紧凑格式映射
    let compact = match header_name.to_lowercase().as_str() {
        "from" => Some("f:"),
        "to" => Some("t:"),
        "contact" => Some("m:"),
        "via" => Some("v:"),
        "call-id" => Some("i:"),
        _ => None,
    };

    for line in msg.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_lowercase();

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
                if let Some(end) = value.find('>') {
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

/// 修改 SDP 中的媒体地址和端口，并注入 SRTP crypto 行
///
/// 将 SDP 中的 c= 行替换为服务器中继地址，
/// 将 m= 行的端口替换为中继端口，
/// 并强制启用 SRTP（RTP/SAVP）+ 注入服务器侧 crypto 密钥。
/// 服务器作为 SRTP B2BUA，每侧使用独立密钥，中继负责解密→重加密。
pub fn rewrite_sdp(
    sdp: &str,
    relay_addr: &str,
    relay_port: u16,
    crypto_key_b64: &str,
) -> String {
    let mut result = Vec::new();
    let mut found_media = false;
    let mut crypto_inserted = false;

    for line in sdp.lines() {
        if line.starts_with("c=") {
            // 替换连接信息为服务器中继地址
            result.push(format!("c=IN IP4 {}", relay_addr));
        } else if line.starts_with("m=audio") {
            // 替换媒体端口
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                // m=audio <port> <proto> <formats...>
                let proto = if parts[2].contains("SAVP") {
                    parts[2].to_string()
                } else {
                    // 将 RTP/AVP 替换为 RTP/SAVP 以启用 SRTP
                    parts[2].replace("AVP", "SAVP")
                };
                let formats: Vec<&str> = parts[3..].to_vec();
                result.push(format!(
                    "m=audio {} {} {}",
                    relay_port,
                    proto,
                    formats.join(" ")
                ));
                found_media = true;
            } else {
                result.push(line.to_string());
            }
        } else {
            // 在 m= 行之后，替换或注入 crypto
            if found_media && !crypto_inserted && !line.starts_with("m=") {
                if line.starts_with("a=crypto") {
                    // 替换现有的 crypto 行
                    result.push(format!(
                        "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{}",
                        crypto_key_b64
                    ));
                    crypto_inserted = true;
                    continue;
                }
            }
            result.push(line.to_string());
        }
    }

    // 如果没有插入过 crypto 行，在末尾添加
    if found_media && !crypto_inserted {
        result.push(format!(
            "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{}",
            crypto_key_b64
        ));
    }

    result.join("\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(frame_sip_message(msg), Some(msg.len()));
    }

    #[test]
    fn test_frame_sip_message_with_body() {
        let msg = b"INVITE sip:1001@example.com SIP/2.0\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(frame_sip_message(msg), Some(msg.len()));
    }

    #[test]
    fn test_frame_sip_message_incomplete() {
        let msg = b"INVITE sip:1001@example.com SIP/2.0\r\nContent-Length: 100\r\n\r\nhello";
        assert_eq!(frame_sip_message(msg), None);
    }

    #[test]
    fn test_frame_sip_message_no_headers_end() {
        let msg = b"REGISTER sip:example.com SIP/2.0\r\nContent-Length: 0\r\n";
        assert_eq!(frame_sip_message(msg), None);
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
}
