//!
//! 处理 MESSAGE 请求（分机间即时消息）：
//! 在线转发、离线暂存、注册上线后自动补投。
//!
//! 作为独立服务运行，与 RegistrarService / MediaRelayManager 类似；
//! 与 Router 共享 connection_writers（写入通道映射）。

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

use super::parser;
use super::registrar::RegistrarService;
use super::router::{
    build_outbound_request_with_from, extract_called_extension, registered_contact_uri,
    server_contact_uri,
};

/// 单条 MESSAGE 消息体最大字节数（防滥用，SIP over TCP 可承载更大消息）
const MAX_MESSAGE_BODY_LEN: usize = 4096;
/// 单条 MESSAGE 原始请求总长上限（头部 + 消息体，离线暂存会保存完整请求文本）
const MAX_MESSAGE_REQUEST_LEN: usize = 8192;
/// 单个分机离线消息队列上限（防内存无限增长）
const MAX_OFFLINE_MESSAGES: usize = 100;
/// 全局离线消息总条数上限（防未注册/过期分机累积导致内存失控）
const MAX_TOTAL_OFFLINE_MESSAGES: usize = 10000;
/// 离线消息 TTL（秒）：超过该时长仍未投递的离线消息视为过期，
/// 在后续暂存或补投时直接丢弃并释放其占用的内存，避免长期累积。
const OFFLINE_MSG_TTL_SECS: u64 = 24 * 60 * 60; // 24 小时
/// 发送方速率限制的固定窗口长度（秒）
const SENDER_RATE_WINDOW_SECS: u64 = 60;
/// 发送方在一个窗口内允许暂存的离线消息条数上限
///（60 秒内最多 120 条，即平均 2 条/秒；足以满足正常使用，同时显著拖慢灌队列攻击）
const SENDER_RATE_LIMIT: u32 = 120;
/// 单个发送方同时暂存在全局离线队列中的消息条数上限（发送方配额，
/// 防止单个已认证分机灌满全局队列而让其他用户的离线消息持续被拒）
const SENDER_OFFLINE_QUOTA: usize = 500;

/// 离线即时消息（分机离线时暂存，注册上线后自动补投）
#[derive(Debug, Clone)]
pub struct OfflineMessage {
    /// 发送方分机号
    pub from_ext: String,
    /// 原始 MESSAGE 请求文本（补投时重建转发）
    pub original_request: String,
    /// 接收时间（Unix 时间戳，秒）
    pub received_at: u64,
}

/// 发送方离线暂存的固定窗口计数（用于速率限制）
#[derive(Debug, Clone, Copy)]
struct SenderRateWindow {
    window_start: u64,
    count: u32,
}

/// 离线消息暂存的结果（用于区分不同拒绝原因，便于日志与测试）
#[derive(Debug, PartialEq, Eq)]
enum StoreOutcome {
    /// 已成功暂存
    Stored,
    /// 发送方速率超限
    RateLimited,
    /// 发送方配额已满
    QuotaExceeded,
    /// 全局离线容量已满
    CapacityFull,
}

/// 从离线消息表中清除所有已过期消息，并移除清空的队列。
/// 返回被清除的消息条数。
fn prune_expired(map: &mut HashMap<String, VecDeque<OfflineMessage>>, now: u64) -> usize {
    let mut removed = 0usize;
    map.retain(|_ext, queue| {
        let before = queue.len();
        queue.retain(|m| now < m.received_at.saturating_add(OFFLINE_MSG_TTL_SECS));
        removed += before - queue.len();
        !queue.is_empty()
    });
    removed
}

/// 把本次未送达的消息 `pending` 与新到达的现有消息合并写回队列，
/// 保持“旧消息在前、新消息在后”的全局顺序，并在超出单队列上限时
/// 从头（最旧）裁剪，避免误删并发新到达的消息。
fn merge_back(queue: &mut VecDeque<OfflineMessage>, pending: VecDeque<OfflineMessage>) {
    let existing = std::mem::take(queue);
    let mut combined = pending;
    combined.extend(existing);
    while combined.len() > MAX_OFFLINE_MESSAGES {
        combined.pop_front();
    }
    *queue = combined;
}

/// 即时消息服务
///
/// 管理分机间 MESSAGE 的在线转发与离线暂存/补投。
pub struct MessageService {
    /// 注册服务引用
    registrar: Arc<RegistrarService>,
    /// 服务器域名
    domain: String,
    /// 连接映射：分机号 -> 写入通道（与 Router 共享，由 server 模块更新）
    connection_writers: Arc<RwLock<HashMap<String, mpsc::Sender<Vec<u8>>>>>,
    /// 分机号码范围（校验 MESSAGE 目标合法性）
    range_start: u32,
    range_end: u32,
    /// 离线即时消息：被叫分机 -> 待投递消息队列（内存存储，重启即清空）
    offline_messages: RwLock<HashMap<String, VecDeque<OfflineMessage>>>,
    /// 发送方离线暂存速率状态（固定窗口计数）：分机号 -> 窗口计数
    sender_rates: RwLock<HashMap<String, SenderRateWindow>>,
}

impl MessageService {
    /// 创建新的即时消息服务
    pub fn new(
        registrar: Arc<RegistrarService>,
        domain: String,
        connection_writers: Arc<RwLock<HashMap<String, mpsc::Sender<Vec<u8>>>>>,
        range_start: u32,
        range_end: u32,
    ) -> Self {
        Self {
            registrar,
            domain,
            connection_writers,
            range_start,
            range_end,
            offline_messages: RwLock::new(HashMap::new()),
            sender_rates: RwLock::new(HashMap::new()),
        }
    }

    /// 获取分机的写入通道
    fn get_writer(&self, extension: &str) -> Option<mpsc::Sender<Vec<u8>>> {
        if !self.registrar.is_registered(extension) {
            return None;
        }
        let writers = self
            .connection_writers
            .read()
            .expect("connection_writers 锁中毒");
        writers.get(extension).cloned()
    }

    /// 检查分机号是否在有效号码范围内
    fn is_valid_extension(&self, extension: &str) -> bool {
        match extension.parse::<u32>() {
            Ok(num) => {
                num.to_string() == extension && num >= self.range_start && num <= self.range_end
            }
            Err(_) => false,
        }
    }

    /// 处理 MESSAGE 请求（分机间即时消息）
    ///
    /// 流程：
    /// 1. 校验主叫（来自连接认证的分机号）、被叫、消息体
    /// 2. 被叫在线：B2BUA 重写后直接转发，返回 200 OK
    /// 3. 被叫离线：暂存到内存队列，注册上线后自动补投，返回 200 OK
    ///
    /// 说明：离线暂存同样返回 200 OK 而非 202 Accepted——部分软电话（如基于 PJSIP 的
    /// MicroSIP）对 MESSAGE 的 202 响应处理不完善，会导致后续消息发送异常；
    /// 200 OK 表示服务端已接收并负责稍后投递，语义同样成立且兼容性最好。
    pub async fn handle_message(&self, request_text: &str, from_ext: &str) -> Vec<u8> {
        // 主叫必须是已注册并绑定到当前连接的分机（由 server 层传入，不信任 From 头）
        if from_ext.is_empty() {
            tracing::warn!("拒绝未认证连接的 MESSAGE");
            return parser::build_response(request_text, 403, "Forbidden");
        }

        // 原始请求总长限制（离线暂存会保存完整请求文本，防止超大头部撑爆内存）
        if request_text.len() > MAX_MESSAGE_REQUEST_LEN {
            tracing::warn!(
                "拒绝超长 MESSAGE 请求 ({} 字节 > {}): {}",
                request_text.len(),
                MAX_MESSAGE_REQUEST_LEN,
                from_ext
            );
            return parser::build_response(request_text, 413, "Message Too Large");
        }

        // 被叫分机号（Request-URI 优先，To 头兜底）
        let callee_ext = extract_called_extension(request_text).unwrap_or_default();
        if callee_ext.is_empty() || callee_ext == from_ext {
            tracing::warn!("拒绝无效 MESSAGE 目标: callee={:?}", callee_ext);
            return parser::build_response(request_text, 400, "Bad Request");
        }
        if !self.is_valid_extension(&callee_ext) {
            tracing::warn!("拒绝向不存在的分机 {} 发送 MESSAGE", callee_ext);
            return parser::build_response(request_text, 404, "Not Found");
        }

        // 消息体检查：非空且不超过大小上限
        let body = parser::extract_body(request_text).unwrap_or_default();
        if body.trim().is_empty() {
            tracing::warn!("拒绝空消息体 MESSAGE: {} -> {}", from_ext, callee_ext);
            return parser::build_response(request_text, 400, "Bad Request");
        }
        if body.len() > MAX_MESSAGE_BODY_LEN {
            tracing::warn!(
                "拒绝超长 MESSAGE ({} 字节 > {}): {} -> {}",
                body.len(),
                MAX_MESSAGE_BODY_LEN,
                from_ext,
                callee_ext
            );
            return parser::build_response(request_text, 413, "Message Too Large");
        }

        tracing::info!(
            "收到 MESSAGE: {} -> {} ({} 字节)",
            from_ext,
            callee_ext,
            body.len()
        );

        // 被叫在线：直接转发
        if let Some(writer) = self.get_writer(&callee_ext) {
            let target_uri = registered_contact_uri(&callee_ext, &self.domain, &self.registrar);
            // 重写 From 为认证主叫（防止伪造 From 冒名），Contact 指向本服务
            let forwarded = build_outbound_request_with_from(
                request_text,
                &target_uri,
                &self.domain,
                &server_contact_uri(from_ext, &self.domain),
                &server_contact_uri(from_ext, &self.domain),
            );
            match writer.try_send(forwarded.into_bytes()) {
                Ok(_) => {
                    tracing::info!("MESSAGE 已投递给在线分机 {}", callee_ext);
                    return parser::build_response(request_text, 200, "OK");
                }
                Err(e) => {
                    tracing::error!("推送 MESSAGE 到 {} 失败: {}", callee_ext, e);
                    // 推送失败视为离线，转入暂存
                }
            }
        }

        // 被叫离线：暂存，等待注册后补投。
        // 只要分机号在配置的 range_start/range_end 范围内即视为合法（离线消息本就是
        // 发给未登录分机的，不要求其当前已注册）；内存防护由 TTL、发送方速率/配额、
        // 请求总长与全局条数上限共同兜底。
        match self.store_offline_message(&callee_ext, from_ext, request_text) {
            StoreOutcome::Stored => {
                // 回 200 OK：服务端已接收并负责稍后补投（202 Accepted 会令部分客户端异常）
                parser::build_response(request_text, 200, "OK")
            }
            _ => {
                // 速率/配额/全局容量任一超限，明确告知客户端未接收
                parser::build_response(request_text, 503, "Service Unavailable")
            }
        }
    }

    /// 暂存离线即时消息
    ///
    /// 返回暂存结果（速率超限、发送方配额满或全局容量满时返回对应拒绝原因）。
    fn store_offline_message(
        &self,
        callee_ext: &str,
        from_ext: &str,
        request_text: &str,
    ) -> StoreOutcome {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // 1) 发送方速率限制（固定窗口：每 SENDER_RATE_WINDOW_SECS 最多 SENDER_RATE_LIMIT 条，
        //    防止单个已认证分机快速灌入离线队列）
        {
            let mut rates = self.sender_rates.write().expect("sender_rates 锁中毒");
            rates.retain(|_, window| {
                now < window.window_start.saturating_add(SENDER_RATE_WINDOW_SECS)
            });
            if !rates.contains_key(from_ext) && rates.len() >= 4096 {
                return StoreOutcome::RateLimited;
            }
            let win = rates
                .entry(from_ext.to_string())
                .or_insert(SenderRateWindow {
                    window_start: now,
                    count: 0,
                });
            if now >= win.window_start + SENDER_RATE_WINDOW_SECS {
                *win = SenderRateWindow {
                    window_start: now,
                    count: 0,
                };
            }
            if win.count >= SENDER_RATE_LIMIT {
                tracing::warn!(
                    "发送方 {} 离线暂存速率超限（{} 秒内已达 {} 条），拒绝新消息",
                    from_ext,
                    SENDER_RATE_WINDOW_SECS,
                    SENDER_RATE_LIMIT
                );
                return StoreOutcome::RateLimited;
            }
            win.count += 1;
        }

        let mut map = self
            .offline_messages
            .write()
            .expect("offline_messages 锁中毒");

        // 2) 惰性清理过期消息，释放容量（TTL 兜底，避免积压的旧消息长期占用内存）
        let expired = prune_expired(&mut map, now);
        if expired > 0 {
            tracing::info!("离线暂存前清理 {} 条过期消息", expired);
        }

        // 3) 发送方配额：同一发送方同时在离线队列中的消息数上限
        let sender_total = map
            .values()
            .flat_map(VecDeque::iter)
            .filter(|m| m.from_ext == from_ext)
            .count();
        if sender_total >= SENDER_OFFLINE_QUOTA {
            tracing::warn!(
                "发送方 {} 离线暂存配额已满（{} 条），拒绝新消息",
                from_ext,
                SENDER_OFFLINE_QUOTA
            );
            return StoreOutcome::QuotaExceeded;
        }

        // 4) 全局离线消息总条数上限（号码范围内任意分机都可暂存离线消息，
        //    需要全局兜底防止恶意灌入导致内存失控）
        let total: usize = map.values().map(VecDeque::len).sum();
        if total >= MAX_TOTAL_OFFLINE_MESSAGES {
            tracing::warn!(
                "全局离线消息已达上限 ({} 条)，丢弃来自 {} 的消息",
                MAX_TOTAL_OFFLINE_MESSAGES,
                from_ext
            );
            return StoreOutcome::CapacityFull;
        }

        let queue = map
            .entry(callee_ext.to_string())
            .or_insert_with(VecDeque::new);

        if queue.len() >= MAX_OFFLINE_MESSAGES {
            tracing::warn!(
                "分机 {} 离线消息队列已满 ({} 条)，丢弃最旧消息",
                callee_ext,
                MAX_OFFLINE_MESSAGES
            );
            queue.pop_front();
        }

        queue.push_back(OfflineMessage {
            from_ext: from_ext.to_string(),
            original_request: request_text.to_string(),
            received_at: now,
        });
        tracing::info!(
            "分机 {} 离线，已暂存来自 {} 的 MESSAGE (队列 {} 条)",
            callee_ext,
            from_ext,
            queue.len()
        );
        StoreOutcome::Stored
    }

    /// 补投分机的离线即时消息（注册上线后由 server 层调用）
    ///
    /// 取出队列并逐条重建转发；已过期的消息在投递前被丢弃（TTL）；若推送中途失败，
    /// 将未送达消息与并发新到达消息合并写回队列（保持旧→新顺序），等待下次投递。
    pub async fn deliver_offline_messages(&self, extension: &str) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Keep queued messages accounted for until delivery succeeds. Nonblocking sends
        // prevent stalled clients and repeated REGISTERs from spawning unbounded work.
        let mut map = self.offline_messages.write().unwrap();
        prune_expired(&mut map, now);
        let Some(queue) = map.get_mut(extension) else {
            return;
        };
        let target_uri = registered_contact_uri(extension, &self.domain, &self.registrar);
        while let Some(msg) = queue.front() {
            let Some(writer) = self.get_writer(extension) else {
                break;
            };
            let forwarded = build_outbound_request_with_from(
                &msg.original_request,
                &target_uri,
                &self.domain,
                &server_contact_uri(&msg.from_ext, &self.domain),
                &server_contact_uri(&msg.from_ext, &self.domain),
            );
            if writer.try_send(forwarded.into_bytes()).is_err() {
                break;
            }
            queue.pop_front();
        }
        if queue.is_empty() {
            map.remove(extension);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 创建测试服务：返回服务实例与共享的写入通道映射
    fn test_service() -> (
        Arc<MessageService>,
        Arc<RwLock<HashMap<String, mpsc::Sender<Vec<u8>>>>>,
    ) {
        let registrar = Arc::new(RegistrarService::new(
            "example.com".to_string(),
            "pw".to_string(),
            HashMap::new(),
            1000,
            2000,
        ));
        registrar.register(super::super::registrar::Registration {
            extension: "1002".into(),
            contact: "sip:1002@example.com".into(),
            expires_at: u64::MAX,
            transport_addr: "127.0.0.1:5061".parse().unwrap(),
        });
        let writers = Arc::new(RwLock::new(HashMap::new()));
        let svc = Arc::new(MessageService::new(
            registrar,
            "example.com".to_string(),
            Arc::clone(&writers),
            1000,
            2000,
        ));
        (svc, writers)
    }

    fn build_message(from: &str, to: &str, body: &str) -> String {
        format!(
            "MESSAGE sip:{}@example.com SIP/2.0\r\n\
             Via: SIP/2.0/TLS client.example.com;branch=z9hG4bKtest\r\n\
             From: <sip:{}@example.com>;tag=caller-tag\r\n\
             To: <sip:{}@example.com>\r\n\
             Call-ID: msg-1\r\n\
             CSeq: 1 MESSAGE\r\n\
             Content-Type: text/plain\r\n\
             Content-Length: {}\r\n\r\n{}",
            to,
            from,
            to,
            body.len(),
            body
        )
    }

    #[tokio::test]
    async fn message_rejects_unauthenticated_connection() {
        let (svc, _) = test_service();
        let msg = build_message("1001", "1002", "hi");
        let resp = svc.handle_message(&msg, "").await;
        assert!(String::from_utf8(resp)
            .unwrap()
            .starts_with("SIP/2.0 403 Forbidden"));
        assert!(svc.offline_messages.read().unwrap().is_empty());
    }

    #[tokio::test]
    async fn message_rejects_unknown_callee() {
        let (svc, _) = test_service();
        let msg = build_message("1001", "9999", "hi");
        let resp = svc.handle_message(&msg, "1001").await;
        assert!(String::from_utf8(resp)
            .unwrap()
            .starts_with("SIP/2.0 404 Not Found"));
    }

    #[tokio::test]
    async fn message_rejects_self_delivery() {
        let (svc, _) = test_service();
        let msg = build_message("1001", "1001", "hi");
        let resp = svc.handle_message(&msg, "1001").await;
        assert!(String::from_utf8(resp)
            .unwrap()
            .starts_with("SIP/2.0 400 Bad Request"));
    }

    #[tokio::test]
    async fn message_rejects_empty_body() {
        let (svc, _) = test_service();
        let msg = build_message("1001", "1002", "   ");
        let resp = svc.handle_message(&msg, "1001").await;
        assert!(String::from_utf8(resp)
            .unwrap()
            .starts_with("SIP/2.0 400 Bad Request"));
        assert!(svc.offline_messages.read().unwrap().is_empty());
    }

    #[tokio::test]
    async fn message_rejects_oversized_body() {
        let (svc, _) = test_service();
        let big = "x".repeat(MAX_MESSAGE_BODY_LEN + 1);
        let msg = build_message("1001", "1002", &big);
        let resp = svc.handle_message(&msg, "1001").await;
        assert!(String::from_utf8(resp)
            .unwrap()
            .starts_with("SIP/2.0 413 Message Too Large"));
        assert!(svc.offline_messages.read().unwrap().is_empty());
    }

    #[tokio::test]
    async fn message_forwards_to_online_callee() {
        let (svc, writers) = test_service();
        let (tx, mut rx) = mpsc::channel(8);
        writers.write().unwrap().insert("1002".to_string(), tx);

        let msg = build_message("1001", "1002", "hello online");
        let resp = svc.handle_message(&msg, "1001").await;
        assert!(String::from_utf8(resp)
            .unwrap()
            .starts_with("SIP/2.0 200 OK"));

        let forwarded = rx.try_recv().expect("在线被叫应直接收到消息");
        let fwd = String::from_utf8(forwarded).unwrap();
        assert!(fwd.starts_with("MESSAGE sip:1002@example.com"));
        assert!(fwd.contains("hello online"));
        assert!(fwd.contains("sip:1001@example.com"));
        // From 头重写为认证主叫（保留原 tag），Contact 指向服务
        assert!(fwd.contains("From: <sip:1001@example.com;transport=tls>;tag=caller-tag"));
        assert!(fwd.contains("Contact: <sip:1001@example.com;transport=tls>"));
        // 直接投递不应落入离线队列
        assert!(svc.offline_messages.read().unwrap().is_empty());
    }

    #[tokio::test]
    async fn message_rewrites_forged_from_header() {
        let (svc, writers) = test_service();
        let (tx, mut rx) = mpsc::channel(8);
        writers.write().unwrap().insert("1002".to_string(), tx);

        // 伪造 From 为 1999，认证主叫是 1001：转发时 From 必须被重写为 1001
        let forged = format!(
            "MESSAGE sip:1002@example.com SIP/2.0\r\n\
             Via: SIP/2.0/TLS client.example.com;branch=z9hG4bKtest\r\n\
             From: <sip:1999@example.com>;tag=caller-tag\r\n\
             To: <sip:1002@example.com>\r\n\
             Call-ID: msg-1\r\n\
             CSeq: 1 MESSAGE\r\n\
             Content-Type: text/plain\r\n\
             Content-Length: 5\r\n\r\nforged"
        );
        let resp = svc.handle_message(&forged, "1001").await;
        assert!(String::from_utf8(resp)
            .unwrap()
            .starts_with("SIP/2.0 200 OK"));

        let forwarded = rx.try_recv().expect("在线被叫应直接收到消息");
        let fwd = String::from_utf8(forwarded).unwrap();
        assert!(fwd.contains("From: <sip:1001@example.com;transport=tls>;tag=caller-tag"));
        assert!(
            !fwd.contains("sip:1999@example.com"),
            "伪造的 From 不应出现在转发中: {}",
            fwd
        );
    }

    #[tokio::test]
    async fn message_accepts_unregistered_callee() {
        let (svc, _) = test_service();
        // 1003 在号码范围内但从未注册：离线消息仍应暂存（离线本就是发给未登录分机的），
        // 待其上线后补投；内存防护由请求总长与全局条数上限兜底
        let msg = build_message("1001", "1003", "hi");
        let resp = svc.handle_message(&msg, "1001").await;
        assert!(String::from_utf8(resp)
            .unwrap()
            .starts_with("SIP/2.0 200 OK"));
        let map = svc.offline_messages.read().unwrap();
        let queue = map.get("1003").expect("范围内未注册分机也应暂存离线消息");
        assert_eq!(queue.len(), 1);
    }

    #[tokio::test]
    async fn message_rejects_oversized_request() {
        let (svc, _) = test_service();
        // body 合法但头部超长（离线暂存保存完整请求文本，需限制总长）
        let body = "hi";
        let msg = format!(
            "MESSAGE sip:1002@example.com SIP/2.0\r\n\
             Via: SIP/2.0/TLS client.example.com;branch=z9hG4bKbig\r\n\
             From: <sip:1001@example.com>;tag=big-tag\r\n\
             To: <sip:1002@example.com>\r\n\
             Call-ID: msg-big\r\n\
             CSeq: 1 MESSAGE\r\n\
             Content-Type: text/plain\r\n\
             X-Padding: {}\r\n\
             Content-Length: {}\r\n\r\n{}",
            "p".repeat(MAX_MESSAGE_REQUEST_LEN),
            body.len(),
            body
        );
        let resp = svc.handle_message(&msg, "1001").await;
        assert!(String::from_utf8(resp)
            .unwrap()
            .starts_with("SIP/2.0 413 Message Too Large"));
        assert!(svc.offline_messages.read().unwrap().is_empty());
    }

    #[tokio::test]
    async fn offline_global_cap_rejects_when_full() {
        let (svc, _) = test_service();
        // 预填消息用近期时间戳（避免被 TTL 清理），发送方用其他分机（避免触发发送方配额），
        // 从而专门验证“全局容量满”这一层兜底。
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // 直接填充到全局上限：100 个分机 × 100 条（号码都在范围内）
        {
            let mut map = svc.offline_messages.write().unwrap();
            for i in 0..100 {
                let ext = format!("{}", 1000 + i);
                let queue: VecDeque<OfflineMessage> = (0..100)
                    .map(|j| OfflineMessage {
                        from_ext: "9999".to_string(),
                        original_request: format!("MESSAGE dummy {}", j),
                        received_at: now,
                    })
                    .collect();
                map.insert(ext, queue);
            }
        }

        let msg = build_message("1001", "1002", "should be dropped");
        let resp = svc.handle_message(&msg, "1001").await;
        assert!(String::from_utf8(resp)
            .unwrap()
            .starts_with("SIP/2.0 503 Service Unavailable"));
        // 1002 队列未被新增（仍为预填的 100 条）
        let map = svc.offline_messages.read().unwrap();
        assert_eq!(map.get("1002").map(|q| q.len()).unwrap_or(0), 100);
    }

    #[tokio::test]
    async fn message_stored_offline_then_delivered_on_register() {
        let (svc, writers) = test_service();
        let msg = build_message("1001", "1002", "hello offline");
        let resp = svc.handle_message(&msg, "1001").await;
        assert!(String::from_utf8(resp)
            .unwrap()
            .starts_with("SIP/2.0 200 OK"));

        // 离线队列中应有一条
        {
            let map = svc.offline_messages.read().unwrap();
            let queue = map.get("1002").expect("离线消息应暂存到 1002 队列");
            assert_eq!(queue.len(), 1);
            assert_eq!(queue[0].from_ext, "1001");
        }

        // 模拟 1002 注册上线
        let (tx, mut rx) = mpsc::channel(8);
        writers.write().unwrap().insert("1002".to_string(), tx);
        svc.deliver_offline_messages("1002").await;

        let delivered = rx.try_recv().expect("上线后应收到补投消息");
        let text = String::from_utf8(delivered).unwrap();
        assert!(text.starts_with("MESSAGE sip:1002@"));
        assert!(text.contains("hello offline"));
        assert!(text.contains("sip:1001@example.com"));
        // 补投时 From 重写为原始发送方（保留原 tag）
        assert!(text.contains("From: <sip:1001@example.com;transport=tls>;tag=caller-tag"));
        // 投递后队列清空
        assert!(svc.offline_messages.read().unwrap().is_empty());
    }

    #[tokio::test]
    async fn offline_message_kept_when_delivery_send_fails() {
        let (svc, writers) = test_service();
        let msg = build_message("1001", "1002", "keep on failure");
        svc.handle_message(&msg, "1001").await;

        // 写入通道接收端已关闭：send 必然失败
        let (tx, rx) = mpsc::channel::<Vec<u8>>(8);
        drop(rx);
        writers.write().unwrap().insert("1002".to_string(), tx);
        svc.deliver_offline_messages("1002").await;

        // 未送达的消息应写回队列，等待下次投递，而不是丢失
        let map = svc.offline_messages.read().unwrap();
        let queue = map.get("1002").expect("发送失败的消息应保留在队列");
        assert_eq!(queue.len(), 1);
        assert!(queue[0].original_request.contains("keep on failure"));
    }

    #[tokio::test]
    async fn offline_message_kept_when_callee_has_no_writer() {
        let (svc, _) = test_service();
        let msg = build_message("1001", "1002", "keep me");
        svc.handle_message(&msg, "1001").await;

        // 未注册 writer 时调用补投：消息应保留
        svc.deliver_offline_messages("1002").await;
        let map = svc.offline_messages.read().unwrap();
        let queue = map.get("1002").expect("消息应保留在队列");
        assert_eq!(queue.len(), 1);
    }

    #[tokio::test]
    async fn offline_queue_caps_at_limit() {
        let (svc, _) = test_service();
        for i in 0..MAX_OFFLINE_MESSAGES + 10 {
            let msg = build_message("1001", "1002", &format!("msg {}", i));
            svc.handle_message(&msg, "1001").await;
        }
        let map = svc.offline_messages.read().unwrap();
        let queue = map.get("1002").unwrap();
        assert_eq!(queue.len(), MAX_OFFLINE_MESSAGES);
        // 最旧的被丢弃，最新保留
        assert!(queue.back().unwrap().original_request.contains("msg 109"));
        assert!(!queue.front().unwrap().original_request.contains("msg 0"));
    }

    /// 构造一条测试用的离线消息（TTL 判断不依赖 received_at，可传任意值）
    fn om(from: &str, body: &str, received_at: u64) -> OfflineMessage {
        OfflineMessage {
            from_ext: from.to_string(),
            original_request: body.to_string(),
            received_at,
        }
    }

    #[test]
    fn merge_back_keeps_old_before_new() {
        // 队列中已存在并发新到达消息 newX，写回 pending 旧消息 oldA/oldB 时，
        // 顺序必须保持“旧在前、新在后”
        let pending: VecDeque<OfflineMessage> =
            vec![om("1001", "oldA", 5), om("1001", "oldB", 6)].into();
        let mut queue: VecDeque<OfflineMessage> = vec![om("1002", "newX", 7)].into();
        merge_back(&mut queue, pending);
        let names: Vec<&str> = queue.iter().map(|m| m.original_request.as_str()).collect();
        assert_eq!(names, vec!["oldA", "oldB", "newX"]);
    }

    #[test]
    fn merge_back_trims_oldest_not_fresh() {
        // 超出单队列上限时从头（最旧）裁剪，绝不能删掉并发新到达的消息
        let pending: VecDeque<OfflineMessage> = (0..95)
            .map(|i| om("1001", &format!("old{}", i), i as u64))
            .collect();
        let mut queue: VecDeque<OfflineMessage> = (0..6)
            .map(|i| om("1002", &format!("new{}", i), 100 + i as u64))
            .collect();
        merge_back(&mut queue, pending);
        assert_eq!(queue.len(), MAX_OFFLINE_MESSAGES);
        // 最旧的 old0 被裁掉，其余 old 与全部 new 保留，且顺序为 old 在前、new 在后
        assert!(!queue.iter().any(|m| m.original_request == "old0"));
        assert!(queue.iter().any(|m| m.original_request == "new0"));
        assert!(queue.iter().any(|m| m.original_request == "new5"));
        assert_eq!(queue.front().unwrap().original_request, "old1");
        assert_eq!(queue.back().unwrap().original_request, "new5");
    }

    #[tokio::test]
    async fn offline_expired_pruned_and_not_delivered() {
        let (svc, writers) = test_service();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // 往 1002 队列塞一条过期、一条未过期的消息
        {
            let mut map = svc.offline_messages.write().unwrap();
            let queue: VecDeque<OfflineMessage> = vec![
                om("1001", "fresh", now),
                om("1001", "stale", now - OFFLINE_MSG_TTL_SECS - 10),
            ]
            .into();
            map.insert("1002".to_string(), queue);
        }

        let (tx, mut rx) = mpsc::channel(8);
        writers.write().unwrap().insert("1002".to_string(), tx);
        svc.deliver_offline_messages("1002").await;

        // 只有未过期的 fresh 被投递，过期 stale 被丢弃
        let delivered = rx.try_recv().expect("应投递未过期的消息");
        assert!(String::from_utf8(delivered).unwrap().contains("fresh"));
        assert!(rx.try_recv().is_err(), "过期消息不应被投递");
        assert!(svc.offline_messages.read().unwrap().is_empty());
    }

    #[tokio::test]
    async fn offline_sender_rate_limit_returns_503() {
        let (svc, _) = test_service();
        // 第 SENDER_RATE_LIMIT 条仍应成功，第 SENDER_RATE_LIMIT+1 条触发速率限制返回 503
        for _ in 0..SENDER_RATE_LIMIT {
            let msg = build_message("1001", "1002", "fast");
            let resp = svc.handle_message(&msg, "1001").await;
            assert!(String::from_utf8(resp)
                .unwrap()
                .starts_with("SIP/2.0 200 OK"));
        }
        let msg = build_message("1001", "1002", "too fast");
        let resp = svc.handle_message(&msg, "1001").await;
        assert!(String::from_utf8(resp)
            .unwrap()
            .starts_with("SIP/2.0 503 Service Unavailable"));
    }

    #[tokio::test]
    async fn offline_sender_quota_exceeded_returns_503() {
        let (svc, _) = test_service();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // 预填正好达到单发送方配额上限的、来自 1001 的离线消息（暂存到 1006）
        {
            let mut map = svc.offline_messages.write().unwrap();
            let queue: VecDeque<OfflineMessage> = (0..SENDER_OFFLINE_QUOTA)
                .map(|i| om("1001", &format!("quota {}", i), now))
                .collect();
            map.insert("1006".to_string(), queue);
        }
        // 1001 已满配额：新离线消息被拒绝
        let msg = build_message("1001", "1002", "over quota");
        let resp = svc.handle_message(&msg, "1001").await;
        assert!(String::from_utf8(resp)
            .unwrap()
            .starts_with("SIP/2.0 503 Service Unavailable"));
        // 1002 没有被写入
        assert!(!svc.offline_messages.read().unwrap().contains_key("1002"));
    }

    #[tokio::test]
    async fn offline_expired_frees_capacity_on_store() {
        let (svc, _) = test_service();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        {
            let mut map = svc.offline_messages.write().unwrap();
            // 大量过期消息占据全局容量
            let queue: VecDeque<OfflineMessage> = (0..100)
                .map(|i| {
                    om(
                        "9999",
                        &format!("stale {}", i),
                        now - OFFLINE_MSG_TTL_SECS - 1,
                    )
                })
                .collect();
            map.insert("1003".to_string(), queue);
        }
        // 新离线暂存时触发惰性清理，过期消息被清除、容量被释放
        let msg = build_message("1004", "1005", "new after cleanup");
        let resp = svc.handle_message(&msg, "1004").await;
        assert!(String::from_utf8(resp)
            .unwrap()
            .starts_with("SIP/2.0 200 OK"));
        let map = svc.offline_messages.read().unwrap();
        assert!(!map.contains_key("1003"), "过期分机的队列应被清理移除");
        assert_eq!(map.get("1005").map(|q| q.len()).unwrap_or(0), 1);
    }
}
