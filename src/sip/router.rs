//! 呼叫路由模块
//!
//! 处理 INVITE、ACK、BYE、CANCEL 等呼叫相关的 SIP 请求。
//! 作为 B2BUA（Back-to-Back User Agent）工作，管理呼叫信令与会话归属，默认原样转发签名 SDP；显式 [media] 模式委托给 Bria 兼容中继。

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;

use super::e2ee::{validate_identity, validate_sdp, SdpRole};
use super::message::MessageService;
use super::parser;
use super::registrar::RegistrarService;

/// 呼叫状态
#[derive(Debug, Clone, PartialEq)]
pub enum CallState {
    /// 正在尝试建立
    Trying,
    /// 被叫振铃中
    Ringing,
    /// 通话已建立
    Established,
    /// 通话已终止
    Terminated,
}

/// 呼叫信息
#[derive(Debug)]
pub struct CallInfo {
    /// Call-ID
    pub call_id: String,
    created_at: std::time::Instant,
    /// 主叫分机号
    pub caller_ext: String,
    /// 被叫分机号
    pub callee_ext: String,
    /// 主叫 From tag
    pub caller_tag: String,
    /// 被叫 To tag
    pub callee_tag: Option<String>,
    /// 主叫侧远端 Contact（主叫对话的 remote target）
    pub caller_remote_contact: Option<String>,
    /// 被叫侧远端 Contact（被叫对话的 remote target）
    pub callee_remote_contact: Option<String>,
    /// 呼叫状态
    pub state: CallState,
    /// 主叫原始 INVITE 消息（用于构建后续响应）
    pub original_invite: String,
    /// Exact outbound INVITE, including its transaction branch for CANCEL.
    callee_invite: String,
    /// 主叫侧写入通道
    pub caller_writer: mpsc::Sender<Vec<u8>>,
    /// 被叫侧写入通道
    pub callee_writer: Option<mpsc::Sender<Vec<u8>>>,
}

/// 呼叫路由器
///
/// 管理所有活跃呼叫，处理呼叫建立、转发和拆除。
pub struct Router {
    /// 活跃呼叫 (Call-ID -> CallInfo)
    active_calls: RwLock<HashMap<String, CallInfo>>,
    sdes: Option<super::sdes_router::SdesRouter>,
    /// 注册服务引用
    registrar: Arc<RegistrarService>,
    /// 服务器域名
    domain: String,
    /// 连接映射：分机号 -> 写入通道（由 server 模块更新，与 MessageService 共享）
    connection_writers: Arc<RwLock<HashMap<String, mpsc::Sender<Vec<u8>>>>>,
    /// 即时消息服务（MESSAGE 在线转发与离线暂存/补投）
    message_service: MessageService,
}

impl Router {
    /// 创建新的路由器
    pub fn new(
        registrar: Arc<RegistrarService>,
        domain: String,
        range_start: u32,
        range_end: u32,
    ) -> Self {
        // 写入通道映射由 Router 与 MessageService 共享
        let connection_writers = Arc::new(RwLock::new(HashMap::new()));
        let message_service = MessageService::new(
            Arc::clone(&registrar),
            domain.clone(),
            Arc::clone(&connection_writers),
            range_start,
            range_end,
        );
        Self {
            active_calls: RwLock::new(HashMap::new()),
            sdes: None,
            registrar,
            domain,
            connection_writers,
            message_service,
        }
    }

    /// Explicit compatibility profile: TLS signaling and server-terminated SRTP.
    pub fn with_media(
        mut self,
        media: &crate::config::MediaConfig,
        range_start: u32,
        range_end: u32,
    ) -> Self {
        let manager = Arc::new(crate::media::relay::MediaRelayManager::new(
            media.rtp_port_start,
            media.rtp_port_end,
            media.media_addr.clone(),
        ));
        self.sdes = Some(super::sdes_router::SdesRouter::new(
            self.registrar.clone(),
            manager,
            self.domain.clone(),
            media.media_addr.clone(),
            range_start,
            range_end,
        ));
        self
    }

    /// Bind dialog actions to the exact TLS channel that established the call.
    pub fn authorizes_dialog(
        &self,
        text: &str,
        writer: &mpsc::Sender<Vec<u8>>,
        method: &str,
    ) -> bool {
        if let Some(router) = &self.sdes {
            return router.authorizes_dialog(text, writer, method);
        }

        let Some(id) = parser::extract_call_id(text) else {
            return false;
        };
        let calls = self.active_calls.read().unwrap();
        let Some(call) = calls.get(&id) else {
            return false;
        };
        let caller = call.caller_writer.same_channel(writer);
        let callee = call
            .callee_writer
            .as_ref()
            .is_some_and(|w| w.same_channel(writer));
        match method {
            "RESPONSE" => {
                callee
                    && parser::extract_header_value(text, "CSeq")
                        == parser::extract_header_value(&call.original_invite, "CSeq")
            }
            "ACK" => caller,
            "CANCEL" => caller && call.state != CallState::Established,
            "BYE" => caller || callee,
            _ => false,
        }
    }

    pub fn cleanup_disconnected(&self, writer: &mpsc::Sender<Vec<u8>>) {
        if let Some(router) = &self.sdes {
            router.cleanup_disconnected(writer);
            return;
        }

        let ids: Vec<_> = self
            .active_calls
            .read()
            .unwrap()
            .values()
            .filter(|c| {
                c.caller_writer.same_channel(writer)
                    || c.callee_writer
                        .as_ref()
                        .is_some_and(|w| w.same_channel(writer))
            })
            .map(|c| c.call_id.clone())
            .collect();
        for id in ids {
            self.cleanup_call(&id);
        }
    }

    pub fn cleanup_expired_calls(&self) {
        if let Some(router) = &self.sdes {
            router.cleanup_expired_calls();
            return;
        }

        let ids: Vec<_> = self
            .active_calls
            .read()
            .unwrap()
            .values()
            .filter(|c| {
                c.created_at.elapsed().as_secs()
                    > if c.state == CallState::Established {
                        14400
                    } else {
                        120
                    }
            })
            .map(|c| c.call_id.clone())
            .collect();
        for id in ids {
            self.cleanup_call(&id);
        }
    }

    /// 注册分机的写入通道（由 server 模块在注册成功后调用）
    pub fn register_writer(&self, extension: &str, writer: mpsc::Sender<Vec<u8>>) {
        if let Some(router) = &self.sdes {
            router.register_writer(extension, writer);
            return;
        }

        let mut writers = self.connection_writers.write().unwrap();
        writers.insert(extension.to_string(), writer);
        tracing::debug!("已注册分机 {} 的写入通道", extension);
    }

    /// 注销分机的写入通道
    pub fn unregister_writer(&self, extension: &str) {
        if let Some(router) = &self.sdes {
            router.unregister_writer(extension);
            return;
        }

        let mut writers = self.connection_writers.write().unwrap();
        writers.remove(extension);
        tracing::debug!("已注销分机 {} 的写入通道", extension);
    }

    /// 获取分机的写入通道
    fn get_writer(&self, extension: &str) -> Option<mpsc::Sender<Vec<u8>>> {
        let writers = self.connection_writers.read().unwrap();
        writers.get(extension).cloned()
    }

    /// 处理 MESSAGE 请求（委托给 MessageService，实现在 message 模块）
    pub async fn handle_message(&self, request_text: &str, from_ext: &str) -> Vec<u8> {
        if let Some(router) = &self.sdes {
            return router.handle_message(request_text, from_ext).await;
        }

        self.message_service
            .handle_message(request_text, from_ext)
            .await
    }

    /// 补投分机的离线即时消息（委托给 MessageService，实现在 message 模块）
    pub async fn deliver_offline_messages(&self, extension: &str) {
        if let Some(router) = &self.sdes {
            router.deliver_offline_messages(extension).await;
            return;
        }

        self.message_service
            .deliver_offline_messages(extension)
            .await
    }

    /// 处理 INVITE 请求
    ///
    /// 流程：
    /// 1. 提取被叫号码
    /// 2. 检查被叫是否在线
    /// 3. 校验 DTLS-SRTP offer，拒绝 SDES / 明文
    /// 4. 原样转发客户端 SDP；服务端不持有媒体密钥
    /// 5. 客户端通过 ICE / DTLS 建立媒体连接
    /// 6. 返回 100 Trying 给主叫
    pub async fn handle_invite(
        &self,
        request_text: &str,
        caller_writer: mpsc::Sender<Vec<u8>>,
    ) -> Vec<u8> {
        if let Some(router) = &self.sdes {
            return router.handle_invite(request_text, caller_writer).await;
        }

        // 提取主叫分机号
        let caller_ext = parser::extract_uri_from_header(request_text, "From")
            .and_then(|uri| parser::extract_extension(&uri))
            .unwrap_or_default();

        // 提取被叫分机号。多数客户端放在 Request-URI；部分客户端会把
        // Request-URI 指向服务器本身，把真实被叫放在 To 头里。
        let callee_ext = extract_called_extension(request_text).unwrap_or_default();

        let call_id = parser::extract_call_id(request_text).unwrap_or_default();
        let caller_tag = parser::extract_from_tag(request_text).unwrap_or_default();

        tracing::info!(
            "收到 INVITE: {} -> {} (Call-ID: {})",
            caller_ext,
            callee_ext,
            call_id
        );

        if call_id.is_empty() || caller_tag.is_empty() {
            return parser::build_response(request_text, 400, "Bad Request");
        }
        // Never replace a live call using an attacker-controlled Call-ID.
        if self.active_calls.read().unwrap().contains_key(&call_id) {
            return parser::build_response(request_text, 482, "Loop Detected");
        }

        {
            let calls = self.active_calls.read().unwrap();
            if calls.len() >= 256
                || calls
                    .values()
                    .filter(|c| c.caller_ext == caller_ext)
                    .count()
                    >= 2
            {
                return parser::build_response(request_text, 503, "Service Unavailable");
            }
        }
        // 检查被叫是否在线
        if !self.registrar.is_registered(&callee_ext) {
            tracing::warn!(
                "被叫 {} 不在线或未注册，返回 404: request_uri={:?}, to={:?}, online_count={}",
                callee_ext,
                parser::extract_request_uri(request_text),
                parser::extract_uri_from_header(request_text, "To"),
                self.registrar.online_count()
            );
            return parser::build_response(request_text, 404, "Not Found");
        }

        // 获取被叫的写入通道
        let callee_writer = match self.get_writer(&callee_ext) {
            Some(w) => w,
            None => {
                tracing::warn!("被叫 {} 无可用连接", callee_ext);
                return parser::build_response(request_text, 480, "Temporarily Unavailable");
            }
        };

        let invite_body = match parser::extract_body(request_text) {
            Some(body) => body,
            None => {
                tracing::warn!(
                    "拒绝 INVITE：强制 SRTP 模式要求初始 INVITE 携带 SDP (Call-ID={})",
                    call_id
                );
                return parser::build_response(request_text, 488, "Not Acceptable Here");
            }
        };

        if !is_sdp(request_text)
            || validate_sdp(&invite_body, SdpRole::Offer).is_err()
            || validate_identity(
                &parser::extract_header_value(request_text, "X-Minghe-Identity")
                    .unwrap_or_default(),
                &invite_body,
                &caller_ext,
                &callee_ext,
                &call_id,
                SdpRole::Offer,
            )
            .is_err()
        {
            return parser::build_response(request_text, 488, "Not Acceptable Here");
        }

        let target_uri = registered_contact_uri(&callee_ext, &self.domain, &self.registrar);
        tracing::debug!(
            "转发 INVITE 到被叫 {} 的注册 Contact: {}",
            callee_ext,
            target_uri
        );

        let rebuilt = request_text.as_bytes();
        let callee_invite = build_outbound_request_bytes(
            rebuilt,
            &target_uri,
            &self.domain,
            &server_contact_uri(&caller_ext, &self.domain),
        );

        // 存储呼叫信息
        let call_info = CallInfo {
            call_id: call_id.clone(),
            created_at: std::time::Instant::now(),
            caller_ext: caller_ext.clone(),
            callee_ext: callee_ext.clone(),
            caller_tag,
            callee_tag: None,
            caller_remote_contact: parser::extract_contact_uri(request_text),
            callee_remote_contact: None,
            state: CallState::Trying,
            original_invite: request_text.to_string(),
            callee_invite: String::from_utf8(callee_invite.clone()).expect("SIP text is UTF-8"),
            caller_writer: caller_writer.clone(),
            callee_writer: Some(callee_writer.clone()),
        };

        {
            let mut calls = self.active_calls.write().unwrap();
            if calls.contains_key(&call_id) {
                return parser::build_response(request_text, 482, "Loop Detected");
            }
            if calls.len() >= 256
                || calls
                    .values()
                    .filter(|c| c.caller_ext == caller_ext)
                    .count()
                    >= 2
            {
                return parser::build_response(request_text, 503, "Service Unavailable");
            }
            calls.insert(call_id.clone(), call_info);
        }

        // 转发 INVITE 到被叫
        if let Err(e) = callee_writer.send(callee_invite).await {
            tracing::error!("无法转发 INVITE 到被叫 {}: {}", callee_ext, e);
            self.cleanup_call(&call_id);
            return parser::build_response(request_text, 500, "Internal Server Error");
        }

        tracing::info!("INVITE 已转发到被叫 {}", callee_ext);

        // 返回 100 Trying 给主叫
        parser::build_response(request_text, 100, "Trying")
    }

    /// 处理来自被叫的响应（100/180/200 等）
    ///
    /// 作为 B2BUA，使用原始 INVITE 的头部信息重建响应转发给主叫。
    /// 被叫的响应中包含被叫的 Via 头部，不能直接转发给主叫，
    /// 否则主叫会因 Via 不匹配而忽略响应。
    pub async fn handle_callee_response(&self, response_text: &str) {
        if let Some(router) = &self.sdes {
            router.handle_callee_response(response_text).await;
            return;
        }

        let call_id = match parser::extract_call_id(response_text) {
            Some(id) => id,
            None => return,
        };

        let status_code = match parser::extract_status_code(response_text) {
            Some(code) => code,
            None => return,
        };

        let body = parser::extract_body(response_text).unwrap_or_default();
        // Validate every provisional/final SDP, including early media. No downgrade.
        let mut invalid = (status_code == 200
            && (body.is_empty() || parser::extract_to_tag(response_text).is_none()))
            || (!body.is_empty()
                && (!is_sdp(response_text) || validate_sdp(&body, SdpRole::Answer).is_err()));
        let (caller_writer, original_invite, callee_ext, callee_writer, callee_invite) = {
            let mut calls = self.active_calls.write().unwrap();
            let Some(call) = calls.get_mut(&call_id) else {
                return;
            };
            invalid |= !body.is_empty()
                && validate_identity(
                    &parser::extract_header_value(response_text, "X-Minghe-Identity")
                        .unwrap_or_default(),
                    &body,
                    &call.callee_ext,
                    &call.caller_ext,
                    &call_id,
                    SdpRole::Answer,
                )
                .is_err();
            if invalid {
                call.state = CallState::Terminated;
            } else {
                match status_code {
                    180 | 183 => call.state = CallState::Ringing,
                    200 => call.state = CallState::Established,
                    n if n >= 300 => call.state = CallState::Terminated,
                    _ => {}
                }
                if let Some(tag) = parser::extract_to_tag(response_text) {
                    call.callee_tag = Some(tag);
                }
                if status_code == 200 {
                    call.callee_remote_contact = parser::extract_contact_uri(response_text);
                }
            }
            (
                call.caller_writer.clone(),
                call.original_invite.clone(),
                call.callee_ext.clone(),
                call.callee_writer.clone(),
                call.callee_invite.clone(),
            )
        };
        let forwarded = if invalid {
            parser::build_response(&original_invite, 488, "Not Acceptable Here")
        } else {
            // Preserve the peer's fingerprint, ICE credentials and addresses byte-for-byte.
            build_forwarded_invite_response(
                &original_invite,
                response_text,
                status_code,
                reason_phrase(response_text),
                &server_contact_uri(&callee_ext, &self.domain),
                &body,
            )
        };
        let delivery_failed = caller_writer.send(forwarded).await.is_err();
        if invalid || status_code >= 300 || delivery_failed {
            if invalid || delivery_failed {
                if let Some(writer) = callee_writer {
                    if status_code == 200 {
                        // A 2xx creates a dialog even if its SDP is unacceptable.
                        // ACK it and immediately BYE rather than orphan the peer.
                        let target =
                            parser::extract_contact_uri(response_text).unwrap_or_else(|| {
                                registered_contact_uri(&callee_ext, &self.domain, &self.registrar)
                            });
                        for method in ["ACK", "BYE"] {
                            if let Some(request) = rejected_dialog_request(
                                &callee_invite,
                                response_text,
                                method,
                                &target,
                                &self.domain,
                            ) {
                                let _ = writer.send(request).await;
                            }
                        }
                    } else if status_code < 200 {
                        if let Some(cancel) = cancel_outbound_invite(&callee_invite) {
                            let _ = writer.send(cancel).await;
                        }
                    }
                }
            }
            self.cleanup_call(&call_id);
        }
    }

    /// 处理 ACK 请求
    pub async fn handle_ack(&self, request_text: &str) {
        if let Some(router) = &self.sdes {
            router.handle_ack(request_text).await;
            return;
        }

        let call_id = match parser::extract_call_id(request_text) {
            Some(id) => id,
            None => return,
        };

        let (callee_writer, target_uri) = {
            let calls = self.active_calls.read().unwrap();
            match calls.get(&call_id) {
                Some(call) => (
                    call.callee_writer.clone(),
                    call.callee_remote_contact.clone().unwrap_or_else(|| {
                        registered_contact_uri(&call.callee_ext, &self.domain, &self.registrar)
                    }),
                ),
                None => {
                    tracing::debug!("收到未知呼叫的 ACK: {}", call_id);
                    return;
                }
            }
        };

        // 转发 ACK 到被叫
        if let Some(writer) = callee_writer {
            let forwarded_ack = build_outbound_request(request_text, &target_uri, &self.domain, "");
            if let Err(e) = writer.send(forwarded_ack.into_bytes()).await {
                tracing::error!("无法转发 ACK: {}", e);
            } else {
                tracing::debug!("ACK 已转发 (Call-ID: {})", call_id);
            }
        }
    }

    /// 处理 BYE 请求
    pub async fn handle_bye(&self, request_text: &str, from_extension: &str) -> Vec<u8> {
        if let Some(router) = &self.sdes {
            return router.handle_bye(request_text, from_extension).await;
        }

        let call_id = match parser::extract_call_id(request_text) {
            Some(id) => id,
            None => {
                return parser::build_response(
                    request_text,
                    481,
                    "Call/Transaction Does Not Exist",
                );
            }
        };

        let other_writer;
        let target_uri;

        {
            let calls = self.active_calls.read().unwrap();
            let call = match calls.get(&call_id) {
                Some(c) => c,
                None => {
                    tracing::warn!("收到未知呼叫的 BYE: {}", call_id);
                    return parser::build_response(
                        request_text,
                        481,
                        "Call/Transaction Does Not Exist",
                    );
                }
            };

            if from_extension != call.caller_ext && from_extension != call.callee_ext {
                return parser::build_response(request_text, 403, "Forbidden");
            }
            // 确定对端的写入通道
            if from_extension == call.caller_ext {
                other_writer = call.callee_writer.clone();
                target_uri = call.callee_remote_contact.clone().unwrap_or_else(|| {
                    registered_contact_uri(&call.callee_ext, &self.domain, &self.registrar)
                });
            } else {
                other_writer = Some(call.caller_writer.clone());
                target_uri = call.caller_remote_contact.clone().unwrap_or_else(|| {
                    registered_contact_uri(&call.caller_ext, &self.domain, &self.registrar)
                });
            }
        }

        let reason = parser::extract_header_value(request_text, "Reason")
            .unwrap_or_else(|| "无".to_string());
        let user_agent = parser::extract_header_value(request_text, "User-Agent")
            .or_else(|| parser::extract_header_value(request_text, "Server"))
            .unwrap_or_else(|| "未知".to_string());
        let session_expires = parser::extract_header_value(request_text, "Session-Expires")
            .or_else(|| parser::extract_header_value(request_text, "x"))
            .unwrap_or_else(|| "无".to_string());

        tracing::info!(
            "收到 BYE: 来自 {} (Call-ID: {}, Reason: {}, User-Agent: {}, Session-Expires: {})",
            from_extension,
            call_id,
            reason,
            user_agent,
            session_expires
        );

        // 转发 BYE 到对端
        if let Some(writer) = other_writer {
            let forwarded_bye = build_outbound_request(request_text, &target_uri, &self.domain, "");
            if let Err(e) = writer.send(forwarded_bye.into_bytes()).await {
                tracing::error!("无法转发 BYE: {}", e);
            }
        }

        // 清理呼叫记录
        self.cleanup_call(&call_id);

        // 返回 200 OK
        parser::build_response(request_text, 200, "OK")
    }

    /// 处理 CANCEL 请求
    pub async fn handle_cancel(&self, request_text: &str) -> Vec<u8> {
        if let Some(router) = &self.sdes {
            return router.handle_cancel(request_text).await;
        }

        let call_id = match parser::extract_call_id(request_text) {
            Some(id) => id,
            None => {
                return parser::build_response(
                    request_text,
                    481,
                    "Call/Transaction Does Not Exist",
                );
            }
        };

        let callee_writer;
        let callee_invite;
        let original_invite;

        {
            let mut calls = self.active_calls.write().unwrap();
            let call = match calls.get_mut(&call_id) {
                Some(c) => c,
                None => {
                    return parser::build_response(
                        request_text,
                        481,
                        "Call/Transaction Does Not Exist",
                    );
                }
            };

            call.state = CallState::Terminated;
            callee_writer = call.callee_writer.clone();
            callee_invite = call.callee_invite.clone();
            original_invite = call.original_invite.clone();
        }

        tracing::info!("收到 CANCEL (Call-ID: {})", call_id);

        // 转发 CANCEL 到被叫
        if let Some(writer) = callee_writer {
            if let Some(forwarded_cancel) = cancel_outbound_invite(&callee_invite) {
                if let Err(e) = writer.send(forwarded_cancel).await {
                    tracing::debug!("无法转发 CANCEL: {}", e);
                }
            }

            // 发送 487 Request Terminated 给主叫
            let terminated = parser::build_response(&original_invite, 487, "Request Terminated");
            let caller_writer = {
                let calls = self.active_calls.read().unwrap();
                calls.get(&call_id).map(|c| c.caller_writer.clone())
            };
            if let Some(writer) = caller_writer {
                let _ = writer.send(terminated).await;
            }
        }

        // 清理呼叫
        self.cleanup_call(&call_id);

        // 返回 200 OK 给 CANCEL
        parser::build_response(request_text, 200, "OK")
    }

    /// 根据 Call-ID 查找呼叫中对端的分机号
    pub fn find_peer_extension(&self, call_id: &str, from_ext: &str) -> Option<String> {
        if let Some(router) = &self.sdes {
            return router.find_peer_extension(call_id, from_ext);
        }

        let calls = self.active_calls.read().unwrap();
        if let Some(call) = calls.get(call_id) {
            if call.caller_ext == from_ext {
                Some(call.callee_ext.clone())
            } else {
                Some(call.caller_ext.clone())
            }
        } else {
            None
        }
    }

    /// 检查是否有匹配的活跃呼叫
    pub fn has_active_call(&self, call_id: &str) -> bool {
        if let Some(router) = &self.sdes {
            return router.has_active_call(call_id);
        }

        let calls = self.active_calls.read().unwrap();
        calls.contains_key(call_id)
    }

    /// 清理呼叫资源
    fn cleanup_call(&self, call_id: &str) {
        let mut calls = self.active_calls.write().unwrap();
        if calls.remove(call_id).is_some() {
            tracing::info!("清理呼叫: {}", call_id);
        }
    }
}

pub(super) fn is_sdp(text: &str) -> bool {
    parser::extract_header_value(text, "Content-Type")
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/sdp"))
}

pub(super) fn cancel_outbound_invite(invite: &str) -> Option<Vec<u8>> {
    let uri = parser::extract_request_uri(invite)?;
    let cseq = parser::extract_header_value(invite, "CSeq")?;
    let number = cseq.split_whitespace().next()?;
    let mut request = format!("CANCEL {uri} SIP/2.0\r\n");
    for header in ["Via", "From", "To", "Call-ID"] {
        request.push_str(&first_header_line(invite, header, None)?);
        request.push_str("\r\n");
    }
    request.push_str(&format!(
        "CSeq: {number} CANCEL\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n"
    ));
    Some(request.into_bytes())
}

pub(super) fn rejected_dialog_request(
    invite: &str,
    answer: &str,
    method: &str,
    target: &str,
    domain: &str,
) -> Option<Vec<u8>> {
    parser::extract_to_tag(answer)?;
    let cseq = parser::extract_header_value(invite, "CSeq")?;
    let number = cseq.split_whitespace().next()?.parse::<u32>().ok()?;
    let number = if method == "BYE" {
        number.checked_add(1)?
    } else {
        number
    };
    let mut request = format!(
        "{method} {target} SIP/2.0\r\nVia: SIP/2.0/TLS {domain};branch={}\r\n",
        parser::generate_branch()
    );
    for header in [
        first_header_line(invite, "From", Some("f"))?,
        first_header_line(answer, "To", Some("t"))?,
        first_header_line(invite, "Call-ID", Some("i"))?,
    ] {
        request.push_str(&header);
        request.push_str("\r\n");
    }
    request.push_str(&format!(
        "CSeq: {number} {method}\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n"
    ));
    Some(request.into_bytes())
}

pub(super) fn build_outbound_request_bytes(
    request: &[u8],
    target_uri: &str,
    domain: &str,
    contact_uri: &str,
) -> Vec<u8> {
    match std::str::from_utf8(request) {
        Ok(text) => build_outbound_request(text, target_uri, domain, contact_uri).into_bytes(),
        Err(_) => request.to_vec(),
    }
}

pub(crate) fn build_outbound_request(
    request: &str,
    target_uri: &str,
    domain: &str,
    contact_uri: &str,
) -> String {
    build_outbound_request_with_from(request, target_uri, domain, contact_uri, "")
}

/// 带主叫身份重写的出站请求重建
///
/// 与 [`build_outbound_request`] 行为一致，额外在 `authenticated_from` 非空时把 From 头
/// 重写为认证后的主叫 URI（保留原 tag 参数），防止伪造 From 冒名；为空时保留原 From 头，
/// 以兼容 INVITE/ACK/BYE 等未启用主叫重写的路径。
pub(crate) fn build_outbound_request_with_from(
    request: &str,
    target_uri: &str,
    domain: &str,
    contact_uri: &str,
    authenticated_from: &str,
) -> String {
    let mut lines = request.lines();
    let Some(first_line) = lines.next() else {
        return request.to_string();
    };

    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() != 3 || parts[0].starts_with("SIP/2.0") {
        return request.to_string();
    }

    let mut rewritten = Vec::new();
    let mut saw_contact = false;
    rewritten.push(format!("{} {} {}", parts[0], target_uri, parts[2]));
    rewritten.push(format!(
        "Via: SIP/2.0/TLS {};branch={}",
        domain,
        parser::generate_branch()
    ));

    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }

        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("via:") || lower.starts_with("v:") {
            continue;
        }
        if lower.starts_with("authorization:") || lower.starts_with("proxy-authorization:") {
            continue;
        }
        if lower.starts_with("route:") {
            continue;
        }
        if lower.starts_with("record-route:") {
            continue;
        }
        if lower.starts_with("contact:") || lower.starts_with("m:") {
            if !contact_uri.is_empty() {
                rewritten.push(format!("Contact: <{}>", contact_uri));
                saw_contact = true;
            }
            continue;
        }
        if lower.starts_with("from:") || lower.starts_with("f:") {
            if !authenticated_from.is_empty() {
                // 重写为认证主叫，保留原 From 头的 tag 参数
                let tag = trimmed.split(';').skip(1).find_map(|p| {
                    let p = p.trim();
                    p.starts_with("tag=").then(|| p.to_string())
                });
                match tag {
                    Some(t) => rewritten.push(format!("From: <{}>;{}", authenticated_from, t)),
                    None => rewritten.push(format!("From: <{}>", authenticated_from)),
                }
            } else {
                rewritten.push(line.to_string());
            }
            continue;
        }

        if let Some(line) = strip_unsupported_negotiation_header(trimmed) {
            rewritten.push(line);
        }
    }

    if !contact_uri.is_empty() && !saw_contact {
        rewritten.push(format!("Contact: <{}>", contact_uri));
    }

    let body = parser::extract_body(request).unwrap_or_default();
    let mut result = rewritten.join("\r\n");
    result.push_str("\r\n\r\n");
    result.push_str(&body);
    result
}

pub(super) fn build_forwarded_invite_response(
    original_invite: &str,
    callee_response: &str,
    status_code: u16,
    reason: &str,
    contact_uri: &str,
    body: &str,
) -> Vec<u8> {
    let mut response = format!("SIP/2.0 {} {}\r\n", status_code, reason);

    for via in header_lines(original_invite, "Via", Some("v")) {
        response.push_str(&via);
        response.push_str("\r\n");
    }

    if let Some(from) = first_header_line(original_invite, "From", Some("f")) {
        response.push_str(&from);
        response.push_str("\r\n");
    }

    let to = first_header_line(callee_response, "To", Some("t"))
        .or_else(|| first_header_line(original_invite, "To", Some("t")))
        .unwrap_or_else(|| format!("To: <{}>", contact_uri));
    response.push_str(&to);
    response.push_str("\r\n");

    if let Some(call_id) = first_header_line(original_invite, "Call-ID", Some("i")) {
        response.push_str(&call_id);
        response.push_str("\r\n");
    }

    if let Some(cseq) = first_header_line(original_invite, "CSeq", None) {
        response.push_str(&cseq);
        response.push_str("\r\n");
    }

    if status_code >= 200 && status_code < 300 {
        response.push_str(&format!("Contact: <{}>\r\n", contact_uri));
    }

    if !body.is_empty() {
        if let Some(identity) = first_header_line(callee_response, "X-Minghe-Identity", None) {
            response.push_str(&identity);
            response.push_str("\r\n");
        }
    }
    let body_bytes = body.as_bytes();
    if !body.is_empty() {
        response.push_str("Content-Type: application/sdp\r\n");
    }
    response.push_str(&format!("Content-Length: {}\r\n\r\n", body_bytes.len()));
    if !body.is_empty() {
        response.push_str(body);
    }

    response.into_bytes()
}

fn strip_unsupported_negotiation_header(line: &str) -> Option<String> {
    let Some((name, value)) = line.split_once(':') else {
        return Some(line.to_string());
    };
    let name = name.trim();
    let name_lower = name.to_ascii_lowercase();

    match name_lower.as_str() {
        "session-expires" | "x" | "min-se" => None,
        "supported" | "k" | "require" | "proxy-require" => {
            let option_tags: Vec<&str> = value
                .split(',')
                .map(str::trim)
                .filter(|tag| {
                    !tag.is_empty()
                        && !tag.eq_ignore_ascii_case("timer")
                        && !tag.eq_ignore_ascii_case("100rel")
                })
                .collect();

            if option_tags.is_empty() {
                None
            } else {
                Some(format!("{}: {}", name, option_tags.join(", ")))
            }
        }
        _ => Some(line.to_string()),
    }
}

fn header_lines(msg: &str, name: &str, compact: Option<&str>) -> Vec<String> {
    let name_prefix = format!("{}:", name.to_ascii_lowercase());
    let compact_prefix = compact.map(|c| format!("{}:", c.to_ascii_lowercase()));

    msg.lines()
        .map(str::trim)
        .take_while(|line| !line.is_empty())
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            lower.starts_with(&name_prefix)
                || compact_prefix
                    .as_ref()
                    .map(|prefix| lower.starts_with(prefix))
                    .unwrap_or(false)
        })
        .map(ToString::to_string)
        .collect()
}

fn first_header_line(msg: &str, name: &str, compact: Option<&str>) -> Option<String> {
    header_lines(msg, name, compact).into_iter().next()
}

pub(super) fn reason_phrase(response: &str) -> &str {
    response
        .lines()
        .next()
        .and_then(|line| line.splitn(3, ' ').nth(2))
        .map(str::trim)
        .filter(|reason| !reason.is_empty())
        .unwrap_or("Unknown")
}

pub(crate) fn server_contact_uri(extension: &str, domain: &str) -> String {
    format!("sip:{}@{};transport=tls", extension, domain)
}

pub(crate) fn registered_contact_uri(
    extension: &str,
    domain: &str,
    registrar: &RegistrarService,
) -> String {
    registrar
        .lookup(extension)
        .map(|reg| reg.contact)
        .unwrap_or_else(|| server_contact_uri(extension, domain))
}

pub(crate) fn extract_called_extension(request: &str) -> Option<String> {
    parser::extract_request_uri(request)
        .and_then(|uri| parser::extract_extension(&uri))
        .or_else(|| {
            parser::extract_uri_from_header(request, "To")
                .and_then(|uri| parser::extract_extension(&uri))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarded_invite_response_preserves_callee_to_tag_and_adds_server_contact() {
        let original_invite = concat!(
            "INVITE sip:1002@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/TLS caller.example.com;branch=z9hG4bKcaller\r\n",
            "From: <sips:1001@example.com>;tag=caller-tag\r\n",
            "To: <sips:1002@example.com>\r\n",
            "Call-ID: call-1\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Length: 0\r\n\r\n"
        );
        let callee_response = concat!(
            "SIP/2.0 200 OK\r\n",
            "Via: SIP/2.0/TLS caller.example.com;branch=z9hG4bKcaller\r\n",
            "From: <sips:1001@example.com>;tag=caller-tag\r\n",
            "To: <sips:1002@example.com>;tag=callee-tag\r\n",
            "Call-ID: call-1\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Length: 0\r\n\r\n"
        );

        let response = build_forwarded_invite_response(
            original_invite,
            callee_response,
            200,
            "OK",
            "sip:1002@example.com;transport=tls",
            "v=0\r\n",
        );
        let response_text = String::from_utf8(response).unwrap();

        assert!(response_text.contains("To: <sips:1002@example.com>;tag=callee-tag\r\n"));
        assert!(response_text.contains("Contact: <sip:1002@example.com;transport=tls>\r\n"));
        assert!(!response_text.contains("caller-tag;tag="));
    }

    #[test]
    fn outbound_invite_uses_server_via_and_contact() {
        let invite = concat!(
            "INVITE sip:1002@stale-contact.invalid SIP/2.0\r\n",
            "Via: SIP/2.0/TLS caller.example.com;branch=z9hG4bKcaller\r\n",
            "Route: <sip:old-proxy.invalid;lr>\r\n",
            "From: <sips:1001@example.com>;tag=caller-tag\r\n",
            "To: <sips:1002@example.com>\r\n",
            "Contact: <sips:1001@caller-device.invalid;transport=tls>\r\n",
            "Call-ID: call-1\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Length: 0\r\n\r\n"
        );

        let rewritten = build_outbound_request(
            invite,
            "sip:1002@callee-device.invalid;transport=tls",
            "example.com",
            "sip:1001@example.com;transport=tls",
        );

        assert!(rewritten
            .starts_with("INVITE sip:1002@callee-device.invalid;transport=tls SIP/2.0\r\n"));
        assert!(rewritten.contains("Via: SIP/2.0/TLS example.com;branch=z9hG4bK"));
        assert!(rewritten.contains("Contact: <sip:1001@example.com;transport=tls>\r\n"));
        assert!(!rewritten.contains("caller-device.invalid"));
        assert!(!rewritten.contains("old-proxy.invalid"));
    }

    #[test]
    fn outbound_invite_strips_session_timer_negotiation() {
        let invite = concat!(
            "INVITE sip:1002@stale-contact.invalid SIP/2.0\r\n",
            "Via: SIP/2.0/TLS caller.example.com;branch=z9hG4bKcaller\r\n",
            "From: <sips:1001@example.com>;tag=caller-tag\r\n",
            "To: <sips:1002@example.com>\r\n",
            "Contact: <sips:1001@caller-device.invalid;transport=tls>\r\n",
            "Call-ID: call-1\r\n",
            "CSeq: 1 INVITE\r\n",
            "Supported: outbound, timer, replaces\r\n",
            "Require: timer\r\n",
            "Session-Expires: 1800;refresher=uac\r\n",
            "Min-SE: 90\r\n",
            "Content-Length: 0\r\n\r\n"
        );

        let rewritten = build_outbound_request(
            invite,
            "sip:1002@callee-device.invalid;transport=tls",
            "example.com",
            "sip:1001@example.com;transport=tls",
        );

        assert!(rewritten.contains("Supported: outbound, replaces\r\n"));
        assert!(!rewritten.contains("Require:"));
        assert!(!rewritten.contains("Session-Expires:"));
        assert!(!rewritten.contains("Min-SE:"));
        assert!(!rewritten.to_ascii_lowercase().contains("timer"));
    }

    #[test]
    fn outbound_invite_strips_unsupported_reliable_provisional_negotiation() {
        let invite = concat!(
            "INVITE sip:1002@stale-contact.invalid SIP/2.0\r\n",
            "Via: SIP/2.0/TLS caller.example.com;branch=z9hG4bKcaller\r\n",
            "From: <sips:1001@example.com>;tag=caller-tag\r\n",
            "To: <sips:1002@example.com>\r\n",
            "Contact: <sips:1001@caller-device.invalid;transport=tls>\r\n",
            "Call-ID: call-1\r\n",
            "CSeq: 1 INVITE\r\n",
            "Supported: replaces, 100rel, outbound\r\n",
            "Require: 100rel\r\n",
            "Proxy-Require: 100rel\r\n",
            "Content-Length: 0\r\n\r\n"
        );

        let rewritten = build_outbound_request(
            invite,
            "sip:1002@callee-device.invalid;transport=tls",
            "example.com",
            "sip:1001@example.com;transport=tls",
        );

        assert!(rewritten.contains("Supported: replaces, outbound\r\n"));
        assert!(!rewritten.contains("100rel"));
        assert!(!rewritten.contains("Require:"));
        assert!(!rewritten.contains("Proxy-Require:"));
    }

    #[test]
    fn outbound_invite_strips_compact_100rel_option_tag() {
        let invite = concat!(
            "INVITE sip:1002@stale-contact.invalid SIP/2.0\r\n",
            "Via: SIP/2.0/TLS caller.example.com;branch=z9hG4bKcaller\r\n",
            "From: <sips:1001@example.com>;tag=caller-tag\r\n",
            "To: <sips:1002@example.com>\r\n",
            "k: 100rel, replaces\r\n",
            "Call-ID: call-1\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Length: 0\r\n\r\n"
        );

        let rewritten = build_outbound_request(
            invite,
            "sip:1002@callee-device.invalid;transport=tls",
            "example.com",
            "sip:1001@example.com;transport=tls",
        );

        assert!(rewritten.contains("k: replaces\r\n"));
        assert!(!rewritten.contains("100rel"));
    }

    #[test]
    fn called_extension_falls_back_to_to_header() {
        let invite = concat!(
            "INVITE sips:pbx.example.com;transport=tls SIP/2.0\r\n",
            "Via: SIP/2.0/TLS caller.example.com;branch=z9hG4bKcaller\r\n",
            "From: <sips:1001@example.com>;tag=caller-tag\r\n",
            "To: <sips:1002@example.com>\r\n",
            "Call-ID: call-1\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Length: 0\r\n\r\n"
        );

        assert_eq!(extract_called_extension(invite), Some("1002".to_string()));
    }

    #[test]
    fn initial_outbound_invite_targets_registered_contact() {
        let invite = concat!(
            "INVITE sip:1002@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/TLS caller.example.com;branch=z9hG4bKcaller\r\n",
            "From: <sips:1001@example.com>;tag=caller-tag\r\n",
            "To: <sips:1002@example.com>\r\n",
            "Contact: <sips:1001@caller-device.invalid;transport=tls>\r\n",
            "Call-ID: call-1\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Length: 0\r\n\r\n"
        );

        let rewritten = build_outbound_request(
            invite,
            "sip:1002@callee-device.invalid;transport=tls",
            "example.com",
            "sip:1001@example.com;transport=tls",
        );

        assert!(rewritten
            .starts_with("INVITE sip:1002@callee-device.invalid;transport=tls SIP/2.0\r\n"));
        assert!(rewritten.contains("To: <sips:1002@example.com>\r\n"));
    }

    #[test]
    fn forwarded_error_response_preserves_reason_phrase() {
        let original_invite = concat!(
            "INVITE sip:1002@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/TLS caller.example.com;branch=z9hG4bKcaller\r\n",
            "From: <sips:1001@example.com>;tag=caller-tag\r\n",
            "To: <sips:1002@example.com>\r\n",
            "Call-ID: call-1\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Length: 0\r\n\r\n"
        );
        let callee_response = concat!(
            "SIP/2.0 404 Not Found\r\n",
            "To: <sips:1002@example.com>;tag=callee-tag\r\n",
            "Content-Length: 0\r\n\r\n"
        );

        let response = build_forwarded_invite_response(
            original_invite,
            callee_response,
            404,
            reason_phrase(callee_response),
            "sip:1002@example.com;transport=tls",
            "",
        );
        let response_text = String::from_utf8(response).unwrap();

        assert!(response_text.starts_with("SIP/2.0 404 Not Found\r\n"));
    }

    #[test]
    fn in_dialog_request_uri_is_rewritten_to_target_contact() {
        let ack = concat!(
            "ACK sips:1002@stale-contact.invalid SIP/2.0\r\n",
            "Via: SIP/2.0/TLS caller.example.com;branch=z9hG4bKack\r\n",
            "From: <sips:1001@example.com>;tag=caller-tag\r\n",
            "To: <sips:1002@example.com>;tag=callee-tag\r\n",
            "Call-ID: call-1\r\n",
            "CSeq: 1 ACK\r\n",
            "Content-Length: 0\r\n\r\n"
        );

        let rewritten = build_outbound_request(
            ack,
            "sip:1002@callee-device.invalid;transport=tls",
            "example.com",
            "",
        );

        assert!(
            rewritten.starts_with("ACK sip:1002@callee-device.invalid;transport=tls SIP/2.0\r\n")
        );
        assert!(rewritten.contains("Via: SIP/2.0/TLS example.com;branch=z9hG4bK"));
        assert!(!rewritten.contains("stale-contact.invalid"));
        assert!(rewritten.contains("To: <sips:1002@example.com>;tag=callee-tag\r\n"));
    }
}
