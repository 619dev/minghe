//! 呼叫路由模块
//!
//! 处理 INVITE、ACK、BYE、CANCEL 等呼叫相关的 SIP 请求。
//! 作为 B2BUA（Back-to-Back User Agent）工作，中继信令并管理媒体会话。

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;

use super::parser;
use super::registrar::RegistrarService;
use crate::media::relay::MediaRelayManager;
use crate::media::srtp::{parse_crypto_attribute, SrtpCryptoSuite};

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
    /// 主叫分机号
    pub caller_ext: String,
    /// 被叫分机号
    pub callee_ext: String,
    /// 主叫 From tag
    pub caller_tag: String,
    /// 被叫 To tag
    pub callee_tag: Option<String>,
    /// 呼叫状态
    pub state: CallState,
    /// 主叫原始 INVITE 消息（用于构建后续响应）
    pub original_invite: String,
    /// 主叫侧写入通道
    pub caller_writer: mpsc::Sender<Vec<u8>>,
    /// 被叫侧写入通道
    pub callee_writer: Option<mpsc::Sender<Vec<u8>>>,
    /// 主叫原始 offer 中的 SRTP 密钥（用于解密主叫发来的媒体）
    pub caller_remote_crypto: Option<SrtpCryptoSuite>,
    /// 服务端转发给主叫的 answer 密钥（用于加密发给主叫的媒体）
    pub caller_local_crypto: Option<SrtpCryptoSuite>,
    /// 被叫 answer 中的 SRTP 密钥（用于解密被叫发来的媒体）
    pub callee_remote_crypto: Option<SrtpCryptoSuite>,
    /// 服务端转发给被叫的 offer 密钥（用于加密发给被叫的媒体）
    pub callee_local_crypto: Option<SrtpCryptoSuite>,
    /// 主叫侧中继端口
    pub caller_relay_port: u16,
    /// 被叫侧中继端口
    pub callee_relay_port: u16,
    /// 媒体中继是否已启动
    pub relay_started: bool,
}

/// 呼叫路由器
///
/// 管理所有活跃呼叫，处理呼叫建立、转发和拆除。
pub struct Router {
    /// 活跃呼叫 (Call-ID -> CallInfo)
    active_calls: RwLock<HashMap<String, CallInfo>>,
    /// 注册服务引用
    registrar: Arc<RegistrarService>,
    /// 媒体中继管理器
    media_manager: Arc<MediaRelayManager>,
    /// 服务器域名
    domain: String,
    /// 媒体地址
    media_addr: String,
    /// 连接映射：分机号 -> 写入通道（由 server 模块更新）
    connection_writers: RwLock<HashMap<String, mpsc::Sender<Vec<u8>>>>,
}

impl Router {
    /// 创建新的路由器
    pub fn new(
        registrar: Arc<RegistrarService>,
        media_manager: Arc<MediaRelayManager>,
        domain: String,
        media_addr: String,
    ) -> Self {
        Self {
            active_calls: RwLock::new(HashMap::new()),
            registrar,
            media_manager,
            domain,
            media_addr,
            connection_writers: RwLock::new(HashMap::new()),
        }
    }

    /// 注册分机的写入通道（由 server 模块在注册成功后调用）
    pub fn register_writer(&self, extension: &str, writer: mpsc::Sender<Vec<u8>>) {
        let mut writers = self.connection_writers.write().unwrap();
        writers.insert(extension.to_string(), writer);
        tracing::debug!("已注册分机 {} 的写入通道", extension);
    }

    /// 注销分机的写入通道
    pub fn unregister_writer(&self, extension: &str) {
        let mut writers = self.connection_writers.write().unwrap();
        writers.remove(extension);
        tracing::debug!("已注销分机 {} 的写入通道", extension);
    }

    /// 获取分机的写入通道
    fn get_writer(&self, extension: &str) -> Option<mpsc::Sender<Vec<u8>>> {
        let writers = self.connection_writers.read().unwrap();
        writers.get(extension).cloned()
    }

    /// 处理 INVITE 请求
    ///
    /// 流程：
    /// 1. 提取被叫号码
    /// 2. 检查被叫是否在线
    /// 3. 分配媒体中继端口
    /// 4. 生成 SRTP 密钥
    /// 5. 转发 INVITE 到被叫（修改 SDP）
    /// 6. 返回 100 Trying 给主叫
    pub async fn handle_invite(
        &self,
        request_text: &str,
        caller_writer: mpsc::Sender<Vec<u8>>,
    ) -> Vec<u8> {
        // 提取主叫分机号
        let caller_ext = parser::extract_uri_from_header(request_text, "From")
            .and_then(|uri| parser::extract_extension(&uri))
            .unwrap_or_default();

        // 提取被叫分机号（从 Request-URI）
        let callee_ext = parser::extract_request_uri(request_text)
            .and_then(|uri| parser::extract_extension(&uri))
            .unwrap_or_default();

        let call_id = parser::extract_call_id(request_text).unwrap_or_default();
        let caller_tag = parser::extract_from_tag(request_text).unwrap_or_default();

        tracing::info!(
            "收到 INVITE: {} -> {} (Call-ID: {})",
            caller_ext,
            callee_ext,
            call_id
        );

        // 如果同一 Call-ID 已有活跃呼叫（上次呼叫残留），先清理
        {
            let calls = self.active_calls.read().unwrap();
            if calls.contains_key(&call_id) {
                tracing::warn!("发现残留呼叫，清理: Call-ID={}", call_id);
                drop(calls); // 释放读锁
                self.cleanup_call(&call_id);
            }
        }

        // 检查被叫是否在线
        if !self.registrar.is_registered(&callee_ext) {
            tracing::warn!("被叫 {} 不在线", callee_ext);
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

        // 分配媒体中继端口
        let relay_session = match self.media_manager.create_session(call_id.clone()) {
            Some(s) => s,
            None => {
                tracing::error!("无法分配媒体中继端口");
                return parser::build_response(request_text, 503, "Service Unavailable");
            }
        };

        let caller_remote_crypto = parser::extract_body(request_text)
            .as_deref()
            .and_then(extract_srtp_crypto_from_sdp);

        let use_srtp = caller_remote_crypto.is_some();
        if use_srtp {
            tracing::debug!("主叫 {} 提供 a=crypto，使用 SRTP B2BUA 模式", caller_ext);
        } else {
            tracing::warn!("主叫 {} 未提供 a=crypto，使用普通 RTP 中继模式", caller_ext);
        }

        // 如果主叫提供 SRTP，则服务端分别向主叫、被叫声明自己的 SRTP 密钥。
        let caller_local_crypto = use_srtp.then(SrtpCryptoSuite::new);
        let callee_local_crypto = use_srtp.then(SrtpCryptoSuite::new);

        // 修改 SDP：替换媒体地址和端口，保留原始 RTP/SRTP 参数
        let callee_invite = if let Some(body) = parser::extract_body(request_text) {
            let new_sdp = if let Some(crypto) = &callee_local_crypto {
                let callee_sdes = crypto.to_sdes_attribute();
                let callee_key = callee_sdes.split("inline:").nth(1).unwrap_or_default();
                parser::rewrite_sdp(
                    &body,
                    &self.media_addr,
                    relay_session.callee_port,
                    callee_key,
                )
            } else {
                parser::rewrite_sdp_plain(&body, &self.media_addr, relay_session.callee_port)
            };

            // 重建 INVITE：替换 SDP body，并把 Request-URI 指向被叫的注册 Contact
            let rebuilt = rebuild_request_with_sdp(request_text, &new_sdp, &self.domain);
            rewrite_request_uri_bytes(&rebuilt, &callee_ext, &self.domain, &self.registrar)
        } else {
            // 无 SDP 的 INVITE（后续通过 re-INVITE 协商）
            rewrite_request_uri(request_text, &callee_ext, &self.domain, &self.registrar)
                .into_bytes()
        };

        // 存储呼叫信息
        let call_info = CallInfo {
            call_id: call_id.clone(),
            caller_ext: caller_ext.clone(),
            callee_ext: callee_ext.clone(),
            caller_tag,
            callee_tag: None,
            state: CallState::Trying,
            original_invite: request_text.to_string(),
            caller_writer: caller_writer.clone(),
            callee_writer: Some(callee_writer.clone()),
            caller_remote_crypto,
            caller_local_crypto,
            callee_remote_crypto: None,
            callee_local_crypto,
            caller_relay_port: relay_session.caller_port,
            callee_relay_port: relay_session.callee_port,
            relay_started: false,
        };

        {
            let mut calls = self.active_calls.write().unwrap();
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
        let call_id = match parser::extract_call_id(response_text) {
            Some(id) => id,
            None => return,
        };

        let status_code = match parser::extract_status_code(response_text) {
            Some(code) => code,
            None => return,
        };

        let caller_writer;
        let caller_relay_port;
        let media_addr;
        let original_invite;
        let callee_ext;

        {
            let mut calls = self.active_calls.write().unwrap();
            let call = match calls.get_mut(&call_id) {
                Some(c) => c,
                None => {
                    tracing::debug!("收到未知呼叫的响应: Call-ID={}", call_id);
                    return;
                }
            };

            // 更新状态
            match status_code {
                100 => { /* Trying - 不改变状态 */ }
                180 | 183 => {
                    call.state = CallState::Ringing;
                    tracing::info!("呼叫 {} 被叫振铃中", call_id);
                    if call.callee_tag.is_none() {
                        call.callee_tag = parser::extract_to_tag(response_text);
                    }
                }
                200 => {
                    if call.state != CallState::Established {
                        call.state = CallState::Established;
                        tracing::info!("呼叫 {} 已建立", call_id);
                    }
                    if call.callee_tag.is_none() {
                        call.callee_tag = parser::extract_to_tag(response_text);
                    }
                    if call.callee_local_crypto.is_some() && call.callee_remote_crypto.is_none() {
                        if let Some(crypto) = parser::extract_body(response_text)
                            .as_deref()
                            .and_then(extract_srtp_crypto_from_sdp)
                        {
                            call.callee_remote_crypto = Some(crypto);
                        } else {
                            tracing::warn!(
                                "被叫 200 OK 缺少可用 a=crypto，无法启动媒体中继: Call-ID={}",
                                call_id
                            );
                        }
                    }
                }
                n if n >= 400 => {
                    call.state = CallState::Terminated;
                    tracing::info!("呼叫 {} 被拒绝: {}", call_id, status_code);
                }
                _ => {}
            }

            caller_writer = call.caller_writer.clone();
            caller_relay_port = call.caller_relay_port;
            media_addr = self.media_addr.clone();
            original_invite = call.original_invite.clone();
            callee_ext = call.callee_ext.clone();
        };

        // 用原始 INVITE 的头部重建响应给主叫
        // 这样 Via、From、To、CSeq、Call-ID 都和主叫的原始请求匹配
        let forwarded_response = if let Some(body) = parser::extract_body(response_text) {
            // 有 SDP body — 修改媒体地址和端口，保留原始 RTP/SRTP 参数
            let caller_key = {
                let calls = self.active_calls.read().unwrap();
                if let Some(call) = calls.get(&call_id) {
                    call.caller_local_crypto.as_ref().map(|crypto| {
                        let sdes = crypto.to_sdes_attribute();
                        sdes.split("inline:").nth(1).unwrap_or_default().to_string()
                    })
                } else {
                    None
                }
            };

            if let Some(caller_key) = caller_key {
                let new_sdp =
                    parser::rewrite_sdp(&body, &media_addr, caller_relay_port, &caller_key);
                // 使用原始 INVITE 头部构建带 SDP 的响应
                let reason = match status_code {
                    100 => "Trying",
                    180 => "Ringing",
                    183 => "Session Progress",
                    200 => "OK",
                    _ => "Unknown",
                };
                build_forwarded_invite_response(
                    &original_invite,
                    response_text,
                    status_code,
                    reason,
                    &server_contact_uri(&callee_ext, &self.domain),
                    &new_sdp,
                )
            } else {
                // 普通 RTP 模式：只改写媒体地址和端口，不注入 crypto
                let new_sdp = parser::rewrite_sdp_plain(&body, &media_addr, caller_relay_port);
                let reason = match status_code {
                    100 => "Trying",
                    180 => "Ringing",
                    183 => "Session Progress",
                    200 => "OK",
                    _ => "Unknown",
                };
                build_forwarded_invite_response(
                    &original_invite,
                    response_text,
                    status_code,
                    reason,
                    &server_contact_uri(&callee_ext, &self.domain),
                    &new_sdp,
                )
            }
        } else {
            // 无 SDP body — 使用原始 INVITE 头部构建简单响应
            let reason = match status_code {
                100 => "Trying",
                180 => "Ringing",
                183 => "Session Progress",
                200 => "OK",
                486 => "Busy Here",
                487 => "Request Terminated",
                603 => "Decline",
                _ => "Unknown",
            };
            build_forwarded_invite_response(
                &original_invite,
                response_text,
                status_code,
                reason,
                &server_contact_uri(&callee_ext, &self.domain),
                "",
            )
        };

        // 转发给主叫
        if let Err(e) = caller_writer.send(forwarded_response).await {
            tracing::error!("无法转发响应到主叫: {}", e);
        }

        // 如果呼叫被拒绝，清理资源
        if status_code >= 400 {
            self.cleanup_call(&call_id);
        }

        // 如果是 200 OK，且中继尚未启动，启动媒体中继
        if status_code == 200 {
            let should_start = {
                let mut calls = self.active_calls.write().unwrap();
                if let Some(call) = calls.get_mut(&call_id) {
                    let has_required_crypto =
                        call.callee_local_crypto.is_none() || call.callee_remote_crypto.is_some();
                    if !call.relay_started && has_required_crypto {
                        call.relay_started = true;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            };
            if should_start {
                self.start_media_relay(&call_id).await;
            } else {
                let calls = self.active_calls.read().unwrap();
                if let Some(call) = calls.get(&call_id) {
                    if call.callee_local_crypto.is_some() && call.callee_remote_crypto.is_none() {
                        tracing::warn!(
                            "媒体中继未启动：缺少被叫 SRTP crypto (Call-ID={})",
                            call_id
                        );
                    }
                }
            }
        }
    }

    /// 处理 ACK 请求
    pub async fn handle_ack(&self, request_text: &str) {
        let call_id = match parser::extract_call_id(request_text) {
            Some(id) => id,
            None => return,
        };

        let (callee_writer, callee_ext) = {
            let calls = self.active_calls.read().unwrap();
            match calls.get(&call_id) {
                Some(call) => (call.callee_writer.clone(), call.callee_ext.clone()),
                None => {
                    tracing::debug!("收到未知呼叫的 ACK: {}", call_id);
                    return;
                }
            }
        };

        // 转发 ACK 到被叫
        if let Some(writer) = callee_writer {
            let forwarded_ack =
                rewrite_request_uri(request_text, &callee_ext, &self.domain, &self.registrar);
            if let Err(e) = writer.send(forwarded_ack.into_bytes()).await {
                tracing::error!("无法转发 ACK: {}", e);
            } else {
                tracing::debug!("ACK 已转发 (Call-ID: {})", call_id);
            }
        }
    }

    /// 处理 BYE 请求
    pub async fn handle_bye(&self, request_text: &str, from_extension: &str) -> Vec<u8> {
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
        let other_ext;

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

            // 确定对端的写入通道
            if from_extension == call.caller_ext {
                other_writer = call.callee_writer.clone();
                other_ext = call.callee_ext.clone();
            } else {
                other_writer = Some(call.caller_writer.clone());
                other_ext = call.caller_ext.clone();
            }
        }

        tracing::info!("收到 BYE: 来自 {} (Call-ID: {})", from_extension, call_id);

        // 转发 BYE 到对端
        if let Some(writer) = other_writer {
            let forwarded_bye =
                rewrite_request_uri(request_text, &other_ext, &self.domain, &self.registrar);
            if let Err(e) = writer.send(forwarded_bye.into_bytes()).await {
                tracing::error!("无法转发 BYE: {}", e);
            }
        }

        // 清理呼叫和媒体资源
        self.cleanup_call(&call_id);

        // 返回 200 OK
        parser::build_response(request_text, 200, "OK")
    }

    /// 处理 CANCEL 请求
    pub async fn handle_cancel(&self, request_text: &str) -> Vec<u8> {
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
        let callee_ext;
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
            callee_ext = call.callee_ext.clone();
            original_invite = call.original_invite.clone();
        }

        tracing::info!("收到 CANCEL (Call-ID: {})", call_id);

        // 转发 CANCEL 到被叫
        if let Some(writer) = callee_writer {
            let forwarded_cancel =
                rewrite_request_uri(request_text, &callee_ext, &self.domain, &self.registrar);
            if let Err(e) = writer.send(forwarded_cancel.into_bytes()).await {
                tracing::error!("无法转发 CANCEL: {}", e);
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
        let calls = self.active_calls.read().unwrap();
        calls.contains_key(call_id)
    }

    /// 启动媒体中继
    async fn start_media_relay(&self, call_id: &str) {
        let calls = self.active_calls.read().unwrap();
        if let Some(call) = calls.get(call_id) {
            tracing::info!(
                "启动 SRTP B2BUA 媒体中继: Call-ID={}, 主叫端口={}, 被叫端口={}",
                call_id,
                call.caller_relay_port,
                call.callee_relay_port
            );

            // 启动 UDP 中继任务
            let caller_port = call.caller_relay_port;
            let callee_port = call.callee_relay_port;
            let media_addr = self.media_addr.clone();
            let call_id_clone = call_id.to_string();
            let caller_decrypt_crypto = call.caller_remote_crypto.clone();
            let callee_encrypt_crypto = call.callee_local_crypto.clone();
            let callee_decrypt_crypto = call.callee_remote_crypto.clone();
            let caller_encrypt_crypto = call.caller_local_crypto.clone();
            let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
            self.media_manager.register_shutdown(call_id, shutdown_tx);

            tokio::spawn(async move {
                if let Err(e) = crate::media::relay::run_relay(
                    &call_id_clone,
                    &media_addr,
                    caller_port,
                    callee_port,
                    caller_decrypt_crypto,
                    callee_encrypt_crypto,
                    callee_decrypt_crypto,
                    caller_encrypt_crypto,
                    shutdown_rx,
                )
                .await
                {
                    tracing::error!("媒体中继错误 ({}): {}", call_id_clone, e);
                }
            });
        }
    }

    /// 清理呼叫资源
    fn cleanup_call(&self, call_id: &str) {
        let mut calls = self.active_calls.write().unwrap();
        if calls.remove(call_id).is_some() {
            tracing::info!("清理呼叫: {}", call_id);
            // 释放媒体中继端口
            self.media_manager.remove_session(call_id);
        }
    }
}

/// 重建带有新 SDP 的 SIP 请求
fn rebuild_request_with_sdp(request: &str, new_sdp: &str, _domain: &str) -> Vec<u8> {
    let header_end = request.find("\r\n\r\n").unwrap_or(request.len());
    let headers = &request[..header_end];
    let sdp_bytes = new_sdp.as_bytes();

    // 更新 Content-Length 并重建消息
    let mut new_headers = Vec::new();
    for line in headers.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("content-length:") || lower.starts_with("l:") {
            new_headers.push(format!("Content-Length: {}", sdp_bytes.len()));
        } else if lower.starts_with("content-type:") {
            // 保留原有的 Content-Type
            new_headers.push(line.to_string());
        } else {
            new_headers.push(line.to_string());
        }
    }

    // 确保有 Content-Type
    let has_content_type = new_headers
        .iter()
        .any(|h| h.to_lowercase().starts_with("content-type:"));
    if !has_content_type {
        new_headers.push("Content-Type: application/sdp".to_string());
    }

    // 确保有 Content-Length
    let has_content_length = new_headers
        .iter()
        .any(|h| h.to_lowercase().starts_with("content-length:"));
    if !has_content_length {
        new_headers.push(format!("Content-Length: {}", sdp_bytes.len()));
    }

    let mut result = new_headers.join("\r\n");
    result.push_str("\r\n\r\n");
    result.push_str(new_sdp);

    result.into_bytes()
}

fn rewrite_request_uri_bytes(
    request: &[u8],
    target_ext: &str,
    domain: &str,
    registrar: &RegistrarService,
) -> Vec<u8> {
    match std::str::from_utf8(request) {
        Ok(text) => rewrite_request_uri(text, target_ext, domain, registrar).into_bytes(),
        Err(_) => request.to_vec(),
    }
}

fn rewrite_request_uri(
    request: &str,
    target_ext: &str,
    domain: &str,
    registrar: &RegistrarService,
) -> String {
    let target_uri = registrar
        .lookup(target_ext)
        .map(|reg| reg.contact)
        .unwrap_or_else(|| format!("sips:{}@{};transport=tls", target_ext, domain));

    let mut lines = request.lines();
    let Some(first_line) = lines.next() else {
        return request.to_string();
    };

    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() != 3 || parts[0].starts_with("SIP/2.0") {
        return request.to_string();
    }

    let mut rewritten = format!("{} {} {}", parts[0], target_uri, parts[2]);
    for line in lines {
        rewritten.push_str("\r\n");
        rewritten.push_str(line);
    }

    if request.ends_with("\r\n") {
        rewritten.push_str("\r\n");
    }
    rewritten
}

fn build_forwarded_invite_response(
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
        .unwrap_or_else(|| format!("To: <sips:{}>", contact_uri));
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

fn header_lines(msg: &str, name: &str, compact: Option<&str>) -> Vec<String> {
    let name_prefix = format!("{}:", name.to_lowercase());
    let compact_prefix = compact.map(|c| format!("{}:", c.to_lowercase()));

    msg.lines()
        .map(str::trim)
        .take_while(|line| !line.is_empty())
        .filter(|line| {
            let lower = line.to_lowercase();
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

fn server_contact_uri(extension: &str, domain: &str) -> String {
    format!("sips:{}@{};transport=tls", extension, domain)
}

fn extract_srtp_crypto_from_sdp(sdp: &str) -> Option<SrtpCryptoSuite> {
    for line in sdp.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("a=crypto") || trimmed.starts_with("crypto:") {
            match parse_crypto_attribute(trimmed)
                .and_then(|(_, _, key)| SrtpCryptoSuite::from_sdes(&key))
            {
                Ok(crypto) => return Some(crypto),
                Err(e) => {
                    tracing::warn!("无法解析 SDP crypto 行 '{}': {}", trimmed, e);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

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
            "sips:1002@example.com;transport=tls",
            "v=0\r\n",
        );
        let response_text = String::from_utf8(response).unwrap();

        assert!(response_text.contains("To: <sips:1002@example.com>;tag=callee-tag\r\n"));
        assert!(response_text.contains("Contact: <sips:1002@example.com;transport=tls>\r\n"));
        assert!(!response_text.contains("caller-tag;tag="));
    }

    #[test]
    fn in_dialog_request_uri_is_rewritten_to_target_contact_fallback() {
        let registrar = RegistrarService::new(
            "example.com".to_string(),
            "secret".to_string(),
            HashMap::new(),
            1000,
            2000,
        );
        let ack = concat!(
            "ACK sips:1002@stale-contact.invalid SIP/2.0\r\n",
            "Via: SIP/2.0/TLS caller.example.com;branch=z9hG4bKack\r\n",
            "From: <sips:1001@example.com>;tag=caller-tag\r\n",
            "To: <sips:1002@example.com>;tag=callee-tag\r\n",
            "Call-ID: call-1\r\n",
            "CSeq: 1 ACK\r\n",
            "Content-Length: 0\r\n\r\n"
        );

        let rewritten = rewrite_request_uri(ack, "1002", "example.com", &registrar);

        assert!(rewritten.starts_with("ACK sips:1002@example.com;transport=tls SIP/2.0\r\n"));
        assert!(!rewritten.contains("stale-contact.invalid"));
        assert!(rewritten.contains("To: <sips:1002@example.com>;tag=callee-tag\r\n"));
    }
}
