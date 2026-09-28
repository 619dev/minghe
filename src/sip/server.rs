//! SIP TLS 服务器模块
//!
//! 核心服务器循环：TLS 监听 → 消息帧分界 → 解析分发 → 响应回写。
//! 每个连接维护独立的读写任务，通过 mpsc 通道解耦。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Semaphore};

use super::parser;
use super::registrar::RegistrarService;
use super::router::Router;
use super::transaction::TransactionManager;
use crate::config::AppConfig;
use crate::media::relay::MediaRelayManager;
use crate::tls::ReloadableTlsAcceptor;

/// 连接状态
struct ConnectionState {
    /// 客户端地址
    peer_addr: SocketAddr,
    /// 已认证的分机号
    extension: Option<String>,
    /// 写入通道（向客户端发送数据）
    writer_tx: mpsc::Sender<Vec<u8>>,
}

/// 服务器共享状态
pub struct ServerState {
    pub config: Arc<AppConfig>,
    pub registrar: Arc<RegistrarService>,
    pub router: Arc<Router>,
    pub transaction_mgr: Arc<TransactionManager>,
    /// 连接映射：peer_addr -> ConnectionState
    connections: RwLock<HashMap<SocketAddr, ConnectionState>>,
}

impl ServerState {
    /// 根据分机号查找写入通道
    fn find_writer_by_extension(&self, ext: &str) -> Option<mpsc::Sender<Vec<u8>>> {
        let conns = self.connections.read().unwrap();
        for conn in conns.values() {
            if conn.extension.as_deref() == Some(ext)
                && self
                    .registrar
                    .lookup(ext)
                    .is_some_and(|r| r.transport_addr == conn.peer_addr)
            {
                return Some(conn.writer_tx.clone());
            }
        }
        None
    }

    /// 注册连接
    fn register_connection(&self, peer_addr: SocketAddr, writer_tx: mpsc::Sender<Vec<u8>>) {
        let mut conns = self.connections.write().unwrap();
        conns.insert(
            peer_addr,
            ConnectionState {
                peer_addr,
                extension: None,
                writer_tx,
            },
        );
    }

    /// 设置连接的分机号（注册成功后调用）
    fn set_connection_extension(&self, peer_addr: &SocketAddr, extension: String) {
        let mut conns = self.connections.write().unwrap();
        if let Some(conn) = conns.get_mut(peer_addr) {
            conn.extension = Some(extension);
        }
    }

    /// 清除连接关联的分机号（显式注销后调用）
    fn clear_connection_extension(&self, peer_addr: &SocketAddr) {
        let mut conns = self.connections.write().unwrap();
        if let Some(conn) = conns.get_mut(peer_addr) {
            conn.extension = None;
        }
    }

    /// 获取连接的分机号
    fn get_connection_extension(&self, peer_addr: &SocketAddr) -> Option<String> {
        let conns = self.connections.read().unwrap();
        conns
            .get(peer_addr)
            .and_then(|c| c.extension.clone())
            .filter(|ext| {
                self.registrar
                    .lookup(ext)
                    .is_some_and(|reg| reg.transport_addr == *peer_addr)
            })
    }

    /// 注销连接
    fn remove_connection(&self, peer_addr: &SocketAddr) -> Option<String> {
        let mut conns = self.connections.write().unwrap();
        conns.remove(peer_addr).and_then(|c| c.extension)
    }
}

/// 启动 SIP TLS 服务器
pub async fn run(
    config: Arc<AppConfig>,
    tls_acceptor: ReloadableTlsAcceptor,
    registrar: Arc<RegistrarService>,
    media_manager: Arc<MediaRelayManager>,
) -> Result<(), Box<dyn std::error::Error>> {
    let media_addr = config.get_media_addr();
    let router = Arc::new(Router::new(
        Arc::clone(&registrar),
        Arc::clone(&media_manager),
        config.server.host.clone(),
        media_addr,
        config.extensions.range_start,
        config.extensions.range_end,
    ));

    let transaction_mgr = Arc::new(TransactionManager::new());
    transaction_mgr.start_cleanup_task();

    let state = Arc::new(ServerState {
        config: Arc::clone(&config),
        registrar,
        router,
        transaction_mgr,
        connections: RwLock::new(HashMap::new()),
    });

    let bind_addr = format!("{}:{}", config.server.listen_addr, config.server.sip_port);
    let listener = TcpListener::bind(&bind_addr).await?;
    tracing::info!("SIP TLS 服务器已绑定到 {}", bind_addr);

    let permits = Arc::new(Semaphore::new(256));
    let cleanup_router = state.router.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            cleanup_router.cleanup_expired_calls();
        }
    });
    loop {
        let (tcp_stream, peer_addr) = listener.accept().await?;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };

        let tls_acceptor = tls_acceptor.current();
        let state = Arc::clone(&state);

        tokio::spawn(async move {
            let _permit = permit;
            match tokio::time::timeout(Duration::from_secs(10), tls_acceptor.accept(tcp_stream))
                .await
            {
                Ok(Ok(tls_stream)) => {
                    tracing::info!("TLS 握手成功: {}", peer_addr);
                    if let Err(e) = handle_connection(tls_stream, peer_addr, state).await {
                        tracing::error!("处理连接 {} 时出错: {}", peer_addr, e);
                    }
                }
                _ => {
                    tracing::debug!("TLS 握手失败或超时 ({})", peer_addr);
                }
            }
        });
    }
}

/// 处理单个 TLS 连接
async fn handle_connection(
    tls_stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    peer_addr: SocketAddr,
    state: Arc<ServerState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (mut reader, mut writer) = tokio::io::split(tls_stream);

    // 创建写入通道
    let (writer_tx, mut writer_rx) = mpsc::channel::<Vec<u8>>(16);

    // 注册连接
    state.register_connection(peer_addr, writer_tx.clone());

    // 写入任务：从通道接收数据，写入 TLS 流
    let write_state = Arc::clone(&state);
    let mut write_handle = tokio::spawn(async move {
        while let Some(data) = writer_rx.recv().await {
            if !matches!(
                tokio::time::timeout(Duration::from_secs(10), writer.write_all(&data)).await,
                Ok(Ok(()))
            ) {
                tracing::debug!("写入 TLS 流失败或超时");
                break;
            }
            if let Some(ext) = write_state.get_connection_extension(&peer_addr) {
                write_state.router.deliver_offline_messages(&ext).await;
            }
            if let Err(e) = writer.flush().await {
                tracing::error!("刷新 TLS 流失败: {}", e);
                break;
            }
        }
    });

    // 读取循环
    let mut buffer = Vec::with_capacity(16384);
    let mut read_buf = [0u8; 8192];
    let mut frame_started = tokio::time::Instant::now();
    let mut rate_started = std::time::Instant::now();
    let mut requests = 0;

    'read_loop: loop {
        let deadline = if buffer.is_empty() {
            tokio::time::Instant::now()
                + Duration::from_secs(if state.get_connection_extension(&peer_addr).is_some() {
                    3600
                } else {
                    120
                })
        } else {
            frame_started + Duration::from_secs(15)
        };
        let result = tokio::select! {
            _ = &mut write_handle => break,
            result = tokio::time::timeout_at(deadline, reader.read(&mut read_buf)) => result,
        };
        let Ok(result) = result else {
            break;
        };
        let n = match result {
            Ok(0) => {
                tracing::info!("连接关闭: {}", peer_addr);
                break;
            }
            Ok(n) => n,
            Err(e) => {
                tracing::error!("读取错误 ({}): {}", peer_addr, e);
                break;
            }
        };

        if buffer.is_empty() {
            frame_started = tokio::time::Instant::now();
        }
        buffer.extend_from_slice(&read_buf[..n]);

        // 尝试从缓冲区中提取完整的 SIP 消息
        loop {
            match parser::frame_sip_message(&buffer) {
                parser::SipFrameResult::Complete(msg_len) => {
                    if rate_started.elapsed() >= Duration::from_secs(60) {
                        rate_started = std::time::Instant::now();
                        requests = 0;
                    }
                    requests += 1;
                    if requests > 300 {
                        break 'read_loop;
                    }
                    let msg_data = buffer[..msg_len].to_vec();
                    buffer.drain(..msg_len);

                    // 处理 SIP 消息
                    if let Ok(msg_text) = std::str::from_utf8(&msg_data) {
                        if tokio::time::timeout(
                            Duration::from_secs(10),
                            process_sip_message(msg_text, peer_addr, writer_tx.clone(), &state),
                        )
                        .await
                        .is_err()
                        {
                            break 'read_loop;
                        }
                    } else {
                        tracing::warn!("收到非 UTF-8 SIP 消息 来自 {}", peer_addr);
                    }
                }
                parser::SipFrameResult::Incomplete => break,
                parser::SipFrameResult::Invalid => {
                    tracing::warn!("收到非法 SIP 消息帧，断开连接: {}", peer_addr);
                    break 'read_loop;
                }
            }
        }

        // 防止缓冲区无限增长
        if buffer.len() > 65536 {
            tracing::warn!("缓冲区溢出，断开连接: {}", peer_addr);
            break;
        }
    }

    state.router.cleanup_disconnected(&writer_tx);
    // 连接断开，清理
    let extension = state.remove_connection(&peer_addr);
    state.registrar.disconnect(peer_addr);
    if let Some(ext) = &extension {
        tracing::info!("分机 {} 断开连接", ext);
        if let Some(writer) = state.find_writer_by_extension(ext) {
            state.router.register_writer(ext, writer);
        } else {
            state.router.unregister_writer(ext);
        }
    }

    write_handle.abort();
    Ok(())
}

/// 处理一条完整的 SIP 消息
async fn process_sip_message(
    msg_text: &str,
    peer_addr: SocketAddr,
    writer_tx: mpsc::Sender<Vec<u8>>,
    state: &Arc<ServerState>,
) {
    if msg_text.trim().is_empty() {
        tracing::debug!("忽略 SIP keepalive 空包: {}", peer_addr);
        return;
    }

    // Contact values are later used in outbound request lines.
    if parser::extract_contact_uri(msg_text).is_some_and(|uri| {
        uri.chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '<' | '>' | '"'))
    }) {
        return;
    }

    if parser::is_request(msg_text) {
        // 处理 SIP 请求
        let method = match parser::extract_method(msg_text) {
            Some(m) => m,
            None => {
                tracing::warn!("无法提取 SIP 方法: {}", peer_addr);
                return;
            }
        };

        if parser::extract_cseq_method(msg_text).as_deref() != Some(method.as_str()) {
            let _ = writer_tx
                .send(parser::build_response(msg_text, 400, "Bad Request"))
                .await;
            return;
        }
        tracing::debug!("收到 {} 请求 来自 {}", method, peer_addr);

        let authenticated = state.get_connection_extension(&peer_addr);
        if !matches!(method.as_str(), "REGISTER" | "OPTIONS") {
            let from = parser::extract_uri_from_header(msg_text, "From")
                .and_then(|u| parser::extract_extension(&u));
            if authenticated.is_none() || from != authenticated {
                let _ = writer_tx
                    .send(parser::build_response(msg_text, 403, "Forbidden"))
                    .await;
                return;
            }
            if matches!(method.as_str(), "ACK" | "BYE" | "CANCEL")
                && !state
                    .router
                    .authorizes_dialog(msg_text, &writer_tx, &method)
            {
                if method != "ACK" {
                    let _ = writer_tx
                        .send(parser::build_response(
                            msg_text,
                            481,
                            "Call/Transaction Does Not Exist",
                        ))
                        .await;
                }
                return;
            }
        }
        // One identity per connection prevents stale writer aliases after account switches.
        if method == "REGISTER" {
            let old = state
                .connections
                .read()
                .unwrap()
                .get(&peer_addr)
                .and_then(|c| c.extension.clone());
            let new = parser::extract_uri_from_header(msg_text, "To")
                .and_then(|u| parser::extract_extension(&u));
            if old.is_some() && old != new {
                let _ = writer_tx
                    .send(parser::build_response(msg_text, 403, "Forbidden"))
                    .await;
                return;
            }
        }
        match method.as_str() {
            "REGISTER" => {
                let response = state.registrar.handle_register(msg_text, peer_addr);

                // 检查是否注册成功（200 OK）
                let mut pending_delivery: Option<(Arc<Router>, String)> = None;
                if let Ok(resp_text) = std::str::from_utf8(&response) {
                    if parser::extract_status_code(resp_text) == Some(200) {
                        // 提取分机号并关联连接
                        if let Some(uri) = parser::extract_uri_from_header(msg_text, "To") {
                            if let Some(ext) = parser::extract_extension(&uri) {
                                if parser::extract_expires(msg_text) == Some(0) {
                                    state.router.cleanup_disconnected(&writer_tx);
                                    state.clear_connection_extension(&peer_addr);
                                    if let Some(writer) = state.find_writer_by_extension(&ext) {
                                        state.router.register_writer(&ext, writer);
                                    } else {
                                        state.router.unregister_writer(&ext);
                                    }
                                    tracing::info!("分机 {} 已显式注销连接 {}", ext, peer_addr);
                                } else {
                                    state.set_connection_extension(&peer_addr, ext.clone());
                                    state.router.register_writer(&ext, writer_tx.clone());
                                    tracing::info!("分机 {} 已关联连接 {}", ext, peer_addr);
                                    // 注册成功：稍后后台补投该分机的离线即时消息
                                    pending_delivery = Some((Arc::clone(&state.router), ext));
                                }
                            }
                        }
                    }
                }

                // 先回 200 OK，避免离线补投（最多串行发送 100 条，通道容量有限）
                // 阻塞注册确认
                let _ = writer_tx.send(response).await;
                if let Some((router, ext)) = pending_delivery {
                    tokio::spawn(async move {
                        router.deliver_offline_messages(&ext).await;
                    });
                }
            }
            "INVITE" => {
                let response = state
                    .router
                    .handle_invite(msg_text, writer_tx.clone())
                    .await;
                let _ = writer_tx.send(response).await;
            }
            "ACK" => {
                state.router.handle_ack(msg_text).await;
            }
            "BYE" => {
                let from_ext = state
                    .get_connection_extension(&peer_addr)
                    .unwrap_or_default();
                let response = state.router.handle_bye(msg_text, &from_ext).await;
                let _ = writer_tx.send(response).await;
            }
            "CANCEL" => {
                let response = state.router.handle_cancel(msg_text).await;
                let _ = writer_tx.send(response).await;
            }
            "MESSAGE" => {
                // 即时消息：主叫分机号取自连接认证的分机（不信任 From 头）
                let from_ext = state
                    .get_connection_extension(&peer_addr)
                    .unwrap_or_default();
                let response = state.router.handle_message(msg_text, &from_ext).await;
                let _ = writer_tx.send(response).await;
            }
            "OPTIONS" => {
                // 心跳 / 能力查询 — 直接回 200 OK
                let response = parser::build_response_with_headers(
                    msg_text,
                    200,
                    "OK",
                    &[
                        (
                            "Allow",
                            "INVITE, ACK, BYE, CANCEL, REGISTER, OPTIONS, MESSAGE",
                        ),
                        ("Accept", "application/sdp"),
                    ],
                );
                let _ = writer_tx.send(response).await;
            }
            _ => {
                tracing::debug!("不支持的方法: {}", method);
                let response = parser::build_response(msg_text, 405, "Method Not Allowed");
                let _ = writer_tx.send(response).await;
            }
        }
    } else if parser::is_response(msg_text) {
        // 处理 SIP 响应（来自被叫的响应，需要转发回主叫）
        let cseq_method = parser::extract_cseq_method(msg_text);

        if cseq_method.as_deref() == Some("INVITE")
            && state.get_connection_extension(&peer_addr).is_some()
            && state
                .router
                .authorizes_dialog(msg_text, &writer_tx, "RESPONSE")
        {
            state.router.handle_callee_response(msg_text).await;
        } else {
            tracing::debug!("收到非 INVITE 的响应: {:?}", cseq_method);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::registrar::Registration;
    use super::*;

    fn fixture() -> Arc<ServerState> {
        let config: AppConfig = toml::from_str(include_str!("../../config.template.toml")).unwrap();
        let registrar = Arc::new(RegistrarService::new(
            "example.com".into(),
            "secret".into(),
            HashMap::new(),
            1000,
            2000,
        ));
        let router = Arc::new(Router::new(
            registrar.clone(),
            Arc::new(MediaRelayManager::new(20000, 20020, "127.0.0.1".into())),
            "example.com".into(),
            "127.0.0.1".into(),
            1000,
            2000,
        ));
        Arc::new(ServerState {
            config: Arc::new(config),
            registrar,
            router,
            transaction_mgr: Arc::new(TransactionManager::new()),
            connections: RwLock::new(HashMap::new()),
        })
    }

    fn connect(
        state: &ServerState,
        ext: &str,
        port: u16,
    ) -> (SocketAddr, mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) {
        let peer = SocketAddr::from(([127, 0, 0, 1], port));
        let (tx, rx) = mpsc::channel(16);
        state.register_connection(peer, tx.clone());
        state.set_connection_extension(&peer, ext.into());
        state.registrar.register(Registration {
            extension: ext.into(),
            contact: format!("sip:{ext}@example.com"),
            expires_at: u64::MAX,
            transport_addr: peer,
        });
        state.router.register_writer(ext, tx.clone());
        (peer, tx, rx)
    }

    fn request(method: &str, from: &str, body: &str) -> String {
        format!("{method} sip:1002@example.com SIP/2.0\r\nFrom: <sip:{from}@example.com>;tag=caller\r\nTo: <sip:1002@example.com>\r\nCall-ID: security-call\r\nCSeq: 1 {method}\r\nContent-Length: {}\r\n\r\n{body}", body.len())
    }

    #[tokio::test]
    async fn rejects_unauthenticated_requests_and_spoofed_identity() {
        let state = fixture();
        let peer = "127.0.0.1:1234".parse().unwrap();
        let (tx, mut rx) = mpsc::channel(16);
        state.register_connection(peer, tx.clone());
        for method in ["INVITE", "BYE", "CANCEL", "MESSAGE"] {
            process_sip_message(&request(method, "1001", ""), peer, tx.clone(), &state).await;
            assert!(String::from_utf8(rx.try_recv().unwrap())
                .unwrap()
                .contains("403 Forbidden"));
        }
        let (peer, tx, mut rx) = connect(&state, "1001", 1235);
        process_sip_message(&request("INVITE", "1999", ""), peer, tx, &state).await;
        assert!(String::from_utf8(rx.try_recv().unwrap())
            .unwrap()
            .contains("403 Forbidden"));
    }

    #[tokio::test]
    async fn dialog_actions_require_original_connection_and_correct_side() {
        let state = fixture();
        let (caller, caller_tx, mut caller_rx) = connect(&state, "1001", 1234);
        let (callee, callee_tx, mut callee_rx) = connect(&state, "1002", 1235);
        let (attacker, attacker_tx, mut attacker_rx) = connect(&state, "1003", 1236);
        let sdp = "v=0\r\nc=IN IP4 127.0.0.1\r\nm=audio 4000 RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n";
        process_sip_message(
            &request("INVITE", "1001", sdp),
            caller,
            caller_tx.clone(),
            &state,
        )
        .await;
        assert!(String::from_utf8(caller_rx.try_recv().unwrap())
            .unwrap()
            .contains("100 Trying"));
        assert!(callee_rx.try_recv().is_ok());
        process_sip_message(
            &request("BYE", "1003", ""),
            attacker,
            attacker_tx.clone(),
            &state,
        )
        .await;
        assert!(String::from_utf8(attacker_rx.try_recv().unwrap())
            .unwrap()
            .contains("481"));
        assert!(state.router.has_active_call("security-call"));
        for method in ["ACK", "CANCEL", "BYE"] {
            assert!(!state.router.authorizes_dialog(
                &request(method, "1003", ""),
                &attacker_tx,
                method
            ));
        }
        assert!(!state.router.authorizes_dialog(
            &request("CANCEL", "1002", ""),
            &callee_tx,
            "CANCEL"
        ));
        let response = "SIP/2.0 486 Busy Here\r\nCall-ID: security-call\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n";
        process_sip_message(response, attacker, attacker_tx, &state).await;
        assert!(caller_rx.try_recv().is_err());
        assert!(state.router.has_active_call("security-call"));
        process_sip_message(response, callee, callee_tx, &state).await;
        assert!(String::from_utf8(caller_rx.try_recv().unwrap())
            .unwrap()
            .contains("486"));
        assert!(!state.router.has_active_call("security-call"));
    }

    #[test]
    fn expired_or_replaced_registration_revokes_connection_identity() {
        let state = fixture();
        let (old, _, _) = connect(&state, "1001", 1234);
        let (new, _, _) = connect(&state, "1001", 1235);
        assert!(state.get_connection_extension(&old).is_none());
        assert_eq!(
            state.get_connection_extension(&new).as_deref(),
            Some("1001")
        );
        state.registrar.unregister("1001");
        assert!(state.get_connection_extension(&new).is_none());
    }
}
