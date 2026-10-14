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
) -> Result<(), Box<dyn std::error::Error>> {
    let mut router = Router::new(
        Arc::clone(&registrar),
        config.server.host.clone(),
        config.extensions.range_start,
        config.extensions.range_end,
    );
    if let Some(media) = &config.media {
        router = router.with_media(
            media,
            config.extensions.range_start,
            config.extensions.range_end,
        );
    }
    let router = Arc::new(router);

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
        // Offerless calls are unsupported; dialog control cannot carry a second
        // unvalidated offer or accidentally forward SDES/plaintext content.
        if matches!(method.as_str(), "ACK" | "BYE" | "CANCEL")
            && parser::extract_body(msg_text).is_some()
        {
            if method != "ACK" {
                let _ = writer_tx
                    .send(parser::build_response(
                        msg_text,
                        415,
                        "Unsupported Media Type",
                    ))
                    .await;
            }
            return;
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
                        ("Accept", "application/sdp, application/jose"),
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

    #[tokio::test]
    async fn bria_profile_routes_call_and_relays_bidirectional_encrypted_audio() {
        use crate::media::srtp::{SrtpCryptoSuite, SrtpSuite};
        use tokio::net::UdpSocket;
        use tokio::time::{timeout, Duration};
        // Reserve an available pair temporarily so concurrent tests use distinct ports.
        let (port, a, b) = {
            let mut pair = None;
            for p in (30000..60000).step_by(4) {
                if let (Ok(a), Ok(b)) = (
                    UdpSocket::bind(("0.0.0.0", p)).await,
                    UdpSocket::bind(("0.0.0.0", p + 2)).await,
                ) {
                    pair = Some((p, a, b));
                    break;
                }
            }
            pair.expect("available relay ports")
        };
        let mut state = fixture();
        let inner = Arc::get_mut(&mut state).unwrap();
        inner.router = Arc::new(
            Router::new(inner.registrar.clone(), "example.com".into(), 1000, 2000).with_media(
                &crate::config::MediaConfig {
                    mode: crate::config::MediaMode::Sdes,
                    rtp_port_start: port,
                    rtp_port_end: port + 4,
                    media_addr: "127.0.0.1".into(),
                },
                1000,
                2000,
            ),
        );
        let (caller, caller_tx, mut caller_rx) = connect(&state, "1001", 15001);
        let (callee, callee_tx, mut callee_rx) = connect(&state, "1002", 15002);
        let mut caller_crypto = SrtpCryptoSuite::new();
        let mut callee_crypto = SrtpCryptoSuite::new_with_suite(SrtpSuite::AeadAes128Gcm);
        let offer = format!("v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 4000 RTP/SAVP 0\r\na=crypto:7 AES_CM_128_HMAC_SHA1_80 inline:{}\r\n", caller_crypto.to_sdes_key());
        // A signed E2EE offer must not silently enter the key-terminating relay.
        process_sip_message(
            &request("INVITE", "1001", &offer),
            caller,
            caller_tx.clone(),
            &state,
        )
        .await;
        assert_eq!(
            parser::extract_status_code(
                std::str::from_utf8(&caller_rx.recv().await.unwrap()).unwrap()
            ),
            Some(488)
        );
        assert!(callee_rx.try_recv().is_err());
        let invite = request("INVITE", "1001", &offer)
            .lines()
            .filter(|l| !l.starts_with("X-Minghe-Identity:"))
            .collect::<Vec<_>>()
            .join("\r\n")
            + "\r\n";
        process_sip_message(&invite, caller, caller_tx.clone(), &state).await;
        assert_eq!(
            parser::extract_status_code(
                std::str::from_utf8(&caller_rx.recv().await.unwrap()).unwrap()
            ),
            Some(100)
        );
        let outgoing = String::from_utf8(callee_rx.recv().await.unwrap()).unwrap();
        let body = parser::extract_body(&outgoing).unwrap();
        assert!(body.contains(&format!("m=audio {} RTP/SAVP", port + 2)));
        assert!(!body.contains("c=IN IP4 10.0.0.1"));
        let key = body.lines().find(|l| l.starts_with("a=crypto:2 ")).unwrap();
        let (_, suite, key) = crate::media::srtp::parse_crypto_attribute(key).unwrap();
        let mut callee_receive =
            SrtpCryptoSuite::from_sdes_with_suite(SrtpSuite::from_sdp_name(&suite).unwrap(), &key)
                .unwrap();
        let answer = format!("v=0\r\no=- 1 1 IN IP4 10.1.0.1\r\ns=-\r\nc=IN IP4 10.1.0.1\r\nt=0 0\r\nm=audio 5000 RTP/SAVP 0\r\na=crypto:2 AEAD_AES_128_GCM inline:{}\r\n", callee_crypto.to_sdes_key());
        let response = format!("SIP/2.0 200 OK\r\nFrom: <sip:1001@example.com>;tag=caller\r\nTo: <sip:1002@example.com>;tag=callee\r\nContact: <sip:1002@example.com>\r\nCall-ID: security-call\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{}", answer.len(), answer);
        drop((a, b));
        process_sip_message(&response, callee, callee_tx, &state).await;
        let response = String::from_utf8(caller_rx.recv().await.unwrap()).unwrap();
        let body = parser::extract_body(&response).unwrap();
        assert!(body.contains(&format!("m=audio {} RTP/SAVP", port)));
        let key = body.lines().find(|l| l.starts_with("a=crypto:7 ")).unwrap();
        let (_, _, key) = crate::media::srtp::parse_crypto_attribute(key).unwrap();
        let mut caller_receive = SrtpCryptoSuite::from_sdes(&key).unwrap();
        process_sip_message(
            &request("ACK", "1001", ""),
            caller,
            caller_tx.clone(),
            &state,
        )
        .await;
        assert!(String::from_utf8(callee_rx.recv().await.unwrap())
            .unwrap()
            .starts_with("ACK "));
        let caller_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let callee_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut got_caller = false;
        let mut got_callee = false;
        timeout(Duration::from_secs(3), async {
            for seq in 1u16.. {
                let mut packet = vec![0x80, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1];
                packet[2..4].copy_from_slice(&seq.to_be_bytes());
                packet.extend_from_slice(b"audio-frame");
                caller_udp
                    .send_to(
                        &caller_crypto.protect_rtp(&packet).unwrap(),
                        ("127.0.0.1", port),
                    )
                    .await
                    .unwrap();
                callee_udp
                    .send_to(
                        &callee_crypto.protect_rtp(&packet).unwrap(),
                        ("127.0.0.1", port + 2),
                    )
                    .await
                    .unwrap();
                let mut buffer = [0; 2048];
                if let Ok(Ok((n, _))) =
                    timeout(Duration::from_millis(20), caller_udp.recv_from(&mut buffer)).await
                {
                    assert_eq!(
                        &caller_receive.unprotect_rtp(&buffer[..n]).unwrap()[12..],
                        b"audio-frame"
                    );
                    got_caller = true;
                }
                if let Ok(Ok((n, _))) =
                    timeout(Duration::from_millis(20), callee_udp.recv_from(&mut buffer)).await
                {
                    assert_eq!(
                        &callee_receive.unprotect_rtp(&buffer[..n]).unwrap()[12..],
                        b"audio-frame"
                    );
                    got_callee = true;
                }
                if got_caller && got_callee {
                    break;
                }
            }
        })
        .await
        .expect("both directions must carry decryptable audio");
        process_sip_message(&request("BYE", "1001", ""), caller, caller_tx, &state).await;
        assert!(!state.router.has_active_call("security-call"));
    }

    #[tokio::test]
    async fn zrtp_profile_routes_hashes_and_opaque_bidirectional_srtp() {
        zrtp_profile_test("").await;
    }

    #[tokio::test]
    async fn zrtp_profile_rejects_answer_downgrade() {
        zrtp_profile_test("downgrade").await;
    }

    #[tokio::test]
    async fn zrtp_profile_rejects_unavailable_udp_ports() {
        zrtp_profile_test("bind").await;
    }

    #[tokio::test]
    async fn zrtp_profile_rejects_changed_hello_after_early_media() {
        zrtp_profile_test("early").await;
    }

    async fn zrtp_profile_test(failure: &str) {
        use crate::media::{srtp::SrtpCryptoSuite, zrtp};
        use tokio::{
            net::UdpSocket,
            time::{timeout, Duration},
        };
        let (port, reservation) = {
            let mut pair = None;
            let start = match failure {
                "downgrade" => 23000,
                "bind" => 26000,
                "early" => 17000,
                _ => 20000,
            };
            for p in (start..start + 3000).step_by(4) {
                if let Ok(sockets) = zrtp::bind(p, p + 2).await {
                    pair = Some((p, sockets));
                    break;
                }
            }
            pair.expect("four available relay ports")
        };
        let mut state = fixture();
        let inner = Arc::get_mut(&mut state).unwrap();
        inner.router = Arc::new(
            Router::new(inner.registrar.clone(), "example.com".into(), 1000, 2000).with_media(
                &crate::config::MediaConfig {
                    mode: crate::config::MediaMode::Zrtp,
                    rtp_port_start: port,
                    rtp_port_end: port + 4,
                    media_addr: "127.0.0.1".into(),
                },
                1000,
                2000,
            ),
        );
        let (caller, caller_tx, mut caller_rx) = connect(&state, "1001", 16001);
        let (callee, callee_tx, mut callee_rx) = connect(&state, "1002", 16002);
        let (caller_hello, caller_hash) = zrtp::tests::hello(1);
        let (callee_hello, callee_hash) = zrtp::tests::hello(2);
        let sdp = |hash: &str| {
            format!("v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\na=zrtp-hash:1.10 {hash}\r\n")
        };
        let invite = |body: &str| {
            request("INVITE", "1001", body)
                .lines()
                .filter(|l| !l.starts_with("X-Minghe-Identity:"))
                .collect::<Vec<_>>()
                .join("\r\n")
                + "\r\n"
        };
        // Neither plaintext-only nor SDES calls may enter the ZRTP profile.
        process_sip_message(
            &invite(&sdp(&caller_hash).replace("a=zrtp-hash:", "a=unknown:")),
            caller,
            caller_tx.clone(),
            &state,
        )
        .await;
        assert_eq!(
            parser::extract_status_code(
                std::str::from_utf8(&caller_rx.recv().await.unwrap()).unwrap()
            ),
            Some(488)
        );
        process_sip_message(
            &invite(&sdp(&caller_hash)),
            caller,
            caller_tx.clone(),
            &state,
        )
        .await;
        assert_eq!(
            parser::extract_status_code(
                std::str::from_utf8(&caller_rx.recv().await.unwrap()).unwrap()
            ),
            Some(100)
        );
        let forwarded = String::from_utf8(callee_rx.recv().await.unwrap()).unwrap();
        assert!(forwarded.contains(&caller_hash));
        assert!(forwarded.contains(&format!("m=audio {} RTP/AVP", port + 2)));
        assert!(!forwarded.contains("a=crypto:"));
        let answer = if failure == "downgrade" {
            sdp(&callee_hash).replace("a=zrtp-hash:", "a=unknown:")
        } else {
            sdp(&callee_hash)
        };
        let response = format!("SIP/2.0 200 OK\r\nFrom: <sip:1001@example.com>;tag=caller\r\nTo: <sip:1002@example.com>;tag=callee\r\nContact: <sip:1002@example.com>\r\nCall-ID: security-call\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{}", answer.len(), answer);
        let reservation = if failure == "bind" {
            Some(reservation)
        } else {
            drop(reservation);
            None
        };
        if failure == "early" {
            let early = response.replace("SIP/2.0 200 OK", "SIP/2.0 183 Session Progress");
            process_sip_message(&early, callee, callee_tx.clone(), &state).await;
            let early = String::from_utf8(caller_rx.recv().await.unwrap()).unwrap();
            assert_eq!(parser::extract_status_code(&early), Some(183));
        }
        let response = if failure == "early" {
            response.replace(&callee_hash, &caller_hash)
        } else {
            response
        };
        process_sip_message(&response, callee, callee_tx, &state).await;
        let forwarded = String::from_utf8(caller_rx.recv().await.unwrap()).unwrap();
        if !failure.is_empty() {
            assert_eq!(parser::extract_status_code(&forwarded), Some(488));
            assert!(!state.router.has_active_call("security-call"));
            for method in ["ACK ", "BYE "] {
                assert!(String::from_utf8(callee_rx.recv().await.unwrap())
                    .unwrap()
                    .starts_with(method));
            }
            drop(reservation);
            timeout(Duration::from_secs(1), async {
                loop {
                    if zrtp::bind(port, port + 2).await.is_ok() {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("rejected answer releases relay sockets");
            return;
        }
        assert!(forwarded.contains(&callee_hash));
        assert!(forwarded.contains(&format!("m=audio {port} RTP/AVP")));
        assert!(forwarded.contains(&format!("a=rtcp:{}", port + 1)));
        process_sip_message(
            &request("ACK", "1001", ""),
            caller,
            caller_tx.clone(),
            &state,
        )
        .await;
        assert!(String::from_utf8(callee_rx.recv().await.unwrap())
            .unwrap()
            .starts_with("ACK "));
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut buffer = [0; 4096];
        // Invalid Hello cannot seize the destination, even before the real endpoint arrives.
        attacker
            .send_to(&callee_hello, ("127.0.0.1", port))
            .await
            .unwrap();
        a.send_to(&caller_hello, ("127.0.0.1", port)).await.unwrap();
        b.send_to(&callee_hello, ("127.0.0.1", port + 2))
            .await
            .unwrap();
        let (n, _) = timeout(Duration::from_secs(1), a.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..n], &callee_hello);
        let (n, _) = timeout(Duration::from_secs(1), b.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..n], &caller_hello);
        // Other handshake messages are passed through without termination or rewriting.
        for kind in [
            b"HelloACK",
            b"Commit  ",
            b"DHPart1 ",
            b"DHPart2 ",
            b"Confirm1",
            b"Confirm2",
            b"Conf2ACK",
        ] {
            let mut handshake = caller_hello[..12].to_vec();
            handshake.extend([0x50, 0x5a, 0, 3]);
            handshake.extend(kind);
            handshake.extend([0; 4]);
            a.send_to(&handshake, ("127.0.0.1", port)).await.unwrap();
            let (n, _) = timeout(Duration::from_secs(1), b.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buffer[..n], &handshake);
        }
        // Simulated endpoint keys: this test checks transparent media transport,
        // not a real ZRTP key exchange. The relay never receives either key.
        let mut a_crypto = SrtpCryptoSuite::new();
        let mut b_crypto = SrtpCryptoSuite::new();
        let mut receive_a = b_crypto.clone();
        let mut receive_b = a_crypto.clone();
        let frame = [0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 10, 20, 30];
        let encrypted_a = a_crypto.protect_rtp(&frame).unwrap();
        let encrypted_b = b_crypto.protect_rtp(&frame).unwrap();
        a.send_to(&encrypted_a, ("127.0.0.1", port)).await.unwrap();
        b.send_to(&encrypted_b, ("127.0.0.1", port + 2))
            .await
            .unwrap();
        let (n, _) = timeout(Duration::from_secs(1), b.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..n], &encrypted_a);
        assert_eq!(receive_b.unprotect_rtp(&buffer[..n]).unwrap(), frame);
        let (n, _) = timeout(Duration::from_secs(1), a.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..n], &encrypted_b);
        assert_eq!(receive_a.unprotect_rtp(&buffer[..n]).unwrap(), frame);
        attacker
            .send_to(&caller_hello, ("127.0.0.1", port))
            .await
            .unwrap();
        assert!(timeout(Duration::from_millis(50), b.recv_from(&mut buffer))
            .await
            .is_err());
        // Separate SRTCP ports also preserve bytes and do not require RTCP mux.
        let ar = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let br = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rtcp = [0x80, 200, 0, 1, 0, 0, 0, 1, 99, 88, 77, 66];
        timeout(Duration::from_secs(1), async {
            let mut got_a = false;
            let mut got_b = false;
            while !got_a || !got_b {
                ar.send_to(&rtcp, ("127.0.0.1", port + 1)).await.unwrap();
                br.send_to(&rtcp, ("127.0.0.1", port + 3)).await.unwrap();
                if let Ok(Ok((n, _))) =
                    timeout(Duration::from_millis(10), ar.recv_from(&mut buffer)).await
                {
                    assert_eq!(&buffer[..n], &rtcp);
                    got_a = true;
                }
                if let Ok(Ok((n, _))) =
                    timeout(Duration::from_millis(10), br.recv_from(&mut buffer)).await
                {
                    assert_eq!(&buffer[..n], &rtcp);
                    got_b = true;
                }
            }
        })
        .await
        .expect("RTCP in both directions");
        process_sip_message(&request("BYE", "1001", ""), caller, caller_tx, &state).await;
        assert!(!state.router.has_active_call("security-call"));
        timeout(Duration::from_secs(1), async {
            loop {
                if zrtp::bind(port, port + 2).await.is_ok() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("BYE releases all four sockets");
    }

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
            "example.com".into(),
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
        let identity = if method == "INVITE" && !body.is_empty() {
            format!(
                "X-Minghe-Identity: {}\r\n",
                super::super::e2ee::test_identity(body, from, "1002", "security-call", "offer")
            )
        } else {
            String::new()
        };
        format!("{method} sip:1002@example.com SIP/2.0\r\nFrom: <sip:{from}@example.com>;tag=caller\r\nTo: <sip:1002@example.com>\r\nCall-ID: security-call\r\nCSeq: 1 {method}\r\nContent-Type: application/sdp\r\n{identity}Content-Length: {}\r\n\r\n{body}", body.len())
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
        let sdp = super::super::e2ee::test_sdp("actpass");
        process_sip_message(
            &request("INVITE", "1001", &sdp),
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

    fn answer(status: u16, sdp: &str, signed_sdp: &str) -> String {
        let identity = super::super::e2ee::test_identity(
            signed_sdp,
            "1002",
            "1001",
            "security-call",
            "answer",
        );
        format!("SIP/2.0 {status} OK\r\nFrom: <sip:1001@example.com>;tag=caller\r\nTo: <sip:1002@example.com>;tag=callee\r\nContact: <sip:1002@example.com>\r\nCall-ID: security-call\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nX-Minghe-Identity: {identity}\r\nContent-Length: {}\r\n\r\n{sdp}", sdp.len())
    }

    #[tokio::test]
    async fn e2ee_forwards_signed_offer_and_answer_without_changing_sdp() {
        let state = fixture();
        let (caller, caller_tx, mut caller_rx) = connect(&state, "1001", 1234);
        let (callee, callee_tx, mut callee_rx) = connect(&state, "1002", 1235);
        let offer = super::super::e2ee::test_sdp("actpass");
        let invite = request("INVITE", "1001", &offer);
        process_sip_message(&invite, caller, caller_tx.clone(), &state).await;
        let forwarded = String::from_utf8(callee_rx.try_recv().unwrap()).unwrap();
        assert_eq!(
            parser::extract_body(&forwarded).as_deref(),
            Some(offer.as_str())
        );
        assert_eq!(
            parser::extract_header_value(&forwarded, "X-Minghe-Identity"),
            parser::extract_header_value(&invite, "X-Minghe-Identity")
        );
        caller_rx.try_recv().unwrap();
        let sdp = super::super::e2ee::test_sdp("active");
        let response = answer(200, &sdp, &sdp);
        process_sip_message(&response, callee, callee_tx, &state).await;
        let forwarded = String::from_utf8(caller_rx.try_recv().unwrap()).unwrap();
        assert!(forwarded.starts_with("SIP/2.0 200"));
        assert_eq!(
            parser::extract_body(&forwarded).as_deref(),
            Some(sdp.as_str())
        );
        assert_eq!(
            parser::extract_header_value(&forwarded, "X-Minghe-Identity"),
            parser::extract_header_value(&response, "X-Minghe-Identity")
        );
        assert!(state.router.has_active_call("security-call"));
        process_sip_message(&request("ACK", "1001", ""), caller, caller_tx, &state).await;
        assert!(String::from_utf8(callee_rx.try_recv().unwrap())
            .unwrap()
            .starts_with("ACK "));
    }

    #[tokio::test]
    async fn e2ee_rejects_unsigned_and_sdes_offers_before_forwarding() {
        let state = fixture();
        let (caller, caller_tx, mut caller_rx) = connect(&state, "1001", 1234);
        let (_, _, mut callee_rx) = connect(&state, "1002", 1235);
        let sdp = super::super::e2ee::test_sdp("actpass");
        let signed = request("INVITE", "1001", &sdp);
        let unsigned = signed
            .lines()
            .filter(|l| !l.starts_with("X-Minghe-Identity:"))
            .collect::<Vec<_>>()
            .join("\r\n");
        let sdes = request(
            "INVITE",
            "1001",
            &sdp.replace("UDP/TLS/RTP/SAVPF", "RTP/SAVP"),
        );
        let changed = signed.replace("a=ice-ufrag:peer", "a=ice-ufrag:evil");
        for invalid in [unsigned, sdes, changed] {
            process_sip_message(&invalid, caller, caller_tx.clone(), &state).await;
            assert!(String::from_utf8(caller_rx.try_recv().unwrap())
                .unwrap()
                .contains("488"));
            assert!(callee_rx.try_recv().is_err());
            assert!(!state.router.has_active_call("security-call"));
        }
    }

    #[tokio::test]
    async fn e2ee_rejects_early_and_final_downgrades_and_releases_peer() {
        for status in [183, 200] {
            let state = fixture();
            let (caller, caller_tx, mut caller_rx) = connect(&state, "1001", 1234);
            let (callee, callee_tx, mut callee_rx) = connect(&state, "1002", 1235);
            let offer = super::super::e2ee::test_sdp("actpass");
            process_sip_message(
                &request("INVITE", "1001", &offer),
                caller,
                caller_tx,
                &state,
            )
            .await;
            let outbound = String::from_utf8(callee_rx.try_recv().unwrap()).unwrap();
            caller_rx.try_recv().unwrap();
            let sdp = super::super::e2ee::test_sdp("active");
            let downgraded = sdp.replace("UDP/TLS/RTP/SAVPF", "RTP/AVP");
            process_sip_message(
                &answer(status, &downgraded, &downgraded),
                callee,
                callee_tx,
                &state,
            )
            .await;
            let rejected = String::from_utf8(caller_rx.try_recv().unwrap()).unwrap();
            assert!(rejected.contains("488"));
            assert!(parser::extract_body(&rejected).is_none());
            assert!(!state.router.has_active_call("security-call"));
            let control = String::from_utf8(callee_rx.try_recv().unwrap()).unwrap();
            if status == 200 {
                assert!(control.starts_with("ACK "));
                let bye = String::from_utf8(callee_rx.try_recv().unwrap()).unwrap();
                assert!(bye.starts_with("BYE "));
                assert!(bye.contains("CSeq: 2 BYE"));
            } else {
                assert!(control.starts_with("CANCEL "));
                assert_eq!(
                    parser::extract_header_value(&control, "Via"),
                    parser::extract_header_value(&outbound, "Via")
                );
            }
        }
    }
}
