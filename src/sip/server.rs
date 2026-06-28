//! SIP TLS 服务器模块
//!
//! 核心服务器循环：TLS 监听 → 消息帧分界 → 解析分发 → 响应回写。
//! 每个连接维护独立的读写任务，通过 mpsc 通道解耦。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

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
            if conn.extension.as_deref() == Some(ext) {
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

    /// 检查是否仍有其他连接关联到指定分机
    fn has_connection_for_extension(&self, ext: &str) -> bool {
        let conns = self.connections.read().unwrap();
        conns
            .values()
            .any(|conn| conn.extension.as_deref() == Some(ext))
    }

    /// 获取连接的分机号
    fn get_connection_extension(&self, peer_addr: &SocketAddr) -> Option<String> {
        let conns = self.connections.read().unwrap();
        conns.get(peer_addr).and_then(|c| c.extension.clone())
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

    loop {
        let (tcp_stream, peer_addr) = listener.accept().await?;
        tracing::info!("新的 TCP 连接来自: {}", peer_addr);

        let tls_acceptor = tls_acceptor.current();
        let state = Arc::clone(&state);

        tokio::spawn(async move {
            match tls_acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => {
                    tracing::info!("TLS 握手成功: {}", peer_addr);
                    if let Err(e) = handle_connection(tls_stream, peer_addr, state).await {
                        tracing::error!("处理连接 {} 时出错: {}", peer_addr, e);
                    }
                }
                Err(e) => {
                    tracing::warn!("TLS 握手失败 ({}): {}", peer_addr, e);
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
    let (writer_tx, mut writer_rx) = mpsc::channel::<Vec<u8>>(64);

    // 注册连接
    state.register_connection(peer_addr, writer_tx.clone());

    // 写入任务：从通道接收数据，写入 TLS 流
    let write_handle = tokio::spawn(async move {
        while let Some(data) = writer_rx.recv().await {
            if let Err(e) = writer.write_all(&data).await {
                tracing::error!("写入 TLS 流失败: {}", e);
                break;
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

    loop {
        let n = match reader.read(&mut read_buf).await {
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

        buffer.extend_from_slice(&read_buf[..n]);

        // 尝试从缓冲区中提取完整的 SIP 消息
        loop {
            match parser::frame_sip_message(&buffer) {
                Some(msg_len) => {
                    let msg_data = buffer[..msg_len].to_vec();
                    buffer.drain(..msg_len);

                    // 处理 SIP 消息
                    if let Ok(msg_text) = std::str::from_utf8(&msg_data) {
                        process_sip_message(msg_text, peer_addr, writer_tx.clone(), &state).await;
                    } else {
                        tracing::warn!("收到非 UTF-8 SIP 消息 来自 {}", peer_addr);
                    }
                }
                None => break, // 缓冲区中无完整消息，继续读取
            }
        }

        // 防止缓冲区无限增长
        if buffer.len() > 65536 {
            tracing::warn!("缓冲区溢出，断开连接: {}", peer_addr);
            break;
        }
    }

    // 连接断开，清理
    let extension = state.remove_connection(&peer_addr);
    if let Some(ext) = &extension {
        tracing::info!("分机 {} 断开连接", ext);
        if !state.has_connection_for_extension(ext) {
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

    if parser::is_request(msg_text) {
        // 处理 SIP 请求
        let method = match parser::extract_method(msg_text) {
            Some(m) => m,
            None => {
                tracing::warn!("无法提取 SIP 方法: {}", peer_addr);
                return;
            }
        };

        tracing::debug!("收到 {} 请求 来自 {}", method, peer_addr);

        match method.as_str() {
            "REGISTER" => {
                let response = state.registrar.handle_register(msg_text, peer_addr);

                // 检查是否注册成功（200 OK）
                if let Ok(resp_text) = std::str::from_utf8(&response) {
                    if parser::extract_status_code(resp_text) == Some(200) {
                        // 提取分机号并关联连接
                        if let Some(uri) = parser::extract_uri_from_header(msg_text, "To") {
                            if let Some(ext) = parser::extract_extension(&uri) {
                                if parser::extract_expires(msg_text) == Some(0) {
                                    state.clear_connection_extension(&peer_addr);
                                    state.router.unregister_writer(&ext);
                                    tracing::info!("分机 {} 已显式注销连接 {}", ext, peer_addr);
                                } else {
                                    state.set_connection_extension(&peer_addr, ext.clone());
                                    state.router.register_writer(&ext, writer_tx.clone());
                                    tracing::info!("分机 {} 已关联连接 {}", ext, peer_addr);
                                }
                            }
                        }
                    }
                }

                let _ = writer_tx.send(response).await;
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
            "OPTIONS" => {
                // 心跳 / 能力查询 — 直接回 200 OK
                let response = parser::build_response_with_headers(
                    msg_text,
                    200,
                    "OK",
                    &[
                        ("Allow", "INVITE, ACK, BYE, CANCEL, REGISTER, OPTIONS"),
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

        if cseq_method.as_deref() == Some("INVITE") {
            state.router.handle_callee_response(msg_text).await;
        } else {
            tracing::debug!("收到非 INVITE 的响应: {:?}", cseq_method);
        }
    }
}
