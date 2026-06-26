//! RTP/SRTP 媒体中继管理模块
//!
//! 管理 RTP 端口分配和媒体中继会话。
//! 每通通话分配两对 UDP 端口，分别面向主叫和被叫，
//! 作为 SRTP B2BUA：解密一侧的 SRTP，用另一侧的密钥重新加密后转发。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Mutex;
use tokio::net::UdpSocket;
use tokio::sync::watch;

use super::srtp::SrtpCryptoSuite;

/// 媒体中继会话信息
#[derive(Debug, Clone)]
pub struct RelaySession {
    /// 会话 ID (= Call-ID)
    pub session_id: String,
    /// 主叫方 RTP 中继端口
    pub caller_port: u16,
    /// 被叫方 RTP 中继端口
    pub callee_port: u16,
    /// 主叫方地址（从首个收到的包中学习）
    pub caller_addr: Option<SocketAddr>,
    /// 被叫方地址（从首个收到的包中学习）
    pub callee_addr: Option<SocketAddr>,
}

/// 媒体中继管理器
///
/// 负责 RTP 端口池的分配与回收，以及中继会话的生命周期管理。
pub struct MediaRelayManager {
    /// RTP 端口范围起始
    port_start: u16,
    /// RTP 端口范围结束
    port_end: u16,
    /// 下一个可分配的端口（原子操作）
    next_port: AtomicU16,
    /// 服务器媒体地址
    media_addr: String,
    /// 活跃的中继会话 (session_id -> RelaySession)
    sessions: Mutex<HashMap<String, RelaySession>>,
    /// 中继任务停止信号 (session_id -> sender)
    shutdown_senders: Mutex<HashMap<String, watch::Sender<bool>>>,
}

impl MediaRelayManager {
    /// 创建新的媒体中继管理器
    pub fn new(port_start: u16, port_end: u16, media_addr: String) -> Self {
        tracing::info!(
            "媒体中继管理器初始化: 端口范围 {}-{}, 媒体地址 {}",
            port_start,
            port_end,
            media_addr
        );
        Self {
            port_start,
            port_end,
            next_port: AtomicU16::new(port_start),
            media_addr,
            sessions: Mutex::new(HashMap::new()),
            shutdown_senders: Mutex::new(HashMap::new()),
        }
    }

    /// 分配一对 RTP/RTCP 端口（偶数为 RTP，偶数+1 为 RTCP）
    fn allocate_port_pair(&self) -> Option<u16> {
        let mut attempts = 0;
        loop {
            let port = self.next_port.fetch_add(2, Ordering::SeqCst);
            if port >= self.port_end {
                // 回绕
                let _ = self.next_port.compare_exchange(
                    port + 2,
                    self.port_start,
                    Ordering::SeqCst,
                    Ordering::Relaxed,
                );
                attempts += 1;
                if attempts > 3 {
                    tracing::error!("RTP 端口池已耗尽");
                    return None;
                }
                continue;
            }
            if port % 2 == 0 {
                tracing::debug!("分配 RTP 端口: {}", port);
                return Some(port);
            }
        }
    }

    /// 创建新的中继会话（如果已存在则返回现有会话）
    pub fn create_session(&self, session_id: String) -> Option<RelaySession> {
        // 检查是否已有此会话
        {
            let sessions = self.sessions.lock().unwrap();
            if let Some(existing) = sessions.get(&session_id) {
                tracing::debug!("媒体中继会话已存在: {}", session_id);
                return Some(existing.clone());
            }
        }

        let caller_port = self.allocate_port_pair()?;
        let callee_port = self.allocate_port_pair()?;

        let session = RelaySession {
            session_id: session_id.clone(),
            caller_port,
            callee_port,
            caller_addr: None,
            callee_addr: None,
        };

        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(session_id.clone(), session.clone());
        tracing::info!(
            "创建媒体中继会话 {}: 主叫端口={}, 被叫端口={}",
            session_id,
            caller_port,
            callee_port
        );

        Some(session)
    }

    /// 移除中继会话并停止中继任务
    pub fn remove_session(&self, session_id: &str) -> Option<RelaySession> {
        // 发送停止信号
        {
            let mut senders = self.shutdown_senders.lock().unwrap();
            if let Some(tx) = senders.remove(session_id) {
                let _ = tx.send(true);
                tracing::debug!("已发送中继停止信号: {}", session_id);
            }
        }

        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions.remove(session_id);
        if session.is_some() {
            tracing::info!("移除媒体中继会话: {}", session_id);
        }
        session
    }

    /// 注册停止信号发送器
    pub fn register_shutdown(&self, session_id: &str, tx: watch::Sender<bool>) {
        let mut senders = self.shutdown_senders.lock().unwrap();
        senders.insert(session_id.to_string(), tx);
    }

    /// 获取中继会话
    pub fn get_session(&self, session_id: &str) -> Option<RelaySession> {
        let sessions = self.sessions.lock().unwrap();
        sessions.get(session_id).cloned()
    }

    /// 获取媒体地址
    pub fn media_addr(&self) -> &str {
        &self.media_addr
    }

    /// 获取活跃会话数量
    pub fn active_session_count(&self) -> usize {
        let sessions = self.sessions.lock().unwrap();
        sessions.len()
    }
}

/// 运行 SRTP B2BUA 媒体中继
///
/// 为指定的呼叫建立两个 UDP socket，双向中继 SRTP 数据包。
/// 采用"地址学习"机制：从首个收到的数据包中获取远端地址。
///
/// SRTP B2BUA 模式下会解密并重加密；普通 RTP 模式下透明转发。
pub async fn run_relay(
    call_id: &str,
    _media_addr: &str,
    caller_port: u16,
    callee_port: u16,
    caller_decrypt_crypto: Option<SrtpCryptoSuite>,
    callee_encrypt_crypto: Option<SrtpCryptoSuite>,
    callee_decrypt_crypto: Option<SrtpCryptoSuite>,
    caller_encrypt_crypto: Option<SrtpCryptoSuite>,
    caller_initial_addr: Option<SocketAddr>,
    callee_initial_addr: Option<SocketAddr>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 绑定两个 UDP socket
    // 使用 0.0.0.0 监听所有接口（Docker 容器内 media_addr 是宿主机 IP，不可直接绑定）
    let caller_bind = format!("0.0.0.0:{}", caller_port);
    let callee_bind = format!("0.0.0.0:{}", callee_port);

    let caller_socket = UdpSocket::bind(&caller_bind)
        .await
        .map_err(|e| format!("无法绑定主叫侧 UDP 端口 {}: {}", caller_bind, e))?;
    let callee_socket = UdpSocket::bind(&callee_bind)
        .await
        .map_err(|e| format!("无法绑定被叫侧 UDP 端口 {}: {}", callee_bind, e))?;

    tracing::info!(
        "RTP/SRTP 媒体中继已启动: {} (主叫侧) <-> {} (被叫侧), Call-ID={}",
        caller_bind,
        callee_bind,
        call_id
    );

    let caller_socket = std::sync::Arc::new(caller_socket);
    let callee_socket = std::sync::Arc::new(callee_socket);

    if let Some(addr) = caller_initial_addr {
        tracing::info!("[{}] 使用主叫 SDP 媒体地址: {}", call_id, addr);
    }
    if let Some(addr) = callee_initial_addr {
        tracing::info!("[{}] 使用被叫 SDP 媒体地址: {}", call_id, addr);
    }

    // 共享的远端地址：优先使用 SDP 中声明的地址，收到实际 UDP 包后更新为源地址。
    let caller_remote = std::sync::Arc::new(tokio::sync::Mutex::new(caller_initial_addr));
    let callee_remote = std::sync::Arc::new(tokio::sync::Mutex::new(callee_initial_addr));

    let call_id_str = call_id.to_string();

    // 任务1: 主叫侧 → 被叫侧
    let cs1 = caller_socket.clone();
    let cs2 = callee_socket.clone();
    let cr1 = caller_remote.clone();
    let cr2 = callee_remote.clone();
    let cid1 = call_id_str.clone();
    let decrypt_caller = caller_decrypt_crypto;
    let encrypt_callee = callee_encrypt_crypto;

    let mut task1 = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let mut logged_first_forward = false;
        loop {
            match cs1.recv_from(&mut buf).await {
                Ok((n, addr)) => {
                    if n == 0 {
                        continue;
                    }
                    // 学习/更新主叫方地址
                    {
                        let mut remote = cr1.lock().await;
                        if *remote != Some(addr) {
                            tracing::debug!("[{}] 学习到主叫方地址: {}", cid1, addr);
                            *remote = Some(addr);
                        }
                    }
                    // SRTP 模式：解密 → 重加密
                    let callee_addr = {
                        let remote = cr2.lock().await;
                        *remote
                    };
                    if let Some(dest) = callee_addr {
                        let packet = &buf[..n];
                        let outbound = match (&decrypt_caller, &encrypt_callee) {
                            (Some(decrypt), Some(encrypt)) => match decrypt.unprotect_rtp(packet) {
                                Ok(rtp) => match encrypt.protect_rtp(&rtp) {
                                    Ok(srtp) => Some(srtp),
                                    Err(e) => {
                                        tracing::debug!("[{}] 主叫侧重加密失败: {}", cid1, e);
                                        None
                                    }
                                },
                                Err(e) => {
                                    tracing::warn!("[{}] 主叫侧 SRTP 解密失败: {}", cid1, e);
                                    None
                                }
                            },
                            _ => {
                                tracing::debug!("[{}] 缺少 SRTP crypto，丢弃主叫侧媒体包", cid1);
                                None
                            }
                        };
                        if let Some(outbound) = outbound {
                            if let Err(e) = cs2.send_to(&outbound, dest).await {
                                tracing::debug!("转发到被叫失败: {}", e);
                            } else if !logged_first_forward {
                                tracing::info!(
                                    "[{}] 主叫 -> 被叫 SRTP 首包已成功解密、重加密并转发到 {}",
                                    cid1,
                                    dest
                                );
                                logged_first_forward = true;
                            }
                        }
                    }
                    // 如果被叫地址未知，暂时丢弃包（等待被叫包或 SDP 地址）
                }
                Err(e) => {
                    tracing::debug!("[{}] 主叫侧 UDP 读取错误: {}", cid1, e);
                    break;
                }
            }
        }
    });

    // 任务2: 被叫侧 → 主叫侧
    let cs3 = callee_socket.clone();
    let cs4 = caller_socket.clone();
    let cr3 = callee_remote.clone();
    let cr4 = caller_remote.clone();
    let cid2 = call_id_str.clone();
    let decrypt_callee = callee_decrypt_crypto;
    let encrypt_caller = caller_encrypt_crypto;

    let mut task2 = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let mut logged_first_forward = false;
        loop {
            match cs3.recv_from(&mut buf).await {
                Ok((n, addr)) => {
                    if n == 0 {
                        continue;
                    }
                    // 学习/更新被叫方地址
                    {
                        let mut remote = cr3.lock().await;
                        if *remote != Some(addr) {
                            tracing::debug!("[{}] 学习到被叫方地址: {}", cid2, addr);
                            *remote = Some(addr);
                        }
                    }
                    // SRTP 模式：解密 → 重加密
                    let caller_addr = {
                        let remote = cr4.lock().await;
                        *remote
                    };
                    if let Some(dest) = caller_addr {
                        let packet = &buf[..n];
                        let outbound = match (&decrypt_callee, &encrypt_caller) {
                            (Some(decrypt), Some(encrypt)) => match decrypt.unprotect_rtp(packet) {
                                Ok(rtp) => match encrypt.protect_rtp(&rtp) {
                                    Ok(srtp) => Some(srtp),
                                    Err(e) => {
                                        tracing::debug!("[{}] 被叫侧重加密失败: {}", cid2, e);
                                        None
                                    }
                                },
                                Err(e) => {
                                    tracing::warn!("[{}] 被叫侧 SRTP 解密失败: {}", cid2, e);
                                    None
                                }
                            },
                            _ => {
                                tracing::debug!("[{}] 缺少 SRTP crypto，丢弃被叫侧媒体包", cid2);
                                None
                            }
                        };
                        if let Some(outbound) = outbound {
                            if let Err(e) = cs4.send_to(&outbound, dest).await {
                                tracing::debug!("转发到主叫失败: {}", e);
                            } else if !logged_first_forward {
                                tracing::info!(
                                    "[{}] 被叫 -> 主叫 SRTP 首包已成功解密、重加密并转发到 {}",
                                    cid2,
                                    dest
                                );
                                logged_first_forward = true;
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("[{}] 被叫侧 UDP 读取错误: {}", cid2, e);
                    break;
                }
            }
        }
    });

    // 等待任一任务结束或呼叫清理信号
    tokio::select! {
        _ = &mut task1 => {},
        _ = &mut task2 => {},
        _ = shutdown_rx.changed() => {},
    }

    task1.abort();
    task2.abort();

    tracing::info!("媒体中继已停止: Call-ID={}", call_id_str);
    Ok(())
}
