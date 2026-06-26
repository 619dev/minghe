//! SIP 协议模块
//!
//! 包含 SIP 信令服务器的所有核心组件：
//! - `server`: TLS SIP 服务器主循环
//! - `parser`: SIP 消息解析与构建
//! - `registrar`: 注册服务与 Digest 认证
//! - `router`: 呼叫路由（INVITE/BYE/CANCEL/ACK）
//! - `transaction`: 事务管理

pub mod server;
pub mod parser;
pub mod registrar;
pub mod router;
pub mod transaction;
