//! 历史媒体实现，仅在 cfg(test) 中编译以保留回归测试；生产服务器不使用。
//!
//! 媒体处理模块 — RTP/SRTP 中继与加密
//!
//! 包含 SRTP 加解密实现和媒体中继服务。

pub mod relay;
pub mod srtp;
