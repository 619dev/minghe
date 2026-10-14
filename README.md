# 鸣鹤 (MingHe)

Rust SIP/TLS 语音服务，支持 ZRTP 密文中继、Bria SDES-SRTP 兼容中继及签名 SDP / DTLS-SRTP 路由。

[English](README_EN.md) · [部署](DEPLOYMENT.md) · [ZRTP 接入](ZRTP.md) · [签名 DTLS 与消息协议](E2EE.md) · [安全与验证](SECURITY.md)

## 选择通话模式

| 配置 | 客户端要求 | 媒体路径与加密边界 |
| --- | --- | --- |
| `[media] mode = "zrtp"` | 支持 ZRTP 1.10、Hello hash，强制加密、禁用 ICE，双方核对 SAS | 服务器原样转发 ZRTP / SRTP / SRTCP；媒体密钥由终端持有 |
| `[media] mode = "sdes"`，或 `[media]` 不设置 mode | 支持 SIP/TLS、所配置的 Digest 算法和 SDES-SRTP，例如兼容版本的 Bria | 服务器解密并重加密语音；不是端到端加密 |
| 不设置 `[media]` | 实现鸣鹤签名 SDP、对方身份验证及 DTLS-SRTP | 服务器原样转发 SDP；媒体由端点通过 ICE / 必要的独立 TURN 建立连接 |

模式在服务启动时确定，不自动回退。双方必须使用同一模式兼容的客户端。没有 `[media]` 并不意味着普通软电话可以直接使用：签名 DTLS 模式需要客户端适配。

所有模式都要求 SIP/TLS 证书验证及 Digest `qop=auth`（默认 SHA-256；MD5 兼容需显式配置，见 [部署指南](DEPLOYMENT.md)），只接受 JWE MESSAGE，不兼容普通 SIP 文本消息。ZRTP 客户端的原生聊天加密协议也不会自动兼容鸣鹤 JWE。

## 快速开始

首次部署复制模板并填写域名或公网 IP、强密码和各分机独立密码：

```bash
mkdir -p config
cp config.template.toml config/config.toml
chmod 600 config/config.toml
# 编辑配置后运行；需要 Rust 1.88+。
cargo build --release --locked
./target/release/minghe -c config/config.toml
```

需要 ZRTP 时，在配置中启用以下表；公网地址必须替换：

```toml
[media]
mode = "zrtp"
rtp_port_start = 20000
rtp_port_end = 20020
media_addr = "203.0.113.10"
```

双方客户端开启强制 ZRTP、禁用 ICE，接通后核对 SAS。完整客户端要求和验收见 [ZRTP.md](ZRTP.md)。现有 Bria 用户使用 `mode = "sdes"`；切换 ZRTP 前先迁移双方客户端。

当前 Compose 引用镜像，**没有 `build` 配置**。从本地源码部署需先构建：

```bash
docker build -t facilisvelox/minghe:latest .
docker compose up -d --force-recreate
docker compose logs -f
```

Linux 上需授权容器 UID 10001 读取配置；UDP 映射、证书、升级及已发布镜像部署见 [DEPLOYMENT.md](DEPLOYMENT.md)。源码验证不代表远端 `latest` 已包含这些改动。

## 功能与限制

- TLS 信令、可配置的 Digest 注册认证、连接及对话归属校验，有界队列、速率与超时限制。
- ZRTP 使用 Hello hash 关联媒体来源、固定 UDP 地址；支持 RTCP mux 和独立 RTCP 端口。服务器不验证 SRTP 认证标签，强制加密由终端执行。
- SDES 兼容中继支持 AES-CM / AES-GCM，只有认证成功的 SRTP 包可以更新 NAT 地址。
- 签名 DTLS 模式保持 SDP 和身份封装原样；接收端必须独立验签并核对实际 DTLS 指纹。
- JWE 密文在线投递及内存离线队列；参考工具提供消息加解密、身份签名和持久重放检测，不提供拨号或音频功能。
- 自签名证书自动续期和 TLS 热重载，非 root Docker 运行。

支持 REGISTER、INVITE、ACK、BYE、CANCEL、OPTIONS、MESSAGE，仅单个活动音频流。初始 INVITE 必须携带 SDP；不支持视频、offerless、re-INVITE 或 ACK 中协商媒体。ZRTP 通话中改变网络地址需挂断重拨。

默认媒体端口池最多五通中继呼叫；其他容量和安全边界统一见 [SECURITY.md](SECURITY.md)。124 项 Rust 测试已通过，包括 Bria 双向 SRTP 和 ZRTP 透明转发；测试没有执行真实 ZRTP 客户端握手。真实双向声音、SAS 及跨网络互通仍需部署验收。

## 文档与开发

- [DEPLOYMENT.md](DEPLOYMENT.md)：配置、构建、发布、Bria 接入及故障排查。
- [ZRTP.md](ZRTP.md)：ZRTP 客户端要求、网络配置及真实通话验收。
- [E2EE.md](E2EE.md)：自定义签名 DTLS-SRTP / JWE 协议和终端参考工具。
- [SECURITY.md](SECURITY.md)：各模式安全边界、容量、测试命令及验证范围。

配置字段参考 [config.template.toml](config.template.toml)。核心实现位于 `src/sip/` 和 `src/media/`，客户端参考工具位于 `tools/`。测试命令统一见安全说明。

如果这个项目对你有用的话，请我喝罐可乐吧。

<img width="30%" src="请我喝可乐.jpg" alt="qrcode">

## 许可证

[Apache License 2.0](LICENSE)，Copyright 2026 MingHe Contributors。
