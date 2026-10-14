# 鸣鹤 (MingHe)

Rust SIP/TLS 分机通信服务，支持 Bria 的 SRTP 媒体中继和需要客户端适配的端到端协议。

[English](README_EN.md) · [Bria 部署](BRIA.md) · [端到端接入规范](E2EE.md) · [安全边界](SECURITY.md) · [部署与迁移](DEPLOYMENT.md)

**支持两种显式通话模式：没有 `[media]` 时使用签名 SDP / DTLS-SRTP；保留 `[media]` 时启用兼容 Bria 的 TLS + SDES-SRTP 中继，恢复跨网络媒体路径。中继模式由服务器解密并重加密语音，不是端到端加密。明文 RTP 和明文 MESSAGE 仍被拒绝。配置步骤见 [Bria 无声修复与部署](BRIA.md)。**

## 功能

- SIP over TLS，默认 `5061/tcp`，客户端必须验证 TLS 证书。
- SIP Digest SHA-256 `qop=auth`，nonce 绑定账号与连接、有效期及重放校验；拒绝 MD5 和缺省算法。
- 默认端到端模式：音频 SDP 原样转发，强制 DTLS-SRTP、SHA-256 证书指纹、RTCP mux 和签名身份封装；拒绝明文及 SDES 降级。
- Bria 兼容模式：改写 SDP 为服务器媒体地址及端口，使用独立密钥双向解密、重加密 SRTP；从有效 SRTP 包学习 NAT 地址。
- SIP MESSAGE 只接受 JWE 密文，离线队列也只保留密文；转发及暂存移除 Digest 认证信息。
- 客户端参考工具：RSA-OAEP-256 + AES-256-GCM 消息加密、Ed25519 身份签名、公钥指纹核对、持久重放检测及口令加密私钥。
- 连接认证、会话归属、帧/队列大小、速率和超时限制，断连清理呼叫。
- 自签名证书自动续期和 TLS 热重载、非 root Docker 部署。

## 模式选择

| 配置 | 语音路径 | 客户端要求 | 加密边界 |
| --- | --- | --- | --- |
| 保留 `[media]` | 服务器 SRTP 中继 | SIP/TLS、SHA-256 Digest、SDES-SRTP；适用于 Bria | 服务器可解密语音，不是端到端加密 |
| 不设置 `[media]` | 终端通过 ICE/DTLS 建立连接 | 签名 SDP、DTLS-SRTP、对方身份校验 | 媒体密钥由两端协商，服务器不解密 |

两种模式都只接受 JWE MESSAGE，不支持 Bria 普通文本消息。模板中的 `[media]` 示例默认被注释；使用 Bria 时必须取消注释并填写公网 IPv4。模式由服务启动时的配置决定，不按呼叫自动切换。

## 端到端模式的必要条件

私钥在终端生成并保存，双方通过独立可信渠道核对公钥包指纹。每份 SDP 由终端签名，接收方先用固定的对方公钥验签，再核对实际 DTLS 证书指纹；消息接收方验证 AEAD、内层签名、接收身份、有效期及重放状态后才显示正文。

服务器的登录认证及格式检查不能替代这些客户端验证。服务器仍能看到账号、地址、呼叫时间和密文长度，也能阻断通信。消息采用静态 RSA 公钥封装，尚无 Double Ratchet 前向保密、入侵后恢复或多设备管理。完整协议、工具命令和限制见 [E2EE.md](E2EE.md)。

## 快速开始

Bria 用户先按 [BRIA.md](BRIA.md) 恢复 `[media]` 配置；端到端模式先完成客户端适配和公钥指纹核对。服务器配置不包含用户端到端私钥或可信对方密钥。

```bash
mkdir -p config
cp config.template.toml config/config.toml
chmod 600 config/config.toml
# 修改 host、default_password 和启用的独立分机密码
```

没有 `[media]` 的最小端到端模式配置：

```toml
[server]
listen_addr = "0.0.0.0"
sip_port = 5061
host = "sip.example.com"

[extensions]
range_start = 1000
range_end = 2000
default_password = "CHANGE_ME_TO_A_STRONG_PASSWORD"

[tls]
cert_path = ""
key_path = ""

[passwords]
# 1001 = "CHANGE_ME_EXTENSION_1001"
# 1002 = "CHANGE_ME_EXTENSION_1002"
```

所有占位密码必须替换为至少 12 字节的随机密码。建议每个分机使用不同密码；共享默认密码允许其持有者登录所有使用该密码的分机。

源码运行（Rust 1.88+）：

```bash
cargo build --release --locked
./target/release/minghe -c config/config.toml
```

Docker 从当前源码构建：

```bash
docker compose up -d --build
docker compose logs -f
```

配置文件须可被容器 UID 10001 读取；宿主用户的 0600 文件在 Linux bind mount 中需要专门授权。端口变量、证书卷及发布注意事项见 [部署与迁移](DEPLOYMENT.md)。

Compose 从当前源码构建配置的镜像，保留证书卷，映射 SIP/TLS TCP 和 UDP `20000-20020`。UDP 映射必须与 `[media]` 范围一致；仅兼容模式分配媒体端口。当前源码修改尚未发布镜像。

公网使用受信任 CA 的证书；使用自签名证书时将 `certs/server.crt` 导入客户端信任并保持证书验证开启，续期后更新信任。TLS 服务端证书不能替代对方终端身份核对。

## 方法与容量

支持 REGISTER、INVITE、ACK、BYE、CANCEL、OPTIONS、MESSAGE。初始 INVITE 必须有 SDP；端到端模式要求签名和 RTCP mux，兼容模式要求 SDES-SRTP，两者均只支持一个活动音频流。不支持 offerless、re-INVITE、视频或在 ACK 中协商媒体。

每主叫最多 2 个呼叫，全局最多 256 个；未接通最多保留 120 秒，接通最多 4 小时。注册最多有效 1 小时；同一连接只绑定一个账号。

MESSAGE body 最多 4 KiB，完整请求最多 8 KiB；离线密文在内存中保留 24 小时，每接收方最多 100 条，全局最多 10000 条。单发送方每分钟最多暂存 120 条、同时最多暂存 500 条。200 仅表示服务端接收，不表示客户端验签解密成功；服务重启会丢失尚未投递的消息。

## 开发与验证

```bash
cargo test --locked
cargo clippy --locked --all-targets
cargo fmt --check
# 在客户端参考工具的 Python 环境中
python -m unittest discover -s tools -p 'test_e2ee_client.py' -v
```

核心代码：`src/sip/e2ee.rs`（准入策略）、`router.rs`（模式选择与签名 SDP 路由）、`sdes_router.rs`（Bria 呼叫及 SRTP 中继）、`message.rs`（密文投递）、`registrar.rs`（注册认证），以及 `tools/e2ee_client.py`（终端参考加密）。媒体实现及 SDP 改写工具仅在显式 `[media]` 兼容模式执行；默认端到端模式不启动中继。

当前修复已通过 116 项 Rust 回归测试、Release 构建、Clippy、格式和 diff 检查；Clippy 仍有未使用代码及风格警告。新增测试实际发送 UDP SRTP 包，覆盖 INVITE、200、ACK、双向 AES-CM/GCM 解密重加密及 BYE。既有 TLS/SIP 测试覆盖注册、离线密文补投、接收端解密和签名 SDP 路由。真实 Bria 跨网络通话和容器启动仍需部署验收，详见 [安全验证记录](SECURITY.md)。

如果这个项目对你有用的话，请我喝罐可乐吧。

<img width=30% height=30% src="请我喝可乐.jpg" alt="qrcode">

## 许可证

[Apache License 2.0](LICENSE)，Copyright 2026 MingHe Contributors。
