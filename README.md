# 鸣鹤 (MingHe)

纯 Rust SIP/TLS 信令路由服务，面向需要客户端端到端加密的内部分机通信。

[English](README_EN.md) · [端到端接入规范](E2EE.md) · [安全边界](SECURITY.md) · [部署与迁移](DEPLOYMENT.md)

**当前源码已切换为强制端到端协议配置。服务端不生成媒体密钥、不解密语音、不接受明文消息。实际客户端仍需适配身份签名、DTLS-SRTP 和加密消息；旧版 SDES 客户端不能直接继续使用。此仓库没有完整软电话客户端。**

## 功能

- SIP over TLS，默认 `5061/tcp`，客户端必须验证 TLS 证书。
- SIP Digest SHA-256 `qop=auth`，nonce 绑定账号与连接、有效期及重放校验；拒绝 MD5 和缺省算法。
- 音频 SDP 原样转发，强制 DTLS-SRTP、SHA-256 证书指纹、RTCP mux 和签名身份封装；拒绝明文及 SDES 降级。
- SIP MESSAGE 只接受 JWE 密文，离线队列也只保留密文；转发及暂存移除 Digest 认证信息。
- 客户端参考工具：RSA-OAEP-256 + AES-256-GCM 消息加密、Ed25519 身份签名、公钥指纹核对、持久重放检测及口令加密私钥。
- 连接认证、会话归属、帧/队列大小、速率和超时限制，断连清理呼叫。
- 自签名证书自动续期和 TLS 热重载、非 root Docker 部署。

## 端到端的必要条件

私钥在终端生成并保存，双方通过独立可信渠道核对公钥包指纹。每份 SDP 由终端签名，接收方先用固定的对方公钥验签，再核对实际 DTLS 证书指纹；消息接收方验证 AEAD、内层签名、接收身份、有效期及重放状态后才显示正文。

服务器的登录认证及格式检查不能替代这些客户端验证。服务器仍能看到账号、地址、呼叫时间和密文长度，也能阻断通信。消息采用静态 RSA 公钥封装，尚无 Double Ratchet 前向保密、入侵后恢复或多设备管理。完整协议、工具命令和限制见 [E2EE.md](E2EE.md)。

## 快速开始

先完成客户端适配和公钥指纹核对。服务器配置不包含用户端到端私钥或可信对方密钥。

```bash
mkdir -p config
cp config.template.toml config/config.toml
chmod 600 config/config.toml
# 修改 host、default_password 和启用的独立分机密码
```

最小配置：

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

Compose 默认使用本地构建的 `minghe:local`，证书保存到命名卷。需要固定公网 TCP 信令端口。服务端不再监听 RTP UDP 端口，旧 `[media]` 配置仅为升级兼容读取，并发出停用提示。跨 NAT 的客户端必须配置 ICE/STUN，必要时配置独立的只转发密文的 TURN；本项目没有 TURN 服务。

公网使用受信任 CA 的证书；使用自签名证书时将 `certs/server.crt` 导入客户端信任并保持证书验证开启，续期后更新信任。TLS 服务端证书不能替代对方终端身份核对。

本次源码修改未发布 Docker Hub 镜像；旧 `latest` 镜像不能代表本次实现。

## 方法与容量

支持 REGISTER、INVITE、ACK、BYE、CANCEL、OPTIONS、MESSAGE。初始 INVITE 必须有签名 SDP；当前仅支持单个活动音频流及 RTCP mux。不支持 offerless、re-INVITE、视频或在 ACK 中协商媒体。

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

核心代码：`src/sip/e2ee.rs`（准入策略）、`router.rs`（签名 SDP 路由）、`message.rs`（密文投递）、`registrar.rs`（注册认证），以及 `tools/e2ee_client.py`（终端参考加密）。旧媒体实现及 SDP 改写工具仅在历史回归测试中编译，生产二进制不包含解密中继。

本机 TLS/SIP 集成测试已验证注册、离线密文补投、接收端解密和签名 SDP 路由。实际终端接入、跨 NAT 双向音频和容器运行仍需上线前验证；单元测试不等同于完整系统安全审计。

如果这个项目对你有用的话，请我喝罐可乐吧。

<img width=30% height=30% src="请我喝可乐.jpg" alt="qrcode">

## 许可证

[Apache License 2.0](LICENSE)，Copyright 2026 MingHe Contributors。
