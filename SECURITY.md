# 安全边界与验证

[English](SECURITY_EN.md) · [首页](README.md) · [部署](DEPLOYMENT.md)

更新日期：2026-10-14。说明针对当前仓库源码与参考工具，不代表已发布镜像、生产部署或独立密码学审计。

## 各模式的安全边界

| 模式 | 服务器媒体能力 | 必要的客户端验证 |
| --- | --- | --- |
| ZRTP：`[media] mode = "zrtp"` | 原样转发握手和媒体，不生成或持有媒体密钥；无法区分明文/密文 RTP 负载或验证 SRTP/SRTCP 标签 | 强制 ZRTP、验证媒体认证标签，双方核对 SAS；见 [ZRTP.md](ZRTP.md) |
| SDES：`[media] mode = "sdes"` 或省略 mode | 持有每侧密钥，解密重加密语音；不是端到端加密 | TLS 证书验证和 SDES-SRTP |
| 签名 DTLS：无 `[media]` | 原样路由 SDP，不启动媒体中继；服务器仅校验身份封装准入 | 固定对方公钥、Ed25519 验签、核对实际 DTLS 指纹；见 [E2EE.md](E2EE.md) |

ZRTP 的 Hello hash 用于关联媒体来源与 SIP 会话，不替代 SAS，也不能证明已完成密钥交换。服务器可篡改信令；客户端不能把服务器登录认证当作对方身份认证。ZRTP 模式没有服务器加密回退，但必须由客户端禁止明文媒体。

所有模式的 MESSAGE 都只接受限定 RSA-OAEP-256 / AES-256-GCM JWE。内层 Ed25519 签名和正文只能由接收端验证，服务器仅检查外层封装。终端必须校验 AEAD、签名、收发身份、有效期和持久重放状态后才显示消息。原生 SIP 文本或其他客户端聊天协议不兼容。

## 共同保护与媒体限制

- SIP/TLS，客户端验证服务器证书；自签名私钥以 0600 保存，自动续期及 TLS 热重载。
- Digest `qop=auth` 默认 SHA-256，拒绝 MD5 和缺省算法；仅 `[server] digest_algorithm = "md5"` 显式启用 MD5，此时允许省略 algorithm（按 MD5 处理）。不自动降级；nonce 绑定账号和连接，5 分钟有效，递增 nc 防重放。
- 连接先注册，From 与认证身份一致；对话控制绑定原始 TLS 连接和方向，被叫响应检查 CSeq；注册过期或替换使旧身份失效。
- 拒绝重复关键头部、折行和控制字符；投递及暂存移除 Digest 认证材料，处理伪造 From。
- 非法早期 SDP 取消被叫侧 INVITE；非法 200 answer 向合法被叫对话发送 ACK/BYE 并清理记录。
- ZRTP 只在 Hello hash 与 SDP 匹配后固定 RTP 来源，最多缓存每侧一个首次 Hello；其他来源不能更新地址。独立 RTCP 来源仅限同一 RTP 来源 IP，端点仍须验证 SRTCP。网络地址变化需重拨。
- SDES 仅通过认证成功的 SRTP 学习 NAT 地址，执行 SRTP 重放校验；支持 AES-CM/GCM，不提供独立 RTCP 转发。
- 签名 DTLS 模式拒绝 SDES、SDP 密钥、明文协议和缺失身份封装；签名及 SDP 原样转发，端点独立验签。
- 参考工具在终端生成密钥，使用口令加密 PKCS#8、0600 独占文件和持久 SQLite 重放记录。工具不提供 SIP 拨号或媒体功能。
- 容器非 root、只读根文件系统、禁用 capabilities 和提权；配置密码不得为占位值或不足 12 字节。

## 容量

| 项目 | 限制 |
| --- | --- |
| TCP/TLS | 256 连接；握手 10 秒；未认证/已认证空闲分别 120/3600 秒 |
| 帧与处理 | 头部 16 KiB、整帧 64 KiB；不完整帧 15 秒；处理及写入 10 秒；发送队列 16 条 |
| 速率 | 每连接每分钟 300 条 SIP；每来源 IP 每分钟 60 次 REGISTER，包含挑战及重试 |
| 分机与注册 | 最多 10000 个分机；每连接一个账号；注册最多 3600 秒 |
| 呼叫 | 每主叫 2 通，全局 256 通；未接通 120 秒、接通 4 小时，30 秒周期清理；媒体池可进一步限制并发 |
| MESSAGE | body 4 KiB、请求 8 KiB；离线 TTL 24 小时，每接收方 100 条，全局 10000 条 |
| 离线发送配额 | 每发送方每分钟 120 条，同时最多 500 条；接收队列满时淘汰最旧消息 |

离线队列只在内存中，重启丢失；200 只表示服务器接收，不表示客户端验签解密成功。共用 NAT 的大量终端需评估来源 IP 限流。

所有模式只支持一个活动音频流，不支持视频、offerless、re-INVITE 或 ACK 中协商媒体。签名 DTLS 要求 RTCP mux 和端点 ICE / 必要的独立 TURN；ZRTP 禁用 ICE，支持 mux 或独立 RTCP；SDES 使用服务器中继。端口池容量见 [部署指南](DEPLOYMENT.md)。

## 尚未提供的保证

服务器可看到账号、地址、SDP、通话时间及密文长度，也能阻断、延迟或重放数据；不提供元数据匿名或网络可用性保证。受控终端或泄露的私钥仍可泄露内容。

消息使用静态 RSA 公钥封装，没有前向保密、入侵后恢复或 Double Ratchet；未来泄露接收私钥可解密录制的历史消息。没有多设备、群组、自动轮换/撤销或加密备份。重放数据库和身份信任必须持久保存。

独立 TURN 不应终止 DTLS。ZRTP 同 IP 的恶意来源或已观察到握手的攻击者仍可能造成拒绝服务。源码测试不能替代真实客户端验证、依赖审计或独立安全审查。

## 验证范围与复现

当前代码通过 124 项 Rust 测试、Release 构建、Clippy、格式与 diff 检查；Clippy 仍有未使用代码及风格警告。Rust 测试实际发送本机 UDP 包，覆盖 Bria 双向 AES-CM/GCM 解密重加密、ZRTP hash 与握手字节转发、两端独立密钥的 SRTP 原样转发及终端解密、RTCP 字节转发、降级/端口失败/早期 hash 变更拒绝和资源释放。

ZRTP Hello 与 RTCP 是构造的测试消息，测试没有执行真实 ZRTP 密钥交换、SAS 或 SRTCP 密码学验证。本次语音改动没有重跑 Python 客户端/TLS 集成测试、容器运行和 Cargo Audit，也没有发布镜像或修改部署配置。真实音频、跨网络互通及客户端强制加密需要另行验收；历史审计结果不能代表当前依赖安全。

```bash
cargo test --locked
cargo build --release --locked
cargo clippy --locked --all-targets
cargo fmt --check
git diff --check
# 两项专项测试需要本机 UDP 端口绑定权限。
cargo test --locked bria_profile -- --nocapture
cargo test --locked zrtp_profile -- --nocapture
docker compose config --quiet
# 安装工具依赖后运行：
python -m unittest discover -s tools -p 'test_e2ee_client.py' -v
MINGHE_BINARY=/absolute/path/to/target/release/minghe \
  python -m unittest discover -s tools -p 'test_e2ee_transport.py' -v
# 已安装 cargo-audit 时，发布前更新依赖审计。
cargo audit
```

Python 依赖见 `tools/requirements-e2ee.txt`。TLS/SIP 集成测试使用临时身份、证书与配置，只监听 127.0.0.1，验证注册、密文补投、重放拒绝和签名 SDP 路由，不发送语音。协议及工具用法见 [E2EE.md](E2EE.md)。

MD5 兼容认证测试包含标准 Digest 向量、配置默认值、算法隔离、注册、错误密码、连接/身份绑定、qop 要求与重放拒绝。MD5 仅用于 SIP 登录，不用于 ZRTP、DTLS、SRTP 或 JWE；登录认证强度低于 SHA-256，应使用强随机密码并保持 TLS 验证。真实 Bria Mobile 登录仍需部署后验证。
