# 安全机制与验证记录

**模式范围：**下述端到端保证适用于没有 `[media]` 的模式。配置 `[media]` 时启用已恢复的 Bria SDES-SRTP 中继，服务器持有媒体密钥并解密重加密语音，不是端到端加密；注册认证、对话归属和 JWE MESSAGE 限制仍保留。见 [BRIA.md](BRIA.md)。

[English](SECURITY_EN.md) · [部署与迁移](DEPLOYMENT.md)

更新日期：2026-10-14。范围为仓库源码、端点参考工具及本地测试；不代表已发布镜像、已部署生产或已完成独立密码学审计。

## 端到端加密边界

默认端到端模式只路由 SIP/TLS 和加密 MESSAGE，不启动 UDP 中继。显式 `[media]` 模式包含 SDES 密钥接收、媒体密钥生成和 SRTP 解密重加密链路；AES/HMAC/SHA-1 为运行时依赖。Docker 映射的 UDP 范围默认是 20000–20020。

端到端模式的语音必须由终端执行 DTLS-SRTP。每份 SDP 同时附带终端 Ed25519 签名，绑定发送/接收分机、Call-ID、offer/answer 方向、完整 SDP 哈希及有效期。服务端只校验封装及协商准入，**不把服务器认证当作端到端身份验证**。接收客户端必须用独立固定的对方公钥验签，再核对实际 DTLS 证书与已签名指纹；缺失或失败时停止呼叫。

MESSAGE 采用 RSA-OAEP-256 / AES-256-GCM JWE，内层是 Ed25519 签名 JWT。终端本地产生私钥、内容密钥和 nonce；服务器仅存取密文。接收端验证 AEAD、签名、身份、有效期和持久重放数据库后才能显示正文。格式正确的封装不证明其密码学有效，服务端无法检查密文内的签名。

完整规范、参考工具用法、独立指纹核对和客户端接入要求见 [E2EE.md](E2EE.md)。本仓库**没有完整软电话客户端**，不得仅凭服务器升级声称旧终端已经具有完整端到端保护。

## 已实现的安全机制

| 机制 | 行为 |
| --- | --- |
| 端到端降级拒绝 | INVITE、早期及最终带 SDP 的应答均校验 DTLS-SRTP、SHA-256 fingerprint、setup、RTCP mux 及签名封装；拒绝 SDES、SDP 密钥、明文或缺失身份封装 |
| 端到端密钥隔离 | 默认端到端模式没有媒体解密上下文、密钥生成或媒体转发任务；服务器配置不包含端到端私钥 |
| 端到端协商绑定 | SDP 字节、签名、ICE 参数保持不变；身份封装与账号、呼叫、方向、哈希和时间绑定；客户端独立验签 |
| Bria 中继边界 | 显式 `[media]` 启用独立密钥的 SDES-SRTP 解密重加密、认证后的 NAT 地址学习和 SRTP 重放校验；拒绝签名端到端 offer 和明文 RTP |
| 拒绝后的清理 | 不兼容早期媒体取消对应 INVITE（保留事务 branch）；非法 200 answer 向合法被叫对话发送 ACK/BYE 并释放呼叫记录 |
| 消息内容保护 | 只接受限定算法的五段 JWE；禁止明文、仅签名消息、弱算法、压缩、远程密钥 URL 和重复/未知 JOSE 参数 |
| 端点完整性及重放 | 参考工具校验 GCM、Ed25519、收发身份、时间及 UUID v4；显示前事务提交 SQLite 重放记录，重启仍拒绝重复；数据库错误时拒绝 |
| 端点密钥保存 | 私钥用口令加密的 PKCS#8，以 0600 独占创建；公钥包必须独立核对指纹；不覆盖已有密钥 |
| 注册认证 | 按 [RFC 8760](https://www.rfc-editor.org/rfc/rfc8760.html) 强制 SHA-256 `qop=auth`，拒绝 MD5、缺省算法及畸形响应；nonce 绑定账号与来源连接，5 分钟有效，原子递增 nc 防重放 |
| 身份及会话归属 | 同一 TLS 连接先注册、From 匹配认证身份；对话方法绑定呼叫原始连接和方向；被叫响应校验 CSeq；注册过期或替换使旧身份失效 |
| 请求和敏感字段 | 拒绝重复关键头部（含 Content-Type 紧凑形式、编码及身份头）、折行/控制字符；对话控制消息不携带未验证正文；投递和暂存移除 Digest 认证材料及伪造 From |
| 密码与 TLS 文件 | 拒绝占位密码及不足 12 字节的密码；自签名 TLS 私钥 0600 写入并原子替换；TLS 验证必须在客户端启用 |
| 容量与部署 | 有界连接、帧、发送队列、速率和呼叫记录；检查呼叫配额（端到端模式还在插入时重新检查）；非 root 容器、只读根文件系统、禁用 capabilities 和提权 |

## 容量限制

- 256 个 TCP/TLS 连接；握手 10 秒；未认证空闲连接 120 秒、已认证空闲连接 3600 秒；不完整帧 15 秒；单次处理及写入 10 秒。
- 单连接每分钟 300 条 SIP 消息，单来源 IP 每分钟 60 次 REGISTER（含挑战和重试）。共用 NAT 的大量终端需要评估限制。
- SIP 头部 16 KiB，整帧 64 KiB，发送队列 16 条；分机范围最多 10000 个号码。
- 注册最多 3600 秒，每连接一个账号；每主叫最多 2 个呼叫，全局最多 256 个。未接通 120 秒、已接通 4 小时后清理，周期 30 秒。
- MESSAGE body 4 KiB、请求 8 KiB；离线 TTL 24 小时，每接收方 100 条（满时淘汰最旧）、全局 10000 条。每发送方每分钟暂存 120 条、同时最多 500 条。队列只在内存中保存，200 不表示接收端成功验签或解密。
- 两种模式均只接受单个活动音频流，端到端模式要求 RTCP mux；不支持 offerless、视频、re-INVITE 或 ACK 中协商媒体。端到端跨 NAT 需要端点 ICE/STUN 和必要的独立 TURN；Bria 使用可达的中继 IPv4 及匹配的 UDP 映射和防火墙规则。

## 仍存在的边界

- 服务器可观察账号、IP、SDP、时间和密文长度，并能丢弃、延迟或重放数据；本项目不提供元数据匿名和可用性保证。
- 私钥泄露或受控终端仍能泄露内容。登录密码及本服务器 TLS 证书不是可信对方身份的替代品。
- 消息采用静态 RSA 公钥封装，**没有前向保密、入侵后恢复或 Double Ratchet**。未来泄露接收私钥可以解密历史录制密文。多设备、群组、自动轮换/撤销、恢复和加密备份尚未实现。
- 签名 SDP 使用短有效期和新的 Call-ID 绑定，客户端需要保护身份状态并防止重复使用呼叫上下文。MESSAGE 重放数据库需要持久保存，不能在每次启动清空。
- 独立 TURN 不应终止 DTLS。支持 TLS/SDES 的旧客户端不等于支持本端到端协议；不应关闭证书、签名或 AEAD 校验换取兼容性。
- 源码检查和测试不能证明没有漏洞；真实客户端及跨 NAT 语音互通、容器启动仍需独立验证。需要大流量拒绝服务防护时使用部署环境的防火墙及限流。

## 验证与发布

本次 Bria 修复通过 116 项 Rust 回归测试、Release 构建、Clippy、格式与 diff 检查，以及 `docker compose config --quiet`。新增 Rust 测试实际发送本机 UDP SRTP 包，覆盖 INVITE、200、ACK、双向 AES-CM/GCM 解密重加密、BYE，并确认签名 offer 不进入中继。此前端到端实现记录的 7 项端点加密测试和 1 项本机 TLS/SIP 集成测试未在 Bria 修复及本次文档更新中重跑。复现命令：

```bash
cargo test --locked
cargo build --release --locked
cargo clippy --locked --all-targets
cargo fmt --check
git diff --check
docker compose config --quiet
# 专项回归，需要本机 UDP 端口绑定权限：
cargo test --locked bria_profile -- --nocapture
python -m unittest discover -s tools -p 'test_e2ee_client.py' -v
MINGHE_BINARY=/absolute/path/to/target/release/minghe \
  python -m unittest discover -s tools -p 'test_e2ee_transport.py' -v
```

端点测试需要 `tools/requirements-e2ee.txt` 中的 Python 依赖。传输测试只监听 127.0.0.1，使用临时身份、证书和配置，测试 TLS 验证、SHA-256 注册、离线密文补投、客户端重放拒绝及真实签名 SDP 的路由；不发送语音媒体。

Clippy 仍有未使用代码及风格警告。Compose 配置检查不等于容器启动验证；Bria 修复未执行容器运行及 RustSec 依赖审计。2026-09-29 的旧审计结果不能用作新版本的审计结论。发布前运行新的 Cargo Audit，完成真实客户端和跨 NAT 验证，并安排独立安全审查。

本次工作没有发布镜像或修改生产部署。Compose 设置 `build: .` 和 `image: facilisvelox/minghe:latest`；`up --build` 从源码构建并在本地打标签，不发布镜像。远端 `latest` 不能证明已包含本次修复。
