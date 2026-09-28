# 鸣鹤 (MingHe)

**最小化安全 SIP 语音通信服务器** — 纯 Rust 编写

[English](README_EN.md)

---

## 特性

- 🔒 **TLS 信令加密** — SIP over TLS (SIPS)，端口 5061，支持 TLS 1.2/1.3
- 🎵 **SRTP 媒体加密** — AES_CM_128_HMAC_SHA1_80 / AEAD_AES_128_GCM (RFC 7714)，SDES 密钥交换
- 🔑 **SIP Digest 认证** — MD5 `qop=auth`，nonce 有效期与重放检测，支持分机独立密码
- 📡 **RTP 媒体中继** — 服务器解密并重新加密，仅从已认证的 SRTP 包学习地址
- 💬 **分机即时消息** — SIP MESSAGE 互发文本，离线时暂存、上线后自动补投
- 📱 **内部分机** — 1000–2000 号段（可配置），支持 INVITE/BYE/CANCEL/ACK
- 🌐 **IP 证书** — 无需域名，支持 IP 地址直接签发 TLS 证书
- 🔄 **证书自动续期** — 自签名证书到期前 30 天自动重新生成，热重载不中断服务
- 🐳 **Docker 就绪** — 多架构镜像 (amd64/arm64)，一键 compose 部署
- 🦀 **纯 Rust** — 异步高性能 (tokio)，内存安全，无 GC

## 快速开始

### Docker / VPS 部署（推荐）

```bash
# 1. 准备配置
mkdir -p config
cp config.template.toml config/config.toml

# 2. 编辑配置（修改 host、media_addr、default_password 及已启用的分机密码）
vim config/config.toml

# 3. 启动
docker compose up -d

# 4. 查看日志
docker compose logs -f
```

> Docker Compose 默认使用命名卷保存自签名证书，不需要手动创建 `certs` 目录。

> ⚠️ 本项目不再提供 Zeabur 模板。SIP 信令使用 TCP/TLS，但语音媒体使用 SRTP/UDP，必须保证配置中的 UDP 端口范围能以相同公网端口直达容器。只支持 HTTP/TCP 转发、随机外部端口或无法开放 UDP 端口范围的平台不适合直接部署本服务。

### 从源码编译

```bash
# 环境要求：Rust 1.88+
cargo build --release --locked

# 准备本地配置（不要提交实际密码）
mkdir -p config
cp config.template.toml config/config.toml
chmod 600 config/config.toml
# 修改 host、media_addr 和所有启用的密码后运行
./target/release/minghe -c config/config.toml
```

## 配置说明

配置文件为 TOML 格式，详见 [`config.template.toml`](config.template.toml)。

### 最小配置

```toml
[server]
listen_addr = "0.0.0.0"
sip_port = 5061
host = "192.168.1.100"          # 你的服务器 IP 或域名

[extensions]
range_start = 1000
range_end = 2000
default_password = "CHANGE_ME_TO_A_STRONG_PASSWORD"

[tls]
cert_path = ""                   # 留空 = 自动生成自签名证书
key_path = ""

[media]
rtp_port_start = 20000
rtp_port_end = 20020
media_addr = "192.168.1.100"     # 必填：客户端可访问的服务器媒体 IP
```

> 所有 `CHANGE_ME…` 值都必须替换为实际随机密码（至少 12 字节）。`media_addr` 必须填写客户端可访问的有效 IP；留空或填写域名会被启动校验拒绝。

> 每通电话默认占用两个偶数 UDP 端口，例如第一通为 `20000/UDP` 和 `20002/UDP`。防火墙、云安全组、容器平台端口映射必须同时放行这些端口。

> 默认 `20000-20020/udp` 支持约 5 通并发，适合小 VPS。需要更多并发时，同时扩大 `config.toml`、Docker 端口映射和防火墙/安全组范围。不要在小 VPS 上默认映射 `20000-30000/udp`，Docker 创建上万个 UDP 端口映射时可能卡死。

### 部署平台要求

| 项目 | 要求 |
|:-----|:-----|
| SIP 信令 | 固定公网 TCP 端口，默认 `5061/tcp` |
| SRTP 媒体 | 固定公网 UDP 端口范围，默认 `20000-20020/udp` |
| 端口映射 | 外部端口必须与 SDP 中公布的端口一致 |
| 媒体地址 | `media_addr` 必须是客户端可访问的公网或内网 IP |

如果部署平台无法开放固定 UDP 端口范围，常见现象是：分机能注册、能拨通、能接听，但双方没有声音。

### 分机独立密码

建议在 `[passwords]` 中为每个分机设置不同的随机密码。未列出的分机使用 `default_password`，知道共享密码的人可以登录所有使用该密码的分机。下面的占位值必须替换：

```toml
[passwords]
1001 = "CHANGE_ME_EXTENSION_1001"
1002 = "CHANGE_ME_EXTENSION_1002"
```

### TLS 证书

| 模式 | 配置 | 说明 |
|:-----|:-----|:-----|
| **自签名** | `cert_path = ""` | 自动生成，到期前 30 天自动续期，推荐内网使用 |
| **IP 证书** | `host = "1.2.3.4"` | 自动识别 IP，生成 IP SAN 证书 |
| **域名证书** | `host = "sip.example.com"` | 自动识别域名，生成 DNS SAN 证书 |
| **外部证书** | `cert_path = "/path/to/cert.pem"` | 使用 Let's Encrypt 等外部证书 |

## 安全与升级

安全检查结果和完整限制见 [SECURITY.md](SECURITY.md)（[English](SECURITY_EN.md)）。

- 客户端必须支持 Digest `qop=auth`，在同一 TLS 连接注册后才能发起呼叫或消息；nonce 过期会收到新的 401 挑战。
- 注册最多有效 1 小时。每个连接只绑定一个账号，切换账号需重连；断连会清理相关呼叫。
- 每个主叫最多发起 2 个并发呼叫；默认媒体端口池支持 5 通。未接通呼叫最多保留 120 秒，已接通呼叫最多 4 小时，后台每 30 秒清理。
- 两端必须主动发送有效 SRTP 包，服务端才学习目标地址。只接收不发送的终端需要适配。
- 单 IP 每分钟最多 60 次 REGISTER（含挑战和重试），单连接每分钟最多 300 条 SIP 消息。共用 NAT 出口的大量终端需评估这些限制。
- 中继在服务端解密再加密，因此服务器属于信任边界；这不是端到端加密。

本次源码更新不代表 Docker Hub 的 `latest` 镜像已同步发布。需要立即使用这些修复时，请从当前源码构建。

## 客户端配置

推荐客户端：

- iOS / Android：Bria Mobile app
- 桌面电话机：方位 Linkvil W610W / W620W

其他客户端需支持 SIP over TLS、SDES-SRTP（`AES_CM_128_HMAC_SHA1_80` 或 `AEAD_AES_128_GCM`）以及可配置自签名证书验证策略。

| 配置项 | 值 |
|:------|:----|
| 服务器地址 | 你的服务器 IP 或域名 |
| 端口 | `5061` |
| 传输协议 | **TLS** |
| 用户名 | 分机号（如 `1001`） |
| 密码 | 对应密码 |
| 域/Realm | 与配置文件 `host` 一致 |

> ⚠️ 使用自签名证书时，请将 `certs/server.crt` 导入客户端为受信任证书，并保持 TLS 证书验证开启。证书续期后需要更新信任；公网部署建议使用受信任 CA 签发的证书。

## 即时消息的存储与投递

消息体最多 4 KiB，完整 MESSAGE 请求最多 8 KiB。离线消息只保存在内存中，保留 24 小时；每个接收分机最多 100 条，满时淘汰最旧消息，全局最多 10000 条。每个发送方每分钟最多暂存 120 条、同时最多暂存 500 条。容量或速率超限返回 503；200 表示服务端已接收，不保证客户端已确认收取。上线及发送队列腾出空间时继续补投，服务重启会丢失尚未投递的消息。

## 架构

```
┌──────────┐     SIP/TLS     ┌───────────────────────┐     SIP/TLS     ┌──────────┐
│          │◄───────────────►│                       │◄───────────────►│          │
│  分机     │    TCP:5061     │    鸣鹤 SIP Server     │    TCP:5061     │  分机     │
│  1001    │                 │                       │                 │  1002    │
│          │     SRTP        │  ┌─────────────────┐  │      SRTP       │          │
│          │◄───────────────►│  │  Media Relay    │  │◄───────────────►│          │
└──────────┘  UDP:20000+     │  │  RTP 媒体中继    │  │   UDP:20000+    └──────────┘
                             │  └─────────────────┘  │
                             │                       │
                             │  ┌─────────────────┐  │
                             │  │  Registrar      │  │
                             │  │  注册 + Digest   │  │
                             │  └─────────────────┘  │
                             │                       │
                             │  ┌─────────────────┐  │
                             │  │  Router         │  │
                             │  │  呼叫路由        │  │
                             │  └─────────────────┘  │
                             └───────────────────────┘
```

## 支持的 SIP 方法

| 方法 | 说明 |
|:-----|:-----|
| `REGISTER` | 分机注册/注销，Digest 认证 |
| `INVITE` | 发起语音通话，SDP 协商，SRTP 密钥分配 |
| `ACK` | 确认通话建立 |
| `BYE` | 结束通话，释放媒体资源 |
| `CANCEL` | 取消未接通的呼叫 |
| `OPTIONS` | 心跳保活 / 能力查询 |
| `MESSAGE` | 分机间即时消息；离线时暂存，上线后自动补投 |

## 项目结构

```
minghe/
├── Cargo.toml                # 项目清单
├── config.toml               # 示例配置（必须修改密码及媒体 IP）
├── config.template.toml      # 配置模板（带详细注释）
├── Dockerfile                # 多阶段构建
├── docker-compose.yml        # 容器编排
├── build-and-push.sh         # 多架构镜像构建脚本
├── SECURITY.md / SECURITY_EN.md # 安全检查、限制与升级说明
├── .env                      # 本地 Compose 环境变量（Git 忽略）
└── src/
    ├── main.rs               # 入口、CLI、优雅关闭
    ├── config.rs             # 配置加载与验证
    ├── tls.rs                # TLS 管理、证书自动续期、热重载
    ├── sip/
    │   ├── mod.rs
    │   ├── server.rs         # TLS 监听、连接管理、消息路由
    │   ├── parser.rs         # SIP 消息解析与构建
    │   ├── registrar.rs      # Digest 认证、注册管理
    │   ├── router.rs         # INVITE/ACK/BYE/CANCEL 路由
    │   ├── message.rs        # 即时消息、离线队列和配额
    │   └── transaction.rs    # 事务跟踪与超时清理
    └── media/
        ├── mod.rs
        ├── srtp.rs           # RFC 3711 / RFC 7714 SRTP 实现（AES-CM / AES-GCM）
        └── relay.rs          # UDP 媒体中继
```

## Docker

### 使用预构建镜像

```bash
docker pull facilisvelox/minghe:latest

# 如果使用宿主机目录挂载证书，请先确保容器内 minghe 用户可写。
mkdir -p config certs
sudo chown -R 10001:10001 certs

docker run -d \
  --name minghe-sip \
  --read-only --cap-drop ALL --security-opt no-new-privileges=true \
  -p 5061:5061/tcp \
  -p 20000-20020:20000-20020/udp \
  -v $(pwd)/config:/app/config:ro \
  -v $(pwd)/certs:/app/certs \
  facilisvelox/minghe:latest
```

### 从源码构建镜像

```bash
docker build -t minghe .
```

### 多架构构建与推送

```bash
# 安装 depot CLI 或 Docker Buildx；脚本优先选择 depot
# 构建并推送 latest
./build-and-push.sh

# 构建指定版本
TAG=v0.1.0 ./build-and-push.sh

# 仅构建不推送
PUSH=0 ./build-and-push.sh
```

## 开发

```bash
# 编译
cargo build --locked

# 测试
cargo test --locked

# 调试模式（详细日志）
RUST_LOG=debug cargo run --locked -- -c config/config.toml

# Release 构建
cargo build --release --locked
```

## 环境变量

| 变量 | 默认值 | 说明 |
|:-----|:------|:-----|
| `RUST_LOG` | `info` | 日志级别：`error` / `warn` / `info` / `debug` / `trace` |
| `SIP_PORT` | `5061` | SIP TLS 端口映射 |
| `RTP_PORT_START` | `20000` | RTP 端口范围起始 |
| `RTP_PORT_END` | `20020` | RTP 端口范围结束，默认约 5 通并发 |
| `CPU_LIMIT` | `1.0` | Docker Compose CPU 限制；1 核 VPS 可直接使用，多核机器可调高 |
| `MEM_LIMIT` | `512M` | Docker Compose 内存限制 |
| `TZ` | `Asia/Shanghai` | 容器时区 |

这些变量仅用于 Compose 端口映射和运行环境，不会覆盖 TOML 配置。修改 SIP 或媒体端口时，必须同时修改配置、映射和防火墙规则；建议 SIP 内外端口保持一致。


如果这个项目对你有用的话，请我喝罐可乐吧。
<br>
<img width=30% height=30% src="请我喝可乐.jpg" alt="qrcode">
<br>
## 许可证

本项目采用 [Apache License 2.0](LICENSE) 开源许可协议。

Copyright 2026 MingHe Contributors
