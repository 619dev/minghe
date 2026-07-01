# 鸣鹤 (MingHe)

**最小化安全 SIP 语音通信服务器** — 纯 Rust 编写

[English](README_EN.md)

---

## 特性

- 🔒 **TLS 信令加密** — SIP over TLS (SIPS)，端口 5061，支持 TLS 1.2/1.3
- 🎵 **SRTP 媒体加密** — AES_CM_128_HMAC_SHA1_80，SDES 密钥交换
- 🔑 **SIP Digest 认证** — MD5 摘要认证，支持默认密码和分机独立密码
- 📡 **RTP 媒体中继** — 服务器侧透明中继，地址学习，隐藏内部拓扑
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

# 2. 编辑配置（至少修改 host 和 default_password）
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
# 环境要求：Rust 1.75+
cargo build --release

# 运行
./target/release/minghe -c config.toml
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
default_password = "YourPassword123"

[tls]
cert_path = ""                   # 留空 = 自动生成自签名证书
key_path = ""

[media]
rtp_port_start = 20000
rtp_port_end = 20020
media_addr = "192.168.1.100"     # 必填：客户端可访问的服务器媒体 IP
```

> ⚠️ `media_addr` 不要留空。Docker、云平台或多网卡环境下自动检测通常会拿到容器内网 IP，导致接听后无声。请填写 Bria、Linkvil 等客户端能直接访问到的公网或内网 IP。

> 每通电话默认占用两个偶数 UDP 端口，例如第一通为 `20000/UDP` 和 `20002/UDP`。防火墙、云安全组、容器平台端口映射必须同时放行这些端口。

> 默认 `20000-20020/udp` 支持约 10 通并发，适合小 VPS。需要更多并发时，同时扩大 `config.toml`、Docker 端口映射和防火墙/安全组范围。不要在小 VPS 上默认映射 `20000-30000/udp`，Docker 创建上万个 UDP 端口映射时可能卡死。

### 部署平台要求

| 项目 | 要求 |
|:-----|:-----|
| SIP 信令 | 固定公网 TCP 端口，默认 `5061/tcp` |
| SRTP 媒体 | 固定公网 UDP 端口范围，默认 `20000-20020/udp` |
| 端口映射 | 外部端口必须与 SDP 中公布的端口一致 |
| 媒体地址 | `media_addr` 必须是客户端可访问的公网或内网 IP |

如果部署平台无法开放固定 UDP 端口范围，常见现象是：分机能注册、能拨通、能接听，但双方没有声音。

### 分机独立密码

在 `[passwords]` 段中为特定分机设置独立密码，未列出的分机使用 `default_password`：

```toml
[passwords]
1001 = "velox@2026"
1002 = "alice@2026"
```

### TLS 证书

| 模式 | 配置 | 说明 |
|:-----|:-----|:-----|
| **自签名** | `cert_path = ""` | 自动生成，到期前 30 天自动续期，推荐内网使用 |
| **IP 证书** | `host = "1.2.3.4"` | 自动识别 IP，生成 IP SAN 证书 |
| **域名证书** | `host = "sip.example.com"` | 自动识别域名，生成 DNS SAN 证书 |
| **外部证书** | `cert_path = "/path/to/cert.pem"` | 使用 Let's Encrypt 等外部证书 |

## 客户端配置

推荐客户端：

- iOS / Android：Bria Mobile app
- 桌面电话机：方位 Linkvil W610W / W620W

其他客户端需支持 SIP over TLS、SDES-SRTP（`AES_CM_128_HMAC_SHA1_80`）以及可配置自签名证书验证策略。

| 配置项 | 值 |
|:------|:----|
| 服务器地址 | 你的服务器 IP 或域名 |
| 端口 | `5061` |
| 传输协议 | **TLS** |
| 用户名 | 分机号（如 `1001`） |
| 密码 | 对应密码 |
| 域/Realm | 与配置文件 `host` 一致 |

> ⚠️ 使用自签名证书时，需要在客户端中**关闭 TLS 证书验证**，或导入 `certs/server.crt` 为受信任证书。

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

## 项目结构

```
minghe/
├── Cargo.toml                # 项目清单
├── config.toml               # 默认配置
├── config.template.toml      # 配置模板（带详细注释）
├── Dockerfile                # 多阶段构建
├── docker-compose.yml        # 容器编排
├── build-and-push.sh         # 多架构镜像构建脚本
├── .env                      # Docker Compose 环境变量
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
    │   └── transaction.rs    # 事务跟踪与超时清理
    └── media/
        ├── mod.rs
        ├── srtp.rs           # RFC 3711 SRTP 实现
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
# 需要安装 depot CLI
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
cargo build

# 测试
cargo test

# 调试模式（详细日志）
RUST_LOG=debug cargo run

# Release 构建
cargo build --release
```

## 环境变量

| 变量 | 默认值 | 说明 |
|:-----|:------|:-----|
| `RUST_LOG` | `info` | 日志级别：`error` / `warn` / `info` / `debug` / `trace` |
| `SIP_PORT` | `5061` | SIP TLS 端口映射 |
| `RTP_PORT_START` | `20000` | RTP 端口范围起始 |
| `RTP_PORT_END` | `20020` | RTP 端口范围结束，默认约 10 通并发 |
| `CPU_LIMIT` | `1.0` | Docker Compose CPU 限制；1 核 VPS 可直接使用，多核机器可调高 |
| `MEM_LIMIT` | `512M` | Docker Compose 内存限制 |
| `TZ` | `Asia/Shanghai` | 容器时区 |

如果这个项目对你有用的话，请我喝罐可乐吧。
<br>
<img width=30% height=30% src="请我喝可乐.jpg" alt="qrcode">
<br>
## 许可证

本项目采用 [Apache License 2.0](LICENSE) 开源许可协议。

Copyright 2026 MingHe Contributors
