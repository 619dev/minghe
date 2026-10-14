# 部署、升级与发布

[English](DEPLOYMENT_EN.md) · [首页](README.md) · [ZRTP 接入](ZRTP.md) · [安全与验证](SECURITY.md)

## 配置与模式

首次部署复制 `config.template.toml` 到 `config/config.toml`，设置服务器 host、至少 12 字节的强密码及分机独立密码。升级时编辑原配置，不用模板覆盖账号或证书设置。源码程序不带 `-c` 时默认读取根目录 `config.toml`；本文命令和 Docker 明确读取 `config/config.toml`。

| 模式 | 配置 | 网络与客户端 |
| --- | --- | --- |
| ZRTP | `[media] mode = "zrtp"` | 公网 IPv4、UDP 中继；双方强制 ZRTP、禁用 ICE、核对 SAS，见 [ZRTP.md](ZRTP.md) |
| Bria SDES | `[media] mode = "sdes"` 或不设置 mode | 公网 IPv4、UDP 中继；SDES-SRTP，服务器可解密语音 |
| 签名 DTLS | 删除整个 `[media]` | 客户端适配 [E2EE.md](E2EE.md)，自行配置 ICE/STUN 及必要的独立 TURN |

模式在启动时确定，不能按呼叫自动切换。迁移前先确认双方客户端支持目标模式，备份配置与 TLS 证书；签名 DTLS 客户端还需保护身份、固定指纹和重放数据库。重启会丢失内存中的未投递离线消息。

中继配置示例，`media_addr` 必须换成双方能访问的服务器真实公网 IPv4：

```toml
[media]
mode = "sdes" # ZRTP 客户端改为 "zrtp"
rtp_port_start = 20000
rtp_port_end = 20020
media_addr = "203.0.113.10"
```

端口池包含起点、不包含终点，使用偶数 RTP 端口。默认 SDES 每通占两个端口；ZRTP 每通占两个 RTP 及两个奇数 RTCP 端口，起止值均须为偶数。默认两种中继均最多五通。Compose 映射整个 UDP `20000-20020`；修改范围时同步修改 TOML、Compose、安全组和防火墙。公网地址不能填容器地址、`0.0.0.0` 或手机地址。

签名 DTLS 模式不使用本服务的 UDP 媒体端口，可移除这部分映射；独立 TURN 的端口单独管理。不要以关闭证书验证或启用明文回退解决连接失败。

## 源码运行

需要 Rust 1.88+：

```bash
mkdir -p config
cp config.template.toml config/config.toml
chmod 600 config/config.toml
# 编辑配置，替换占位值并选择通话模式。
cargo build --release --locked
./target/release/minghe -c config/config.toml
```

## Docker 运行与升级

当前 `docker-compose.yml` 只有 `image`，没有 `build`。使用当前源码时先构建，再重建容器：

```bash
docker build -t facilisvelox/minghe:latest .
docker compose up -d --force-recreate
docker compose logs -f
```

使用已发布镜像时先确认镜像版本，再拉取并启动；不要在本地源码构建后执行 pull 覆盖它：

```bash
# 仅用于部署已发布镜像。
docker compose pull
docker compose up -d --force-recreate
```

生产部署宜将 Compose 的 image 固定为经过验收的版本标签或 digest。当前源码验证不能证明远端 `latest` 内容；ZRTP 改动尚未在本次工作中发布。`docker compose down` 停止服务，保留证书卷；不要用 `down -v` 删除证书。

容器以 UID/GID 10001 运行。Linux bind mount 目录需可遍历，配置和外部证书/私钥需该 UID 可读；宿主用户所有的 0600 文件通常不能直接被容器读取。使用文件所有权、专用组或 ACL 授予所需权限，保持配置挂载只读。默认 `/app/certs` 命名卷持久保存证书并允许续期写入。

| Compose 变量 | 默认值 | 用途 |
| --- | --- | --- |
| `SIP_PORT` | `5061` | 宿主机 TCP 端口；容器目标仍为 5061 |
| `RUST_LOG` | `info` | 日志级别 |
| `TZ` | `Asia/Shanghai` | 时区 |
| `CPU_LIMIT` | `1.0` | CPU 限额 |
| `MEM_LIMIT` | `512M` | 内存限额 |

环境变量不替代 TOML 的账号、密码、host 和证书。修改 TOML 的 `sip_port` 时也需修改映射的容器目标端口。健康检查只确认进程存活，不代表注册或媒体可用。

## TLS 与客户端

公网使用受信任 CA 证书，`cert_path` 和 `key_path` 同时设置。留空时生成自签名证书 `certs/server.crt`；Docker 中位于证书卷。将公有证书导入客户端信任，续期后更新信任；私钥不得分发。服务器 TLS 信任和通话对方身份验证是独立步骤。

Bria 使用 SIP/TLS、SHA-256 Digest `qop=auth`，启用 SDES-SRTP 并验证服务器证书。确认版本支持这些功能。两端主动发送 SRTP 才能建立 NAT 返回路径；服务端仅从认证成功的 SRTP 包学习地址。支持 AES_CM_128_HMAC_SHA1_80 与 AEAD_AES_128_GCM，不提供独立 RTCP/SRTCP 转发。此模式不是端到端加密。

ZRTP 的客户端设置和 SAS 验收集中在 [ZRTP.md](ZRTP.md)。所有模式只接受鸣鹤 JWE MESSAGE，不支持 Bria 普通文本消息；签名 DTLS 与消息工具集中在 [E2EE.md](E2EE.md)。

## 镜像发布

[build-and-push.sh](build-and-push.sh) 支持 Depot 和 Docker Buildx，默认 `PUSH=1` 会推送；非 latest 的 TAG 还会更新 latest。文档更新不需要执行发布。

```bash
# 单平台本地构建并加载，不推送；平台按部署环境选择。
PUSH=0 BUILDER=buildx PLATFORM=linux/amd64 TAG=media-review ./build-and-push.sh

# 完成验收后发布到指定仓库，同时更新 latest。
REPO=YOUR_DOCKER_HUB_USER TAG=YOUR_RELEASE_TAG ./build-and-push.sh
```

Buildx 的 `PUSH=0` 多平台构建不加载本地镜像；Depot 使用 `--load`。使用自定义仓库或标签时同步修改 Compose 的 image。发布前按 [SECURITY.md](SECURITY.md) 运行检查，并完成真实终端、跨网络和容器验收。

## 排查

| 现象 | 检查 |
| --- | --- |
| 配置启动失败 | 密码占位值及长度、host、分机范围、成对证书路径、mode 及媒体端口范围 |
| 容器无法读配置或证书 | UID 10001 的读取/目录遍历权限和挂载路径 |
| 注册失败 | TLS 信任、SHA-256 / qop=auth、账号密码及来源 IP 限流 |
| Bria 呼叫 488 | SDES 模式及支持的套件；拒绝 DTLS 指纹、签名身份 offer 和明文协议 |
| ZRTP 呼叫 488 | Hello hash、ZRTP 1.10、禁用 ICE、仅音频；中继端口是否可绑定 |
| 签名 DTLS 呼叫 488 | 原始 SDP 字节、身份封装、fingerprint、setup、RTCP mux |
| 中继接听后无声 | 公网 IPv4、完整 UDP 映射、防火墙、双方是否发送媒体/Hello；ZRTP 客户端是否完成握手 |
| 签名 DTLS 无声 | 客户端验签、实际 DTLS 指纹、ICE 候选及 TURN 连通性 |
| MESSAGE 415 | application/jose、受限五段 JWE、是否附加 CLI 换行或发送原生聊天协议 |
| 接收端拒绝消息 | 固定指纹、GCM/签名、收发身份、时间和重放数据库 |
| 重启后离线消息消失 | 队列只在内存中；200 不等于客户端成功解密 |

只共享脱敏日志，隐藏密码、Digest Authorization、SDES 密钥、终端私钥和消息正文。
