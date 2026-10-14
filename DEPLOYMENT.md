# 部署、升级与发布

[English](DEPLOYMENT_EN.md) · [首页](README.md) · [端到端协议](E2EE.md) · [安全验证记录](SECURITY.md)

## Bria 兼容模式

旧版 Bria 用户保留或恢复 `[media]`，填写服务器公网 IPv4，并放行匹配的 UDP 范围，详见 [BRIA.md](BRIA.md)。该配置显式启用 TLS + SDES-SRTP 中继，服务器终止媒体加密。下面的端到端迁移要求适用于没有 `[media]` 的默认端到端模式。

## 迁移到端到端模式

端到端模式与未适配的 Bria/SDES 客户端不兼容。先在两台实际终端实现 SHA-256 Digest `qop=auth`、签名 SDP、DTLS-SRTP 和 JWE MESSAGE，并通过独立渠道核对对方公钥包指纹。客户端参考工具不提供拨号或媒体功能。私钥只在各终端生成和保存，不放入服务器配置、镜像或卷。

选择端到端模式时删除整个 `[media]` 节，并移除服务器中继的 UDP 映射和防火墙规则。保留 `[media]` 会选择 Bria 中继模式。客户端自行配置 ICE/STUN；需要中继时使用不终止 DTLS 的独立 TURN。不得通过关闭证书验证、接受 SDES 或明文回退解决互通问题。

备份服务器配置与 TLS 证书，并保护客户端身份、固定的公钥指纹和持久重放数据库。离线消息队列仅在内存中，重启会丢失未投递密文。回滚旧服务器会恢复旧安全边界，不能继续按当前端到端承诺使用。

## 配置和运行

首次部署时，从 [config.template.toml](config.template.toml) 复制到 `config/config.toml`，替换 host 和全部启用的密码占位值。根目录 [config.toml](config.toml) 是另一份示例，不是默认部署目录。密码至少 12 字节，优先为每个分机设置不同的随机密码。

升级时编辑现有部署配置，不要用模板覆盖账号、证书路径或 `[media]`。Bria 媒体端口默认映射 UDP `20000-20020`，它不是环境变量；自定义 TOML 范围时必须同步调整 Compose 和防火墙。

源码运行需要 Rust 1.88+：

```bash
mkdir -p config
cp config.template.toml config/config.toml
chmod 600 config/config.toml
# 编辑配置，替换占位值。
cargo build --release --locked
./target/release/minghe -c config/config.toml
```

Compose 从当前源码构建 `facilisvelox/minghe:latest`：

```bash
docker compose up -d --build
docker compose logs -f
docker compose down
```

容器以 UID/GID 10001 运行。Linux bind mount 的配置目录需要可遍历，配置文件需要该 UID 可读；宿主用户所有且仅 0600 的文件通常不能直接被它读取。可通过文件所有权、专用组或 ACL 给 UID 10001 最小只读权限，保持配置挂载 `:ro`。外部证书及私钥同样需要容器可读；证书目录需要续期写入权限。默认命名卷负责持久保存 `/app/certs`，不要删除该卷来重启服务。

| Compose 变量 | 默认值 | 用途 |
| --- | --- | --- |
| `SIP_PORT` | `5061` | 宿主机 TCP 端口；容器目标仍为 5061 |
| `RUST_LOG` | `info` | 日志级别 |
| `TZ` | `Asia/Shanghai` | 时区 |
| `CPU_LIMIT` | `1.0` | CPU 限额 |
| `MEM_LIMIT` | `512M` | 内存限额 |

这些环境变量不替代 TOML 的账号、密码、host 或证书配置。若修改 TOML 的 `sip_port`，也要修改 Compose 映射的容器目标端口。端到端模式仅需开放 SIP/TLS TCP 端口；Bria 兼容模式还需开放配置的 UDP 媒体范围；独立 TURN 的端口由其部署单独管理。健康检查只验证进程存活，不证明注册、端到端身份或媒体可用。

公网部署使用受信任 CA 证书，`cert_path` 与 `key_path` 同时设置。自签名模式生成 `certs/server.crt` 和私钥；Docker 中在证书卷内，需从卷中安全导出公有证书供客户端导入信任。续期后更新客户端信任，始终启用证书验证。服务器证书与终端身份公钥是两个独立信任关系。

## 构建和发布镜像

[build-and-push.sh](build-and-push.sh) 支持 Depot 和 Docker Buildx。**默认 `PUSH=1` 会推送远端；指定非 latest 的 TAG 时，还会同时更新 latest。** 文档更新或本地测试无需执行发布命令。

```bash
# 单平台本地构建并加载，不推送；按实际架构选择平台。
PUSH=0 BUILDER=buildx PLATFORM=linux/amd64 TAG=media-review ./build-and-push.sh

# 完成发布验证后推送到自己的仓库；也会更新该仓库 latest。
REPO=YOUR_DOCKER_HUB_USER TAG=YOUR_RELEASE_TAG ./build-and-push.sh
```

Buildx 的 `PUSH=0` 多平台模式仅验证构建，不加载本地镜像；Depot 模式使用其 `--load` 行为。Compose 同时设置 `build: .` 和 `image: facilisvelox/minghe:latest`；`up --build` 从本地源码构建并在本地打该标签，不会推送远端。要部署已发布镜像，显式修改 Compose image/build 或使用脚本打印的 docker run 指令，并保留容器限制、配置只读挂载和证书持久卷。当前源码修改尚未发布镜像。

## 部署验收和常见问题

发布前运行 [安全说明中的测试命令](SECURITY.md)，安装端点工具依赖，重新进行 Cargo Audit，并验证实际终端的双向音频、跨 NAT/TURN、证书信任、指纹替换拒绝、重放拒绝和容器运行。Rust Bria 回归测试实际发送双向 UDP SRTP 包，并覆盖 AES-CM/GCM 两端；独立 Python TLS/SIP 集成测试验证信令和加密消息，不发送语音。两者均不能替代真实跨 NAT Bria 验收。

| 现象 | 检查 |
| --- | --- |
| 启动拒绝配置 | host、密码占位值及长度、分机范围、证书路径是否成对设置 |
| 容器无法读取配置/证书 | UID 10001 文件读取和目录遍历权限、挂载位置 |
| 注册持续失败 | TLS 信任、SHA-256 与 qop=auth、正确账号密码、连接绑定及来源 IP 速率限制 |
| Bria 呼叫收到 488 | 是否已启用 `[media]`，两端是否提供支持的 SDES-SRTP 套件；此模式拒绝明文 RTP、DTLS 指纹和签名端到端 offer |
| 端到端呼叫收到 488 | SDP 协议、RTCP mux、setup、指纹、身份封装及签名的原始 SDP 字节是否满足规范 |
| Bria 接听后无声音 | `media_addr` 是否为公网 IPv4，TOML/Compose/防火墙的 UDP 范围是否一致，两端是否发送 SRTP，以及两个方向的首包转发日志 |
| 端到端信令成功但没有音频 | 客户端验签、实际 DTLS 指纹、ICE 候选和独立 TURN 连通性 |
| MESSAGE 收到 415 | 是否为 application/jose 五段受限 JWE，是否误发明文或附加 CLI 换行 |
| 消息在客户端被拒绝 | 固定的对方指纹、GCM/签名、收发身份、时钟和重放记录；不要关闭校验 |
| 服务重启后无离线消息 | 队列仅在内存中；200 不等于客户端已解密 |

仅共享脱敏后的日志；不要发送配置密码、Digest Authorization、端点私钥或消息正文用于排查。
