# Bria 跨网络无声修复与部署

[English](BRIA_EN.md) · [首页](README.md) · [部署与发布](DEPLOYMENT.md) · [安全边界](SECURITY.md)

新版本曾移除服务器 SRTP 中继，旧 Bria 配置因此失去跨 NAT 媒体路径。本次修复恢复显式 `[media]` 兼容模式和 Docker UDP 映射。未设置 `[media]` 时仍使用签名 SDP / DTLS-SRTP 端到端模式，两个模式不会自动回退。

## 配置

编辑部署使用的 `config/config.toml`，保留其他配置，恢复旧版 `[media]` 节。若已删除，在文件末尾添加（表头不可重复）：

```toml
[media]
rtp_port_start = 20000
rtp_port_end = 20020
media_addr = "你的服务器公网IPv4"
```

`media_addr` 必须填写双方能访问的服务器公网 IPv4，不能填写容器 IP、`0.0.0.0` 或任何一方手机的地址。Docker 默认映射 UDP `20000-20020`；若自定义媒体端口范围，需要同步修改 Compose 映射。服务器安全组、防火墙以及有 NAT 时的端口转发也要允许此范围的 UDP。

两种模式的注册均要求 SHA-256 Digest `qop=auth`，不接受 MD5 或缺省算法；先确认当前 Bria 版本支持此认证。

Bria 保留原来的 SIP/TLS 账号配置，启用 SDES-SRTP（Secure RTP）并验证服务器 TLS 证书。TLS / 登录密码不会替代 SRTP 设置。两端需主动发送媒体以建立 NAT 映射；服务端仅从认证成功的 SRTP 包学习返回地址。

## 构建与启动

在包含修复代码的项目目录运行：

```bash
docker compose up -d --build --force-recreate
docker compose logs -f minghe
```

Compose 现在配置 `build: .`，该命令会使用本地修复源码构建镜像。只拉取 `latest` 不会获得尚未发布的代码。不要删除证书卷。

启动日志应包含“已启用 Bria 兼容 SRTP 中继”。接听后应出现“媒体中继已启动”和两个方向“SRTP 首包已成功解密、重加密并转发”。只有信令成功或媒体中继启动日志，不代表 UDP 已经双向可达。

## 无声排查

| 现象 | 检查 |
| --- | --- |
| 没有兼容模式启动日志 | 部署读取的是否为 `config/config.toml`，`[media]` 是否仍被注释，容器是否已重建 |
| 呼叫返回 488 | 是否使用 SDES-SRTP、是否提供支持的密钥套件；兼容模式拒绝 DTLS 指纹和签名端到端 offer |
| 中继启动但没有首包转发日志 | UDP 映射、安全组、防火墙、公网 IPv4，以及双方是否主动发送 SRTP |
| 只有一个方向有转发日志 | 无声一侧的 NAT、客户端音频输入/输出、SRTP 协商及网络路径 |
| 媒体端口分配失败 | 端口池是否耗尽，配置范围是否需要扩大并同步映射 |

不要公开 SDP 的 `a=crypto`、配置密码或 Digest Authorization。

## 容量与限制

每通呼叫占用两个偶数 UDP 端口；分配范围包含 `rtp_port_start`、不包含 `rtp_port_end`。默认 `20000..20020` 提供 10 个偶数端口，最多同时支持 5 通中继呼叫，还受每主叫 2 通、全局 256 通的限制。需要更多并发时同步扩大 TOML、Docker 和防火墙范围。仅支持单个活动音频流，不支持视频、offerless、re-INVITE 或 ACK 中协商媒体；当前中继处理 SRTP 音频，不提供独立 RTCP/SRTCP 转发。

## 验证与安全边界

回归测试覆盖 INVITE → 200 → ACK → 双向 UDP SRTP → BYE，模拟两端私网 SDP 和实际动态 UDP 来源地址，并验证 AES-CM / GCM 不同套件的解密及重新加密。它不能替代两台 Bria 在真实不同网络的验收。

Bria 兼容模式使用 TLS + SDES-SRTP，服务器持有每侧媒体密钥并解密重加密语音，**不是端到端加密**。明文 RTP 仍被拒绝，注册认证和对话连接归属校验仍保留。MESSAGE 继续要求 JWE，与 Bria 普通文本消息不兼容。需要签名 SDP / DTLS-SRTP 端到端保护时删除整个 `[media]` 节，并使用已实现 [E2EE.md](E2EE.md) 协议的客户端。
