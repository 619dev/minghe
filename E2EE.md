# 端到端加密接入规范

[English](E2EE_EN.md) · [部署与迁移](DEPLOYMENT.md)

鸣鹤现在只路由信令及加密消息，不参与媒体密钥交换，不启动 UDP 解密中继。旧的 SDES-SRTP / 明文 RTP / 明文 MESSAGE 不再接受，没有兼容性降级开关。

**仓库提供服务端准入策略和客户端参考加密工具，尚不包含可直接拨打电话的客户端。实际软电话必须实现下述身份校验、DTLS-SRTP 和消息协议后才能使用。仅升级服务器不能让原有 Bria / Linkvil 配置自动获得这些能力。**

## 信任与密钥

- 每个客户端本地生成独立 RSA-3072/4096 消息加密密钥及 Ed25519 身份签名密钥。私钥不得上传服务器，不能由服务器生成或通过 SIP 登录密码派生。
- 公钥包包括版本、分机身份、消息加密公钥、身份签名公钥；对其规范 JSON（UTF-8、键排序、无额外空格）计算 SHA-256，作为身份核对指纹。
- 首次通过当面扫码、已可信渠道等方式独立核对公钥包指纹，并在客户端保存身份与指纹绑定。仅从本服务器下载公钥并自动信任，无法抵御恶意服务器。
- 公钥替换、分机身份变更和增加设备必须重新核对。不得静默接受新密钥。SIP 登录密码仅保护注册，不作为端到端身份凭据。
- 参考工具将私钥以口令加密的 PKCS#8 保存到 0600 文件；不会覆盖已有文件。生产客户端应使用系统密钥库，并实现恢复、撤销和设备管理。

## 语音

客户端使用 [DTLS-SRTP（RFC 5763）](https://www.rfc-editor.org/rfc/rfc5763.html) 和 [RFC 5764](https://www.rfc-editor.org/rfc/rfc5764.html)。服务端只接受一个活动音频流：

```sdp
v=0
o=- 1 1 IN IP4 192.0.2.1
s=-
c=IN IP4 192.0.2.1
t=0 0
m=audio 4000 UDP/TLS/RTP/SAVPF 111
a=fingerprint:sha-256 AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB
a=setup:actpass
a=rtcp-mux
```

实际 SDP 使用 CRLF，包括最后一行；示例指纹必须替换为客户端实际证书 SHA-256 指纹。支持 `UDP/TLS/RTP/SAVP` 或 `UDP/TLS/RTP/SAVPF`，offer 的 `setup` 必须是 `actpass`，answer 为 `active` 或 `passive`。允许会话级 fingerprint/setup 或媒体级覆盖。拒绝 SHA-1 指纹、重复 DTLS 属性、SDES `a=crypto`、SDP `k=` 密钥、明文协议、多个媒体流、端口为 0 或无 RTCP mux 的 SDP。初始 INVITE 必须携带 offer；不支持 offerless、re-INVITE、视频或通过 ACK 携带新 SDP。

每个 offer、早期媒体 answer（183 等）及最终 answer 同时携带：

```text
Content-Type: application/sdp
X-Minghe-Identity: <compact JWS>
```

该 JWS 使用 Ed25519 签名。受保护头部只能有 `alg=EdDSA`、`typ=minghe-sdp+jwt` 和 `kid`（签名公钥 SPKI DER 的 SHA-256 小写十六进制）。载荷仅含：

| 字段 | 内容 |
| --- | --- |
| `iss` / `aud` | 发送 / 接收分机号，字符串 |
| `call_id` | 本次 SIP Call-ID |
| `role` | `offer` 或 `answer` |
| `sdp_sha256` | 完整 SDP 原始字节的 SHA-256 小写十六进制 |
| `iat` / `exp` | Unix 秒，整数；有效期不超过 120 秒 |

服务器校验格式、方向、Call-ID、SDP 哈希和有效期，原样转发签名及 SDP；**服务器的格式校验不等同于签名验证。接收客户端必须用独立固定的对方公钥验签**，核对预期分机、Call-ID、方向、哈希及时间，之后才使用 SDP。客户端必须避免重复使用已完成呼叫的 Call-ID；新设备重新注册也不能重置此身份信任。

客户端还必须对实际 DTLS 握手证书计算指纹，与已验签 SDP 中的指纹比较；失败时停止呼叫。DTLS 使用现代、支持临时密钥交换的套件，禁用旧协议、弱 SRTP 套件和明文回退，并启用 SRTP 重放保护。签名保护指纹免遭服务器替换，DTLS 握手将媒体密钥限定在两个终端之间。两层验证缺一不可。

客户端自行使用 ICE / STUN 建立连接，必要时配置独立 TURN。TURN 仅转发 DTLS / SRTP 密文，不能终止 DTLS；鸣鹤不提供 TURN，也不分配媒体端口。网络不具备直连条件且未配置 TURN 时，呼叫会失败，不会回退到解密中继。

非法早期 SDP 会触发 488 并取消被叫侧 INVITE；非法 200 answer 会触发 488，并向有合法对话 tag 的被叫发送 ACK/BYE。客户端仍必须自行处理拒绝及超时。

## 即时消息

采用 [RFC 7516 JWE Compact Serialization](https://www.rfc-editor.org/rfc/rfc7516.html)，SIP body 是五段 base64url 字符串，无换行或填充，媒体类型为 `application/jose`。这是一项需要客户端适配的鸣鹤协议配置，并非现有 SIP 文本消息客户端的自动兼容功能。

受保护头部仅接受以下字段：

```json
{"alg":"RSA-OAEP-256","enc":"A256GCM","cty":"JWT","kid":"接收方加密公钥SPKI-DER的SHA256小写十六进制"}
```

客户端每条消息重新生成随机 256-bit 内容密钥及 96-bit nonce，以接收方 RSA 公钥执行 OAEP（SHA-256 / MGF1-SHA-256），AES-256-GCM 使用编码后的 JWE 受保护头作为 AAD，128-bit tag。禁止 `RSA1_5`、`dir`、压缩、远程密钥 URL 或算法回退。

加密前先生成内层 Ed25519 签名 JWT：受保护头为 `alg=EdDSA`、`typ=JWT` 和签名公钥 `kid`。载荷只允许 `iss`、`aud`、`jti`（UUID v4）、`iat`、`exp`、`text`。有效期最多 24 小时；接收方允许发送时间最多领先本地时钟 30 秒，要求过期时间严格晚于当前时间。消息身份由内层签名决定，不能信任服务器改写的 From 头。

接收方先验证本地预期接收密钥及 GCM tag，再用固定的发送方公钥验签，核对发送方、接收方及有效期，将 `(发送方, 接收方, jti)` 原子写入持久重放数据库后才显示正文。失败、重复或数据库不可用时拒绝。不得把失败原因转换为详细解密错误返回服务器。

服务器无法验证密文内的签名或正文，只做封装准入检查。格式正确不证明密码学有效；不能把伪造的五段文本当成“已经加密成功”。离线存储及投递保留密文字节；转发和暂存前清除 Digest 认证头及伪造 From。现有 4 KiB 消息体、8 KiB 请求、24 小时 TTL、队列及发送方配额继续适用。

参考工具限制原文最多 1800 UTF-8 字节，并最终检查密文不超过 4096 字节。4096-bit RSA 和 JSON 转义开销较大时，应进一步缩短正文。

## 客户端参考工具

`tools/e2ee_client.py` 使用 [pyca/cryptography](https://cryptography.io/en/50.0.2/installation/) 提供密钥生成、消息加解密、SDP 签名及验证。它不发送 SIP 请求，不建立 ICE / DTLS 连接，不播放语音。

在各客户端自己的设备执行，**不要在服务端部署目录生成实际用户私钥**：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r tools/requirements-e2ee.txt
mkdir -p e2ee-keys
.venv/bin/python tools/e2ee_client.py keygen --extension 1001 \
  --private e2ee-keys/1001.private.json --public e2ee-keys/1001.public.json
```

运行下面命令前替换引号内的指纹和 Call-ID 占位值。命令交互读取并确认至少 12 字节的本地私钥口令，不通过命令行参数传入。它输出公钥包身份指纹。另一设备为 1002 独立执行；只交换 `.public.json`，独立核对并保存双方输出的指纹。

```bash
# 在 1001 设备，输入待加密文本；输出用作 MESSAGE body。
.venv/bin/python tools/e2ee_client.py encrypt \
  --private e2ee-keys/1001.private.json --peer e2ee-keys/1002.public.json \
  --peer-fingerprint '独立核对过的1002指纹'

# 在 1002 设备，输入收到的完整 JWE；replay DB 必须长期保存。
.venv/bin/python tools/e2ee_client.py decrypt \
  --private e2ee-keys/1002.private.json --peer e2ee-keys/1001.public.json \
  --peer-fingerprint '独立核对过的1001指纹' --replay-db e2ee-keys/received.sqlite3

# 对客户端实际生成的 CRLF SDP 签名；输出放入 X-Minghe-Identity。
.venv/bin/python tools/e2ee_client.py sign-sdp \
  --private e2ee-keys/1001.private.json --peer e2ee-keys/1002.public.json \
  --peer-fingerprint '独立核对过的1002指纹' \
  --sdp offer.sdp --call-id '本次Call-ID' --role offer

# 接收客户端在启动 DTLS 前验证；标准输入是收到的签名头值。
.venv/bin/python tools/e2ee_client.py verify-sdp \
  --private e2ee-keys/1002.private.json --peer e2ee-keys/1001.public.json \
  --peer-fingerprint '独立核对过的1001指纹' \
  --sdp received-offer.sdp --call-id '预期Call-ID' --role offer
```

输入完毕后用 EOF 结束标准输入。CLI 输出有一个终端换行，写入 SIP body/header 时去掉该换行；SIP Content-Length 必须是最终 body 的字节长度。接入实际客户端时可调用模块函数，并使用本地可信密钥库代替文件。

## 安全边界和未完成部分

- 服务器仍可看到账号、在线状态、IP、通话时间、SDP 及密文长度，也能阻断、延迟或丢弃消息；这里不提供元数据匿名或可用性保证。
- 消息 RSA 公钥封装**不具备前向保密或入侵后恢复**：未来泄露接收私钥可解密此前录制的消息。需要 Signal 类安全目标时，应另外接入经过审计的预密钥/Double Ratchet 实现，不能把本配置宣传为 Signal 等价。
- 本参考实现是单设备模式，没有多设备同步、群组、自动密钥轮换/撤销、可信公钥目录或端到端加密备份。删除重放数据库会丢失重放记忆；必须和身份状态一起保护、持久化。
- 签名过的 SDP 仍会向服务器披露地址等媒体协商信息；私密应用数据必须放入加密消息。DTLS 证书信任不能只依赖本服务器的 TLS 证书。
- 已有 nonce、注册身份、会话归属、帧大小、速率、连接/呼叫超时和 TLS 验证机制继续适用；Digest 已改为 SHA-256 `qop=auth`，不接受 MD5 或缺省算法。
- 参考工具测试涵盖真实加解密、篡改、身份替换、方向和 Call-ID 绑定、过期及持久重放检测。尚未用实际 SIP 终端、跨 NAT 网络或真实语音做验证；上线前必须完成客户端接入及独立安全审计。
