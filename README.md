# fingerprint-bridge

Rust HTTPS 域名中转：浏览器访问 **B**，B 请求固定的 **A**；只有 B 需要部署软件和证书。

本项目按实际收到的 TLS ClientHello 配置上游，尽量保留 HTTP 字节、头部顺序和 HTTP/2 控制帧，并用实际报文验证效果。**这是实验性实现，不承诺任意浏览器的全部 TLS/HTTP/TCP 特征完全相同。** 测试失败、缺失证据和未实现功能都明确报告。

## 已实现

| 层 | 实现 | 检验方式 |
| --- | --- | --- |
| TLS | 从入站 ClientHello 映射密码套件及顺序、支持组、签名算法、ALPN、GREASE、KeyShare 组、可配置扩展顺序、OCSP/SCT、zlib/Brotli 证书压缩 | 采集**实际发出的** ClientHello，比较 JA3、JA4 和原始顺序等细项 |
| HTTP/1.1 | 原始头部字节变换，保留头部大小写、顺序、空格、重复字段、Cookie、消息体、chunk 分界和 trailer；支持 keep-alive、HEAD、100 Continue | 独立 HTTPS 测试站点比较直连/中转接收到的请求 |
| HTTP/2 | 保留连接和流的对应关系；转发 SETTINGS、WINDOW_UPDATE、PRIORITY、DATA 等帧；保留头部顺序、重复字段、HPACK 表示方式/Huffman 选择/动态索引、HEADERS 优先级和填充，尽量保留 CONTINUATION 边界 | 测试有序 SETTINGS、窗口增量、优先级、流编号、连续请求、HPACK 字节及动态表独立淘汰 |
| TCP | 读取真实 PCAP 中的 SYN；解析 IP 版本、TTL/跳数、DF、窗口、MSS、WS、SACK、时间戳存在性、选项顺序和标志；可手动设置 Linux TCP_MAXSEG/TTL | 正反例报文测试；可选 Linux loopback 实测抓包 |
| 验收 | 差异按字段输出 JSON；缺失层也判失败 | CLI 退出码：0 一致、1 差异/缺失、2 输入/运行错误 |

**TCP 数据面仍由 B 的内核创建。** 当前没有实现每客户端独立的 TCP 栈模拟，不会把 MSS/TTL 两个设置宣称为完整 TCP 指纹克隆。原始流量逐包透传又无法实现这里要求的 HTTPS 域名改写。

## 构建

Linux 推荐安装 Rust、C/C++ 编译器、CMake、Perl、libclang 开发文件和系统 CA：

```sh
sudo apt-get install build-essential cmake perl libclang-dev ca-certificates pkg-config python3 git
sh scripts/cargo-tls.sh build --locked --release
```

Rust 工具链锁定在 `rust-toolchain.toml`；依赖锁定在 `Cargo.lock`。底层采用 `btls` 的 BoringSSL 绑定，需要编译原生依赖。它是第三方 TLS 依赖，升级时应重跑指纹测试。

推荐构建脚本启用 `patched-tls`：从 Cargo 校验过的固定版 `btls-sys 0.5.6` 源码建立隔离副本，先应用依赖自带补丁，再应用 `scripts/patches/` 中的项目补丁。补丁在握手序列化内部保留 TLS 1.3/旧套件的混排顺序、SCSV 与 padding 存在性，支持仅 TLS 1.3 的套件配置，补齐 `SecP256r1MLKEM768` / `SecP384r1MLKEM1024` 的真实密钥交换，并支持 ML-DSA-44/65/87 证书密钥解析和签名验证。保留 transcript/Finished、密码学输入校验和证书验证；不修改加密后的网络字节、不宣称支持未实现算法。源文件/补丁改变会生成新的构建目录，补丁不适配时构建失败。普通 `cargo build` 仍使用未追加项目补丁的后端，不能获得这些修复；CI 使用推荐构建方式。

## 启动 B

为 B 准备浏览器信任的证书及私钥。A 使用其现有 HTTPS 服务和证书，无需改动：

```sh
./target/release/fingerprint-bridge serve \
  --listen 0.0.0.0:8443 \
  --public b.example:8443 \
  --upstream a.example:443 \
  --cert /etc/fingerprint-bridge/b-chain.pem \
  --key /etc/fingerprint-bridge/b.key \
  --reports ./reports
```

浏览器访问 `https://b.example:8443/`。B 的上游固定为启动参数中的 A；客户端不能选择任意转发目标。上游证书链和主机名验证始终开启。`--ca` 用于额外信任的私有 CA；没有关闭验证的选项。

`--connect IP:PORT` 可以固定网络连接地址，但 SNI、HTTP authority 和证书验证仍使用 `--upstream`。每个下游连接对应一个上游连接，不跨用户池化连接、不添加 X-Forwarded-For/Via、不覆盖 User-Agent、不解压响应、不自动跟随重定向、不重试应用请求。

B 向客户端协商的 TLS 版本跟随 A 本次连接实际选择的 TLS 1.2 或 TLS 1.3，避免直连 A 使用 1.2、访问 B 却使用 1.3。该约束不等于两侧使用相同证书、密钥或全部握手消息。

`--strict-tls` 在实际出站 ClientHello 与入站的归一化特征不一致时，拒绝继续转发 HTTP。**此时上游 TCP/TLS 握手已经发生**，它不是发送 ClientHello 前的隐藏机制；它也不是 TCP/HTTP 的严格一致保证。

`--max-connections` 限制并发连接（默认 256）；`--handshake-timeout` 默认 15 秒；`--connection-lifetime` 是连接最长寿命（默认 3600 秒），不是空闲超时。默认监听本机 `127.0.0.1:8443`。

## 域名和 Cookie

会话以浏览器保存在 **B** 的 Cookie 为准：

* 请求 `Cookie` 原样转发，包括值与顺序，不维护另一个服务器端 cookie jar。
* 请求 `Host` / `:authority` 从配置的 B 改为 A。其他 authority 被拒绝。
* `Origin` / `Referer` 中**恰好匹配 B 的 HTTPS authority** 改为 A；保留路径、查询和转义形式。
* 响应 `Location` 中恰好匹配 A 的 HTTPS authority 改为 B。
* `Set-Cookie` 仅改匹配 A 的 `Domain` 属性，保留值、Path、Secure、HttpOnly、SameSite。没有 Domain 的 cookie 自然由浏览器存为 B 的 host-only cookie。
* 不进行全局字符串替换，不修改 HTML/JavaScript/响应体中的链接、CSP、CORS 响应头或 cookie 路径。故任意网站的登录、跳转和脚本兼容性不属于当前保证。

## 运行测试

```sh
cargo fmt --check
sh scripts/cargo-tls.sh clippy --locked --all-targets -- -D warnings
sh scripts/cargo-tls.sh test --locked
python3 -m venv .venv
.venv/bin/pip install -r scripts/requirements-test.txt
sh scripts/cargo-tls.sh build --locked --bin fingerprint-bridge --example language-client
.venv/bin/python scripts/lab.py
.venv/bin/python -m unittest discover -s scripts -p 'test_*.py' -v
```

`scripts/lab.py` 建立独立的 A/B 测试证书和本机 HTTPS 站点，以同一个 Python/OpenSSL 客户端分别直连 A 和经过 B，在 A 侧采集真实 ClientHello 与解密后的 HTTP。测试覆盖 HTTP/1.1、HTTP/2、多请求、Cookie、响应重写、二进制消息体、HPACK Huffman/动态表、HEADERS 分片/优先级/填充，以及拒绝错误证书主机名、不受信 CA、strict-TLS 不匹配。

`lab_pass=true` 表示这些功能断言通过，**不表示 `tls.pass=true` 或全层一致**。完整差异在 `test-results/lab/`。仓库内附本次本地实测结果；真实 Chrome/Firefox/Safari 和服务器 TCP 抓包尚待独立验收。

原生 TLS 回归测试另以一个明确配置、底层支持的客户端组合生成真实 ClientHello；该组合经映射后逐字段一致。这是指定组合的回归证据，不是浏览器认证。

混合组另有独立 Go `crypto/tls` 专项测试（Go 1.26+，CI 固定 1.27.1）：

```sh
mkdir -p target/matrix-clients
go build -o target/matrix-clients/hybrid-probe scripts/clients/hybrid_probe.go
.venv/bin/python scripts/hybrid_lab.py --output test-results/ci-hybrid-lab
```

每个新组测试正常握手、HelloRetryRequest、错误 EC 点、错误 key_share 长度、非规范 ML-KEM 公钥、被篡改的 ML-KEM 密文、错误证书主机名。正常情况必须完成真实 TLS 1.3 握手并传输带 B Cookie 的 HTTP；畸形点/长度/公钥必须产生 `illegal_parameter`，密文篡改和错误主机名必须在 HTTP 到达 A 前失败。该测试显式限定组以强制覆盖新能力；不改变下面矩阵中的默认客户端，也不把 HRR 功能通过视为完整 HRR 指纹一致。

ML-DSA 另用 Go 1.27.1 `crypto/mldsa` 独立对端生成 ML-DSA-44 CA、服务器证书和密钥：有效证书必须完成 TLS 1.3 与 HTTP，篡改证书签名必须在 HTTP 到达 A 前失败；A 同时验证 B Cookie 和改写后的 authority。它验证真实协商和签名，不只是 ClientHello 中出现算法编号。

DSA 专项测试使用独立 OpenSSL 对端，覆盖 6 个 TLS 1.2 DHE-DSS 套件与 SHA-1/224/256/384/512 五种握手签名的 30 个组合；另验证未提供签名算法和篡改证书必须失败。仅受控测试显式选择算法，矩阵客户端默认行为不变。SHA-384/512 的 DSA **证书签名**另由 OpenSSL 签发证书、独立 Go 服务端完成 TLS 1.2/1.3 握手验证；篡改签名和替换摘要 OID 均须在 HTTP 到达 A 前被拒绝。只有补丁后端声明这两项证书能力，未实现的 Ed448 仍被过滤。原握手能力结果见 [DSA 验证记录](test-results/DSA-VALIDATION.md)；新增证书能力见 [DSA 证书验证记录](test-results/DSA-CERTIFICATES-VALIDATION.md)。

AES-CCM 专项验证覆盖 12 个 TLS 1.2 RSA / DHE-RSA / ECDHE-ECDSA 套件，以及 TLS 1.3 `TLS_AES_128_CCM_SHA256` / `TLS_AES_128_CCM_8_SHA256`。B 上游只按入站提供列表启用这些能力，使用真实 CCM 加解密及 16/8 字节标签；TLS 1.3 的内容类型和填充也参与认证。独立 OpenSSL 测试验证大于 16 KiB 的双向 HTTP、Cookie 和域名改写、密文/标签篡改，以及拒绝未提供的套件。CCM 每个 traffic key 限制为 `2^23` 条记录，达到限额前须轮换密钥或重新连接；CCM8 首次认证失败即终止。该能力不包含 DTLS，也不继承客户端的会话恢复或 0-RTT。

实现范围、58 个真实握手案例、内部用量边界测试及双架构矩阵结果见 [CCM 验证记录](test-results/CCM-VALIDATION.md)。矩阵日志中的 `TLS_CAPABILITIES` 提供五组实测算法/扩展编号，不改变比较和严格门禁，也不替代原始报文复核。

## GitHub Actions 跨架构 / 发行版 / 语言矩阵

工作流 `.github/workflows/ci.yml` 在 push、pull request 和手动运行时执行。原有 Rust、HTTP/1.1、HTTP/2、证书拒绝测试保留；增加 **8 个原生环境、72 个客户端/协议组合**：

| 维度 | 覆盖 |
| --- | --- |
| 架构 | x86_64（`ubuntu-24.04`）、ARM64（`ubuntu-24.04-arm`）；不使用 QEMU |
| Linux 用户态 | Ubuntu 24.04、Debian 13、Fedora 43、Alpine 3.23（musl）官方容器 |
| Python | `http.client` + OpenSSL，HTTP/1.1 |
| Node.js | `https` / `http2` + OpenSSL，HTTP/1.1 和 HTTP/2 |
| Go | `net/http` + `crypto/tls`，HTTP/1.1 和 HTTP/2 |
| Java | JDK `HttpClient` + JSSE，HTTP/1.1 和 HTTP/2 |
| Rust 客户端 | `reqwest` + rustls，HTTP/1.1 和 HTTP/2；独立于 B 的 BoringSSL |

每个组合由**同一个客户端进程依次建立直连 1、直连 2、中转三个独立连接**，每条连接发送两次请求，验证 keep-alive/流复用。A 是隔离的测试站点，保持固定端口、证书、HTTP 响应；B 仅执行正常中转。证书链和主机名校验开启，Cookie 固定为浏览器保存在 B 的测试值，不访问真实网站或真实账号。

`scripts/matrix_lab.py` 在 A 侧采集实际 ClientHello、原始 HTTP/1.1 头部、有序 HTTP/2 头部、SETTINGS/WINDOW_UPDATE/PRIORITY、HPACK 字节摘要、HEADERS/CONTINUATION 长度/标志/优先级/填充，以及按源端口关联的初始 TCP SYN。先比较两次直连，建立基线；再逐层比较直连和中转。自然随机字段沿用前述归一化规则；**不按观察到的差异自动扩大忽略列表**。例如 rustls 自身随机排列扩展时，会保留 JA3/JA4 和原始顺序证据，报告基线不稳定，不伪称全层匹配。

默认启用严格验收：`match` 才通过；`mismatch`、`missing-evidence`、`inconclusive-baseline` 退出 1；编译、抓包、协议、客户端或采集错误退出 2。已知 TLS/HPACK 差异会让一致性检查变红，这是实际验收结果，不用 `continue-on-error` 掩盖。各环境 `fail-fast: false`，任何一个失败仍继续收集其他环境。

手动运行可设置 `strict=false` 只收集差异；它只放宽差异退出码，基础设施错误仍失败，报告中的 `fingerprint_pass` 不变。报告模式下绿色的任务不表示指纹一致。

Actions 的 `fingerprint consistency gate` 汇总完整的 72 行表。缺失环境、重复组合、错误架构、丢失 PCAP/ClientHello 均不能得到通过。每个 `matrix-evidence-架构-发行版` artifact 包含三个样本 JSON、实际 ClientHello、SYN PCAP、逐字段差异、客户端/B 日志、运行时和 TLS 库版本、镜像 ID；另有 `fingerprint-matrix-report` 总表。产物保留 14 天，不上传 CA 私钥。

**容器共享 GitHub runner 的 Linux 内核。** 该矩阵验证不同架构和发行版用户态/TLS 库，TCP 是对应 runner 的内核与 loopback 路径；它不代表各发行版独立内核、Windows/macOS 客户端、真实网络路径、浏览器、HTTP/3、会话恢复或任意其他 CPU 架构都已覆盖。TCP 缺失时不会降级成通过。

本机完整重现某个环境（需要 Docker；在 ARM64 主机上原生得到 ARM64 结果）：

```sh
docker build --build-arg BASE_IMAGE=debian:13 -f scripts/ci/Dockerfile -t fp-matrix .
mkdir -p test-results/ci-matrix-local
docker run --rm --network none --cap-drop ALL --cap-add NET_RAW \
  --security-opt no-new-privileges \
  -v "$PWD/test-results/ci-matrix-local:/evidence" fp-matrix
```

运行期间只使用容器 loopback，`NET_RAW` 用于 SYN 采集，不需要 `--privileged`。本地没有原始套接字权限时可运行 `--no-capture --report-only` 调试客户端，但这类报告始终标记 TCP 缺失，不能用于完整验收。Python 标准库没有 HTTP/2 客户端，所以 Python/h2 不作为假“跳过即通过”的组合；既有 Python/hpack 协议测试仍保留。

HPACK 修复与前后对比见 [第一轮验证记录](test-results/FINGERPRINT-FIX-VALIDATION.md)；后续修复见 [TLS 后端验证记录](test-results/TLS-BACKEND-VALIDATION.md)、[混合组 / TLS 1.3 验证记录](test-results/HYBRID-GROUP-VALIDATION.md) 和 [ML-DSA 证书验证记录](test-results/MLDSA-VALIDATION.md)。完整跨环境结果以各记录链接的 Actions 实际运行报告为准。

## 在 Linux 服务器抓包验收

测试脚本支持真实 loopback SYN 抓包，需要 root 或 CAP_NET_RAW：

```sh
sudo .venv/bin/python scripts/lab.py \
  --binary ./target/debug/fingerprint-bridge \
  --capture-interface lo \
  --output ./test-results/server-lab
```

只保存 `127.0.0.1 → 本次测试 A 端口` 的初始 SYN，按 A 实际接受连接的源端口匹配直连和中转。不会修改系统网络参数；服务器 A/B 均只监听 loopback 的临时高位端口。捕获失败会报错，不会自动跳过。**同一 Linux 主机上的匹配也不能代表 Windows/macOS/手机客户端经过 B 时匹配。**

真实部署可在自有测试采集点分别捕获一条直连流和一条中转流，导出 classic pcap 后比较：

```sh
./target/release/fingerprint-bridge inspect-pcap direct.pcap > direct-tcp.json
./target/release/fingerprint-bridge inspect-pcap bridged.pcap > bridged-tcp.json
./target/release/fingerprint-bridge compare direct-tcp.json bridged-tcp.json --layers tcp
```

先按五元组选择对应流。该命令不猜测多个连接之间的关联，也不重排、去重 PCAP 中的 SYN。支持 Ethernet/VLAN、RAW IP、Linux SLL/SLL2；不支持 PCAPNG、IPv4 分片或 IPv6 扩展头，遇到不能解析的相关包会报错。必要时用 `editcap -F pcap` 转换格式。

## TLS 报告与归一化

运行时 `--reports` 生成 `<id>.inbound.json`、`<id>.outbound.json` 和 `<id>.report.json`。它比较 **B 入站与 B 出站**；与独立的直连 A 基线是不同证据，不能混为一谈。这些 TLS 文件中的 HTTP/TCP 是 `null`，不会虚构在线观测。

实验室额外开启 `--http-evidence`，在 TLS 解密后、HTTP 改写前后记录同一条连接，并生成 `<id>.http.json`。该选项默认关闭，要求 `--reports`，会记录请求 Cookie 等明文；只用于受控测试，Unix 文件权限为 0600，每侧最多 1 MiB，截断会使验证失败。独立 Python 检查器比较请求顺序、控制帧、HPACK 表示/Huffman/索引及帧布局，仅豁免允许改写的 authority/origin/referer 值和必要编码长度。矩阵新增 B-paired TLS/HTTP 列；它们不替代 A 侧的两次直连与中转比较，也不会把不稳定基线改成通过。

```sh
./target/release/fingerprint-bridge compare reports/ID.inbound.json reports/ID.outbound.json --layers tls
# 默认要求 tls,http,tcp 三层，因此上述两个运行时文件默认完整验收会失败。
./target/release/fingerprint-bridge inspect-hello clienthello-records.bin > client-tls.json
```

TLS 归一化忽略 ClientRandom、session-id 值、密钥字节、SNI 值、padding 内容与长度、session ticket/PSK binder/cookie/ECH 密文；保留相应扩展的存在性和顺序，KeyShare 组与长度等结构。GREASE 数值归一化为同一保留值，位置保留。JA3/JA4 按其定义忽略 GREASE，并同时输出细项，防止“哈希一样但其他字段不同”被误判。

TCP 忽略地址、端口、序列号、确认号、校验和以及时间戳数值；保留时间戳是否存在、选项顺序、窗口、MSS、WS、SACK、TTL、DF 等。**TTL/MSS 差异不会自动以网络变化为由豁免。**

这些是明确的测量范围，不覆盖所有未知指纹。默认 TLS 报告不记录明文 Cookie、请求体、TLS 私钥或会话密钥。`--http-evidence` 会额外记录有界的明文请求，请勿对真实用户流量开启。

## 当前边界

* TCP 栈仍属于 B；只有 MSS/TTL 可显式设置。没有自动推测客户端 OS 或复制窗口缩放/拥塞控制/重传策略。
* TLS backend 不支持的套件、组、签名算法和扩展会被报告；未知扩展不原样注入加密握手。缺少重协商或 PSK 扩展时不再主动补入；推荐构建已修复 SCSV、混排 TLS 1.3/旧套件和无 padding 时误添加扩展的问题；部分签名算法/组/扩展仍不支持，padding 的任意位置、HelloRetryRequest 等完整指纹仍未保证，TLS 矩阵尚未通过。TLS 1.0/1.1 不支持。
* ALPS、真实 ECH 内层、客户端证书认证、跨连接 TLS 会话恢复/0-RTT、HelloRetryRequest 后的完整握手指纹未实现一致性。报告只解析首个 ClientHello。不使用固定 User-Agent 模板冒充实测。
* HTTP/2 分别维护入站/出站 HPACK 状态；未改字段保留原编码，改写值沿用原 Huffman 选择和索引方式。域名长度改变造成两侧动态表淘汰不同时会修正索引，已淘汰条目必要时改为不索引字面量。原分片边界尽量保留，长度变化由最后一片吸收，超出对端 SETTINGS_MAX_FRAME_SIZE 时增加分片。因此不承诺任意域名长度下的压缩字节和帧长相同。单帧/单头部块限制 1 MiB，动态表上限 64 KiB，单块至多 1024 帧。
* 不支持 HTTP/3/QUIC、HTTP Upgrade/WebSocket、CONNECT、HTTP/2 server push。HTTP/1.1 只接受 origin-form/OPTIONS `*`，拒绝 CL+TE、重复 Content-Length 和 obs-fold。
* 这是有界缓冲、并发限制和证书验证的原型，还没有生产负载或恶意流量审计。新增客户端/依赖版本必须重跑验收。

## 参考

* [TLS 1.3 / RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html)
* [HTTP/2 / RFC 9113](https://www.rfc-editor.org/rfc/rfc9113.html)
* [HPACK / RFC 7541](https://www.rfc-editor.org/rfc/rfc7541.html)
* [JA3 算法](https://github.com/salesforce/ja3)
* [JA4 TLS 指纹规范](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md)
* [btls](https://github.com/0x676e67/btls)

JA3/JA4 算法在本项目中独立实现；未复制 JA4+ 的非开源实现。本项目不实现 JA4H/JA4T 品牌算法，而是直接比较所列 HTTP/TCP 字段。
