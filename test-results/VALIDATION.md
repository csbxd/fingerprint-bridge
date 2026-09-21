# 验证记录

日期：2026-09-21。环境：Linux x86_64、Rust 1.98.1、Python 3.12.14、OpenSSL 3.5.8。

| 验证 | 结果 | 范围 |
| --- | --- | --- |
| `cargo fmt --check` | 通过 | Rust 格式 |
| `cargo clippy --locked --all-targets -- -D warnings` | 通过 | 编译与静态检查 |
| `cargo test --locked` | 24 通过，0 失败，0 忽略 | TLS/HTTP/TCP 解析、转换、差异和原生 TLS 回归 |
| 独立 HTTPS HTTP/1.1 测试 | 通过 | 在 A 测试站点比较直连与中转的请求行、头部值/顺序、B Cookie、二进制请求/响应体、持久连接 |
| 独立 HTTPS HTTP/2 测试 | 通过 | 原始 SETTINGS 顺序/值、WINDOW_UPDATE、PRIORITY、流 ID、伪头部/普通头部顺序、重复字段、Cookie、响应重写 |
| 指定原生 TLS 客户端组合 | 归一化字段全部一致 | 由真实 BoringSSL 序列化产生 ClientHello，再经映射重新序列化；TLS 1.2/1.3、指定密码套件/支持组/签名算法、h2/HTTP1 ALPN、OCSP/SCT |
| Python/OpenSSL 默认 TLS 客户端 | 存在差异 | 6 类细项以及 JA3/JA4 摘要差异；详见 JSON，未当作通过 |
| 错误上游证书主机名 | 请求被阻止 | 未转发 HTTP |
| 不受信任上游 CA | 请求被阻止 | 未转发 HTTP |
| `--strict-tls` 不匹配 | 请求被阻止 | 完成上游 TLS 后，尚未转发 HTTP；不表示上游未看到握手 |
| 缺失 TCP/HTTP 证据 | 验收失败 | 不以“未采集”替代“一致” |
| 真实 TCP SYN 抓包 | 未执行 | 当前本地运行环境没有 CAP_NET_RAW；已提供可选 Linux 抓包入口 |
| 用户提供的 SSH 测试机 | 未连接成功 | DNS 解析失败；经已配置代理尝试时 SSH banner 阶段超时，尚未进行密钥认证 |
| GitHub Actions | 已编写，尚未运行 | 必须在推送后检查实际 workflow 结果 |

## 独立 TLS 实测差异

Python/OpenSSL 默认客户端包含底层 backend 不能复现的算法或行为。HTTP/1.1、HTTP/2 两条链路均观察到：

* 密码套件列表存在差异；TLS 1.3 套件顺序已经按输入保留。
* 扩展列表、支持组、点格式、签名算法和其他扩展载荷存在差异。
* JA3、JA3 原始串和 JA4 因上述差异而不同。

该测试验证了差异检测确实生效，并不认证该默认客户端的 TLS 一致性。指定原生 TLS 客户端组合的正例则证明可配置范围内的实际报文保持有效。

## 证据文件

* `lab/lab-summary.json`：完整比较及三个拒绝测试的结果。
* `lab/http-1.1.direct.json` / `lab/http-1.1.bridged.json`：独立 A 测试站点采集的 HTTP/1.1 与 TLS 证据。
* `lab/h2.direct.json` / `lab/h2.bridged.json`：独立 A 测试站点采集的 HTTP/2 与 TLS 证据。

这些文件中的域名、Cookie 和端口均来自临时本机测试。证书、私钥和 SSH 密钥未包含在项目中。

不能将这份记录解读为 Chrome/Firefox/Safari/移动设备的全指纹认证、生产压测结论或异地网络 TCP 一致性证明。
