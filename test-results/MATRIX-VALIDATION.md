# 跨平台矩阵的本地验证记录

本次变更新增 2 架构 × 4 Linux 用户态发行版 × 9 客户端/协议组合，共 72 个验收格。

## 已执行

- `cargo fmt --check`、`cargo clippy --locked --all-targets -- -D warnings`、构建通过。
- 原有 24 项 Rust 测试通过。
- 新增 10 项 Python 测试通过，覆盖缺失/重复组合、架构错误、PCAP 丢失、伪造通过标志、TLS/HTTP/TCP 人为差异、直连基线变化和分片 ClientHello 采集。
- `actionlint 1.7.7` 和 `git diff --check` 通过。
- Python、Node.js、Go、Java、Rust 的 9 个实际客户端/协议组合在本机均完成三条连接，每条连接两次请求；证书、域名/Cookie/Location、响应体断言通过。
- 原有独立 HTTP/1.1、HTTP/2 HTTPS 实验及三种证书/strict-TLS 拒绝实验重新通过。
- `--no-capture` 的严格执行返回 1，报告 `fingerprint_pass=false`；未具备原始套接字权限却请求抓包时，即使使用 `--report-only` 也返回 2 并保存错误。

## 实际指纹结果与范围

本地完整指纹判定**没有通过**：TCP 采集权限缺失；五种语言的 HTTP/1.1 头部一致，四种语言的 HTTP/2 HPACK/帧布局有差异，TLS 存在逐字段差异。rustls 的两次直连还出现扩展顺序随机化，原始证据保留该变化，不能把直连基线本身不稳定判成稳定一致。

本地使用 Ubuntu x86_64 用户态；没有本地 Docker daemon，未在这里执行 ARM64 或发行版容器。跨环境构建、原始 TCP SYN 采集和汇总结果以对应 GitHub Actions 运行的 artifacts 为准。本文件不预先宣称远端矩阵通过。

严格工作流预期会揭示既有 TLS/HPACK 等差异；它不会用允许列表、`continue-on-error` 或缺失即跳过来制造绿色的一致性结果。协议功能回归和完整指纹一致性是不同结论。
