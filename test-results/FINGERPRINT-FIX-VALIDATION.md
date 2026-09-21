# 指纹保留修复验证

## 修复前的证据

[Actions #6](https://github.com/csbxd/fingerprint-bridge/actions/runs/35627651431) 完成 72 个组合：48 mismatch、24 inconclusive-baseline、0 全层 match。TLS 72/72 有差异，HTTP/1.1 40/40 一致，HTTP/2 32/32 有差异，TCP SYN 72/72 一致（同一 runner 内核的 loopback 范围）。

## 本次修改

- HPACK 不再把整个头部块改成 never-indexed 字面量。保留原表示方式、名字索引、Huffman 选择；只有需改写的值重新编码。
- 每个连接/方向分别维护输入、输出动态表。处理域名长度变化引发的不同淘汰结果，修正索引，避免后续请求/响应解码失同步。
- HEADERS/CONTINUATION 保留原分片、优先级、填充与标志；长度变化先由最后一片吸收，遵守对端最大帧长。
- TLS 不再补入客户端未发送的 renegotiation_info/psk_key_exchange_modes；明确报告无法发送 renegotiation SCSV 的限制。
- 对固定版本 btls 的扩展排序传入完整的后端扩展表，避开其随机补齐路径及该路径中 seeds[i - offset] 的越界读取。补齐排序不等于启用扩展。
- 一致性比较规则、失败退出码、72 格覆盖要求均未放宽。

## 本地验证

30 项 Rust 测试（原 24 项及新增 6 项）、11 项 Python 测试、fmt、clippy 通过。新增回归覆盖 RFC 7541 Huffman 向量/全部字节、原编码不变、动态表不同淘汰与索引修复、连续响应 Cookie/Location、分帧/对端帧限制和 TLS 额外扩展。

五种语言的 9 个真实组合均完成请求、响应、Cookie、证书校验；HTTP/1.1 五种语言一致。HTTP/2 的结果如下，比较包含实际 A 侧 HPACK SHA-256、完整头部顺序及帧布局：

| 客户端 | 修复前 HTTP/2 | 修复后 HTTP/2 |
| --- | --- | --- |
| Node.js | DIFF | MATCH |
| Java | DIFF | MATCH |
| Rust | DIFF | MATCH |
| Go | DIFF；直连基线不稳定 | DIFF；直连之间头部顺序也变化 |

独立 HTTP/1.1/HTTP/2 实验、错误主机名/不信任 CA/strict-TLS 拒绝测试通过。

## 剩余限制

TLS 仍有后端缺失的套件、签名算法、组、扩展及套件排序差异；Rust 的两次独立直连还会随机排列 TLS 扩展。没有把这些差异变成白名单。仅 B 可改的条件下，B 的 TCP 栈也不能被宣称为任意客户端 TCP 栈的完整复制。

本地没有原始套接字权限，使用 --no-capture --report-only；TCP 缺失，fingerprint_pass=false，不构成全层通过。跨发行版、ARM64、真实 SYN 抓包的结果须读取此次修复提交对应的 GitHub Actions 报告；本文件不预先宣称远端通过。
