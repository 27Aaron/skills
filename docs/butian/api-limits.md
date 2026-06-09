# API 限流与使用策略

扫描过程中会调用以下外部 API 获取漏洞和威胁情报数据。本文档汇总各服务的限流策略和处理方式。

## 数据源概览

| 数据源                                                                   | 用途                 | 是否需要 API Key |
| ------------------------------------------------------------------------ | -------------------- | ---------------- |
| [OSV](https://osv.dev/)                                                  | 依赖漏洞查询         | 否               |
| [NVD](https://nvd.nist.gov/)                                             | CVE 详情和 CVSS 评分 | 否               |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 已知被利用漏洞目录   | 否               |
| [FIRST EPSS](https://www.first.org/epss/)                                | 漏洞利用预测评分     | 否               |

---

## OSV (Open Source Vulnerabilities)

**端点**:

- 批量查询: `POST https://api.osv.dev/v1/querybatch`
- 单个漏洞: `GET https://api.osv.dev/v1/vulns/{id}`

**限流策略**:

- 官方未公布硬性速率限制
- 建议使用批量查询（`querybatch`），每次最多 100 个包
- 避免短时间内大量并发请求

**行为**:

- 默认按 100 个包一批进行批量查询
- 单线程顺序执行，避免触发限流
- 失败后指数退避重试（1s → 3s）

---

## NVD (National Vulnerability Database)

**端点**:

- CVE API 2.0: `GET https://services.nvd.nist.gov/rest/json/cves/2.0`

**限流策略（官方文档）**:

| 认证方式   | 速率限制                     |
| ---------- | ---------------------------- |
| 无 API Key | 5 次请求 / 30 秒（滚动窗口） |

**行为**:

- 使用批量查询参数 `cveIds`，单次查询最多包含多个 CVE ID
- 失败后指数退避重试（1s → 3s）

---

## CISA KEV (Known Exploited Vulnerabilities)

**端点**:

- 目录下载: `GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

**限流策略**:

- 单文件下载，约 2MB JSON
- 无明确速率限制，但建议缓存

**行为**:

- 下载后本地缓存 24 小时
- 缓存位置: `.butian/cache/kev/catalog.json`

---

## FIRST EPSS (Exploit Prediction Scoring System)

**端点**:

- 批量查询: `GET https://api.first.org/epss/?cve=CVE-2024-XXXX,CVE-2024-YYYY`

**限流策略**:

- 官方未公布硬性速率限制
- 建议批量查询，单次最多 100 个 CVE
- 非商业用途免费使用

**行为**:

- 按批次查询 EPSS 数据（100 CVE/批）
- 单线程顺序执行

---

## 通用优化策略

### 重试机制

所有 API 调用使用指数退避重试：

- 第一次重试: 1 秒后
- 第二次重试: 3 秒后
- 最多重试 2 次

### 并发策略

所有网络请求均为**单线程顺序执行**，避免触发外部 API 限流和不可预期的并发问题。

### 离线 / 弱网环境

如果在无法访问外部 API 的环境中运行：

- 扫描器会优雅降级，记录错误到 `errors` 列表
- 本地扫描（密钥检测、敏感文件、gitignore）不受影响
- 漏洞和过期依赖检查会被跳过
