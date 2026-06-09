# 安全扫描报告

- 项目：go
- 路径：`/Users/aaron/Documents/Project/skills/tests/demo/projects/go`
- 生成时间：2026-06-10 04:49:00
- 扫描耗时：25.3 秒

## 报告总结

- TL;DR：发现 26 个已确认依赖风险项，其中 8 个为紧急项、10 个为高风险项，仓库安检仍有疑似硬编码凭证 1 处。 注意：本次检查不完整，部分官方漏洞源、包管理器或工具链检查失败，需复核后再判断剩余风险。
- 详细说明：本次检查覆盖项目 go，识别到 2 个依赖包，命中 26 个已确认风险项。仓库安检方面，发现疑似硬编码凭证 1 处、被 git 跟踪的敏感文件 0 个、建议补充的 .gitignore 规则 0 条、本地配置/工作流检查项 0 个、建议 1 条。过期依赖 0 个，建议按维护窗口和兼容性评估安排升级。另外，本次有部分官方漏洞源、包管理器或工具链检查失败；失败项补齐前，报告只代表成功完成的检查项。
- 能力边界：安全往往不是最显眼的需求，却是产品长期稳定运行的底线。此 Skill 会帮助你发现依赖漏洞、过期依赖和仓库暴露风险，帮助团队更早暴露容易被忽视的供应链问题。但它不能替代代码审计、渗透测试或部署安全评估；业务逻辑、权限控制、SQL 注入、XSS 等代码层风险仍需单独复核。
- 优先级建议：
  - 优先处理 18 个紧急/高风险项；依赖漏洞先处理有明确修复版本或官方处置路径的项，仓库安检项先处理工作流权限、凭证、容器和供应链配置。
  - 安排研发确认凭证和敏感文件是否真实有效；如有效，先轮换或撤销，再清理代码中的明文。
  - 依赖修复后必须重新运行扫描；如果仍出现同名旧版本，通常是间接依赖被父包锁定，需要询问用户是否确认升级父依赖到 latest。
  - 复查扫描错误，补齐失败的官方漏洞源、包管理器或工具链检查后再确认最终结论。


## 服务器运行环境

未启用服务器运行环境扫描。

## 命中风险项

| 影响程度 | 依赖名称 | 当前版本 | 安全编号 | 修复版本 | 说明 |
| --- | --- | --- | --- | --- | --- |
| 紧急 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | [CVE-2024-45337](https://www.cve.org/CVERecord?id=CVE-2024-45337)、[GHSA-v778-237x-gjrc](https://osv.dev/vulnerability/GHSA-v778-237x-gjrc)、[GO-2024-3321](https://osv.dev/vulnerability/GO-2024-3321) | 0.31.0 | golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 公告摘要：Misuse of ServerConfig.PublicKeyCallback may cause authorization bypass in golang.org/x/crypto；建议升级到 0.31.0 或更高版本。；EPSS 97.3%；CVSS 9.1；NVD 2024-12-12 |
| 紧急 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | [CVE-2026-39832](https://www.cve.org/CVERecord?id=CVE-2026-39832)、[GO-2026-5006](https://osv.dev/vulnerability/GO-2026-5006) | 0.52.0 | golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 公告摘要：Invoking agent constraints dropped when forwarding keys in golang.org/x/crypto/ssh/agent；建议升级到 0.52.0 或更高版本。；EPSS 21.1%；CVSS 9.1；CWE-502；NVD 2026-05-22 |
| 紧急 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | [CVE-2026-39830](https://www.cve.org/CVERecord?id=CVE-2026-39830)、[GO-2026-5017](https://osv.dev/vulnerability/GO-2026-5017) | 0.52.0 | golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 公告摘要：Invoking client can cause server deadlock on unexpected responses in golang.org/x/crypto/ssh；建议升级到 0.52.0 或更高版本。；EPSS 17.1%；CVSS 9.1；CWE-119；NVD 2026-05-22 |
| 紧急 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | [CVE-2026-39834](https://www.cve.org/CVERecord?id=CVE-2026-39834)、[GO-2026-5020](https://osv.dev/vulnerability/GO-2026-5020) | 0.52.0 | golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 公告摘要：Invoking infinite loop on large channel writes in golang.org/x/crypto/ssh；建议升级到 0.52.0 或更高版本。；EPSS 17.1%；CVSS 9.1；CWE-190；NVD 2026-05-22 |
| 紧急 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | [CVE-2026-46595](https://www.cve.org/CVERecord?id=CVE-2026-46595)、[GO-2026-5023](https://osv.dev/vulnerability/GO-2026-5023) | 0.52.0 | golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 公告摘要：Invoking VerifiedPublicKeyCallback permissions skip enforcement in golang.org/x/crypto/ssh；建议升级到 0.52.0 或更高版本。；EPSS 16.4%；CVSS 10；CWE-863；NVD 2026-05-22 |
| 紧急 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | [CVE-2026-39833](https://www.cve.org/CVERecord?id=CVE-2026-39833)、[GO-2026-5005](https://osv.dev/vulnerability/GO-2026-5005) | 0.52.0 | golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 公告摘要：Invoking key constraints not enforced in golang.org/x/crypto/ssh/agent；建议升级到 0.52.0 或更高版本。；EPSS 13%；CVSS 9.1；CWE-862；NVD 2026-05-22 |
| 紧急 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | [CVE-2026-42508](https://www.cve.org/CVERecord?id=CVE-2026-42508)、[GO-2026-5021](https://osv.dev/vulnerability/GO-2026-5021) | 0.52.0 | golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 公告摘要：Invoking auth bypass via unenforced @revoked status in golang.org/x/crypto/ssh/knownhosts；建议升级到 0.52.0 或更高版本。；EPSS 11.7%；CVSS 9.1；CWE-295；NVD 2026-05-22 |
| 紧急 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | [CVE-2026-39831](https://www.cve.org/CVERecord?id=CVE-2026-39831)、[GO-2026-5019](https://osv.dev/vulnerability/GO-2026-5019) | 0.52.0 | golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 公告摘要：Invoking bypass of FIDO/U2F security keys physical interaction in golang.org/x/crypto/ssh；建议升级到 0.52.0 或更高版本。；EPSS 10%；CVSS 9.1；CWE-862；NVD 2026-05-22 |
| 高风险 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | [CVE-2025-22869](https://www.cve.org/CVERecord?id=CVE-2025-22869)、[GHSA-hcg3-q754-cr77](https://osv.dev/vulnerability/GHSA-hcg3-q754-cr77)、[GO-2025-3487](https://osv.dev/vulnerability/GO-2025-3487) | 0.35.0 | golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 存在拒绝服务风险；建议升级到 0.35.0 或更高版本。；EPSS 69.6%；CVSS 7.5；CWE-770；NVD 2025-02-26 |
| 高风险 | github.com/gin-gonic/gin | v1.6.3 | [CVE-2020-28483](https://www.cve.org/CVERecord?id=CVE-2020-28483)、[GHSA-h395-qcrw-5vmq](https://osv.dev/vulnerability/GHSA-h395-qcrw-5vmq)、[GO-2021-0052](https://osv.dev/vulnerability/GO-2021-0052) | 1.7.7 | github.com/gin-gonic/gin v1.6.3 公告摘要：Inconsistent Interpretation of HTTP Requests in github.com/gin-gonic/gin；建议升级到 1.7.7 或更高版本。；EPSS 58.5%；CVSS 7.1；CWE-444；NVD 2021-01-20 |
| 高风险 | github.com/gin-gonic/gin | v1.6.3 | [CVE-2023-26125](https://www.cve.org/CVERecord?id=CVE-2023-26125)、[GHSA-3vp4-m3rf-835h](https://osv.dev/vulnerability/GHSA-3vp4-m3rf-835h) | 1.9.0 | github.com/gin-gonic/gin v1.6.3 公告摘要：Improper input validation in github.com/gin-gonic/gin；建议升级到 1.9.0 或更高版本。；EPSS 55.2%；CVSS 7.3；CWE-20、CWE-77；NVD 2023-05-04 |
| 高风险 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | [CVE-2022-30636](https://www.cve.org/CVERecord?id=CVE-2022-30636)、[GO-2024-2961](https://osv.dev/vulnerability/GO-2024-2961) | 0.0.0-20220525230936-793ad666bf5e | golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 公告摘要：Limited directory traversal vulnerability on Windows in golang.org/x/crypto；建议升级到 0.0.0-20220525230936-793ad666bf5e 或更高版本。；EPSS 40.6%；CVSS 7.5；NVD 2024-07-02 |
| 高风险 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | [CVE-2022-27191](https://www.cve.org/CVERecord?id=CVE-2022-27191)、[GHSA-8c26-wmh5-6g9v](https://osv.dev/vulnerability/GHSA-8c26-wmh5-6g9v)、[GO-2021-0356](https://osv.dev/vulnerability/GO-2021-0356) | 0.0.0-20220314234659-1baeb1ce4c0b | golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 存在拒绝服务风险；建议升级到 0.0.0-20220314234659-1baeb1ce4c0b 或更高版本。；EPSS 25.3%；CVSS 7.5；NVD 2022-03-18 |
| 高风险 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | [CVE-2026-46597](https://www.cve.org/CVERecord?id=CVE-2026-46597)、[GO-2026-5013](https://osv.dev/vulnerability/GO-2026-5013) | 0.52.0 | golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 公告摘要：Invoking byte arithmetic causes underflow and panic in golang.org/x/crypto/ssh；建议升级到 0.52.0 或更高版本。；EPSS 17.1%；CVSS 7.5；CWE-704；NVD 2026-05-22 |
| 高风险 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | [CVE-2026-39829](https://www.cve.org/CVERecord?id=CVE-2026-39829)、[GO-2026-5018](https://osv.dev/vulnerability/GO-2026-5018) | 0.52.0 | golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 存在拒绝服务风险；建议升级到 0.52.0 或更高版本。；EPSS 10.8%；CVSS 7.5；CWE-347；NVD 2026-05-22 |
| 高风险 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | [CVE-2020-29652](https://www.cve.org/CVERecord?id=CVE-2020-29652)、[GHSA-3vm4-22fp-5rfm](https://osv.dev/vulnerability/GHSA-3vm4-22fp-5rfm)、[GO-2021-0227](https://osv.dev/vulnerability/GO-2021-0227) | 0.0.0-20201216223049-8b5274cf687f | golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 公告摘要：golang.org/x/crypto/ssh NULL Pointer Dereference vulnerability；建议升级到 0.0.0-20201216223049-8b5274cf687f 或更高版本。；EPSS 9.2%；CVSS 7.5；CWE-476；NVD 2020-12-17 |
| 高风险 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | [CVE-2021-43565](https://www.cve.org/CVERecord?id=CVE-2021-43565)、[GHSA-gwc9-m7rh-j2ww](https://osv.dev/vulnerability/GHSA-gwc9-m7rh-j2ww)、[GO-2022-0968](https://osv.dev/vulnerability/GO-2022-0968) | 0.0.0-20211202192323-5770296d904e | golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 公告摘要：x/crypto/ssh vulnerable to panic via malformed packets；建议升级到 0.0.0-20211202192323-5770296d904e 或更高版本。；EPSS 7.7%；CVSS 7.5；NVD 2022-09-06 |
| 高风险 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | [CVE-2025-47913](https://www.cve.org/CVERecord?id=CVE-2025-47913)、[GHSA-56w8-48fp-6mgv](https://osv.dev/vulnerability/GHSA-56w8-48fp-6mgv)、[GO-2025-4116](https://osv.dev/vulnerability/GO-2025-4116) | 0.43.0 | golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 存在拒绝服务风险；建议升级到 0.43.0 或更高版本。；EPSS 6%；CVSS 7.5；CWE-617；NVD 2025-11-13 |
| 中风险 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | [CVE-2023-48795](https://www.cve.org/CVERecord?id=CVE-2023-48795)、[GHSA-45x7-px36-x8w8](https://osv.dev/vulnerability/GHSA-45x7-px36-x8w8)、[GO-2023-2402](https://osv.dev/vulnerability/GO-2023-2402) | 0.17.0、0.0.0-20231218163308-9d2ee975ef9f | golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 公告摘要：Prefix Truncation Attack against ChaCha20-Poly1305 and Encrypt-then-MAC aka Terrapin；建议升级到 0.17.0、0.0.0-20231218163308-9d2ee975ef9f 或更高版本。；EPSS 98%；CVSS 5.9；CWE-354；NVD 2023-12-18 |
| 中风险 | github.com/gin-gonic/gin | v1.6.3 | [CVE-2023-29401](https://www.cve.org/CVERecord?id=CVE-2023-29401)、[GHSA-2c4m-59x9-fr2g](https://osv.dev/vulnerability/GHSA-2c4m-59x9-fr2g)、[GO-2023-1737](https://osv.dev/vulnerability/GO-2023-1737) | 1.9.1 | github.com/gin-gonic/gin v1.6.3 公告摘要：Gin Web Framework does not properly sanitize filename parameter of Context.FileAttachment function；建议升级到 1.9.1 或更高版本。；EPSS 63%；CVSS 4.3；CWE-494；NVD 2023-06-08 |
| 中风险 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | [CVE-2026-46598](https://www.cve.org/CVERecord?id=CVE-2026-46598)、[GO-2026-5033](https://osv.dev/vulnerability/GO-2026-5033) | 0.52.0 | golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 公告摘要：Invoking pathological inputs can lead to client panic in golang.org/x/crypto/ssh/agent；建议升级到 0.52.0 或更高版本。；EPSS 16%；CVSS 5.3；CWE-129；NVD 2026-05-22 |
| 中风险 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | [CVE-2025-58181](https://www.cve.org/CVERecord?id=CVE-2025-58181)、[GHSA-j5w8-q4qc-rx2x](https://osv.dev/vulnerability/GHSA-j5w8-q4qc-rx2x)、[GO-2025-4134](https://osv.dev/vulnerability/GO-2025-4134) | 0.45.0 | golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 公告摘要：golang.org/x/crypto/ssh allows an attacker to cause unbounded memory consumption；建议升级到 0.45.0 或更高版本。；EPSS 14.4%；CVSS 5.3；CWE-770；NVD 2025-11-19 |
| 中风险 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | [CVE-2026-39828](https://www.cve.org/CVERecord?id=CVE-2026-39828)、[GO-2026-5014](https://osv.dev/vulnerability/GO-2026-5014) | 0.52.0 | golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 公告摘要：Invoking bypass of certificate restrictions in golang.org/x/crypto/ssh；建议升级到 0.52.0 或更高版本。；EPSS 10.5%；CVSS 6.3；CWE-295；NVD 2026-05-22 |
| 中风险 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | [CVE-2026-39835](https://www.cve.org/CVERecord?id=CVE-2026-39835)、[GO-2026-5015](https://osv.dev/vulnerability/GO-2026-5015) | 0.52.0 | golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 公告摘要：Invoking server panic during CheckHostKey/Authenticate in golang.org/x/crypto/ssh；建议升级到 0.52.0 或更高版本。；EPSS 8.9%；CVSS 5.3；CWE-295；NVD 2026-05-22 |
| 中风险 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | [CVE-2026-39827](https://www.cve.org/CVERecord?id=CVE-2026-39827)、[GO-2026-5016](https://osv.dev/vulnerability/GO-2026-5016) | 0.52.0 | golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 存在拒绝服务风险；建议升级到 0.52.0 或更高版本。；EPSS 6.6%；CVSS 6.5；CWE-924；NVD 2026-05-22 |
| 中风险 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | [CVE-2025-47914](https://www.cve.org/CVERecord?id=CVE-2025-47914)、[GHSA-f6x5-jh6r-wrfv](https://osv.dev/vulnerability/GHSA-f6x5-jh6r-wrfv)、[GO-2025-4135](https://osv.dev/vulnerability/GO-2025-4135) | 0.45.0 | golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 公告摘要：golang.org/x/crypto/ssh/agent vulnerable to panic if message is malformed due to out of bounds read；建议升级到 0.45.0 或更高版本。；EPSS 2.6%；CVSS 5.3；CWE-125；NVD 2025-11-19 |


## 仓库安检

- 硬编码密钥：发现 1 处疑似明文凭证。
- 敏感文件跟踪：没有发现被 git 跟踪的敏感文件。
- .gitignore：没有发现需要补充的敏感文件忽略规则。
- 本地配置检查：发现 0 个需要确认的仓库安检项，1 条建议。

| 位置 | 类型 | 可信度 | 证据预览 |
| --- | --- | --- | --- |
| config/config.go:5 | PostgreSQL 连接字符串 | high | postgre...host |

### 依赖配置与维护

| 等级 | 位置 | 检查项 | 依据 | 处理 |
| --- | --- | --- | --- | --- |
| 建议 | .github/dependabot.yml | 配置 Dependabot | GitHub remote origin: git@github.com:27Aaron/skills.git | .github/dependabot.yml，建议创建覆盖 gomod 的配置；推送到 GitHub 后，Dependabot 会按 schedule 检查更新。 |


## 过期依赖

没有检测到明确的过期依赖，或当前包管理器没有返回可用结果。

提醒：过期依赖用于版本维护规划；处理顺序仍以当前风险项和发布窗口为准。


## 覆盖说明

### 1. 疑似硬编码凭证：config/config.go:5
- 影响程度：高风险
- 位置：`config/config.go`
- 为什么要关注：扫描在 config/config.go:5 发现PostgreSQL 连接字符串特征，需要研发确认是否是真实可用凭证。
- 可能影响：如果该凭证真实可用，泄露后可能造成未授权访问或数据暴露。
- 建议动作：先确认是否真实有效；如有效，先轮换或撤销，再移除代码中的明文。


## 扫描错误

- [outdated_check] 命令不可用：go


## 下一步建议

- 优先处理 18 个紧急/高风险项；依赖漏洞先处理有明确修复版本或官方处置路径的项，仓库安检项先处理工作流权限、凭证、容器和供应链配置。
- 安排研发确认凭证和敏感文件是否真实有效；如有效，先轮换或撤销，再清理代码中的明文。
- 依赖修复后必须重新运行扫描；如果仍出现同名旧版本，通常是间接依赖被父包锁定，需要询问用户是否确认升级父依赖到 latest。
- 复查扫描错误，补齐失败的官方漏洞源、包管理器或工具链检查后再确认最终结论。
- 依赖修复后必须重新运行扫描，确认风险项是否真正消失。
- 修复脚本只执行普通包管理器升级；如果复扫仍出现同名旧版本，报告中会标注父依赖信息，可继续升级父依赖来解除锁定。
