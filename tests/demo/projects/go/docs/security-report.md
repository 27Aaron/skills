# 安全扫描报告

- 项目：go
- 路径：`/Users/aaron/Documents/Project/skills/tests/demo/projects/go`
- 生成时间：2026-06-10 07:19:11
- 扫描耗时：37.2 秒

## 报告总结

- TL;DR：发现 26 个已确认依赖风险项，其中 8 个为紧急项、10 个为高风险项，仓库安检仍有疑似硬编码凭证 1 处。 注意：本次检查不完整，部分官方漏洞源、包管理器或工具链检查失败，需复核后再判断剩余风险。
- 详细说明：本次检查覆盖项目 go，识别到 2 个依赖包，命中 26 个已确认风险项。仓库安检方面，发现疑似硬编码凭证 1 处、被 git 跟踪的敏感文件 0 个、建议补充的 .gitignore 规则 0 条、本地配置/工作流检查项 0 个、建议 1 条。过期依赖 0 个，建议按维护窗口和兼容性评估安排升级。另外，本次有部分官方漏洞源、包管理器或工具链检查失败；失败项补齐前，报告只代表成功完成的检查项。
- 能力边界：安全往往不是最显眼的需求，却是产品长期稳定运行的底线。此报告基于本地可确认的依赖和仓库证据，帮助你发现应用依赖漏洞、过期依赖和仓库暴露风险，并把可处理的问题整理成清晰的修复线索。它不能替代代码审计、渗透测试或完整安全评估；业务逻辑、权限控制、输入校验、SQL 注入、XSS 等代码层风险仍需结合业务场景复核。安全的价值不只在于发现问题，更在于让团队知道风险在哪里、先处理什么，以及如何让每一次修复都成为系统可靠性的积累。
- 优先级建议：
  - 优先处理 18 个紧急/高风险项；依赖漏洞先处理有明确修复版本或官方处置路径的项，仓库安检项先处理工作流权限、凭证、容器和供应链配置。
  - 安排研发确认凭证和敏感文件是否真实有效；如有效，先轮换或撤销，再清理代码中的明文。
  - 依赖修复后必须重新运行扫描；如果仍出现同名旧版本，通常是间接依赖被父包锁定，需要询问用户是否确认升级父依赖到 latest。
  - 复查扫描错误，补齐失败的官方漏洞源、包管理器或工具链检查后再确认最终结论。


## 当前风险

| 影响程度 | 依赖名称 | 当前版本 | 修复版本 | 安全编号 |
| --- | --- | --- | --- | --- |
| 紧急 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | 0.31.0 | [CVE-2024-45337](https://www.cve.org/CVERecord?id=CVE-2024-45337)、[GHSA-v778-237x-gjrc](https://osv.dev/vulnerability/GHSA-v778-237x-gjrc)、[GO-2024-3321](https://osv.dev/vulnerability/GO-2024-3321) |
| 紧急 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | 0.52.0 | [CVE-2026-39832](https://www.cve.org/CVERecord?id=CVE-2026-39832)、[GO-2026-5006](https://osv.dev/vulnerability/GO-2026-5006) |
| 紧急 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | 0.52.0 | [CVE-2026-39830](https://www.cve.org/CVERecord?id=CVE-2026-39830)、[GO-2026-5017](https://osv.dev/vulnerability/GO-2026-5017) |
| 紧急 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | 0.52.0 | [CVE-2026-39834](https://www.cve.org/CVERecord?id=CVE-2026-39834)、[GO-2026-5020](https://osv.dev/vulnerability/GO-2026-5020) |
| 紧急 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | 0.52.0 | [CVE-2026-46595](https://www.cve.org/CVERecord?id=CVE-2026-46595)、[GO-2026-5023](https://osv.dev/vulnerability/GO-2026-5023) |
| 紧急 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | 0.52.0 | [CVE-2026-39833](https://www.cve.org/CVERecord?id=CVE-2026-39833)、[GO-2026-5005](https://osv.dev/vulnerability/GO-2026-5005) |
| 紧急 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | 0.52.0 | [CVE-2026-42508](https://www.cve.org/CVERecord?id=CVE-2026-42508)、[GO-2026-5021](https://osv.dev/vulnerability/GO-2026-5021) |
| 紧急 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | 0.52.0 | [CVE-2026-39831](https://www.cve.org/CVERecord?id=CVE-2026-39831)、[GO-2026-5019](https://osv.dev/vulnerability/GO-2026-5019) |
| 高风险 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | 0.35.0 | [CVE-2025-22869](https://www.cve.org/CVERecord?id=CVE-2025-22869)、[GHSA-hcg3-q754-cr77](https://osv.dev/vulnerability/GHSA-hcg3-q754-cr77)、[GO-2025-3487](https://osv.dev/vulnerability/GO-2025-3487) |
| 高风险 | github.com/gin-gonic/gin | v1.6.3 | 1.7.7 | [CVE-2020-28483](https://www.cve.org/CVERecord?id=CVE-2020-28483)、[GHSA-h395-qcrw-5vmq](https://osv.dev/vulnerability/GHSA-h395-qcrw-5vmq)、[GO-2021-0052](https://osv.dev/vulnerability/GO-2021-0052) |
| 高风险 | github.com/gin-gonic/gin | v1.6.3 | 1.9.0 | [CVE-2023-26125](https://www.cve.org/CVERecord?id=CVE-2023-26125)、[GHSA-3vp4-m3rf-835h](https://osv.dev/vulnerability/GHSA-3vp4-m3rf-835h) |
| 高风险 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | 待确认 | [CVE-2022-30636](https://www.cve.org/CVERecord?id=CVE-2022-30636)、[GO-2024-2961](https://osv.dev/vulnerability/GO-2024-2961) |
| 高风险 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | 待确认 | [CVE-2022-27191](https://www.cve.org/CVERecord?id=CVE-2022-27191)、[GHSA-8c26-wmh5-6g9v](https://osv.dev/vulnerability/GHSA-8c26-wmh5-6g9v)、[GO-2021-0356](https://osv.dev/vulnerability/GO-2021-0356) |
| 高风险 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | 0.52.0 | [CVE-2026-46597](https://www.cve.org/CVERecord?id=CVE-2026-46597)、[GO-2026-5013](https://osv.dev/vulnerability/GO-2026-5013) |
| 高风险 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | 0.52.0 | [CVE-2026-39829](https://www.cve.org/CVERecord?id=CVE-2026-39829)、[GO-2026-5018](https://osv.dev/vulnerability/GO-2026-5018) |
| 高风险 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | 待确认 | [CVE-2020-29652](https://www.cve.org/CVERecord?id=CVE-2020-29652)、[GHSA-3vm4-22fp-5rfm](https://osv.dev/vulnerability/GHSA-3vm4-22fp-5rfm)、[GO-2021-0227](https://osv.dev/vulnerability/GO-2021-0227) |
| 高风险 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | 待确认 | [CVE-2021-43565](https://www.cve.org/CVERecord?id=CVE-2021-43565)、[GHSA-gwc9-m7rh-j2ww](https://osv.dev/vulnerability/GHSA-gwc9-m7rh-j2ww)、[GO-2022-0968](https://osv.dev/vulnerability/GO-2022-0968) |
| 高风险 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | 0.43.0 | [CVE-2025-47913](https://www.cve.org/CVERecord?id=CVE-2025-47913)、[GHSA-56w8-48fp-6mgv](https://osv.dev/vulnerability/GHSA-56w8-48fp-6mgv)、[GO-2025-4116](https://osv.dev/vulnerability/GO-2025-4116) |
| 中风险 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | 0.17.0 | [CVE-2023-48795](https://www.cve.org/CVERecord?id=CVE-2023-48795)、[GHSA-45x7-px36-x8w8](https://osv.dev/vulnerability/GHSA-45x7-px36-x8w8)、[GO-2023-2402](https://osv.dev/vulnerability/GO-2023-2402) |
| 中风险 | github.com/gin-gonic/gin | v1.6.3 | 1.9.1 | [CVE-2023-29401](https://www.cve.org/CVERecord?id=CVE-2023-29401)、[GHSA-2c4m-59x9-fr2g](https://osv.dev/vulnerability/GHSA-2c4m-59x9-fr2g)、[GO-2023-1737](https://osv.dev/vulnerability/GO-2023-1737) |
| 中风险 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | 0.52.0 | [CVE-2026-46598](https://www.cve.org/CVERecord?id=CVE-2026-46598)、[GO-2026-5033](https://osv.dev/vulnerability/GO-2026-5033) |
| 中风险 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | 0.45.0 | [CVE-2025-58181](https://www.cve.org/CVERecord?id=CVE-2025-58181)、[GHSA-j5w8-q4qc-rx2x](https://osv.dev/vulnerability/GHSA-j5w8-q4qc-rx2x)、[GO-2025-4134](https://osv.dev/vulnerability/GO-2025-4134) |
| 中风险 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | 0.52.0 | [CVE-2026-39828](https://www.cve.org/CVERecord?id=CVE-2026-39828)、[GO-2026-5014](https://osv.dev/vulnerability/GO-2026-5014) |
| 中风险 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | 0.52.0 | [CVE-2026-39835](https://www.cve.org/CVERecord?id=CVE-2026-39835)、[GO-2026-5015](https://osv.dev/vulnerability/GO-2026-5015) |
| 中风险 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | 0.52.0 | [CVE-2026-39827](https://www.cve.org/CVERecord?id=CVE-2026-39827)、[GO-2026-5016](https://osv.dev/vulnerability/GO-2026-5016) |
| 中风险 | golang.org/x/crypto | v0.0.0-20200622213623-75b288015ac9 | 0.45.0 | [CVE-2025-47914](https://www.cve.org/CVERecord?id=CVE-2025-47914)、[GHSA-f6x5-jh6r-wrfv](https://osv.dev/vulnerability/GHSA-f6x5-jh6r-wrfv)、[GO-2025-4135](https://osv.dev/vulnerability/GO-2025-4135) |


## 仓库安检

- 硬编码密钥：发现 1 处疑似明文凭证。
- 敏感文件跟踪：没有发现被 git 跟踪的敏感文件。
- .gitignore：没有发现需要补充的敏感文件忽略规则。
- 本地配置检查：发现 0 个需要确认的仓库安检项，1 条建议。

| 位置 | 类型 | 可信度 | 证据预览 |
| --- | --- | --- | --- |
| config/config.go:5 | PostgreSQL 连接字符串 | high | postgre...host |

### 依赖配置与维护

| 等级 | 位置 | 检查项 | 处理 |
| --- | --- | --- | --- |
| 建议 | .github/dependabot.yml | 配置 Dependabot | .github/dependabot.yml，建议创建覆盖 gomod 的配置；推送到 GitHub 后，Dependabot 会按 schedule 检查更新。 |


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
