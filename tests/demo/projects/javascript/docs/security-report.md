# 安全扫描报告

- 项目：javascript
- 路径：`/Users/aaron/Documents/Project/skills/tests/demo/projects/javascript`
- 生成时间：2026-06-10 19:17:10
- 扫描耗时：7.0 秒

## 报告总结

- 结论：本次在 2 个 npm 依赖中命中 7 个已确认依赖风险项，其中 3 个需要优先处理；另有 3 处疑似硬编码凭证需要确认。
- 扫描说明：本次检查覆盖项目 javascript，识别到 2 个 npm 依赖，命中 7 个已确认依赖风险项，涉及 minimist、lodash。仓库安检发现 3 处疑似硬编码凭证。依赖维护建议 1 条。过期依赖检查未执行：默认不运行项目包管理器命令。
- 建议动作：
  - 先升级 lodash 到 4.18.0、minimist 到 1.2.6，完成后重新运行扫描。
  - 确认 src/config.js 中的凭证线索是否真实有效；如有效，先轮换或撤销，再清理代码中的明文。
  - 依赖修复后必须重新运行扫描；如果仍出现同名旧版本，通常是间接依赖被父包锁定，需要询问用户是否确认升级父依赖到 latest。
  - 需要过期依赖结论时，显式允许项目包管理器命令后补跑版本维护检查。
- 未覆盖与边界：安全往往不是最显眼的需求，却是产品长期稳定运行的底线。此报告基于本地可确认的依赖和仓库证据，帮助你发现应用依赖漏洞、过期依赖和仓库暴露风险，并把可处理的问题整理成清晰的修复线索。它不能替代代码审计、渗透测试或完整安全评估；业务逻辑、权限控制、输入校验、SQL 注入、XSS 等代码层风险仍需结合业务场景复核。安全的价值不只在于发现问题，更在于让团队知道风险在哪里、先处理什么，以及如何让每一次修复都成为系统可靠性的积累。


## 当前风险

| 影响程度 | 依赖名称 | 当前版本 | 修复版本 | 安全编号 | 可利用性 | 发现时间 |
| --- | --- | --- | --- | --- | --- | --- |
| 紧急 | minimist | 0.0.8 | 0.2.4 | [CVE-2021-44906](https://www.cve.org/CVERecord?id=CVE-2021-44906)、[GHSA-xvch-5gv4-984h](https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h) | EPSS 74.3% | 2022-03-17 |
| 紧急 | lodash | 4.17.20 | 4.18.0 | [CVE-2026-4800](https://www.cve.org/CVERecord?id=CVE-2026-4800)、[GHSA-r5fr-rjxr-66jc](https://osv.dev/vulnerability/GHSA-r5fr-rjxr-66jc) | EPSS 14.7% | 2026-03-31 |
| 高风险 | lodash | 4.17.20 | 4.17.21 | [CVE-2021-23337](https://www.cve.org/CVERecord?id=CVE-2021-23337)、[GHSA-35jh-r3h4-6jhm](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm) | EPSS 89.1% | 2021-02-15 |
| 中风险 | lodash | 4.17.20 | 4.17.21 | [CVE-2020-28500](https://www.cve.org/CVERecord?id=CVE-2020-28500)、[GHSA-29mw-wpgm-hmr9](https://osv.dev/vulnerability/GHSA-29mw-wpgm-hmr9) | EPSS 48% | 2021-02-15 |
| 中风险 | minimist | 0.0.8 | 0.2.1 | [CVE-2020-7598](https://www.cve.org/CVERecord?id=CVE-2020-7598)、[GHSA-vh95-rmgr-6w4m](https://osv.dev/vulnerability/GHSA-vh95-rmgr-6w4m) | EPSS 40.6% | 2020-03-11 |
| 中风险 | lodash | 4.17.20 | 4.17.23 | [CVE-2025-13465](https://www.cve.org/CVERecord?id=CVE-2025-13465)、[GHSA-xxjr-mmjv-4gpg](https://osv.dev/vulnerability/GHSA-xxjr-mmjv-4gpg) | EPSS 8.3% | 2026-01-21 |
| 中风险 | lodash | 4.17.20 | 4.18.0 | [CVE-2026-2950](https://www.cve.org/CVERecord?id=CVE-2026-2950)、[GHSA-f23m-r3pf-42rh](https://osv.dev/vulnerability/GHSA-f23m-r3pf-42rh) | EPSS 7.9% | 2026-03-31 |


## 仓库安检

- 硬编码密钥：发现 3 处疑似明文凭证。
- 敏感文件跟踪：没有发现被 git 跟踪的敏感文件。
- .gitignore：没有发现需要补充的敏感文件忽略规则。
- 本地配置检查：发现 0 个需要确认的仓库安检项，1 条建议。

| 位置 | 类型 | 可信度 | 证据预览 |
| --- | --- | --- | --- |
| src/config.js:1 | 疑似密码 | medium | password = "demo_p************report" |
| src/config.js:2 | 疑似 API Key | medium | api_key = "demo_a***********report" |
| src/config.js:3 | PostgreSQL 连接字符串 | high | postgre...host |

### 依赖配置与维护

| 等级 | 位置 | 检查项 | 处理 |
| --- | --- | --- | --- |
| 建议 | .github/dependabot.yml | 配置 Dependabot | 建议创建覆盖 npm 的配置；推送到 GitHub 后，Dependabot 会按 schedule 检查更新。 |


## 过期依赖

没有检测到明确的过期依赖，或当前包管理器没有返回可用结果。

提醒：过期依赖用于版本维护规划；处理顺序仍以当前风险项和发布窗口为准。


## 覆盖说明

### 1. 疑似硬编码凭证：src/config.js:3
- 影响程度：高风险
- 位置：`src/config.js`
- 为什么要关注：扫描在 src/config.js:3 发现PostgreSQL 连接字符串特征，需要研发确认是否是真实可用凭证。
- 可能影响：如果该凭证真实可用，泄露后可能造成未授权访问或数据暴露。
- 建议动作：先确认是否真实有效；如有效，先轮换或撤销，再移除代码中的明文。

### 2. 疑似硬编码凭证：src/config.js:1
- 影响程度：中风险
- 位置：`src/config.js`
- 为什么要关注：扫描在 src/config.js:1 发现疑似密码特征，需要研发确认是否是真实可用凭证。
- 可能影响：如果该凭证真实可用，泄露后可能造成未授权访问或数据暴露。
- 建议动作：先确认是否真实有效；如有效，先轮换或撤销，再移除代码中的明文。

### 3. 疑似硬编码凭证：src/config.js:2
- 影响程度：中风险
- 位置：`src/config.js`
- 为什么要关注：扫描在 src/config.js:2 发现疑似 API Key特征，需要研发确认是否是真实可用凭证。
- 可能影响：如果该凭证真实可用，泄露后可能造成未授权访问或数据暴露。
- 建议动作：先确认是否真实有效；如有效，先轮换或撤销，再移除代码中的明文。


## 扫描错误

- [outdated_check] 已跳过过期依赖检查：默认不执行项目内包管理器命令；如需执行 npm/pnpm/yarn/uv/go/cargo 等项目工具，请显式传入 --allow-project-exec。


## 下一步建议

- 先升级 lodash 到 4.18.0、minimist 到 1.2.6，完成后重新运行扫描。
- 确认 src/config.js 中的凭证线索是否真实有效；如有效，先轮换或撤销，再清理代码中的明文。
- 依赖修复后必须重新运行扫描；如果仍出现同名旧版本，通常是间接依赖被父包锁定，需要询问用户是否确认升级父依赖到 latest。
- 需要过期依赖结论时，显式允许项目包管理器命令后补跑版本维护检查。
- 依赖修复后必须重新运行扫描，确认风险项是否真正消失。
- 修复脚本只执行普通包管理器升级；如果复扫仍出现同名旧版本，报告中会标注父依赖信息，可继续升级父依赖来解除锁定。
