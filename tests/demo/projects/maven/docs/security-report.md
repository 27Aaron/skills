# 安全扫描报告

- 项目：maven
- 路径：`/Users/aaron/Documents/Project/skills/tests/demo/projects/maven`
- 生成时间：2026-06-10 07:21:03
- 扫描耗时：37.8 秒

## 报告总结

- TL;DR：发现 41 个已确认依赖风险项，其中 6 个为紧急项、35 个为高风险项，仓库安检仍有疑似硬编码凭证 1 处。
- 详细说明：本次检查覆盖项目 maven，识别到 2 个依赖包，命中 41 个已确认风险项。仓库安检方面，发现疑似硬编码凭证 1 处、被 git 跟踪的敏感文件 0 个、建议补充的 .gitignore 规则 0 条、本地配置/工作流检查项 0 个、建议 1 条。过期依赖 0 个，建议按维护窗口和兼容性评估安排升级。
- 能力边界：安全往往不是最显眼的需求，却是产品长期稳定运行的底线。此报告基于本地可确认的依赖和仓库证据，帮助你发现应用依赖漏洞、过期依赖和仓库暴露风险，并把可处理的问题整理成清晰的修复线索。它不能替代代码审计、渗透测试或完整安全评估；业务逻辑、权限控制、输入校验、SQL 注入、XSS 等代码层风险仍需结合业务场景复核。安全的价值不只在于发现问题，更在于让团队知道风险在哪里、先处理什么，以及如何让每一次修复都成为系统可靠性的积累。
- 优先级建议：
  - 优先处理 41 个紧急/高风险项；依赖漏洞先处理有明确修复版本或官方处置路径的项，仓库安检项先处理工作流权限、凭证、容器和供应链配置。
  - 安排研发确认凭证和敏感文件是否真实有效；如有效，先轮换或撤销，再清理代码中的明文。
  - 依赖修复后必须重新运行扫描；如果仍出现同名旧版本，通常是间接依赖被父包锁定，需要询问用户是否确认升级父依赖到 latest。


## 当前风险

| 影响程度 | 依赖名称 | 当前版本 | 修复版本 | 安全编号 |
| --- | --- | --- | --- | --- |
| 紧急 | org.apache.commons:commons-text | 1.9 | 1.10.0 | [CVE-2022-42889](https://www.cve.org/CVERecord?id=CVE-2022-42889)、[GHSA-599f-7c49-w659](https://osv.dev/vulnerability/GHSA-599f-7c49-w659) |
| 紧急 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.4 | [CVE-2020-9548](https://www.cve.org/CVERecord?id=CVE-2020-9548)、[GHSA-p43x-xfjf-5jhr](https://osv.dev/vulnerability/GHSA-p43x-xfjf-5jhr) |
| 紧急 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.4 | [CVE-2020-9547](https://www.cve.org/CVERecord?id=CVE-2020-9547)、[GHSA-q93h-jc49-78gg](https://osv.dev/vulnerability/GHSA-q93h-jc49-78gg) |
| 紧急 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.3 | [CVE-2020-8840](https://www.cve.org/CVERecord?id=CVE-2020-8840)、[GHSA-4w82-r329-3q67](https://osv.dev/vulnerability/GHSA-4w82-r329-3q67) |
| 紧急 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.4 | [CVE-2020-9546](https://www.cve.org/CVERecord?id=CVE-2020-9546)、[GHSA-5p34-5m6p-p58g](https://osv.dev/vulnerability/GHSA-5p34-5m6p-p58g) |
| 紧急 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.2 | [CVE-2019-20330](https://www.cve.org/CVERecord?id=CVE-2019-20330)、[GHSA-gww7-p5w4-wrfv](https://osv.dev/vulnerability/GHSA-gww7-p5w4-wrfv) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.8 | [CVE-2020-36179](https://www.cve.org/CVERecord?id=CVE-2020-36179)、[GHSA-9gph-22xh-8x98](https://osv.dev/vulnerability/GHSA-9gph-22xh-8x98) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.4 | [CVE-2020-11113](https://www.cve.org/CVERecord?id=CVE-2020-11113)、[GHSA-9vvp-fxw6-jcxr](https://osv.dev/vulnerability/GHSA-9vvp-fxw6-jcxr) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.8 | [CVE-2020-35728](https://www.cve.org/CVERecord?id=CVE-2020-35728)、[GHSA-5r5r-6hpj-8gg9](https://osv.dev/vulnerability/GHSA-5r5r-6hpj-8gg9) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.4 | [CVE-2020-10672](https://www.cve.org/CVERecord?id=CVE-2020-10672)、[GHSA-95cm-88f5-f2c7](https://osv.dev/vulnerability/GHSA-95cm-88f5-f2c7) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.4 | [CVE-2020-10673](https://www.cve.org/CVERecord?id=CVE-2020-10673)、[GHSA-fqwf-pjwf-7vqv](https://osv.dev/vulnerability/GHSA-fqwf-pjwf-7vqv) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.8 | [CVE-2020-36188](https://www.cve.org/CVERecord?id=CVE-2020-36188)、[GHSA-f9xh-2qgp-cq57](https://osv.dev/vulnerability/GHSA-f9xh-2qgp-cq57) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.5 | [CVE-2020-14062](https://www.cve.org/CVERecord?id=CVE-2020-14062)、[GHSA-c265-37vj-cwcc](https://osv.dev/vulnerability/GHSA-c265-37vj-cwcc) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.5 | [CVE-2020-14195](https://www.cve.org/CVERecord?id=CVE-2020-14195)、[GHSA-mc6h-4qgp-37qh](https://osv.dev/vulnerability/GHSA-mc6h-4qgp-37qh) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.4 | [CVE-2020-10650](https://www.cve.org/CVERecord?id=CVE-2020-10650)、[GHSA-rpr3-cw39-3pxh](https://osv.dev/vulnerability/GHSA-rpr3-cw39-3pxh) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.5 | [CVE-2020-14060](https://www.cve.org/CVERecord?id=CVE-2020-14060)、[GHSA-j823-4qch-3rgm](https://osv.dev/vulnerability/GHSA-j823-4qch-3rgm) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.8 | [CVE-2020-36184](https://www.cve.org/CVERecord?id=CVE-2020-36184)、[GHSA-m6x4-97wx-4q27](https://osv.dev/vulnerability/GHSA-m6x4-97wx-4q27) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.4 | [CVE-2020-11112](https://www.cve.org/CVERecord?id=CVE-2020-11112)、[GHSA-58pp-9c76-5625](https://osv.dev/vulnerability/GHSA-58pp-9c76-5625) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.5 | [CVE-2020-14061](https://www.cve.org/CVERecord?id=CVE-2020-14061)、[GHSA-c2q3-4qrh-fm48](https://osv.dev/vulnerability/GHSA-c2q3-4qrh-fm48) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.8 | [CVE-2020-35491](https://www.cve.org/CVERecord?id=CVE-2020-35491)、[GHSA-r3gr-cxrf-hg25](https://osv.dev/vulnerability/GHSA-r3gr-cxrf-hg25) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.8 | [CVE-2020-36181](https://www.cve.org/CVERecord?id=CVE-2020-36181)、[GHSA-cvm9-fjm9-3572](https://osv.dev/vulnerability/GHSA-cvm9-fjm9-3572) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.8 | [CVE-2020-36189](https://www.cve.org/CVERecord?id=CVE-2020-36189)、[GHSA-vfqx-33qm-g869](https://osv.dev/vulnerability/GHSA-vfqx-33qm-g869) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.8 | [CVE-2020-35490](https://www.cve.org/CVERecord?id=CVE-2020-35490)、[GHSA-wh8g-3j2c-rqj5](https://osv.dev/vulnerability/GHSA-wh8g-3j2c-rqj5) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.4 | [CVE-2020-10968](https://www.cve.org/CVERecord?id=CVE-2020-10968)、[GHSA-rf6r-2c4q-2vwg](https://osv.dev/vulnerability/GHSA-rf6r-2c4q-2vwg) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.8 | [CVE-2020-36180](https://www.cve.org/CVERecord?id=CVE-2020-36180)、[GHSA-8c4j-34r4-xr8g](https://osv.dev/vulnerability/GHSA-8c4j-34r4-xr8g) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.8 | [CVE-2020-36182](https://www.cve.org/CVERecord?id=CVE-2020-36182)、[GHSA-89qr-369f-5m5x](https://osv.dev/vulnerability/GHSA-89qr-369f-5m5x) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.8 | [CVE-2020-36185](https://www.cve.org/CVERecord?id=CVE-2020-36185)、[GHSA-8w26-6f25-cm9x](https://osv.dev/vulnerability/GHSA-8w26-6f25-cm9x) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.6 | [CVE-2020-24616](https://www.cve.org/CVERecord?id=CVE-2020-24616)、[GHSA-h3cw-g4mq-c5x2](https://osv.dev/vulnerability/GHSA-h3cw-g4mq-c5x2) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.8 | [CVE-2020-36186](https://www.cve.org/CVERecord?id=CVE-2020-36186)、[GHSA-v585-23hc-c647](https://osv.dev/vulnerability/GHSA-v585-23hc-c647) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.8 | [CVE-2020-36187](https://www.cve.org/CVERecord?id=CVE-2020-36187)、[GHSA-r695-7vr9-jgc2](https://osv.dev/vulnerability/GHSA-r695-7vr9-jgc2) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.8 | [CVE-2020-36183](https://www.cve.org/CVERecord?id=CVE-2020-36183)、[GHSA-9m6f-7xcq-8vf8](https://osv.dev/vulnerability/GHSA-9m6f-7xcq-8vf8) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.4 | [CVE-2020-11620](https://www.cve.org/CVERecord?id=CVE-2020-11620)、[GHSA-h4rc-386g-6m85](https://osv.dev/vulnerability/GHSA-h4rc-386g-6m85) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.4 | [CVE-2020-11111](https://www.cve.org/CVERecord?id=CVE-2020-11111)、[GHSA-v3xw-c963-f5hc](https://osv.dev/vulnerability/GHSA-v3xw-c963-f5hc) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.6 | [CVE-2020-24750](https://www.cve.org/CVERecord?id=CVE-2020-24750)、[GHSA-qjw2-hr98-qgfh](https://osv.dev/vulnerability/GHSA-qjw2-hr98-qgfh) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.4 | [CVE-2020-11619](https://www.cve.org/CVERecord?id=CVE-2020-11619)、[GHSA-27xj-rqx5-2255](https://osv.dev/vulnerability/GHSA-27xj-rqx5-2255) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.4 | [CVE-2020-10969](https://www.cve.org/CVERecord?id=CVE-2020-10969)、[GHSA-758m-v56v-grj4](https://osv.dev/vulnerability/GHSA-758m-v56v-grj4) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.9.10.7 | [CVE-2021-20190](https://www.cve.org/CVERecord?id=CVE-2021-20190)、[GHSA-5949-rw7g-wx7w](https://osv.dev/vulnerability/GHSA-5949-rw7g-wx7w)、[BIT-nifi-2021-20190](https://osv.dev/vulnerability/BIT-nifi-2021-20190) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.13.2.1 | [CVE-2020-36518](https://www.cve.org/CVERecord?id=CVE-2020-36518)、[GHSA-57j2-w4cx-62h2](https://osv.dev/vulnerability/GHSA-57j2-w4cx-62h2) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.13.4.2 | [CVE-2022-42003](https://www.cve.org/CVERecord?id=CVE-2022-42003)、[GHSA-jjjh-jjxp-wpff](https://osv.dev/vulnerability/GHSA-jjjh-jjxp-wpff) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.13.4 | [CVE-2022-42004](https://www.cve.org/CVERecord?id=CVE-2022-42004)、[GHSA-rgv9-q543-rqg4](https://osv.dev/vulnerability/GHSA-rgv9-q543-rqg4) |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | 2.10.5.1 | [CVE-2020-25649](https://www.cve.org/CVERecord?id=CVE-2020-25649)、[GHSA-288c-cq4h-88gq](https://osv.dev/vulnerability/GHSA-288c-cq4h-88gq) |


## 仓库安检

- 硬编码密钥：发现 1 处疑似明文凭证。
- 敏感文件跟踪：没有发现被 git 跟踪的敏感文件。
- .gitignore：没有发现需要补充的敏感文件忽略规则。
- 本地配置检查：发现 0 个需要确认的仓库安检项，1 条建议。

| 位置 | 类型 | 可信度 | 证据预览 |
| --- | --- | --- | --- |
| src/main/java/example/Config.java:6 | PostgreSQL 连接字符串 | high | postgre...host |

### 依赖配置与维护

| 等级 | 位置 | 检查项 | 处理 |
| --- | --- | --- | --- |
| 建议 | .github/dependabot.yml | 配置 Dependabot | .github/dependabot.yml，建议创建覆盖 maven 的配置；推送到 GitHub 后，Dependabot 会按 schedule 检查更新。 |


## 过期依赖

没有检测到明确的过期依赖，或当前包管理器没有返回可用结果。

提醒：过期依赖用于版本维护规划；处理顺序仍以当前风险项和发布窗口为准。


## 覆盖说明

### 1. 疑似硬编码凭证：src/main/java/example/Config.java:6
- 影响程度：高风险
- 位置：`src/main/java/example/Config.java`
- 为什么要关注：扫描在 src/main/java/example/Config.java:6 发现PostgreSQL 连接字符串特征，需要研发确认是否是真实可用凭证。
- 可能影响：如果该凭证真实可用，泄露后可能造成未授权访问或数据暴露。
- 建议动作：先确认是否真实有效；如有效，先轮换或撤销，再移除代码中的明文。


## 扫描错误

没有记录到扫描错误。


## 下一步建议

- 优先处理 41 个紧急/高风险项；依赖漏洞先处理有明确修复版本或官方处置路径的项，仓库安检项先处理工作流权限、凭证、容器和供应链配置。
- 安排研发确认凭证和敏感文件是否真实有效；如有效，先轮换或撤销，再清理代码中的明文。
- 依赖修复后必须重新运行扫描；如果仍出现同名旧版本，通常是间接依赖被父包锁定，需要询问用户是否确认升级父依赖到 latest。
- 依赖修复后必须重新运行扫描，确认风险项是否真正消失。
- 修复脚本只执行普通包管理器升级；如果复扫仍出现同名旧版本，报告中会标注父依赖信息，可继续升级父依赖来解除锁定。
