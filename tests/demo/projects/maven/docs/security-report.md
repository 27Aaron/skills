# 安全扫描报告

- 项目：maven
- 路径：`/Users/aaron/Documents/Project/skills/tests/demo/projects/maven`
- 生成时间：2026-06-10 03:56:43
- 扫描耗时：39.6 秒

## 报告总结

- TL;DR：发现 41 个已确认依赖风险项，其中 6 个为紧急项、35 个为高风险项，仓库安检仍有疑似硬编码凭证 1 处。
- 详细说明：本次检查覆盖项目 maven，识别到 2 个依赖包，命中 41 个已确认风险项。仓库安检方面，发现疑似硬编码凭证 1 处、被 git 跟踪的敏感文件 0 个、建议补充的 .gitignore 规则 0 条、本地配置/工作流检查项 0 个、建议 1 条。过期依赖 0 个，建议按维护窗口和兼容性评估安排升级。
- 能力边界：安全往往不是最显眼的需求，却是产品长期稳定运行的底线。此 Skill 会帮助你发现依赖漏洞、过期依赖和仓库暴露风险，帮助团队更早暴露容易被忽视的供应链问题。但它不能替代代码审计、渗透测试或部署安全评估；业务逻辑、权限控制、SQL 注入、XSS 等代码层风险仍需单独复核。
- 优先级建议：
  - 优先处理 41 个紧急/高风险项；依赖漏洞先处理有明确修复版本或官方处置路径的项，仓库安检项先处理工作流权限、凭证、容器和供应链配置。
  - 安排研发确认凭证和敏感文件是否真实有效；如有效，先轮换或撤销，再清理代码中的明文。
  - 依赖修复后必须重新运行扫描；如果仍出现同名旧版本，通常是间接依赖被父包锁定，需要询问用户是否确认升级父依赖到 latest。


## 服务器运行环境

未启用服务器运行环境扫描。

## 命中风险项

| 影响程度 | 依赖名称 | 当前版本 | 安全编号 | 修复版本 | 说明 |
| --- | --- | --- | --- | --- | --- |
| 紧急 | org.apache.commons:commons-text | 1.9 | [CVE-2022-42889](https://www.cve.org/CVERecord?id=CVE-2022-42889)、[GHSA-599f-7c49-w659](https://osv.dev/vulnerability/GHSA-599f-7c49-w659) | 1.10.0 | org.apache.commons:commons-text 1.9 公告摘要：Arbitrary code execution in Apache Commons Text；建议升级到 1.10.0 或更高版本。；EPSS 99.9%；CVSS 9.8；CWE-94；NVD 2022-10-13 |
| 紧急 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-9548](https://www.cve.org/CVERecord?id=CVE-2020-9548)、[GHSA-p43x-xfjf-5jhr](https://osv.dev/vulnerability/GHSA-p43x-xfjf-5jhr) | 2.9.10.4、2.8.11.6、2.7.9.7 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：jackson-databind mishandles the interaction between serialization gadgets and typing；建议升级到 2.9.10.4、2.8.11.6、2.7.9.7 或更高版本。；EPSS 98.4%；CVSS 9.8；CWE-502；NVD 2020-03-02 |
| 紧急 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-9547](https://www.cve.org/CVERecord?id=CVE-2020-9547)、[GHSA-q93h-jc49-78gg](https://osv.dev/vulnerability/GHSA-q93h-jc49-78gg) | 2.9.10.4、2.8.11.6、2.7.9.7 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：jackson-databind mishandles the interaction between serialization gadgets and typing；建议升级到 2.9.10.4、2.8.11.6、2.7.9.7 或更高版本。；EPSS 97.3%；CVSS 9.8；CWE-502；NVD 2020-03-02 |
| 紧急 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-8840](https://www.cve.org/CVERecord?id=CVE-2020-8840)、[GHSA-4w82-r329-3q67](https://osv.dev/vulnerability/GHSA-4w82-r329-3q67) | 2.6.7.4、2.7.9.7、2.8.11.5、2.9.10.3 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：Deserialization of Untrusted Data in jackson-databind；建议升级到 2.6.7.4、2.7.9.7、2.8.11.5、2.9.10.3 或更高版本。；EPSS 92.3%；CVSS 9.8；CWE-502；NVD 2020-02-10 |
| 紧急 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-9546](https://www.cve.org/CVERecord?id=CVE-2020-9546)、[GHSA-5p34-5m6p-p58g](https://osv.dev/vulnerability/GHSA-5p34-5m6p-p58g) | 2.9.10.4 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：jackson-databind mishandles the interaction between serialization gadgets and typing；建议升级到 2.9.10.4 或更高版本。；EPSS 85.3%；CVSS 9.8；CWE-502；NVD 2020-03-02 |
| 紧急 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2019-20330](https://www.cve.org/CVERecord?id=CVE-2019-20330)、[GHSA-gww7-p5w4-wrfv](https://osv.dev/vulnerability/GHSA-gww7-p5w4-wrfv) | 2.6.7.4、2.7.9.7、2.8.11.5、2.9.10.2 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：Deserialization of Untrusted Data in jackson-databind；建议升级到 2.6.7.4、2.7.9.7、2.8.11.5、2.9.10.2 或更高版本。；EPSS 83.7%；CVSS 9.8；CWE-502；NVD 2020-01-03 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-36179](https://www.cve.org/CVERecord?id=CVE-2020-36179)、[GHSA-9gph-22xh-8x98](https://osv.dev/vulnerability/GHSA-9gph-22xh-8x98) | 2.9.10.8、2.6.7.5 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：Unsafe Deserialization in jackson-databind；建议升级到 2.9.10.8、2.6.7.5 或更高版本。；EPSS 98.4%；CVSS 8.8；CWE-502；NVD 2021-01-07 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-11113](https://www.cve.org/CVERecord?id=CVE-2020-11113)、[GHSA-9vvp-fxw6-jcxr](https://osv.dev/vulnerability/GHSA-9vvp-fxw6-jcxr) | 2.9.10.4 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：jackson-databind mishandles the interaction between serialization gadgets and typing；建议升级到 2.9.10.4 或更高版本。；EPSS 98.3%；CVSS 8.8；CWE-502；NVD 2020-03-31 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-35728](https://www.cve.org/CVERecord?id=CVE-2020-35728)、[GHSA-5r5r-6hpj-8gg9](https://osv.dev/vulnerability/GHSA-5r5r-6hpj-8gg9) | 2.9.10.8 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：Serialization gadget exploit in jackson-databind；建议升级到 2.9.10.8 或更高版本。；EPSS 97.5%；CVSS 8.1；CWE-502；NVD 2020-12-27 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-10672](https://www.cve.org/CVERecord?id=CVE-2020-10672)、[GHSA-95cm-88f5-f2c7](https://osv.dev/vulnerability/GHSA-95cm-88f5-f2c7) | 2.9.10.4 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：jackson-databind mishandles the interaction between serialization gadgets and typing；建议升级到 2.9.10.4 或更高版本。；EPSS 97.4%；CVSS 8.8；CWE-502；NVD 2020-03-18 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-10673](https://www.cve.org/CVERecord?id=CVE-2020-10673)、[GHSA-fqwf-pjwf-7vqv](https://osv.dev/vulnerability/GHSA-fqwf-pjwf-7vqv) | 2.9.10.4、2.6.7.4 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：jackson-databind mishandles the interaction between serialization gadgets and typing；建议升级到 2.9.10.4、2.6.7.4 或更高版本。；EPSS 95.7%；CVSS 8.8；CWE-502；NVD 2020-03-18 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-36188](https://www.cve.org/CVERecord?id=CVE-2020-36188)、[GHSA-f9xh-2qgp-cq57](https://osv.dev/vulnerability/GHSA-f9xh-2qgp-cq57) | 2.9.10.8、2.6.7.5 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：Unsafe Deserialization in jackson-databind；建议升级到 2.9.10.8、2.6.7.5 或更高版本。；EPSS 93.3%；CVSS 8.1；CWE-502；NVD 2021-01-06 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-14062](https://www.cve.org/CVERecord?id=CVE-2020-14062)、[GHSA-c265-37vj-cwcc](https://osv.dev/vulnerability/GHSA-c265-37vj-cwcc) | 2.9.10.5 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：Deserialization of untrusted data in Jackson Databind；建议升级到 2.9.10.5 或更高版本。；EPSS 93.1%；CVSS 8.1；CWE-502；NVD 2020-06-14 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-14195](https://www.cve.org/CVERecord?id=CVE-2020-14195)、[GHSA-mc6h-4qgp-37qh](https://osv.dev/vulnerability/GHSA-mc6h-4qgp-37qh) | 2.9.10.5 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：Deserialization of untrusted data in Jackson Databind；建议升级到 2.9.10.5 或更高版本。；EPSS 92.9%；CVSS 8.1；CWE-502；NVD 2020-06-16 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-10650](https://www.cve.org/CVERecord?id=CVE-2020-10650)、[GHSA-rpr3-cw39-3pxh](https://osv.dev/vulnerability/GHSA-rpr3-cw39-3pxh) | 2.9.10.4 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：jackson-databind vulnerable to unsafe deserialization；建议升级到 2.9.10.4 或更高版本。；EPSS 92.8%；CVSS 8.1；CWE-502；NVD 2022-12-26 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-14060](https://www.cve.org/CVERecord?id=CVE-2020-14060)、[GHSA-j823-4qch-3rgm](https://osv.dev/vulnerability/GHSA-j823-4qch-3rgm) | 2.9.10.5 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：Deserialization of untrusted data in Jackson Databind；建议升级到 2.9.10.5 或更高版本。；EPSS 92.8%；CVSS 8.1；CWE-502；NVD 2020-06-14 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-36184](https://www.cve.org/CVERecord?id=CVE-2020-36184)、[GHSA-m6x4-97wx-4q27](https://osv.dev/vulnerability/GHSA-m6x4-97wx-4q27) | 2.9.10.8 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：Unsafe Deserialization in jackson-databind；建议升级到 2.9.10.8 或更高版本。；EPSS 91.9%；CVSS 8.8；CWE-502；NVD 2021-01-06 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-11112](https://www.cve.org/CVERecord?id=CVE-2020-11112)、[GHSA-58pp-9c76-5625](https://osv.dev/vulnerability/GHSA-58pp-9c76-5625) | 2.9.10.4 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：jackson-databind mishandles the interaction between serialization gadgets and typing；建议升级到 2.9.10.4 或更高版本。；EPSS 91.5%；CVSS 8.8；CWE-502；NVD 2020-03-31 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-14061](https://www.cve.org/CVERecord?id=CVE-2020-14061)、[GHSA-c2q3-4qrh-fm48](https://osv.dev/vulnerability/GHSA-c2q3-4qrh-fm48) | 2.9.10.5 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：Deserialization of untrusted data in Jackson Databind；建议升级到 2.9.10.5 或更高版本。；EPSS 91.1%；CVSS 8.1；CWE-502；NVD 2020-06-14 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-35491](https://www.cve.org/CVERecord?id=CVE-2020-35491)、[GHSA-r3gr-cxrf-hg25](https://osv.dev/vulnerability/GHSA-r3gr-cxrf-hg25) | 2.9.10.8 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：Serialization gadgets exploit in jackson-databind；建议升级到 2.9.10.8 或更高版本。；EPSS 91%；CVSS 8.1；CWE-502；NVD 2020-12-17 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-36181](https://www.cve.org/CVERecord?id=CVE-2020-36181)、[GHSA-cvm9-fjm9-3572](https://osv.dev/vulnerability/GHSA-cvm9-fjm9-3572) | 2.9.10.8、2.6.7.5 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：Unsafe Deserialization in jackson-databind；建议升级到 2.9.10.8、2.6.7.5 或更高版本。；EPSS 90.8%；CVSS 8.8；CWE-502；NVD 2021-01-06 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-36189](https://www.cve.org/CVERecord?id=CVE-2020-36189)、[GHSA-vfqx-33qm-g869](https://osv.dev/vulnerability/GHSA-vfqx-33qm-g869) | 2.9.10.8、2.6.7.5 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：Unsafe Deserialization in jackson-databind；建议升级到 2.9.10.8、2.6.7.5 或更高版本。；EPSS 89.1%；CVSS 8.1；CWE-502；NVD 2021-01-06 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-35490](https://www.cve.org/CVERecord?id=CVE-2020-35490)、[GHSA-wh8g-3j2c-rqj5](https://osv.dev/vulnerability/GHSA-wh8g-3j2c-rqj5) | 2.9.10.8 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：Serialization gadgets exploit in jackson-databind；建议升级到 2.9.10.8 或更高版本。；EPSS 89%；CVSS 8.1；CWE-502；NVD 2020-12-17 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-10968](https://www.cve.org/CVERecord?id=CVE-2020-10968)、[GHSA-rf6r-2c4q-2vwg](https://osv.dev/vulnerability/GHSA-rf6r-2c4q-2vwg) | 2.9.10.4 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：jackson-databind mishandles the interaction between serialization gadgets and typing；建议升级到 2.9.10.4 或更高版本。；EPSS 88.4%；CVSS 8.8；CWE-502；NVD 2020-03-26 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-36180](https://www.cve.org/CVERecord?id=CVE-2020-36180)、[GHSA-8c4j-34r4-xr8g](https://osv.dev/vulnerability/GHSA-8c4j-34r4-xr8g) | 2.9.10.8、2.6.7.5 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：Unsafe Deserialization in jackson-databind；建议升级到 2.9.10.8、2.6.7.5 或更高版本。；EPSS 87.2%；CVSS 8.8；CWE-502；NVD 2021-01-07 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-36182](https://www.cve.org/CVERecord?id=CVE-2020-36182)、[GHSA-89qr-369f-5m5x](https://osv.dev/vulnerability/GHSA-89qr-369f-5m5x) | 2.9.10.8、2.6.7.5 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：Unsafe Deserialization in jackson-databind；建议升级到 2.9.10.8、2.6.7.5 或更高版本。；EPSS 86.7%；CVSS 8.8；CWE-502；NVD 2021-01-07 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-36185](https://www.cve.org/CVERecord?id=CVE-2020-36185)、[GHSA-8w26-6f25-cm9x](https://osv.dev/vulnerability/GHSA-8w26-6f25-cm9x) | 2.9.10.8 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：Unsafe Deserialization in jackson-databind；建议升级到 2.9.10.8 或更高版本。；EPSS 86.7%；CVSS 8.1；CWE-502；NVD 2021-01-06 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-24616](https://www.cve.org/CVERecord?id=CVE-2020-24616)、[GHSA-h3cw-g4mq-c5x2](https://osv.dev/vulnerability/GHSA-h3cw-g4mq-c5x2) | 2.9.10.6 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：Code Injection in jackson-databind；建议升级到 2.9.10.6 或更高版本。；EPSS 86.6%；CVSS 8.1；CWE-502；NVD 2020-08-25 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-36186](https://www.cve.org/CVERecord?id=CVE-2020-36186)、[GHSA-v585-23hc-c647](https://osv.dev/vulnerability/GHSA-v585-23hc-c647) | 2.9.10.8 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：Unsafe Deserialization in jackson-databind；建议升级到 2.9.10.8 或更高版本。；EPSS 86%；CVSS 8.1；CWE-502；NVD 2021-01-06 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-36187](https://www.cve.org/CVERecord?id=CVE-2020-36187)、[GHSA-r695-7vr9-jgc2](https://osv.dev/vulnerability/GHSA-r695-7vr9-jgc2) | 2.9.10.8 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：Unsafe Deserialization in jackson-databind；建议升级到 2.9.10.8 或更高版本。；EPSS 85.2%；CVSS 8.1；CWE-502；NVD 2021-01-06 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-36183](https://www.cve.org/CVERecord?id=CVE-2020-36183)、[GHSA-9m6f-7xcq-8vf8](https://osv.dev/vulnerability/GHSA-9m6f-7xcq-8vf8) | 2.9.10.8、2.6.7.5 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：Unsafe Deserialization in jackson-databind；建议升级到 2.9.10.8、2.6.7.5 或更高版本。；EPSS 84.9%；CVSS 8.1；CWE-502；NVD 2021-01-07 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-11620](https://www.cve.org/CVERecord?id=CVE-2020-11620)、[GHSA-h4rc-386g-6m85](https://osv.dev/vulnerability/GHSA-h4rc-386g-6m85) | 2.9.10.4 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：jackson-databind mishandles the interaction between serialization gadgets and typing；建议升级到 2.9.10.4 或更高版本。；EPSS 84.7%；CVSS 8.1；CWE-502；NVD 2020-04-07 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-11111](https://www.cve.org/CVERecord?id=CVE-2020-11111)、[GHSA-v3xw-c963-f5hc](https://osv.dev/vulnerability/GHSA-v3xw-c963-f5hc) | 2.9.10.4 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：jackson-databind mishandles the interaction between serialization gadgets and typing；建议升级到 2.9.10.4 或更高版本。；EPSS 84.3%；CVSS 8.8；CWE-502；NVD 2020-03-31 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-24750](https://www.cve.org/CVERecord?id=CVE-2020-24750)、[GHSA-qjw2-hr98-qgfh](https://osv.dev/vulnerability/GHSA-qjw2-hr98-qgfh) | 2.6.7.5、2.9.10.6 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：Unsafe Deserialization in jackson-databind；建议升级到 2.6.7.5、2.9.10.6 或更高版本。；EPSS 84.2%；CVSS 8.1；CWE-502；NVD 2020-09-17 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-11619](https://www.cve.org/CVERecord?id=CVE-2020-11619)、[GHSA-27xj-rqx5-2255](https://osv.dev/vulnerability/GHSA-27xj-rqx5-2255) | 2.9.10.4 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：jackson-databind mishandles the interaction between serialization gadgets and typing；建议升级到 2.9.10.4 或更高版本。；EPSS 80.6%；CVSS 8.1；CWE-502；NVD 2020-04-07 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-10969](https://www.cve.org/CVERecord?id=CVE-2020-10969)、[GHSA-758m-v56v-grj4](https://osv.dev/vulnerability/GHSA-758m-v56v-grj4) | 2.9.10.4 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：jackson-databind mishandles the interaction between serialization gadgets and typing；建议升级到 2.9.10.4 或更高版本。；EPSS 77.8%；CVSS 8.8；CWE-502；NVD 2020-03-26 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2021-20190](https://www.cve.org/CVERecord?id=CVE-2021-20190)、[GHSA-5949-rw7g-wx7w](https://osv.dev/vulnerability/GHSA-5949-rw7g-wx7w)、[BIT-nifi-2021-20190](https://osv.dev/vulnerability/BIT-nifi-2021-20190) | 2.9.10.7、2.6.7.5 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：Deserialization of untrusted data in jackson-databind；建议升级到 2.9.10.7、2.6.7.5 或更高版本。；EPSS 66.5%；CVSS 8.3；CWE-502；NVD 2021-01-19 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-36518](https://www.cve.org/CVERecord?id=CVE-2020-36518)、[GHSA-57j2-w4cx-62h2](https://osv.dev/vulnerability/GHSA-57j2-w4cx-62h2) | 2.13.2.1、2.12.6.1 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：Deeply nested json in jackson-databind；建议升级到 2.13.2.1、2.12.6.1 或更高版本。；EPSS 65.8%；CVSS 7.5；CWE-787；NVD 2022-03-11 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2022-42003](https://www.cve.org/CVERecord?id=CVE-2022-42003)、[GHSA-jjjh-jjxp-wpff](https://osv.dev/vulnerability/GHSA-jjjh-jjxp-wpff) | 2.12.7.1、2.13.4.2 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：Uncontrolled Resource Consumption in Jackson-databind；建议升级到 2.12.7.1、2.13.4.2 或更高版本。；EPSS 55.1%；CVSS 7.5；CWE-502；NVD 2022-10-02 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2022-42004](https://www.cve.org/CVERecord?id=CVE-2022-42004)、[GHSA-rgv9-q543-rqg4](https://osv.dev/vulnerability/GHSA-rgv9-q543-rqg4) | 2.12.7.1、2.13.4 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：Uncontrolled Resource Consumption in FasterXML jackson-databind；建议升级到 2.12.7.1、2.13.4 或更高版本。；EPSS 48.5%；CVSS 7.5；CWE-502；NVD 2022-10-02 |
| 高风险 | com.fasterxml.jackson.core:jackson-databind | 2.9.10.1 | [CVE-2020-25649](https://www.cve.org/CVERecord?id=CVE-2020-25649)、[GHSA-288c-cq4h-88gq](https://osv.dev/vulnerability/GHSA-288c-cq4h-88gq) | 2.6.7.4、2.9.10.7、2.10.5.1 | com.fasterxml.jackson.core:jackson-databind 2.9.10.1 公告摘要：XML External Entity (XXE) Injection in Jackson Databind；建议升级到 2.6.7.4、2.9.10.7、2.10.5.1 或更高版本。；EPSS 22.6%；CVSS 7.5；CWE-611；NVD 2020-12-03 |


## 仓库安检

- 硬编码密钥：发现 1 处疑似明文凭证。
- 敏感文件跟踪：没有发现被 git 跟踪的敏感文件。
- .gitignore：没有发现需要补充的敏感文件忽略规则。
- 本地配置检查：发现 0 个需要确认的仓库安检项，1 条建议。

| 位置 | 类型 | 可信度 | 证据预览 |
| --- | --- | --- | --- |
| src/main/java/example/Config.java:6 | PostgreSQL 连接字符串 | high | postgre...host |

### 依赖配置与维护

| 等级 | 位置 | 检查项 | 依据 | 处理 |
| --- | --- | --- | --- | --- |
| 建议 | .github/dependabot.yml | 配置 Dependabot | GitHub remote origin: git@github.com:27Aaron/skills.git | .github/dependabot.yml，建议创建覆盖 maven 的配置；推送到 GitHub 后，Dependabot 会按 schedule 检查更新。 |


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
