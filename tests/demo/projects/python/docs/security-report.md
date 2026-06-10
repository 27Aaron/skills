# 安全扫描报告

- 项目：python
- 路径：`/Users/aaron/Documents/Project/skills/tests/demo/projects/python`
- 生成时间：2026-06-10 17:27:06
- 扫描耗时：41.6 秒

## 报告总结

- TL;DR：发现 45 个已确认依赖风险项，其中 6 个为紧急项、21 个为高风险项，仓库安检仍有疑似硬编码凭证 3 处。 注意：本次检查不完整，部分官方漏洞源、包管理器或工具链检查失败，需复核后再判断剩余风险。
- 详细说明：本次检查覆盖项目 python，识别到 2 个依赖包，命中 45 个已确认风险项。仓库安检方面，发现疑似硬编码凭证 3 处、被 git 跟踪的敏感文件 0 个、建议补充的 .gitignore 规则 0 条、本地配置/工作流检查项 0 个、建议 1 条。过期依赖 0 个，建议按维护窗口和兼容性评估安排升级。另外，本次有部分官方漏洞源、包管理器或工具链检查失败；失败项补齐前，报告只代表成功完成的检查项。
- 能力边界：安全往往不是最显眼的需求，却是产品长期稳定运行的底线。此报告基于本地可确认的依赖和仓库证据，帮助你发现应用依赖漏洞、过期依赖和仓库暴露风险，并把可处理的问题整理成清晰的修复线索。它不能替代代码审计、渗透测试或完整安全评估；业务逻辑、权限控制、输入校验、SQL 注入、XSS 等代码层风险仍需结合业务场景复核。安全的价值不只在于发现问题，更在于让团队知道风险在哪里、先处理什么，以及如何让每一次修复都成为系统可靠性的积累。
- 优先级建议：
  - 优先处理 27 个紧急/高风险项；依赖漏洞先处理有明确修复版本或官方处置路径的项，仓库安检项先处理工作流权限、凭证、容器和供应链配置。
  - 安排研发确认凭证和敏感文件是否真实有效；如有效，先轮换或撤销，再清理代码中的明文。
  - 依赖修复后必须重新运行扫描；如果仍出现同名旧版本，通常是间接依赖被父包锁定，需要询问用户是否确认升级父依赖到 latest。
  - 复查扫描错误，补齐失败的官方漏洞源、包管理器或工具链检查后再确认最终结论。


## 当前风险

| 影响程度 | 依赖名称 | 当前版本 | 修复版本 | 安全编号 |
| --- | --- | --- | --- | --- |
| 紧急 | django | 2.2.0 | 2.2.4 | [CVE-2019-14234](https://www.cve.org/CVERecord?id=CVE-2019-14234)、[GHSA-6r97-cj55-9hrq](https://osv.dev/vulnerability/GHSA-6r97-cj55-9hrq)、[PYSEC-2019-13](https://osv.dev/vulnerability/PYSEC-2019-13) |
| 紧急 | django | 2.2.0 | 2.2.9 | [CVE-2019-19844](https://www.cve.org/CVERecord?id=CVE-2019-19844)、[GHSA-vfq6-hq5r-27r6](https://osv.dev/vulnerability/GHSA-vfq6-hq5r-27r6)、[PYSEC-2019-16](https://osv.dev/vulnerability/PYSEC-2019-16) |
| 紧急 | django | 2.2.0 | 2.2.10 | [CVE-2020-7471](https://www.cve.org/CVERecord?id=CVE-2020-7471)、[GHSA-hmr4-m2h5-33qx](https://osv.dev/vulnerability/GHSA-hmr4-m2h5-33qx)、[PYSEC-2020-35](https://osv.dev/vulnerability/PYSEC-2020-35)、[BIT-django-2020-7471](https://osv.dev/vulnerability/BIT-django-2020-7471) |
| 紧急 | django | 2.2.0 | 2.2.28 | [CVE-2022-28346](https://www.cve.org/CVERecord?id=CVE-2022-28346)、[GHSA-2gwj-7jmv-h26r](https://osv.dev/vulnerability/GHSA-2gwj-7jmv-h26r)、[PYSEC-2022-190](https://osv.dev/vulnerability/PYSEC-2022-190)、[BIT-django-2022-28346](https://osv.dev/vulnerability/BIT-django-2022-28346) |
| 紧急 | django | 2.2.0 | 2.2.28 | [CVE-2022-28347](https://www.cve.org/CVERecord?id=CVE-2022-28347)、[GHSA-w24h-v9qh-8gxj](https://osv.dev/vulnerability/GHSA-w24h-v9qh-8gxj)、[PYSEC-2022-191](https://osv.dev/vulnerability/PYSEC-2022-191)、[BIT-django-2022-28347](https://osv.dev/vulnerability/BIT-django-2022-28347) |
| 紧急 | django | 2.2.0 | 5.2.8 | [CVE-2025-64459](https://www.cve.org/CVERecord?id=CVE-2025-64459)、[GHSA-frmv-pr5f-9mcr](https://osv.dev/vulnerability/GHSA-frmv-pr5f-9mcr)、[BIT-django-2025-64459](https://osv.dev/vulnerability/BIT-django-2025-64459)、[PYSEC-2025-108](https://osv.dev/vulnerability/PYSEC-2025-108) |
| 高风险 | django | 2.2.0 | 2.2.11 | [CVE-2020-9402](https://www.cve.org/CVERecord?id=CVE-2020-9402)、[GHSA-3gh2-xw74-jmcw](https://osv.dev/vulnerability/GHSA-3gh2-xw74-jmcw)、[PYSEC-2020-345](https://osv.dev/vulnerability/PYSEC-2020-345)、[PYSEC-2020-36](https://osv.dev/vulnerability/PYSEC-2020-36)、[BIT-django-2020-9402](https://osv.dev/vulnerability/BIT-django-2020-9402) |
| 高风险 | django | 2.2.0 | 2.2.4 | [CVE-2019-14233](https://www.cve.org/CVERecord?id=CVE-2019-14233)、[GHSA-h5jv-4p7w-64jg](https://osv.dev/vulnerability/GHSA-h5jv-4p7w-64jg)、[PYSEC-2019-12](https://osv.dev/vulnerability/PYSEC-2019-12) |
| 高风险 | django | 2.2.0 | 2.2.4 | [CVE-2019-14235](https://www.cve.org/CVERecord?id=CVE-2019-14235)、[GHSA-v9qg-3j8p-r63v](https://osv.dev/vulnerability/GHSA-v9qg-3j8p-r63v)、[PYSEC-2019-14](https://osv.dev/vulnerability/PYSEC-2019-14) |
| 高风险 | django | 2.2.0 | 2.2.21 | [CVE-2021-31542](https://www.cve.org/CVERecord?id=CVE-2021-31542)、[GHSA-rxjp-mfm9-w4wr](https://osv.dev/vulnerability/GHSA-rxjp-mfm9-w4wr)、[PYSEC-2021-7](https://osv.dev/vulnerability/PYSEC-2021-7)、[BIT-django-2021-31542](https://osv.dev/vulnerability/BIT-django-2021-31542) |
| 高风险 | django | 2.2.0 | 2.2.4 | [CVE-2019-14232](https://www.cve.org/CVERecord?id=CVE-2019-14232)、[GHSA-c4qh-4vgv-qc6g](https://osv.dev/vulnerability/GHSA-c4qh-4vgv-qc6g)、[PYSEC-2019-11](https://osv.dev/vulnerability/PYSEC-2019-11) |
| 高风险 | django | 2.2.0 | 2.2.16 | [CVE-2020-24583](https://www.cve.org/CVERecord?id=CVE-2020-24583)、[GHSA-m6gj-h9gm-gw44](https://osv.dev/vulnerability/GHSA-m6gj-h9gm-gw44)、[PYSEC-2020-33](https://osv.dev/vulnerability/PYSEC-2020-33)、[BIT-django-2020-24583](https://osv.dev/vulnerability/BIT-django-2020-24583) |
| 高风险 | django | 2.2.0 | 2.2.16 | [CVE-2020-24584](https://www.cve.org/CVERecord?id=CVE-2020-24584)、[GHSA-fr28-569j-53c4](https://osv.dev/vulnerability/GHSA-fr28-569j-53c4)、[PYSEC-2020-34](https://osv.dev/vulnerability/PYSEC-2020-34)、[BIT-django-2020-24584](https://osv.dev/vulnerability/BIT-django-2020-24584) |
| 高风险 | django | 2.2.0 | 4.0.7 | [CVE-2022-36359](https://www.cve.org/CVERecord?id=CVE-2022-36359)、[GHSA-8x94-hmjh-97hq](https://osv.dev/vulnerability/GHSA-8x94-hmjh-97hq)、[BIT-django-2022-36359](https://osv.dev/vulnerability/BIT-django-2022-36359)、[PYSEC-2022-245](https://osv.dev/vulnerability/PYSEC-2022-245) |
| 高风险 | django | 2.2.0 | 2.2.27 | [CVE-2022-23833](https://www.cve.org/CVERecord?id=CVE-2022-23833)、[GHSA-6cw3-g6wv-c2xv](https://osv.dev/vulnerability/GHSA-6cw3-g6wv-c2xv)、[PYSEC-2022-20](https://osv.dev/vulnerability/PYSEC-2022-20)、[BIT-django-2022-23833](https://osv.dev/vulnerability/BIT-django-2022-23833) |
| 高风险 | urllib3 | 1.25.8 | 1.26.17 | [CVE-2023-43804](https://www.cve.org/CVERecord?id=CVE-2023-43804)、[GHSA-v845-jxx5-vc9f](https://osv.dev/vulnerability/GHSA-v845-jxx5-vc9f)、[PYSEC-2023-192](https://osv.dev/vulnerability/PYSEC-2023-192) |
| 高风险 | urllib3 | 1.25.8 | 1.26.5 | [CVE-2021-33503](https://www.cve.org/CVERecord?id=CVE-2021-33503)、[GHSA-q2q7-5pp4-w6pg](https://osv.dev/vulnerability/GHSA-q2q7-5pp4-w6pg)、[PYSEC-2021-108](https://osv.dev/vulnerability/PYSEC-2021-108) |
| 高风险 | django | 2.2.0 | 2.2.26 | [CVE-2021-45115](https://www.cve.org/CVERecord?id=CVE-2021-45115)、[GHSA-53qw-q765-4fww](https://osv.dev/vulnerability/GHSA-53qw-q765-4fww)、[PYSEC-2022-1](https://osv.dev/vulnerability/PYSEC-2022-1)、[BIT-django-2021-45115](https://osv.dev/vulnerability/BIT-django-2021-45115) |
| 高风险 | django | 2.2.0 | 2.2.26 | [CVE-2021-45116](https://www.cve.org/CVERecord?id=CVE-2021-45116)、[GHSA-8c5j-9r9f-c6w8](https://osv.dev/vulnerability/GHSA-8c5j-9r9f-c6w8)、[PYSEC-2022-2](https://osv.dev/vulnerability/PYSEC-2022-2)、[BIT-django-2021-45116](https://osv.dev/vulnerability/BIT-django-2021-45116) |
| 高风险 | django | 2.2.0 | 2.2.25 | [CVE-2021-44420](https://www.cve.org/CVERecord?id=CVE-2021-44420)、[GHSA-v6rh-hp5x-86rv](https://osv.dev/vulnerability/GHSA-v6rh-hp5x-86rv)、[PYSEC-2021-439](https://osv.dev/vulnerability/PYSEC-2021-439)、[BIT-django-2021-44420](https://osv.dev/vulnerability/BIT-django-2021-44420) |
| 高风险 | django | 2.2.0 | 5.2.6 | [CVE-2025-57833](https://www.cve.org/CVERecord?id=CVE-2025-57833)、[GHSA-6w2r-r2m5-xq5w](https://osv.dev/vulnerability/GHSA-6w2r-r2m5-xq5w)、[BIT-django-2025-57833](https://osv.dev/vulnerability/BIT-django-2025-57833)、[PYSEC-2025-105](https://osv.dev/vulnerability/PYSEC-2025-105) |
| 高风险 | django | 2.2.0 | 5.2.8 | [CVE-2025-64458](https://www.cve.org/CVERecord?id=CVE-2025-64458)、[GHSA-qw25-v68c-qjf3](https://osv.dev/vulnerability/GHSA-qw25-v68c-qjf3)、[BIT-django-2025-64458](https://osv.dev/vulnerability/BIT-django-2025-64458)、[PYSEC-2025-107](https://osv.dev/vulnerability/PYSEC-2025-107) |
| 高风险 | urllib3 | 1.25.8 | 2.6.0 | [CVE-2025-66418](https://www.cve.org/CVERecord?id=CVE-2025-66418)、[GHSA-gm62-xv2j-4w53](https://osv.dev/vulnerability/GHSA-gm62-xv2j-4w53) |
| 高风险 | urllib3 | 1.25.8 | 2.6.0 | [CVE-2025-66471](https://www.cve.org/CVERecord?id=CVE-2025-66471)、[GHSA-2xpw-w6gg-jr37](https://osv.dev/vulnerability/GHSA-2xpw-w6gg-jr37) |
| 高风险 | django | 2.2.0 | 2.2.24 | [CVE-2021-33571](https://www.cve.org/CVERecord?id=CVE-2021-33571)、[GHSA-p99v-5w3c-jqq9](https://osv.dev/vulnerability/GHSA-p99v-5w3c-jqq9)、[PYSEC-2021-99](https://osv.dev/vulnerability/PYSEC-2021-99)、[BIT-django-2021-33571](https://osv.dev/vulnerability/BIT-django-2021-33571) |
| 高风险 | urllib3 | 1.25.8 | 2.6.3 | [CVE-2026-21441](https://www.cve.org/CVERecord?id=CVE-2026-21441)、[GHSA-38jv-5279-wg99](https://osv.dev/vulnerability/GHSA-38jv-5279-wg99) |
| 高风险 | urllib3 | 1.25.8 | 2.7.0 | [CVE-2026-44431](https://www.cve.org/CVERecord?id=CVE-2026-44431)、[GHSA-qccp-gfcp-xxvc](https://osv.dev/vulnerability/GHSA-qccp-gfcp-xxvc)、[PYSEC-2026-141](https://osv.dev/vulnerability/PYSEC-2026-141) |
| 中风险 | django | 2.2.0 | 2.2.18 | [CVE-2021-3281](https://www.cve.org/CVERecord?id=CVE-2021-3281)、[GHSA-fvgf-6h6h-3322](https://osv.dev/vulnerability/GHSA-fvgf-6h6h-3322)、[PYSEC-2021-9](https://osv.dev/vulnerability/PYSEC-2021-9)、[BIT-django-2021-3281](https://osv.dev/vulnerability/BIT-django-2021-3281) |
| 中风险 | django | 2.2.0 | 2.2.13 | [CVE-2020-13254](https://www.cve.org/CVERecord?id=CVE-2020-13254)、[GHSA-wpjr-j57x-wxfw](https://osv.dev/vulnerability/GHSA-wpjr-j57x-wxfw)、[PYSEC-2020-31](https://osv.dev/vulnerability/PYSEC-2020-31)、[BIT-django-2020-13254](https://osv.dev/vulnerability/BIT-django-2020-13254) |
| 中风险 | django | 2.2.0 | 2.2.3 | [CVE-2019-12781](https://www.cve.org/CVERecord?id=CVE-2019-12781)、[GHSA-6c7v-2f49-8h26](https://osv.dev/vulnerability/GHSA-6c7v-2f49-8h26)、[PYSEC-2019-10](https://osv.dev/vulnerability/PYSEC-2019-10) |
| 中风险 | django | 2.2.0 | 2.2.2 | [CVE-2019-12308](https://www.cve.org/CVERecord?id=CVE-2019-12308)、[GHSA-7rp2-fm2h-wchj](https://osv.dev/vulnerability/GHSA-7rp2-fm2h-wchj)、[PYSEC-2019-79](https://osv.dev/vulnerability/PYSEC-2019-79) |
| 中风险 | django | 2.2.0 | 2.2.22 | [CVE-2021-32052](https://www.cve.org/CVERecord?id=CVE-2021-32052)、[GHSA-qm57-vhq3-3fwf](https://osv.dev/vulnerability/GHSA-qm57-vhq3-3fwf)、[PYSEC-2021-8](https://osv.dev/vulnerability/PYSEC-2021-8)、[BIT-django-2021-32052](https://osv.dev/vulnerability/BIT-django-2021-32052) |
| 中风险 | django | 2.2.0 | 2.2.20 | [CVE-2021-28658](https://www.cve.org/CVERecord?id=CVE-2021-28658)、[GHSA-xgxc-v2qg-chmh](https://osv.dev/vulnerability/GHSA-xgxc-v2qg-chmh)、[PYSEC-2021-6](https://osv.dev/vulnerability/PYSEC-2021-6)、[BIT-django-2021-28658](https://osv.dev/vulnerability/BIT-django-2021-28658) |
| 中风险 | django | 2.2.0 | 2.2.2 | [CVE-2019-11358](https://www.cve.org/CVERecord?id=CVE-2019-11358)、[GHSA-6c3j-c64m-qhgq](https://osv.dev/vulnerability/GHSA-6c3j-c64m-qhgq)、[DRUPAL-CORE-2019-006](https://osv.dev/vulnerability/DRUPAL-CORE-2019-006) |
| 中风险 | django | 2.2.0 | 2.2.13 | [CVE-2020-13596](https://www.cve.org/CVERecord?id=CVE-2020-13596)、[GHSA-2m34-jcjv-45xf](https://osv.dev/vulnerability/GHSA-2m34-jcjv-45xf)、[PYSEC-2020-32](https://osv.dev/vulnerability/PYSEC-2020-32)、[BIT-django-2020-13596](https://osv.dev/vulnerability/BIT-django-2020-13596) |
| 中风险 | django | 2.2.0 | 2.2.27 | [CVE-2022-22818](https://www.cve.org/CVERecord?id=CVE-2022-22818)、[GHSA-95rw-fx8r-36v6](https://osv.dev/vulnerability/GHSA-95rw-fx8r-36v6)、[PYSEC-2022-19](https://osv.dev/vulnerability/PYSEC-2022-19)、[BIT-django-2022-22818](https://osv.dev/vulnerability/BIT-django-2022-22818) |
| 中风险 | django | 2.2.0 | 5.2.2 | [CVE-2025-48432](https://www.cve.org/CVERecord?id=CVE-2025-48432)、[GHSA-7xr5-9hcq-chf9](https://osv.dev/vulnerability/GHSA-7xr5-9hcq-chf9)、[BIT-django-2025-48432](https://osv.dev/vulnerability/BIT-django-2025-48432)、[PYSEC-2025-47](https://osv.dev/vulnerability/PYSEC-2025-47) |
| 中风险 | django | 2.2.0 | 2.2.8 | [CVE-2019-19118](https://www.cve.org/CVERecord?id=CVE-2019-19118)、[GHSA-hvmf-r92r-27hr](https://osv.dev/vulnerability/GHSA-hvmf-r92r-27hr)、[PYSEC-2019-15](https://osv.dev/vulnerability/PYSEC-2019-15) |
| 中风险 | urllib3 | 1.25.8 | 1.25.9 | [CVE-2020-26137](https://www.cve.org/CVERecord?id=CVE-2020-26137)、[GHSA-wqvq-5m8c-6g24](https://osv.dev/vulnerability/GHSA-wqvq-5m8c-6g24)、[PYSEC-2020-148](https://osv.dev/vulnerability/PYSEC-2020-148) |
| 中风险 | django | 2.2.0 | 2.2.26 | [CVE-2021-45452](https://www.cve.org/CVERecord?id=CVE-2021-45452)、[GHSA-jrh2-hc4r-7jwx](https://osv.dev/vulnerability/GHSA-jrh2-hc4r-7jwx)、[PYSEC-2022-3](https://osv.dev/vulnerability/PYSEC-2022-3)、[BIT-django-2021-45452](https://osv.dev/vulnerability/BIT-django-2021-45452) |
| 中风险 | django | 2.2.0 | 5.1.1 | [CVE-2024-45231](https://www.cve.org/CVERecord?id=CVE-2024-45231)、[GHSA-rrqc-c2jx-6jgv](https://osv.dev/vulnerability/GHSA-rrqc-c2jx-6jgv)、[BIT-django-2024-45231](https://osv.dev/vulnerability/BIT-django-2024-45231) |
| 中风险 | urllib3 | 1.25.8 | 1.26.19 | [CVE-2024-37891](https://www.cve.org/CVERecord?id=CVE-2024-37891)、[GHSA-34jh-p97f-mpxf](https://osv.dev/vulnerability/GHSA-34jh-p97f-mpxf) |
| 中风险 | django | 2.2.0 | 2.2.24 | [CVE-2021-33203](https://www.cve.org/CVERecord?id=CVE-2021-33203)、[GHSA-68w8-qjq3-2gfm](https://osv.dev/vulnerability/GHSA-68w8-qjq3-2gfm)、[PYSEC-2021-98](https://osv.dev/vulnerability/PYSEC-2021-98)、[BIT-django-2021-33203](https://osv.dev/vulnerability/BIT-django-2021-33203) |
| 中风险 | urllib3 | 1.25.8 | 2.5.0 | [CVE-2025-50181](https://www.cve.org/CVERecord?id=CVE-2025-50181)、[GHSA-pq67-6m6q-mj2v](https://osv.dev/vulnerability/GHSA-pq67-6m6q-mj2v) |
| 中风险 | urllib3 | 1.25.8 | 1.26.18 | [CVE-2023-45803](https://www.cve.org/CVERecord?id=CVE-2023-45803)、[GHSA-g4mx-q9vg-27p4](https://osv.dev/vulnerability/GHSA-g4mx-q9vg-27p4)、[PYSEC-2023-212](https://osv.dev/vulnerability/PYSEC-2023-212) |


## 仓库安检

- 硬编码密钥：发现 3 处疑似明文凭证。
- 敏感文件跟踪：没有发现被 git 跟踪的敏感文件。
- .gitignore：没有发现需要补充的敏感文件忽略规则。
- 本地配置检查：发现 0 个需要确认的仓库安检项，1 条建议。

| 位置 | 类型 | 可信度 | 证据预览 |
| --- | --- | --- | --- |
| app/settings.py:1 | 疑似密码 | medium | password = "***" |
| app/settings.py:2 | 疑似 API Key | medium | api_key = "***" |
| app/settings.py:3 | PostgreSQL 连接字符串 | high | postgre...host |

### 依赖配置与维护

| 等级 | 位置 | 检查项 | 处理 |
| --- | --- | --- | --- |
| 建议 | .github/dependabot.yml | 配置 Dependabot | .github/dependabot.yml，建议创建覆盖 pip 的配置；推送到 GitHub 后，Dependabot 会按 schedule 检查更新。 |


## 过期依赖

没有检测到明确的过期依赖，或当前包管理器没有返回可用结果。

提醒：过期依赖用于版本维护规划；处理顺序仍以当前风险项和发布窗口为准。


## 覆盖说明

### 1. 疑似硬编码凭证：app/settings.py:3
- 影响程度：高风险
- 位置：`app/settings.py`
- 为什么要关注：扫描在 app/settings.py:3 发现PostgreSQL 连接字符串特征，需要研发确认是否是真实可用凭证。
- 可能影响：如果该凭证真实可用，泄露后可能造成未授权访问或数据暴露。
- 建议动作：先确认是否真实有效；如有效，先轮换或撤销，再移除代码中的明文。

### 2. 疑似硬编码凭证：app/settings.py:1
- 影响程度：中风险
- 位置：`app/settings.py`
- 为什么要关注：扫描在 app/settings.py:1 发现疑似密码特征，需要研发确认是否是真实可用凭证。
- 可能影响：如果该凭证真实可用，泄露后可能造成未授权访问或数据暴露。
- 建议动作：先确认是否真实有效；如有效，先轮换或撤销，再移除代码中的明文。

### 3. 疑似硬编码凭证：app/settings.py:2
- 影响程度：中风险
- 位置：`app/settings.py`
- 为什么要关注：扫描在 app/settings.py:2 发现疑似 API Key特征，需要研发确认是否是真实可用凭证。
- 可能影响：如果该凭证真实可用，泄露后可能造成未授权访问或数据暴露。
- 建议动作：先确认是否真实有效；如有效，先轮换或撤销，再移除代码中的明文。


## 扫描错误

- [outdated_check] 已跳过过期依赖检查：默认不执行项目内包管理器命令；如需执行 npm/pnpm/yarn/uv/go/cargo 等项目工具，请显式传入 --allow-project-exec。


## 下一步建议

- 优先处理 27 个紧急/高风险项；依赖漏洞先处理有明确修复版本或官方处置路径的项，仓库安检项先处理工作流权限、凭证、容器和供应链配置。
- 安排研发确认凭证和敏感文件是否真实有效；如有效，先轮换或撤销，再清理代码中的明文。
- 依赖修复后必须重新运行扫描；如果仍出现同名旧版本，通常是间接依赖被父包锁定，需要询问用户是否确认升级父依赖到 latest。
- 复查扫描错误，补齐失败的官方漏洞源、包管理器或工具链检查后再确认最终结论。
- 依赖修复后必须重新运行扫描，确认风险项是否真正消失。
- 修复脚本只执行普通包管理器升级；如果复扫仍出现同名旧版本，报告中会标注父依赖信息，可继续升级父依赖来解除锁定。
