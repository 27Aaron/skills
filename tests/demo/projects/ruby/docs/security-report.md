# 安全扫描报告

- 项目：ruby
- 路径：`/Users/aaron/Documents/Project/skills/tests/demo/projects/ruby`
- 生成时间：2026-06-10 03:55:44
- 扫描耗时：43.6 秒

## 报告总结

- TL;DR：发现 44 个已确认依赖风险项，其中 1 个为紧急项、26 个为高风险项，仓库安检仍有疑似硬编码凭证 3 处。
- 详细说明：本次检查覆盖项目 ruby，识别到 2 个依赖包，命中 44 个已确认风险项。仓库安检方面，发现疑似硬编码凭证 3 处、被 git 跟踪的敏感文件 0 个、建议补充的 .gitignore 规则 0 条、本地配置/工作流检查项 0 个、建议 1 条。过期依赖 0 个，建议按维护窗口和兼容性评估安排升级。
- 能力边界：安全往往不是最显眼的需求，却是产品长期稳定运行的底线。此 Skill 会帮助你发现依赖漏洞、过期依赖和仓库暴露风险，帮助团队更早暴露容易被忽视的供应链问题。但它不能替代代码审计、渗透测试或部署安全评估；业务逻辑、权限控制、SQL 注入、XSS 等代码层风险仍需单独复核。
- 优先级建议：
  - 优先处理 27 个紧急/高风险项；依赖漏洞先处理有明确修复版本或官方处置路径的项，仓库安检项先处理工作流权限、凭证、容器和供应链配置。
  - 安排研发确认凭证和敏感文件是否真实有效；如有效，先轮换或撤销，再清理代码中的明文。
  - 依赖修复后必须重新运行扫描；如果仍出现同名旧版本，通常是间接依赖被父包锁定，需要询问用户是否确认升级父依赖到 latest。


## 服务器运行环境

未启用服务器运行环境扫描。

## 命中风险项

| 影响程度 | 依赖名称 | 当前版本 | 安全编号 | 修复版本 | 说明 |
| --- | --- | --- | --- | --- | --- |
| 紧急 | rack | 2.0.8 | [CVE-2022-30123](https://www.cve.org/CVERecord?id=CVE-2022-30123)、[GHSA-wq4h-7r42-5hrr](https://osv.dev/vulnerability/GHSA-wq4h-7r42-5hrr) | 2.0.9.1、2.1.4.1、2.2.3.1 | rack 2.0.8 公告摘要：Possible shell escape sequence injection vulnerability in Rack；建议升级到 2.0.9.1、2.1.4.1、2.2.3.1 或更高版本。；EPSS 85.1%；CVSS 10；CWE-150；NVD 2022-12-05 |
| 高风险 | rack | 2.0.8 | [CVE-2022-44570](https://www.cve.org/CVERecord?id=CVE-2022-44570)、[GHSA-65f5-mfpf-vfhj](https://osv.dev/vulnerability/GHSA-65f5-mfpf-vfhj) | 2.0.9.2、2.1.4.2、2.2.6.2、3.0.4.1 | rack 2.0.8 存在拒绝服务风险；建议升级到 2.0.9.2、2.1.4.2、2.2.6.2、3.0.4.1 或更高版本。；EPSS 87.1%；CVSS 7.5；CWE-400、CWE-1333；NVD 2023-02-09 |
| 高风险 | rack | 2.0.8 | [CVE-2022-44571](https://www.cve.org/CVERecord?id=CVE-2022-44571)、[GHSA-93pm-5p5f-3ghx](https://osv.dev/vulnerability/GHSA-93pm-5p5f-3ghx) | 2.0.9.2、2.1.4.2、2.2.6.1、3.0.4.1 | rack 2.0.8 存在拒绝服务风险；建议升级到 2.0.9.2、2.1.4.2、2.2.6.1、3.0.4.1 或更高版本。；EPSS 87.1%；CVSS 7.5；CWE-400、CWE-1333；NVD 2023-02-09 |
| 高风险 | rack | 2.0.8 | [CVE-2023-27530](https://www.cve.org/CVERecord?id=CVE-2023-27530)、[GHSA-3h57-hmj3-gj3p](https://osv.dev/vulnerability/GHSA-3h57-hmj3-gj3p) | 2.0.9.3、2.1.4.3、2.2.6.3、3.0.4.2 | rack 2.0.8 存在拒绝服务风险；建议升级到 2.0.9.3、2.1.4.3、2.2.6.3、3.0.4.2 或更高版本。；EPSS 83.9%；CVSS 7.5；CWE-400、CWE-770；NVD 2023-03-10 |
| 高风险 | rack | 2.0.8 | [CVE-2025-27610](https://www.cve.org/CVERecord?id=CVE-2025-27610)、[GHSA-7wqh-767x-r66v](https://osv.dev/vulnerability/GHSA-7wqh-767x-r66v) | 2.2.13、3.0.14、3.1.12 | rack 2.0.8 公告摘要：:Static；建议升级到 2.2.13、3.0.14、3.1.12 或更高版本。；EPSS 80.5%；CVSS 7.5；CWE-23；NVD 2025-03-10 |
| 高风险 | rack | 2.0.8 | [CVE-2022-30122](https://www.cve.org/CVERecord?id=CVE-2022-30122)、[GHSA-hxqx-xwvh-44m2](https://osv.dev/vulnerability/GHSA-hxqx-xwvh-44m2) | 2.0.9.1、2.1.4.1、2.2.3.1 | rack 2.0.8 存在拒绝服务风险；建议升级到 2.0.9.1、2.1.4.1、2.2.3.1 或更高版本。；EPSS 77.8%；CVSS 7.5；CWE-400、CWE-1333；NVD 2022-12-05 |
| 高风险 | rack | 2.0.8 | [CVE-2020-8161](https://www.cve.org/CVERecord?id=CVE-2020-8161)、[GHSA-5f9h-9pjv-v6j7](https://osv.dev/vulnerability/GHSA-5f9h-9pjv-v6j7) | 2.1.3 | rack 2.0.8 公告摘要：:Directory app bundled with Rack；建议升级到 2.1.3 或更高版本。；EPSS 76.2%；CVSS 8.6；CWE-548、CWE-22；NVD 2020-07-02 |
| 高风险 | rack | 2.0.8 | [CVE-2020-8184](https://www.cve.org/CVERecord?id=CVE-2020-8184)、[GHSA-j6w9-fv6q-3q52](https://osv.dev/vulnerability/GHSA-j6w9-fv6q-3q52) | 2.1.4、2.2.3 | rack 2.0.8 公告摘要：Rack allows Percent-encoded cookies to overwrite existing prefixed cookie names；建议升级到 2.1.4、2.2.3 或更高版本。；EPSS 74.6%；CVSS 7.5；CWE-784、CWE-20；NVD 2020-06-19 |
| 高风险 | rack | 2.0.8 | [CVE-2025-46727](https://www.cve.org/CVERecord?id=CVE-2025-46727)、[GHSA-gjh7-p2fx-99vx](https://osv.dev/vulnerability/GHSA-gjh7-p2fx-99vx) | 2.2.14、3.0.16、3.1.14 | rack 2.0.8 公告摘要：:QueryParser；建议升级到 2.2.14、3.0.16、3.1.14 或更高版本。；EPSS 74.6%；CVSS 7.5；CWE-400、CWE-770；NVD 2025-05-07 |
| 高风险 | rack | 2.0.8 | [CVE-2024-26146](https://www.cve.org/CVERecord?id=CVE-2024-26146)、[GHSA-54rr-7fvw-6x8f](https://osv.dev/vulnerability/GHSA-54rr-7fvw-6x8f) | 3.0.9.1、2.2.8.1、2.1.4.4、2.0.9.4 | rack 2.0.8 存在拒绝服务风险；建议升级到 3.0.9.1、2.2.8.1、2.1.4.4、2.0.9.4 或更高版本。；EPSS 74%；CVSS 7.5；CWE-1333；NVD 2024-02-29 |
| 高风险 | rack | 2.0.8 | [CVE-2025-27111](https://www.cve.org/CVERecord?id=CVE-2025-27111)、[GHSA-8cgq-6mh2-7j6v](https://osv.dev/vulnerability/GHSA-8cgq-6mh2-7j6v) | 2.2.12、3.0.13、3.1.11 | rack 2.0.8 公告摘要：Escape Sequence Injection vulnerability in Rack lead to Possible Log Injection；建议升级到 2.2.12、3.0.13、3.1.11 或更高版本。；EPSS 71.7%；CVSS 7.5；CWE-93、CWE-117；NVD 2025-03-04 |
| 高风险 | rack | 2.0.8 | [CVE-2024-25126](https://www.cve.org/CVERecord?id=CVE-2024-25126)、[GHSA-22f2-v57c-j9cx](https://osv.dev/vulnerability/GHSA-22f2-v57c-j9cx) | 3.0.9.1、2.2.8.1 | rack 2.0.8 公告摘要：Rack vulnerable to ReDoS in content type parsing (2nd degree polynomial)；建议升级到 3.0.9.1、2.2.8.1 或更高版本。；EPSS 64%；CVSS 7.5；CWE-1333；NVD 2024-02-29 |
| 高风险 | rack | 2.0.8 | [CVE-2024-26141](https://www.cve.org/CVERecord?id=CVE-2024-26141)、[GHSA-xj5v-6v4g-jfw6](https://osv.dev/vulnerability/GHSA-xj5v-6v4g-jfw6) | 3.0.9.1、2.2.8.1 | rack 2.0.8 存在拒绝服务风险；建议升级到 3.0.9.1、2.2.8.1 或更高版本。；EPSS 61.7%；CVSS 7.5；CWE-400；NVD 2024-02-29 |
| 高风险 | rack | 2.0.8 | [CVE-2025-61772](https://www.cve.org/CVERecord?id=CVE-2025-61772)、[GHSA-wpv5-97wm-hp9c](https://osv.dev/vulnerability/GHSA-wpv5-97wm-hp9c) | 2.2.19、3.1.17、3.2.2 | rack 2.0.8 存在拒绝服务风险；建议升级到 2.2.19、3.1.17、3.2.2 或更高版本。；EPSS 55.7%；CVSS 7.5；CWE-400；NVD 2025-10-07 |
| 高风险 | rack | 2.0.8 | [CVE-2025-61919](https://www.cve.org/CVERecord?id=CVE-2025-61919)、[GHSA-6xw4-3v39-52mm](https://osv.dev/vulnerability/GHSA-6xw4-3v39-52mm) | 2.2.20、3.1.18、3.2.3 | rack 2.0.8 存在拒绝服务风险；建议升级到 2.2.20、3.1.18、3.2.3 或更高版本。；EPSS 51.8%；CVSS 7.5；CWE-400；NVD 2025-10-10 |
| 高风险 | rack | 2.0.8 | [CVE-2025-61770](https://www.cve.org/CVERecord?id=CVE-2025-61770)、[GHSA-p543-xpfm-54cp](https://osv.dev/vulnerability/GHSA-p543-xpfm-54cp) | 2.2.19、3.1.17、3.2.2 | rack 2.0.8 存在拒绝服务风险；建议升级到 2.2.19、3.1.17、3.2.2 或更高版本。；EPSS 50.3%；CVSS 7.5；CWE-400；NVD 2025-10-07 |
| 高风险 | rack | 2.0.8 | [CVE-2022-44572](https://www.cve.org/CVERecord?id=CVE-2022-44572)、[GHSA-rqv2-275x-2jq5](https://osv.dev/vulnerability/GHSA-rqv2-275x-2jq5) | 2.0.9.2、2.1.4.2、2.2.6.1、3.0.4.1 | rack 2.0.8 存在拒绝服务风险；建议升级到 2.0.9.2、2.1.4.2、2.2.6.1、3.0.4.1 或更高版本。；EPSS 49%；CVSS 7.5；CWE-400、CWE-1333；NVD 2023-02-09 |
| 高风险 | rack | 2.0.8 | [CVE-2025-59830](https://www.cve.org/CVERecord?id=CVE-2025-59830)、[GHSA-625h-95r8-8xpm](https://osv.dev/vulnerability/GHSA-625h-95r8-8xpm) | 2.2.18 | rack 2.0.8 公告摘要：:QueryParser allows params_limit bypass via semicolon-separated parameters；建议升级到 2.2.18 或更高版本。；EPSS 33.8%；CVSS 7.5；CWE-400、CWE-770；NVD 2025-09-25 |
| 高风险 | rack | 2.0.8 | [CVE-2026-22860](https://www.cve.org/CVERecord?id=CVE-2026-22860)、[GHSA-mxw3-3hh2-x2mh](https://osv.dev/vulnerability/GHSA-mxw3-3hh2-x2mh) | 2.2.22、3.1.20、3.2.5 | rack 2.0.8 公告摘要：Directory；建议升级到 2.2.22、3.1.20、3.2.5 或更高版本。；EPSS 31%；CVSS 7.5；CWE-22、CWE-548；NVD 2026-02-18 |
| 高风险 | rack | 2.0.8 | [CVE-2025-61771](https://www.cve.org/CVERecord?id=CVE-2025-61771)、[GHSA-w9pc-fmgc-vxvw](https://osv.dev/vulnerability/GHSA-w9pc-fmgc-vxvw) | 2.2.19、3.1.17、3.2.2 | rack 2.0.8 存在拒绝服务风险；建议升级到 2.2.19、3.1.17、3.2.2 或更高版本。；EPSS 28.5%；CVSS 7.5；CWE-400；NVD 2025-10-07 |
| 高风险 | rack | 2.0.8 | [CVE-2026-34829](https://www.cve.org/CVERecord?id=CVE-2026-34829)、[GHSA-8vqr-qjwx-82mw](https://osv.dev/vulnerability/GHSA-8vqr-qjwx-82mw) | 2.2.23、3.1.21、3.2.6 | rack 2.0.8 公告摘要：Rack's multipart parsing without Content-Length header allows unbounded chunked file uploads；建议升级到 2.2.23、3.1.21、3.2.6 或更高版本。；EPSS 21.1%；CVSS 7.5；CWE-400、CWE-770；NVD 2026-04-02 |
| 高风险 | rack | 2.0.8 | [CVE-2026-34785](https://www.cve.org/CVERecord?id=CVE-2026-34785)、[GHSA-h2jq-g4cq-5ppq](https://osv.dev/vulnerability/GHSA-h2jq-g4cq-5ppq) | 2.2.23、3.1.21、3.2.6 | rack 2.0.8 公告摘要：:Static prefix matching can expose unintended files under the static root；建议升级到 2.2.23、3.1.21、3.2.6 或更高版本。；EPSS 15.5%；CVSS 7.5；CWE-187、CWE-200；NVD 2026-04-02 |
| 高风险 | rack | 2.0.8 | [CVE-2026-34830](https://www.cve.org/CVERecord?id=CVE-2026-34830)、[GHSA-qv7j-4883-hwh7](https://osv.dev/vulnerability/GHSA-qv7j-4883-hwh7) | 2.2.23、3.1.21、3.2.6 | rack 2.0.8 公告摘要：:Sendfile header-based X-Accel-Mapping regex injection enables unauthorized X-Accel-Redirect；建议升级到 2.2.23、3.1.21、3.2.6 或更高版本。；EPSS 15.5%；CVSS 7.5；CWE-625；NVD 2026-04-02 |
| 高风险 | rack | 2.0.8 | [CVE-2026-34230](https://www.cve.org/CVERecord?id=CVE-2026-34230)、[GHSA-v569-hp3g-36wr](https://osv.dev/vulnerability/GHSA-v569-hp3g-36wr) | 2.2.23、3.1.21、3.2.6 | rack 2.0.8 公告摘要：:Utils.select_best_encoding via wildcard Accept-Encoding header；建议升级到 2.2.23、3.1.21、3.2.6 或更高版本。；EPSS 6.7%；CVSS 7.5；CWE-400、CWE-407；NVD 2026-04-02 |
| 高风险 | rack | 2.0.8 | [CVE-2026-34826](https://www.cve.org/CVERecord?id=CVE-2026-34826)、[GHSA-x8cg-fq8g-mxfx](https://osv.dev/vulnerability/GHSA-x8cg-fq8g-mxfx) | 2.2.23、3.1.21、3.2.6 | rack 2.0.8 存在拒绝服务风险；建议升级到 2.2.23、3.1.21、3.2.6 或更高版本。；EPSS 6.2%；CVSS 7.5；CWE-400、CWE-770；NVD 2026-04-02 |
| 高风险 | nokogiri | 1.13.10 | [GHSA-c4rq-3m3g-8wgx](https://osv.dev/vulnerability/GHSA-c4rq-3m3g-8wgx) | 1.19.3 | nokogiri 1.13.10 公告摘要：Nokogiri CSS selector tokenizer has regular expression backtracking；建议升级到 1.19.3 或更高版本。 |
| 高风险 | nokogiri | 1.13.10 | [GHSA-mrxw-mxhj-p664](https://osv.dev/vulnerability/GHSA-mrxw-mxhj-p664) | 1.18.4 | nokogiri 1.13.10 公告摘要：Nokogiri updates packaged libxslt to v1.1.43 to resolve multiple CVEs；建议升级到 1.18.4 或更高版本。 |
| 中风险 | rack | 2.0.8 | [CVE-2025-25184](https://www.cve.org/CVERecord?id=CVE-2025-25184)、[GHSA-7g2v-jj9q-g3rg](https://osv.dev/vulnerability/GHSA-7g2v-jj9q-g3rg) | 2.2.11、3.0.12、3.1.10 | rack 2.0.8 公告摘要：:CommonLogger；建议升级到 2.2.11、3.0.12、3.1.10 或更高版本。；EPSS 80.8%；CVSS 6.5；CWE-93、CWE-117；NVD 2025-02-12 |
| 中风险 | rack | 2.0.8 | [CVE-2023-27539](https://www.cve.org/CVERecord?id=CVE-2023-27539)、[GHSA-c6qg-cjj8-47qp](https://osv.dev/vulnerability/GHSA-c6qg-cjj8-47qp) | 2.2.6.4、3.0.6.1 | rack 2.0.8 存在拒绝服务风险；建议升级到 2.2.6.4、3.0.6.1 或更高版本。；EPSS 58.8%；CVSS 5.3；NVD 2025-01-09 |
| 中风险 | rack | 2.0.8 | [CVE-2025-32441](https://www.cve.org/CVERecord?id=CVE-2025-32441)、[GHSA-vpfw-47h7-xj4g](https://osv.dev/vulnerability/GHSA-vpfw-47h7-xj4g) | 2.2.14 | rack 2.0.8 公告摘要：Rack session gets restored after deletion；建议升级到 2.2.14 或更高版本。；EPSS 26.5%；CVSS 4.2；CWE-362、CWE-367、CWE-613；NVD 2025-05-07 |
| 中风险 | rack | 2.0.8 | [CVE-2026-34786](https://www.cve.org/CVERecord?id=CVE-2026-34786)、[GHSA-q4qf-9j86-f5mh](https://osv.dev/vulnerability/GHSA-q4qf-9j86-f5mh) | 2.2.23、3.1.21、3.2.6 | rack 2.0.8 公告摘要：: Static header_rules bypass via URL-encoded paths；建议升级到 2.2.23、3.1.21、3.2.6 或更高版本。；EPSS 14.4%；CVSS 5.3；CWE-180；NVD 2026-04-02 |
| 中风险 | rack | 2.0.8 | [CVE-2026-34831](https://www.cve.org/CVERecord?id=CVE-2026-34831)、[GHSA-q2ww-5357-x388](https://osv.dev/vulnerability/GHSA-q2ww-5357-x388) | 2.2.23、3.1.21、3.2.6 | rack 2.0.8 公告摘要：:Files error responses；建议升级到 2.2.23、3.1.21、3.2.6 或更高版本。；EPSS 13.6%；CVSS 6.5；CWE-130、CWE-135；NVD 2026-04-02 |
| 中风险 | rack | 2.0.8 | [CVE-2026-34763](https://www.cve.org/CVERecord?id=CVE-2026-34763)、[GHSA-7mqq-6cf9-v2qp](https://osv.dev/vulnerability/GHSA-7mqq-6cf9-v2qp) | 2.2.23、3.1.21、3.2.6 | rack 2.0.8 公告摘要：:Directory；建议升级到 2.2.23、3.1.21、3.2.6 或更高版本。；EPSS 13.6%；CVSS 5.3；CWE-625；NVD 2026-04-02 |
| 中风险 | rack | 2.0.8 | [CVE-2026-25500](https://www.cve.org/CVERecord?id=CVE-2026-25500)、[GHSA-whrj-4476-wvmp](https://osv.dev/vulnerability/GHSA-whrj-4476-wvmp) | 2.2.22、3.1.20、3.2.5 | rack 2.0.8 公告摘要：:Directory via javascript: filenames rendered into anchor href；建议升级到 2.2.22、3.1.20、3.2.5 或更高版本。；EPSS 7.4%；CVSS 5.4；CWE-79；NVD 2026-02-18 |
| 中风险 | rack | 2.0.8 | [CVE-2026-26961](https://www.cve.org/CVERecord?id=CVE-2026-26961)、[GHSA-vgpv-f759-9wx3](https://osv.dev/vulnerability/GHSA-vgpv-f759-9wx3) | 2.2.23、3.1.21、3.2.6 | rack 2.0.8 公告摘要：Rack's greedy multipart boundary parsing can cause parser differentials and WAF bypass.；建议升级到 2.2.23、3.1.21、3.2.6 或更高版本。；EPSS 3.1%；CVSS 5.3；CWE-436；NVD 2026-04-02 |
| 中风险 | rack | 2.0.8 | [CVE-2025-61780](https://www.cve.org/CVERecord?id=CVE-2025-61780)、[GHSA-r657-rxjc-j557](https://osv.dev/vulnerability/GHSA-r657-rxjc-j557) | 2.2.20、3.1.18、3.2.3 | rack 2.0.8 公告摘要：Rack has a Possible Information Disclosure Vulnerability；建议升级到 2.2.20、3.1.18、3.2.3 或更高版本。；EPSS 1.5%；CVSS 5.8；CWE-200、CWE-441、CWE-913；NVD 2025-10-10 |
| 中风险 | nokogiri | 1.13.10 | [GHSA-v2fc-qm4h-8hqv](https://osv.dev/vulnerability/GHSA-v2fc-qm4h-8hqv) | 1.19.3 | nokogiri 1.13.10 公告摘要：Nokogiri XSLT transform has a memory leak；建议升级到 1.19.3 或更高版本。 |
| 中风险 | nokogiri | 1.13.10 | [GHSA-wx95-c6cv-8532](https://osv.dev/vulnerability/GHSA-wx95-c6cv-8532) | 1.19.1 | nokogiri 1.13.10 公告摘要：Nokogiri does not check the return value from xmlC14NExecute；建议升级到 1.19.1 或更高版本。 |
| 待确认 | nokogiri | 1.13.10 | [GHSA-353f-x4gh-cqq8](https://osv.dev/vulnerability/GHSA-353f-x4gh-cqq8) | 1.18.9 | nokogiri 1.13.10 公告摘要：Nokogiri patches vendored libxml2 to resolve multiple CVEs；建议升级到 1.18.9 或更高版本。 |
| 待确认 | nokogiri | 1.13.10 | [GHSA-5w6v-399v-w3cc](https://osv.dev/vulnerability/GHSA-5w6v-399v-w3cc) | 1.18.8 | nokogiri 1.13.10 公告摘要：Nokogiri updates packaged libxml2 to v2.13.8 to resolve CVE-2025-32414 and CVE-2025-32415；建议升级到 1.18.8 或更高版本。 |
| 待确认 | nokogiri | 1.13.10 | [GHSA-pxvg-2qj5-37jq](https://osv.dev/vulnerability/GHSA-pxvg-2qj5-37jq) | 1.14.3 | nokogiri 1.13.10 公告摘要：Nokogiri updates packaged libxml2 to v2.10.4 to resolve multiple CVEs；建议升级到 1.14.3 或更高版本。 |
| 待确认 | nokogiri | 1.13.10 | [GHSA-r95h-9x8f-r3f7](https://osv.dev/vulnerability/GHSA-r95h-9x8f-r3f7) | 1.16.5 | nokogiri 1.13.10 公告摘要：Nokogiri updates packaged libxml2 to v2.12.7 to resolve CVE-2024-34459；建议升级到 1.16.5 或更高版本。 |
| 待确认 | nokogiri | 1.13.10 | [GHSA-vvfq-8hwr-qm4m](https://osv.dev/vulnerability/GHSA-vvfq-8hwr-qm4m) | 1.18.3 | nokogiri 1.13.10 公告摘要：Nokogiri updates packaged libxml2 to 2.13.6 to resolve CVE-2025-24928 and CVE-2024-56171；建议升级到 1.18.3 或更高版本。 |
| 待确认 | nokogiri | 1.13.10 | [GHSA-xc9x-jj77-9p9j](https://osv.dev/vulnerability/GHSA-xc9x-jj77-9p9j) | 1.16.2、1.15.6 | nokogiri 1.13.10 公告摘要：Nokogiri update packaged libxml2 to v2.12.5 to resolve CVE-2024-25062；建议升级到 1.16.2、1.15.6 或更高版本。 |


## 仓库安检

- 硬编码密钥：发现 3 处疑似明文凭证。
- 敏感文件跟踪：没有发现被 git 跟踪的敏感文件。
- .gitignore：没有发现需要补充的敏感文件忽略规则。
- 本地配置检查：发现 0 个需要确认的仓库安检项，1 条建议。

| 位置 | 类型 | 可信度 | 证据预览 |
| --- | --- | --- | --- |
| config.rb:1 | 疑似密码 | medium | password = "***" |
| config.rb:2 | 疑似 API Key | medium | api_key = "***" |
| config.rb:3 | PostgreSQL 连接字符串 | high | postgre...host |

### 依赖配置与维护

| 等级 | 位置 | 检查项 | 依据 | 处理 |
| --- | --- | --- | --- | --- |
| 建议 | .github/dependabot.yml | 配置 Dependabot | GitHub remote origin: git@github.com:27Aaron/skills.git | .github/dependabot.yml，建议创建覆盖 bundler 的配置；推送到 GitHub 后，Dependabot 会按 schedule 检查更新。 |


## 过期依赖

没有检测到明确的过期依赖，或当前包管理器没有返回可用结果。

提醒：过期依赖用于版本维护规划；处理顺序仍以当前风险项和发布窗口为准。


## 覆盖说明

### 1. 疑似硬编码凭证：config.rb:3
- 影响程度：高风险
- 位置：`config.rb`
- 为什么要关注：扫描在 config.rb:3 发现PostgreSQL 连接字符串特征，需要研发确认是否是真实可用凭证。
- 可能影响：如果该凭证真实可用，泄露后可能造成未授权访问或数据暴露。
- 建议动作：先确认是否真实有效；如有效，先轮换或撤销，再移除代码中的明文。

### 2. 疑似硬编码凭证：config.rb:1
- 影响程度：中风险
- 位置：`config.rb`
- 为什么要关注：扫描在 config.rb:1 发现疑似密码特征，需要研发确认是否是真实可用凭证。
- 可能影响：如果该凭证真实可用，泄露后可能造成未授权访问或数据暴露。
- 建议动作：先确认是否真实有效；如有效，先轮换或撤销，再移除代码中的明文。

### 3. 疑似硬编码凭证：config.rb:2
- 影响程度：中风险
- 位置：`config.rb`
- 为什么要关注：扫描在 config.rb:2 发现疑似 API Key特征，需要研发确认是否是真实可用凭证。
- 可能影响：如果该凭证真实可用，泄露后可能造成未授权访问或数据暴露。
- 建议动作：先确认是否真实有效；如有效，先轮换或撤销，再移除代码中的明文。


## 扫描错误

没有记录到扫描错误。


## 下一步建议

- 优先处理 27 个紧急/高风险项；依赖漏洞先处理有明确修复版本或官方处置路径的项，仓库安检项先处理工作流权限、凭证、容器和供应链配置。
- 安排研发确认凭证和敏感文件是否真实有效；如有效，先轮换或撤销，再清理代码中的明文。
- 依赖修复后必须重新运行扫描；如果仍出现同名旧版本，通常是间接依赖被父包锁定，需要询问用户是否确认升级父依赖到 latest。
- 依赖修复后必须重新运行扫描，确认风险项是否真正消失。
- 修复脚本只执行普通包管理器升级；如果复扫仍出现同名旧版本，报告中会标注父依赖信息，可继续升级父依赖来解除锁定。
