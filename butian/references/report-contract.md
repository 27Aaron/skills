# 补天报告契约

本文件保存报表生成细节。默认扫描流程只需要执行 `scripts/run_audit.py`；只有调试、修改报告结构或分步生成时才需要读取这里。

## Analysis JSON

`analyze_scan.py` 会生成确定性基线：漏洞排序、`risk_summary`、`summary`、`red/yellow/green`、仓库卫生项、过期依赖和扫描错误。agent 之后只能做轻量复核和业务语言润色；不要删除已确认漏洞，不要把过期依赖改写成漏洞，不要把脱敏预览扩展成完整密钥。

- 命中漏洞：所有漏洞按影响程度排序（critical > high > medium > low），全部放入 `top_issues`，不要只放前 5 个。必须透传 `advisory_id`、`aliases`、`cve_id`、`package`、`version`、`severity`、`summary`、`fixed_versions` 等字段，网页会完整展示 GHSA。漏洞表的说明列必须是一句普通人能看懂的话，不要写"事实/为什么/影响/动作"四段，也不要在说明里堆 CVE/GHSA 编号。
- 仓库卫生扫描：透传 `hygiene.gitignore_missing`、`hygiene.tracked_secrets`、`hygiene.sensitive_tracked`。密钥内容必须脱敏，只写位置、类型、可信度和预览。
- 过期依赖：透传 `outdated`。过期依赖是维护信号，不等同于漏洞；用低风险、排期处理的语言描述。
- 风险项分级：`red` 放需优先处理或专业处理的事项；`yellow` 放需业务/部署确认的事项；`green` 可保留给 agent 的内部修复计划，但网页不再单独展示低风险维护区块。
- 每一项都必须设置 `severity`：`critical`、`high`、`medium`、`low`、`info` 之一。
- 必须构建 `risk_summary`：`{ "critical": N, "high": N, "medium": N, "low": N, "info": N }`。
- 必须构建 `summary`：每份 analysis JSON 都要有 `summary.tldr`、`summary.detail`、`summary.priority`。报告面向偏产品经理、项目负责人和非安全背景读者，少用术语，讲清楚"是否影响发布"、"是否需要马上安排"、"需要研发/运维确认什么"。`TL;DR` 不要写 `12 个 critical + 14 个 medium` 这类机器口吻；改写成"发现多项已确认依赖漏洞，风险集中在 next，建议先固定升级"这类产品语言。`detail` 不要展开 CVE/GHSA 编号列表；需要提证据编号时只放在漏洞表 GHSA 列。`priority` 必须是字符串数组。
- 必须透传 scan.py 输出中的 `generated_at` 和 `scan_seconds`，它们用于计算全流程耗时。

## Markdown 报告

Markdown 必须使用普通人能看懂的产品风险语言，并按以下顺序组织：

1. `# 安全扫描报告`
2. `## 报告总结`：`TL;DR`、详细说明、能力边界。
3. `## 命中漏洞`：列出已确认漏洞，按修复优先级排序；每条说明用一句小白能看懂的话；没有命中也要写清楚。
4. `## 仓库卫生扫描`：说明硬编码密钥、敏感文件跟踪、`.gitignore` 规则缺失情况。
5. `## 过期依赖`：说明过期依赖数量和维护建议，每条用一句话，明确"过期不等于漏洞"。
6. `## 需要人工确认的事项`：如密钥、访问控制、部署配置、恶意包等；只写"为什么要关注 / 可能影响 / 建议动作"，不要再写"事实"字段。
7. `## 扫描错误`：列出失败的官方漏洞源、包管理器或工具链检查。
8. `## 下一步建议`：只给用户阅读后的决策建议，不要求用户在网页点击按钮。

## HTML 报告

HTML 阅读流：项目概览 -> 报告总结 -> 仓库卫生 -> 命中漏洞 -> 过期依赖 -> 优先处理 -> 待确认事项 -> 扫描错误。静态 HTML 文件路径为 `.butian/<timestamp>/content/security-report.html`。

报告源码资产拆分为 `assets/report_template.html`、`assets/report.css` 和 `assets/report.js`，但 `build_report.py` 必须把 CSS/JS 内联进最终的 `security-report.html`，最终报告仍然是一个可单独移动和双击打开的 HTML 文件。

命中漏洞和过期依赖都默认展示 7 条，数量更多时用只读展开/收起按钮查看剩余全部条目；表格列宽必须稳定，依赖名称列按全量行计算宽度并保持单行展示，展开后不应触发表格重新挤压或换行。命中漏洞表的修复版本列必须把每个版本拆成独立项，每行最多显示两个版本，第三个及之后自动换行，不能挤压或覆盖 GHSA 列。
