---
name: butian
description: 补天 项目代码安全扫描助手，用于"帮我看看项目有没有安全问题"、"安全扫描"、"扫一下项目"、"依赖有没有漏洞"、"木马包"、"恶意包"、"硬编码密钥"、"API Key"、"token"、"env 是否误提交"、"gitignore 是否合理"、"依赖是否太旧"、漏洞检查、项目安全、供应链安全、安全报告等代码仓库检查场景；支持 JavaScript/TypeScript、Python、Go、Rust 项目；默认中文解释，保留 API 字段名、生态名、命令和版本号。
---

# 项目安全检查

对用户项目做一次本地安全扫描，产出 Markdown 审计报告和只读 HTML 报告。默认用一键流水线执行：预检 -> 扫描 -> 生成 analysis JSON -> 生成 Markdown -> 生成静态 HTML -> agent 复核摘要。修复不在网页里执行，只在用户看完报告并在对话里明确同意后由 agent 执行。

## 核心边界

- 只在本地读取用户项目文件；不上传源码、lockfile、env 或密钥；不要上传完整 lockfile、`.env`、私钥、证书、数据库、日志或任意项目文件。
- 依赖漏洞检查会直接请求 OSV、NVD、CISA KEV 和 FIRST EPSS；只发送最小必要信息：`ecosystem`、`name`、`version`。
- 报告里不要泄露完整密钥，只能写文件、行号、类型和脱敏预览。
- 完整项目安全扫描必须先在被扫项目的 `docs/` 下生成 Markdown 审计报告；如果当前工作目录就是被扫项目，也就是当前工作目录的 `docs/`。报告文件例如 `docs/security-report-YYYY-MM-DD.md`。用户阅读报告后明确允许修复，才可以执行升级、删除缓存跟踪、修改 `.gitignore`、清理历史或轮换凭证相关操作。
- 官方漏洞源：OSV 用于按包坐标命中开源依赖漏洞；NVD、CISA KEV 和 FIRST EPSS 只在 OSV 返回 CVE 后做 CVSS/CWE、已知被利用和利用概率富化；不做泛安全情报查询。
- 能力边界：安全往往不是最显眼的需求，却是产品长期稳定运行的底线。帮助您发现依赖漏洞、过期依赖和仓库卫生风险，让容易被忽视的供应链问题更早暴露出来。但它不能替代代码审计、渗透测试或部署安全评估；代码层面的权限、业务逻辑、SQL 注入、XSS 等问题仍需单独复核。
- 脚本路径按本 skill 目录解析；如果当前 shell 不在 skill 根目录，使用这些脚本的绝对路径。扫描目标由脚本参数或 preflight JSON 中的 `project.path` 决定，报告写到被扫项目的 `.butian/` 和 `docs/`。

## 铁律

- **只改本地工作区。** 脚本只能创建/更新 `.butian/`、被扫项目的 `docs/security-report-YYYY-MM-DD.md`，并确保 `.gitignore` 包含 `.butian/`；安全扫描本身只读文件、调官方漏洞源，不修改源码、依赖或配置。
- **先做生态预检。** 完整依赖漏洞扫描只支持 JavaScript/TypeScript、Python、Go、Rust；没有命中支持文件时，先提示用户暂不支持依赖漏洞扫描，只做仓库卫生扫描。
- **报告先完整生成，再展示路径。** 必须等 Markdown 报告、analysis JSON 和静态 HTML 都写完后，再把 HTML 路径和摘要告诉用户；不要启动本地 server，也不要兜底起本地服务。
- **网页只读。** HTML 只用于阅读报告，不提供任何会触发本地操作的按钮。
- **修复操作需确认。** 用户看完报告后，在对话里回复 `同意` / `修复` / `OK` / `Yes` 等明确话术，agent 才能执行修复。
- **明确能力边界。** 终端摘要、Markdown 和 HTML 都必须提示本 skill 不是万能安全审计；它解决依赖相关安全问题，代码层风险需要单独复核。
- **不要把"依赖过旧"说成"存在漏洞"。** 只有命中漏洞数据时才说有漏洞。
- **不要制造恐慌。** 没有证据时说"不确定"，不要说"肯定安全"或"肯定中招"。

## 默认流程

常规完整扫描优先执行一键流水线：

```bash
# macOS / Linux
python3 scripts/run_audit.py
# Windows
py -3 scripts/run_audit.py
```

`scripts/run_audit.py` 默认扫描当前目录并自动向上识别项目根目录；需要扫描其他目录时，把路径作为最后一个参数传入。脚本会按顺序运行预检、扫描、analysis 生成、Markdown 生成和 HTML 生成，生成后会尝试用系统默认浏览器自动打开静态 HTML 报告，并在终端输出固定的人类可读摘要：`📊 风险总览`、`⚠️ 能力边界`、`🚨 重点关注`、`📁 报告路径`；其中能力边界必须使用 Markdown 引用格式 `>` 输出完整文案。只有自动化或测试需要机器可读结果时才使用 `--compact`，此时输出 JSON。如果输出中的模式是 `hygiene_only`，必须告诉用户：`当前项目没有发现 补天支持的依赖文件，暂不支持依赖漏洞扫描；本次只做仓库卫生扫描，检查硬编码密钥、敏感文件跟踪和 .gitignore 风险。`

对话最终回复如果需要转述扫描结果，必须使用 Markdown 引用格式 `>` 展示完整能力边界，不要自行压缩成短句，也不要另起"提示"类标题。固定写法如下：

```text
⚠️ 能力边界

> 安全往往不是最显眼的需求，却是产品长期稳定运行的底线。补天会优先帮助你发现依赖漏洞、过期依赖和仓库卫生风险，让容易被忽视的供应链问题更早暴露出来。但它不能替代代码审计、渗透测试或部署安全评估；代码层面的权限、业务逻辑、SQL 注入、XSS 等问题仍需单独复核。
```

扫描较慢、调试或自动化运行时，才给 `run_audit.py` 追加 `--skip-outdated`、`--api-concurrency`、`--outdated-concurrency`、`--skip-hygiene`、`--include-packages`、`--max-secret-files`、`--no-root-discovery`、`--no-open`。如果流水线中某一步失败，再按下面的分步流程定位。

## Step 0 生态预检

调试或分步运行时，先执行预检脚本：

```bash
# macOS / Linux
python3 scripts/preflight.py
# Windows
py -3 scripts/preflight.py
```

`scripts/preflight.py` 默认扫描当前目录并自动向上识别项目根目录；需要扫描其他目录时，把路径作为最后一个参数传入。它会创建 `.butian/<timestamp>/content/` 和 `.butian/<timestamp>/assets/`，把 JSON 打印到终端，并把同一份结果保存到 `.butian/<timestamp>/assets/preflight.json`；同时确保 `.gitignore` 忽略 `.butian/`，并在 `butian_workspace.gitignore` 记录扫描前 `.gitignore` 是否已存在、是否本次新增 `.butian/`。结果里的 `output_file` 是实际保存路径。先读 preflight JSON，再决定扫描模式。

如果 `language_support.supported` 为 `true`，继续执行完整流程：仓库卫生扫描 -> 依赖提取 -> 官方漏洞源检查 -> 过旧依赖检查。

如果 `language_support.supported` 为 `false`，先告诉用户：`当前项目没有发现 补天支持的依赖文件，暂不支持依赖漏洞扫描；本次只做仓库卫生扫描，检查硬编码密钥、敏感文件跟踪和 .gitignore 风险。` 然后运行 `scan.py --preflight <preflight_json>` 生成只包含仓库卫生扫描、硬编码密钥和敏感文件跟踪结论的报告；不要调用官方漏洞源，也不要暗示已经检查过依赖漏洞。

预检脚本只负责检测支持的依赖文件、确定扫描模式，并准备本地 `.butian/` 工作目录；不要在预检阶段探测系统包管理器、执行软件更新、系统更新或内核更新检查。

## Step 1 扫描

读取 Step 0 的 preflight JSON 后再运行扫描。`scan.py` 会复用 `project.path`、`recommended_scan_mode` 和同一个时间戳目录；默认输出到 `.butian/<timestamp>/assets/scan.json`，输出路径由脚本写入 `output_file`，不要在命令里手写临时文件路径。

```bash
# macOS / Linux
python3 scripts/scan.py --preflight <preflight_json>
# Windows
py -3 scripts/scan.py --preflight <preflight_json>
```

`scan.py` 默认用 1 并发请求官方漏洞源；过旧依赖检查按 CPU 数量做本地并发。脚本会自动完成：仓库卫生检查（gitignore / 敏感文件 / 硬编码密钥）-> 生态识别与依赖提取（npm/pnpm/yarn、pypi、go、crates-io）-> 直接请求 OSV、NVD、CISA KEV 和 FIRST EPSS 查漏洞（OSV 100 个包一批；NVD/EPSS 100 个 CVE 一批）-> 过旧依赖检查。如果 preflight 的 `recommended_scan_mode` 是 `hygiene_only`，脚本只做仓库卫生扫描，并跳过依赖提取、官方漏洞源和过旧依赖检查。扫描较慢或调试时才追加 `--api-concurrency`、`--outdated-concurrency`、`--skip-outdated`、`--include-packages`、`--max-secret-files`。

## Step 2 生成 analysis JSON

读 `.butian/<timestamp>/assets/scan.json` 后，先用脚本构建 `.butian/<timestamp>/assets/analysis.json`（schema 见 `scripts/build_report.py` 顶部注释）：

```bash
# macOS / Linux
python3 scripts/analyze_scan.py .butian/<timestamp>/assets/scan.json
# Windows
py -3 scripts/analyze_scan.py .butian/<timestamp>/assets/scan.json
```

`analyze_scan.py` 会生成确定性基线：漏洞排序、`risk_summary`、`summary`、`red/yellow/green`、仓库卫生项、过期依赖和扫描错误。agent 之后只能做轻量复核和业务语言润色；不要删除已确认漏洞，不要把过期依赖改写成漏洞，不要把脱敏预览扩展成完整密钥。

- **命中漏洞**：所有漏洞按严重度排序（critical > high > medium > low），全部放入 `top_issues`，不要只放前 5 个。必须透传 `advisory_id`、`aliases`、`cve_id`、`package`、`version`、`severity`、`summary`、`fixed_versions` 等字段，网页会完整展示 GHSA。漏洞表的说明列必须是一句普通人能看懂的话，不要写"事实/为什么/影响/动作"四段，也不要在说明里堆 CVE/GHSA 编号。
- **仓库卫生扫描**：透传 `hygiene.gitignore_missing`、`hygiene.tracked_secrets`、`hygiene.sensitive_tracked`。密钥内容必须脱敏，只写位置、类型、可信度和预览。
- **过期依赖**：透传 `outdated`。过期依赖是维护信号，不等同于漏洞；用低风险、排期处理的语言描述。
- **风险项分级**：`red` 放需优先处理或专业处理的事项；`yellow` 放需业务/部署确认的事项；`green` 可保留给 agent 的内部修复计划，但网页不再单独展示低风险维护区块。
- **每一项都必须设置 `severity`**：`critical`、`high`、`medium`、`low`、`info` 之一。
- **必须构建 `risk_summary`**：`{ "critical": N, "high": N, "medium": N, "low": N, "info": N }`。
- **必须构建 `summary`**：每份 analysis JSON 都要有 `summary.tldr`、`summary.detail`、`summary.priority`。报告面向偏产品经理、项目负责人和非安全背景读者，少用术语，讲清楚"是否影响发布"、"是否需要马上安排"、"需要研发/运维确认什么"。`TL;DR` 不要写 `12 个 critical + 14 个 medium` 这类机器口吻；改写成"发现多项已确认依赖漏洞，风险集中在 next，建议先固定升级"这类产品语言。`detail` 不要展开 CVE/GHSA 编号列表；需要提证据编号时只放在漏洞表 GHSA 列。`priority` 必须是字符串数组。
- 必须透传 scan.py 输出中的 `generated_at` 和 `scan_seconds`，它们用于计算全流程耗时。

## Step 3 Markdown 报告

先把结论写到被扫项目的 `docs/security-report-YYYY-MM-DD.md`。默认用脚本从 analysis JSON 生成：

```bash
# macOS / Linux
python3 scripts/render_markdown.py .butian/<timestamp>/assets/analysis.json
# Windows
py -3 scripts/render_markdown.py .butian/<timestamp>/assets/analysis.json
```

Markdown 必须使用普通人能看懂的产品风险语言，并按以下顺序组织：

1. `# 安全扫描报告`
2. `## 报告总结`
   - `TL;DR`：一句话摘要。
   - 详细说明：更完整地解释风险范围、是否影响发布、建议谁来处理；不要堆 CVE/GHSA 编号。
   - 能力边界：说明安全是产品长期稳定运行的底线，补天主要覆盖依赖漏洞、过期依赖和仓库卫生信号，不能替代代码审计、渗透测试或部署安全评估。
3. `## 命中漏洞`：列出已确认漏洞，按修复优先级排序；每条说明用一句小白能看懂的话；没有命中也要写清楚。
4. `## 仓库卫生扫描`：说明硬编码密钥、敏感文件跟踪、`.gitignore` 规则缺失情况。
5. `## 过期依赖`：说明过期依赖数量和维护建议，每条用一句话，明确"过期不等于漏洞"。
6. `## 需要人工确认的事项`：如密钥、访问控制、部署配置、恶意包等；只写"为什么要关注 / 可能影响 / 建议动作"，不要再写"事实"字段。
7. `## 扫描错误`：列出失败的官方漏洞源、包管理器或工具链检查。
8. `## 下一步建议`：只给用户阅读后的决策建议，不要求用户在网页点击按钮。

## Step 4 HTML 报告

默认生成静态 HTML 报告，保存到本次运行目录的 `content/` 下，并在 macOS / Windows / Linux 尝试用系统默认浏览器自动打开；自动化或测试运行才加 `--no-open`；不要启动本地 server，也不要把静态文件和本地服务混用。

报告源码资产拆分为 `assets/report_template.html`、`assets/report.css` 和 `assets/report.js`，但 `build_report.py` 必须把 CSS/JS 内联进最终的 `security-report.html`，最终报告仍然是一个可单独移动和双击打开的 HTML 文件。

```bash
# macOS / Linux
python3 scripts/build_report.py .butian/<timestamp>/assets/analysis.json
# Windows
py -3 scripts/build_report.py .butian/<timestamp>/assets/analysis.json
```

`build_report.py` 默认把 HTML 写到 `.butian/<timestamp>/content/security-report.html`，不需要在命令里手写输出路径。终端里告诉用户：

- 报告已生成: `.butian/<timestamp>/content/security-report.html`
- `HTML 已保存到本次运行的 content 目录，之后也可以从这里重新查看。`
- `HTML 已尝试在默认浏览器中自动打开。` 如果自动打开失败，告诉用户手动打开报告路径。
- `如果你想继续处理修复，在对话里说一声“可以修 / 修复 / OK / Yes”都可以。`
- `确认后会按主要修复 -> 次要修复处理。`

HTML 阅读流：项目概览 -> 报告总结 -> 仓库卫生 -> 命中漏洞 -> 过期依赖 -> 优先处理的高风险项 -> 人工复核 -> 扫描错误。静态 HTML 文件路径为 `.butian/<timestamp>/content/security-report.html`。

HTML 表格交互：命中漏洞和过期依赖都默认展示 7 条，数量更多时用只读展开/收起按钮查看剩余全部条目；表格列宽必须稳定，包名列按全量行计算宽度并保持单行展示，展开后不应触发表格重新挤压或换行。

## Step 5 用户确认后的修复

如果用户在看完报告后回复 `同意` / `修复` / `OK` / `Yes` / `可以修` 等明确授权：

1. 按"主要修复 -> 次要修复"执行：
   - 主要修复：已确认的严重/高危漏洞升级、有明确修复版本的依赖、用户明确同意处理的真实凭证风险。
   - 次要修复：`.gitignore` 补规则、低风险维护项、过期依赖升级计划。
2. 不要在没有额外确认时执行凭证轮换、git 历史清理、删除文件、批量跨大版本升级。
3. 修复后运行项目已有测试、构建或最小验证命令，并把结果告诉用户。

## 依赖与运行前提

- 全部脚本是 Python 3 标准库，零第三方依赖（不用 pip install）。
- macOS/Linux 自带 python3；Windows 需先装 Python 3，命令改为 `python` 或 `py -3`。
- 依赖扫描支持 JavaScript/TypeScript（npm/pnpm/yarn lockfile）、Python（pypi：`poetry.lock`、`uv.lock`、`Pipfile.lock`、`requirements.txt`）、Go、Rust（crates-io）。
- 本 skill 是 agent 驱动：扫描出数据后由 agent 做分级分析，不是双击即用的独立 App。

## 修复建议规则

- 密钥泄露：先撤销或轮换密钥，再删除代码中的明文；如果进入 git 历史，需单独确认后再用 BFG Repo Cleaner 等工具清理。
- 确认受影响的依赖：升级到修复版本，然后运行测试和构建。提醒兼容性风险。
- 恶意包：立即移除，检查 CI 环境凭证并轮换。
- 版本不明确：说明只命中包名，需要 lockfile 才能确认。
- 依赖过旧：建议纳入升级计划，但不要在没有漏洞证据时当作安全事故处理。
