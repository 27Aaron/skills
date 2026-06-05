---
name: butian
description: >
  Use when the user asks to check project security, scan for dependency vulnerabilities,
  find hardcoded secrets, check sensitive files tracked by git, audit .gitignore coverage,
  detect outdated dependencies, or generate a security report. Triggers include:
  "帮我看看项目有没有安全问题"、"安全扫描"、"扫一下项目"、"依赖有没有漏洞"、
  "木马包"、"恶意包"、"硬编码密钥"、"API Key"、"token"、"env 是否误提交"、
  "gitignore 是否合理"、"依赖是否太旧"、"漏洞检查"、"供应链安全"。
  Supports JavaScript/TypeScript, Python, Go, Rust projects. Chinese-first output.
---

# 补天

本地项目安全扫描。产出 Markdown 审计报告 + 只读 HTML 报告，面向产品经理、项目负责人等非安全背景读者。全程只读，修复需用户确认。

## 它会查什么

- **依赖漏洞** — 从 lockfile 提取依赖，逐个查已知漏洞（CVE / GHSA），按严重度排序
- **硬编码密钥** — 扫代码里写死的 API Key / token / 密码，报告只给脱敏预览
- **敏感文件误提交** — `.env`、私钥、证书是否被 git 跟踪
- **仓库卫生** — `.gitignore` 该挡的有没有挡住
- **过期依赖** — 给升级建议，但不把"过期"夸大成"有漏洞"

支持 JavaScript / TypeScript、Python、Go、Rust。

## 它的边界（很重要）

它解决的是**依赖和仓库卫生**这一层的安全问题，不能替代代码审计、渗透测试或部署安全评估——业务逻辑、权限、SQL 注入、XSS 这些代码层风险，仍然得单独复核。报告里会反复强调这点，不制造恐慌，也不给你虚假的安全感。

## 铁律

- **全程只读，绝不擅自动手。** 扫描只读文件、调漏洞 API，不碰源码和依赖；网页报告也只用来读，没有任何会触发本地操作的按钮
- **修复要你点头。** 看完报告，你在对话里说一句"可以修 / 修复 / OK"，Agent 才会动手升级或清理
- **不把"过旧"说成"有漏洞"。** 只有命中漏洞数据时才说有漏洞
- **不制造恐慌。** 没有证据时说"不确定"，不说"肯定安全"或"肯定中招"

## 技术约束

- 只在本地读取用户项目文件；不上传源码、lockfile、env 或密钥；不要上传完整 lockfile、`.env`、私钥、证书、数据库、日志或任意项目文件。
- 依赖漏洞检查会直接请求 OSV、NVD、CISA KEV 和 FIRST EPSS；只发送最小必要信息：`ecosystem`、`name`、`version`。
- 报告里不要泄露完整密钥，只能写文件、行号、类型和脱敏预览。
- 完整项目安全扫描必须先在被扫项目的 `docs/` 下生成 Markdown 审计报告；如果当前工作目录就是被扫项目，也就是当前工作目录的 `docs/`。报告文件例如 `docs/security-report-YYYY-MM-DD.md`。用户阅读报告后明确允许修复，才可以执行升级、删除缓存跟踪、修改 `.gitignore`、清理历史或轮换凭证相关操作。
- 官方漏洞源：OSV 用于按包坐标命中开源依赖漏洞；NVD、CISA KEV 和 FIRST EPSS 只在 OSV 返回 CVE 后做 CVSS/CWE、已知被利用和利用概率富化；不做泛安全情报查询。
- 脚本路径按本 skill 目录解析；如果当前 shell 不在 skill 根目录，使用这些脚本的绝对路径。扫描目标由脚本参数或 preflight JSON 中的 `project.path` 决定，报告写到被扫项目的 `.butian/` 和 `docs/`。

## 执行流程

### 一键流水线（默认）

```bash
# macOS / Linux
python3 scripts/run_audit.py
# Windows
py -3 scripts/run_audit.py
```

`scripts/run_audit.py` 默认扫描当前目录并自动向上识别最近的项目根目录；在 monorepo 子项目中运行时，优先使用当前子项目的 manifest/lockfile，不要跳到上层 git repo。需要扫描其他目录时，把路径作为最后一个参数传入。脚本会按顺序运行预检、扫描、analysis 生成、Markdown 生成和 HTML 生成，生成后会尝试用系统默认浏览器自动打开静态 HTML 报告，并在终端输出固定的人类可读摘要：`📊 风险总览`、`⚠️ 能力边界`、`🚨 重点关注`、`📁 报告路径`；其中能力边界必须使用 Markdown 引用格式 `>` 输出完整文案。只有自动化或测试需要机器可读结果时才使用 `--compact`，此时输出 JSON。如果输出中的模式是 `hygiene_only`，必须告诉用户：`当前项目没有发现支持的依赖文件，暂不支持依赖漏洞扫描；本次只做仓库卫生扫描，检查硬编码密钥、敏感文件跟踪和 .gitignore 风险。`

对话最终回复如果需要转述扫描结果，必须使用 Markdown 引用格式 `>` 展示完整能力边界，不要自行压缩成短句，也不要另起"提示"类标题。固定写法如下：

```text
⚠️ 能力边界

> 安全往往不是最显眼的需求，却是产品长期稳定运行的底线。补天会优先帮助你发现依赖漏洞、过期依赖和仓库卫生风险，让容易被忽视的供应链问题更早暴露出来。但它不能替代代码审计、渗透测试或部署安全评估；代码层面的权限、业务逻辑、SQL 注入、XSS 等问题仍需单独复核。
```

报告生成完毕后，告诉用户：

- 报告已生成: `.butian/<timestamp>/content/security-report.html`
- `HTML 已保存到本次运行的 content 目录，之后也可以从这里重新查看。`
- `HTML 已尝试在默认浏览器中自动打开。` 如果自动打开失败，告诉用户手动打开报告路径。
- `如果你想继续处理修复，在对话里说一声"可以修 / 修复 / OK / Yes"都可以。`
- `确认后会按主要修复 -> 次要修复处理。`

如果流水线中某一步失败，再按下面的分步流程定位。各脚本的调试和性能参数见 `python3 scripts/<script>.py --help`。

### Step 0 生态预检

调试或分步运行时，先执行预检脚本：

```bash
# macOS / Linux
python3 scripts/preflight.py
# Windows
py -3 scripts/preflight.py
```

`scripts/preflight.py` 默认扫描当前目录并自动向上识别最近的项目根目录；如果当前目录属于 monorepo 子项目，必须以最近的项目 manifest/lockfile 为准。需要扫描其他目录时，把路径作为最后一个参数传入。它会创建 `.butian/<timestamp>/content/` 和 `.butian/<timestamp>/assets/`，把 JSON 打印到终端，并把同一份结果保存到 `.butian/<timestamp>/assets/preflight.json`；同时确保 `.gitignore` 忽略 `.butian/`，并在 `butian_workspace.gitignore` 记录扫描前 `.gitignore` 是否已存在、是否本次新增 `.butian/`。结果里的 `output_file` 是实际保存路径。先读 preflight JSON，再决定扫描模式。

如果 `language_support.supported` 为 `true`，继续执行完整流程：仓库卫生扫描 -> 依赖提取 -> 官方漏洞源检查 -> 过旧依赖检查。

如果 `language_support.supported` 为 `false`，先告诉用户：`当前项目没有发现支持的依赖文件，暂不支持依赖漏洞扫描；本次只做仓库卫生扫描，检查硬编码密钥、敏感文件跟踪和 .gitignore 风险。` 然后运行 `scan.py --preflight <preflight_json>` 生成只包含仓库卫生扫描、硬编码密钥和敏感文件跟踪结论的报告；不要调用官方漏洞源，也不要暗示已经检查过依赖漏洞。

### Step 1 扫描

读取 Step 0 的 preflight JSON 后再运行扫描。`scan.py` 会复用 `project.path`、`recommended_scan_mode` 和同一个时间戳目录；默认输出到 `.butian/<timestamp>/assets/scan.json`，输出路径由脚本写入 `output_file`，不要在命令里手写临时文件路径。

```bash
# macOS / Linux
python3 scripts/scan.py --preflight <preflight_json>
# Windows
py -3 scripts/scan.py --preflight <preflight_json>
```

`scan.py` 过旧依赖检查只运行当前项目内的包管理器或项目本地虚拟环境，不扫描系统 Python 环境。Python 项目只有发现项目内 `.venv` / `venv` / `env` 时才执行该虚拟环境的 `pip list --outdated`，否则跳过 PyPI 过期检查。脚本会自动完成：仓库卫生检查（gitignore / 敏感文件 / 硬编码密钥）-> 生态识别与依赖提取（npm/pnpm/yarn、pypi、go、crates-io）-> 直接请求 OSV、NVD、CISA KEV 和 FIRST EPSS 查漏洞（OSV 100 个包一批；NVD/EPSS 100 个 CVE 一批）-> 过旧依赖检查。如果 preflight 的 `recommended_scan_mode` 是 `hygiene_only`，脚本只做仓库卫生扫描，并跳过依赖提取、官方漏洞源和过旧依赖检查。

### Step 2 生成 analysis JSON

读 `.butian/<timestamp>/assets/scan.json` 后，先用脚本构建 `.butian/<timestamp>/assets/analysis.json`：

```bash
# macOS / Linux
python3 scripts/analyze_scan.py .butian/<timestamp>/assets/scan.json
# Windows
py -3 scripts/analyze_scan.py .butian/<timestamp>/assets/scan.json
```

`analyze_scan.py` 会生成确定性基线；agent 之后只能做轻量复核和业务语言润色。修改 report schema、Markdown 顺序或 HTML 展示时，先读 `references/report-contract.md`。

### Step 3 Markdown 报告

先把结论写到被扫项目的 `docs/security-report-YYYY-MM-DD.md`。默认用脚本从 analysis JSON 生成：

```bash
# macOS / Linux
python3 scripts/render_markdown.py .butian/<timestamp>/assets/analysis.json
# Windows
py -3 scripts/render_markdown.py .butian/<timestamp>/assets/analysis.json
```

Markdown 必须使用普通人能看懂的产品风险语言。完整章节顺序和字段要求见 `references/report-contract.md`。

### Step 4 HTML 报告

生成静态 HTML 报告（CSS/JS 内联，单文件可移动），自动用系统默认浏览器打开。报告写到 `.butian/<timestamp>/content/security-report.html`。

```bash
# macOS / Linux
python3 scripts/build_report.py .butian/<timestamp>/assets/analysis.json
# Windows
py -3 scripts/build_report.py .butian/<timestamp>/assets/analysis.json
```

`build_report.py` 默认把 HTML 写到 `.butian/<timestamp>/content/security-report.html`，不需要在命令里手写输出路径。

### Step 5 用户确认后的修复

如果用户在看完报告后回复 `同意` / `修复` / `OK` / `Yes` / `可以修` 等明确授权：

1. 按"主要修复 -> 次要修复"执行：
   - 主要修复：已确认的紧急/高风险漏洞升级、有明确修复版本的依赖、用户明确同意处理的真实凭证风险。
   - 次要修复：`.gitignore` 补规则、低风险维护项、过期依赖升级计划。
2. 不要在没有额外确认时执行凭证轮换、git 历史清理、删除文件、批量跨大版本升级。
3. 修复后运行项目已有测试、构建或最小验证命令，并把结果告诉用户。

## 修复建议规则

- 密钥泄露：先撤销或轮换密钥，再删除代码中的明文；如果进入 git 历史，需单独确认后再用 BFG Repo Cleaner 等工具清理。
- 确认受影响的依赖：升级到修复版本，然后运行测试和构建。提醒兼容性风险。
- 恶意包：立即移除，检查 CI 环境凭证并轮换。
- 版本不明确：说明只命中包名，需要 lockfile 才能确认。
- 依赖过旧：建议纳入升级计划，但不要在没有漏洞证据时当作安全事故处理。

## 依赖与运行前提

- 全部脚本是 Python 3 标准库，零第三方依赖（不用 pip install）。
- macOS/Linux 自带 python3；Windows 需先装 Python 3，并使用 `py -3` 执行上述 Windows 示例。
- 依赖扫描支持：JavaScript/TypeScript（`package-lock.json` / `pnpm-lock.yaml` / `yarn.lock`）、Python（`poetry.lock` / `uv.lock` / `Pipfile.lock` / `requirements.txt`）、Go（`go.sum`）、Rust（`Cargo.lock`）。`requirements.txt` 只用 `==` / `===` 精确版本做漏洞匹配；范围约束需要 lockfile 才能确认受影响版本。
