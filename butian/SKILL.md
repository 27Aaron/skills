---
name: butian
description: >
  Use when the user asks to check local dependency security and repository hygiene,
  scan for dependency vulnerabilities, find hardcoded secrets, check sensitive files
  tracked by git, audit .gitignore coverage, detect outdated dependencies, or generate
  a security report. Triggers include:
  "帮我看看项目有没有安全问题"、"安全扫描"、"扫一下项目"、"依赖有没有漏洞"、
  "木马包"、"恶意包"、"硬编码密钥"、"API Key"、"token"、"env 是否误提交"、
  "gitignore 是否合理"、"依赖是否太旧"、"漏洞检查"、"供应链安全"。
  Supports JavaScript/TypeScript, Python, Go, Rust projects. Chinese-first output.
---

# 补天

本地项目安全扫描。产出 Markdown 审计报告 + 只读 HTML 报告，面向产品经理、项目负责人等非安全背景读者。扫描不改源码和依赖；报告工作区写入本地 `.butian/` 和 `docs/`，修复需用户确认。

## 它会查什么

- **依赖漏洞** — 从 lockfile 提取依赖，逐个查已知漏洞（CVE / GHSA），按严重度排序
- **硬编码密钥** — 扫代码里写死的 API Key / token / 密码，报告只给脱敏预览
- **敏感文件误提交** — `.env`、私钥、证书是否被 git 跟踪
- **仓库卫生** — `.gitignore` 该挡的有没有挡住；报告展示中文类型标签（如"LLM/API 密钥 (sk-)"）和脱敏预览，不超过 5 条，超出显示"…及其他 N 处"
- **过期依赖** — 给升级建议，但不把"过期"夸大成"有漏洞"

支持 JavaScript / TypeScript、Python、Go、Rust。

## 它的边界（很重要）

它解决的是**依赖和仓库卫生**这一层的安全问题，不能替代代码审计、渗透测试或部署安全评估——业务逻辑、权限、SQL 注入、XSS 这些代码层风险，仍然得单独复核。报告里会反复强调这点，不制造恐慌，也不给你虚假的安全感。

## 铁律

- **扫描不改业务项目。** 扫描只读取项目文件、调漏洞 API，不修改源码、依赖、数据库、日志或任意项目文件；会创建/更新 `.butian/` 本地报告工作区，并会确保 `.gitignore` 忽略 `.butian/`
- **修复要你点头。** 报告生成并打开后，Agent 先用 AskUserQuestion 询问是否修复（确认修复 / 取消修复）；确认后再用 AskUserQuestion 询问升级策略（升级到已修复版本 / 升级到最新版本）。Agent 不会自行执行任何升级命令。
- **不把"过旧"说成"有漏洞"。** 只有命中漏洞数据时才说有漏洞
- **不制造恐慌。** 没有证据时说"不确定"，不说"肯定安全"或"肯定中招"

## 技术约束

- 只在本地读取用户项目文件；不上传源码、lockfile、env 或密钥；不要上传完整 lockfile、`.env`、私钥、证书、数据库、日志或任意项目文件；除 `.butian/`、`docs/security-report-YYYY-MM-DD.md` 和必要的 `.gitignore` 规则外，不修改源码、依赖、数据库、日志或任意项目文件。
- 依赖漏洞检查会直接请求 OSV、NVD、CISA KEV 和 FIRST EPSS；只发送最小必要信息：`ecosystem`、`name`、`version`。
- 报告里不要泄露完整密钥，只能写文件、行号、类型和脱敏预览。HTML 报告用结构化列表展示：路径（等宽加粗）+ 中文类型标签 + 脱敏 `preview`（code 背景），不裸露英文 type 标识。
- 扫描自动排除工具配置目录（`.git`、`.butian`、`.claude`、`node_modules`、`.next`、`dist` 等），不扫自身的模板和静态资源文件。`generic_sk_key` 正则使用 `\b` 词边界，避免 CSS `mask-composite` 等误匹配。
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

`scripts/run_audit.py` 默认扫描当前目录并自动向上识别最近的项目根目录；在 monorepo 子项目中运行时，优先使用当前子项目的 manifest/lockfile，不要跳到上层 git repo。需要扫描其他目录时，把路径作为最后一个参数传入。脚本会按顺序运行预检、扫描、analysis 生成、Markdown 生成和 HTML 生成，生成后会尝试用系统默认浏览器自动打开静态 HTML 报告（仅首次扫描自动打开，复扫不会重复弹出），并在终端输出固定的人类可读摘要：`📊 风险总览`、`⚠️ 能力边界`、`🚨 重点关注`、`📁 报告路径`；其中能力边界必须使用 Markdown 引用格式 `>` 输出完整文案。人工交互扫描默认不要加 `--no-open`；只有 CI、自动化或测试需要避免弹浏览器时才使用 `--no-open`。如果输出中的模式是 `hygiene_only`，必须告诉用户：`当前项目未发现支持的依赖文件，暂无法执行依赖漏洞扫描；本次仅做仓库卫生扫描，检查硬编码密钥、敏感文件跟踪和 .gitignore 风险。`

对话最终回复如果需要转述扫描结果，必须使用 Markdown 引用格式 `>` 展示完整能力边界，不要自行压缩成短句，也不要另起"提示"类标题。固定写法如下：

```text
⚠️ 能力边界

> 安全往往不是最显眼的需求，却是产品长期稳定运行的底线。此 Skill 会帮助你发现依赖漏洞、过期依赖和仓库卫生风险，帮助团队更早暴露容易被忽视的供应链问题。但它不能替代代码审计、渗透测试或部署安全评估；业务逻辑、权限控制、SQL 注入、XSS 等代码层风险仍需单独复核。
```

报告生成完毕后，告诉用户：

- 报告已生成: `.butian/<timestamp>/content/security-report.html`
- `HTML 报告已保存，之后也可以从 content 目录重新查看。`
- `已尝试在默认浏览器中打开报告。` 如果自动打开失败，告诉用户手动打开报告路径。

**重要：不要自行执行任何升级命令（npm install / pip install / yarn add 等）。** 扫描脚本只负责生成并打开报告，不会自动修复。你的职责是在用户看完报告后，用 AskUserQuestion 询问是否修复和修复策略；如果当前环境不支持 AskUserQuestion，就用普通对话提问。

如果流水线中某一步失败，再按下面的分步流程定位。各脚本的调试和性能参数见 `python3 scripts/<script>.py --help`。

### Step 0 生态预检

调试或分步运行时，先执行预检脚本：

```bash
# macOS / Linux
python3 scripts/detect.py
# Windows
py -3 scripts/detect.py
```

`scripts/detect.py` 默认扫描当前目录并自动向上识别最近的项目根目录；如果当前目录属于 monorepo 子项目，必须以最近的项目 manifest/lockfile 为准。需要扫描其他目录时，把路径作为最后一个参数传入。它会创建 `.butian/<timestamp>/content/` 和 `.butian/<timestamp>/assets/`，把 JSON 打印到终端，并把同一份结果保存到 `.butian/<timestamp>/assets/preflight.json`；同时确保 `.gitignore` 忽略 `.butian/`，并在 `butian_workspace.gitignore` 记录扫描前 `.gitignore` 是否已存在、是否本次新增 `.butian/`。结果里的 `output_file` 是实际保存路径。先读 preflight JSON，再决定扫描模式。

如果 `language_support.supported` 为 `true`，继续执行完整流程：仓库卫生扫描 -> 依赖提取 -> 官方漏洞源检查 -> 过旧依赖检查。

如果 `language_support.supported` 为 `false`，先告诉用户：`当前项目未发现支持的依赖文件，暂无法执行依赖漏洞扫描；本次仅做仓库卫生扫描，检查硬编码密钥、敏感文件跟踪和 .gitignore 风险。` 然后运行 `scan.py --preflight <preflight_json>` 生成只包含仓库卫生扫描、硬编码密钥和敏感文件跟踪结论的报告；不要调用官方漏洞源，也不要暗示已经检查过依赖漏洞。

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
python3 scripts/analyze.py .butian/<timestamp>/assets/scan.json
# Windows
py -3 scripts/analyze.py .butian/<timestamp>/assets/scan.json
```

`analyze.py` 会生成确定性基线；agent 之后只能做轻量复核和业务语言润色。修改 report schema、Markdown 顺序或 HTML 展示时，先读 `references/report-contract.md`。

### Step 3 Markdown 报告

先把结论写到被扫项目的 `docs/security-report-YYYY-MM-DD.md`。默认用脚本从 analysis JSON 生成（仅首次扫描生成，复扫跳过）：

```bash
# macOS / Linux
python3 scripts/report.py .butian/<timestamp>/assets/analysis.json
# Windows
py -3 scripts/report.py .butian/<timestamp>/assets/analysis.json
```

Markdown 必须使用普通人能看懂的产品风险语言。完整章节顺序和字段要求见 `references/report-contract.md`。

### Step 4 HTML 报告

生成静态 HTML 报告（CSS/JS 内联，单文件可移动），自动用系统默认浏览器打开。报告写到 `.butian/<timestamp>/content/security-report.html`。

```bash
# macOS / Linux
python3 scripts/visualize.py .butian/<timestamp>/assets/analysis.json
# Windows
py -3 scripts/visualize.py .butian/<timestamp>/assets/analysis.json
```

`visualize.py` 默认把 HTML 写到 `.butian/<timestamp>/content/security-report.html`，不需要在命令里手写输出路径。

### Step 5 用户确认修复

扫描完成、Markdown 报告生成、HTML 报告打开、终端摘要输出之后，如果存在可修复依赖漏洞，Agent 按以下三轮流程引导用户修复。这些询问写在 Skill 工作流里，不写进扫描脚本。

#### 第一轮：顶层依赖升级

1. **是否修复**：用 AskUserQuestion 提供 `确认修复` / `取消修复`。用户选择取消时，停止修复，只总结报告路径和主要风险。
2. **修复方式**：用户确认修复后，用 AskUserQuestion 提供 `将依赖升级到已修复版本` / `将依赖升级到最新版本`。
   - **将依赖升级到已修复版本**：把命中漏洞的包升级到已知修复版本（改动最小，推荐）
   - **将依赖升级到最新版本**：把命中漏洞的包升级到最新版本（一步到位，但可能有重大变更）
3. **执行升级**：用户选择策略后，运行修复脚本：

```bash
# 升级到已修复版本
python3 scripts/fix.py .butian/<timestamp>/assets/analysis.json --strategy fixed

# 升级到最新版本
python3 scripts/fix.py .butian/<timestamp>/assets/analysis.json --strategy latest
```

4. **复扫验证**：升级完成后，重新运行 `python3 scripts/run_audit.py` 复扫并生成新报告。复扫不会重复弹出浏览器（仅首次扫描自动打开）。如果此轮修复后无残留，进入最终报告步骤；如果有残留，继续下一轮。

#### 第二轮：处理残留（复扫后仍有残留时）

复扫后如果仍有同名依赖漏洞残留，说明是父依赖锁定了嵌套旧版本。报告会标注父依赖声明的版本范围，帮助理解残留原因。

5. **向用户说明**：顶层依赖已升级成功；残留项来自父依赖锁定的嵌套旧版本；报告中已标注每个残留的父依赖信息。
6. **是否继续**：用 AskUserQuestion 提供 `升级父依赖并复扫` / `暂不处理`。用户选择暂不处理时，生成最终报告并结束。
7. **执行升级**：用户选择继续后，运行：

```bash
python3 scripts/fix.py .butian/<timestamp>/assets/analysis.json --strategy parent-upgrade
```

脚本会自动：升级父依赖到 latest → 升级有漏洞的子依赖到修复版本。无法追溯到 `package.json` 根依赖的残留会标注出来，需要等待上游修复或人工评估。

8. **复扫并展示结果**：升级完成后，重新运行 `python3 scripts/run_audit.py` 复扫。如果此轮修复后无残留，进入最终报告步骤；如果有残留，继续下一轮。

#### 第三轮：强制覆盖残留依赖（第二轮后仍有残留时）

第二轮 `parent-upgrade` 后如果仍有残留（无法追溯到 `package.json` 根依赖的间接依赖），可通过 npm `overrides` 强制覆盖所有嵌套实例。

9. **向用户说明**：第二轮升级后仍有残留，这些依赖无法追溯到根依赖；可通过在 `package.json` 中写入 `overrides` 强制所有嵌套实例升级到修复版本。
10. **是否继续**：用 AskUserQuestion 提供 `强制覆盖残留依赖` / `暂不处理`。用户选择暂不处理时，生成最终报告并结束。
11. **执行覆盖**：用户选择继续后，运行：

```bash
python3 scripts/fix.py .butian/<timestamp>/assets/analysis.json --strategy force-residual
```

脚本会自动：读取 analysis.json 中残留的可修复项 → 在 `package.json` 的 `overrides` 字段中添加版本强制约束 → 运行 `npm install` 使 overrides 生效。

12. **复扫并展示结果**：覆盖完成后，重新运行 `python3 scripts/run_audit.py` 复扫。进入最终报告步骤。

#### 最终报告

所有修复轮次结束后（无论哪一轮结束），用 `--final-report` 生成最终 Markdown 审计报告：

```bash
python3 scripts/run_audit.py --final-report
```

终端摘要会以 `📁 最终报告路径` 标注最终 Markdown。提醒用户运行项目测试、构建或启动检查。

#### 三轮后仍有残留

如果三轮升级后仍有残留（极少见），说明可能是非 npm 生态或特殊依赖结构，需要人工评估。告知用户当前状态并结束。

## 修复建议规则

- 密钥泄露：先撤销或轮换密钥，再删除代码中的明文；如果进入 git 历史，需单独确认后再用 BFG Repo Cleaner 等工具清理。
- 确认受影响的依赖：升级到修复版本，然后运行测试和构建。提醒兼容性风险。
- 恶意包：立即移除，检查 CI 环境凭证并轮换。
- 版本不明确：说明只命中包名，需要 lockfile 才能确认。
- 依赖过旧：建议纳入升级计划，但不要在没有漏洞证据时当作安全事故处理。

## 依赖与运行前提

- 全部脚本是 Python 3 标准库，零第三方依赖（不用 pip install）。
- 最低 Python 3.8；Python 3.11+ 可使用内置 `tomllib` 解析 TOML lockfile，3.8–3.10 自动回退到正则提取（覆盖绝大多数 lockfile 格式）。
- macOS/Linux 自带 python3；Windows 需先装 Python 3，并使用 `py -3` 执行上述 Windows 示例。
- 依赖扫描支持：JavaScript/TypeScript（`package-lock.json` / `pnpm-lock.yaml` / `yarn.lock`）、Python（`poetry.lock` / `uv.lock` / `Pipfile.lock` / `requirements.txt`）、Go（`go.sum`）、Rust（`Cargo.lock`）。`requirements.txt` 只用 `==` / `===` 精确版本做漏洞匹配；支持 `-r` 文件包含和行续行符。

## CLI 参数参考

### run_audit.py

| 参数                      | 说明                                |
| ------------------------- | ----------------------------------- |
| `--no-open`               | 不自动打开 HTML 报告                |
| `--final-report`          | 最终复扫时强制生成 Markdown 报告    |
| `--verbose`               | 输出详细日志到 stderr               |
| `--debug`                 | 输出调试级别日志                    |
| `--follow-symlinks`       | 跟随符号链接扫描（默认跳过）        |
| `--skip-outdated`         | 跳过过期依赖检查                    |
| `--skip-hygiene`          | 跳过仓库卫生检查                    |
| `--include-packages`      | 在输出中包含完整包列表              |
| `--max-secret-files <n>`  | 密钥扫描最大文件数                  |

## 日志与缓存

- 日志文件：`.butian/<timestamp>/logs/scan.log`
- 本地缓存：`.butian/cache/`（跨 run 共享，默认 24 小时过期）
