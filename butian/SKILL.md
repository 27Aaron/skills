---
name: butian
description: >
  Use when the user asks to check local dependency security, run repository security checks,
  scan for dependency vulnerabilities with lockfile/exact versions, find hardcoded secrets, check sensitive files
  tracked by git, audit .gitignore coverage, inspect GitHub Actions workflow security,
  review local supply-chain/IaC/container configuration, detect outdated dependencies,
  scan a Linux server runtime through read-only SSH, or generate a security report. Triggers include:
  "帮我看看项目有没有安全问题"、"安全扫描"、"扫一下项目"、"依赖有没有漏洞"、
  "木马包"、"恶意包"、"硬编码密钥"、"API Key"、"token"、"env 是否误提交"、
  "gitignore 是否合理"、"依赖是否太旧"、"漏洞检查"、"供应链安全"、
  "服务器扫描"、"Linux 服务器安全"、"SSH 扫描"。
  支持 JavaScript/TypeScript、Python、Go、Rust、PHP/Packagist、Ruby/RubyGems、
  Dart/Flutter Pub、Elixir/Erlang Hex、.NET/NuGet、Maven/JVM 的应用依赖检查；输出以简体中文为主。
---

# 补天

本地项目安全扫描。产出 Markdown 审计报告 + 只读 HTML 报告，面向产品经理、项目负责人等非安全背景读者。扫描不改源码和依赖；报告工作区写入本地 `.butian/` 和 `docs/butian/security-report-*.md`，并会直接确保 `.gitignore` 忽略 `.butian/` 与生成的安全报告文件；修复需用户确认。

## 它会查什么

- **依赖漏洞** — 从支持的依赖文件提取本地可确认的依赖坐标，逐个查已知漏洞（CVE / GHSA），按严重度排序
- **硬编码密钥** — 扫代码里写死的 API Key / token / 密码；默认脱敏，`.env.example`、`.env.sample`、`.env.template`、`.env.dist` 这类模板文件会在本地报告里展示完整命中值和前后代码上下文
- **敏感文件误提交** — `.env`、私钥、证书是否被 git 跟踪
- **仓库安检** — `.gitignore` 该挡的有没有挡住；GitHub Actions 是否存在过宽权限、危险触发器、脚本注入等本地静态风险；依赖配置与维护、IaC/容器配置是否有明显缺口；报告展示中文类型标签和凭证证据预览，不超过 5 条，超出显示"…及其他 N 处"
- **过期依赖** — 给出版本维护和升级窗口建议
- **Linux 服务器运行环境** — 在用户明确提供 SSH 目标后，只读采集 Linux 发行版、系统包、当前运行内核、重点运行服务和监听端口；按发行版包版本查询已确认漏洞。Docker 只采集容器名、镜像标签和端口映射，不进入容器、不扫描镜像内部

依赖漏洞扫描支持这些应用依赖生态：

- JavaScript / TypeScript：`package-lock.json` / `pnpm-lock.yaml` / `yarn.lock`
- Python：`poetry.lock` / `uv.lock` / `Pipfile.lock` / `requirements.txt`
- Go：`go.sum`
- Rust：`Cargo.lock`
- PHP / Packagist：`composer.lock`
- Ruby / RubyGems：`Gemfile.lock`
- Dart / Flutter Pub：`pubspec.lock`
- Elixir / Erlang Hex：`mix.lock`
- .NET / NuGet：`packages.lock.json` / `packages.config`
- Maven/JVM：`pom.xml` 中直接写明版本的依赖

依赖漏洞查询只处理能从本地文件提取出**精确包名 + 精确版本**的应用依赖坐标。Maven/JVM 第一版只解析本地 `pom.xml` 中直接写明版本的依赖；`${...}` 属性、父 POM、BOM、profile 或版本范围无法本地确认时跳过，不做漏洞查询。

## 它的边界（很重要）

它解决的是**应用依赖安全和本地仓库安检**这一层的问题，不能替代代码审计、渗透测试、GitHub 远端设置审计或部署安全评估——业务逻辑、权限、SQL 注入、XSS、线上权限和云账号配置这些风险，仍然得单独复核。报告里会反复强调这点，不制造恐慌，也不给你虚假的安全感。

应用依赖漏洞扫描不包含 Dockerfile、compose、Kubernetes、devcontainer、镜像/SBOM、OS/发行版包、系统包或系统安全公告生态；不要把这些混进 lockfile / manifest 依赖漏洞查询。只有用户明确启用 Linux 服务器扫描时，才通过只读 SSH 或离线 inventory 采集发行版包和运行环境信息。既有 IaC/容器本地静态规则仍只属于仓库安检，不等于镜像、SBOM 或系统包漏洞扫描。

## 铁律

- **扫描不改业务项目。** 扫描只读取项目文件、调漏洞 API，不修改源码、依赖、数据库、日志或任意项目文件；会创建/更新 `.butian/` 本地报告工作区和 `docs/butian/security-report-*.md` Markdown 报告文件，并会确保 `.gitignore` 忽略 `.butian/` 和 `docs/butian/security-report-*.md`，这个内部动作不用写进用户报告。
- **修复要你点头同意。** 报告生成并打开后，Agent 先用 AskUserQuestion 询问是否开始修复（开始修复 / 先不修复）；确认后再用 AskUserQuestion 询问升级方式（升级到修复版本 / 全部升级到最新版）。硬编码凭证占位符、Dependabot 配置、过期依赖更新等收尾维护动作统一放进一个多选 AskUserQuestion。Agent 不会自行执行任何升级命令或创建治理配置。
- **风险项和建议分开呈现。** 已确认依赖风险、仓库安检项、版本建议分别归类，避免混在一起影响判断。
- **不制造恐慌。** 没有证据时说"不确定"，不说"肯定安全"或"肯定中招"

## 技术约束

- 只在本地读取用户项目文件；不上传源码、lockfile、env 或密钥；不要上传完整 lockfile、`.env`、私钥、证书、数据库、日志或任意项目文件；扫描阶段除 `.butian/`、`docs/butian/security-report-<run-id>.md` 和 `.gitignore` 中的 `.butian/`、`docs/butian/security-report-*.md` 忽略规则外，不修改源码、依赖、数据库、日志或任意项目文件；敏感文件相关 `.gitignore` 规则只能在用户确认修复后写入；不要为用户创建 CI/CD workflow。
- 依赖漏洞检查会直接请求 OSV、NVD、CISA KEV 和 FIRST EPSS；只发送最小必要信息：`ecosystem`、`name`、`version`。
- 报告里不要泄露完整密钥，只能写文件、行号、类型和脱敏预览。HTML 报告用结构化列表展示：路径（等宽加粗）+ 中文类型标签 + 脱敏 `preview`（code 背景），不裸露英文 type 标识。
- 扫描自动排除工具配置目录（`.git`、`.butian`、`.claude`、`node_modules`、`.next`、`dist` 等），不扫自身的模板和静态资源文件。`generic_sk_key` 正则使用 `\b` 词边界，避免 CSS `mask-composite` 等误匹配。仓库安检的 GitHub Actions、供应链、IaC/容器规则全部是本地 Python 静态规则，不调用外部扫描器，也不为用户创建 CI/CD workflow。
- 依赖漏洞检查只查询本地可确认的应用依赖坐标；如果缺少精确版本、版本来自无法本地解析的间接配置，或属于 Dockerfile、compose、Kubernetes、devcontainer、镜像/SBOM、OS/发行版包、系统包、安全公告生态，则跳过漏洞查询并说明边界。
- 服务器扫描默认不安装任何工具，不要求 Trivy、Grype、Syft 或 osv-scanner；不执行系统升级、不重启服务、不修改服务器文件。仅通过 NVD/CPE、服务版本或 Docker 模糊标签推断的结果不进入报告风险项。Docker 只使用宿主机可见元数据，不进入容器、不扫描镜像内部。
- 完整项目安全扫描必须先在被扫项目的 `docs/butian/` 下生成 Markdown 审计报告；如果当前工作目录就是被扫项目，也就是当前工作目录的 `docs/butian/`。报告文件例如 `docs/butian/security-report-<run-id>.md`。用户阅读报告后明确允许修复，才可以执行升级、删除缓存跟踪、补写敏感文件忽略规则、清理历史或轮换凭证相关操作。
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

`scripts/run_audit.py` 默认扫描当前目录并自动向上识别最近的项目根目录；在 monorepo 子项目中运行时，优先使用当前子项目的 manifest/lockfile，不要跳到上层 git repo。需要扫描其他目录时，把路径作为最后一个参数传入。如果当前 shell 不在本 skill 目录，使用脚本的绝对路径，例如 `python3 /path/to/butian/scripts/run_audit.py /path/to/project`。脚本会按顺序运行预检、扫描、analysis 生成、Markdown 生成和 HTML 生成，生成后会尝试用系统默认浏览器自动打开静态 HTML 报告（仅首次扫描自动打开，复扫不会重复弹出），并在终端输出固定的人类可读摘要：`📊 风险总览`、`⚠️ 能力边界`、`🚨 重点关注`、`📁 报告路径`；其中能力边界必须使用 Markdown 引用格式 `>` 输出完整文案。人工交互扫描默认不要加 `--no-open`；只有 CI、自动化或测试需要避免弹浏览器时才使用 `--no-open`。如果输出中的模式是 `hygiene_only`，必须告诉用户：`当前项目未发现支持的应用依赖文件，暂无法执行依赖漏洞扫描；本次仅做仓库安检，检查硬编码密钥、敏感文件跟踪、.gitignore、GitHub Actions、依赖配置与维护和 IaC/容器配置风险。`

启用 Linux 服务器扫描时，用户必须明确提供 SSH 目标或离线 inventory，例如 `python3 scripts/run_audit.py --server user@example.com`、`python3 scripts/run_audit.py --server-only --server user@example.com` 或 `python3 scripts/run_audit.py --server-inventory server-inventory.json`。服务器扫描只执行白名单内的只读采集命令；`--include-docker-metadata` 也只读取宿主机可见的容器名、镜像标签和端口映射，不进入容器、不扫描镜像内部。

对话最终回复如果需要转述扫描结果，必须使用 Markdown 引用格式 `>` 展示完整能力边界，不要自行压缩成短句，也不要另起"提示"类标题。固定写法如下：

```text
⚠️ 能力边界

> 安全往往不是最显眼的需求，却是产品长期稳定运行的底线。此 Skill 会帮助你发现应用依赖漏洞、过期依赖和仓库暴露风险，帮助团队更早暴露容易被忽视的供应链问题。但依赖漏洞查询只处理本地可确认精确包名和精确版本的应用依赖坐标，不把 Dockerfile、compose、Kubernetes、devcontainer、镜像/SBOM、OS/发行版包、系统包或系统安全公告生态混入 lockfile 扫描，也不能替代代码审计、渗透测试或部署安全评估；业务逻辑、权限控制、SQL 注入、XSS 等代码层风险仍需单独复核。
```

报告生成完毕后，告诉用户：

- 报告已生成: `.butian/<timestamp>/content/security-report.html`
- Markdown 报告已生成: `docs/butian/security-report-<run-id>.md`
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

`scripts/detect.py` 默认扫描当前目录并自动向上识别最近的项目根目录；如果当前目录属于 monorepo 子项目，必须以最近的项目 manifest/lockfile 为准。需要扫描其他目录时，把路径作为最后一个参数传入。它会创建 `.butian/<timestamp>/content/` 和 `.butian/<timestamp>/assets/`，把 JSON 打印到终端，并把同一份结果保存到 `.butian/<timestamp>/assets/preflight.json`；同时确保 `.gitignore` 忽略 `.butian/` 和 `docs/butian/security-report-*.md`，并在 `butian_workspace.gitignore` 记录扫描前 `.gitignore` 是否已存在、是否本次新增工作区忽略规则。结果里的 `output_file` 是实际保存路径。先读 preflight JSON，再决定扫描模式。

如果 `language_support.supported` 为 `true`，继续执行完整流程：仓库安检 -> 依赖提取 -> 官方漏洞源检查 -> 过旧依赖检查。

如果 `language_support.supported` 为 `false`，先告诉用户：`当前项目未发现支持的应用依赖文件，暂无法执行依赖漏洞扫描；本次仅做仓库安检，检查硬编码密钥、敏感文件跟踪、.gitignore、GitHub Actions、依赖配置与维护和 IaC/容器配置风险。` 然后运行 `scan.py --preflight <preflight_json>` 生成只包含本地仓库安检结论的报告；不要调用官方漏洞源，也不要暗示已经检查过依赖漏洞。

### Step 1 扫描

读取 Step 0 的 preflight JSON 后再运行扫描。`scan.py` 会复用 `project.path`、`recommended_scan_mode` 和同一个时间戳目录；默认输出到 `.butian/<timestamp>/assets/scan.json`，输出路径由脚本写入 `output_file`，不要在命令里手写临时文件路径。

```bash
# macOS / Linux
python3 scripts/scan.py --preflight <preflight_json>
# Windows
py -3 scripts/scan.py --preflight <preflight_json>
```

`scan.py` 过旧依赖检查只运行当前项目内的包管理器或项目本地虚拟环境，不扫描系统 Python 环境。Python 项目只有发现项目内 `.venv` / `venv` / `env` 时才执行该虚拟环境的 `pip list --outdated`，否则跳过 PyPI 过期检查。脚本会自动完成：仓库安检（gitignore / 敏感文件 / 硬编码密钥）-> 生态识别与依赖提取（npm/pnpm/yarn、PyPI、Go、crates.io、Packagist、RubyGems、Pub、Hex、NuGet、Maven）-> 仅对精确包名 + 精确版本坐标直接请求 OSV、NVD、CISA KEV 和 FIRST EPSS 查漏洞（OSV 100 个包一批；NVD/EPSS 100 个 CVE 一批）-> 过旧依赖检查。如果 preflight 的 `recommended_scan_mode` 是 `hygiene_only`，脚本只做仓库安检，并跳过依赖提取、官方漏洞源和过旧依赖检查。

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

先把结论写到被扫项目的 `docs/butian/security-report-<run-id>.md`。默认用脚本从 analysis JSON 生成（仅首次扫描生成，复扫跳过）：

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

#### 待确认动作队列

依赖漏洞修复之外，报告里可能还有需要用户点头的维护动作。Agent 先把它们放入待确认动作队列，不要在依赖修复继续进行时打断用户。

目前队列只包含这三类，并在收尾时用一个多选 AskUserQuestion 统一询问，不再逐项弹出多个问题。推荐问题：`建议顺手处理下面这些维护动作，可以减少后续遗留风险。你希望现在执行哪些？` 选项按顺序展示为 `处理凭证占位符`、`创建 Dependabot 配置`、`更新过期依赖`、`取消/暂不处理`；前三项可多选，底部的 `取消/暂不处理` 是互斥选项，用户选择后不执行其他收尾动作，直接进入最终报告/结束。没有命中的动作不要展示对应选项，例如没有 Dependabot finding 就不展示 `创建 Dependabot 配置`，没有过期依赖或本轮已执行 `--strategy latest` 就不展示 `更新过期依赖`。

1. **处理凭证占位符**：如果报告中有 `疑似硬编码凭证`，尤其是 `.env.example`、`.env.sample`、`.env.template`、`.env.dist` 等模板文件命中，把 `处理凭证占位符` 放入多选 AskUserQuestion。选项说明：`建议优先确认。逐项判断疑似密钥是否只是示例值；如果是真实凭证，会先提醒轮换或撤销，再移除明文。` 用户确认后，先让用户判断是否真实可用；如只是模板占位符，替换为明显不可用的示例值；如是真实可用凭证，先轮换或撤销，再移除明文。
2. **创建 Dependabot 配置**：如果报告的 `仓库安检 / 依赖配置与维护` 中出现 `配置 Dependabot`，说明本地检测到 GitHub remote 和 GitHub Dependabot 官方支持的生态，但仓库缺少 `.github/dependabot.yml`。把 `创建 Dependabot 配置` 放入多选 AskUserQuestion。选项说明：`建议开启。Dependabot 是 GitHub 的依赖更新助手，会定期检查依赖新版本，并自动提交更新 PR，方便后续持续维护依赖安全。` 用户确认后才运行：

```bash
python3 scripts/fix.py .butian/<timestamp>/assets/analysis.json --strategy dependabot
```

该策略只创建 `.github/dependabot.yml`，不会覆盖已有文件；推送到 GitHub 后 Dependabot 才会按 schedule 创建版本更新 PR。
3. **更新过期依赖**：如果 analysis 或 HTML 报告中 `outdated` / `过期依赖` 数量大于 0，且本轮尚未执行过 `--strategy latest`，把 `更新过期依赖` 放入多选 AskUserQuestion。选项说明：`建议按维护窗口处理。升级过期依赖属于版本维护动作，不等同于修复已确认风险，可能带来兼容性变化，升级后需要验证。` 用户确认后运行：

```bash
python3 scripts/fix.py .butian/<timestamp>/assets/analysis.json --strategy latest
```

该策略是版本维护动作，会按包管理器能力把可解析依赖升级到 latest，不等同于已确认漏洞修复；执行前必须提醒可能带来兼容性变化，执行后需要重新运行 `python3 scripts/run_audit.py` 复扫。

触发时机：

- 用户选择 `开始修复`、`升级到修复版本`、`全部升级到最新版`、`继续处理`（升级父依赖并重新扫描）或 `强制覆盖` 时，继续原本修复流程，不弹出待确认动作队列。
- 用户选择 `先不修复`、`暂不处理`、`暂不验证`，或依赖修复流程准备生成最终报告前，如果待确认动作队列非空，必须先用一个多选 AskUserQuestion 询问上面三类动作；用户处理所选动作或选择 `取消/暂不处理` 后，再生成最终报告/结束。
- 如果用户已经选择 `全部升级到最新版` 或已运行 `fix.py --strategy latest`，视为已经处理过期依赖维护，不再重复弹出 `更新过期依赖`。
- 典型场景：提示残留风险来自父依赖锁定的嵌套旧版本时，如果用户选择 `继续处理`（升级父依赖并重新扫描），正常执行 parent-upgrade，不弹出待确认动作队列；如果用户选择 `暂不处理`，先弹出包含硬编码凭证占位符、创建 Dependabot 配置和更新过期依赖的多选 AskUserQuestion，然后再进入最终报告。

#### 第一轮：顶层依赖升级

1. **是否修复**：用 AskUserQuestion 提供 `开始修复` / `先不修复`。提问时用"风险项"替代"依赖漏洞"，格式如"建议优先处理本次发现的已确认风险项，避免已知依赖问题继续留在项目里。现在开始修复吗？"。选项说明：`开始修复` = `按推荐流程升级受影响依赖，完成后会重新扫描确认风险项是否已清除。`；`先不修复` = `暂时不修改项目依赖，只保留本次报告，后续可以再根据报告处理。` 用户选择先不修复时，停止依赖修复；如待确认动作队列非空，先弹出收尾多选问题，再总结报告路径和主要风险。
2. **修复方式**：用户确认修复后，用 AskUserQuestion 提供 `升级到修复版本` / `全部升级到最新版`。提问时写"建议优先选择改动较小的修复方式。你希望怎么升级这些有风险的依赖？"
   - **升级到修复版本**：推荐。只把有风险的依赖升级到已知修复版本，改动较小，通常更适合先处理安全风险。
   - **全部升级到最新版**：更彻底，但可能跨较多版本，兼容性变化更大；适合有维护窗口并准备做完整测试时选择。
3. **执行升级**：用户选择策略后，运行修复脚本：

```bash
# 升级到已修复版本
python3 scripts/fix.py .butian/<timestamp>/assets/analysis.json --strategy fixed

# 升级到最新版本
python3 scripts/fix.py .butian/<timestamp>/assets/analysis.json --strategy latest
```

4. **复扫验证**：升级完成后，重新运行 `python3 scripts/run_audit.py` 复扫并生成新的 HTML/analysis。复扫不会重复弹出浏览器（仅首次扫描自动打开）；Markdown 仍按首次报告或最终报告规则生成。如果此轮修复后无残留，进入最终报告步骤；如果有残留，继续下一轮。

#### 第二轮：处理残留（复扫后仍有残留时）

复扫后如果仍有同名依赖漏洞残留，说明是父依赖锁定了嵌套旧版本。报告会标注父依赖声明的版本范围，帮助理解残留原因。

5. **向用户说明**：顶层依赖已升级成功；残留项来自父依赖锁定的嵌套旧版本；报告中已标注每个残留的父依赖信息。
6. **是否继续**：用 AskUserQuestion 提供 `继续处理` / `暂不处理`。提问时写"顶层依赖已升级成功，但仍有部分风险项来自嵌套依赖。建议继续尝试升级它们的父依赖，并重新扫描确认结果。" 选项说明：`继续处理` = `尝试升级锁定这些嵌套依赖的父依赖，然后重新扫描，看看残留风险是否可以清除。`；`暂不处理` = `不继续改依赖；报告会保留残留项和原因，后续可以人工评估或等待上游依赖更新。` 用户选择 `继续处理` 时，正常继续下一步，不弹出待确认动作队列。用户选择暂不处理时，先处理待确认动作队列，再生成最终报告并结束。
7. **执行升级**：用户选择继续后，运行：

```bash
python3 scripts/fix.py .butian/<timestamp>/assets/analysis.json --strategy parent-upgrade
```

脚本会自动：升级父依赖到最新 → 升级有漏洞的子依赖到修复版本。无法追溯到 `package.json` 根依赖的残留会标注出来，需要等待上游修复或人工评估。

8. **重新扫描并展示结果**：升级完成后，重新运行 `python3 scripts/run_audit.py` 重新扫描并刷新 HTML/analysis。如果此轮修复后无残留，进入最终报告步骤；如果有残留，继续下一轮。

#### 第三轮：强制覆盖残留依赖（第二轮后仍有残留时）

第二轮 `parent-upgrade` 后如果仍有残留（无法追溯到 `package.json` 根依赖的间接依赖），可通过 npm `overrides` 强制覆盖所有嵌套实例。

9. **向用户说明**：第二轮升级后仍有残留，这些依赖无法追溯到根依赖；可通过在 `package.json` 中写入 `overrides` 强制所有嵌套实例升级到修复版本。
10. **是否继续**：用 AskUserQuestion 提供 `强制覆盖` / `暂不处理`。提问时写"仍有少量嵌套依赖无法通过普通升级处理。建议仅在你接受兼容性验证成本时，再使用 overrides 强制指定安全版本。" 选项说明：`强制覆盖` = `在 package.json 中写入 overrides，让嵌套依赖也使用指定的安全版本；完成后需要重新安装依赖并验证项目。`；`暂不处理` = `不写入 overrides；保留报告结果，后续再结合项目兼容性和上游依赖情况评估。` 用户选择 `强制覆盖` 时，正常继续下一步，不弹出待确认动作队列。用户选择暂不处理时，先处理待确认动作队列，再生成最终报告并结束。
11. **执行覆盖**：用户选择继续后，运行：

```bash
python3 scripts/fix.py .butian/<timestamp>/assets/analysis.json --strategy force-residual
```

脚本会自动：读取 analysis.json 中残留的可修复项 → 在 `package.json` 的 `overrides` 字段中添加版本强制约束 → 运行 `npm install` 使 overrides 生效。

12. **重新扫描并展示结果**：覆盖完成后，重新运行 `python3 scripts/run_audit.py` 重新扫描并刷新 HTML/analysis。进入最终报告步骤。

#### 最终报告

所有修复轮次结束后（无论哪一轮结束），用 `--final-report` 生成最终 Markdown 审计报告：

```bash
python3 scripts/run_audit.py --final-report
```

终端摘要会以 `📁 最终报告路径` 标注最终 Markdown。

#### Step 6 修复后验证

最终报告生成后，用 AskUserQuestion 询问用户是否运行项目构建验证，提供 `运行验证` / `暂不验证`。提问时写"修复已经完成。建议现在运行项目构建或测试，确认升级后项目还能正常工作。" 选项说明：`运行验证` = `根据项目类型执行构建或测试命令，检查依赖升级后是否出现兼容性问题。`；`暂不验证` = `不运行构建或测试；报告会保留修复结果，但上线或提交前仍建议自行验证。` 用户选择运行后，根据项目生态自动执行对应的构建/测试命令：

- **npm/pnpm/yarn**：`npm run build`、`npm run dev`
- **Python (pip)**：`pip install -e . && python -m pytest`
- **Python (uv)**：`uv sync && uv run pytest`
- **Python (poetry)**：`poetry install && poetry run pytest`
- **Python (pipenv)**：`pipenv install --dev && pipenv run pytest`
- **Go**：`go build ./...`、`go test ./...`
- **Rust**：`cargo build`、`cargo test`

如果构建或启动报错，帮助用户分析错误并尝试修复（如版本冲突、缺失依赖等），修复后重新验证直到通过。用户选择暂不验证时，仅提醒后续自行验证即可结束。

#### 三轮后仍有残留

如果三轮升级后仍有残留（极少见），说明可能是非 npm 生态或特殊依赖结构，需要人工评估。告知用户当前状态并结束。

## 修复建议规则

- 密钥泄露：先撤销或轮换密钥，再删除代码中的明文；如果进入 git 历史，需单独确认后再用 BFG Repo Cleaner 等工具清理。
- 确认受影响的依赖：升级到修复版本，然后运行测试和构建。提醒兼容性风险。
- 恶意包：立即移除，检查 CI 环境凭证并轮换。
- 版本不明确：说明只命中包名，需要 lockfile 才能确认。
- 依赖过旧：建议纳入版本维护计划，结合版本跨度、兼容性和发布窗口分批处理。

## 依赖与运行前提

- 全部脚本是 Python 3 标准库，零第三方依赖（不用 pip install）。
- 最低 Python 3.8；Python 3.11+ 可使用内置 `tomllib` 解析 TOML lockfile，3.8–3.10 自动回退到正则提取（覆盖绝大多数 lockfile 格式）。
- macOS/Linux 自带 python3；Windows 需先装 Python 3，并使用 `py -3` 执行上述 Windows 示例。
- 依赖扫描支持：JavaScript/TypeScript（`package-lock.json` / `pnpm-lock.yaml` / `yarn.lock`）、Python（`poetry.lock` / `uv.lock` / `Pipfile.lock` / `requirements.txt`）、Go（`go.sum`）、Rust（`Cargo.lock`）、PHP / Packagist（`composer.lock`）、Ruby / RubyGems（`Gemfile.lock`）、Dart / Flutter Pub（`pubspec.lock`）、Elixir / Erlang Hex（`mix.lock`）、.NET / NuGet（`packages.lock.json` / `packages.config`）、Maven/JVM（`pom.xml` 中直接写明版本的依赖）。`requirements.txt` 只用 `==` / `===` 精确版本做漏洞匹配；支持 `-r` 文件包含和行续行符。所有生态都只查询能从本地文件提取出精确包名 + 精确版本的应用依赖坐标；Maven/JVM 第一版遇到 `${...}` 属性、父 POM、BOM、profile 或版本范围无法本地确认时跳过。

## CLI 参数参考

### run_audit.py

| 参数                     | 说明                             |
| ------------------------ | -------------------------------- |
| `--no-open`              | 不自动打开 HTML 报告             |
| `--no-root-discovery`    | 使用传入路径本身，不向上寻找项目根 |
| `--final-report`         | 最终复扫时强制生成 Markdown 报告 |
| `--verbose`              | 输出详细日志到 stderr            |
| `--debug`                | 输出调试级别日志                 |
| `--follow-symlinks`      | 跟随符号链接扫描（默认跳过）     |
| `--skip-outdated`        | 跳过过期依赖检查                 |
| `--skip-hygiene`         | 跳过仓库安检                     |
| `--include-packages`     | 在输出中包含完整包列表           |
| `--max-secret-files <n>` | 密钥扫描最大文件数               |

## 日志与缓存

- 日志文件：`.butian/<timestamp>/logs/scan.log`
- 本地缓存：`.butian/cache/`（跨 run 共享，默认 24 小时过期）
