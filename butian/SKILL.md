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

本地安全扫描 Skill。默认面向代码项目，生成 Markdown 审计报告和只读 HTML 报告，帮助非安全背景读者理解依赖漏洞、硬编码凭证、敏感文件跟踪、`.gitignore`、GitHub Actions、依赖维护和 IaC/容器本地配置风险。

服务器扫描是另一个显式能力：只有用户明确要求 Linux 服务器安全扫描，并提供 SSH 目标或离线 inventory 时才启用。服务器扫描只生成 Markdown 报告，不生成 HTML 展示页。

## 新手快速路径

1. **第一次项目扫描报告**：在目标项目目录中，让 Agent 调用补天脚本；手动运行时使用脚本绝对路径，例如 `python3 /path/to/butian/scripts/run_audit.py /path/to/project`。项目扫描会生成 `.butian/<run-id>/content/security-report.html` 和 `docs/butian/security-report-<run-id>.md`，并尝试自动打开 HTML。先让用户看报告，再问是否修复。
2. **修复前先确认**：用户明确选择开始修复后，才运行 `fix.py` 或包管理器命令。默认优先升级到已知修复版本；升级到 latest、Dependabot、凭证占位符替换、过期依赖维护都需要用户点头。
3. **修复完成后的最终报告**：修复和复扫结束后运行 `python3 /path/to/butian/scripts/run_audit.py --final-report /path/to/project`。项目最终复扫会再次生成 HTML 和 Markdown，并尝试打开最终 HTML；如果用户显式传了 `--no-open`，仍尊重不打开。
4. **默认只处理项目**：不要加 `--server`、`--server-only` 或 `--server-inventory`，除非用户明确要求服务器扫描。普通项目扫描不扫描系统 Python、全局 npm、全局 pnpm 或操作系统包，也不会碰系统升级、系统服务、数据库或日志。

## 什么时候读哪个 reference

- 项目的安全扫描、报告契约、数据源边界、修复交互和 AskUserQuestion：读 `references/project-scan.md`。
- Linux 服务器安全扫描、只读 SSH、服务器维护建议和 Markdown 报告契约：只有用户明确要求服务器扫描时，读 `references/server-scan.md`。

## 铁律

- **扫描阶段不改业务源码和依赖。** 项目扫描对业务代码和依赖只读；它会创建/更新 `.butian/` 本地报告工作区、缓存、`docs/butian/security-report-*.md`，以及必要的报告忽略规则，并会确保 `.gitignore` 忽略 `.butian/` 和生成的安全报告文件。
- **默认是项目扫描。** 不主动扫描系统目录、用户主目录、系统 Python、全局 npm、全局 pnpm、操作系统包、系统服务、数据库或日志。
- **服务器扫描必须由用户明确要求。** 只有用户提供 `--server`、`--server-only --server` 或 `--server-inventory` 时，才进入服务器运行环境扫描。
- **修复必须先问用户。** 项目报告生成后，先用 AskUserQuestion 询问是否修复；升级方式、Dependabot、凭证占位符和过期依赖维护都需要确认。收尾维护动作使用多选 AskUserQuestion 统一确认。
- **风险项和建议分开呈现。** 已确认风险、仓库安检、过期依赖、服务器维护建议不能混成一种风险。
- **不制造恐慌。** 没有证据时说“不确定”；任何跳过、API 失败或采集失败都必须保留为不完整检查。

## 默认项目流程

Agent 优先直接调用本 skill 里的 `run_audit.py`。如果用户手动运行，先确认 shell 位于本 skill 目录；否则使用脚本绝对路径。

```bash
# 在本 skill 目录中
python3 scripts/run_audit.py /path/to/project

# 不在本 skill 目录中
python3 /path/to/butian/scripts/run_audit.py /path/to/project
```

流水线顺序是：

1. `detect.py`：识别项目根、依赖生态和扫描模式。
2. `scan.py`：执行仓库安检、依赖解析、官方漏洞源查询和过期依赖检查。
3. `analyze.py`：生成确定性 `analysis.json`。
4. `report.py`：生成 Markdown 审计报告。
5. `visualize.py`：项目扫描生成自包含 HTML 报告并按打开策略尝试打开。

如果输出模式是 `hygiene_only`，必须告诉用户：

```text
当前项目未发现支持的应用依赖文件，暂无法执行依赖漏洞扫描；本次仅做仓库安检，检查硬编码密钥、敏感文件跟踪、.gitignore、GitHub Actions、依赖配置与维护和 IaC/容器配置风险。
```

完整项目规则见 `references/project-scan.md`。

## 能力边界

对话最终回复如果需要转述扫描结果，必须使用 Markdown 引用格式 `>` 展示完整能力边界，不要自行压缩成短句，也不要另起“提示”类标题。

固定写法：

```text
⚠️ 能力边界

> 安全往往不是最显眼的需求，却是产品长期稳定运行的底线。此 Skill 会帮助你发现应用依赖漏洞、过期依赖和仓库暴露风险，帮助团队更早暴露容易被忽视的供应链问题。但依赖漏洞查询只处理本地可确认精确包名和精确版本的应用依赖坐标，不把 Dockerfile、compose、Kubernetes、devcontainer、镜像/SBOM、OS/发行版包、系统包或系统安全公告生态混入 lockfile 扫描，也不能替代代码审计、渗透测试或部署安全评估；业务逻辑、权限控制、SQL 注入、XSS 等代码层风险仍需单独复核。
```

## 服务器扫描入口

服务器扫描只在用户明确要求时使用：

```bash
python3 scripts/run_audit.py --server user@example.com /path/to/project
python3 scripts/run_audit.py --server-only --server user@example.com /path/to/project
python3 scripts/run_audit.py --server-inventory server-inventory.json /path/to/project
```

服务器扫描只做只读 SSH 或离线 inventory 分析，不使用 `sudo`，不修改配置，不重启服务，不安装工具，不读取业务数据库和日志。详细规则见 `references/server-scan.md`。

## 分步调试入口

默认使用 `run_audit.py`。只有流水线失败或需要调试时，才分步运行：

```bash
python3 scripts/detect.py
python3 scripts/scan.py --preflight .butian/<run-id>/assets/preflight.json
python3 scripts/analyze.py .butian/<run-id>/assets/scan.json
python3 scripts/report.py .butian/<run-id>/assets/analysis.json
python3 scripts/visualize.py .butian/<run-id>/assets/analysis.json
```

各脚本参数以 `python3 scripts/<script>.py --help` 为准；维护项目扫描、报告或修复流程前先读 `references/project-scan.md`，维护服务器扫描前先读 `references/server-scan.md`。
