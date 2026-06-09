---
name: butian
description: |
  补天：为本地代码仓库补上安全裂缝，围绕依赖漏洞、过期依赖、硬编码凭证、敏感文件误提交、仓库忽略规则、供应链与 IaC/容器配置做只读审计。
  输出以简体中文为主，优先生成能给团队阅读和跟进的 Markdown/HTML 安全报告。
  触发词：「帮我看看项目有没有安全问题」「安全扫描」「扫一下项目」「依赖有没有漏洞」「硬编码密钥」「gitignore 是否合理」「漏洞检查」「供应链安全」。
---

# 补天

本地安全扫描 Skill。默认面向代码项目，生成 Markdown 审计报告和只读 HTML 报告，帮助非安全背景读者理解依赖漏洞、硬编码凭证、敏感文件跟踪、`.gitignore`、GitHub Actions、依赖维护和 IaC/容器本地配置风险。

服务器扫描是独立的可选能力，用于检查显式提供的 SSH 目标或离线 inventory 对应的 Linux 运行环境。推荐使用本机 `.ssh/config` Host 别名，也允许直接传 `user@ip`；无论哪种方式都必须使用密钥登录，采集命令会禁用密码和键盘交互回退。`--server-only` 只生成 Markdown 报告，项目 + 服务器混合扫描可以在项目 HTML 的“服务器运行环境”章节展示服务器内容。

## 默认执行规则

1. **第一次扫描报告**：在目标项目目录中运行 `run_audit.py` 完成首次扫描。项目扫描会生成 `.butian/<run-id>/content/security-report.html` 和 `docs/butian/security-report-<run-id>.md`，并尝试自动打开 HTML。先展示报告，再询问是否修复。
2. **修复前先确认**：确认开始修复后，才运行 `fix.py` 或包管理器命令。默认优先升级到已知修复版本；升级到 latest、Dependabot、凭证占位符替换、过期依赖维护都需要确认。
3. **修复完成后的最终报告**：修复和复扫结束后，运行 `run_audit.py --final-report`。项目最终复扫会再次生成 HTML 和 Markdown，并尝试打开最终 HTML；如果传入了 `--no-open`，仍尊重不打开。
4. **默认只处理项目**：默认不加 `--server`、`--server-only` 或 `--server-inventory`。普通项目扫描不扫描系统 Python、全局 npm、全局 pnpm 或操作系统包，也不会碰系统升级、系统服务、数据库或日志；提供 SSH 目标或离线 inventory 时，服务器扫描按独立流程处理。

## 详细参考

- 项目的安全扫描、报告契约、数据源边界、修复交互和 AskUserQuestion：`references/project-scan.md`。
- Linux 服务器安全扫描、密钥登录、只读 SSH、服务器维护建议和报告契约：`references/server-scan.md`。

## 铁律

- **扫描阶段不改业务内容。** 项目扫描不会修改业务源码、依赖、数据库或日志；它会创建/更新 `.butian/` 本地报告工作区、缓存、`docs/butian/security-report-*.md`，以及必要的报告忽略规则，并会确保 `.gitignore` 忽略 `.butian/` 和生成的安全报告文件。
- **报告证据必须脱敏。** 普通密钥只展示脱敏预览，模板文件也只展示脱敏命中值；脱敏不要过度，尽量保留足够上下文让新手能找到对应位置。
- **默认是项目扫描。** 不主动扫描系统目录、用户主目录、系统 Python、全局 npm、全局 pnpm、操作系统包、系统服务、数据库或日志。
- **服务器扫描需要明确的扫描来源。** 只有提供 `--server <ssh_target>`、`--server-only --server <ssh_target>` 或 `--server-inventory` 时，才进入服务器运行环境扫描。`--server` 可以是 SSH config Host 别名，也可以是 `user@ip`；必须确保密钥登录可用，脚本会禁用密码和键盘交互回退。
- **修复必须先问用户。** 项目报告生成后，先用 AskUserQuestion 询问是否修复；升级方式、Dependabot、凭证占位符和过期依赖维护都需要确认。收尾维护动作使用多选 AskUserQuestion 统一确认。
- **风险项和建议分开呈现。** 已确认风险、仓库安检、过期依赖、服务器维护建议不能混成一种风险。
- **不制造恐慌。** 没有证据时说“不确定”；任何跳过、API 失败或采集失败都必须保留为不完整检查。

## 默认项目流程

默认通过本 skill 里的 `run_audit.py` 完成项目扫描，并按当前操作系统选择 Python 启动器。实际执行时可以使用脚本绝对路径，避免依赖 shell 当前目录。

```bash
# macOS / Linux
python3 scripts/run_audit.py <project_path>

# Windows
py -3 scripts/run_audit.py <project_path>
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

> 安全往往不是最显眼的需求，却是产品长期稳定运行的底线。此报告基于本地可确认的依赖和仓库证据，帮助你发现应用依赖漏洞、过期依赖和仓库暴露风险，并把可处理的问题整理成清晰的修复线索。它不能替代代码审计、渗透测试或完整安全评估；业务逻辑、权限控制、输入校验、SQL 注入、XSS 等代码层风险仍需结合业务场景复核。安全的价值不只在于发现问题，更在于让团队知道风险在哪里、先处理什么，以及如何让每一次修复都成为系统可靠性的积累。
```
