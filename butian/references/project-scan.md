# 项目的安全扫描

本文件是默认项目扫描的完整参考。项目扫描负责检查仓库和应用依赖，并生成 Markdown + HTML 报告；修复交互和 AskUserQuestion 契约也放在这里，避免读者在多个文件之间来回跳转。

## 默认范围

项目扫描只处理当前项目目录内可确认的代码和依赖文件。默认不扫描系统 Python、全局 npm、全局 pnpm、操作系统包、系统服务、数据库或日志，也不会执行系统升级、系统重启或服务重启。

扫描阶段允许写入的本地产物只有：

- `.butian/<run-id>/assets/*.json`
- `.butian/<run-id>/content/security-report.html`
- `.butian/<run-id>/logs/scan.log`
- `.butian/cache/`
- `docs/butian/security-report-<run-id>.md`
- `.gitignore` 中用于忽略 `.butian/` 和 `docs/butian/security-report-*.md` 的规则

敏感文件相关 `.gitignore` 修复、Dependabot 配置、依赖升级、凭证替换、历史清理都属于修复阶段，必须用户确认。

## 支持的应用依赖生态

- JavaScript / TypeScript：`package-lock.json`、`pnpm-lock.yaml`、`yarn.lock`
- Python：`poetry.lock`、`uv.lock`、`Pipfile.lock`、`requirements.txt`
- Go：`go.sum`
- Rust：`Cargo.lock`
- PHP / Packagist：`composer.lock`
- Ruby / RubyGems：`Gemfile.lock`
- Dart / Flutter Pub：`pubspec.lock`
- Elixir / Erlang Hex：`mix.lock`
- .NET / NuGet：`packages.lock.json`、`packages.config`
- Maven/JVM：`pom.xml` 中直接写明版本的依赖

依赖漏洞查询只处理能从本地文件提取出精确包名和精确版本的应用依赖坐标。Maven/JVM 第一版只解析本地 `pom.xml` 中直接写明版本的依赖；`${...}` 属性、父 POM、BOM、profile 或版本范围无法本地确认时跳过。

## 扫描内容

- **依赖漏洞**：按本地 lockfile / manifest 提取包坐标，请求 OSV，并用 NVD、CISA KEV、FIRST EPSS 富化 CVE 信息。
- **硬编码密钥**：正则和 entropy 组合检测，报告只展示脱敏预览和代码上下文。
- **敏感文件误提交**：检查 `.env`、私钥、证书、数据库导出等是否被 git 跟踪。
- **`.gitignore` 覆盖**：检查项目是否忽略本地报告工作区和常见敏感文件。
- **GitHub Actions**：本地静态检查过宽权限、危险触发器、脚本注入、远程脚本管道执行等。
- **依赖配置与维护**：检查 lockfile 缺失、可疑安装脚本、registry 配置和 Dependabot 建议。
- **IaC / 容器配置**：本地检查 Dockerfile、Compose、Kubernetes、Terraform 常见配置风险。
- **过期依赖**：默认不扫描系统包和全局包，也不执行项目本地虚拟环境；只有显式传入 `--allow-project-exec` 时，才允许过期检查执行 `.venv/bin/python` 等项目内工具。

## 数据源、缓存和错误处理

官方数据源：

- OSV：按包坐标查询开源依赖漏洞。
- NVD：在 OSV 返回 CVE 后补充 CVSS、CWE、发布时间等 CVE 详情。
- CISA KEV：在 OSV 返回 CVE 后补充“是否已知被利用”信号。
- FIRST EPSS：在 OSV 返回 CVE 后补充利用概率和百分位。

发送到外部服务的最小必要字段只有 `ecosystem`、`name`、`version` 和 CVE 编号。不要上传源码、lockfile、`.env`、私钥、证书、数据库、日志或任意项目文件。

缓存位于 `.butian/cache/`，跨 run 共享，默认 24 小时过期。缓存只保存漏洞源响应和元数据，不保存源码或密钥。

任何官方漏洞源失败、API 限流、包管理器失败、Git 检查失败或扫描文件上限截断，都必须进入 `errors` 或 coverage 信息。报告不能把失败解释成“0 风险”。

## 不覆盖范围

项目扫描不能替代：

- 代码审计
- 渗透测试
- GitHub 远端设置审计
- 云账号权限审计
- 部署安全评估
- 业务逻辑、权限控制、SQL 注入、XSS 等代码层风险审查

应用依赖漏洞扫描不包含：

- Dockerfile / compose / Kubernetes / devcontainer 的镜像漏洞扫描
- 镜像 SBOM 或镜像 layer 扫描
- OS/发行版包漏洞扫描
- 系统安全公告生态
- 系统 Python、全局 npm、全局 pnpm

IaC/容器本地规则属于仓库安检，只能发现配置层明显缺口，不等于镜像漏洞扫描、SBOM 扫描或服务器漏洞扫描。

## hygiene_only 模式

如果项目没有支持的应用依赖文件，`run_audit.py` 会进入 `hygiene_only`。此时不要调用官方漏洞源，也不要暗示已经检查过依赖漏洞。必须对用户说明：

```text
当前项目未发现支持的应用依赖文件，暂无法执行依赖漏洞扫描；本次仅做仓库安检，检查硬编码密钥、敏感文件跟踪、.gitignore、GitHub Actions、依赖配置与维护和 IaC/容器配置风险。
```

## 项目报告契约

`analyze.py` 会生成确定性 `analysis.json`：漏洞排序、`risk_summary`、`summary`、`red/yellow/green`、仓库安检项、过期依赖和扫描错误。后续只允许做轻量复核和业务语言润色；不要删除已确认风险项，不要把过期依赖改写成漏洞，不要把脱敏预览扩展成完整密钥。

- 当前风险：所有风险项按影响程度排序，全部放入 `top_issues`，不要只放前 5 个。必须透传 `advisory_id`、`aliases`、`cve_id`、`package`、`version`、`severity`、`summary`、`fixed_versions` 等字段。
- 仓库安检：透传 `hygiene.gitignore_missing`、`hygiene.tracked_secrets`、`hygiene.sensitive_tracked`、`hygiene.workflow_checks`、`hygiene.repository_checks`、`hygiene.iac_checks`、`hygiene.coverage`。密钥内容必须脱敏，只写位置、类型、可信度和预览。
- 过期依赖：透传 `outdated`。它是版本维护优化项，不是已确认漏洞。
- 风险项分级：`red` 放需优先处理或专业处理的事项；`yellow` 放需业务/部署确认的事项；`green` 可保留给后续修复计划，但网页不再单独展示低风险维护区块。
- 每一项都必须设置 `severity`：`critical`、`high`、`medium`、`low`、`info` 之一。
- 必须构建 `risk_summary`：`{ "critical": N, "high": N, "medium": N, "low": N, "info": N }`。
- 必须构建 `summary.tldr`、`summary.detail`、`summary.priority`。报告面向偏产品经理、项目负责人和非安全背景读者，少用术语，讲清楚“是否影响发布”“是否需要马上安排”“需要研发/运维确认什么”。
- 必须透传 scan.py 输出中的 `generated_at` 和 `scan_seconds`，它们用于计算全流程耗时。

Markdown 报告按以下顺序组织：报告总结、当前风险、仓库安检、过期依赖、覆盖说明、扫描错误、下一步建议。服务器运行环境暂不放入 Markdown 报告。

项目 HTML 报告阅读流：项目概览、报告总结、服务器运行环境、仓库安检、当前风险、过期依赖、优先处理、待确认事项、扫描错误。静态 HTML 文件路径为 `.butian/<timestamp>/content/security-report.html`。

当前风险和过期依赖都默认展示 7 条，数量更多时用只读展开/收起按钮查看剩余全部条目；表格列宽必须稳定，修复版本列不能挤压或覆盖安全编号列。

## AskUserQuestion 修复交互

这里的 AskUserQuestion 选项和触发时机是核心行为，整理文档或拆分代码时不能删减。

总原则：

- 扫描脚本只生成报告，不自动修复。
- 展示 HTML / Markdown 报告后，再询问是否开始修复。
- 如果当前环境支持 AskUserQuestion，必须使用 AskUserQuestion。
- 如果当前环境不支持 AskUserQuestion，用普通对话提问，但选项、顺序和触发时机保持一致。
- 任何依赖升级、Dependabot 创建、硬编码凭证占位符处理、过期依赖维护都必须用户确认。

### 第一轮：是否修复

如果存在可修复依赖风险，用 AskUserQuestion 提供：

- `开始修复`
- `先不修复`

提问文案：

```text
建议优先处理本次发现的已确认风险项，避免已知依赖问题继续留在项目里。现在开始修复吗？
```

`开始修复` 说明：按推荐流程升级受影响依赖，完成后会重新扫描确认风险项是否已清除。

`先不修复` 说明：暂时不修改项目依赖，只保留本次报告，后续可以再根据报告处理。

### 第二轮：修复方式

用户选择 `开始修复` 后，用 AskUserQuestion 提供：

- `升级到修复版本`
- `全部升级到最新版`

提问文案：

```text
建议优先选择改动较小的修复方式。你希望怎么升级这些有风险的依赖？
```

`升级到修复版本` 是推荐选项：只把有风险的依赖升级到已知修复版本，改动较小。

`全部升级到最新版` 更彻底，但可能跨较多版本，兼容性变化更大。

### 待确认动作队列

依赖漏洞修复之外，报告里可能还有需要确认的维护动作。先把它们放入待确认动作队列，不要在依赖修复继续进行时打断当前流程。

目前队列包含：

- `处理凭证占位符`
- `创建 Dependabot 配置`
- `更新过期依赖`
- `取消/暂不处理`

推荐使用多选 AskUserQuestion。提问文案：

```text
建议顺手处理下面这些维护动作，可以减少后续遗留风险。你希望现在执行哪些？
```

底部的 `取消/暂不处理` 是互斥选项。用户选择后不执行其他收尾动作，直接进入最终报告或结束。

如果报告中有 `疑似硬编码凭证`，尤其是 `.env.example`、`.env.sample`、`.env.template`、`.env.dist` 等模板文件命中，把 `处理凭证占位符` 放入多选 AskUserQuestion。

如果报告的 `仓库安检 / 依赖配置与维护` 中出现 `配置 Dependabot`，说明本地检测到 GitHub remote 和 GitHub Dependabot 官方支持的生态，但仓库缺少 `.github/dependabot.yml`。把 `创建 Dependabot 配置` 放入多选 AskUserQuestion。选项说明必须包含：

```text
建议开启。Dependabot 是 GitHub 的依赖更新助手，会定期检查依赖新版本，并自动提交更新 PR，方便后续持续维护依赖安全。
```

如果 analysis 或 HTML 报告中 `outdated` / `过期依赖` 数量大于 0，且本轮尚未执行过 `--strategy latest`，把 `更新过期依赖` 放入多选 AskUserQuestion。选项说明必须说明：升级过期依赖属于版本维护动作，不等同于修复已确认风险，可能带来兼容性变化，升级后需要验证。

触发时机：

- 用户选择 `开始修复`、`升级到修复版本`、`全部升级到最新版`、`继续处理`（升级父依赖并重新扫描）或 `强制覆盖` 时，继续原本修复流程，不弹出待确认动作队列。
- 用户选择 `先不修复`、`暂不处理`、`暂不验证`，或依赖修复流程准备生成最终报告前，如果待确认动作队列非空，必须先用一个多选 AskUserQuestion 询问上面三类动作；用户选择暂不处理、处理所选动作或选择 `取消/暂不处理` 后，再生成最终报告或结束。
- 如果用户已经选择 `全部升级到最新版` 或已运行 `fix.py --strategy latest`，视为已经处理过期依赖维护，不再重复弹出 `更新过期依赖`。

不要回退到旧式逐项弹窗；收尾维护动作统一进入一个多选问题。

### 嵌套残留：继续处理

顶层依赖升级后，如果复扫仍有同名依赖漏洞残留，说明通常是父依赖锁定了嵌套旧版本。此时用 AskUserQuestion 提供：

- `继续处理`
- `暂不处理`

提问文案：

```text
顶层依赖已升级成功，但仍有部分风险项来自嵌套依赖。建议继续尝试升级它们的父依赖，并重新扫描确认结果。
```

用户选择 `继续处理` 后运行：

```bash
python3 scripts/fix.py .butian/<timestamp>/assets/analysis.json --strategy parent-upgrade
```

### 强制覆盖残留依赖

第二轮 `parent-upgrade` 后如果仍有残留，且无法追溯到 `package.json` 根依赖，可询问：

- `强制覆盖`
- `暂不处理`

提问文案：

```text
仍有少量嵌套依赖无法通过普通升级处理。建议仅在你接受兼容性验证成本时，再使用 overrides 强制指定安全版本。
```

用户选择 `强制覆盖` 后运行：

```bash
python3 scripts/fix.py .butian/<timestamp>/assets/analysis.json --strategy force-residual
```

### 最终报告和验证

所有修复轮次结束后运行：

```bash
python3 scripts/run_audit.py --final-report
```

`--final-report` 会重新生成项目 HTML 和 Markdown，并尝试打开最终 HTML；只有用户显式传 `--no-open` 时才跳过自动打开。

最终报告生成后，用 AskUserQuestion 询问用户是否运行项目构建验证：

- `运行验证`
- `暂不验证`

提问文案：

```text
修复已经完成。建议现在运行项目构建或测试，确认升级后项目还能正常工作。
```

## 分步调试入口

默认使用：

```bash
# macOS / Linux
python3 scripts/run_audit.py

# Windows
py -3 scripts/run_audit.py
```

调试时再分步运行：

```bash
# macOS / Linux
python3 scripts/detect.py
python3 scripts/scan.py --preflight .butian/<run-id>/assets/preflight.json
python3 scripts/analyze.py .butian/<run-id>/assets/scan.json
python3 scripts/report.py .butian/<run-id>/assets/analysis.json
python3 scripts/visualize.py .butian/<run-id>/assets/analysis.json

# Windows
py -3 scripts/detect.py
py -3 scripts/scan.py --preflight .butian/<run-id>/assets/preflight.json
py -3 scripts/analyze.py .butian/<run-id>/assets/scan.json
py -3 scripts/report.py .butian/<run-id>/assets/analysis.json
py -3 scripts/visualize.py .butian/<run-id>/assets/analysis.json
```
