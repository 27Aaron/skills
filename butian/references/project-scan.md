# 项目扫描参考

本文件保存默认项目扫描的详细规则。普通使用优先读 `SKILL.md`；只有需要解释扫描范围、调试分步流程或确认边界时才读这里。

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
- **过期依赖**：只运行项目内包管理器或项目本地虚拟环境，不扫描系统包和全局包。

## hygiene_only 模式

如果项目没有支持的应用依赖文件，`run_audit.py` 会进入 `hygiene_only`。此时不要调用官方漏洞源，也不要暗示已经检查过依赖漏洞。必须对用户说明：

```text
当前项目未发现支持的应用依赖文件，暂无法执行依赖漏洞扫描；本次仅做仓库安检，检查硬编码密钥、敏感文件跟踪、.gitignore、GitHub Actions、依赖配置与维护和 IaC/容器配置风险。
```

## 分步流程

默认使用：

```bash
python3 scripts/run_audit.py
```

调试时再分步运行：

```bash
python3 scripts/detect.py
python3 scripts/scan.py --preflight .butian/<run-id>/assets/preflight.json
python3 scripts/analyze.py .butian/<run-id>/assets/scan.json
python3 scripts/report.py .butian/<run-id>/assets/analysis.json
python3 scripts/visualize.py .butian/<run-id>/assets/analysis.json
```

生成报告后先让用户阅读 HTML，再按 `references/repair-flow.md` 询问是否修复。
