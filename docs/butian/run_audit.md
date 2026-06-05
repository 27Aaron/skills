# run_audit.py 技术文档

> 源码路径：`butian/scripts/run_audit.py`

## 概览

`run_audit.py` 是 Butian 安全审计的完整管线编排器。它按顺序调用 `detect → scan → analyze → report → visualize`（+ 可选 `sarif`）六个阶段，一次性完成从预检到报告生成的全流程。

## 职责

| #   | 职责       | 说明                                                                   |
| --- | ---------- | ---------------------------------------------------------------------- |
| 1   | 管线编排   | 按序调用 detect → scan → analyze → report → visualize [+ sarif]        |
| 2   | 参数透传   | 将用户参数传递给各子阶段（包括新增的 verbose/debug/cache/baseline 等） |
| 3   | 结果汇总   | 收集各阶段的文件路径和风险统计                                         |
| 4   | 终端摘要   | 输出格式化的终端摘要（包含 Unicode 表格）                              |
| 5   | 报告打开   | 默认尝试用系统浏览器打开 HTML 报告，`--no-open` 仅供 CI/自动化使用      |
| 6   | 退出码控制 | 根据 `--severity-threshold` 返回语义化退出码                           |

## CLI 用法

```bash
# 基本用法
python3 run_audit.py                        # 当前目录，完整扫描
python3 run_audit.py /path/to/project       # 指定项目路径
python3 run_audit.py --skip-outdated .      # 跳过过期依赖检查
python3 run_audit.py --compact .            # 输出紧凑 JSON 摘要
python3 run_audit.py --no-open .            # CI/自动化场景：不自动打开 HTML 报告

# 新增功能
python3 run_audit.py --verbose .            # 详细日志输出
python3 run_audit.py --debug .              # 调试级别日志
python3 run_audit.py --progress .           # 显示扫描进度
python3 run_audit.py --sarif .              # 生成 SARIF 格式结果
python3 run_audit.py --baseline .           # 启用基线过滤
python3 run_audit.py --generate-baseline .  # 生成基线文件
python3 run_audit.py --severity-threshold high .  # high+ 漏洞时退出码 1
python3 run_audit.py --follow-symlinks .    # 跟随符号链接
python3 run_audit.py --no-cache .           # 禁用缓存
python3 run_audit.py --cache-ttl 3600 .     # 自定义缓存过期时间

# CI/CD 组合用法
python3 run_audit.py --compact --no-open --sarif --severity-threshold high .
```

## CLI 参数

| 参数                   | 类型     | 默认值   | 说明                                   |
| ---------------------- | -------- | -------- | -------------------------------------- |
| `project_path`         | 位置参数 | `.`      | 项目路径                               |
| `--no-root-discovery`  | flag     | false    | 不向上遍历查找项目根                   |
| `--skip-outdated`      | flag     | false    | 跳过过期依赖检查                       |
| `--skip-hygiene`       | flag     | false    | 跳过仓库卫生检查                       |
| `--max-secret-files`   | int      | None     | 限制密钥扫描的文件数量                 |
| `--include-packages`   | flag     | false    | 在扫描输出中包含完整包列表             |
| `--compact`            | flag     | false    | 输出紧凑 JSON                          |
| `--no-open`            | flag     | false    | 不自动打开 HTML 报告                   |
| `--verbose`            | flag     | false    | 输出详细日志到 stderr                  |
| `--debug`              | flag     | false    | 输出调试级别日志                       |
| `--follow-symlinks`    | flag     | false    | 跟随符号链接扫描                       |
| `--no-cache`           | flag     | false    | 禁用本地缓存                           |
| `--cache-ttl`          | int      | 86400    | 缓存过期时间（秒）                     |
| `--progress`           | flag     | 自动检测 | 显示扫描进度                           |
| `--no-progress`        | flag     | false    | 禁用进度信息                           |
| `--severity-threshold` | choice   | —        | 退出码阈值（low/medium/high/critical） |
| `--baseline`           | flag     | false    | 启用基线过滤                           |
| `--skip-baseline`      | flag     | false    | 跳过基线过滤                           |
| `--generate-baseline`  | flag     | false    | 从当前扫描结果生成基线文件             |
| `--sarif`              | flag     | false    | 生成 SARIF v2.1.0 格式结果             |

## 退出码

| 退出码 | 含义                                     |
| ------ | ---------------------------------------- |
| 0      | 扫描完成，无超阈值发现                   |
| 1      | 存在不低于 `--severity-threshold` 的发现 |
| 2      | 执行错误（子进程失败等）                 |

## 管线流程

```
run_audit.py
│
├─ 1. detect.py --compact [--no-root-discovery] <project_path>
│     → preflight.json
│     → stdout: preflight JSON
│
├─ 2. scan.py --preflight <preflight_file> [新增参数透传]
│     → scan.json
│     → stdout: scan JSON
│     透传: --verbose, --debug, --follow-symlinks, --no-cache,
│           --cache-ttl, --progress, --severity-threshold,
│           --baseline, --generate-baseline
│
├─ 3. analyze.py <scan_file> <analysis_path>
│     → analysis.json
│
├─ 4. report.py <analysis_path> <markdown_path>
│     → docs/butian/security-report-YYYY-MM-DD_HHMMSS.md
│
├─ 5. visualize.py <analysis_path> <html_path> [--no-open]
│     → .butian/<run>/content/security-report.html
│
├─ 6. [可选] sarif.py <analysis_path> <sarif_path>    ← 新增
│     → .butian/<run>/assets/results.sarif.json
│     触发条件: --sarif
│
└─ 输出终端摘要（或紧凑 JSON）+ 退出码判断
```

`run_audit.py` 不执行依赖升级，也不询问用户是否修复。修复确认属于 `SKILL.md` 的 Agent 工作流：用户明确选择修复策略后，再调用 `fix.py --strategy fixed|latest` 执行升级，并重新运行 `run_audit.py` 验证。

## 子进程调用方式

### `run_json(cmd)` — 解析 JSON 输出

调用子脚本，解析 stdout 为 JSON。用于 `detect` 和 `scan` 阶段（它们输出 JSON 到 stdout）。

### `run_text(cmd, echo=True)` — 获取文本输出

调用子脚本，获取 stdout 文本。用于 `analyze`、`report`、`visualize` 阶段。

## 终端摘要格式

当不使用 `--compact` 时，输出包含以下内容：

```
⏺ 扫描完成 ✅ 模式：full_dependency_scan（完整依赖漏洞扫描）。

📊 风险总览

┌──────────────────────┬───────┐
│    影响程度          │ 数量  │
├──────────────────────┼───────┤
│ 🔴 紧急 (Critical)    │ 1     │
│ 🟠 高风险 (High)      │ 2     │
│ 🟡 中风险 (Medium)    │ 3     │
└──────────────────────┴───────┘

- 总依赖：142 个 npm 包
- 已确认漏洞：5 个
- 仓库卫生：0 个硬编码凭证 / 0 个跟踪的敏感文件 / .gitignore 完整
- 过期依赖：3 个（仅作维护信号，不算漏洞）
- 扫描错误：无

⚠️ 能力边界
> 安全往往不是最显眼的需求...

🚨 重点关注（按修复优先级）
[核心风险包的 Unicode 表格]

📁 报告路径
- Markdown 审计报告：docs/butian/security-report-2025-01-15_120000.md
- HTML 报告：.butian/.../content/security-report.html
- analysis JSON：.butian/.../assets/analysis.json
```

## 核心辅助函数

### Unicode 表格

| 函数                                       | 作用                                   |
| ------------------------------------------ | -------------------------------------- |
| `table(headers, rows, min_widths, aligns)` | 生成 Unicode 边框表格（`┌─┬─┐` 风格）  |
| `fit_cell(value, width, align)`            | 对齐表格单元格内容                     |
| `display_width(value)`                     | 计算字符串的显示宽度（CJK 字符计为 2） |

### 漏洞分析

| 函数                                                  | 作用                                                  |
| ----------------------------------------------------- | ----------------------------------------------------- |
| `format_focus(analysis, scan_mode)`                   | 生成重点关注区域的表格（按命中漏洞数排序的前 6 个包） |
| `format_risk_rows(risk_summary)`                      | 格式化风险统计行（含 emoji 指示器）                   |
| `format_human_summary(summary, scan, analysis, args)` | 组装完整的终端摘要文本                                |
| `best_fixed_version(issues)`                          | 从多个漏洞记录中选出最佳修复版本                      |
| `risk_nature(issues)`                                 | 通过模式匹配识别风险类型（SSRF、XSS、DoS 等）         |
| `mode_label(scan_mode)`                               | 将扫描模式映射为中文标签                              |

### 路径工具

| 函数                                | 作用                                 |
| ----------------------------------- | ------------------------------------ |
| `relative_path(path, project_path)` | 将绝对路径转为相对于项目根的相对路径 |

## 输出 JSON 结构（--compact 模式）

```json
{
  "preflight_file": ".butian/.../assets/preflight.json",
  "scan_file": ".butian/.../assets/scan.json",
  "analysis_file": ".butian/.../assets/analysis.json",
  "markdown_report": "docs/butian/security-report-2025-01-15_120000.md",
  "html_report": ".butian/.../content/security-report.html",
  "sarif_file": ".butian/.../assets/results.sarif.json",
  "scan_mode": "full_dependency_scan",
  "risk_summary": { "critical": 1, "high": 2, "medium": 3, "low": 1 },
  "errors": []
}
```

> `sarif_file` 仅在 `--sarif` 模式下出现。依赖修复不属于 `run_audit.py` 的输出结构。

## 设计要点

- **子进程编排**：每个阶段作为独立 Python 子进程运行，通过 JSON stdout 传递数据
- **双模式输出**：`--compact` 适合程序消费（JSON），默认模式适合人类阅读（Unicode 表格）
- **CJK 宽度感知**：`display_width()` 正确处理中文字符的终端显示宽度
- **参数透传**：`build_scan_cmd()` 将所有相关参数（含新增的 verbose/debug/cache/baseline 等）传递给 `scan.py`
- **错误传播**：子进程非零退出码通过 `SystemExit` 向上传播
- **能力边界声明**：终端摘要中包含明确的能力边界说明
- **语义化退出码**：`--severity-threshold` 控制管线退出码，支持 CI/CD 集成
- **SARIF 输出**：`--sarif` 生成标准化安全结果，可上传到 GitHub Advanced Security 等

## 相关文档

| 文档                        | 说明                     |
| --------------------------- | ------------------------ |
| `docs/butian/scan.md`       | scan.py 核心引擎技术文档 |
| `docs/butian/sarif.md`      | SARIF 输出生成器技术文档 |
| `docs/butian/baseline.md`   | 基线文件使用指南         |
| `docs/butian/ci-cd.md`      | CI/CD 集成模板           |
| `docs/butian/api-limits.md` | API 限流与使用策略       |
