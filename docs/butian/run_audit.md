# run_audit.py 技术文档

> 源码路径：`butian/scripts/run_audit.py`（518 行）

## 概览

`run_audit.py` 是 Butian 安全审计的完整管线编排器。它按顺序调用 `detect → scan → analyze → report → visualize` 五个阶段，一次性完成从预检到报告生成的全流程。

## 职责

| #   | 职责     | 说明                                                  |
| --- | -------- | ----------------------------------------------------- |
| 1   | 管线编排 | 按序调用 detect → scan → analyze → report → visualize |
| 2   | 参数透传 | 将用户参数传递给各子阶段                              |
| 3   | 结果汇总 | 收集各阶段的文件路径和风险统计                        |
| 4   | 终端摘要 | 输出格式化的终端摘要（包含 Unicode 表格）             |

## CLI 用法

```bash
python3 run_audit.py                        # 当前目录，完整扫描
python3 run_audit.py /path/to/project       # 指定项目路径
python3 run_audit.py --skip-outdated .      # 跳过过期依赖检查
python3 run_audit.py --skip-hygiene .       # 跳过仓库卫生检查
python3 run_audit.py --no-open .            # 不自动打开 HTML 报告
python3 run_audit.py --compact .            # 输出紧凑 JSON 摘要
python3 run_audit.py --no-root-discovery .  # 不向上查找项目根
python3 run_audit.py --include-packages .   # 在扫描中包含完整包列表
python3 run_audit.py --max-secret-files 300 .  # 限制密钥扫描文件数
```

## CLI 参数

| 参数                  | 类型     | 默认值  | 说明                            |
| --------------------- | -------- | ------- | ------------------------------- |
| `project_path`        | 位置参数 | `.`     | 项目路径                        |
| `--no-root-discovery` | flag     | `false` | 不向上遍历查找项目根            |
| `--skip-outdated`     | flag     | `false` | 跳过过期依赖检查（加快扫描）    |
| `--skip-hygiene`      | flag     | `false` | 跳过仓库卫生检查                |
| `--max-secret-files`  | int      | `None`  | 限制密钥扫描的文件数量          |
| `--include-packages`  | flag     | `false` | 在扫描输出中包含完整包列表      |
| `--compact`           | flag     | `false` | 输出紧凑 JSON（不输出终端摘要） |
| `--no-open`           | flag     | `false` | 不自动打开 HTML 报告            |

## 管线流程

```
run_audit.py
│
├─ 1. detect.py --compact [--no-root-discovery] <project_path>
│     → preflight.json
│     → stdout: preflight JSON
│
├─ 2. scan.py --preflight <preflight_file> [--skip-outdated] [--skip-hygiene] ...
│     → scan.json
│     → stdout: scan JSON
│
├─ 3. analyze.py <scan_file> <analysis_path>
│     → analysis.json
│
├─ 4. report.py <analysis_path> <markdown_path>
│     → docs/security-report-YYYY-MM-DD.md
│
├─ 5. visualize.py <analysis_path> <html_path> [--no-open]
│     → .butian/<run>/content/security-report.html
│
└─ 输出终端摘要（或紧凑 JSON）
```

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
│    影响程度           │ 数量  │
├──────────────────────┼───────┤
│ 🔴 紧急 (Critical)   │ 1     │
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
- Markdown 审计报告：docs/security-report-2025-01-15.md
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
  "markdown_report": "docs/security-report-2025-01-15.md",
  "html_report": ".butian/.../content/security-report.html",
  "scan_mode": "full_dependency_scan",
  "risk_summary": { "critical": 1, "high": 2, "medium": 3, "low": 1 },
  "errors": []
}
```

## 设计要点

- **子进程编排**：每个阶段作为独立 Python 子进程运行，通过 JSON stdout 传递数据
- **双模式输出**：`--compact` 适合程序消费（JSON），默认模式适合人类阅读（Unicode 表格）
- **CJK 宽度感知**：`display_width()` 正确处理中文字符的终端显示宽度
- **参数透传**：`build_scan_cmd()` 将所有相关参数传递给 `scan.py`
- **错误传播**：子进程非零退出码通过 `SystemExit` 向上传播
- **能力边界声明**：终端摘要中包含明确的能力边界说明
