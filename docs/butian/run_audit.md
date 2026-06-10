# run_audit.py 技术文档

> 源码路径：`butian/scripts/run_audit.py`

## 概览

`run_audit.py` 是完整管线编排器。它按顺序调用 `detect → scan → analyze → visualize → report` 五个阶段，一次性完成从预检到报告生成的全流程。

## 职责

| #   | 职责          | 说明                                                                                                                         |
| --- | ------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| 1   | 管线编排      | 按序调用 detect → scan → analyze → visualize → report                                                                        |
| 2   | 参数透传      | 将用户参数传递给各子阶段（verbose/debug/follow-symlinks）                                                                    |
| 3   | 结果汇总      | 收集各阶段的文件路径和风险统计                                                                                               |
| 4   | 终端摘要      | 输出格式化的终端摘要（包含 Unicode 表格）                                                                                    |
| 5   | 报告输出      | HTML 和 Markdown 都生成到 `docs/butian/<日期>/`，普通报告和最终报告使用固定文件名                                         |
| 6   | 打开控制      | 不自动打开浏览器；终端只展示摘要、报告绝对路径和后续交互提示                                                               |

## CLI 用法

```bash
# macOS / Linux
python3 run_audit.py                        # 当前目录，完整扫描
python3 run_audit.py /path/to/project       # 指定项目路径
python3 run_audit.py --skip-outdated .      # 跳过过期依赖检查
python3 run_audit.py --no-open .            # 兼容旧参数；默认也不会自动打开 HTML 报告

python3 run_audit.py --verbose .            # 详细日志输出
python3 run_audit.py --debug .              # 调试级别日志
python3 run_audit.py --follow-symlinks .    # 跟随符号链接
python3 run_audit.py --final-report .       # 最终复扫：生成 security-report-final.html 和 security-report-final.md

# Windows
py -3 run_audit.py                          # 当前目录，完整扫描
py -3 run_audit.py C:\path\to\project       # 指定项目路径
py -3 run_audit.py --skip-outdated .        # 跳过过期依赖检查
py -3 run_audit.py --no-open .              # 兼容旧参数；默认也不会自动打开 HTML 报告

py -3 run_audit.py --verbose .              # 详细日志输出
py -3 run_audit.py --debug .                # 调试级别日志
py -3 run_audit.py --follow-symlinks .      # 跟随符号链接
py -3 run_audit.py --final-report .         # 最终复扫：生成 security-report-final.html 和 security-report-final.md
```

## CLI 参数

| 参数                  | 类型     | 默认值 | 说明                             |
| --------------------- | -------- | ------ | -------------------------------- |
| `project_path`        | 位置参数 | `.`    | 项目路径                         |
| `--no-root-discovery` | flag     | false  | 不向上遍历查找项目根             |
| `--skip-outdated`     | flag     | false  | 跳过过期依赖检查                 |
| `--allow-project-exec` | flag     | false  | 允许过期检查执行项目内工具       |
| `--skip-hygiene`      | flag     | false  | 跳过仓库安检                     |
| `--max-secret-files`  | int      | None   | 限制密钥扫描的文件数量           |
| `--include-packages`  | flag     | false  | 在扫描输出中包含完整包列表       |
| `--no-open`           | flag     | false  | 兼容旧参数；默认也不会自动打开 HTML 报告 |
| `--final-report`      | flag     | false  | 生成 `security-report-final.html` 和 `security-report-final.md` |
| `--verbose`           | flag     | false  | 输出详细日志到 stderr            |
| `--debug`             | flag     | false  | 输出调试级别日志                 |
| `--follow-symlinks`   | flag     | false  | 跟随符号链接扫描                 |

## 管线流程

```
run_audit.py
│
├─ 1. detect.py [--no-root-discovery] <project_path>
│     → preflight.json
│     → stdout: preflight JSON
│
├─ 2. scan.py --preflight <preflight_file> [新增参数透传]
│     → scan.json
│     → stdout: scan JSON
│     透传: --verbose, --debug, --follow-symlinks
│     仓库安检会同时产出密钥/敏感文件/.gitignore、GitHub Actions、依赖配置与维护、IaC/容器结构化 finding
│
├─ 3. analyze.py <scan_file> <analysis_path>
│     → analysis.json
│
├─ 4. visualize.py <analysis_path> <html_path> --no-open
│     → docs/butian/YYYY-MMDD/security-report.html
│     → docs/butian/YYYY-MMDD/security-report-final.html（--final-report）
│     始终只保存文件，不自动打开浏览器
├─ 5. report.py <analysis_path> <markdown_path>
│     → docs/butian/YYYY-MMDD/security-report.md
│     → docs/butian/YYYY-MMDD/security-report-final.md（--final-report）
│
└─ 输出终端摘要
```

`run_audit.py` 不执行依赖升级，也不询问用户是否修复。完整修复交互契约以 `butian/references/project-scan.md` 为准；本页只说明脚本编排和输出边界。

修复交互在报告展示后进入 AskUserQuestion：先确认是否修复，再选择升级策略；修复后重新运行 `run_audit.py` 复扫。复扫确认仍有 npm 嵌套残留时，才进入 `parent-upgrade` 或 `force-residual` 后续轮次。Dependabot、凭证占位符和过期依赖维护属于可选收尾动作，不由 `run_audit.py` 自动执行，也不能和修复确认放在同一个 AskUserQuestion 中。

所有项目修复轮次结束后，运行 `run_audit.py --final-report` 生成最终 HTML 报告和 Markdown 审计报告。

## 子进程调用方式

### `run_json(cmd)` — 解析 JSON 输出

调用子脚本，解析 stdout 为 JSON。用于 `detect` 和 `scan` 阶段（它们输出 JSON 到 stdout）。

### `run_text(cmd, echo=True)` — 获取文本输出

调用子脚本，获取 stdout 文本。用于 `analyze`、`visualize`、`report` 阶段。

## 终端摘要格式

输出包含以下内容：

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
- 已确认风险项：5 个
- 仓库安检：0 个硬编码凭证 / 0 个跟踪的敏感文件 / .gitignore 完整
- 过期依赖：3 个（建议按维护窗口评估升级）
- 扫描错误：无

⚠️ 能力边界
> 安全往往不是最显眼的需求...

🚨 重点关注（按修复优先级）
[核心风险包的 Unicode 表格]

📁 报告路径
- HTML 报告（不会自动打开）：/path/to/project/docs/butian/2026-0609/security-report.html
- Markdown 审计报告：/path/to/project/docs/butian/2026-0609/security-report.md

# 或最终复扫时：
📁 报告路径
- HTML 报告（不会自动打开）：/path/to/project/docs/butian/2026-0609/security-report-final.html
- 最终 Markdown 审计报告：/path/to/project/docs/butian/2026-0609/security-report-final.md

# 或中间复扫时：
📁 报告路径
- HTML 报告（不会自动打开）：/path/to/project/docs/butian/2026-0609/security-report.html
- Markdown 审计报告：/path/to/project/docs/butian/2026-0609/security-report.md

```

终端摘要只展示仓库安检的基础计数，详细的 GitHub Actions、依赖配置与维护、IaC/容器 finding 会进入 Markdown 和 HTML 报告的"仓库安检"章节，并继续参与 `red/yellow/green` 风险分级。`hygiene_only` 模式只跳过依赖漏洞和过期依赖检查，不跳过这些本地 Python 仓库安检规则。

终端摘要不是完整报告。判断 HTML/Markdown 展示是否准确时，应打开最新 `docs/butian/<日期>/security-report.html` 和同目录 `security-report.md`；最终复扫看 `security-report-final.*`。

## 核心辅助函数

### Unicode 表格

| 函数                                       | 作用                                   |
| ------------------------------------------ | -------------------------------------- |
| `table(headers, rows, min_widths, aligns)` | 生成 Unicode 边框表格（`┌─┬─┐` 风格）  |
| `fit_cell(value, width, align)`            | 对齐表格单元格内容                     |
| `display_width(value)`                     | 计算字符串的显示宽度（CJK 字符计为 2） |

### 漏洞分析

| 函数                                                  | 作用                                                                                     |
| ----------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `format_focus(analysis, scan_mode)`                   | 生成重点关注区域的表格（按当前风险项数排序的前 6 个包）                                  |
| `format_risk_rows(risk_summary)`                      | 格式化风险统计行（含 emoji 指示器）                                                      |
| `format_human_summary(summary, scan, analysis, args)` | 组装完整的终端摘要文本                                                                   |
| `best_fixed_version(issues)`                          | 从多个风险项记录中选出最佳修复版本                                                       |
| `risk_nature(issues)`                                 | 通过模式匹配识别风险类型（中间件/代理绕过、SSRF、DoS、缓存风险等），仅用于终端重点关注表 |
| `mode_label(scan_mode)`                               | 将扫描模式映射为中文标签                                                                 |

### 路径工具

| 函数                                | 作用                                 |
| ----------------------------------- | ------------------------------------ |
| `absolute_path(path)`               | 将报告摘要里的路径格式化为绝对路径   |

## 设计要点

- **子进程编排**：每个阶段作为独立 Python 子进程运行，通过 JSON stdout 传递数据
- **CJK 宽度感知**：`display_width()` 正确处理中文字符的终端显示宽度
- **参数透传**：`build_scan_cmd()` 将 verbose/debug/follow-symlinks 传递给 `scan.py`
- **能力边界声明**：终端摘要中包含明确的能力边界说明
- **报告文件名**：普通扫描写 `security-report.html` 和 `security-report.md`，最终复扫写 `security-report-final.html` 和 `security-report-final.md`
- **最终报告**：`--final-report` 在修复完成后生成最终 HTML 和 Markdown 审计报告
- **仓库安检明细下沉到报告**：终端保持短摘要，结构化本地规则的依据、处理方式和分组展示放在 Markdown/HTML 报告里，避免终端输出过长
- **报告验收以最新日期目录为准**：同一项目可能保留多个 `docs/butian/<日期>`，不要用旧 HTML 判断当前模板。

## 相关文档

| 文档                        | 说明                     |
| --------------------------- | ------------------------ |
| `docs/butian/scan.md`       | scan.py 核心引擎技术文档 |
| `docs/butian/api-limits.md` | API 限流与使用策略       |
