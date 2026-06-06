# run_audit.py 技术文档

> 源码路径：`butian/scripts/run_audit.py`

## 概览

`run_audit.py` 是 Butian 安全审计的完整管线编排器。它按顺序调用 `detect → scan → analyze → report → visualize` 五个阶段，一次性完成从预检到报告生成的全流程。

## 职责

| #   | 职责          | 说明                                                                                       |
| --- | ------------- | ------------------------------------------------------------------------------------------ |
| 1   | 管线编排      | 按序调用 detect → scan → analyze → report → visualize                                      |
| 2   | 参数透传      | 将用户参数传递给各子阶段（verbose/debug/follow-symlinks）                                  |
| 3   | 结果汇总      | 收集各阶段的文件路径和风险统计                                                             |
| 4   | 终端摘要      | 输出格式化的终端摘要（包含 Unicode 表格）                                                  |
| 5   | 报告打开      | 首次扫描自动用系统浏览器打开 HTML 报告，复扫跳过（由 `.butian/.first-scan-done` 标记控制） |
| 6   | Markdown 控制 | 首次扫描 + 最终复扫（`--final-report`）生成 Markdown，中间复扫跳过                         |

## CLI 用法

```bash
# 基本用法
python3 run_audit.py                        # 当前目录，完整扫描
python3 run_audit.py /path/to/project       # 指定项目路径
python3 run_audit.py --skip-outdated .      # 跳过过期依赖检查
python3 run_audit.py --no-open .            # CI/自动化场景：不自动打开 HTML 报告

# 可选参数
python3 run_audit.py --verbose .            # 详细日志输出
python3 run_audit.py --debug .              # 调试级别日志
python3 run_audit.py --follow-symlinks .    # 跟随符号链接
python3 run_audit.py --final-report .       # 最终复扫：强制生成 Markdown 报告
```

## CLI 参数

| 参数                  | 类型     | 默认值 | 说明                             |
| --------------------- | -------- | ------ | -------------------------------- |
| `project_path`        | 位置参数 | `.`    | 项目路径                         |
| `--no-root-discovery` | flag     | false  | 不向上遍历查找项目根             |
| `--skip-outdated`     | flag     | false  | 跳过过期依赖检查                 |
| `--skip-hygiene`      | flag     | false  | 跳过仓库卫生检查                 |
| `--max-secret-files`  | int      | None   | 限制密钥扫描的文件数量           |
| `--include-packages`  | flag     | false  | 在扫描输出中包含完整包列表       |
| `--no-open`           | flag     | false  | 不自动打开 HTML 报告             |
| `--final-report`      | flag     | false  | 最终复扫时强制生成 Markdown 报告 |
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
│
├─ 3. analyze.py <scan_file> <analysis_path>
│     → analysis.json
│
├─ 4. report.py <analysis_path> <markdown_path>  ← 首次扫描或 --final-report 时执行
│     → docs/butian/security-report-YYYY-MM-DD_HHMMSS.md
│     复扫时跳过（由 .butian/.first-scan-done 标记控制）
├─ 5. visualize.py <analysis_path> <html_path> [--no-open]
│     → .butian/<run>/content/security-report.html
│     首次扫描自动打开浏览器，复扫跳过（.first-scan-done 标记）
│
└─ 输出终端摘要
```

`run_audit.py` 不执行依赖升级，也不询问用户是否修复。修复确认属于 `SKILL.md` 的 Agent 工作流，分三轮进行：

**第一轮**：用户选择修复策略后，调用 `fix.py --strategy fixed|latest` 执行顶层依赖升级，然后重新运行 `run_audit.py` 复扫验证。复扫不会重复弹出浏览器，也不会生成 Markdown。

**第二轮**（复扫后仍有残留时）：如果复扫仍出现同名旧版本，通常是间接依赖被父包锁定。脚本会自动分析父依赖声明的 semver 范围，分三档处理：修复版本在范围内（只需重新解析 lockfile）、不在范围内（升级父依赖到 latest）、无法追溯到根依赖（报告给用户）。调用 `fix.py --strategy parent-upgrade`。当前仅支持 npm `package-lock.json` 场景。升级后重新运行 `run_audit.py` 复扫。

**第三轮**（第二轮后仍有残留时）：通过 `fix.py --strategy force-residual` 在 `package.json` 的 `overrides` 字段强制覆盖残留依赖。

**最终报告**：所有修复轮次结束后，运行 `run_audit.py --final-report` 生成最终 Markdown 审计报告。终端摘要以 `📁 最终报告路径` 标注。

## 子进程调用方式

### `run_json(cmd)` — 解析 JSON 输出

调用子脚本，解析 stdout 为 JSON。用于 `detect` 和 `scan` 阶段（它们输出 JSON 到 stdout）。

### `run_text(cmd, echo=True)` — 获取文本输出

调用子脚本，获取 stdout 文本。用于 `analyze`、`report`、`visualize` 阶段。

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

# 或最终复扫时：
📁 报告路径
- 最终Markdown 审计报告：docs/butian/security-report-2025-01-15_143000.md
- HTML 报告：.butian/.../content/security-report.html
- analysis JSON：.butian/.../assets/analysis.json

# 或中间复扫时（无 Markdown 生成）：
📁 报告路径
- Markdown 审计报告：复扫未生成（首次扫描已有）
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

| 函数                                                  | 作用                                                    |
| ----------------------------------------------------- | ------------------------------------------------------- |
| `format_focus(analysis, scan_mode)`                   | 生成重点关注区域的表格（按命中风险项数排序的前 6 个包） |
| `format_risk_rows(risk_summary)`                      | 格式化风险统计行（含 emoji 指示器）                     |
| `format_human_summary(summary, scan, analysis, args)` | 组装完整的终端摘要文本                                  |
| `best_fixed_version(issues)`                          | 从多个风险项记录中选出最佳修复版本                      |
| `risk_nature(issues)`                                 | 通过模式匹配识别风险类型（SSRF、XSS、DoS 等）           |
| `mode_label(scan_mode)`                               | 将扫描模式映射为中文标签                                |

### 路径工具

| 函数                                | 作用                                 |
| ----------------------------------- | ------------------------------------ |
| `relative_path(path, project_path)` | 将绝对路径转为相对于项目根的相对路径 |

## 设计要点

- **子进程编排**：每个阶段作为独立 Python 子进程运行，通过 JSON stdout 传递数据
- **CJK 宽度感知**：`display_width()` 正确处理中文字符的终端显示宽度
- **参数透传**：`build_scan_cmd()` 将 verbose/debug/follow-symlinks 传递给 `scan.py`
- **能力边界声明**：终端摘要中包含明确的能力边界说明
- **首次标记**：`.butian/.first-scan-done` 标记控制浏览器弹出和 Markdown 生成，复扫不重复
- **最终报告**：`--final-report` 在修复完成后强制生成最终 Markdown 审计报告

## 相关文档

| 文档                        | 说明                     |
| --------------------------- | ------------------------ |
| `docs/butian/scan.md`       | scan.py 核心引擎技术文档 |
| `docs/butian/api-limits.md` | API 限流与使用策略       |
