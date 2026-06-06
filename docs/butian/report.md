# report.py 技术文档

> 源码路径：`butian/scripts/report.py`（431 行）

## 概览

`report.py` 接收 `analyze.py` 的分析 JSON，渲染为人类可读的 Markdown 安全报告。它使用模板引擎（`string.Template`）将分析数据填入 `templates/report.md` 模板。

## 职责

| #   | 职责           | 说明                                                                     |
| --- | -------------- | ------------------------------------------------------------------------ |
| 1   | 风险项表格渲染 | 将风险项列表渲染为 Markdown 表格（含严重度、包名、版本、GHSA、修复版本） |
| 2   | 仓库卫生报告   | 渲染硬编码密钥、敏感文件、gitignore 状态                                 |
| 3   | 过期依赖报告   | 渲染版本维护信号表格                                                     |
| 4   | 人工确认事项   | 渲染 red + yellow 事项的详细描述                                         |
| 5   | 摘要与建议     | 渲染 TL;DR、优先级建议和下一步操作                                       |

## CLI 用法

```bash
python3 report.py .butian/<timestamp>/assets/analysis.json                                # 自动输出到 docs/butian/
python3 report.py analysis.json docs/butian/security-report-2025-01-15_120000.md           # 指定输出路径
```

## CLI 参数

| 参数              | 类型     | 必需 | 说明                                                                             |
| ----------------- | -------- | ---- | -------------------------------------------------------------------------------- |
| `analysis_json`   | 位置参数 | ✅   | `analyze.py` 输出的 JSON 路径                                                    |
| `output_markdown` | 位置参数 | ❌   | 输出 Markdown 路径（默认 `<project>/docs/butian/security-report-<datetime>.md`） |

## 核心常量

```python
CAPABILITY_BOUNDARY = (
    "安全往往不是最显眼的需求，却是产品长期稳定运行的底线。"
    "补天会优先帮助你发现依赖漏洞、过期依赖和仓库卫生风险，"
    "让容易被忽视的供应链问题更早暴露出来。"
    "但它不能替代代码审计、渗透测试或部署安全评估；"
    "代码层面的权限、业务逻辑、SQL 注入、XSS 等问题仍需单独复核。"
)
```

## 核心函数

### 渲染函数

| 函数                               | 输出内容                                                    |
| ---------------------------------- | ----------------------------------------------------------- |
| `render_summary(analysis)`         | TL;DR + 详细说明 + 扫描范围 + 能力边界 + 优先级建议         |
| `render_vulnerabilities(analysis)` | 风险项表格（严重度、包名、版本、GHSA、修复版本、说明）      |
| `render_hygiene(analysis)`         | 硬编码密钥统计 + 表格、敏感文件统计 + 表格、gitignore 状态  |
| `render_outdated(analysis)`        | 过期依赖表格（包名、当前版本、最近版本、建议）              |
| `render_manual_items(analysis)`    | red + yellow 事项的详细说明（关注原因、可能影响、建议动作） |
| `render_errors(analysis)`          | 扫描错误列表                                                |
| `render_next_steps(analysis)`      | 下一步建议                                                  |

### 工具函数

| 函数                               | 作用                                                              |
| ---------------------------------- | ----------------------------------------------------------------- |
| `security_ids(item)`               | 从风险项记录中提取所有 GHSA ID（支持嵌套列表、逗号分隔等格式）    |
| `severity_label(value)`            | 将严重度字符串映射为中文标签（紧急/高风险/中风险/低风险/待确认）  |
| `is_hygiene_only(analysis)`        | 判断是否为仅卫生扫描模式                                          |
| `date_from_analysis(analysis)`     | 从 `generated_at` 提取日期部分                                    |
| `datetime_from_analysis(analysis)` | 从 `generated_at` 提取文件系统安全的时间戳（`YYYY-MM-DD_HHMMSS`） |
| `is_outdated_item(item)`           | 判断过期依赖条目是否有实际可升级的版本                            |
| `cell(value)`                      | Markdown 表格单元格转义（处理 `` `\|` `` 和换行）                 |

### 模板渲染

```python
def render_markdown(analysis):
    tpl = load_template()  # 读取 templates/report.md
    return tpl.substitute(
        project_name=...,
        project_path=...,
        generated_at=...,
        scan_seconds=...,
        summary=render_summary(analysis),
        vulnerabilities=render_vulnerabilities(analysis),
        hygiene=render_hygiene(analysis),
        outdated=render_outdated(analysis),
        manual_items=render_manual_items(analysis),
        errors=render_errors(analysis),
        next_steps=render_next_steps(analysis),
    )
```

## 输出路径

默认路径规则：`<project_path>/docs/butian/security-report-<YYYY-MM-DD_HHMMSS>.md`

时间戳精确到秒，同一天多次扫描不会覆盖。

## 报告结构

生成的 Markdown 报告包含以下章节：

1. **摘要** — TL;DR、详细说明、扫描范围、能力边界、优先级建议
2. **命中风险项** — 依赖风险项详情表格（仅 `full_dependency_scan` 模式）
3. **仓库卫生** — 硬编码密钥、敏感文件、gitignore 状态
4. **过期依赖** — 版本维护信号表格（附"不等同于漏洞"提示）
5. **需要人工确认的事项** — red + yellow 分级事项详情
6. **扫描错误** — 失败的检查步骤
7. **下一步** — 优先级建议和操作指引

## 设计要点

- **模板驱动**：报告结构由 `templates/report.md` 控制，修改模板即可调整输出格式
- **中文标签**：所有面向用户的文本使用中文严重度标签
- **能力边界声明**：每份报告都包含明确的能力边界说明，避免用户误认为报告覆盖了所有安全问题
- **GHSA ID 提取**：`security_ids()` 递归处理多种 ID 格式（列表、逗号分隔、嵌套字段）
- **空状态处理**：每个渲染函数都处理了数据为空的情况，输出友好的提示文字
