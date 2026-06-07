# visualize.py 技术文档

> 源码路径：`butian/scripts/visualize.py`

## 概览

`visualize.py` 将 `analyze.py` 的分析 JSON 注入到 HTML 模板中，生成一个**完全自包含**的交互式 HTML 安全报告。CSS 和 JavaScript 被内联嵌入，无需外部依赖即可在浏览器中打开。

## 职责

| #   | 职责            | 说明                                         |
| --- | --------------- | -------------------------------------------- |
| 1   | JSON 安全序列化 | 将分析数据转义后嵌入 `<script>` 标签         |
| 2   | 资产内联        | 将 CSS 和 JS 文件内容直接嵌入 HTML           |
| 3   | 报告生成        | 将数据注入模板占位符，输出独立 HTML 文件     |
| 4   | 自动打开        | 首次扫描在默认浏览器中自动打开报告，复扫跳过 |

## CLI 用法

```bash
python3 visualize.py analysis.json                                # 自动输出 + 自动打开浏览器
python3 visualize.py analysis.json output.html                    # 指定输出路径
python3 visualize.py --no-open analysis.json                      # 不自动打开浏览器
```

## CLI 参数

| 参数            | 类型     | 必需    | 说明                                                                |
| --------------- | -------- | ------- | ------------------------------------------------------------------- |
| `analysis_json` | 位置参数 | ✅      | `analyze.py` 输出的 JSON 路径                                       |
| `output_html`   | 位置参数 | ❌      | 输出 HTML 路径（默认 `.butian/<run>/content/security-report.html`） |
| `--no-open`     | flag     | `false` | 不在浏览器中自动打开报告（CI/自动化使用）                           |

## 环境变量

| 变量             | 值                          | 效果               |
| ---------------- | --------------------------- | ------------------ |
| `BUTIAN_NO_OPEN` | `1` / `true` / `yes` / `on` | 等同于 `--no-open` |

## 核心函数

### 序列化与转义

| 函数                           | 作用                                                                                    |
| ------------------------------ | --------------------------------------------------------------------------------------- |
| `json_for_script(value)`       | 将 JSON 序列化为紧凑格式，并转义 `<script>` 标签中的特殊字符（`&`、`<`、`>`、` `、` `） |
| `script_asset_for_html(value)` | 转义 `</script` 防止内联 JS 被提前关闭                                                  |
| `style_asset_for_html(value)`  | 转义 `</style` 防止内联 CSS 被提前关闭                                                  |

### 路径与配置

| 函数                                 | 作用                                              |
| ------------------------------------ | ------------------------------------------------- |
| `default_output_path(analysis_path)` | 返回 `.butian/<run>/content/security-report.html` |

### 浏览器打开

| 函数                                    | 作用                                                                                                                    |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `should_open_report(args, output_path)` | 综合 `--no-open`、`BUTIAN_NO_OPEN` 环境变量和 `.first-scan-done` 标记判断是否打开                                       |
| `_first_scan_done(output_path)`         | 检查 `.butian/.first-scan-done` 标记文件是否存在                                                                        |
| `_mark_first_scan_done(output_path)`    | 创建 `.butian/.first-scan-done` 标记文件                                                                                |
| `_butian_dir_for(output_path)`          | 从输出路径向上查找 `.butian/` 目录                                                                                      |
| `open_report(path)`                     | 跨平台打开 HTML 报告（macOS `open`、Windows `startfile`、Linux `xdg-open`/`gio`/`wslview`，最终 fallback `webbrowser`） |
| `spawn_open_command(cmd)`               | 以 `Popen` 后台启动打开命令，不阻塞脚本执行                                                                             |

首次扫描时浏览器打开成功后，会创建 `.butian/.first-scan-done` 标记文件。后续复扫检测到该标记后跳过浏览器打开，打印 `"已跳过自动打开报告（首次扫描已完成）。"`。

## 模板注入流程

```
templates/report.html
  ├─ __REPORT_CSS__  ← static/report.css  (内联样式)
  ├─ __REPORT_DATA__ ← analysis.json      (转义后的 JSON)
  └─ __REPORT_JS__   ← static/report.js   (内联脚本)
```

注入后检查是否仍有残留占位符，如有则抛出 `SystemExit`。

## HTML 报告渲染要点

`templates/report.js` 会在浏览器端消费 `analysis.json`，其中仓库安检部分会读取以下字段：

| 字段                        | HTML 展示                                                          |
| --------------------------- | ------------------------------------------------------------------ |
| `hygiene.tracked_secrets`   | 待确认项中最多展示 5 条，显示文件行号、中文密钥类型和脱敏预览      |
| `hygiene.sensitive_tracked` | 待确认项中最多展示 5 条，显示文件路径和中文敏感文件类型            |
| `hygiene.gitignore_missing` | 摘要卡片展示建议补充的规则数量                                     |
| `hygiene.workflow_checks`   | 以"GitHub Actions 工作流安全"标签展示结构化 finding，最多展示 6 条 |
| `hygiene.repository_checks` | 以"依赖与发布治理"标签展示结构化 finding，最多展示 6 条      |
| `hygiene.iac_checks`        | 以"IaC / 容器 / 部署配置"标签展示结构化 finding，最多展示 6 条     |

结构化 finding 在 HTML 中保留 `file:line`、中文分组标签、`title`、`evidence` 和 `recommendation`。当展示条目超过上限时，页面追加"…及其他 N 处"，避免小屏幕报告被长列表淹没。

如果仓库安检没有任何密钥、敏感文件、缺失规则或结构化本地 finding，HTML 会隐藏整个"仓库安检"段落，避免空卡片干扰阅读。若扫描使用 `--skip-hygiene`，页面会展示跳过原因和建议动作，而不是给出通过结论。

## 输出路径

默认路径：`.butian/<run_id>/content/security-report.html`

## 跨平台浏览器打开策略

```
macOS  → open <path>
Windows → os.startfile(<path>)
Linux  → xdg-open / gio open / wslview (按优先级尝试)
Fallback → webbrowser.open_new_tab(file://...)
```

## 设计要点

- **完全自包含**：HTML 文件内联了所有 CSS 和 JavaScript，无需网络即可查看
- **XSS 防护**：`json_for_script()` 转义了 HTML 特殊字符和 Unicode 行分隔符
- **占位符校验**：生成后检查是否所有 `__REPORT_*__` 占位符都已替换，防止输出损坏的 HTML
- **环境变量控制**：CI/CD 环境中可通过 `BUTIAN_NO_OPEN=1` 禁止自动打开浏览器
- **后台打开**：使用 `Popen` 启动浏览器进程，不阻塞脚本退出
- **首次标记**：`.butian/.first-scan-done` 标记确保浏览器只在首次扫描时弹出，复扫不重复
- **常量导出**：`FIRST_SCAN_MARKER = ".first-scan-done"` 可供其他模块（如 `run_audit.py`）复用
- **仓库安检可读性**：HTML 只展示脱敏预览和证据摘要；本地规则使用中文分组，给专业用户保留复核线索，也让小白用户能看到明确建议
