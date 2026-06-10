# visualize.py 技术文档

> 源码路径：`butian/scripts/visualize.py`
> 展示逻辑：`butian/templates/report.html`、`butian/templates/report.css`、`butian/templates/report.js`

## 概览

`visualize.py` 将 `analyze.py` 的 `analysis.json` 注入为一个完全自包含的 HTML 安全报告。HTML 内联 CSS、JavaScript 和报告数据，不依赖外部网络资源，适合直接通过浏览器打开、截图、发送给同事或作为本地验收面。

HTML 是最完整的报告界面：它不仅展示 Markdown 中的风险和仓库安检事实，还提供折叠详情、代码证据、tooltip、响应式布局和编辑入口。

## 职责

| #   | 职责            | 说明                                                            |
| --- | --------------- | --------------------------------------------------------------- |
| 1   | JSON 安全序列化 | 将 `analysis.json` 转成可安全放入 `<script>` 的 JSON            |
| 2   | 资产内联        | 把 `report.css` 和 `report.js` 直接嵌入 HTML                    |
| 3   | 共享标签注入    | 将 `SECRET_TYPE_LABELS` 和 `SENSITIVE_TYPE_LABELS` 注入前端脚本 |
| 4   | HTML 输出       | 生成 `docs/butian/<日期>/security-report.html`                  |
| 5   | 浏览器打开控制  | 默认不自动打开；只有直接传 `--force-open` 才尝试打开            |

## CLI 用法

```bash
python3 visualize.py analysis.json
python3 visualize.py analysis.json output.html
python3 visualize.py --no-open analysis.json
```

## CLI 参数

| 参数            | 类型     | 必需 | 说明                                                           |
| --------------- | -------- | ---- | -------------------------------------------------------------- |
| `analysis_json` | 位置参数 | 是   | `analyze.py` 输出的 JSON 路径                                  |
| `output_html`   | 位置参数 | 否   | 输出 HTML 路径，默认 `docs/butian/<日期>/security-report.html` |
| `--no-open`     | flag     | 否   | 兼容旧参数；默认也不自动打开浏览器                             |
| `--force-open`  | flag     | 否   | 直接调用 `visualize.py` 时显式尝试打开浏览器                   |

## 环境变量

| 变量             | 值                                  | 效果                                      |
| ---------------- | ----------------------------------- | ----------------------------------------- |
| `BUTIAN_NO_OPEN` | `1` / `true` / `yes` / `on`         | 等同于 `--no-open`                        |
| `BUTIAN_EDITOR`  | `vscode` / `cursor` / `none` / `off` | 指定或关闭代码证据的编辑器协议检测        |

## 核心函数

### 序列化与转义

| 函数                           | 作用                                                         |
| ------------------------------ | ------------------------------------------------------------ |
| `json_for_script(value)`       | 序列化 JSON，并转义 `<script>` 中危险字符和 Unicode 行分隔符 |
| `script_asset_for_html(value)` | 转义 `</script`，防止内联 JS 被提前关闭                      |
| `style_asset_for_html(value)`  | 转义 `</style`，防止内联 CSS 被提前关闭                      |

### 路径与打开策略

| 函数                                 | 作用                                                                |
| ------------------------------------ | ------------------------------------------------------------------- |
| `default_output_path(analysis_path)` | 返回 `docs/butian/<日期>/security-report.html`                      |
| `open_decision(args, output_path)`   | 默认不打开；仅 `--force-open` 且未被 `--no-open`/环境变量禁止时打开 |
| `skipped_open_message(reason)`       | 输出未打开报告的中文原因                                            |
| `open_report(path)`                  | macOS/Windows/Linux/WSL 跨平台打开 HTML                             |
| `spawn_open_command(cmd)`            | 后台启动浏览器命令，不阻塞脚本                                      |
| `editor_config()`                    | 注入代码证据“编辑”按钮所需的编辑器协议和系统兜底命令                |

## 模板注入流程

```text
templates/report.html
  ├─ __REPORT_CSS__  <- templates/report.css
  ├─ __REPORT_DATA__ <- analysis.json
  └─ __REPORT_JS__   <- templates/report.js（已注入共享中文标签和编辑器配置）
```

生成时会检查所有 `__REPORT_*__` 占位符是否已替换；若仍有残留，直接失败，避免输出损坏 HTML。

## HTML 章节

当前 HTML 按以下顺序渲染：

1. 概览：项目、生态、依赖数、最高风险等级、风险项分布、路径、分支、来源。
2. 报告总结：TL;DR、说明、优先级建议、能力边界。
3. 仓库安检：凭证与敏感文件、`.gitignore`、GitHub Actions、依赖配置与维护、IaC/容器。
4. 当前风险：已确认依赖风险表格和可展开详情。
5. 过期依赖：版本维护信号列表。
6. 优先处理：red 行动项。
7. 待确认事项：非凭证类 yellow 行动项。
8. 扫描错误：仅有错误时显示。

空章节会按场景隐藏，避免页面出现“没有内容但占空间”的孤立卡片。

## 当前风险渲染

`renderVulnTable(DATA.vulns)` 负责当前风险表。

| 规则     | 说明                                                         |
| -------- | ------------------------------------------------------------ |
| 排序     | 按严重度降序，再按包名/版本等稳定规则                        |
| 默认展示 | 最多 7 条风险行                                              |
| 展开按钮 | 超过 7 条时显示 `余下 N 项`                                  |
| 详情展开 | 每条有增强信息的风险行支持点击、Enter、Space 展开            |
| 安全编号 | 只展示 CVE 并链接到 cve.org；无 CVE 时显示 `-`               |
| 修复版本 | 只展示高于当前版本的修复版本，用 chip 列表展示，多个版本换行 |
| 详情文案 | `plainRiskStory()` 输出普通人可读但不夸大的描述              |

详情面板可展示：

| 内容          | 来源                                           |
| ------------- | ---------------------------------------------- |
| 关键信号      | EPSS、CVSS、CWE、KEV、公开时间                 |
| 漏洞描述      | `cve_enrichments[].description`                |
| 发布时间      | `nvdPublishedAt`                               |
| 攻击条件      | CVSS vector 的 AV/AC/PR/UI                     |
| 影响维度      | CVSS vector 的 C/I/A                           |
| EPSS 利用预测 | `epss`、`epssPercentile`、`epssScoreDate`      |
| CISA KEV      | `kevListed`、`kevDueDate`、`kevRequiredAction` |
| 处理建议      | 修复版本 + 复扫和兼容性验证提醒                |

详情文案必须遵守“专业但保守”的口径：优先使用 advisory 摘要中的明确类型；影响描述使用“可能”“如果项目依赖/使用该能力”；信息不足时提示按公告确认，不自行编造攻击链。

## 仓库安检渲染

`renderHygiene(DATA.hygiene)` 消费以下字段：

| 字段                | HTML 展示                                                  |
| ------------------- | ---------------------------------------------------------- |
| `tracked_secrets`   | 凭证与敏感文件分组；文件位置、中文密钥类型、预览或代码证据 |
| `sensitive_tracked` | 凭证与敏感文件分组；文件路径和中文敏感文件类型             |
| `gitignore_missing` | 摘要中提示建议补充的规则，最多直接列出 8 条                |
| `workflow_checks`   | GitHub Actions 工作流安全卡片，最多展示 8 条               |
| `repository_checks` | 依赖配置与维护卡片，最多展示 8 条                          |
| `iac_checks`        | IaC / 容器 / 部署配置卡片，最多展示 8 条                   |

如果仓库安检没有任何可展示项，HTML 隐藏整个 `仓库安检` 章节。若使用 `--skip-hygiene`，章节会显示跳过事实、影响和重新扫描建议，而不是给出通过结论。

### 凭证类事项合并

`yellow` 中 `type == "secret_exposure"` 的事项会合并到 `仓库安检 / 凭证与敏感文件`，不再出现在底部 `待确认事项`。这样 `.env.example:17` 这类凭证确认项和代码证据放在同一处，减少重复阅读。

非凭证类 yellow 项仍在 `待确认事项` 中展示。

### 代码证据块

当 finding 带有 `code_context` 时，HTML 渲染为代码块：

| 元素       | 说明                                                  |
| ---------- | ----------------------------------------------------- |
| 左上角语言 | 由文件名/扩展名推断，例如 `ENV`、`JavaScript`、`YAML` |
| 右上角按钮 | `编辑`，优先用 VS Code/Cursor 协议打开文件位置；没有协议时复制系统兜底命令 |
| 行号       | `code_context[].line`                                 |
| 高亮       | `code_context[].match == true` 的行                   |
| 内容       | `code_context[].content`，是否脱敏由扫描阶段决定      |

代码块最多展示 3 行。命中首行时展示前 3 行，命中末行时展示最后 3 行；命中在中间时只保留上一行、命中行和下一行。旧报告如果带有更多 `code_context` 行，前端也会按同一规则裁剪，避免凭证证据块过长。

## 过期依赖渲染

`renderOutdated(DATA.outdated)` 只在存在可升级版本时渲染。无过期依赖时隐藏整个章节。

HTML 不显示建议列，只显示包名和版本流：

```text
package-name    current -> latest
```

响应式规则：

| 视口     | 默认展示              |
| -------- | --------------------- |
| 桌面双列 | 最多 7 行，即 14 个包 |
| 移动单列 | 最多 7 个包           |

超过默认数量时显示 `余下 N 项`。版本号允许换行，不用省略号截断，避免长版本串显示不完整。

## 优先处理与待确认事项

| 章节         | 来源              | 展示                                           |
| ------------ | ----------------- | ---------------------------------------------- |
| `优先处理`   | `red`             | 折叠卡片，包含为什么要关注、可能影响、建议动作 |
| `待确认事项` | 非凭证类 `yellow` | 折叠卡片，包含为什么要关注、可能影响、建议动作 |

凭证类 yellow 项已经移动到仓库安检；如果页面底部仍出现凭证类 `待确认事项`，应视为回归。

## 扫描错误

`DATA.errors` 非空时，HTML 展示：

```text
扫描过程中遇到以下问题：
[step] message
```

错误不参与“通过”判断。API 失败、包管理器失败、跳过项必须保留可见线索。

## 浏览器打开策略

```text
macOS    -> open <path>
Windows  -> os.startfile(<path>)
Linux    -> xdg-open / gio open / wslview
Fallback -> webbrowser.open_new_tab(file://...)
```

默认不会自动打开浏览器；`--force-open` 只作为直接调试 `visualize.py` 时的显式开关。`--no-open` 或 `BUTIAN_NO_OPEN=1` 会明确打印跳过原因。

## 验收命令

```bash
python3 -m unittest tests.butian.test_visualize
python3 -m unittest tests.butian.test_report_assets
node --check butian/templates/report.js
git diff --check
```

涉及视觉或文案验收时，应重新生成真实报告并检查最新 run：

```bash
python3 butian/scripts/run_audit.py --no-open /path/to/project
```

不要用旧的 `.butian/<run>` HTML 判断当前代码。

## 设计要点

- **自包含**：HTML 内联所有 CSS、JS 和数据。
- **安全注入**：JSON、CSS、JS 都做必要转义。
- **标签一致**：密钥和敏感文件中文标签来自 `labels.py`。
- **可读优先**：风险详情面向普通读者，但不能夸大或编造影响。
- **响应式稳定**：当前风险和过期依赖在低分辨率下仍遵守折叠数量。
- **交互可键盘操作**：当前风险详情支持点击、Enter、Space。
- **跳过不等于通过**：跳过仓库安检或依赖扫描时，页面必须说明能力边界。
