# report.py / report.js 报告输出契约

> 相关源码：`butian/scripts/report.py`、`butian/templates/report.md`、`butian/templates/report.js`

## 概览

报告生成两种面向人的输出：

| 产物              | 路径                                                | 定位                                                                           |
| ----------------- | --------------------------------------------------- | ------------------------------------------------------------------------------ |
| HTML 交互报告     | `<project>/docs/butian/<日期>/security-report.html` | 适合在浏览器中验收；展示更完整的解释、折叠详情、代码证据、tooltip 和响应式布局 |
| Markdown 审计报告 | `<project>/docs/butian/<日期>/security-report.md`   | 适合归档、PR 讨论、复制到文档系统；保留表格化事实和修复目标                    |

两端共用 `analysis.json`。`report.py` 负责 Markdown，`visualize.py` 把 `analysis.json`、`report.css`、`report.js` 内联到 HTML。报告层只做展示和兼容字段归一化，不重新计算漏洞数量、严重度或修复版本。

## 顶部元信息

Markdown 固定展示：

```markdown
# 安全扫描报告

- 项目：<project.name>
- 路径：`<project.path>`
- 生成时间：<generated_at>
- 扫描耗时：<scan_seconds> 秒
```

HTML 顶部展示同一批运行信息，并额外展示：

| 字段                                       | HTML 展示                                                    |
| ------------------------------------------ | ------------------------------------------------------------ |
| `risk_summary`                             | 风险等级、风险项分布条、紧急/高风险/中风险/低风险/待确认数量 |
| `project.total_packages` / `package_count` | 依赖数                                                       |
| `project.ecosystems`                       | 生态                                                         |
| `project.git_branch`                       | 分支                                                         |
| `project.lockfiles`                        | 来源                                                         |

空状态不能写成“绝对安全”。无风险时只能表达“本次未命中已确认风险项”或“当前检查未发现”。

## 报告总结

Markdown `render_summary()` 输出：

- `TL;DR`
- `详细说明`
- `扫描范围`，仅 `hygiene_only` 模式出现
- `能力边界`
- `优先级建议`

HTML `renderReportSummary()` 输出：

- `TL;DR` 小结
- 一段面向普通读者的扫描说明
- 优先级建议列表
- 能力边界说明

HTML 会清理老旧或过度技术化的摘要文字，例如去掉 “0 个仓库安检项” 这类噪音，过期依赖统一表达为维护信号。能力边界必须保留，避免用户把依赖扫描当成代码审计、渗透测试或部署安全评估。

## 当前风险

### Markdown 展示

Markdown 章节名是 `当前风险`。只在完整依赖扫描中展示风险表；`hygiene_only` 模式会明确说明未执行依赖漏洞扫描。

表格列固定为：

```markdown
| 影响程度 | 依赖名称 | 当前版本 | 修复版本 | 安全编号 |
```

字段规则：

| 列       | 来源/规则                                                |
| -------- | -------------------------------------------------------- |
| 影响程度 | `severity_label()`：紧急、高风险、中风险、低风险、待确认 |
| 依赖名称 | `package` 或 `name`                                      |
| 当前版本 | `version`                                                |
| 修复版本 | `fixed_versions`，无明确版本时显示 `待确认`              |
| 安全编号 | CVE 链接到 `cve.org`，GHSA/其他公告链接到 OSV            |

Markdown 只保留修复决策最常用的字段，不展开 HTML 里的详情、长 tooltip、攻击条件和代码级互动。

### HTML 展示

HTML 章节名是 `当前风险`。表格列固定为：

| 列       | 展示规则                                             |
| -------- | ---------------------------------------------------- |
| 影响程度 | 彩色中文 badge：紧急、高风险、中风险、低风险、待确认 |
| 依赖名称 | 包名，带 `title` 防止窄屏截断后不可读                |
| 当前版本 | `version`                                            |
| 修复版本 | 只展示高于当前版本的修复版本 chip；多个版本自动换行  |
| 安全编号 | 只展示 CVE，可点击到 cve.org；无 CVE 时显示 `-`      |
| 详情     | 面向普通读者的准确风险描述 + 简短升级建议            |

默认只展示 7 条风险行；超过 7 条时出现 `余下 N 项` 按钮。展开后仍使用同一表格结构，不改变列含义。低分辨率下也遵守 7 行约束。

每条风险如果有增强信息，会生成可点击/键盘可操作的详情行：

| 详情内容      | 来源                                                    |
| ------------- | ------------------------------------------------------- |
| 关键信号      | EPSS、CVSS、CWE、KEV、公开时间                          |
| 漏洞描述      | `cve_enrichments[].description`                         |
| 发布时间      | `nvdPublishedAt`                                        |
| 攻击条件      | CVSS vector 的 AV/AC/PR/UI                              |
| 影响维度      | CVSS vector 的 C/I/A                                    |
| EPSS 利用预测 | `epss`、`epssPercentile`、`epssScoreDate`               |
| CISA KEV      | `kevListed`、`kevDueDate`、`kevRequiredAction`          |
| 处理建议      | 修复版本 + “升级后重新扫描，并完成核心流程兼容性验证。” |

### HTML 详情文案映射

`plainRiskStory()` 优先使用官方公告摘要的明确关键词，CWE 只做辅助，避免把不确定内容写成确定攻击链。当前支持的主要映射如下：

| 识别线索                                                     | 展示口径                                                             |
| ------------------------------------------------------------ | -------------------------------------------------------------------- |
| `server-side request forgery` / `ssrf` + `WebSocket upgrade` | WebSocket upgrade 场景可能错误转发服务端请求                         |
| `path traversal` / CWE-22 系列                               | URL 路径规范化可能判断不严；如果用于白名单或前缀校验，限制可能被绕过 |
| `host confusion` / authority delimiter                       | URL 主机信息规范化可能改变原始目标                                   |
| `middleware` + `bypass`                                      | 特定路由场景可能绕过中间件或代理检查                                 |
| `large numeric range` + `max`                                | 展开超大数字范围可能先消耗大量内存和 CPU                             |
| `connection exhaustion`                                      | 特定请求处理场景可能长时间占用连接                                   |
| DoS / resource exhaustion                                    | 处理特殊输入时可能大量占用资源                                       |
| buffer / bounds / memory                                     | 调用方传入输出缓冲区时可能缺少边界检查                               |
| `Set-Cookie` / cookie injection / header injection           | 生成响应头时可能没有充分校验调用方传入的字段                         |
| XSS / HTML injection / CSS declaration injection / CWE-79    | 输出脚本、样式或 HTML 时可能没有充分转义不可信输入                   |
| cache leakage / Vary Authorization / Vary Cookie             | 缓存响应可能没有正确区分 Authorization 或 Cookie                     |
| redirect + cache-poison                                      | 缓存跳转响应可能没有正确区分请求上下文                               |
| cache poisoning / cache-busting                              | 缓存键或缓存结果可能没有正确区分请求上下文                           |
| IP Restriction / non-canonical IPv6 / static deny            | 非标准 IPv6 地址解析可能与访问限制规则不一致                         |
| NumericDate / JWT exp/nbf/iat                                | JWT 时间声明校验可能不够严格                                         |
| JWT Authorization scheme / Bearer                            | Authorization 头可能未严格限制 Bearer 方案                           |
| prototype pollution                                          | 对象配置键名可能被攻击者控制并污染原型                               |
| development server + read response                           | 开发服务器可能接受非预期网页请求并返回响应内容                       |
| app.mount / mount prefix / percent-encoded routing           | 挂载子应用时编码路径处理可能不一致                                   |

兜底文案必须保守：`当前版本命中已公开安全公告。报告未提供足够细分类型，建议先按公告确认项目是否调用受影响功能。` 正常报告中应尽量减少兜底命中。

禁止回退到这些容易误导的旧表达：

- `这个版本`
- `当前版本存在...`
- `读取服务器上不该公开的文件`
- `关键数据被覆盖`
- 把路径规范化、缓存或 header 问题直接写成更重的攻击结果

## 仓库安检

### Markdown 展示

Markdown 章节名是 `仓库安检`，包含：

| 分组                      | 展示                                              |
| ------------------------- | ------------------------------------------------- |
| 硬编码密钥                | 数量摘要 + `位置 / 类型 / 可信度 / 证据预览` 表格 |
| 敏感文件跟踪              | 数量摘要 + `文件 / 类型 / 大小` 表格              |
| `.gitignore`              | 建议补充的规则                                    |
| GitHub Actions 工作流安全 | 结构化 finding 表格                               |
| 依赖配置与维护            | 结构化 finding 表格                               |
| IaC / 容器 / 部署配置     | 结构化 finding 表格                               |

GitHub Actions 工作流安全和 IaC / 容器 / 部署配置会保留证据列：

```markdown
| 等级 | 位置 | 检查项 | 依据 | 处理 |
```

依赖配置与维护只保留处理动作，不输出依据列：

```markdown
| 等级 | 位置 | 检查项 | 处理 |
```

Markdown 当前仍保留 `需要人工确认的事项` 章节，方便归档时看到 red/yellow 行动项的完整文本。凭证类事项可能同时在 `仓库安检` 和 `需要人工确认的事项` 中出现；HTML 会做去重合并。

### HTML 展示

HTML 章节名是 `仓库安检`。如果没有密钥、敏感文件、缺失规则或结构化本地 finding，整个章节隐藏，不显示空卡片。

HTML 内部分组：

| 分组                      | 展示规则                                                                                     |
| ------------------------- | -------------------------------------------------------------------------------------------- |
| 凭证与敏感文件            | 展示硬编码凭证、凭证类 yellow 项、敏感文件；最多展示 5 条同类基础项，超出显示 `…及其他 N 处` |
| GitHub Actions 工作流安全 | 最多展示 8 条卡片                                                                            |
| 依赖配置与维护            | 最多展示 8 条卡片                                                                            |
| IaC / 容器 / 部署配置     | 最多展示 8 条卡片                                                                            |
| `.gitignore`              | 在摘要中展示建议补充规则，最多直接列 8 条                                                    |

凭证类 yellow 项会移动到 `仓库安检 / 凭证与敏感文件` 中，不再出现在底部 `待确认事项`。非凭证类 yellow 项仍保留在 `待确认事项`。

### 凭证代码证据

当 finding 带有 `code_context` 时，HTML 会渲染代码块：

| 元素           | 说明                                                                 |
| -------------- | -------------------------------------------------------------------- |
| 左上角语言     | 根据文件名/扩展名推断，例如 `ENV`、`JavaScript`、`YAML`              |
| 右上角编辑按钮 | 优先用 VS Code/Cursor 协议打开文件位置；没有协议时复制系统兜底命令   |
| 行号           | 使用 `code_context[].line`                                           |
| 命中行         | `code_context[].match == true` 时高亮                                |
| 内容           | 展示 `code_context[].content` 原文；是否脱敏取决于扫描阶段提供的内容 |

例如 `.env.example:17` 命中时，HTML 应展示 16-18 行上下文，方便用户定位。该代码块默认随凭证卡片折叠；展开卡片后查看。

如果没有 `code_context`，HTML 会退回展示 `preview`。

## 过期依赖

### Markdown 展示

Markdown 章节名是 `过期依赖`。只有存在明确可升级版本时才渲染表格；无过期依赖时写：

```markdown
没有检测到明确的过期依赖，或当前包管理器没有返回可用结果。
```

表格列固定为：

```markdown
| 依赖名称 | 当前版本 | 最近版本 | 建议 |
```

Markdown 的 `建议` 列保留维护建议，因为它更适合归档和修复排期。

### HTML 展示

HTML 章节名是 `过期依赖`。如果没有可展示的过期依赖，整个章节隐藏。

HTML 不展示建议列，只展示紧凑的版本流：

```text
package-name    current → latest
```

布局规则：

| 视口     | 默认展示                  |
| -------- | ------------------------- |
| 桌面双列 | 最多 7 行，也就是 14 个包 |
| 移动单列 | 最多 7 个包               |

超过默认数量时显示 `余下 N 项`，展开后显示剩余项。版本号允许换行，不用省略号截断，避免 `uuid 13.0.0 → 13.0.2 / 14.0.0` 这类内容显示不完整。

## 优先处理 / 待确认事项

HTML 仍可能展示两个折叠卡片区：

| 章节         | 来源              | 展示规则                                                                 |
| ------------ | ----------------- | ------------------------------------------------------------------------ |
| `优先处理`   | `red`             | 高优先级本地仓库安检项等；使用 `为什么要关注 / 可能影响 / 建议动作` 三段 |
| `待确认事项` | 非凭证类 `yellow` | 需要研发判断的事项；凭证类 yellow 已合并到仓库安检                       |

这些卡片是补充行动项，不替代 `当前风险` 表格。用户前面要求删除的三段说明只针对凭证代码块下方的重复说明，不代表所有 red/yellow 卡片都删除。

Markdown 的 `需要人工确认的事项` 仍会输出 red + yellow 的完整说明，便于归档和审计复核。

## 扫描错误

Markdown：

- 没有错误时输出 `没有记录到扫描错误。`
- 有错误时按 `step` 和 `message` 列表展示。

HTML：

- 没有错误时隐藏错误区。
- 有错误时展示 `扫描过程中遇到以下问题`，逐行列出 `[step] message`。

扫描错误、API 失败、跳过项不能当成 0 风险处理。

## 下一步建议

Markdown `下一步建议` 使用 `summary.priority`，并在存在依赖修复项时追加：

- 依赖修复后必须重新运行扫描。
- 如果复扫仍出现同名旧版本，可能是间接依赖被父包锁定，需要升级父依赖或处理 lockfile。

HTML 把主要建议放在 `报告总结` 和各风险详情的 `处理建议` 中，不单独渲染 `下一步建议` 章节。

## 跳过与空状态

| 场景             | Markdown                                     | HTML                                              |
| ---------------- | -------------------------------------------- | ------------------------------------------------- |
| `hygiene_only`   | 当前风险和过期依赖明确说明未执行依赖相关扫描 | 当前风险显示“扫描范围/结论口径”卡片；过期依赖隐藏 |
| `--skip-hygiene` | 仓库安检说明跳过                             | 仓库安检显示“事实/为什么要关注/建议动作”          |
| 无当前风险       | `未命中已确认的依赖风险项。`                 | 当前风险显示 0 项空状态                           |
| 无仓库安检项     | 保守空状态文字                               | 仓库安检整个章节隐藏                              |
| 无过期依赖       | 保守空状态文字                               | 过期依赖整个章节隐藏                              |
| 无扫描错误       | `没有记录到扫描错误。`                       | 错误区隐藏                                        |

## 验收要点

修改报告展示时至少验证：

```bash
python3 -m unittest tests.butian.test_report
python3 -m unittest tests.butian.test_report_assets
node --check butian/templates/report.js
git diff --check
```

涉及真实 HTML 验收时，重新运行：

```bash
python3 butian/scripts/run_audit.py --no-open /path/to/project
```

然后检查最新 `docs/butian/<日期>/security-report.html` 或 `security-report-final.html`，不要用旧日期目录判断新代码。

## 设计原则

- **事实优先**：先展示本地扫描和官方公告能证明的事实。
- **条件化表达**：涉及业务影响时使用“如果项目依赖/使用该能力”。
- **不夸大**：不把路径规范化、缓存、header 注入等问题写成更重的攻击结果。
- **双端一致但不强行相同**：HTML 适合交互验收，Markdown 适合归档；两者可以展示层级不同。Markdown 保留完整公告编号，HTML 当前风险表只保留 CVE；风险数量、升级建议和能力边界必须一致。
- **跳过不等于通过**：任何跳过、错误、API 失败都必须在报告中保留可见线索。
