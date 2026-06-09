# Butian 技术文档总览

## 概览

`butian` 是一个面向本地仓库的安全扫描 Skill。它把预检、依赖扫描、仓库安检、分析、Markdown 报告、HTML 可视化和可选修复拆成独立 Python 脚本，便于测试、复用和逐步排错。

这组文档覆盖 `butian/scripts` 下每个行为脚本，并说明测试入口、输入输出、边界和维护注意事项。新增脚本时需要同步补测试和文档，否则 `tests/butian/test_scripts_inventory.py` 会失败。

## Skill 场景化参考

公开发布后的 `butian/SKILL.md` 是轻量入口。详细内容按使用场景下沉到 `butian/references/`，减少普通扫描时的阅读负担。

| 场景 | 参考文件 | 说明 |
| ---- | -------- | ---- |
| 默认项目扫描 | `butian/references/project-scan.md` | 项目扫描范围、hygiene-only 口径、报告路径和分步调试 |
| Linux 服务器扫描 | `butian/references/server-scan.md` | 只读 SSH 边界、启用方式、Docker 元数据和服务器风险证据标准 |
| 修复交互 | `butian/references/repair-flow.md` | AskUserQuestion 选项、待确认动作队列、嵌套残留和最终验证 |
| 数据源和边界 | `butian/references/sources-and-limits.md` | OSV/NVD/CISA/EPSS、缓存、错误处理和非覆盖范围 |
| 报告契约 | `butian/references/report-contract.md` | analysis JSON、Markdown 和 HTML 报告输出契约 |

## 管线总览

| 步骤 | 脚本                                                                                  | 主要输入                 | 主要输出                                     | 说明                                                         |
| ---- | ------------------------------------------------------------------------------------- | ------------------------ | -------------------------------------------- | ------------------------------------------------------------ |
| 1    | `detect.py`                                                                           | 项目路径                 | `.butian/<run>/assets/preflight.json`        | 检测 lockfile、推荐扫描模式、准备本地工作区                  |
| 2    | `scan.py`                                                                             | 项目路径或 preflight     | `.butian/<run>/assets/scan.json`             | 本地仓库安检、依赖解析、OSV/NVD/CISA/EPSS 查询、过期依赖检查 |
| 2a   | `server_collect.py` / `server_inventory.py` / `server_match.py` / `server_analyze.py` | SSH 目标或离线 inventory | `.butian/<run>/assets/server-*.json`         | 可选 Linux 服务器只读采集、资产标准化、漏洞匹配和服务器分析  |
| 3    | `analyze.py`                                                                          | `scan.json`              | `.butian/<run>/assets/analysis.json`         | 标准化风险项、分红黄绿行动项、生成摘要和修复建议             |
| 4    | `report.py`                                                                           | `analysis.json`          | `docs/butian/security-report-*.md`           | 输出给人读的 Markdown 审计报告                               |
| 5    | `visualize.py`                                                                        | `analysis.json`          | `.butian/<run>/content/security-report.html` | 输出自包含 HTML 报告并按首次扫描策略打开                     |
| 6    | `fix.py`                                                                              | `analysis.json`          | 包管理器命令结果或配置文件                   | 用户确认后执行依赖升级策略或创建 Dependabot 配置             |
| 7    | `run_audit.py`                                                                        | 项目路径                 | 全链路产物                                   | 串联 detect、scan、analyze、report、visualize                |

## 脚本文档索引

| 脚本                  | 文档                              | 测试入口                                | 关注点                                                       |
| --------------------- | --------------------------------- | --------------------------------------- | ------------------------------------------------------------ |
| `analyze.py`          | `docs/butian/analyze.md`          | `tests/butian/test_analyze.py`          | 风险排序、摘要、依赖修复项、仓库安检归一化                   |
| `cache.py`            | `docs/butian/cache.md`            | `tests/butian/test_cache.py`            | 官方漏洞源本地缓存目录、读写和过期清理                       |
| `dependency_parsers.py` | `docs/butian/dependency_parsers.md` | `tests/butian/test_scan.py`             | 依赖生态检测、lockfile 解析、包坐标去重和来源汇总            |
| `detect.py`           | `docs/butian/detect.md`           | `tests/butian/test_detect.py`           | 项目根发现、lockfile 识别、preflight 输出                    |
| `finding_utils.py`    | `docs/butian/finding_utils.md`    | `tests/butian/test_finding_utils.py`    | finding schema、文件遍历、证据截断、去重                     |
| `fix.py`              | `docs/butian/fix.md`              | `tests/butian/test_fix.py`              | fixed/latest/parent-upgrade/force-residual/dependabot 策略   |
| `iac_checks.py`       | `docs/butian/iac_checks.md`       | `tests/butian/test_iac_checks.py`       | Docker、Compose、Kubernetes、Terraform 本地规则              |
| `labels.py`           | `docs/butian/labels.md`           | `tests/butian/test_labels.py`           | 密钥和敏感文件类型的中文标签                                 |
| `repo_checks.py`      | `docs/butian/repo_checks.md`      | `tests/butian/test_repo_checks.py`      | Dependabot、GitHub remote、lockfile、安装脚本、registry 配置 |
| `report.py`           | `docs/butian/report.md`           | `tests/butian/test_report.py`           | Markdown 渲染、表格转义、风险/仓库安检/过期依赖输出          |
| `run_audit.py`        | `docs/butian/run_audit.md`        | `tests/butian/test_run_audit.py`        | 全链路编排、首次扫描和复扫策略                               |
| `scan.py`             | `docs/butian/scan.md`             | `tests/butian/test_scan.py`             | 扫描 CLI、并行编排、密钥扫描、过期依赖和结果汇总              |
| `server_analyze.py`   | `docs/butian/server_analyze.md`   | `tests/butian/test_server_analyze.py`   | 服务器风险归并、Docker/端口维护建议、错误保留                |
| `server_collect.py`   | `docs/butian/server_collect.md`   | `tests/butian/test_server_collect.py`   | 只读 SSH 命令白名单、Docker 元数据、离线 inventory           |
| `server_inventory.py` | `docs/butian/server_inventory.md` | `tests/butian/test_server_inventory.py` | Linux 发行版、系统包、内核、监听端口和 Docker 解析           |
| `server_match.py`     | `docs/butian/server_match.md`     | `tests/butian/test_server_match.py`     | OSV 发行版包坐标、详情公告、CVE 富化和覆盖缺口               |
| `visualize.py`        | `docs/butian/visualize.md`        | `tests/butian/test_visualize.py`        | HTML 注入、资产内联、交互报告和浏览器打开策略                |
| `vulnerability_sources.py` | `docs/butian/vulnerability_sources.md` | `tests/butian/test_scan.py`        | OSV/NVD/CISA KEV/FIRST EPSS 查询、富化、缓存和风险信号合并    |
| `workspace.py`        | `docs/butian/workspace.md`        | `tests/butian/test_scan_helpers.py`     | 本地工作区、运行目录、项目根发现和扫描路径保护               |
| `workflow_checks.py`  | `docs/butian/workflow_checks.md`  | `tests/butian/test_workflow_checks.py`  | GitHub Actions 工作流安全规则                                |

## 产物目录

| 路径                                         | 内容                  | 生命周期                        |
| -------------------------------------------- | --------------------- | ------------------------------- |
| `.butian/<run>/assets/preflight.json`        | 预检结果              | 每次扫描生成                    |
| `.butian/<run>/assets/scan.json`             | 原始扫描结果          | 每次扫描生成                    |
| `.butian/<run>/assets/server-inventory.json` | 服务器原始采集结果    | 启用服务器扫描时生成            |
| `.butian/<run>/assets/server-assets.json`    | 服务器标准化资产      | 启用服务器扫描时生成            |
| `.butian/<run>/assets/server-vulns.json`     | 服务器漏洞匹配结果    | 启用服务器扫描时生成            |
| `.butian/<run>/assets/server-analysis.json`  | 服务器分析结果        | 启用服务器扫描时生成            |
| `.butian/<run>/assets/analysis.json`         | 分析结果              | 每次扫描生成                    |
| `.butian/<run>/content/security-report.html` | 自包含 HTML 报告      | 每次扫描生成                    |
| `.butian/<run>/logs/scan.log`                | DEBUG 日志            | `--verbose` 或 `--debug` 时生成 |
| `.butian/cache/`                             | OSV/NVD/EPSS/KEV 缓存 | 跨 run 复用                     |
| `docs/butian/security-report-*.md`           | Markdown 审计报告     | 首扫或最终复扫生成              |

## 测试策略

Butian 的测试以标准库 `unittest` 为主，不依赖真实外部服务。外部 API、包管理器命令、浏览器打开和时间相关行为通过 mock 或临时目录隔离。

推荐本地验证命令：

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile butian/scripts/*.py
node --check butian/templates/report.js
git diff --check
```

更细的覆盖矩阵见 `docs/butian/testing-matrix.md`。维护时先补最小失败测试，再改实现，最后跑对应脚本测试和完整 discover。

## 报告契约

`scan.py` 输出原始事实，`analyze.py` 负责解释和排序，`report.py` 与 `visualize.py` 只做展示层转换。完整输出合同见 [`report.md`](./report.md) 和 [`visualize.md`](./visualize.md)。核心规则：

- Markdown 偏归档和修复表格；HTML 偏交互验收和普通人可读解释。
- `当前风险`、`仓库安检`、`过期依赖` 是三类不同信号，不能混为同一种风险。
- HTML 当前风险默认只展示 7 条风险行，超过后显示 `余下 N 项`。
- HTML 过期依赖默认展示 7 行：桌面双列最多 14 个包，移动单列最多 7 个包。
- HTML 没有过期依赖或仓库安检项时隐藏对应章节，避免空卡片。
- 凭证类待确认项合并到 `仓库安检 / 凭证与敏感文件`；非凭证类 yellow 项才保留在底部 `待确认事项`。
- 风险详情文案必须基于 advisory 摘要和 CWE 线索，使用条件化表达，不夸大攻击结果。
- 空状态不能写成绝对安全，只能写成当前检查未发现。
- 扫描错误、API 失败和跳过项必须保留，不能当作 0 风险处理。

## 维护规则

新增或修改脚本时，需要同步检查四件事：

1. 是否已有针对该脚本的单元测试，且边界条件被覆盖。
2. 是否需要更新 `docs/butian/<script>.md`。
3. 是否需要更新 `docs/butian/testing-matrix.md`。
4. 是否影响 `run_audit.py` 的全链路编排或报告契约。
