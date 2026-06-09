# Butian 单元测试矩阵

## 概览

本页记录 `butian/scripts` 下每个 Python 脚本对应的测试文件、主要覆盖点和重点边界。它和 `tests/butian/test_scripts_inventory.py` 一起作为覆盖守护：新增脚本必须补测试声明，行为脚本必须补文档页。

## 脚本到测试映射

| 脚本                 | 测试文件                                                | 核心覆盖                                                                           |
| -------------------- | ------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `__init__.py`        | `test_scripts_inventory.py`                             | 包初始化文件纳入脚本清单，避免新增脚本漏登记                                       |
| `analyze.py`         | `test_analyze.py`                                       | 严重度标准化、风险排序、红黄绿分组、摘要、修复项、嵌套依赖上下文                   |
| `detect.py`          | `test_detect.py`                                        | lockfile 识别、项目根发现、preflight 输出、自定义 output、工作区准备               |
| `finding_utils.py`   | `test_finding_utils.py`, `test_repo_checks.py`          | 文件遍历、排除目录、读取容错、行号定位、证据截断、finding 规范化、去重             |
| `fix.py`             | `test_fix.py`                                           | 修复项提取、包管理器命令生成、npm 父依赖计划、overrides、Dependabot 配置创建、失败退出码 |
| `iac_checks.py`      | `test_iac_checks.py`                                    | Dockerfile、Compose、Kubernetes、Terraform 规则和证据行号                          |
| `labels.py`          | `test_labels.py`                                        | 标签覆盖扫描器类型、中文展示名、report/analyze 共享同一字典                        |
| `repo_checks.py`     | `test_repo_checks.py`                                   | GitHub remote 判定、Dependabot 全生态建议、lockfile 缺失、安装脚本风险、registry token/TLS/source 检查 |
| `report.py`          | `test_report.py`, `test_report_assets.py`               | Markdown 表格转义、CVE/GHSA 链接、hygiene 渲染、空状态、模板资产一致性             |
| `run_audit.py`       | `test_run_audit.py`                                     | 子命令编排、首次扫描 Markdown、最终报告、跳过逻辑、失败传播                        |
| `scan.py`            | `test_scan.py`, `test_scan_helpers.py`, `test_cache.py` | 生态解析、lockfile 解析、密钥扫描、敏感文件、缓存、API 合并、CLI 行为              |
| `server_analyze.py`  | `test_server_analyze.py`                                | 服务器已确认风险、Docker 旧标签维护建议、敏感公网端口、错误合并                    |
| `server_collect.py`  | `test_server_collect.py`                                | 只读 SSH 命令白名单、可选 Docker 元数据、命令失败保留、离线 inventory              |
| `server_inventory.py` | `test_server_inventory.py`                             | Linux 发行版识别、包清单解析、内核包匹配、监听端口、Docker 标签解析                |
| `server_match.py`   | `test_server_match.py`                                  | OSV 发行版包查询、source package 查询、详情公告、CVE 富化、不支持 ecosystem 说明   |
| `visualize.py`       | `test_visualize.py`, `test_report_assets.py`            | JSON/HTML 转义、资产内联、标签注入、占位符校验、HTML 报告交互、浏览器打开策略      |
| `workflow_checks.py` | `test_workflow_checks.py`                               | GitHub Actions permissions、trigger、checkout、远程脚本、不可信上下文、runner 风险 |

## 详细覆盖说明

### `analyze.py`

- 输入覆盖：空扫描、仅仓库安检、完整依赖扫描、有错误的扫描、含过期依赖的扫描。
- 风险覆盖：critical/high/medium/low/info、未知严重度、缺失 fixed version、多个 advisory ID。
- 依赖覆盖：直接依赖、嵌套依赖、父依赖版本范围、残留依赖指导。
- 输出覆盖：`risk_summary`、`red`、`yellow`、`green`、`summary.priority`、`dependency_fix_items`。

### `detect.py`

- 输入覆盖：根目录、子目录、`--no-root-discovery`、自定义输出路径。
- 行为覆盖：存在 lockfile 时推荐 `full_dependency_scan`，不存在时推荐 `hygiene_only`。
- 产物覆盖：`preflight.json` 文件写入、stdout JSON、run 目录、assets/content 目录。

### `finding_utils.py`

- 路径覆盖：正常相对路径、跨盘符或 `relpath` 失败回退。
- 文件覆盖：UTF-8、无效 UTF-8、缺失文件、大文件跳过。
- 遍历覆盖：suffix、name、suffix+name、默认排除目录、自定义排除目录、`max_files`。
- schema 覆盖：severity/confidence 兜底、空字段默认值、额外字段过滤、证据长度上限。

### `fix.py`

- 策略覆盖：`fixed`/`minimal`、`latest`、`parent-upgrade`、`force-residual`。
- 生态覆盖：npm、pnpm、yarn、PyPI、Go、Cargo。
- npm 覆盖：lockfile 父链、根依赖识别、dedupe 命令、无法定位父依赖时的 overrides。
- 失败覆盖：单条命令失败、多条命令部分失败、无可修复项、未知策略。

### `iac_checks.py`

- Docker 覆盖：`latest` 标签、缺少非 root `USER`、远程脚本管道执行、`ADD` 远程 URL、明文 secret 环境变量。
- Compose 覆盖：`privileged`、Docker socket、敏感端口暴露、明文 secret。
- Kubernetes 覆盖：Secret 明文、privileged、hostPath、hostNetwork、root 运行。
- Terraform 覆盖：state/tfvars、敏感端口公网开放。

### `labels.py`

- 覆盖 `scan.SECRET_REGEXES` 的所有 secret type。
- 覆盖 `scan.SENSITIVE_FILE_PATTERNS` 的所有 sensitive file type。
- 断言标签非空、key 是稳定机器标识、展示层 helper 对未知类型有回退。

### `repo_checks.py`

- Dependabot 覆盖：GitHub remote + 官方支持生态时提示缺失配置；`.github/` 存在但没有 GitHub remote 时不提示；全量官方 `package-ecosystem` 映射可生成配置；workflow action 未纳入维护；已有配置时不重复提醒。
- 供应链覆盖：manifest 缺 lockfile、install/postinstall 脚本下载远程脚本、base64 解码执行。
- registry 覆盖：`.npmrc`/pip/poetry/cargo/go 配置中的 token、password、secret、TLS 降级和私有源提醒。

### `report.py`

- 表格覆盖：竖线、反引号、换行、空值和列表值转义。
- 渲染覆盖：摘要、漏洞表、仓库安检、过期依赖、人工确认事项、扫描错误、下一步。
- 兼容覆盖：缺字段的旧 analysis、仅 hygiene 模式、无风险项模式。
- 展示分工覆盖：Markdown 保留归档表格和人工确认事项；HTML 凭证类待确认项合并进仓库安检。

### `run_audit.py`

- 编排覆盖：按顺序调用 detect、scan、analyze、report、visualize。
- 首扫覆盖：生成 Markdown 和 HTML，允许自动打开。
- 复扫覆盖：中间复扫跳过 Markdown，`--final-report` 生成最终 Markdown。
- 失败覆盖：任一子命令失败时退出非零，并保留已生成路径提示。

### `scan.py`

- 本地扫描覆盖：密钥正则、entropy、误报过滤、敏感文件跟踪、`.gitignore` 建议。
- 生态覆盖：npm、pnpm、yarn、pip、pipenv、poetry、uv、Go、Cargo。
- API 覆盖：OSV batch、NVD、CISA KEV、EPSS、缓存命中/过期/损坏。
- CLI 覆盖：`--skip-hygiene`、`--skip-outdated`、`--include-packages`、`--follow-symlinks`、`--api-concurrency`。

### `server_collect.py`

- 命令覆盖：`/etc/os-release`、`uname -r`、dpkg/rpm/apk 包清单、`ss`/`netstat` 监听端口。
- 安全覆盖：命令白名单只读，不包含 install、upgrade、restart、sudo；可选 Docker 只读取 `docker version` 和 `docker ps` 元数据。
- 错误覆盖：单条命令失败写入 `errors`，不把失败解释成没有风险；离线 inventory 可读写 round-trip。

### `server_inventory.py`

- 发行版覆盖：Ubuntu、Debian、Alpine、RHEL、Rocky、AlmaLinux、CentOS Stream、SUSE/openSUSE、Amazon Linux、Oracle Linux；国产或冷门 `ID_LIKE` 不自动放行。
- 包解析覆盖：dpkg source package、rpm、apk、内核包与 `uname -r` 关联。
- 暴露面覆盖：TCP `LISTEN`、UDP `UNCONN`、公网地址判断、敏感服务端口。
- Docker 覆盖：只基于明确镜像名和版本标签提示旧标签，`latest`、custom tag、无版本标签不生成风险。

### `server_match.py`

- 查询覆盖：只对 OSV 支持的 `Ubuntu:*`、`Debian:*`、`Alpine:*` 发行版包坐标查询。
- 证据覆盖：querybatch 只作为 ID 命中来源；必须再调用详情接口获取完整 OSV 公告后，才能提取 CVE、fixed version、affected 坐标和摘要。
- 包名覆盖：Debian/Ubuntu 二进制包优先用 `source_name` 查询，报告保留实际安装包名和 source package。
- 缺口覆盖：不支持的 OSV ecosystem 写入 `errors`，不发起模糊查询，也不能解释为没有漏洞。

### `server_analyze.py`

- 风险覆盖：只保留 `confidence=confirmed` 的服务器风险进入 `server_issues`。
- 维护覆盖：Docker 明确旧标签和高敏感服务公网监听进入 `server_maintenance`，不等同于 CVE。
- 错误覆盖：资产解析错误和漏洞源错误合并保留，供报告和终端摘要展示。

### `visualize.py`

- 转义覆盖：`</script>`、`</style>`、HTML 特殊字符、Unicode 行分隔符。
- 注入覆盖：`__REPORT_DATA__`、`__REPORT_CSS__`、`__REPORT_JS__`、共享标签 JSON。
- 打开覆盖：`--no-open`、`BUTIAN_NO_OPEN`、首次扫描标记、不同平台 opener fallback。
- 当前风险覆盖：默认 7 条风险行、`余下 N 项`、详情行 click/Enter/Space 展开、只展示高于当前版本的修复版本 chip、HTML 表格只展示 CVE 编号。
- 详情文案覆盖：SSRF、URL 路径/主机规范化、middleware/proxy bypass、DoS、buffer bounds、header/cookie injection、IP restriction、cache leakage/cache poisoning、XSS/HTML/CSS injection、JWT 时间声明等准确描述。
- 仓库安检覆盖：空状态隐藏、`--skip-hygiene` 显示跳过说明、凭证代码块语言/复制按钮/行号/命中行、凭证类 yellow 项并入 `凭证与敏感文件`。
- 过期依赖覆盖：无数据隐藏章节；桌面双列默认 7 行、移动单列默认 7 项；长版本号不省略；按钮显示 desktop/mobile 不同余项数量。

### `workflow_checks.py`

- permissions 覆盖：`write-all`、缺显式 permissions、最小权限建议。
- trigger 覆盖：`pull_request_target`、高风险 trigger 和 checkout 组合。
- run 覆盖：不可信上下文进入 shell、远程脚本管道执行。
- runner 覆盖：PR 场景使用 self-hosted runner。

## 推荐验证命令

```bash
python3 -m unittest tests.butian.test_scripts_inventory -v
python3 -m unittest tests.butian.test_finding_utils tests.butian.test_labels -v
python3 -m unittest discover -s tests -v
python3 -m py_compile butian/scripts/*.py
node --check butian/templates/report.js
git diff --check
```

## 维护检查清单

1. 改脚本前先找对应测试文件，新增行为先写失败测试。
2. 修改输出 schema 时同步更新 `analyze.py`、`report.py`、`visualize.py` 的兼容测试。
3. 修改 report 文案时同时检查 Markdown 和 HTML 两端；HTML 详情文案还要检查真实 `.butian/<run>/content/security-report.html`。
4. 修改本地规则时同步检查 `finding_utils.py` schema 和 `testing-matrix.md`。
5. 修改 CLI 参数时补 `parse_args` 和主流程测试。
