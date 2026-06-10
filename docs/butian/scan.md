# scan.py 技术文档

> 源码路径：`butian/scripts/scan.py`

## 概览

`scan.py` 是安全扫描器的核心引擎，负责收集项目安全数据并输出结构化 JSON，供下游 `analyze.py` 和 `report.py` 消费。扫描过程不修改业务源码或依赖；只准备本地工作区、缓存和报告产物，并确保这些本地产物路径被项目忽略规则覆盖。

## 职责

| #   | 职责         | 说明                                                                                                                                              |
| --- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | 仓库安检     | `.gitignore` 状态、敏感文件跟踪、硬编码密钥扫描（113 个正则 + Shannon entropy 熵值分析）、GitHub Actions 工作流安全、依赖配置与维护、IaC/容器配置 |
| 2   | 依赖生态检测 | 识别 lockfile 类型，提取包名和版本号                                                                                                              |
| 3   | 漏洞查询     | 调用 OSV、NVD、CISA KEV、FIRST EPSS 四个官方数据源                                                                                                |
| 4   | 过期依赖检测 | 通过各语言包管理器获取最新版本信息                                                                                                                |

## 支持的生态

| 语言                    | 包管理器   | 依赖文件             |
| ----------------------- | ---------- | -------------------- |
| JavaScript / TypeScript | npm        | `package-lock.json`  |
| JavaScript / TypeScript | pnpm       | `pnpm-lock.yaml`     |
| JavaScript / TypeScript | yarn       | `yarn.lock`          |
| Python                  | pip        | `requirements.txt`   |
| Python                  | pipenv     | `Pipfile.lock`       |
| Python                  | poetry     | `poetry.lock`        |
| Python                  | uv         | `uv.lock`            |
| Go                      | go modules | `go.sum`             |
| Rust                    | cargo      | `Cargo.lock`         |
| PHP / Packagist         | Composer   | `composer.lock`      |
| Ruby / RubyGems         | Bundler    | `Gemfile.lock`       |
| Dart / Flutter Pub      | pub        | `pubspec.lock`       |
| Elixir / Erlang Hex     | mix        | `mix.lock`           |
| .NET / NuGet            | NuGet      | `packages.lock.json` |
| .NET / NuGet            | NuGet      | `packages.config`    |
| Maven/JVM               | Maven      | `pom.xml`            |

依赖漏洞查询只处理能从本地文件提取出**精确包名 + 精确版本**的应用依赖坐标。Maven/JVM 第一版只解析本地 `pom.xml` 中直接写明版本的依赖；`${...}` 属性、父 POM、BOM、profile 或版本范围无法本地确认时跳过，不做漏洞查询。

本轮新增的依赖漏洞生态不包含 Dockerfile、compose、Kubernetes、devcontainer、镜像/SBOM、OS/发行版包、系统包或系统安全公告生态扫描；这些不会被混进 lockfile / manifest 依赖漏洞查询。既有 IaC/容器本地静态规则仍只属于仓库安检，不等于镜像、SBOM 或系统包漏洞扫描。

## CLI 用法

```bash
python3 scan.py --preflight <preflight_json>    # 从 preflight 文件读取配置
python3 scan.py [project_path]                  # 自动检测项目根目录
python3 scan.py --no-root-discovery <path>      # 直接扫描给定路径
python3 scan.py --skip-outdated <path>          # 跳过过期依赖检查（更快）
python3 scan.py --allow-project-exec <path>     # 显式允许执行项目内工具做过期检查
python3 scan.py --skip-hygiene <path>           # 跳过仓库安检
python3 scan.py --include-packages <path>       # 在输出中包含完整包列表
python3 scan.py --max-secret-files 300 <path>   # 限制密钥扫描的文件数量
python3 scan.py --verbose                       # 输出详细日志到 stderr
python3 scan.py --debug                         # 输出调试级别日志
python3 scan.py --follow-symlinks               # 跟随符号链接扫描
```

## CLI 参数

| 参数                  | 类型 | 默认值 | 说明                                 |
| --------------------- | ---- | ------ | ------------------------------------ |
| `project_path`        | 位置 | `.`    | 项目路径                             |
| `--preflight`         | str  | —      | 复用 preflight JSON 文件             |
| `--output`            | str  | 自动   | 指定输出路径                         |
| `--no-root-discovery` | flag | false  | 不向上遍历查找项目根                 |
| `--skip-outdated`     | flag | false  | 跳过过期依赖检查                     |
| `--allow-project-exec` | flag | false  | 允许过期检查执行项目内工具，例如 `.venv/bin/python` |
| `--skip-hygiene`      | flag | false  | 跳过仓库安检                         |
| `--max-secret-files`  | int  | 500    | 限制密钥扫描的文件数量               |
| `--include-packages`  | flag | false  | 在输出中包含完整包列表               |
| `--verbose`           | flag | false  | 输出详细日志到 stderr（INFO 级别）   |
| `--debug`             | flag | false  | 输出调试级别日志到 stderr 和日志文件 |
| `--follow-symlinks`   | flag | false  | 跟随符号链接扫描（默认跳过）         |

## 核心常量

| 常量                             | 值                                                              | 用途                               |
| -------------------------------- | --------------------------------------------------------------- | ---------------------------------- |
| `OSV_QUERYBATCH_URL`             | `https://api.osv.dev/v1/querybatch`                             | OSV 批量查询端点                   |
| `OSV_VULN_URL_PREFIX`            | `https://api.osv.dev/v1/vulns/`                                 | OSV 单条漏洞端点                   |
| `NVD_CVE_API_URL`                | `https://services.nvd.nist.gov/rest/json/cves/2.0`              | NVD CVE 查询端点                   |
| `CISA_KEV_JSON_URL`              | `https://www.cisa.gov/.../known_exploited_vulnerabilities.json` | CISA 已知被利用漏洞目录            |
| `EPSS_API_URL`                   | `https://api.first.org/data/v1/epss`                            | EPSS 漏洞利用预测评分              |
| `BUTIAN_DIR`                     | `.butian`                                                       | 工作区目录名                       |
| `BUTIAN_ASSETS_DIR`              | `assets`                                                        | 工作区内的资产子目录               |
| `BUTIAN_GITIGNORE_EXTRA_ENTRIES` | `docs/butian/*/security-report*.md/html`                         | 除 `.butian/` 外额外忽略的生成报告 |
| `CACHE_DIR_NAME`                 | `cache`                                                         | 缓存子目录名                       |

## 关键函数

### 工作区管理

| 函数                                                    | 作用                                                                           |
| ------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `find_project_root(start_path)`                         | 向上遍历目录树，找到包含项目标记文件（`.git`、`package.json` 等）的根目录      |
| `ensure_butian_run(project_path, run_id)`               | 创建 `.butian/<run>/` 运行目录；默认 run id 为 `YYYYMMDD-HHMM`，重复时追加后缀 |
| `default_asset_path(project_path, filename, preflight)` | 返回默认的资产文件路径                                                         |
| `butian_gitignore_status(project_path)`                 | 返回本地产物忽略规则的状态，包含缺失项和已新增项                               |

### 日志系统

| 函数                                     | 作用                                               |
| ---------------------------------------- | -------------------------------------------------- |
| `setup_logging(verbose, debug, log_dir)` | 配置 `butian` logger，输出到 stderr 和可选日志文件 |

- 日志文件路径：`.butian/<run>/logs/scan.log`
- stderr 级别：默认 WARNING，`--verbose` → INFO，`--debug` → DEBUG
- 文件始终 DEBUG 级别
- Logger 名称：`butian`，避免重复添加 handler

### 本地缓存

| 函数                                         | 作用                         |
| -------------------------------------------- | ---------------------------- |
| `cache_dir(project_path, source)`            | 返回指定数据源的缓存目录路径 |
| `cache_read(cache_path, ttl_seconds)`        | 读取缓存（过期返回 None）    |
| `cache_write(cache_path, data, source, key)` | 写入缓存（含元数据）         |
| `cache_clean(project_path, ttl_seconds)`     | 清理过期缓存条目             |

- 缓存目录：`.butian/cache/{osv,nvd,epss,kev}/`（跨 run 共享）
- 缓存结构：`{"cached_at": "...", "ttl_seconds": 86400, "source": "osv", "key": "...", "data": {...}}`
- 默认 TTL：24 小时（86400 秒）
- CISA KEV 缓存已从 `/tmp/` 迁移到 `.butian/cache/kev/`

### 二进制文件 / 符号链接

| 函数                       | 作用                                           |
| -------------------------- | ---------------------------------------------- |
| `is_binary_file(filepath)` | 读取前 8KB 检测 NUL 字节，判断是否为二进制文件 |

- 符号链接：默认跳过，`--follow-symlinks` 时跟随
- 二进制文件：`scan_secrets()` 中自动跳过（在打开文件前检测）

### 仓库安检

| 函数                                               | 作用                                                                                                |
| -------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `scan_hygiene(project_path, max_secret_files)`     | 执行完整的仓库安检：gitignore、敏感文件跟踪、密钥扫描、GitHub Actions、依赖配置与维护、IaC/容器配置 |
| `scan_secrets(project_path, max_files, max_bytes)` | 正则模式匹配 + Shannon entropy 熵值分析，识别硬编码密钥                                             |
| `check_sensitive_tracked(project_path)`            | 检查被 git 跟踪的敏感文件（详见下方「敏感文件类型」）                                               |
| `check_gitignore(project_path, sensitive_tracked)` | 检查 `.gitignore` 是否覆盖了常见敏感文件模式                                                        |

新增本地规则模块：

| 模块                 | 作用                                                                                                                                                                                                                    |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `finding_utils.py`   | 统一 finding schema、文件读取、路径、行号、证据截断和去重工具；所有新增本地规则都通过它输出同一种结构                                                                                                                   |
| `workflow_checks.py` | 本地解析 `.github/workflows/*.yml` / `.github/workflows/*.yaml`，检查过宽 permissions、缺少显式最小权限边界、危险 trigger、checkout 凭据持久化、不可信上下文进入 `run:`、远程脚本管道执行、PR self-hosted runner 等风险 |
| `repo_checks.py`     | 在 GitHub remote + Dependabot 支持生态成立时检查 `dependabot.yml` 建议并生成可创建配置；同时检查 lockfile 缺失、可疑安装脚本、registry 来源/token/TLS 配置                                                              |
| `iac_checks.py`      | 检查 Dockerfile、Compose、Kubernetes、Terraform 中的常见本地配置风险                                                                                                                                                    |

新增 `hygiene` 输出字段保持纯本地实现，不调用外部扫描器，也不创建 CI/CD workflow：

```json
{
  "gitignore_exists": true,
  "gitignore_missing": [],
  "tracked_secrets": [],
  "sensitive_tracked": [],
  "repository_checks": [],
  "workflow_checks": [],
  "iac_checks": [],
  "coverage": {
    "builtin_rules": [
      "secrets",
      "sensitive_files",
      "gitignore",
      "github_actions",
      "repo_governance",
      "supply_chain",
      "iac_container"
    ]
  }
}
```

结构化本地 finding 使用统一 schema，便于 `analyze.py`、Markdown 和 HTML 复用：

```json
{
  "id": "actions.remote_script_pipe",
  "category": "github_actions",
  "severity": "medium",
  "confidence": "high",
  "file": ".github/workflows/ci.yml",
  "line": 24,
  "title": "workflow 直接执行远程脚本",
  "detail": "curl/wget 管道到 shell 缺少完整性校验，远端脚本被替换时会直接在 runner 上执行。",
  "evidence": "run: curl https://example.com/install.sh | bash",
  "recommendation": "下载固定版本并校验 checksum/signature，或使用可信 action/包管理器替代。",
  "source": "builtin",
  "fixable": false
}
```

新增本地规则覆盖矩阵：

| 分组                      | 字段                | 重点规则                                                                                                                                                                                                                                          | 严重度倾向                |
| ------------------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------- |
| GitHub Actions 工作流安全 | `workflow_checks`   | `permissions: write-all`、建议声明显式最小 permissions、高风险 trigger + checkout、未关闭 `persist-credentials`、不可信上下文进入 `run:`、`curl/wget \| sh`、PR 使用 self-hosted runner                                                           | `high` / `medium` / `low` |
| 依赖配置与维护            | `repository_checks` | 项目 remote 指向 GitHub 且检测到 Dependabot 官方支持的 manifest、lockfile、workflow 或工具配置时，缺少 Dependabot 会提示创建 `.github/dependabot.yml`；已有配置时检查 GitHub Actions 和当前支持生态是否覆盖。以建议形式展示，便于团队纳入维护流程 | `info`                    |
| 供应链配置                | `repository_checks` | manifest 缺 lockfile、安装脚本下载远程脚本或 base64 解码执行、registry 配置中出现 token/password/secret、仓库包含 registry 来源配置需确认、registry TLS 校验被降低                                                                                | `high` / `medium` / `low` |
| IaC / 容器 / 部署配置     | `iac_checks`        | Dockerfile 使用 `latest`、缺非 root `USER`、远程脚本管道执行、`ADD` 远程 URL、明文 `ENV` secret、Compose privileged / Docker socket / 敏感端口、Kubernetes Secret/privileged/hostPath/hostNetwork/root、Terraform state/tfvars 和公网敏感端口     | `high` / `medium` / `low` |

### 依赖解析

| 函数                                                                                    | 作用                                                          |
| --------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| `detect_ecosystems(project_path)`                                                       | 检测项目中存在的包管理器生态                                  |
| `extract_packages(project_path, ecosystems)`                                            | 从支持的依赖文件中提取本地可确认的包名和版本                  |
| `parse_npm_lock` / `parse_pnpm_lock` / `parse_yarn_lock`                                | 各自解析对应的 JS lockfile                                    |
| `parse_requirements_txt` / `parse_pipfile_lock` / `parse_poetry_lock` / `parse_uv_lock` | 各自解析对应的 Python lockfile                                |
| `parse_go_sum`                                                                          | 解析 `go.sum`                                                 |
| `parse_cargo_lock`                                                                      | 解析 `Cargo.lock`                                             |
| `parse_composer_lock`                                                                   | 解析 PHP / Packagist 的 `composer.lock`                       |
| `parse_gemfile_lock`                                                                    | 解析 Ruby / RubyGems 的 `Gemfile.lock`                        |
| `parse_pubspec_lock`                                                                    | 解析 Dart / Flutter Pub 的 `pubspec.lock`                     |
| `parse_mix_lock`                                                                        | 解析 Elixir / Erlang Hex 的 `mix.lock`                        |
| `parse_packages_lock_json` / `parse_packages_config` / `parse_nuget`                    | 解析 .NET / NuGet 的 `packages.lock.json` / `packages.config` |
| `parse_maven_pom`                                                                       | 解析 Maven/JVM 的 `pom.xml` 中直接写明版本的依赖              |

解析器只返回本地可确认的精确坐标。`requirements.txt` 只使用 `==` / `===` 精确版本；Maven/JVM 遇到 `${...}` 属性、父 POM、BOM、profile 或版本范围时会跳过对应依赖。

### 漏洞查询

| 函数                                                                 | 作用                                                |
| -------------------------------------------------------------------- | --------------------------------------------------- |
| `check_vulnerabilities(packages, batch_size, errors, concurrency)`   | 主入口：分批查询 OSV，再通过 NVD/CISA/EPSS 增强数据 |
| `fetch_osv_querybatch(batch)`                                        | 向 OSV API 发送批量查询请求                         |
| `fetch_nvd_enrichments(cve_ids, errors)`                             | 从 NVD 获取 CVE 详情和 CVSS 评分                    |
| `fetch_cisa_kev_enrichments(cve_ids, errors)`                        | 检查 CVE 是否在 CISA 已知被利用漏洞目录中           |
| `fetch_epss_enrichments(cve_ids, errors)`                            | 获取 EPSS 利用概率评分                              |
| `merge_cve_patch(target, patch)`                                     | 将多个数据源的 CVE 增强信息合并                     |
| `build_official_vulnerability(package, osv_record, cve_enrichments)` | 构建标准化的漏洞记录                                |

### 过期依赖

| 函数                                                                      | 作用                                                       |
| ------------------------------------------------------------------------- | ---------------------------------------------------------- |
| `check_outdated(project_path, ecosystems, errors, concurrency, packages)` | 调用各语言包管理器获取过期依赖信息                         |
| `_pip_outdated` / `_go_outdated` / `_cargo_outdated` / `_yarn_outdated`   | 已实现生态的过期检查逻辑；未实现过期检查的生态只做漏洞查询 |

## 扫描流程

```
main()
  ├─ 初始化: setup_logging()
  ├─ cache_clean()                     清理过期缓存
  ├─ Step 1: detect_ecosystems()        识别包管理器生态
  ├─ Step 2: extract_packages()         从支持的依赖文件提取依赖坐标
  ├─ Step 3-5 (并行 ThreadPoolExecutor):
  │   ├─ run_hygiene_step()             仓库安检
  │   ├─ run_vulnerability_step()       依赖漏洞查询（带缓存）
  │   └─ run_outdated_step()            过期依赖检测
  └─ write_json_output()                输出 JSON
```

## 输出 JSON 结构

```json
{
  "generated_at": "2026-06-09 15:50:00",
  "scan_seconds": 12.3,
  "project": {
    "path": "/path/to/project",
    "name": "my-project",
    "ecosystems": ["npm"],
    "lockfiles": ["package-lock.json"],
    "git_repo": true,
    "git_branch": "main",
    "total_packages": 142,
    "total_vulnerabilities": 5
  },
  "scan_config": { ... },
  "output_file": ".butian/.../scan.json",
  "butian_workspace": { "gitignore": { ... } },
  "step_seconds": { "ecosystem_detection": 0.1, "vulnerabilities": 8.5, ... },
  "hygiene": {
    "gitignore_exists": true,
    "gitignore_missing": [],
    "tracked_secrets": [],
    "sensitive_tracked": [],
    "repository_checks": [ ... ],
    "workflow_checks": [ ... ],
    "iac_checks": [ ... ],
    "coverage": {
      "builtin_rules": [
        "secrets",
        "sensitive_files",
        "gitignore",
        "github_actions",
        "repo_governance",
        "supply_chain",
        "iac_container"
      ]
    }
  },
  "package_count": 142,
  "package_sources": [ { "ecosystem": "npm", "source": "package-lock.json", "count": 142 } ],
  "vulnerabilities": [ ... ],
  "vulnerability_count": 5,
  "outdated": [ ... ],
  "outdated_count": 3,
  "errors": []
}
```

## 密钥检测能力

### 检测引擎

`scan_secrets()` 采用**双阶段检测**：

| 阶段    | 机制                       | 置信度        | 说明                                                   |
| ------- | -------------------------- | ------------- | ------------------------------------------------------ |
| Phase 1 | 正则模式匹配（113 个模式） | high / medium | 精确匹配已知格式的密钥和 token                         |
| Phase 2 | Shannon entropy 熵值分析   | low           | 对无已知前缀的高随机性字符串进行可疑标记，用户自行判断 |

两阶段结果自动交叉去重：若同一行已被正则匹配命中，entropy 不再重复报告。同一行内，高可信度匹配（如 `aws_access_key`）会抑制低可信度匹配（如 `generic_api_key`），避免重复告警。

### 密钥扫描文件范围

`scan_secrets()` 不只扫代码文件，也覆盖常见配置、部署和凭据文件。为降低误报，已知 lockfile 会被排除，不把 `integrity` / hash 当作硬编码密钥。

| 范围         | 例子                                                                                                  |
| ------------ | ----------------------------------------------------------------------------------------------------- |
| 代码与脚本   | `.py`、`.js`、`.ts`、`.go`、`.rs`、`.rb`、`.php`、`.java`、`.sh`                                      |
| 配置与数据   | `.json`、`.jsonc`、`.json5`、`.yaml`、`.toml`、`.ini`、`.conf`、`.properties`、`.xml`                 |
| IaC / 部署   | `.tf`、`.tfvars`、`.hcl`、`Dockerfile`、`Dockerfile.*`、`Makefile`、`Procfile`、`Jenkinsfile`         |
| 包管理凭据   | `.npmrc`、`.pypirc`、`.netrc`、`.gem/credentials`、`gradle.properties`、`settings.xml`                |
| 云与应用凭据 | `service-account*.json`、`client_secret*.json`、`sa-key.json`、`.aws/credentials`、`.kube/config`     |
| 主动跳过     | `package-lock.json`、`pnpm-lock.yaml`、`yarn.lock`、`poetry.lock`、`Cargo.lock`、`go.sum` 等 lockfile |

更多脱敏示例见 [`secret-detection-examples.md`](./secret-detection-examples.md)。

### 云厂商密钥（21 个模式）

| 类型                      | 说明                                             | 置信度 |
| ------------------------- | ------------------------------------------------ | ------ |
| `aws_access_key`          | AWS Access Key ID（`AKIA...`）                   | high   |
| `aws_secret_key`          | AWS Secret Access Key                            | medium |
| `aws_session_token`       | AWS Session Token（`ASIA...`）                   | high   |
| `gcp_service_account`     | GCP 服务账号 JSON（`"type": "service_account"`） | high   |
| `gcp_api_key`             | GCP API Key（`AIza...`）                         | high   |
| `gcp_oauth_token`         | GCP OAuth Token（`ya29....`）                    | high   |
| `azure_client_secret`     | Azure Client Secret                              | medium |
| `azure_connection_string` | Azure Storage 连接字符串                         | high   |
| `azure_sas_token`         | Azure SAS Token（`sv=...&sig=...`）              | high   |
| `aliyun_access_key`       | 阿里云 AccessKey ID（`LTAI...`）                 | high   |
| `aliyun_secret_key`       | 阿里云 AccessKey Secret                          | medium |
| `tencent_secret_id`       | 腾讯云 SecretId（`AKID...`）                     | high   |
| `huawei_access_key`       | 华为云 Access Key                                | medium |
| `huawei_secret_key`       | 华为云 Secret Key                                | medium |
| `oracle_api_key`          | Oracle Cloud OCID（`ocid1....`）                 | high   |
| `digitalocean_token`      | DigitalOcean Token（`dop_v1_...`）               | high   |
| `linode_api_key`          | Linode / Akamai API Key（需上下文）              | medium |
| `vultr_api_key`           | Vultr API Key（需上下文）                        | medium |
| `cloudflare_api_key`      | Cloudflare API Key（`v1.0-...`）                 | high   |
| `cloudflare_origin_ca`    | Cloudflare Origin Certificate                    | high   |
| `heroku_api_key`          | Heroku API Key（UUID 格式，需上下文）            | medium |

### SaaS / 第三方服务 Token（78 个模式）

| 类型                        | 说明                                        | 置信度 |
| --------------------------- | ------------------------------------------- | ------ |
| **代码托管**                |                                             |        |
| `github_token`              | GitHub PAT（`ghp_...`）                     | high   |
| `github_fine_grained_pat`   | GitHub fine-grained PAT（`github_pat_...`） | high   |
| `github_oauth`              | GitHub OAuth Token（`gho_...`）             | high   |
| `github_app_token`          | GitHub App Token（`ghu_` / `ghs_...`）      | high   |
| `github_refresh_token`      | GitHub Refresh Token（`ghr_...`）           | high   |
| `gitlab_token`              | GitLab Token（`glpat-...`）                 | high   |
| `gitlab_runner_token`       | GitLab Runner Token（`glrt-...`）           | high   |
| `gitlab_deploy_token`       | GitLab Deploy Token（`gldt-...`）           | high   |
| **即时通讯**                |                                             |        |
| `slack_token`               | Slack Token（`xoxb-...` / `xoxp-...`）      | high   |
| `slack_webhook`             | Slack Webhook URL                           | high   |
| `discord_token`             | Discord Bot Token                           | high   |
| `discord_bot_token`         | Discord Bot Token（BOT 前缀）               | high   |
| `discord_webhook`           | Discord Webhook URL                         | high   |
| **支付**                    |                                             |        |
| `stripe_secret_key`         | Stripe Secret Key（`sk_live_...`）          | high   |
| `stripe_publishable_key`    | Stripe Publishable Key（`pk_live_...`）     | medium |
| `stripe_restricted_key`     | Stripe Restricted Key（`rk_live_...`）      | high   |
| `square_access_token`       | Square Access Token（`sq0atp-...`）         | high   |
| `square_oauth_secret`       | Square OAuth Secret（`sq0csp-...`）         | high   |
| `shopify_token`             | Shopify Token（`shpat_...`）                | high   |
| `paypal_bearer_token`       | PayPal Bearer Token                         | medium |
| `braintree_token`           | Braintree Token                             | medium |
| **通信**                    |                                             |        |
| `twilio_api_key`            | Twilio API Key（`SK...`）                   | high   |
| `twilio_account_sid`        | Twilio Account SID（`AC...`）               | high   |
| `sendgrid_api_key`          | SendGrid API Key（`SG....`）                | high   |
| `resend_api_key`            | Resend API Key（需上下文）                  | medium |
| `mailgun_api_key`           | Mailgun API Key（`key-...`）                | high   |
| `mailchimp_api_key`         | Mailchimp API Key                           | medium |
| **LLM / AI**                |                                             |        |
| `openai_key`                | OpenAI API Key（`sk-...` / `sk-proj-...`）  | high   |
| `anthropic_key`             | Anthropic API Key（`sk-ant-...`）           | high   |
| `groq_api_key`              | Groq API Key（`gsk_...`）                   | high   |
| `huggingface_token`         | Hugging Face Token（`hf_...`）              | high   |
| `replicate_token`           | Replicate Token（`r8_...`）                 | high   |
| **包管理**                  |                                             |        |
| `npm_token`                 | NPM Token（`//registry.npmjs.org/...`）     | high   |
| `npmrc_auth_token`          | NPM Auth Token（`npm_...`）                 | high   |
| `pypi_token`                | PyPI Token（`pypi-AgEIcH...`）              | high   |
| `rubygems_token`            | RubyGems Token（`rubygems_...`）            | medium |
| `nuget_api_key`             | NuGet API Key（`oy2...`）                   | medium |
| `docker_hub_token`          | Docker Hub Token（`dckr_pat_...`）          | high   |
| **监控 / 可观测性**         |                                             |        |
| `datadog_api_key`           | Datadog API Key（需上下文）                 | medium |
| `datadog_app_key`           | Datadog App Key（需上下文）                 | medium |
| `newrelic_key`              | New Relic Key（`NRAK...`）                  | high   |
| `sentry_token`              | Sentry Token（`sntrys_...`）                | high   |
| `grafana_api_key`           | Grafana API Key（JWT 格式，需上下文）       | medium |
| `sonar_token`               | SonarQube Token（`squ_...`）                | high   |
| **CI/CD**                   |                                             |        |
| `terraform_token`           | Terraform Cloud Token（`....atlasv1....`）  | medium |
| `hashicorp_vault_token`     | HashiCorp Vault Token（`hvs.` / `hvb.`）    | high   |
| `pulumi_token`              | Pulumi Token（`pul-...`）                   | high   |
| `circleci_token`            | CircleCI Token（`CCIRERES_...`）            | medium |
| `travis_token`              | Travis CI Token（需上下文）                 | medium |
| `buildkite_token`           | Buildkite Token（`bkua_...`）               | medium |
| `jenkins_token`             | Jenkins Token（需上下文）                   | medium |
| `jfrog_token`               | JFrog Token（`cmVmd...`）                   | medium |
| **项目管理**                |                                             |        |
| `atlassian_token`           | JIRA / Confluence Token（需上下文）         | medium |
| `notion_token`              | Notion Token（`secret_...` / `ntn_...`）    | medium |
| `linear_api_key`            | Linear API Key（`lin_api_...`）             | medium |
| `airtable_api_key`          | Airtable API Key（`key...`）                | medium |
| `asana_token`               | Asana Token（需 `asana` 上下文）            | medium |
| `pagerduty_token`           | PagerDuty Token（需上下文）                 | medium |
| `postman_api_key`           | Postman API Key（`PMAK-...`）               | medium |
| **云服务**                  |                                             |        |
| `firebase_key`              | Firebase API Key                            | medium |
| `cloudflare_api_token`      | Cloudflare API Token（需上下文）            | medium |
| `vercel_token`              | Vercel Token（需上下文）                    | medium |
| `netlify_token`             | Netlify Token（需上下文）                   | medium |
| `railway_token`             | Railway Token（需上下文）                   | medium |
| `render_token`              | Render Token（需上下文）                    | medium |
| `snyk_token`                | Snyk Token（需上下文）                      | medium |
| `clerk_secret_key`          | Clerk Secret Key（需上下文）                | medium |
| `supabase_service_role_key` | Supabase service-role JWT（需上下文）       | medium |
| `algolia_admin_key`         | Algolia Admin API Key（需上下文）           | medium |
| `databricks_token`          | Databricks Token（`dapi...`）               | high   |
| `fastly_api_key`            | Fastly API Key（需上下文）                  | medium |
| `ngrok_token`               | Ngrok Token（需上下文）                     | medium |
| **数据库连接字符串**        |                                             |        |
| `mongodb_connection`        | MongoDB 连接字符串                          | high   |
| `postgres_connection`       | PostgreSQL 连接字符串                       | high   |
| `mysql_connection`          | MySQL 连接字符串                            | high   |
| `redis_connection`          | Redis 连接字符串                            | high   |
| `amqp_connection`           | AMQP / RabbitMQ 连接字符串                  | high   |
| `kafka_connection`          | Kafka / Confluent 连接凭据                  | medium |

### 通用 / 启发式模式（14 个模式）

| 类型                | 说明                                                                                      | 置信度 |
| ------------------- | ----------------------------------------------------------------------------------------- | ------ |
| `private_key`       | RSA / EC / OpenSSH / DSA / PGP 私钥                                                       | high   |
| `generic_password`  | 通用密码赋值（`password = "..."`）                                                        | medium |
| `generic_api_key`   | 通用 API Key 赋值（`api_key = "..."`）                                                    | medium |
| `generic_token`     | 通用 Token 赋值（`access_token = "..."`）                                                 | medium |
| `generic_secret`    | 通用密钥赋值（`secret_key = "..."`）                                                      | medium |
| `generic_sk_key`    | `sk-` 前缀通用捕获（排除 `sk-proj-` / `sk-ant-`，避免与 openai_key / anthropic_key 重复） | medium |
| `bearer_token`      | Authorization: Bearer ...                                                                 | high   |
| `jwt_token`         | JWT Token（`eyJ....`）                                                                    | high   |
| `base64_secret`     | Base64 编码密钥                                                                           | medium |
| `connection_string` | 通用连接字符串                                                                            | medium |
| `basic_auth_url`    | URL 中包含 `user:password@host`                                                           | medium |
| `netrc_password`    | `.netrc` 中的 `machine ... login ... password ...`                                        | medium |
| `encryption_key`    | 加密密钥（`aes_key = "..."`）                                                             | medium |
| `webhook_url`       | Webhook URL（含密钥路径）                                                                 | high   |

### Entropy 熵值检测

对 `.env` 文件和代码文件中的赋值语句进行 Shannon entropy 分析：

| 检测类型               | 阈值  | 说明                                           |
| ---------------------- | ----- | ---------------------------------------------- |
| `base64_high_entropy`  | ≥ 4.5 | 高随机性 base64 字符串（如 `K7gNU3sdo+OL...`） |
| `hex_high_entropy`     | ≥ 3.0 | 高随机性十六进制字符串（≥ 32 字符）            |
| `generic_high_entropy` | ≥ 4.2 | 其他高随机性字符串                             |

- 需要变量名包含 `key`、`token`、`secret`、`password` 等关键词提示（`_SECRET_HINT_KEYWORDS`）
- 最小字符串长度 20 字符
- 纯数字、纯字母等低熵值自动跳过
- 同一行若已被正则匹配，entropy 不重复报告

### 敏感文件检测（29 种类型）

| 类型                | 匹配规则                                                                                    | 说明                           |
| ------------------- | ------------------------------------------------------------------------------------------- | ------------------------------ |
| **环境 / 配置文件** |                                                                                             |                                |
| `env_file`          | `.env`、`.env.local`、`.env.production` 等                                                  | 环境变量文件                   |
| `envrc`             | `.envrc`                                                                                    | direnv 配置                    |
| `npmrc`             | `.npmrc`                                                                                    | NPM 配置（可能含 auth token）  |
| `pypirc`            | `.pypirc`                                                                                   | PyPI 凭据配置                  |
| `netrc`             | `.netrc`                                                                                    | 网络凭据文件                   |
| `gem_credentials`   | `.gem/credentials`                                                                          | RubyGems 凭据                  |
| `app_config`        | `application.yml` / `application.properties`                                                | 应用配置（可能含数据库密码）   |
| `ci_secrets`        | `secrets.yml` / `secrets.json`                                                              | CI/CD 密钥文件                 |
| `gradle_properties` | `gradle.properties`                                                                         | Gradle 属性（可能含签名密钥）  |
| `maven_settings`    | `settings.xml`                                                                              | Maven 设置（可能含仓库凭据）   |
| **密钥 / 证书**     |                                                                                             |                                |
| `private_key`       | `.pem`、`.key`、`.p12`、`.pfx`、`.jks`、`.keystore`、`.pub`、`.gpg`、`.pgp`、`.asc`、`.ppk` | 私钥文件                       |
| `ssh_key`           | `id_rsa`、`id_ed25519`、`id_ecdsa`、`ssh_host_*_key`                                        | SSH 密钥                       |
| `kubeconfig`        | `kubeconfig`、`.kube/config`                                                                | Kubernetes 配置                |
| `docker_cfg`        | `.dockercfg`、`config.json`                                                                 | Docker 凭据                    |
| **凭据文件**        |                                                                                             |                                |
| `credentials`       | `credentials.json`、`service-account*.json`、`client_secret*.json`、`sa-key.json`           | 云服务凭据                     |
| `aws_credentials`   | `.aws/credentials`                                                                          | AWS 凭据文件                   |
| `gcp_credentials`   | `gcloud-credentials`、`gcloud-config`、`gcloud-token`                                       | GCP 凭据文件                   |
| `azure_credentials` | `azureProfile.json`                                                                         | Azure 配置                     |
| `ansible_vault`     | `vault_password.txt`、`vault-password.txt`                                                  | Ansible Vault 密码             |
| `terraform_state`   | `terraform.tfstate`、`terraform.tfstate.backup`                                             | Terraform 状态文件             |
| `terraform_vars`    | `terraform.tfvars`                                                                          | Terraform 变量（可能含密钥值） |
| **数据文件**        |                                                                                             |                                |
| `database`          | `.sqlite`、`.sqlite3`、`.db`、`.dump`、`.rdb`、`.redis`、`.bson`                            | 数据库文件                     |
| `dump`              | `.sql`、`.pgdump`、`.mysqldump`、`.mongoexport`、`.jsonl`、`.csv`                           | 数据导出                       |
| `log`               | `.log`                                                                                      | 日志文件（可能泄露密钥）       |
| **历史 / 备份**     |                                                                                             |                                |
| `history`           | `.bash_history`、`.zsh_history`、`.python_history` 等                                       | Shell / REPL 历史              |
| `backup`            | `.bak`、`.backup`、`.old`、`.orig`、`.save`、`.swp`                                         | 备份文件                       |

### 误报过滤

#### 子串匹配跳过标记（21 个）

包含以下关键词的行将被跳过：

`example`、`placeholder`、`your_`、`todo`、`sample`、`changeme`、`replace_`、`insert_`、`put_your`、`FIXME`、`REPLACE`、`<your`、`dummy`、`fake`、`mock`、`stub`、`redacted`、`<masked>`、`********`、`sanitized`、`[secret]`

#### 词边界跳过标记（3 个）

以下标记使用 `\b` 词边界匹配，仅匹配独立单词，避免误杀：

`xxx`、`test`、`default`

#### 测试夹具文件标记

如果某个文件只用于测试密钥检测规则，可以在文件头部加入：

```text
# butian: allow-secret-fixtures
```

带有该标记的文件会整体跳过硬编码密钥扫描，并在 `coverage.secret_scan.skipped_fixture_files` 中计数。这个标记只用于测试夹具，不应用在业务源码、配置文件或真实凭据文件里。

#### 文件过滤

- 扫描文件扩展名白名单：`.py`、`.js`、`.ts`、`.jsx`、`.tsx`、`.go`、`.rs`、`.rb`、`.php`、`.java`、`.yaml`、`.env*` 等
- 排除目录：`.git`、`node_modules`、`__pycache__`、`dist`、`build`、`vendor` 等
- 最大文件大小：1MB
- 默认最大扫描文件数：500

## 安全设计

- **业务只读**：不会修改业务源码或依赖；只创建 `.butian/` 工作区、缓存、报告产物，并维护对应忽略规则
- **密钥预览策略**：`secret_preview()` 默认对硬编码密钥做预览化展示；`generic_*`、连接串、私钥等高风险格式会更强地遮盖。
- **模板文件识别**：`is_env_template()` 识别 `.env.example`、`.env.sample`、`.env.template`、`.env.dist` 等模板文件；这类文件不会被当成“敏感文件被 git 跟踪”，但仍会参与密钥特征扫描，并允许 HTML 展示扫描阶段提供的代码上下文，方便研发确认是否为真实可用凭证。
- **文件大小限制**：默认最大扫描 1MB 的文件内容
- **二进制文件跳过**：`is_binary_file()` 检测 NUL 字节，自动跳过二进制文件
- **符号链接处理**：默认跳过符号链接，`--follow-symlinks` 时跟随
- **API 请求重试**：`_request_with_retry()` 带指数退避，默认重试 2 次
- **本地缓存**：`.butian/cache/` 缓存 OSV/NVD/EPSS/KEV 数据，减少重复 API 调用
- **无外部依赖**：仅使用 Python 标准库

## 工作区结构

```
.butian/
├── <run>/                          # 每次扫描的运行目录，例如 20260609-1550
│   ├── assets/
│   │   ├── scan.json               # 扫描结果
│   │   └── analysis.json           # 分析结果
│   └── logs/
│       └── scan.log                # 扫描日志（需 --verbose 或 --debug）
├── cache/                          # 跨 run 共享缓存
│   ├── osv/                        # OSV 漏洞缓存
│   ├── nvd/                        # NVD CVE 缓存
│   ├── epss/                       # EPSS 评分缓存
│   └── kev/                        # CISA KEV 目录缓存
```

## .gitignore 管理

`scan.py` 自动在项目 `.gitignore` 中添加以下条目：

```
# Local security scan workspace
.butian/
docs/butian/*/security-report.md
docs/butian/*/security-report.html
docs/butian/*/security-report-final.md
docs/butian/*/security-report-final.html
```

- `.butian/` — 本地扫描工作区（扫描结果、缓存、日志）
- `docs/butian/*/security-report*.md/html` — 生成的 Markdown 和 HTML 审计报告；`docs/butian/` 下的手写文档不应被忽略

`has_butian_gitignore_entry()` 检查 `.butian/` 或 `.butian` 条目是否存在；`ensure_butian_gitignore()` 在首次扫描时追加完整条目。
