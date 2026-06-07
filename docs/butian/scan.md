# scan.py 技术文档

> 源码路径：`butian/scripts/scan.py`

## 概览

`scan.py` 是 Butian 安全扫描器的核心引擎，负责收集项目安全数据并输出结构化 JSON，供下游 `analyze.py` 和 `report.py` 消费。扫描过程**只读**，仅创建/更新 `.butian/` 本地工作区。

## 职责

| #   | 职责         | 说明                                                                                    |
| --- | ------------ | --------------------------------------------------------------------------------------- |
| 1   | 仓库安检 | `.gitignore` 状态、敏感文件跟踪、硬编码密钥扫描（95 个正则 + Shannon entropy 熵值分析） |
| 2   | 依赖生态检测 | 识别 lockfile 类型，提取包名和版本号                                                    |
| 3   | 漏洞查询     | 调用 OSV、NVD、CISA KEV、FIRST EPSS 四个官方数据源                                      |
| 4   | 过期依赖检测 | 通过各语言包管理器获取最新版本信息                                                      |

## 支持的生态

| 语言                    | 包管理器   | Lockfile            |
| ----------------------- | ---------- | ------------------- |
| JavaScript / TypeScript | npm        | `package-lock.json` |
| JavaScript / TypeScript | pnpm       | `pnpm-lock.yaml`    |
| JavaScript / TypeScript | yarn       | `yarn.lock`         |
| Python                  | pip        | `requirements.txt`  |
| Python                  | pipenv     | `Pipfile.lock`      |
| Python                  | poetry     | `poetry.lock`       |
| Python                  | uv         | `uv.lock`           |
| Go                      | go modules | `go.sum`            |
| Rust                    | cargo      | `Cargo.lock`        |

## CLI 用法

```bash
python3 scan.py --preflight <preflight_json>    # 从 preflight 文件读取配置
python3 scan.py [project_path]                  # 自动检测项目根目录
python3 scan.py --no-root-discovery <path>      # 直接扫描给定路径
python3 scan.py --skip-outdated <path>          # 跳过过期依赖检查（更快）
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
| `--skip-hygiene`      | flag | false  | 跳过仓库安检                         |
| `--max-secret-files`  | int  | 500    | 限制密钥扫描的文件数量               |
| `--include-packages`  | flag | false  | 在输出中包含完整包列表               |
| `--verbose`           | flag | false  | 输出详细日志到 stderr（INFO 级别）   |
| `--debug`             | flag | false  | 输出调试级别日志到 stderr 和日志文件 |
| `--follow-symlinks`   | flag | false  | 跟随符号链接扫描（默认跳过）         |

## 核心常量

| 常量                             | 值                                                              | 用途                           |
| -------------------------------- | --------------------------------------------------------------- | ------------------------------ |
| `OSV_QUERYBATCH_URL`             | `https://api.osv.dev/v1/querybatch`                             | OSV 批量查询端点               |
| `OSV_VULN_URL_PREFIX`            | `https://api.osv.dev/v1/vulns/`                                 | OSV 单条漏洞端点               |
| `NVD_CVE_API_URL`                | `https://services.nvd.nist.gov/rest/json/cves/2.0`              | NVD CVE 查询端点               |
| `CISA_KEV_JSON_URL`              | `https://www.cisa.gov/.../known_exploited_vulnerabilities.json` | CISA 已知被利用漏洞目录        |
| `EPSS_API_URL`                   | `https://api.first.org/data/v1/epss`                            | EPSS 漏洞利用预测评分          |
| `BUTIAN_DIR`                     | `.butian`                                                       | 工作区目录名                   |
| `BUTIAN_ASSETS_DIR`              | `assets`                                                        | 工作区内的资产子目录           |
| `BUTIAN_CONTENT_DIR`             | `content`                                                       | 工作区内的内容子目录           |
| `BUTIAN_GITIGNORE_EXTRA_ENTRIES` | `("docs/butian",)`                                              | 除 `.butian/` 外额外忽略的目录 |
| `CACHE_DIR_NAME`                 | `cache`                                                         | 缓存子目录名                   |

## 关键函数

### 工作区管理

| 函数                                                    | 作用                                                                      |
| ------------------------------------------------------- | ------------------------------------------------------------------------- |
| `find_project_root(start_path)`                         | 向上遍历目录树，找到包含项目标记文件（`.git`、`package.json` 等）的根目录 |
| `ensure_butian_run(project_path, run_id)`               | 创建 `.butian/<timestamp>-<run_id>/` 运行目录                             |
| `default_asset_path(project_path, filename, preflight)` | 返回默认的资产文件路径                                                    |
| `butian_gitignore_status(project_path)`                 | 返回 `.gitignore` 中 `.butian/` 条目的状态                                |

### 日志系统

| 函数                                     | 作用                                               |
| ---------------------------------------- | -------------------------------------------------- |
| `setup_logging(verbose, debug, log_dir)` | 配置 `butian` logger，输出到 stderr 和可选日志文件 |

- 日志文件路径：`.butian/<timestamp>/logs/scan.log`
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

| 函数                                               | 作用                                                      |
| -------------------------------------------------- | --------------------------------------------------------- |
| `scan_hygiene(project_path, max_secret_files)`     | 执行完整的仓库安检：gitignore、敏感文件跟踪、密钥扫描 |
| `scan_secrets(project_path, max_files, max_bytes)` | 正则模式匹配 + Shannon entropy 熵值分析，识别硬编码密钥   |
| `check_sensitive_tracked(project_path)`            | 检查被 git 跟踪的敏感文件（详见下方「敏感文件类型」）     |
| `check_gitignore(project_path, sensitive_tracked)` | 检查 `.gitignore` 是否覆盖了常见敏感文件模式              |

### 依赖解析

| 函数                                                                                    | 作用                                   |
| --------------------------------------------------------------------------------------- | -------------------------------------- |
| `detect_ecosystems(project_path)`                                                       | 检测项目中存在的包管理器生态           |
| `extract_packages(project_path, ecosystems)`                                            | 从 lockfile 中提取所有依赖的名称和版本 |
| `parse_npm_lock` / `parse_pnpm_lock` / `parse_yarn_lock`                                | 各自解析对应的 JS lockfile             |
| `parse_requirements_txt` / `parse_pipfile_lock` / `parse_poetry_lock` / `parse_uv_lock` | 各自解析对应的 Python lockfile         |
| `parse_go_sum`                                                                          | 解析 `go.sum`                          |
| `parse_cargo_lock`                                                                      | 解析 `Cargo.lock`                      |

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

| 函数                                                                      | 作用                               |
| ------------------------------------------------------------------------- | ---------------------------------- |
| `check_outdated(project_path, ecosystems, errors, concurrency, packages)` | 调用各语言包管理器获取过期依赖信息 |
| `_pip_outdated` / `_go_outdated` / `_cargo_outdated` / `_yarn_outdated`   | 各生态的过期检查实现               |

## 扫描流程

```
main()
  ├─ 初始化: setup_logging()
  ├─ cache_clean()                     清理过期缓存
  ├─ Step 1: detect_ecosystems()        识别包管理器生态
  ├─ Step 2: extract_packages()         从 lockfile 提取依赖坐标
  ├─ Step 3-5 (并行 ThreadPoolExecutor):
  │   ├─ run_hygiene_step()             仓库安检
  │   ├─ run_vulnerability_step()       依赖漏洞查询（带缓存）
  │   └─ run_outdated_step()            过期依赖检测
  └─ write_json_output()                输出 JSON
```

## 输出 JSON 结构

```json
{
  "generated_at": "2025-01-15 10:30:00",
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
    "gitignore_missing": [],
    "tracked_secrets": [],
    "sensitive_tracked": []
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

| 阶段    | 机制                      | 置信度        | 说明                                                   |
| ------- | ------------------------- | ------------- | ------------------------------------------------------ |
| Phase 1 | 正则模式匹配（95 个模式） | high / medium | 精确匹配已知格式的密钥和 token                         |
| Phase 2 | Shannon entropy 熵值分析  | low           | 对无已知前缀的高随机性字符串进行可疑标记，用户自行判断 |

两阶段结果自动交叉去重：若同一行已被正则匹配命中，entropy 不再重复报告。同一行内，高可信度匹配（如 `aws_access_key`）会抑制低可信度匹配（如 `generic_api_key`），避免重复告警。

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

### SaaS / 第三方服务 Token（65 个模式）

| 类型                     | 说明                                       | 置信度 |
| ------------------------ | ------------------------------------------ | ------ |
| **代码托管**             |                                            |        |
| `github_token`           | GitHub PAT（`ghp_...`）                    | high   |
| `github_oauth`           | GitHub OAuth Token（`gho_...`）            | high   |
| `github_app_token`       | GitHub App Token（`ghu_` / `ghs_...`）     | high   |
| `github_refresh_token`   | GitHub Refresh Token（`ghr_...`）          | high   |
| `gitlab_token`           | GitLab Token（`glpat-...`）                | high   |
| **即时通讯**             |                                            |        |
| `slack_token`            | Slack Token（`xoxb-...` / `xoxp-...`）     | high   |
| `slack_webhook`          | Slack Webhook URL                          | high   |
| `discord_token`          | Discord Bot Token                          | high   |
| `discord_bot_token`      | Discord Bot Token（BOT 前缀）              | high   |
| `discord_webhook`        | Discord Webhook URL                        | high   |
| **支付**                 |                                            |        |
| `stripe_secret_key`      | Stripe Secret Key（`sk_live_...`）         | high   |
| `stripe_publishable_key` | Stripe Publishable Key（`pk_live_...`）    | medium |
| `stripe_restricted_key`  | Stripe Restricted Key（`rk_live_...`）     | high   |
| `square_access_token`    | Square Access Token（`sq0atp-...`）        | high   |
| `square_oauth_secret`    | Square OAuth Secret（`sq0csp-...`）        | high   |
| `shopify_token`          | Shopify Token（`shpat_...`）               | high   |
| `paypal_bearer_token`    | PayPal Bearer Token                        | medium |
| `braintree_token`        | Braintree Token                            | medium |
| **通信**                 |                                            |        |
| `twilio_api_key`         | Twilio API Key（`SK...`）                  | high   |
| `twilio_account_sid`     | Twilio Account SID（`AC...`）              | high   |
| `sendgrid_api_key`       | SendGrid API Key（`SG....`）               | high   |
| `mailgun_api_key`        | Mailgun API Key（`key-...`）               | high   |
| `mailchimp_api_key`      | Mailchimp API Key                          | medium |
| **LLM / AI**             |                                            |        |
| `openai_key`             | OpenAI API Key（`sk-...` / `sk-proj-...`） | high   |
| `anthropic_key`          | Anthropic API Key（`sk-ant-...`）          | high   |
| `huggingface_token`      | Hugging Face Token（`hf_...`）             | high   |
| `replicate_token`        | Replicate Token（`r8_...`）                | high   |
| **包管理**               |                                            |        |
| `npm_token`              | NPM Token（`//registry.npmjs.org/...`）    | high   |
| `npmrc_auth_token`       | NPM Auth Token（`npm_...`）                | high   |
| `pypi_token`             | PyPI Token（`pypi-AgEIcH...`）             | high   |
| `rubygems_token`         | RubyGems Token（`rubygems_...`）           | medium |
| `nuget_api_key`          | NuGet API Key（`oy2...`）                  | medium |
| `docker_hub_token`       | Docker Hub Token（`dckr_pat_...`）         | high   |
| **监控 / 可观测性**      |                                            |        |
| `datadog_api_key`        | Datadog API Key（需上下文）                | medium |
| `datadog_app_key`        | Datadog App Key（需上下文）                | medium |
| `newrelic_key`           | New Relic Key（`NRAK...`）                 | high   |
| `sentry_token`           | Sentry Token（`sntrys_...`）               | high   |
| `grafana_api_key`        | Grafana API Key（JWT 格式，需上下文）      | medium |
| `sonar_token`            | SonarQube Token（`squ_...`）               | high   |
| **CI/CD**                |                                            |        |
| `terraform_token`        | Terraform Cloud Token（`....atlasv1....`） | medium |
| `circleci_token`         | CircleCI Token（`CCIRERES_...`）           | medium |
| `travis_token`           | Travis CI Token（需上下文）                | medium |
| `buildkite_token`        | Buildkite Token（`bkua_...`）              | medium |
| `jenkins_token`          | Jenkins Token（需上下文）                  | medium |
| `jfrog_token`            | JFrog Token（`cmVmd...`）                  | medium |
| **项目管理**             |                                            |        |
| `atlassian_token`        | JIRA / Confluence Token（需上下文）        | medium |
| `notion_token`           | Notion Token（`secret_...` / `ntn_...`）   | medium |
| `linear_api_key`         | Linear API Key（`lin_api_...`）            | medium |
| `airtable_api_key`       | Airtable API Key（`key...`）               | medium |
| `asana_token`            | Asana Token（需 `asana` 上下文）           | medium |
| `pagerduty_token`        | PagerDuty Token（需上下文）                | medium |
| `postman_api_key`        | Postman API Key（`PMAK-...`）              | medium |
| **云服务**               |                                            |        |
| `firebase_key`           | Firebase API Key                           | medium |
| `databricks_token`       | Databricks Token（`dapi...`）              | high   |
| `fastly_api_key`         | Fastly API Key（需上下文）                 | medium |
| `ngrok_token`            | Ngrok Token（需上下文）                    | medium |
| **数据库连接字符串**     |                                            |        |
| `mongodb_connection`     | MongoDB 连接字符串                         | high   |
| `postgres_connection`    | PostgreSQL 连接字符串                      | high   |
| `mysql_connection`       | MySQL 连接字符串                           | high   |
| `redis_connection`       | Redis 连接字符串                           | high   |
| `amqp_connection`        | AMQP / RabbitMQ 连接字符串                 | high   |
| `kafka_connection`       | Kafka / Confluent 连接凭据                 | medium |

### 通用 / 启发式模式（12 个模式）

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

#### 文件过滤

- 扫描文件扩展名白名单：`.py`、`.js`、`.ts`、`.jsx`、`.tsx`、`.go`、`.rs`、`.rb`、`.php`、`.java`、`.yaml`、`.env*` 等
- 排除目录：`.git`、`node_modules`、`__pycache__`、`dist`、`build`、`vendor` 等
- 最大文件大小：1MB
- 默认最大扫描文件数：500

## 安全设计

- **只读操作**：不会修改项目文件（仅创建 `.butian/` 工作区和更新其 `.gitignore` 条目）
- **密钥预览脱敏**：`secret_preview()` 对硬编码密钥只显示前缀字符，不暴露完整值
- **模板文件识别**：`is_env_template()` 跳过 `.example`、`.sample`、`.template` 后缀的文件
- **文件大小限制**：默认最大扫描 1MB 的文件内容
- **二进制文件跳过**：`is_binary_file()` 检测 NUL 字节，自动跳过二进制文件
- **符号链接处理**：默认跳过符号链接，`--follow-symlinks` 时跟随
- **API 请求重试**：`_request_with_retry()` 带指数退避，默认重试 2 次
- **本地缓存**：`.butian/cache/` 缓存 OSV/NVD/EPSS/KEV 数据，减少重复 API 调用
- **无外部依赖**：仅使用 Python 标准库

## 工作区结构

```
.butian/
├── .first-scan-done                # 首次扫描标记（控制浏览器弹出和 Markdown 生成）
├── <timestamp>/                    # 每次扫描的运行目录
│   ├── assets/
│   │   ├── scan.json               # 扫描结果
│   │   └── analysis.json           # 分析结果
│   ├── content/
│   │   └── security-report.html    # HTML 报告
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
# Butian local workspace
.butian/
docs/butian
```

- `.butian/` — 本地扫描工作区（扫描结果、缓存、日志）
- `docs/butian` — Markdown 审计报告目录（无需提交到版本控制）

`has_butian_gitignore_entry()` 检查 `.butian/` 或 `.butian` 条目是否存在；`ensure_butian_gitignore()` 在首次扫描时追加完整条目。
