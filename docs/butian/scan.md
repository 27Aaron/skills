# scan.py 技术文档

> 源码路径：`butian/scripts/scan.py`（2623 行）

## 概览

`scan.py` 是 Butian 安全扫描器的核心引擎，负责收集项目安全数据并输出结构化 JSON，供下游 `analyze.py` 和 `report.py` 消费。扫描过程**只读**，仅创建/更新 `.butian/` 本地工作区。

## 职责

| #   | 职责         | 说明                                               |
| --- | ------------ | -------------------------------------------------- |
| 1   | 仓库卫生检查 | `.gitignore` 状态、敏感文件跟踪、硬编码密钥扫描    |
| 2   | 依赖生态检测 | 识别 lockfile 类型，提取包名和版本号               |
| 3   | 漏洞查询     | 调用 OSV、NVD、CISA KEV、FIRST EPSS 四个官方数据源 |
| 4   | 过期依赖检测 | 通过各语言包管理器获取最新版本信息                 |

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
python3 scan.py --skip-hygiene <path>           # 跳过仓库卫生检查
python3 scan.py --include-packages <path>       # 在输出中包含完整包列表
python3 scan.py --max-secret-files 300 <path>   # 限制密钥扫描的文件数量
python3 scan.py --compact                       # 输出紧凑 JSON
```

## 核心常量

| 常量                  | 值                                                              | 用途                    |
| --------------------- | --------------------------------------------------------------- | ----------------------- |
| `OSV_QUERYBATCH_URL`  | `https://api.osv.dev/v1/querybatch`                             | OSV 批量查询端点        |
| `OSV_VULN_URL_PREFIX` | `https://api.osv.dev/v1/vulns/`                                 | OSV 单条漏洞端点        |
| `NVD_CVE_API_URL`     | `https://services.nvd.nist.gov/rest/json/cves/2.0`              | NVD CVE 查询端点        |
| `CISA_KEV_JSON_URL`   | `https://www.cisa.gov/.../known_exploited_vulnerabilities.json` | CISA 已知被利用漏洞目录 |
| `EPSS_API_URL`        | `https://api.first.org/data/v1/epss`                            | EPSS 漏洞利用预测评分   |
| `BUTIAN_DIR`          | `.butian`                                                       | 工作区目录名            |
| `BUTIAN_ASSETS_DIR`   | `assets`                                                        | 工作区内的资产子目录    |
| `BUTIAN_CONTENT_DIR`  | `content`                                                       | 工作区内的内容子目录    |

## 关键函数

### 工作区管理

| 函数                                                    | 作用                                                                      |
| ------------------------------------------------------- | ------------------------------------------------------------------------- |
| `find_project_root(start_path)`                         | 向上遍历目录树，找到包含项目标记文件（`.git`、`package.json` 等）的根目录 |
| `ensure_butian_run(project_path, run_id)`               | 创建 `.butian/<timestamp>-<run_id>/` 运行目录                             |
| `default_asset_path(project_path, filename, preflight)` | 返回默认的资产文件路径                                                    |
| `butian_gitignore_status(project_path)`                 | 返回 `.gitignore` 中 `.butian/` 条目的状态                                |

### 仓库卫生

| 函数                                               | 作用                                                          |
| -------------------------------------------------- | ------------------------------------------------------------- |
| `scan_hygiene(project_path, max_secret_files)`     | 执行完整的仓库卫生检查：gitignore、敏感文件跟踪、密钥扫描     |
| `scan_secrets(project_path, max_files, max_bytes)` | 正则扫描文件内容，识别硬编码的 AWS 密钥、GitHub Token、私钥等 |
| `check_sensitive_tracked(project_path)`            | 检查被 git 跟踪的敏感文件（`.env`、私钥、数据库文件等）       |
| `check_gitignore(project_path, sensitive_tracked)` | 检查 `.gitignore` 是否覆盖了常见敏感文件模式                  |

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
  ├─ Step 1: detect_ecosystems()        识别包管理器生态
  ├─ Step 2: extract_packages()         从 lockfile 提取依赖坐标
  ├─ Step 3-5 (并行 ThreadPoolExecutor):
  │   ├─ run_hygiene_step()             仓库卫生检查
  │   ├─ run_vulnerability_step()       依赖漏洞查询
  │   └─ run_outdated_step()            过期依赖检测
  └─ 输出 JSON → .butian/<run>/assets/scan.json
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

## 安全设计

- **只读操作**：不会修改项目文件（仅创建 `.butian/` 工作区和更新其 `.gitignore` 条目）
- **密钥预览脱敏**：`secret_preview()` 对硬编码密钥只显示前缀字符，不暴露完整值
- **模板文件识别**：`is_env_template()` 跳过 `.example`、`.sample`、`.template` 后缀的文件
- **文件大小限制**：默认最大扫描 1MB 的文件内容
- **API 请求重试**：`_request_with_retry()` 带指数退避，默认重试 2 次
- **无外部依赖**：仅使用 Python 标准库
