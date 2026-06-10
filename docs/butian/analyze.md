# analyze.py 技术文档

> 源码路径：`butian/scripts/analyze.py`

## 概览

`analyze.py` 接收 `scan.py` 的输出 JSON，构建确定性的分析结果。它将原始扫描数据转化为结构化的风险分级、问题排序和修复建议，为 `report.py` 和 `visualize.py` 提供标准化的输入。

## 职责

| #   | 职责           | 说明                                                                                    |
| --- | -------------- | --------------------------------------------------------------------------------------- |
| 1   | 风险分级       | 按严重度排序，将问题分为红/黄/绿三档                                                    |
| 2   | 漏洞摘要       | 为每条漏洞生成人类可读的中文摘要                                                        |
| 3   | 修复建议       | 为有修复版本的依赖生成升级方案                                                          |
| 4   | 仓库安检归一化 | 将硬编码密钥、敏感文件、GitHub Actions、依赖配置与维护、IaC/容器 finding 转成统一行动项 |
| 5   | 摘要生成       | 构建结论、扫描说明和建议动作                                                            |

## CLI 用法

```bash
python3 analyze.py .butian/<run>/assets/scan.json                          # 自动输出到同目录
python3 analyze.py scan.json output-analysis.json                          # 指定输出路径
```

## CLI 参数

| 参数          | 类型     | 必需 | 说明                                            |
| ------------- | -------- | ---- | ----------------------------------------------- |
| `scan_json`   | 位置参数 | ✅   | `scan.py` 输出的 JSON 文件路径                  |
| `output_json` | 位置参数 | ❌   | 分析结果输出路径（默认 `assets/analysis.json`） |

## 核心常量

### 输出契约版本

```python
ANALYSIS_SCHEMA_VERSION = "1.0.0"
```

`analysis.json` 顶层固定写入 `schema_version`。后续如果改变字段含义、删除字段或调整下游依赖的结构，需要递增该版本，并同步更新报告、修复器和测试夹具。

### 严重度排序

```python
SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}
```

### 中文标签

| Key        | 标签   |
| ---------- | ------ |
| `critical` | 紧急   |
| `high`     | 高风险 |
| `medium`   | 中风险 |
| `low`      | 低风险 |
| `info`     | 待确认 |

### 共享展示标签

`SECRET_TYPE_LABELS` 和 `SENSITIVE_TYPE_LABELS` 从 `labels.py` 导入，分别把 `aws_access_key`、`private_key`、`slack_token`、`env_file`、`terraform_state` 等机器标识映射为报告可读名称。

这两个字典被 `analyze.py`、`report.py` 和 `visualize.py` 共享，避免 Markdown 与 HTML 报告出现同一类型不同翻译的问题。新增扫描类型时应先补 `labels.py`，再运行 `tests/butian/test_labels.py` 验证覆盖。

### 结构化仓库安检分组

```python
STRUCTURED_HYGIENE_GROUPS = (
    "workflow_checks",
    "repository_checks",
    "iac_checks",
)
```

这三个字段来自 `scan_hygiene()` 的纯本地 Python 规则，不依赖外部扫描器。`analyze.py` 会把它们统一转成 `type = "local_repository_check"` 的行动项，并保留 `source_id`、`category`、`confidence`、`evidence`、`line`、`source` 等证据字段。

## 核心函数

### 风险分级

| 函数                                     | 作用                                                                                                |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `build_top_issues(scan)`                 | 将漏洞列表标准化，补充 `tier`（red/yellow/green）、`rank`（排名）、`summary`（Markdown 用中文摘要） |
| `build_hygiene_items(scan)`              | 将仓库安检问题分为 red/yellow/green，覆盖密钥、敏感文件、`.gitignore` 和结构化本地规则              |
| `build_dependency_fix_items(top_issues)` | 按包分组漏洞，生成升级建议（包含目标版本、涉及的公告 ID）                                           |

### 摘要生成

| 函数                             | 作用                                                          |
| -------------------------------- | ------------------------------------------------------------- |
| `build_summary(scan, analysis)`  | 生成结论、扫描说明和建议动作列表                              |
| `advisory_issue_phrase(summary)` | 将英文公告摘要翻译/精简为 Markdown 风险表说明                 |
| `vulnerability_summary(item)`    | 为单条漏洞生成 Markdown 用完整描述（包名+版本+风险+修复建议） |

HTML 的 `当前风险 / 详情` 不直接使用 `vulnerability_summary()` 的长句，而是在 `templates/report.js` 中通过 `plainRiskStory()` 依据 advisory 摘要和 CWE 生成更适合普通读者的精确描述。这样 Markdown 保持归档表格，HTML 保持可读解释，两者共享风险数量、安全编号和修复版本。

### 工具函数

| 函数                        | 作用                                    |
| --------------------------- | --------------------------------------- |
| `normalize_severity(value)` | 标准化严重度字符串，未知值归为 `"info"` |
| `sort_items(items)`         | 按严重度降序 → 包名 → 版本 排序         |
| `count_risks(*groups)`      | 统计各严重度的数量                      |
| `highest_version(values)`   | 从版本列表中选出最高版本                |

## 风险分级逻辑

```
┌─────────────────────────────────────────────────┐
│ RED（优先处理）                                 │
│   - 被跟踪的 .env、私钥、凭证、SSH 密钥文件     │
│   - 紧急/高风险漏洞                             │
│   - high/critical 的本地仓库安检项               │
├─────────────────────────────────────────────────┤
│ YELLOW（需要人工确认）                          │
│   - 疑似硬编码凭证                              │
│   - 被跟踪的日志、数据库文件                    │
│   - .gitignore 缺少敏感文件规则                 │
│   - 中风险漏洞                                  │
│   - medium 的本地仓库安检项                      │
├─────────────────────────────────────────────────┤
│ GREEN（可作为修复计划）                         │
│   - 依赖升级建议（含目标版本）                  │
│   - .gitignore 规则补充建议                     │
│   - low/info 的依赖配置与维护建议                │
└─────────────────────────────────────────────────┘
```

### 结构化仓库安检行动项

`workflow_checks`、`repository_checks`、`iac_checks` 中的每条 finding 会被转换为如下行动项：

```json
{
  "name": "Dockerfile 使用 latest 镜像标签",
  "type": "local_repository_check",
  "severity": "medium",
  "path": "Dockerfile",
  "file": "Dockerfile",
  "line": 1,
  "category": "iac_container",
  "source_id": "iac.docker_latest_tag",
  "confidence": "high",
  "evidence": "FROM node:latest",
  "why_manual": "latest 会随时间漂移，构建结果和漏洞暴露面不可复现。",
  "risk": "latest 会随时间漂移，构建结果和漏洞暴露面不可复现。",
  "disposal": "固定到具体版本标签；高要求发布链路可进一步固定 digest。",
  "source": "builtin"
}
```

分级规则很直接：`critical/high` 进入 red，`medium` 进入 yellow，`low/info` 进入 green。这样专业用户能在报告里看到完整证据，小白用户也能按"优先处理 / 需要确认 / 可作为计划"理解行动顺序。

HTML 渲染时会对凭证类 yellow 项做一次展示归并：`type == "secret_exposure"` 的事项会移动到 `仓库安检 / 凭证与敏感文件` 中，和 `tracked_secrets` 的代码证据放在一起；非凭证类 yellow 项才保留在底部 `待确认事项`。

## 输出 JSON 结构

```json
{
  "schema_version": "1.0.0",
  "generated_at": "2026-06-09 15:50:00",
  "scan_seconds": 12.3,
  "project": { "path": "...", "name": "..." },
  "scan_config": { "scan_mode": "full_dependency_scan", ... },
  "source_scan_file": "/abs/path/to/scan.json",
  "output_file": "/abs/path/to/analysis.json",
  "risk_summary": { "critical": 1, "high": 2, "medium": 3, "low": 1, "info": 0 },
  "hygiene": { ... },
  "outdated": [ ... ],
  "top_issues": [
    {
      "rank": 1,
      "tier": "red",
      "name": "next",
      "package": "next",
      "version": "15.5.1",
      "severity": "critical",
      "summary": "next 15.5.1 命中已公开安全公告；建议升级到 15.5.2 或更高版本。",
      "advisory_summary": "...",
      "fixed_versions": ["15.5.2"],
      "dependency_context": {
        "kind": "nested_locked",
        "note": "被父依赖锁定的嵌套副本",
        "locations": [
          {
            "path": "node_modules/next/node_modules/postcss",
            "parent": "next",
            "version": "8.4.31"
          }
        ],
        "top_level_versions": ["8.5.10"]
      },
      ...
    }
  ],
  "red": [ ... ],
  "yellow": [ ... ],
  "green": [
    {
      "name": "升级 next",
      "type": "dependency_upgrade",
      "severity": "critical",
      "summary": "next 命中 2 个风险项，建议升级到 15.5.2 或更高版本后运行测试。该建议只覆盖包管理器可解析的普通升级；修复后必须复扫。",
      "fix_config": {
        "type": "upgrade",
        "ecosystem": "npm",
        "package": "next",
        "current_versions": ["15.5.1"],
        "target_version": "15.5.2",
        "advisory_ids": ["GHSA-xxx", "GHSA-yyy"],
        "upgrade_scope": "direct_package",
        "residual_guidance": "如果复扫仍出现同名旧版本，通常是间接依赖被父包锁定；需询问用户是否确认升级父依赖到 latest...",
        ...
      }
    }
  ],
  "errors": [],
  "package_count": 142,
  "vulnerability_count": 5,
  "outdated_count": 3,
  "package_sources": [ ... ],
  "butian_workspace": { ... },
  "summary": {
    "tldr": "本次在 142 个 npm 依赖中命中 5 个已确认依赖风险项，其中 3 个需要优先处理；仓库安检未发现凭证或敏感文件问题。",
    "detail": "本次检查覆盖项目 ...，识别到 142 个 npm 依赖，命中 5 个已确认依赖风险项，涉及 next、lodash。仓库安检未发现疑似硬编码凭证、敏感文件跟踪或 .gitignore 缺失。",
    "priority": ["先升级 next 到 15.5.2、lodash 到 4.18.0，完成后重新运行扫描。", ...],
    "tier_stats": {
      "red": "3 项优先处理",
      "yellow": "2 项需要人工确认",
      "green": "4 项可作为修复计划"
    }
  }
}
```

## `advisory_issue_phrase` Markdown 摘要

该函数通过模式匹配将英文公告摘要转化为 Markdown 表格中的简洁中文说明。它的目标是归档和修复排期，不负责 HTML 中更细的普通人解释。

| 模式                                 | 输出示例                                                        |
| ------------------------------------ | --------------------------------------------------------------- |
| `large numeric range` + `max`        | "大范围数字展开可能绕过 max 限制，带来拒绝服务风险"             |
| `host confusion` + `percent-encoded` | "对百分号编码的 authority 分隔符处理不当，可能造成主机解析混淆" |
| `server-side request forgery`        | "存在服务端请求伪造风险"                                        |
| `middleware` + `proxy bypass`        | "存在中间件/代理绕过风险"                                       |
| `denial of service`                  | "存在拒绝服务风险"                                              |
| `cache`                              | "存在缓存可信度风险"                                            |
| 未匹配                               | "公告摘要：{原文}"                                              |

HTML 详情的映射范围更广，见 [`report.md`](./report.md) 的“HTML 详情文案映射”。维护时不要只更新 `advisory_issue_phrase()`；如果用户会在浏览器里看到该风险，还要同步检查 `plainRiskStory()` 和 `tests.butian.test_report_assets`。

## 设计要点

- **确定性输出**：相同输入始终产生相同输出，不含随机性
- **可复核润色**：脚本运行后可以轻量调整面向业务的措辞，但 schema 和风险计数应由脚本保证
- **三档分级**：red/yellow/green 分别对应"必须处理"、"人工确认"、"计划修复"三个行动层级
- **中文优先**：所有面向用户的文本均为中文
- **证据可追溯**：结构化仓库安检保留 `source_id`、`file`、`line`、`evidence` 和 `recommendation`，报告可直接解释"为什么提示"和"下一步做什么"
- **边界清晰**：本地仓库安检项代表静态规则命中；远端 GitHub 设置审计、渗透测试和部署安全评估需要单独流程覆盖
