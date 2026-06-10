# 四大 API 可用字段全景研究

> 生成时间：2026-06-06
> 目的：梳理 OSV / NVD / CISA KEV / EPSS 四个 API 返回的全部字段，对比 `scan.py` 中已提取的字段，识别可丰富展示的增量内容。

---

## 1. OSV (`api.osv.dev`) — 主漏洞源

### 端点

| 端点     | URL                                      | 用途                 |
| -------- | ---------------------------------------- | -------------------- |
| 批量查询 | `POST https://api.osv.dev/v1/querybatch` | 按包名+版本查漏洞    |
| 详情查询 | `GET https://api.osv.dev/v1/vulns/{id}`  | 获取单个漏洞完整记录 |

### 完整字段清单

```json
{
  "schema_version": "string",        // OSV schema 版本 (SemVer)
  "id": "string",                    // 漏洞 ID (GHSA-xxx, CVE-xxx, OSV-xxx)
  "modified": "string (RFC3339)",    // 【必填】最后修改时间
  "published": "string (RFC3339)",   // 发布时间
  "withdrawn": "string (RFC3339)",   // 撤回时间（缺失=有效）
  "aliases": ["string"],             // 同一漏洞在其他数据库的 ID
  "upstream": ["string"],            // 上游漏洞 ID（Linux 发行版常用）
  "related": ["string"],             // 相关漏洞 ID（非别名）
  "summary": "string",               // 一行摘要（~120 字符）
  "details": "string (CommonMark)",  // 详细技术描述（Markdown）
  "severity": [{                     // 严重度评分
    "type": "string",                // CVSS_V2 | CVSS_V3 | CVSS_V4 | Ubuntu | 自定义
    "score": "string"                // CVSS 向量字符串或评分
  }],
  "affected": [{                     // 受影响包列表
    "package": {
      "ecosystem": "string",         // 生态系统（npm, PyPI, Go, crates.io, Maven 等 45+）
      "name": "string",              // 包名
      "purl": "string"               // Package URL（可选但推荐）
    },
    "severity": [{...}],             // 包级别严重度（优先级高于顶层）
    "ranges": [{
      "type": "string",              // SEMVER | ECOSYSTEM | GIT
      "repo": "string",             // Git 仓库 URL（仅 GIT 类型）
      "events": [{
        "introduced": "string",      // 漏洞引入版本（特殊值 "0" 表示所有版本）
        "fixed": "string",           // 修复版本
        "last_affected": "string",   // 最后受影响版本
        "limit": "string"            // 上限版本（主要用于 GIT 范围）
      }],
      "database_specific": {}        // 范围级别的数据库特定数据
    }],
    "versions": ["string"],          // 明确受影响的版本列表
    "ecosystem_specific": {},        // 生态系统特定元数据
    "database_specific": {}          // 数据库特定元数据
  }],
  "references": [{                   // 参考链接
    "type": "string",                // ADVISORY | ARTICLE | DETECTION | DISCUSSION |
                                    // REPORT | FIX | INTRODUCED | PACKAGE | EVIDENCE | WEB
    "url": "string"
  }],
  "credits": [{                      // 致谢信息
    "name": "string",                // 姓名/组织
    "contact": ["string"],           // 联系方式（URL）
    "type": "string"                 // FINDER | REPORTER | ANALYST | COORDINATOR |
                                    // REMEDIATION_DEVELOPER | REMEDIATION_REVIEWER |
                                    // REMEDIATION_VERIFIER | TOOL | SPONSOR | OTHER
  }],
  "database_specific": {}            // 顶层数据库特定数据
}
```

### 已提取 vs 未提取对比

| 字段                                         | 已提取 | 提取位置 (`scan.py`)                                | 展示价值 |
| -------------------------------------------- | :----: | --------------------------------------------------- | :------: |
| `id`                                         |   ✅   | `build_official_vulnerability()`                    |    —     |
| `aliases`                                    |   ✅   | `build_official_vulnerability()`                    |    —     |
| `summary`                                    |   ✅   | `build_official_vulnerability()`                    |    —     |
| `details`                                    |   ⚠️   | 仅做 `summary` 的备选 (`summary or details`)        |  ⭐⭐⭐  |
| `severity[].score`                           |   ✅   | `extract_osv_cvss()`                                |    —     |
| `severity[].type`                            |   ❌   | 未提取（CVSS 版本：V2/V3/V4）                       |   ⭐⭐   |
| `affected[].ranges[].events[].fixed`         |   ✅   | `extract_osv_fixed_versions()`                      |    —     |
| `affected[].ranges[].events[].introduced`    |   ❌   | 未提取（漏洞引入版本）                              |   ⭐⭐   |
| `affected[].ranges[].events[].last_affected` |   ❌   | 未提取（最后受影响版本）                            |   ⭐⭐   |
| `affected[].versions[]`                      |   ❌   | 未提取（明确受影响版本列表）                        |  ⭐⭐⭐  |
| `affected[].severity`                        |   ❌   | 未提取（包级别严重度）                              |   ⭐⭐   |
| `affected[].ecosystem_specific`              |   ❌   | 未提取                                              |    ⭐    |
| `affected[].database_specific`               |   ❌   | 未提取（如 GitHub 的 `cwe_ids`, `github_reviewed`） |   ⭐⭐   |
| `affected[].package.purl`                    |   ❌   | 未提取                                              |    ⭐    |
| **`references[]`**                           |   ❌   | **未提取（advisory/patch/article/detection 链接）** |  ⭐⭐⭐  |
| **`published`**                              |   ❌   | **未提取（漏洞发布时间）**                          |  ⭐⭐⭐  |
| `modified`                                   |   ❌   | 未提取（最后修改时间）                              |    ⭐    |
| **`withdrawn`**                              |   ❌   | **未提取（撤回标记）**                              |   ⭐⭐   |
| `credits[]`                                  |   ❌   | 未提取（发现者/报告者）                             |    ⭐    |
| `related[]`                                  |   ❌   | 未提取（相关漏洞 ID）                               |    ⭐    |
| `upstream[]`                                 |   ❌   | 未提取（上游漏洞 ID）                               |    ⭐    |

---

## 2. NVD (`services.nvd.nist.gov`) — CVE 详细信息

### 端点

| 端点     | URL                                                               | 用途            |
| -------- | ----------------------------------------------------------------- | --------------- |
| CVE 查询 | `GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveIds=...` | 批量查 CVE 详情 |

### 完整字段清单（单个 CVE 记录）

```json
{
  "cve": {
    "id": "string",                          // CVE-ID
    "sourceIdentifier": "string",            // 数据来源 CNA 标识
    "published": "string (ISO 8601)",        // 发布时间
    "lastModified": "string (ISO 8601)",     // 最后修改时间
    "vulnStatus": "string",                  // 漏洞状态
                                            //   Analyzed | Modified | Deferred |
                                            //   Rejected | Received | AwaitingAnalysis |
                                            //   UndergoingAnalysis
    "cveTags": [{                            // CVE 标签
      "sourceIdentifier": "string",
      "tags": ["disputed" | "unsupported-when-assigned" | "exclusively-hosted-service"]
    }],
    "descriptions": [{                       // 漏洞描述（多语言）
      "lang": "string",                      // 语言代码 (en, es 等)
      "value": "string"                      // 描述文本
    }],
    "metrics": {                             // CVSS 评分
      "cvssMetricV2": [{
        "source": "string",
        "type": "Primary | Secondary",
        "cvssData": {
          "version": "2.0",
          "vectorString": "string",          // CVSS v2 向量
          "accessVector": "NETWORK | ADJACENT_NETWORK | LOCAL",
          "accessComplexity": "HIGH | MEDIUM | LOW",
          "authentication": "MULTIPLE | SINGLE | NONE",
          "confidentialityImpact": "COMPLETE | PARTIAL | NONE",
          "integrityImpact": "COMPLETE | PARTIAL | NONE",
          "availabilityImpact": "COMPLETE | PARTIAL | NONE",
          "baseScore": number
        },
        "baseSeverity": "HIGH | MEDIUM | LOW",
        "exploitabilityScore": number,
        "impactScore": number,
        "acInsufInfo": boolean,
        "obtainAllPrivilege": boolean,
        "obtainUserPrivilege": boolean,
        "obtainOtherPrivilege": boolean,
        "userInteractionRequired": boolean
      }],
      "cvssMetricV30": [{ /* 同 V31 结构，version="3.0" */ }],
      "cvssMetricV31": [{
        "source": "string",
        "type": "Primary | Secondary",
        "cvssData": {
          "version": "3.1",
          "vectorString": "string",          // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
          "attackVector": "NETWORK | ADJACENT_NETWORK | LOCAL | PHYSICAL",
          "attackComplexity": "HIGH | LOW",
          "privilegesRequired": "HIGH | LOW | NONE",
          "userInteraction": "NONE | REQUIRED",
          "scope": "UNCHANGED | CHANGED",
          "confidentialityImpact": "HIGH | LOW | NONE",
          "integrityImpact": "HIGH | LOW | NONE",
          "availabilityImpact": "HIGH | LOW | NONE",
          "baseScore": number,
          "baseSeverity": "CRITICAL | HIGH | MEDIUM | LOW"
        },
        "exploitabilityScore": number,
        "impactScore": number
      }],
      "cvssMetricV40": [{ /* CVSS v4.0 结构 */ }]
    },
    "weaknesses": [{                         // CWE 弱点类型
      "source": "string",
      "type": "Primary | Secondary",
      "description": [{
        "lang": "string",
        "value": "string"                    // CWE-ID (如 CWE-79)
      }]
    }],
    "configurations": [{                     // 受影响产品 (CPE)
      "nodes": [{
        "operator": "OR | AND",
        "negate": boolean,
        "cpeMatch": [{
          "vulnerable": boolean,
          "criteria": "string",              // CPE 匹配字符串
          "matchCriteriaId": "string (UUID)"
        }]
      }]
    }],
    "references": [{                         // 参考链接
      "url": "string",
      "source": "string"
      // 注：NVD 文档提到 references 有 resource tags（如 Third Party Advisory,
      //     Vendor Advisory, Patch 等），但 API 响应中 tags 字段可能不总是出现
    }],
    "evaluatorComment": "string",            // NVD 分析师评论
    "evaluatorImpact": "string",             // NVD 评估影响说明
    "evaluatorSolution": "string",           // NVD 建议解决方案
    "vendorComments": [{                     // 厂商官方声明
      "organization": "string",              // 厂商名称（如 Red Hat, Adobe）
      "comment": "string",                   // 声明内容
      "lastModified": "string"               // 声明更新时间
    }],
    // CISA KEV 内嵌字段（NVD 内的冗余副本）
    "cisaExploitAdd": "string",              // CISA KEV 收录日期
    "cisaActionDue": "string",               // CISA 要求修复截止日
    "cisaRequiredAction": "string",          // CISA 要求的修复动作
    "cisaVulnerabilityName": "string"        // CISA 漏洞名称
  }
}
```

### 已提取 vs 未提取对比

| 字段                                            | 已提取 | 提取位置 (`scan.py`)                                 | 展示价值 |
| ----------------------------------------------- | :----: | ---------------------------------------------------- | :------: |
| `id`                                            |   ✅   | `parse_nvd_vulnerability_entry()`                    |    —     |
| `descriptions[]` (English)                      |   ✅   | `first_english_description()`                        |    —     |
| `metrics.cvssMetricV*` (baseScore/baseSeverity) |   ✅   | `extract_cvss_metrics()` / `normalize_cvss_metric()` |    —     |
| `metrics.*.exploitabilityScore`                 |   ✅   | `normalize_cvss_metric()`                            |    —     |
| `metrics.*.impactScore`                         |   ✅   | `normalize_cvss_metric()`                            |    —     |
| `weaknesses[]` → CWE IDs                        |   ✅   | `extract_cwe_ids()`                                  |    —     |
| `published`                                     |   ✅   | `nvdPublishedAt`                                     |    —     |
| `lastModified`                                  |   ✅   | `nvdModifiedAt`                                      |    —     |
| **`references[]`**                              |   ❌   | **未提取（补丁/公告/厂商建议链接）**                 |  ⭐⭐⭐  |
| **`vulnStatus`**                                |   ❌   | **未提取（Analyzed/Rejected/Modified 等）**          |   ⭐⭐   |
| **`cveTags[]`**                                 |   ❌   | **未提取（disputed/unsupported 标签）**              |   ⭐⭐   |
| `sourceIdentifier`                              |   ❌   | 未提取（CNA 数据来源）                               |    ⭐    |
| CVSS `attackVector`                             |   ❌   | 未提取（攻击途径：N/A/L/P）                          |  ⭐⭐⭐  |
| CVSS `attackComplexity`                         |   ❌   | 未提取（攻击复杂度）                                 |   ⭐⭐   |
| CVSS `privilegesRequired`                       |   ❌   | 未提取（是否需要权限）                               |   ⭐⭐   |
| CVSS `userInteraction`                          |   ❌   | 未提取（是否需要用户交互）                           |   ⭐⭐   |
| CVSS `scope`                                    |   ❌   | 未提取（影响范围）                                   |    ⭐    |
| CVSS `confidentialityImpact`                    |   ❌   | 未提取（机密性影响）                                 |   ⭐⭐   |
| CVSS `integrityImpact`                          |   ❌   | 未提取（完整性影响）                                 |   ⭐⭐   |
| CVSS `availabilityImpact`                       |   ❌   | 未提取（可用性影响）                                 |   ⭐⭐   |
| CVSS `vectorString`                             |   ✅   | `normalize_cvss_metric()` 存为 `"vector"`            |    —     |
| `configurations[]`                              |   ❌   | 未提取（CPE 受影响产品列表）                         |    ⭐    |
| **`vendorComments[]`**                          |   ❌   | **未提取（厂商官方声明）**                           |  ⭐⭐⭐  |
| `evaluatorComment`                              |   ❌   | 未提取（NVD 分析师评论）                             |    ⭐    |
| `evaluatorImpact`                               |   ❌   | 未提取（NVD 影响评估）                               |    ⭐    |
| `evaluatorSolution`                             |   ❌   | 未提取（NVD 建议解决方案）                           |   ⭐⭐   |
| `cisaExploitAdd` 等                             |   ❌   | 未提取（NVD 内嵌 CISA KEV，与独立 KEV API 冗余）     |    ⭐    |

---

## 3. CISA KEV (`cisa.gov`) — 已知被利用漏洞

### 端点

| 端点     | URL                                                                                       | 用途                           |
| -------- | ----------------------------------------------------------------------------------------- | ------------------------------ |
| KEV 目录 | `GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | 下载完整 KEV 目录（~2MB JSON） |

### 完整字段清单（单条记录）

```json
{
  "cveID": "string", // CVE-ID
  "vendorProject": "string", // 厂商/项目名
  "product": "string", // 产品名
  "vulnerabilityName": "string", // 漏洞名称
  "dateAdded": "string (YYYY-MM-DD)", // 加入 KEV 目录的日期
  "shortDescription": "string", // 简短描述
  "requiredAction": "string", // 要求的修复动作
  "dueDate": "string (YYYY-MM-DD)", // 修复截止日期
  "knownRansomwareCampaignUse": "string", // 勒索软件利用情况 ("Known" | "Unknown")
  "cwes": ["string"], // CWE ID 列表
  "notes": "string" // 额外备注
}
```

### 已提取 vs 未提取对比

| 字段                         | 已提取 | 展示价值 |
| ---------------------------- | :----: | :------: |
| `cveID`                      |   ✅   |    —     |
| `vulnerabilityName`          |   ✅   |    —     |
| `shortDescription`           |   ✅   |    —     |
| `dateAdded`                  |   ✅   |    —     |
| `dueDate`                    |   ✅   |    —     |
| `knownRansomwareCampaignUse` |   ✅   |    —     |
| `requiredAction`             |   ✅   |    —     |
| `vendorProject`              |   ✅   |    —     |
| `product`                    |   ✅   |    —     |
| `notes`                      |   ✅   |    —     |
| `cwes`                       |   ✅   |    —     |

**结论：CISA KEV 提取完整，无增量字段。**

---

## 4. FIRST EPSS (`api.first.org`) — 漏洞利用预测

### 端点

| 端点      | URL                                              | 用途                           |
| --------- | ------------------------------------------------ | ------------------------------ |
| EPSS 查询 | `GET https://api.first.org/data/v1/epss?cve=...` | 批量查 EPSS 分数（100 CVE/次） |

### 完整字段清单

```json
{
  "status": "string",
  "total": number,
  "data": [{
    "cve": "string",               // CVE-ID
    "epss": "string (float)",      // EPSS 分数 (0-1)，预测 30 天内被利用的概率
    "percentile": "string (float)",// 百分位 (0-1)，相对排名
    "date": "string (YYYY-MM-DD)", // 评分日期
    "model_version": "string"      // 模型版本（如 "v2024.01.01"）
  }]
}
```

### 已提取 vs 未提取对比

| 字段            | 已提取 | 展示价值 |
| --------------- | :----: | :------: |
| `cve`           |   ✅   |    —     |
| `epss`          |   ✅   |    —     |
| `percentile`    |   ✅   |    —     |
| `date`          |   ✅   |    —     |
| `model_version` |   ✅   |    —     |

**结论：EPSS 提取完整，无增量字段。**

---

## 5. 丰富展示建议

### Tier 1：高价值（用户最关心，实现 ROI 最高）

| #   | 新增内容              | 来源 API                                                               | 当前问题                                       | 建议展示方式                                                        |
| --- | --------------------- | ---------------------------------------------------------------------- | ---------------------------------------------- | ------------------------------------------------------------------- |
| 1   | **参考链接**          | OSV `references[]` + NVD `references[]`                                | 用户看到 GHSA/CVE ID 但点不进去看详情          | 漏洞表格新增"参考"列，显示 1-2 个关键链接（优先 FIX/ADVISORY 类型） |
| 2   | **CVSS 攻击向量解读** | NVD `attackVector/attackComplexity/privilegesRequired/userInteraction` | 只有分数和等级，不知道能不能远程打、要不要权限 | 展开详情面板用标签展示：`🌐 远程` `🔓 无需权限` `👤 无需交互`       |
| 3   | **漏洞发布时间**      | OSV `published` + NVD `published`                                      | 无法判断漏洞是昨天的还是 3 年前的              | 表格或详情显示："发布于 2024-03-15，已公开 1 年+"                   |
| 4   | **厂商声明**          | NVD `vendorComments[]`                                                 | 厂商可能说"我产品不受影响"，但报告没体现       | 详情面板高亮显示："🛡️ Red Hat 声明：不受影响"                       |

### Tier 2：中等价值（提升专业度和决策质量）

| #   | 新增内容           | 来源 API                                                       | 说明                                                         | 建议展示方式                                        |
| --- | ------------------ | -------------------------------------------------------------- | ------------------------------------------------------------ | --------------------------------------------------- |
| 5   | **漏洞状态标签**   | NVD `vulnStatus` + `cveTags`                                   | `disputed`（有争议）/ `Rejected`（已拒绝）应标出来           | 风险信号标签新增：`⚠️ 有争议` `🚫 已拒绝`           |
| 6   | **CIA 影响维度**   | NVD `confidentialityImpact/integrityImpact/availabilityImpact` | 比单纯分数更直观：影响数据机密性还是服务可用性               | 标签展示：`🔒 机密性:H` `📝 完整性:H` `⚡ 可用性:L` |
| 7   | **受影响版本范围** | OSV `affected[].versions[]` + `introduced` event               | 用户只看到"当前版本"和"修复版本"，不知道从哪个版本开始受影响 | 详情显示："从 v1.2.0 引入，v1.3.1 修复"             |
| 8   | **漏洞详情全文**   | OSV `details`                                                  | 比现有 `summary` 更丰富的 Markdown 技术描述                  | 详情展开面板渲染 Markdown                           |

### Tier 3：锦上添花（提升报告完整度）

| #   | 新增内容         | 来源 API                                           | 说明                       |
| --- | ---------------- | -------------------------------------------------- | -------------------------- |
| 9   | 发现者致谢       | OSV `credits[]`                                    | 漏洞发现者/报告者信息      |
| 10  | CPE 受影响产品   | NVD `configurations[]`                             | 精确到 CPE 级别的产品匹配  |
| 11  | 生态系统特定信息 | OSV `affected[].ecosystem_specific`                | 如 Go 的函数级影响信息     |
| 12  | GitHub 审核标志  | OSV `affected[].database_specific.github_reviewed` | 标记是否经 GitHub 官方审核 |
| 13  | NVD 分析师评论   | NVD `evaluatorComment/Solution/Impact`             | NVD 分析师补充说明         |
| 14  | 撤回标记         | OSV `withdrawn`                                    | 已撤回的漏洞应特殊标注     |
| 15  | Package URL      | OSV `affected[].package.purl`                      | 标准 PURL 标识符           |
| 16  | CVSS 版本区分    | OSV `severity[].type`                              | 区分 CVSS v2/v3/v4         |
| 17  | 相关漏洞         | OSV `related[]` + `upstream[]`                     | 关联但非别名的漏洞列表     |

---

## 6. 当前数据流图

```
packages[] ──→ OSV querybatch ──→ matched (pkg, vuln_id)[]
                                      │
                                      ▼
                              OSV vulns/{id} (详情)
                                      │
                                      ├── id, aliases, summary/details
                                      ├── severity[].score → CVSS 分数
                                      ├── affected[].ranges[].events[].fixed → 修复版本
                                      │
                                      │  ❌ references[], published, withdrawn,
                                      │  ❌ credits[], introduced, last_affected,
                                      │  ❌ affected[].versions[], ecosystem_specific
                                      │
                                      ▼
                              提取 CVE IDs
                                      │
                    ┌─────────────────┼─────────────────┐
                    ▼                 ▼                   ▼
              NVD CVE API      CISA KEV JSON       FIRST EPSS API
                    │                 │                   │
                    ├── description   ├── 完整提取 ✅      ├── 完整提取 ✅
                    ├── CVSS scores   ├── KEV 标记        ├── EPSS 分数
                    ├── CWE IDs       ├── 勒索利用        ├── 百分位
                    ├── published     ├── 修复要求        ├── 评分日期
                    │                 │                   │
                    │  ❌ references[], vulnStatus, cveTags,
                    │  ❌ attackVector, attackComplexity,
                    │  ❌ privilegesRequired, userInteraction,
                    │  ❌ CIA impacts, vendorComments[],
                    │  ❌ configurations[], evaluatorComment
                    │
                    └─────────────────┼─────────────────┘
                                      ▼
                              merge_cve_patch()
                                      │
                                      ▼
                              build_official_vulnerability()
                                      │
                                      ▼
                              analysis.json → security-report.html / security-report.md
```

---

## 7. 可视化建议

### 7.1 漏洞表格增强

当前漏洞表格列：`影响程度 | 依赖名称 | 当前版本 | 修复版本 | GHSA | 说明`

建议增加：

- **参考链接列**：显示最关键的 1-2 个 advisory/patch 链接（小图标）
- **时间列**：漏洞发布时间（如 "2024-03"）

### 7.2 漏洞详情展开面板

点击漏洞行展开，显示完整信息：

```
┌─────────────────────────────────────────────────────┐
│ CVE-2024-1234 · GHSA-xxxx-xxxx                      │
│ 🔴 高风险 · CVSS 8.1                                 │
│ 发布于 2024-03-15 · 已公开 1 年+                      │
├─────────────────────────────────────────────────────┤
│ 攻击条件                                            │
│ 🌐 网络可达  🔓 无需权限  👤 无需用户交互  ⚡ 低复杂度 │
├─────────────────────────────────────────────────────┤
│ 影响维度                                            │
│ 🔒 机密性: 高  📝 完整性: 高  ⚡ 可用性: 低            │
├─────────────────────────────────────────────────────┤
│ 🛡️ Red Hat 声明：此漏洞不影响 Red Hat 版本            │
├─────────────────────────────────────────────────────┤
│ 参考链接                                            │
│ 🔗 GitHub Advisory  🔗 NVD  🔗 Patch Commit         │
├─────────────────────────────────────────────────────┤
│ 技术详情                                            │
│ [details 字段的 Markdown 渲染]                        │
└─────────────────────────────────────────────────────┘
```

### 7.3 风险信号标签增强

当前 `risk_signals` 已有：`cvss_critical`, `cisa_kev`, `ransomware_campaign`, `epss_high_percentile`

建议新增：

- `disputed` — 漏洞有争议
- `withdrawn` — 漏洞已撤回
- `vendor_no_impact` — 厂商声明不受影响
- `remote_exploitable` — 可远程利用（AV:N）
- `no_auth_required` — 无需认证（PR:N）
- `old_vulnerability` — 漏洞公开超过 1 年
- `recent_vulnerability` — 漏洞公开不足 30 天

---

## 8. 实现优先级建议

### Phase 1（最小改动，最大收益）

1. **提取 OSV `references[]`** — 在 `fetch_osv_vulnerability()` 返回后解析
2. **提取 OSV `published`** — 直接从 OSV record 取
3. **提取 NVD `references[]`** — 在 `parse_nvd_vulnerability_entry()` 中新增
4. **提取 NVD CVSS 向量分解** — 在 `normalize_cvss_metric()` 中扩展

### Phase 2（中等改动）

5. **提取 NVD `vulnStatus` + `cveTags`** — 新增状态标签
6. **提取 NVD `vendorComments[]`** — 新增厂商声明
7. **提取 OSV `affected[].versions[]` + `introduced`** — 受影响范围
8. **提取 OSV `details`** — 完整技术描述

### Phase 3（锦上添花）

9. OSV `credits[]`、`withdrawn`、`ecosystem_specific`
10. NVD `configurations[]`、`evaluatorComment`
11. 前端展开面板、CVSS 向量可视化
