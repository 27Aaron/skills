# sarif.py 技术文档

> 源码路径：`butian/scripts/sarif.py`

## 概览

`sarif.py` 将 `analysis.json` 转换为 [SARIF v2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)（Static Analysis Results Interchange Format）标准格式，用于与 GitHub Advanced Security、GitLab SAST、Azure DevOps 等安全面板集成。

## 职责

| #   | 职责         | 说明                                                      |
| --- | ------------ | --------------------------------------------------------- |
| 1   | 漏洞转换     | 将 `top_issues` 中的依赖漏洞转为 SARIF results            |
| 2   | 密钥转换     | 将 `tracked_secrets` 中的硬编码密钥发现转为 SARIF results |
| 3   | 敏感文件转换 | 将 `sensitive_tracked` 中的敏感文件发现转为 SARIF results |
| 4   | 规则生成     | 自动生成去重的 SARIF rules，包含 helpUri 链接             |

## CLI 用法

```bash
# 自动输出到 analysis.json 同目录
python3 sarif.py .butian/<timestamp>/assets/analysis.json

# 指定输出路径
python3 sarif.py analysis.json output.sarif.json
```

## 严重度映射

| butian 严重度 | SARIF level | SARIF rank |
| ------------- | ----------- | ---------- |
| critical      | error       | 9.0        |
| high          | error       | 9.0        |
| medium        | warning     | 5.0        |
| low           | note        | 3.0        |
| info          | note        | 1.0        |

## 关键函数

| 函数                                        | 作用                                                     |
| ------------------------------------------- | -------------------------------------------------------- |
| `build_sarif(analysis)`                     | 从 analysis JSON 构建完整 SARIF 文档                     |
| `sarif_rule_from_vulnerability(vuln, idx)`  | 将漏洞转为 SARIF rule（含 GHSA/CVE 链接）                |
| `sarif_result_from_vulnerability(vuln, ri)` | 将漏洞转为 SARIF result                                  |
| `sarif_result_from_secret(secret)`          | 将密钥发现转为 SARIF result                              |
| `sarif_result_from_sensitive(item)`         | 将敏感文件发现转为 SARIF result                          |
| `default_output_path(analysis_path)`        | 默认输出到 `analysis.json` 同目录的 `results.sarif.json` |

## 输出结构

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "补天 (Butian)",
        "version": "1.0.0",
        "rules": [...]
      }
    },
    "results": [...],
    "invocations": [{
      "executionSuccessful": true,
      "startTimeUtc": "2026-06-05 10:00:00"
    }]
  }]
}
```

## Rule ID 约定

| 发现类型 | Rule ID 格式              | 示例                                   |
| -------- | ------------------------- | -------------------------------------- |
| 漏洞     | 原始 advisory_id / cve_id | `GHSA-jjhx-jh4p-89rf`, `CVE-2024-1234` |
| 密钥     | `butian-secret-{type}`    | `butian-secret-aws_access_key`         |
| 敏感文件 | `butian-sensitive-{type}` | `butian-sensitive-env_file`            |

## 集成方式

在 `run_audit.py` 中通过 `--sarif` 参数触发：

```bash
python3 run_audit.py --sarif --compact --no-open .
# 输出: .butian/<timestamp>/assets/results.sarif.json
```

GitHub Actions 上传示例：

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: .butian/*/assets/results.sarif.json
    category: butian-security
```

## 相关文档

| 文档                       | 说明           |
| -------------------------- | -------------- |
| `docs/butian/run_audit.md` | 管线编排器文档 |
| `docs/butian/ci-cd.md`     | CI/CD 集成模板 |
