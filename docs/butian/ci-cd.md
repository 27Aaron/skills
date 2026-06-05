# CI/CD 集成指南

补天支持在 CI/CD 流水线中作为安全扫描步骤使用。本文档提供常见 CI/CD 平台的集成模板。

## 通用原则

- 使用 `--compact` 输出 JSON 摘要，便于脚本解析
- 使用 `--no-open` 避免 CI 环境尝试打开浏览器
- 使用 `--severity-threshold` 控制流水线通过/失败
- 使用 `--sarif` 生成 SARIF 格式结果，上传到安全面板

---

## GitHub Actions

```yaml
name: Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: "0 2 * * 1" # 每周一凌晨 2 点

jobs:
  butian-security:
    runs-on: ubuntu-latest
    permissions:
      security-events: write # SARIF 上传需要

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.x"

      - name: Run Butian Security Scan
        run: |
          python3 butian/scripts/run_audit.py \
            --compact \
            --no-open \
            --sarif \
            --severity-threshold high \
            .

      - name: Upload SARIF results
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: .butian/*/assets/results.sarif.json
          category: butian-security

      - name: Archive scan artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: butian-scan-results
          path: .butian/
          retention-days: 30
```

### 退出码说明

| 退出码 | 含义                    | GitHub Actions 行为 |
| ------ | ----------------------- | ------------------- |
| 0      | 无超阈值发现            | 步骤通过            |
| 1      | 存在 high/critical 漏洞 | 步骤失败（默认）    |
| 2      | 执行错误                | 步骤失败            |

---

## GitLab CI

```yaml
stages:
  - security

butian-security:
  stage: security
  image: python:3-slim
  variables:
    SEVERITY_THRESHOLD: "high"
  script:
    - python3 butian/scripts/run_audit.py
      --compact
      --no-open
      --sarif
      --severity-threshold $SEVERITY_THRESHOLD
      .
  artifacts:
    paths:
      - .butian/
    reports:
      # SARIF 可被 GitLab 安全面板识别（14.8+）
    when: always
    expire_in: 30 days
  # 允许 exit code 1 (发现漏洞) 不阻塞流水线
  allow_failure:
    exit_codes: 1
  # 但 exit code 2 (执行错误) 会阻塞
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

---

## Jenkins Pipeline

```groovy
pipeline {
    agent any

    tools {
        python 'Python3'
    }

    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    python3 butian/scripts/run_audit.py \
                        --compact \
                        --no-open \
                        --sarif \
                        --severity-threshold high \
                        .
                '''
            }
            post {
                always {
                    archiveArtifacts(
                        artifacts: '.butian/**/*',
                        allowEmptyArchive: true
                    )
                    // 发布 SARIF 结果（需要 SARIF 插件）
                    recordIssues(
                        tools: [sarif(pattern: '.butian/*/assets/results.sarif.json')],
                        qualityGates: [
                            [threshold: 0, type: 'TOTAL_ERROR', unstable: false]
                        ]
                    )
                }
            }
        }
    }
}
```

---

## 基线模式（已知问题豁免）

在 CI 中使用基线文件，忽略已确认的已知问题：

```bash
# 首次运行，生成基线
python3 butian/scripts/run_audit.py --generate-baseline .

# 后续运行，自动过滤基线中的已知问题
python3 butian/scripts/run_audit.py --baseline --severity-threshold high .
```

基线文件 `.butian-baseline.json` 应提交到仓库，团队共享。

---

## 定时扫描

建议配置定时扫描（如每周一次），及时发现新披露的漏洞：

| 平台           | 配置方式                            |
| -------------- | ----------------------------------- |
| GitHub Actions | `schedule: cron`                    |
| GitLab CI      | Scheduled Pipelines                 |
| Jenkins        | Build Triggers → Build periodically |

---

## 缓存优化

CI 环境通常每次构建都是全新环境，缓存不会持久化。如需加速：

```yaml
# GitHub Actions 缓存示例
- name: Cache butian results
  uses: actions/cache@v4
  with:
    path: .butian/cache/
    key: butian-${{ hashFiles('**/package-lock.json', '**/yarn.lock', '**/requirements.txt') }}
```
