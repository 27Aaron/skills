# 基线文件使用指南

## 概述

基线文件（`.butian-baseline.json`）用于标记已确认的、可接受的安全发现。被基线收录的条目不会出现在最终报告中，减少噪音，让团队聚焦于新发现的风险。

## 何时使用基线

- **已评估的漏洞**：团队已确认某个漏洞不影响生产环境，暂不修复
- **测试用凭证**：代码中的测试用 API Key，非生产环境使用
- **遗留敏感文件**：历史提交中的配置文件，已确认无安全风险
- **已知技术债**：已排入修复计划但尚未处理的低优先级问题

## 基线文件格式

文件位置：项目根目录 `.butian-baseline.json`

```json
{
  "version": 1,
  "description": "补天扫描基线：已知/接受的发现将不会出现在最终报告中",
  "entries": [
    {
      "fingerprint": "vuln__npm__lodash__4.17.20__GHSA-jjhx-jh4p-89rf",
      "reason": "已评估：该漏洞仅影响模板编译功能，项目未使用此功能",
      "suppressed_at": "2026-06-01T10:00:00",
      "package": "lodash",
      "version": "4.17.20",
      "vuln_id": "GHSA-jjhx-jh4p-89rf"
    },
    {
      "fingerprint": "secret__tests/config.py__42__aws_access_key",
      "reason": "测试用凭证，指向 LocalStack 本地环境",
      "suppressed_at": "2026-06-01T10:00:00",
      "file": "tests/config.py",
      "line": 42,
      "type": "aws_access_key"
    },
    {
      "fingerprint": "sensitive__.env.example__env_file",
      "reason": "示例环境变量文件，不含真实凭证",
      "suppressed_at": "2026-06-01T10:00:00",
      "file": ".env.example",
      "type": "env_file"
    }
  ]
}
```

### 字段说明

| 字段            | 必填 | 说明                           |
| --------------- | ---- | ------------------------------ |
| `fingerprint`   | ✅   | 发现的唯一指纹，由工具自动生成 |
| `reason`        | ✅   | 豁免原因，团队可见             |
| `suppressed_at` | ✅   | 豁免时间                       |
| `package`       | ❌   | 漏洞所属包名                   |
| `version`       | ❌   | 受影响版本                     |
| `vuln_id`       | ❌   | 漏洞 ID (GHSA/CVE)             |
| `file`          | ❌   | 文件路径                       |
| `line`          | ❌   | 行号                           |
| `type`          | ❌   | 密钥/文件类型                  |

## 使用方式

### 自动生成基线

从当前扫描结果自动生成基线文件：

```bash
# 一步到位：扫描并生成基线
python3 butian/scripts/run_audit.py --generate-baseline .

# 或在 scan.py 中单独生成
python3 butian/scripts/scan.py --generate-baseline .
```

### 手动创建基线

1. 运行扫描，查看报告中的发现
2. 复制需要豁免的条目的 `fingerprint`
3. 创建 `.butian-baseline.json`，将条目添加到 `entries` 数组
4. 填写 `reason` 字段说明豁免原因

### 使用基线过滤

```bash
# 启用基线过滤（如果存在基线文件）
python3 butian/scripts/run_audit.py --baseline .

# 在 CI 中结合使用
python3 butian/scripts/run_audit.py --baseline --severity-threshold high .
```

### 跳过基线

如果需要查看全部发现（包括已豁免的）：

```bash
python3 butian/scripts/run_audit.py --skip-baseline .
```

## 指纹规则

补天为不同类型的发现生成不同格式的指纹：

### 漏洞指纹

```
vuln__{ecosystem}__{package}__{version}__{vuln_id}
```

示例: `vuln__npm__express__4.17.3__GHSA-rv95-8r57-2r2r`

### 密钥指纹

```
secret__{file}__{line}__{type}
```

示例: `secret__config/database.py__15__generic_password`

### 敏感文件指纹

```
sensitive__{file}__{type}
```

示例: `sensitive__.env__env_file`

## 注意事项

- 基线文件**应该提交到版本控制**，让整个团队共享
- 定期审查基线条目，移除不再适用的豁免
- 每个条目**必须**填写豁免原因（`reason`）
- 版本升级后，对应的漏洞指纹可能变化，需更新基线
- 基线不能替代修复，只是延迟处理已知风险的标记方式

## 与退出码配合

```bash
# CI 示例：基线过滤后，如果仍有 high 以上漏洞则失败
python3 butian/scripts/run_audit.py \
    --baseline \
    --severity-threshold high \
    .
echo "退出码: $?"
# 0 = 基线过滤后无高风险发现
# 1 = 仍有未豁免的高风险发现
# 2 = 执行错误
```
