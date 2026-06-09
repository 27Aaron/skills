# labels.py 技术文档

> 源码路径：`butian/scripts/labels.py`

## 概览

`labels.py` 维护面向用户展示的共享中文标签。它把扫描器内部的机器标识，例如 `openai_key`、`terraform_state`，映射成 Markdown 和 HTML 报告可读的中文名称。

## 职责

| #   | 职责         | 说明                                                          |
| --- | ------------ | ------------------------------------------------------------- |
| 1   | 密钥标签     | 为 `scan.SECRET_REGEXES` 中的 secret type 提供展示名称        |
| 2   | 敏感文件标签 | 为 `scan.SENSITIVE_FILE_PATTERNS` 中的 file type 提供展示名称 |
| 3   | 展示一致性   | 让 `analyze.py`、`report.py`、`visualize.py` 使用同一份标签   |
| 4   | 新类型守护   | 通过单元测试发现新增扫描类型但没有展示文案的情况              |

## 导出对象

### `SECRET_TYPE_LABELS`

密钥类型标签表。示例：

| key                  | 展示名称             |
| -------------------- | -------------------- |
| `openai_key`         | OpenAI API Key       |
| `aws_access_key`     | AWS 访问密钥         |
| `aws_session_token`  | AWS 临时会话 Token   |
| `gcp_oauth_token`    | GCP OAuth Token      |
| `mongodb_connection` | MongoDB 连接字符串   |
| `base64_secret`      | 疑似 Base64 编码密钥 |

### `SENSITIVE_TYPE_LABELS`

敏感文件类型标签表。示例：

| key               | 展示名称              |
| ----------------- | --------------------- |
| `env_file`        | 环境变量文件          |
| `private_key`     | 私钥或证书文件        |
| `terraform_state` | Terraform 状态文件    |
| `kubeconfig`      | Kubernetes kubeconfig |
| `docker_cfg`      | Docker 凭据配置       |
| `history`         | 命令历史文件          |

## 使用位置

| 脚本           | 使用方式                                                            |
| -------------- | ------------------------------------------------------------------- |
| `analyze.py`   | 在 `build_hygiene_items()` 中把密钥和敏感文件类型转换成行动项名称   |
| `report.py`    | 在 Markdown 仓库安检表格、敏感文件表格和人工确认事项中显示中文类型  |
| `visualize.py` | 注入 `report.js`，让 HTML 前端使用同一份标签                        |
| `report.js`    | 在 HTML 的 `仓库安检 / 凭证与敏感文件` 中渲染密钥和敏感文件中文类型 |

## HTML 注入

`visualize.py` 会在内联 `report.js` 前替换两个占位符：

```js
__SECRET_TYPE_LABELS__;
__SENSITIVE_TYPE_LABELS__;
```

替换值来自 `labels.py`，并通过 `json_for_script()` 做 `<script>` 安全转义。这样新增扫描类型时只需要改一处标签表，Markdown 和 HTML 两端都会同步。

## 测试覆盖

主要测试文件：`tests/butian/test_labels.py`。

覆盖点包括：

- `SECRET_TYPE_LABELS` 覆盖 `scan.SECRET_REGEXES` 的所有 secret type。
- `SENSITIVE_TYPE_LABELS` 覆盖 `scan.SENSITIVE_FILE_PATTERNS` 的所有 file type。
- key 为小写机器标识，不包含空格。
- value 非空且不是简单重复 key。
- `analyze.py` 和 `report.py` 引用的是同一份共享字典。
- 报告 helper 对未知类型有稳定 fallback。

## 维护流程

新增密钥规则或敏感文件规则时：

1. 在 `scan.py` 增加扫描类型。
2. 在 `labels.py` 增加展示名称。
3. 如果 HTML 需要特殊分类，再检查 `report.js` 是否有分组逻辑。
4. 运行 `python3 -m unittest tests.butian.test_labels -v`。
5. 再运行完整 `python3 -m unittest discover -s tests -v`。
