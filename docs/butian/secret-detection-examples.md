# 硬编码密钥检测示例

> 本页示例均为脱敏写法，用于说明报告会识别哪些场景，不包含可复用的真实凭据。

## 覆盖范围

硬编码密钥扫描会读取常见代码、配置、部署和凭据文件，并跳过 lockfile，避免把依赖完整性 hash 当成密钥。

| 位置       | 示例文件                                                    |
| ---------- | ----------------------------------------------------------- |
| 代码与脚本 | `app.py`、`index.ts`、`deploy.sh`                           |
| 配置文件   | `config.json`、`application.properties`、`settings.xml`     |
| 部署文件   | `Dockerfile`、`Makefile`、`prod.tfvars`                     |
| 凭据文件   | `.env`、`.npmrc`、`.pypirc`、`.netrc`、`.aws/credentials`   |
| 云账号文件 | `service-account.json`、`client_secret.json`、`sa-key.json` |

## 常见命中示例

| 场景                                      | 脱敏示例                                              | 报告类型                    |
| ----------------------------------------- | ----------------------------------------------------- | --------------------------- |
| GCP 服务账号 JSON                         | `"type": "service_account"`                           | `gcp_service_account`       |
| OpenAI / 兼容 LLM Key                     | `OPENAI_API_KEY=sk-proj-***`                          | `openai_key`                |
| Groq Key                                  | `GROQ_API_KEY=gsk_***`                                | `groq_api_key`              |
| GitHub fine-grained PAT                   | `GITHUB_TOKEN=github_pat_***`                         | `github_fine_grained_pat`   |
| GitLab Runner Token                       | `GITLAB_RUNNER_TOKEN=glrt-***`                        | `gitlab_runner_token`       |
| Vault Token                               | `VAULT_TOKEN=hvs.***`                                 | `hashicorp_vault_token`     |
| Pulumi Token                              | `PULUMI_ACCESS_TOKEN=pul-***`                         | `pulumi_token`              |
| NPM registry Token                        | `//registry.npmjs.org/:_authToken=npm_***`            | `npmrc_auth_token`          |
| `.netrc` 机器密码                         | `machine api.company.local login deploy password ***` | `netrc_password`            |
| URL 内嵌密码                              | `https://deploy:***@api.company.local`                | `basic_auth_url`            |
| Supabase service-role key                 | `SUPABASE_SERVICE_ROLE_KEY=eyJ***`                    | `supabase_service_role_key` |
| Clerk Secret Key                          | `CLERK_SECRET_KEY=sk_live_***`                        | `clerk_secret_key`          |
| Vercel / Netlify / Railway / Render Token | `VERCEL_TOKEN=***`                                    | 对应平台 token 类型         |
| 数据库连接串                              | `postgres://user:***@host/db`                         | `postgres_connection`       |
| 私钥文件内容                              | `-----BEGIN *** PRIVATE KEY-----`                     | `private_key`               |

## 报告里怎么看

| 字段       | 含义                                                                     |
| ---------- | ------------------------------------------------------------------------ |
| 类型       | 命中的密钥类别，例如 `github_token`、`aws_access_key`                    |
| 可信度     | `high` 通常是稳定前缀或明确格式；`medium` 通常需要结合上下文确认         |
| 位置       | 文件路径和行号，用于快速定位                                             |
| 预览       | `secret_preview()` 提供的预览文本；不同密钥类型遮盖程度不同              |
| 代码上下文 | HTML 中可展示命中行前后约 2 行，包含行号、命中行高亮、语言标签和复制按钮 |

`.env.example`、`.env.sample`、`.env.template`、`.env.dist` 这类模板文件不会被当成“敏感文件被 git 跟踪”，但仍会参与密钥特征扫描。HTML 会展示扫描阶段提供的代码上下文，是否完整展示取决于扫描阶段是否允许该文件类型 reveal；这能帮助研发确认它到底是占位样例还是真实可用凭证。

## 处理建议

1. 先确认是否为真实凭据，而不是测试样例或模板值。
2. 若是真实凭据，先在对应平台轮换或吊销。
3. 从仓库中移除明文值，改用本机环境变量、CI secret 或平台 secret 管理。
4. 如凭据已提交到远端仓库，再评估是否需要清理 Git 历史。
