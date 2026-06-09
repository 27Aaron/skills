# iac_checks.py 技术文档

> 源码路径：`butian/scripts/iac_checks.py`

## 概览

`iac_checks.py` 检查仓库中的 IaC、容器和部署配置风险。它是纯本地规则模块，不解析云账号、不连接集群，也不修改配置文件。

## 职责

| #   | 职责            | 说明                                                 |
| --- | --------------- | ---------------------------------------------------- |
| 1   | Dockerfile 检查 | 镜像标签、用户权限、远程脚本、敏感环境变量           |
| 2   | Compose 检查    | privileged、Docker socket、端口暴露、明文 secret     |
| 3   | Kubernetes 检查 | Secret、hostPath、hostNetwork、privileged、root 用户 |
| 4   | Terraform 检查  | state/tfvars、敏感端口公网开放                       |
| 5   | finding 输出    | 使用 `finding_utils.py` 统一证据、行号和 schema      |

## 扫描范围

| 类型           | 文件模式                                | 输出字段             |
| -------------- | --------------------------------------- | -------------------- |
| Dockerfile     | `Dockerfile`、`*.Dockerfile`            | `hygiene.iac_checks` |
| Docker Compose | `docker-compose.yml`、`compose.yaml` 等 | `hygiene.iac_checks` |
| Kubernetes     | `*.yaml`、`*.yml` 中的 K8s 资源         | `hygiene.iac_checks` |
| Terraform      | `*.tf`、`*.tfvars`、`terraform.tfstate` | `hygiene.iac_checks` |

## Dockerfile 规则

| 规则                   | 严重度     | 说明                                     |
| ---------------------- | ---------- | ---------------------------------------- |
| 使用 `latest` 标签     | medium     | 构建结果会随时间漂移，漏洞暴露面不可复现 |
| 缺少非 root `USER`     | low/medium | 容器进程默认 root 增加逃逸后的影响范围   |
| `curl/wget ... \| sh`  | medium/high | 远端脚本被替换时会直接进入镜像或构建机  |
| `ADD` 远程 URL         | medium     | 构建时下载远端内容，缺少完整性校验       |
| `ENV` 中出现 secret    | high       | 明文密钥可能进入镜像层和镜像历史         |

## Compose 规则

| 规则                        | 严重度      | 说明                                        |
| --------------------------- | ----------- | ------------------------------------------- |
| `privileged: true`          | high        | 容器获得过宽宿主机能力                      |
| 挂载 `/var/run/docker.sock` | high        | 容器可控制宿主 Docker daemon                |
| 敏感端口绑定 `0.0.0.0`      | medium/high | 数据库、Redis、管理端口可能被公网访问       |
| 环境变量明文 secret         | high        | 凭据可能进入版本库、日志或容器 inspect 输出 |

## Kubernetes 规则

| 规则                            | 严重度      | 说明                                    |
| ------------------------------- | ----------- | --------------------------------------- |
| Secret 使用明文 data/stringData | medium      | YAML 中保存敏感内容，需要确认是否真实值 |
| `securityContext.privileged`    | high        | Pod 容器获得过宽宿主机权限              |
| `hostPath`                      | high        | 容器可读写宿主机路径                    |
| `hostNetwork: true`             | medium/high | Pod 使用宿主网络，绕过部分网络隔离      |
| root 用户运行                   | medium      | 容器内权限过高，扩大入侵影响            |

## Terraform 规则

| 规则                             | 严重度      | 说明                                                 |
| -------------------------------- | ----------- | ---------------------------------------------------- |
| 提交 `terraform.tfstate`         | high        | state 可能包含云资源 ID、数据库密码和 provider token |
| 提交 `*.tfvars`                  | medium/high | 变量文件常保存凭据或生产配置                         |
| 安全组开放敏感端口到 `0.0.0.0/0` | high        | 数据库、SSH、管理端口可能直接暴露公网                |

## 输出示例

```json
{
  "id": "iac.docker_latest_tag",
  "category": "iac_container",
  "severity": "medium",
  "confidence": "high",
  "file": "Dockerfile",
  "line": 1,
  "title": "Dockerfile 使用 latest 镜像标签",
  "detail": "latest 会随时间漂移，构建结果和漏洞暴露面不可复现。",
  "evidence": "FROM node:latest",
  "recommendation": "固定到具体版本标签；高要求发布链路可进一步固定 digest。",
  "source": "builtin",
  "fixable": false
}
```

## 测试覆盖

主要测试文件：`tests/butian/test_iac_checks.py`。

覆盖点包括：

- Dockerfile latest、缺 USER、远程脚本、远程 ADD、ENV secret。
- Compose privileged、Docker socket、端口暴露、环境变量 secret。
- Kubernetes Secret、privileged、hostPath、hostNetwork、root 用户。
- Terraform state/tfvars、公网敏感端口。
- 证据截断、行号定位和去重。

## 维护注意

IaC 文件格式灵活，当前规则以轻量文本/结构识别为主。新增规则时优先保证低误报：能从本地文件直接证明的事实才给高严重度；需要团队确认的配置使用 medium、low 或 info，并在 recommendation 中说明确认动作。
