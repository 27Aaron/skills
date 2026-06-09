# workflow_checks.py 技术文档

> 源码路径：`butian/scripts/workflow_checks.py`

## 概览

`workflow_checks.py` 检查 GitHub Actions 工作流中的常见供应链和权限风险。它只读取 `.github/workflows/*.yml` 与 `.github/workflows/*.yaml`，不访问 GitHub API，也不创建或修改 workflow。

## 职责

| #   | 职责           | 说明                                                 |
| --- | -------------- | ---------------------------------------------------- |
| 1   | 权限检查       | 识别 `permissions: write-all` 和缺少显式最小权限边界 |
| 2   | 触发器检查     | 识别高风险 trigger，例如 `pull_request_target`       |
| 3   | checkout 检查  | 检查 PR 场景中是否关闭 `persist-credentials`         |
| 4   | shell 注入检查 | 识别不可信上下文进入 `run:`                          |
| 5   | 远程脚本检查   | 识别 `curl/wget ... \| sh/bash`                      |
| 6   | runner 检查    | 识别 PR 场景使用 self-hosted runner                  |

## 输出字段

所有 finding 会进入 `scan.py` 的 `hygiene.workflow_checks`。示例：

```json
{
  "id": "actions.remote_script_pipe",
  "category": "github_actions",
  "severity": "medium",
  "confidence": "high",
  "file": ".github/workflows/ci.yml",
  "line": 24,
  "title": "workflow 直接执行远程脚本",
  "detail": "curl/wget 管道到 shell 缺少完整性校验，远端脚本被替换时会直接在 runner 上执行。",
  "evidence": "run: curl https://example.com/install.sh | bash",
  "recommendation": "下载固定版本并校验 checksum/signature，或使用可信 action/包管理器替代。",
  "source": "builtin",
  "fixable": false
}
```

## 规则说明

### permissions

| 规则                     | 严重度      | 说明                                            |
| ------------------------ | ----------- | ----------------------------------------------- |
| `permissions: write-all` | high        | workflow token 获得过宽写权限                   |
| 缺少顶层 `permissions`   | low/info    | GitHub 默认权限受仓库设置影响，建议显式最小权限 |
| job 级权限过宽           | medium/high | 单个 job 获得不必要的写权限                     |

### trigger

`pull_request_target` 会在目标仓库上下文运行，对外部 PR 更敏感。该规则不会简单禁止使用，而是结合 checkout、runner 和 run 脚本风险给出建议。

### checkout

PR 相关 workflow 使用 `actions/checkout` 时，如果没有配置 `persist-credentials: false`，token 可能留在 git config 中。建议在不需要 push 的 job 中关闭凭据持久化。

### 不可信上下文

重点识别把以下上下文直接拼入 shell 的情况：

- `github.event.pull_request.title`
- `github.event.pull_request.body`
- `github.head_ref`
- `github.event.issue.title`
- issue/comment/body 等用户可控字段

这类 finding 关注 shell 注入风险，建议改用环境变量、严格引用、白名单或专用 action。

### 远程脚本管道执行

匹配 `curl` 或 `wget` 下载内容后直接管道给 `sh`、`bash`、`python`、`node` 等解释器。建议固定版本、校验 checksum/signature，或使用可信包管理器/action。

### self-hosted runner

外部 PR 触发的 job 如果运行在 `self-hosted` runner 上，恶意 PR 可能接触公司内网、缓存或凭据。建议隔离 runner、限制 trigger，或改用 GitHub-hosted runner。

## 测试覆盖

主要测试文件：`tests/butian/test_workflow_checks.py`。

覆盖点包括：

- `permissions: write-all`。
- 缺少显式 permissions。
- `pull_request_target` 与 checkout 组合。
- `persist-credentials` 未关闭。
- 不可信 GitHub context 进入 `run:`。
- 远程脚本管道执行。
- PR 场景 self-hosted runner。
- 多 workflow 文件遍历、行号定位和去重。

## 维护注意

GitHub Actions YAML 写法很多，本模块偏向保守本地启发式。新增规则时应同时给出明确 evidence 和 remediation，避免只给“可能有风险”但没有可执行动作的提示。
