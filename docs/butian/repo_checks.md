# repo_checks.py 技术文档

> 源码路径：`butian/scripts/repo_checks.py`

## 概览

`repo_checks.py` 负责仓库层面的依赖治理和供应链配置检查。它不调用外部服务，只读取本地文件，把 Dependabot、lockfile、安装脚本和 registry 配置问题转换成统一 finding。

## 职责

| #   | 职责              | 说明                                                   |
| --- | ----------------- | ------------------------------------------------------ |
| 1   | Dependabot 建议   | 在 GitHub 托管仓库中按官方支持生态生成依赖维护配置建议 |
| 2   | lockfile 检查     | 发现 manifest 存在但 lockfile 缺失的生态               |
| 3   | 安装脚本检查      | 识别安装阶段下载远程脚本、base64 解码执行等高风险模式  |
| 4   | registry 配置检查 | 识别 token/password/secret、TLS 降级、私有源提醒       |
| 5   | schema 统一       | 通过 `finding_utils.make_finding()` 输出结构化 finding |

## 输出字段

所有 finding 会进入 `scan.py` 的 `hygiene.repository_checks`：

```json
{
  "id": "repo.install_script_remote",
  "category": "supply_chain",
  "severity": "medium",
  "confidence": "high",
  "file": "package.json",
  "line": 12,
  "title": "安装脚本执行远程内容",
  "detail": "安装阶段下载并执行远程脚本，远端内容被替换时会影响本地或 CI 环境。",
  "evidence": "postinstall: curl https://example.com/install.sh | bash",
  "recommendation": "固定可信来源并校验 checksum/signature，或改用包管理器内置安装方式。",
  "source": "builtin",
  "fixable": false
}
```

## 规则分组

### Dependabot

适用场景：

- `git remote` 指向 GitHub，例如 `git@github.com:org/repo.git` 或 `https://github.com/org/repo.git`。
- 存在 GitHub Dependabot 支持的 dependency manifest、lockfile、workflow 或工具配置。
- 未发现 `.github/dependabot.yml` 或 `.github/dependabot.yaml`。

输出倾向为 `info`，因为它是治理建议，不代表当前已经存在可利用漏洞。报告里会把它放在依赖配置与维护分组，帮助团队建立更新机制。

扫描阶段不会直接写入仓库文件。finding 会携带 `fix_config.type == "dependabot_config"`，用户确认后可通过 `fix.py --strategy dependabot` 创建 `.github/dependabot.yml`；如果文件已存在，修复器不会覆盖。

GitHub remote 使用 `git config --get-regexp '^remote\..*\.url$'` 读取，而不是直接 `cat .git/config`。这样可以兼容 worktree、submodule、include 配置和 `.git` 是文件的情况。

当前支持生成的官方 `package-ecosystem` 值包括：

| GitHub YAML value | 常见触发文件或目录 |
| ----------------- | ------------------ |
| `bazel`           | `MODULE.bazel`、`WORKSPACE` |
| `bun`             | `bun.lock` |
| `bundler`         | `Gemfile`、`Gemfile.lock` |
| `cargo`           | `Cargo.toml`、`Cargo.lock` |
| `composer`        | `composer.json`、`composer.lock` |
| `conda`           | `environment.yml` / `environment.yaml` |
| `deno`            | `deno.json`、`deno.jsonc` |
| `devcontainers`   | `devcontainer.json`、`.devcontainer/devcontainer.json` |
| `docker`          | `Dockerfile`、`Containerfile` |
| `docker-compose`  | `compose.yml`、`docker-compose.yml` 等 |
| `dotnet-sdk`      | `global.json` |
| `helm`            | `Chart.yaml` |
| `mix`             | `mix.exs`、`mix.lock` |
| `julia`           | `Project.toml`、`Manifest.toml` |
| `elm`             | `elm.json` |
| `gitsubmodule`    | `.gitmodules` |
| `github-actions`  | `.github/workflows/*.yml` / `.yaml` |
| `gomod`           | `go.mod`、`go.sum` |
| `gradle`          | `build.gradle`、`build.gradle.kts`、`gradle/libs.versions.toml` |
| `maven`           | `pom.xml` |
| `nix`             | `flake.lock`、`flake.nix` |
| `npm`             | `package.json`、`package-lock.json`、`pnpm-lock.yaml`、`yarn.lock` |
| `nuget`           | `*.csproj`、`*.fsproj`、`*.vbproj`、`packages.config` |
| `opentofu`        | `*.tofu`、`.terraform.lock.hcl` |
| `pip`             | `requirements*.txt`、`pyproject.toml`、`Pipfile`、`poetry.lock` |
| `pre-commit`      | `.pre-commit-config.yaml` / `.yml` |
| `pub`             | `pubspec.yaml`、`pubspec.lock` |
| `rust-toolchain`  | `rust-toolchain`、`rust-toolchain.toml` |
| `sbt`             | `build.sbt`、`project/plugins.sbt`、`project/build.properties` |
| `swift`           | `Package.swift`、`Package.resolved` |
| `terraform`       | `*.tf`、`terragrunt.hcl` |
| `uv`              | `uv.lock` |
| `vcpkg`           | `vcpkg.json`、`vcpkg-configuration.json` |

多语言项目会生成同一份 `.github/dependabot.yml`，并在 `updates` 下为每个生态和目录创建独立条目。重复别名会按 GitHub 要求归并：`pnpm` / `yarn` 使用 `npm`，`poetry` / `pipenv` / `pip-compile` 使用 `pip`。

### lockfile

典型检查：

| manifest                              | 期望 lockfile                                        |
| ------------------------------------- | ---------------------------------------------------- |
| `package.json`                        | `package-lock.json`、`pnpm-lock.yaml` 或 `yarn.lock` |
| `requirements.txt` / `pyproject.toml` | 对应 pip-tools、poetry、uv 或其他锁定文件            |
| `go.mod`                              | `go.sum`                                             |
| `Cargo.toml`                          | `Cargo.lock`                                         |

缺 lockfile 的 finding 通常是 `medium` 或 `low`，取决于生态和上下文。它提示依赖解析不可复现，不等同于确认漏洞。

### 安装脚本

重点识别：

- `curl ... | sh`、`wget ... | bash`。
- `python -c`、`node -e` 等动态执行远程或拼接内容。
- base64 解码后直接执行。
- install/postinstall/preinstall 中的可疑下载和执行组合。

这类问题通常是 `medium` 或 `high`，因为安装阶段常在开发机或 CI 中运行，影响面比普通脚本更大。

### registry 配置

检查对象包括 `.npmrc`、`.yarnrc`、pip 配置、poetry 配置、cargo 配置和 Go proxy 相关配置。

重点识别：

- `token`、`password`、`secret` 等明文凭据。
- `strict-ssl=false`、`verify_ssl=false`、`trusted-host` 等 TLS 降级。
- 私有 registry、镜像源或代理源，需要团队确认来源可信。

## 测试覆盖

主要测试文件：`tests/butian/test_repo_checks.py`。

覆盖点包括：

- GitHub remote 存在且检测到支持生态时，Dependabot 缺失会输出建议和可创建配置。
- `.github/` 存在但没有 GitHub remote 时不输出缺失 Dependabot 建议。
- 官方支持生态映射完整，覆盖多语言、多目录项目。
- 已配置 Dependabot 时不重复输出。
- workflow 引用 action 时提示将 GitHub Actions 纳入版本维护。
- manifest 缺 lockfile。
- npm install/postinstall 远程脚本和 base64 执行。
- `.npmrc` token、registry 来源和 TLS 降级。
- finding 使用统一 schema，证据行号可回溯。

## 维护注意

`repo_checks.py` 的规则应保持“本地可证明”。不能因为看到某个私有 registry 就直接判定为风险，只能提示“需要确认来源和访问控制”。对真实凭据、TLS 降级、远程脚本执行这类更明确的问题，才提升严重度。
