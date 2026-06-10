# fix.py 技术文档

> 源码路径：`butian/scripts/fix.py`

## 概览

`fix.py` 是依赖修复执行器。它读取 `analyze.py` 的分析结果，按策略生成修复计划，并在传入 `--yes` 后执行包管理器升级命令或创建用户确认后的治理配置文件。不参与自动管线（`run_audit.py` 不调用它），而是在确认修复方案后单独调用。

## 职责

| #   | 职责             | 说明                                                                     |
| --- | ---------------- | ------------------------------------------------------------------------ |
| 1   | 升级命令生成     | 根据修复策略（minimal/latest/parent-upgrade/force-residual）生成升级命令 |
| 2   | npm 嵌套依赖分析 | 解析 `package-lock.json`，追踪嵌套依赖的父依赖链                         |
| 3   | 强制覆盖         | 通过 npm `overrides` 机制强制覆盖无法追溯的残留依赖                      |
| 4   | 配置创建         | 根据 analysis 中的 `dependabot_config` 创建 `.github/dependabot.yml`     |
| 5   | dry-run 边界     | 默认只打印修复计划；只有追加 `--yes` 才真正修改项目                      |
| 6   | 命令执行         | 顺序执行升级命令，收集成功/失败结果，并在任一命令失败时返回非零退出码    |

## CLI 用法

```bash
python3 fix.py <analysis.json> --strategy fixed             # 只打印升级到已知修复版本的计划
python3 fix.py <analysis.json> --strategy latest            # 只打印全部依赖升级到最新版本的计划
python3 fix.py <analysis.json> --strategy parent-upgrade    # 只打印升级父依赖清理嵌套残留的计划
python3 fix.py <analysis.json> --strategy force-residual    # 只打印强制覆盖残留依赖的计划
python3 fix.py <analysis.json> --strategy dependabot        # 只打印创建 Dependabot 配置的计划

python3 fix.py <analysis.json> --strategy fixed --yes       # 确认后真正执行
python3 fix.py <analysis.json> --strategy dependabot --yes  # 确认后创建配置文件
python3 fix.py <analysis.json> --strategy latest --dry-run  # 显式只看计划，不修改项目
```

## CLI 参数

| 参数            | 类型     | 必需 | 说明                                                                                          |
| --------------- | -------- | ---- | --------------------------------------------------------------------------------------------- |
| `analysis_json` | 位置参数 | ✅   | `analyze.py` 输出的 JSON 路径                                                                 |
| `--strategy`    | 选项     | ✅   | 修复策略，可选 `fixed`、`minimal`、`latest`、`parent-upgrade`、`force-residual`、`dependabot` |
| `--yes`         | flag     | 否   | 真正执行生成后的修复计划；省略时只做 dry-run                                                  |
| `--dry-run`     | flag     | 否   | 显式只打印修复计划，不修改项目；即使同时传 `--yes` 也不会执行                                 |

## 修复策略

| 策略             | 别名      | 行为                                                             | 适用场景                       |
| ---------------- | --------- | ---------------------------------------------------------------- | ------------------------------ |
| `fixed`          | `minimal` | 仅升级有漏洞的包到已知修复版本                                   | 精准修复，影响范围最小         |
| `latest`         | —         | 升级**全部**依赖到最新版本（不限于漏洞包）                       | 大版本维护窗口，一次性拉新     |
| `parent-upgrade` | —         | 升级嵌套依赖的根父包到 latest，再升级子包到目标版本              | npm 嵌套依赖被旧版父包锁定     |
| `force-residual` | —         | 向 `package.json` 写入 `overrides`，强制所有嵌套实例使用指定版本 | 无法追溯到根依赖的深层嵌套残留 |
| `dependabot`     | —         | 创建 analysis 中生成的 `.github/dependabot.yml`，不覆盖已有文件  | GitHub 仓库缺少依赖维护配置    |

> `fixed` 和 `minimal` 是同义词，`normalize_strategy()` 会统一为 `minimal`。

## 退出码

| 情况                   | 退出码 | 说明                                        |
| ---------------------- | ------ | ------------------------------------------- |
| 没有可执行命令且无失败 | `0`    | 没有可修复项、策略不适用或仅生成空计划      |
| 所有命令执行成功       | `0`    | 包管理器命令均返回成功                      |
| 任一命令失败           | `1`    | 保留成功/失败明细，提示用户复核包管理器输出 |
| Dependabot 文件已存在  | `1`    | 不覆盖用户已有配置，提示人工合并            |

`fix.py` 默认不会修改项目。没有 `--yes` 时，所有策略都只打印执行计划并返回 `0`；`--dry-run` 是显式只看计划的安全开关。AskUserQuestion 的确认发生在调用方决定追加 `--yes` 之前。

`fix.py` 不会吞掉部分失败。真正执行时，即使前面的升级命令成功，只要后续任一命令失败，最终也会退出 `1`，避免自动化调用误判修复完成。

## 核心常量

### 升级命令构建器

```python
_UPGRADE_BUILDERS = {
    "npm":       lambda pkg, ver: ["npm", "install", f"{pkg}@{ver}"],
    "pnpm":      lambda pkg, ver: ["pnpm", "add", f"{pkg}@{ver}"],
    "yarn":      lambda pkg, ver: ["yarn", "add", f"{pkg}@{ver}"],
    "go":        lambda pkg, ver: ["go", "get", f"{pkg}@v{ver}"],
    "crates-io": lambda pkg, ver: ["cargo", "update", "-p", pkg, "--precise", ver],
}
```

## 核心函数

### 升级命令生成

| 函数                                               | 作用                                         |
| -------------------------------------------------- | -------------------------------------------- |
| `extract_fixable_items(analysis)`                  | 从分析结果中提取所有可修复的依赖升级项       |
| `extract_dependabot_config_items(analysis)`        | 从分析结果中提取可创建的 Dependabot 配置     |
| `build_upgrade_commands(fix_items, strategy, ...)` | 按策略生成升级命令列表                       |
| `build_all_latest_commands(project_path)`          | 检测所有生态，生成全部依赖的 latest 升级命令 |
| `_latest_commands(ecosystem, package, ...)`        | 为单个包生成 latest 升级命令                 |

### Python 包管理器检测

| 函数                             | 作用                                                       |
| -------------------------------- | ---------------------------------------------------------- |
| `_pypi_manager(project_path)`    | 根据 lockfile 检测 Python 项目级管理器（uv/poetry/pipenv） |
| `_pypi_fixed_cmd(pkg, ver, ...)` | 为检测到的包管理器生成 fixed 版本安装命令                  |
| `_pypi_latest_cmd(pkg, ...)`     | 为检测到的包管理器生成 latest 升级命令                     |

### npm 嵌套依赖分析

| 函数                                                     | 作用                                            |
| -------------------------------------------------------- | ----------------------------------------------- |
| `build_npm_parent_upgrade_plan(analysis, project_path)`  | 解析 lockfile，为嵌套漏洞依赖生成父依赖升级计划 |
| `build_parent_upgrade_commands(plan)`                    | 从升级计划生成命令序列（升级父→升级子→dedupe）  |
| `build_force_residual_overrides(analysis, project_path)` | 为无法追溯的残留依赖生成 `overrides` 映射       |

### npm lockfile 路径工具

| 函数                                          | 作用                                     |
| --------------------------------------------- | ---------------------------------------- |
| `_npm_package_name_from_lock_path(path)`      | 从 lockfile 路径提取包名                 |
| `_npm_parent_name_from_lock_path(path)`       | 从 lockfile 路径提取直接父包名           |
| `_npm_names_from_lock_path(path)`             | 从 lockfile 路径提取完整包名链           |
| `_npm_lock_path_for_names(names)`             | 从包名链构造 lockfile 路径               |
| `_npm_parent_lock_path(path)`                 | 获取父级的 lockfile 路径                 |
| `_resolve_npm_dependency(packages, key, dep)` | 沿依赖树向上解析依赖的实际 lockfile 位置 |
| `_direct_root_for_npm_lock_path(...)`         | 追溯嵌套路径到 package.json 中的根依赖   |

### 执行与输出

| 函数                                                | 作用                                              |
| --------------------------------------------------- | ------------------------------------------------- |
| `execute_fixes(commands, project_path)`             | 顺序执行升级命令，返回成功/失败列表               |
| `execute_parent_upgrade_fixes(analysis, path)`      | 执行 parent-upgrade 策略的完整流程                |
| `execute_force_residual_fixes(analysis, path)`      | 执行 force-residual 策略的完整流程                |
| `execute_dependabot_config_fixes(analysis, path)`   | 创建 `.github/dependabot.yml`，并拒绝覆盖已有文件 |
| `should_execute(args)`                              | 只有传入 `--yes` 且未传 `--dry-run` 时才允许执行  |
| `print_execution_plan(strategy, project_path, ...)` | 打印 dry-run 修复计划                             |
| `post_fix_guidance(strategy)`                       | 返回修复后的验证指引文本                          |

### 工具函数

| 函数                            | 作用                                           |
| ------------------------------- | ---------------------------------------------- |
| `_parse_version(version_str)`   | 解析 `"1.2.3"` 为 `(1, 2, 3)`，去除预发布标签  |
| `_semver_satisfies(ver, range)` | 简化的 npm semver 范围匹配（支持 ^、~、>= 等） |
| `_go_version(ver)`              | 确保 Go 版本号带 `v` 前缀                      |
| `normalize_strategy(strategy)`  | 将 `fixed` 归一化为 `minimal`                  |
| `strategy_label(strategy)`      | 将策略名映射为中文标签                         |

## Semver 范围匹配

`_semver_satisfies` 支持以下 npm 风格范围：

| 范围格式       | 含义                   |
| -------------- | ---------------------- |
| `^1.2.3`       | 兼容版本（同大版本）   |
| `~1.2.3`       | 补丁版本（同大小版本） |
| `>=1.2.3`      | 大于等于               |
| `>1.2.3`       | 大于                   |
| `<=1.2.3`      | 小于等于               |
| `<1.2.3`       | 小于                   |
| `1.2.3`        | 精确匹配               |
| `A \|\| B`     | 联合（任一匹配即可）   |
| `*` / `latest` | 任意版本               |

## parent-upgrade 执行流程

```
build_npm_parent_upgrade_plan()
    ├─ 解析 package-lock.json
    ├─ 遍历 lockfile 中每个嵌套包
    ├─ 匹配漏洞包 → 追溯直接父包
    ├─ 追溯到 package.json 根依赖
    └─ 输出: upgrades[] + unfixable[] + skipped[]

build_parent_upgrade_commands()
    ├─ 对每个根父包: npm install <parent>@latest
    ├─ 对每个子包: npm install <child>@<target>
    └─ npm dedupe（提升满足条件的嵌套副本）

execute_parent_upgrade_fixes()
    ├─ 执行上述命令
    ├─ _cleanup_stale_nested(): 清理 lockfile 残留条目 + 物理目录
    └─ 重新 npm install 重新解析
```

## force-residual 执行流程

```
build_force_residual_overrides()
    ├─ 获取 parent-upgrade 计划中的 unfixable 项
    ├─ 区分根依赖 vs 纯传递依赖
    │   ├─ 根依赖: overrides[pkg] = "$pkg"（引用自身）
    │   └─ 传递依赖: overrides[pkg] = "<target_version>"
    └─ 输出: overrides{} + items[] + skipped[]

execute_force_residual_fixes()
    ├─ 读取 package.json，合并已有 overrides
    ├─ 写回 package.json
    └─ npm install 应用 overrides
```

## Python 包管理器适配

`fix.py` 只在检测到项目级 Python 管理器时生成 PyPI 修复命令，不回退到系统 pip。

| 管理器                            | 检测方式            | fixed 命令                | latest 命令             |
| --------------------------------- | ------------------- | ------------------------- | ----------------------- |
| uv                                | `uv.lock` 存在      | `uv add pkg==ver`         | `uv add pkg`            |
| poetry                            | `poetry.lock` 存在  | `poetry add pkg@ver`      | `poetry add pkg@latest` |
| pipenv                            | `Pipfile.lock` 存在 | `pipenv install pkg==ver` | `pipenv install pkg`    |
| requirements.txt / 无项目级管理器 | —                   | 不自动生成命令            | 不自动生成命令          |

## 设计要点

- **独立于管线**：不被 `run_audit.py` 自动调用，由 SKILL.md 引导用户按需使用
- **默认 dry-run**：不带 `--yes` 时只展示修复计划，不执行包管理器命令或写文件
- **策略分层**：从最小影响（minimal）到最强力（force-residual），逐步升级修复力度
- **npm 深度分析**：专门处理 npm 嵌套依赖问题，支持追溯父依赖链和 overrides 强制覆盖
- **Python 项目管理器**：只检测 uv/poetry/pipenv，避免在不明确的环境中调用系统 pip
- **安全性**：force-residual 对根依赖使用 `"$pkg"` 引用而非硬编码版本，避免版本冲突
- **修复后指引**：`post_fix_guidance()` 为每种策略生成相应的验证建议
