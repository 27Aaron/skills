# workspace.py 技术文档

> 源码路径：`butian/scripts/workspace.py`

## 概览

`workspace.py` 维护本地工作区、运行目录、项目根发现和扫描路径安全边界。它不执行漏洞查询，也不读取业务文件内容；只负责让其他脚本稳定找到 `.butian/<run>/assets/` 和安全的项目根。

## 职责

| #   | 职责             | 说明                                                                          |
| --- | ---------------- | ----------------------------------------------------------------------------- |
| 1   | 工作区准备       | 创建 `.butian/`、运行目录和 `assets/`                                         |
| 2   | 本地产物忽略规则 | 确保 `.gitignore` 忽略 `.butian/` 和 `docs/butian/*/security-report*.md/html` |
| 3   | 项目根发现       | 从子目录向上找到最近的项目 manifest/lockfile 或 git 根                        |
| 4   | 安全路径保护     | 阻止把系统目录、用户主目录等高风险路径作为 `project_path`                     |

## 核心函数

| 函数                                                         | 作用                            |
| ------------------------------------------------------------ | ------------------------------- |
| `ensure_butian_run(project_path, run_id=None)`               | 创建并返回 `.butian/<run-id>/`  |
| `default_asset_path(project_path, filename, preflight=None)` | 返回默认 assets 输出路径        |
| `run_dir_from_output_file(output_file)`                      | 从 assets 文件路径反推 run 目录 |
| `find_project_root(start_path=".")`                          | 自动识别最近项目根目录          |
| `ensure_safe_project_path(project_path)`                     | 拒绝系统目录和用户主目录        |
| `butian_gitignore_status(project_path)`                      | 返回本地产物忽略规则状态        |

## 兼容关系

`scan.py` 会 re-export 本模块的公共函数，旧代码仍可通过 `from butian.scripts import scan` 调用 `scan.ensure_butian_run()`、`scan.default_asset_path()` 等 helper。

## 测试覆盖

- `tests/butian/test_scan_helpers.py`
- `tests/butian/test_detect.py`
- `tests/butian/test_scan.py`
