# dependency_parsers.py 技术文档

> 源码路径：`butian/scripts/dependency_parsers.py`

## 概览

`dependency_parsers.py` 负责检测项目依赖生态，并从本地 lockfile / manifest 中提取可确认的包坐标。它不请求外部漏洞源，不读取业务源码，也不判断风险；只输出 `ecosystem`、`name`、`version`、`source`、`is_direct` 等结构化包信息。

## 职责

| #   | 职责          | 说明                                                     |
| --- | ------------- | -------------------------------------------------------- |
| 1   | 生态检测      | 根据 `LOCKFILE_MAP` 查找 npm、PyPI、Go、Rust 等支持生态  |
| 2   | lockfile 解析 | 解析各生态本地文件，提取精确包名和版本                   |
| 3   | 去重          | 按 `ecosystem + name + version` 去重，避免重复查询漏洞源 |
| 4   | 来源汇总      | 生成 `package_sources`，让报告说明依赖来自哪些文件       |

## 支持生态

| 生态      | 文件                                                         |
| --------- | ------------------------------------------------------------ |
| npm       | `package-lock.json`                                          |
| pnpm      | `pnpm-lock.yaml`                                             |
| yarn      | `yarn.lock`                                                  |
| PyPI      | `poetry.lock`、`uv.lock`、`Pipfile.lock`、`requirements.txt` |
| Go        | `go.sum`                                                     |
| crates.io | `Cargo.lock`                                                 |
| Packagist | `composer.lock`                                              |
| RubyGems  | `Gemfile.lock`                                               |
| Pub       | `pubspec.lock`                                               |
| Hex       | `mix.lock`                                                   |
| NuGet     | `packages.lock.json`、`packages.config`                      |
| Maven     | `pom.xml`                                                    |

## 精确版本原则

漏洞查询只处理本地可确认的精确版本。`requirements.txt` 只接受 `==` / `===`，Maven 只接受直接写明且不含 `${...}`、版本范围或父 POM/BOM 推断的版本。

## 核心函数

| 函数                                                     | 作用                                     |
| -------------------------------------------------------- | ---------------------------------------- |
| `detect_ecosystems(project_path)`                        | 返回命中的生态和 lockfile                |
| `extract_packages(project_path, ecosystems)`             | 调用对应 parser 并汇总去重               |
| `package_source_summary(packages)`                       | 统计包来源文件                           |
| `package_version_index(packages)`                        | 建立 `(ecosystem, name) -> version` 索引 |
| `current_version_for(version_index, ecosystem, package)` | 查询当前版本                             |

## 兼容关系

`scan.py` 会 re-export 本模块的 parser 和 helper。旧测试和外部脚本仍可通过 `scan.parse_npm_lock()`、`scan.extract_packages()`、`scan.LOCKFILE_MAP` 调用。

## 测试覆盖

- `tests/butian/test_scan.py`
- `tests/butian/test_detect.py`
