# finding_utils.py 技术文档

> 源码路径：`butian/scripts/finding_utils.py`

## 概览

`finding_utils.py` 是 Butian 本地规则的公共工具层。`repo_checks.py`、`iac_checks.py`、`workflow_checks.py` 等脚本都通过它生成统一的 finding 结构，避免每个规则模块各自处理路径、证据、严重度和去重。

## 职责

| #   | 职责         | 说明                                                 |
| --- | ------------ | ---------------------------------------------------- |
| 1   | 路径标准化   | 把绝对路径转成项目内相对路径，跨盘符失败时回退原路径 |
| 2   | 文件读取     | 以 UTF-8 容错读取文本，跳过缺失文件和超大文件        |
| 3   | 文件遍历     | 按后缀或文件名遍历项目文件，并排除沉重目录           |
| 4   | 行号定位     | 根据证据文本返回首次命中的行号                       |
| 5   | 证据处理     | 压缩空白并限制 evidence 长度                         |
| 6   | finding 构造 | 统一字段、兜底 severity/confidence、过滤空扩展字段   |
| 7   | 去重         | 按 `id/file/line/evidence` 保序去重                  |

## 核心常量

`DEFAULT_EXCLUDE_DIRS` 覆盖 `.git`、`.butian`、`node_modules`、`dist`、`build`、`coverage`、虚拟环境、IDE 配置和多语言缓存目录。它用于本地规则遍历，避免扫描缓存、依赖包和构建产物。

`VALID_SEVERITIES` 固定为：

```python
{"critical", "high", "medium", "low", "info"}
```

`VALID_CONFIDENCES` 固定为：

```python
{"high", "medium", "low"}
```

## 函数说明

### `relpath(path, project_path)`

返回 `path` 相对 `project_path` 的路径。正常情况下输出项目内相对路径；如果 `os.path.relpath()` 抛出 `ValueError`，例如 Windows 不同盘符，函数返回原始路径。

### `read_text(path, max_bytes=1024 * 1024)`

读取文本文件并返回字符串。

- 文件不存在、权限不足或读取失败时返回空字符串。
- 文件大小超过 `max_bytes` 时返回空字符串。
- UTF-8 解码使用 `errors="ignore"`，避免单个坏字节中断扫描。

### `iter_files(project_path, suffixes=None, names=None, max_files=2000, exclude_dirs=None)`

遍历项目文件。

- `suffixes` 按小写后缀匹配，例如 `.yml`。
- `names` 按小写完整文件名匹配，例如 `dockerfile`。
- 同时提供 `suffixes` 和 `names` 时，满足任一条件即可返回。
- `exclude_dirs=None` 使用默认排除目录。
- `exclude_dirs=[]` 表示调用方显式关闭默认排除，测试会覆盖这个语义。
- `max_files` 达到上限后停止生成。

### `line_for_text(path, needle)`

返回 `needle` 首次出现的 1-based 行号。`needle` 为空、文件不存在或没有匹配时返回 `None`。

### `evidence_snippet(value, max_len=180)`

把任意值转换成单行 evidence：

- `None` 变为空字符串。
- 连续空白压缩成单个空格。
- 长度不超过 `max_len`。
- 截断时用 `...` 结尾；`max_len <= 3` 时返回对应长度的点号，保证不会超过上限。

### `make_finding(...)`

构造统一 finding 字典。基础字段如下：

```json
{
  "id": "repo.install_script_remote",
  "category": "supply_chain",
  "severity": "medium",
  "confidence": "high",
  "file": "package.json",
  "line": 12,
  "title": "install 脚本执行远程内容",
  "detail": "安装阶段下载并执行远程脚本，供应链被替换时会直接影响本地或 CI 环境。",
  "evidence": "postinstall: curl https://example.com/install.sh | bash",
  "recommendation": "固定可信来源并校验 checksum/signature。",
  "source": "builtin",
  "fixable": false
}
```

未知 severity 会降级为 `info`，未知 confidence 会降级为 `low`。额外字段会被保留，但值为 `None` 的字段会被过滤。

### `dedupe_findings(findings)`

按 `(id, file, line, evidence)` 去重，并保留首次出现的 finding。输入为 `None` 或空列表时返回空列表。

## 测试覆盖

主要测试文件：

- `tests/butian/test_finding_utils.py`
- `tests/butian/test_repo_checks.py`

覆盖点包括：

- 相对路径正常路径和异常回退。
- UTF-8、无效 UTF-8、缺失文件和超大文件。
- suffix、name、组合匹配、默认排除、自定义排除、最大文件数。
- 行号命中、空 needle、缺失文件。
- evidence 空白压缩、长度上限和短上限。
- severity/confidence 兜底、默认字段、扩展字段过滤。
- 去重保序。

## 维护注意

本文件是本地规则的共享底座。修改字段名、默认值、证据截断或排除目录时，必须同步检查 `repo_checks.py`、`iac_checks.py`、`workflow_checks.py`、`analyze.py`、`report.py` 和 `visualize.py` 是否依赖旧语义。
