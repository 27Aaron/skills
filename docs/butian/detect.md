# detect.py 技术文档

> 源码路径：`butian/scripts/detect.py`（132 行）

## 概览

`detect.py` 是扫描管线的第一步（预检），负责检测项目的语言/包管理器支持情况，并准备好 `.butian/` 工作区。它输出一份 `preflight.json`，指导后续 `scan.py` 选择正确的扫描模式。

## 职责

| #   | 职责           | 说明                                                                                           |
| --- | -------------- | ---------------------------------------------------------------------------------------------- |
| 1   | 依赖文件检测   | 扫描项目根目录，匹配已知的 lockfile 名称                                                       |
| 2   | 工作区准备     | 创建 `.butian/<run>/` 运行目录结构；默认 run id 为 `YYYYMMDD-HHMM`，同一分钟重复扫描会追加后缀 |
| 3   | 扫描模式推荐   | 根据是否找到依赖文件推荐 `full_dependency_scan` 或 `hygiene_only`                              |
| 4   | Gitignore 准备 | 确保 `.gitignore` 覆盖 Butian 本地工作区和报告目录                                             |

## CLI 用法

```bash
python3 detect.py                        # 当前目录，自动检测项目根
python3 detect.py /path/to/project       # 指定项目路径
python3 detect.py --no-root-discovery .  # 不向上查找，直接用给定路径
python3 detect.py --output custom.json   # 自定义输出路径
python3 detect.py --compact              # 输出紧凑 JSON
```

## CLI 参数

| 参数                  | 类型     | 默认值   | 说明                                   |
| --------------------- | -------- | -------- | -------------------------------------- |
| `project_path`        | 位置参数 | `.`      | 项目路径                               |
| `--no-root-discovery` | flag     | `false`  | 不向上遍历查找项目根，直接使用给定路径 |
| `--output`            | string   | 自动生成 | 指定 JSON 输出路径                     |
| `--compact`           | flag     | `false`  | 输出紧凑 JSON（无缩进）                |

## 核心函数

### `detect_language_support(project_path)`

遍历 `LOCKFILE_MAP`（从 `scan.py` 导入），检查项目中是否存在已知的依赖文件。

返回结构：

```json
{
  "supported": true,
  "ecosystems": ["npm"],
  "matched_files": [{ "ecosystem": "npm", "file": "package-lock.json" }]
}
```

### `build_preflight(project_path, args)`

组装完整的预检报告，包含：

- 项目基本信息（路径、名称）
- 语言支持检测结果
- 推荐的扫描模式
- 工作区路径信息（运行目录、资产目录、内容目录）
- Gitignore 状态（包含缺失项、已新增项和最终存在状态）

扫描模式逻辑：

- 发现支持的 lockfile → `"full_dependency_scan"`
- 未发现 → `"hygiene_only"`（仅仓库安检）

### `default_output_path(project_path)`

默认输出路径：`.butian/<run>/assets/preflight.json`

## 输出 JSON 结构

```json
{
  "generated_at": "2026-06-09 15:50:00",
  "project": {
    "path": "/absolute/path/to/project",
    "name": "my-project"
  },
  "language_support": {
    "supported": true,
    "ecosystems": ["npm"],
    "matched_files": [{ "ecosystem": "npm", "file": "package-lock.json" }]
  },
  "recommended_scan_mode": "full_dependency_scan",
  "butian_workspace": {
    "run_dir": ".butian/20260609-1550",
    "assets_dir": ".butian/20260609-1550/assets",
    "content_dir": ".butian/20260609-1550/content",
    "gitignore": {
      "path": ".gitignore",
      "preexisting": true,
      "had_butian_entry": false,
      "missing_entries": [],
      "added_butian_entry": true,
      "added_entries": [".butian/", "docs/butian/security-report-*.md"],
      "exists_after": true
    }
  },
  "output_file": ".butian/20260609-1550/assets/preflight.json"
}
```

## 依赖关系

从 `scan.py` 导入以下工具函数：

| 导入项                     | 用途                                   |
| -------------------------- | -------------------------------------- |
| `LOCKFILE_MAP`             | 生态 → lockfile 文件名的映射           |
| `butian_gitignore_status`  | 获取 Butian 本地工作区相关忽略规则状态 |
| `default_asset_path`       | 构建默认资产文件路径                   |
| `ensure_butian_run`        | 创建运行目录                           |
| `find_project_root`        | 向上遍历查找项目根                     |
| `run_dir_from_output_file` | 从输出文件路径反推运行目录             |

## 设计要点

- **仅使用标准库**：无任何第三方依赖
- **输出双重写入**：JSON 同时写入文件和 stdout（文件供后续步骤使用，stdout 供调用方检查）
- **项目根发现**：`find_project_root()` 支持从子目录启动时自动向上定位
- **预检即准备工作区**：默认输出路径会创建 `.butian/<run>/assets` 和 `.butian/<run>/content`，并记录本次忽略规则准备结果，供 `scan.py` 复用
