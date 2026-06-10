#!/usr/bin/env python3
"""项目扫描预检。

完整扫描前先检查：
  1. 识别支持的项目依赖文件。
  2. 准备本地 .butian 工作区，并检查 .gitignore 覆盖情况。

脚本会把 JSON 输出到 stdout，默认也写入
.butian/<timestamp>/assets/preflight.json。这里只使用 Python 标准库。
"""

import argparse
import json
import os
import sys
import time

try:
    from .scan import (
        LOCKFILE_MAP,
        butian_gitignore_status,
        default_asset_path,
        ensure_butian_run,
        ensure_safe_project_path,
        find_project_root,
        run_dir_from_output_file,
    )
except ImportError:
    from scan import (  # pyright: ignore[reportMissingImports]
        LOCKFILE_MAP,
        butian_gitignore_status,
        default_asset_path,
        ensure_butian_run,
        ensure_safe_project_path,
        find_project_root,
        run_dir_from_output_file,
    )


def parse_args(argv):
    parser = argparse.ArgumentParser(description="运行项目扫描预检")
    parser.add_argument("project_path", nargs="?", default=".")
    parser.add_argument(
        "--no-root-discovery",
        action="store_true",
        help="直接使用传入路径，不向上查找项目根目录",
    )
    parser.add_argument(
        "--output",
        help="把 JSON 写入指定路径，而不是默认资产路径",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="输出紧凑 JSON，而不是格式化 JSON",
    )
    return parser.parse_args(argv)


def default_output_path(project_path):
    return default_asset_path(project_path, "preflight.json")


def detect_language_support(project_path):
    ecosystems = []
    matched_files = []
    for ecosystem, names in LOCKFILE_MAP.items():
        for file_name in names:
            if os.path.isfile(os.path.join(project_path, file_name)):
                ecosystems.append(ecosystem)
                matched_files.append({"ecosystem": ecosystem, "file": file_name})
                break

    return {
        "supported": bool(matched_files),
        "ecosystems": ecosystems,
        "matched_files": matched_files,
    }


def build_preflight(project_path, args):
    ensure_safe_project_path(project_path)
    language_support = detect_language_support(project_path)
    output_file = args.output or default_output_path(project_path)
    run_dir = (
        ensure_butian_run(project_path)
        if args.output
        else run_dir_from_output_file(output_file)
    )
    recommended_scan_mode = (
        "full_dependency_scan" if language_support["supported"] else "hygiene_only"
    )

    return {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "project": {
            "path": project_path,
            "name": os.path.basename(project_path),
        },
        "language_support": language_support,
        "recommended_scan_mode": recommended_scan_mode,
        "butian_workspace": {
            "run_dir": run_dir,
            "assets_dir": os.path.join(run_dir, "assets"),
            "gitignore": butian_gitignore_status(project_path),
        },
        "output_file": output_file,
    }


def main():
    args = parse_args(sys.argv[1:])
    project_path = (
        os.path.abspath(args.project_path)
        if args.no_root_discovery
        else find_project_root(args.project_path)
    )
    try:
        preflight = build_preflight(project_path, args)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2
    output = preflight["output_file"]
    os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)

    with open(output, "w", encoding="utf-8") as handle:
        json.dump(preflight, handle, ensure_ascii=False, indent=2)
        handle.write("\n")

    if args.compact:
        print(json.dumps(preflight, ensure_ascii=False, separators=(",", ":")))
    else:
        print(json.dumps(preflight, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
