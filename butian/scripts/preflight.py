#!/usr/bin/env python3
"""补天 preflight probe.

Checks before the full scanner:
  1. Detect supported project dependency files.
  2. Prepare the local .butian workspace and .gitignore entry.

The script prints JSON to stdout and writes the same JSON to
.butian/<timestamp>/assets/preflight.json by default. It uses only Python
standard library modules.
"""

import argparse
import json
import os
import sys
import time

from scan import (
    LOCKFILE_MAP,
    butian_gitignore_status,
    default_asset_path,
    find_project_root,
    run_dir_from_output_file,
)


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Run 补天 preflight checks")
    parser.add_argument("project_path", nargs="?", default=".")
    parser.add_argument(
        "--no-root-discovery",
        action="store_true",
        help="use the supplied path exactly instead of walking up to the project root",
    )
    parser.add_argument(
        "--output",
        help="write JSON to this path instead of the default temp-file path",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="emit compact JSON instead of pretty-printed JSON",
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
    language_support = detect_language_support(project_path)
    output_file = args.output or default_output_path(project_path)
    run_dir = run_dir_from_output_file(output_file)
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
            "content_dir": os.path.join(run_dir, "content"),
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
    preflight = build_preflight(project_path, args)
    output = preflight["output_file"]
    os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)

    with open(output, "w", encoding="utf-8") as handle:
        json.dump(preflight, handle, ensure_ascii=False, indent=2)
        handle.write("\n")

    if args.compact:
        print(json.dumps(preflight, ensure_ascii=False, separators=(",", ":")))
    else:
        print(json.dumps(preflight, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
