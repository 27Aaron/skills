#!/usr/bin/env python3
"""Run all demo projects and copy reports to stable docs paths."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEMO_DIR = Path(__file__).resolve().parent
PROJECTS_DIR = DEMO_DIR / "projects"
AUDIT_SCRIPT = ROOT / "butian" / "scripts" / "run_audit.py"

PROJECT_ORDER = (
    "javascript",
    "python",
    "go",
    "rust",
    "php",
    "ruby",
    "dart",
    "elixir",
    "dotnet",
    "maven",
)


def project_dirs(selected: list[str] | None = None) -> list[Path]:
    names = selected or list(PROJECT_ORDER)
    projects = []
    for name in names:
        path = PROJECTS_DIR / name
        if not path.is_dir():
            raise FileNotFoundError(f"demo project not found: {name}")
        projects.append(path)
    return projects


def latest_file(root: Path, pattern: str) -> Path:
    matches = [path for path in root.glob(pattern) if path.is_file()]
    if not matches:
        raise FileNotFoundError(f"no file matched {root / pattern}")
    return max(matches, key=lambda path: path.stat().st_mtime_ns)


def reset_runtime(project: Path) -> None:
    docs_dir = project / "docs"
    shutil.rmtree(project / ".butian", ignore_errors=True)
    shutil.rmtree(docs_dir / "butian", ignore_errors=True)
    for filename in ("security-report.md", "security-report.html"):
        (docs_dir / filename).unlink(missing_ok=True)


def copy_stable_reports(project: Path) -> tuple[Path, Path]:
    docs_dir = project / "docs"
    docs_dir.mkdir(exist_ok=True)
    markdown = latest_file(docs_dir / "butian", "security-report-*.md")
    html = latest_file(project / ".butian", "*/content/security-report.html")

    stable_markdown = docs_dir / "security-report.md"
    stable_html = docs_dir / "security-report.html"
    shutil.copyfile(markdown, stable_markdown)
    shutil.copyfile(html, stable_html)
    shutil.rmtree(docs_dir / "butian", ignore_errors=True)
    return stable_markdown, stable_html


def run_project(project: Path, keep_runtime: bool = False) -> tuple[Path, Path]:
    if not keep_runtime:
        reset_runtime(project)
    cmd = [
        sys.executable,
        str(AUDIT_SCRIPT),
        "--no-root-discovery",
        "--no-open",
        "--final-report",
        str(project),
    ]
    subprocess.run(cmd, cwd=ROOT, check=True)
    return copy_stable_reports(project)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run demo audits and write stable Markdown/HTML reports."
    )
    parser.add_argument(
        "--project",
        action="append",
        choices=PROJECT_ORDER,
        help="Run one demo project. Can be repeated. Defaults to all projects.",
    )
    parser.add_argument(
        "--keep-runtime",
        action="store_true",
        help="Keep existing .butian runtime data instead of cleaning before each run.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available demo projects and exit.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if args.list:
        for name in PROJECT_ORDER:
            print(name)
        return 0

    for project in project_dirs(args.project):
        markdown, html = run_project(project, keep_runtime=args.keep_runtime)
        print(f"{project.name}:")
        print(f"  Markdown: {os.path.relpath(markdown, ROOT)}")
        print(f"  HTML:     {os.path.relpath(html, ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
