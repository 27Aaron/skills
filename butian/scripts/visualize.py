#!/usr/bin/env python3
"""Inject analysis JSON into the HTML template -> a standalone security report.

Usage:
    visualize.py <analysis.json> [output.html]
    visualize.py --no-open <analysis.json> [output.html]

The analysis JSON is produced by analyze.py and may be lightly reviewed by
the agent after interpreting scan.py output.  For the full schema, see
``references/report-contract.md``.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import webbrowser
from pathlib import Path

try:
    from .scan import BUTIAN_CONTENT_DIR, run_dir_from_output_file
except ImportError:
    from scan import (  # pyright: ignore[reportMissingImports]
        BUTIAN_CONTENT_DIR,
        run_dir_from_output_file,
    )

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(HERE, "..", "templates")
STATIC_DIR = os.path.join(HERE, "..", "static")
TEMPLATE = os.path.join(TEMPLATES_DIR, "report.html")
REPORT_CSS = os.path.join(STATIC_DIR, "report.css")
REPORT_JS = os.path.join(STATIC_DIR, "report.js")


def json_for_script(value):
    """Serialize JSON for embedding inside a <script> block."""
    blob = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return (
        blob.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def read_text(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def script_asset_for_html(value):
    return value.replace("</script", "<\\/script")


def style_asset_for_html(value):
    return value.replace("</style", "<\\/style")


def default_output_path(analysis_path):
    run_dir = run_dir_from_output_file(analysis_path)
    content_dir = os.path.join(run_dir, BUTIAN_CONTENT_DIR)
    os.makedirs(content_dir, exist_ok=True)
    return os.path.join(content_dir, "security-report.html")


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Build a standalone HTML report",
    )
    parser.add_argument("analysis_json")
    parser.add_argument("output_html", nargs="?")
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="do not open the generated HTML report in the default browser",
    )
    return parser.parse_args(argv)


def should_open_report(args):
    if args.no_open:
        return False
    value = os.environ.get("BUTIAN_NO_OPEN", "")
    return value.strip().lower() not in {"1", "true", "yes", "on"}


def spawn_open_command(cmd):
    try:
        subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except (OSError, ValueError):
        return False


def open_report(path):
    resolved = Path(path).resolve()
    target = str(resolved)

    if sys.platform == "darwin":
        if spawn_open_command(["open", target]):
            return True
    elif os.name == "nt":
        startfile = getattr(os, "startfile", None)
        if startfile is not None:
            try:
                startfile(target)
                return True
            except OSError:
                pass
    else:
        for opener in ("xdg-open", "gio", "wslview"):
            opener_path = shutil.which(opener)
            if opener_path is None:
                continue
            cmd = (
                [opener_path, "open", target]
                if opener == "gio"
                else [opener_path, target]
            )
            if spawn_open_command(cmd):
                return True

    try:
        return webbrowser.open_new_tab(resolved.as_uri())
    except Exception:
        return False


def main():
    args = parse_args(sys.argv[1:])
    src = args.analysis_json
    out = args.output_html or default_output_path(src)

    with open(src, "r", encoding="utf-8") as f:
        data = json.load(f)
    tpl = read_text(TEMPLATE)
    report_css = style_asset_for_html(read_text(REPORT_CSS).rstrip())
    report_js = script_asset_for_html(read_text(REPORT_JS).rstrip())

    blob = json_for_script(data)
    html = (
        tpl.replace("__REPORT_CSS__", report_css)
        .replace("__REPORT_DATA__", blob)
        .replace("__REPORT_JS__", report_js)
    )
    placeholders = [
        marker
        for marker in ("__REPORT_CSS__", "__REPORT_DATA__", "__REPORT_JS__")
        if marker in html
    ]
    if placeholders:
        missing = ", ".join(placeholders)
        raise SystemExit(f"HTML report still contains placeholders: {missing}")

    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"报告已生成: {out}")
    print("HTML 已保存到本次运行的 content 目录，之后也可以从这里重新查看。")
    if should_open_report(args):
        if open_report(out):
            print("HTML 已尝试在默认浏览器中自动打开。")
        else:
            print("未能自动打开 HTML，请手动打开上面的报告路径。")
    else:
        print("已跳过自动打开 HTML。")
    print("如果你想继续处理修复，在对话里说一声“可以修 / 修复 / OK / Yes”就行。")


if __name__ == "__main__":
    main()
