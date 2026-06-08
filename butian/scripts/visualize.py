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
    from .labels import SECRET_TYPE_LABELS, SENSITIVE_TYPE_LABELS
    from .scan import BUTIAN_CONTENT_DIR, run_dir_from_output_file
except ImportError:
    from labels import (  # pyright: ignore[reportMissingImports]
        SECRET_TYPE_LABELS,
        SENSITIVE_TYPE_LABELS,
    )
    from scan import (  # pyright: ignore[reportMissingImports]
        BUTIAN_CONTENT_DIR,
        run_dir_from_output_file,
    )

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(HERE, "..", "templates")
TEMPLATE = os.path.join(TEMPLATES_DIR, "report.html")
REPORT_CSS = os.path.join(TEMPLATES_DIR, "report.css")
REPORT_JS = os.path.join(TEMPLATES_DIR, "report.js")


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


def _butian_dir_for(output_path):
    """Find the .butian/ directory that contains *output_path*."""
    current = os.path.dirname(os.path.abspath(output_path))
    while current != os.path.dirname(current):
        if os.path.basename(current) == ".butian":
            return current
        current = os.path.dirname(current)
    return None


FIRST_SCAN_MARKER = ".first-scan-done"


def _first_scan_done(output_path):
    """Return True if a previous scan already completed for this project."""
    butian_dir = _butian_dir_for(output_path)
    if butian_dir:
        return os.path.exists(os.path.join(butian_dir, FIRST_SCAN_MARKER))
    return False


def _mark_first_scan_done(output_path):
    butian_dir = _butian_dir_for(output_path)
    if butian_dir:
        try:
            with open(os.path.join(butian_dir, FIRST_SCAN_MARKER), "w") as f:
                f.write("")
        except OSError:
            pass


def should_open_report(args, output_path=None):
    should_open, _reason = open_decision(args, output_path)
    return should_open


def open_decision(args, output_path=None):
    if args.no_open:
        return False, "no_open"
    value = os.environ.get("BUTIAN_NO_OPEN", "")
    if value.strip().lower() in {"1", "true", "yes", "on"}:
        return False, "environment"
    # Only open the browser on the very first scan for this project.
    if output_path and _first_scan_done(output_path):
        return False, "first_scan_done"
    return True, "open"


def skipped_open_message(reason):
    if reason == "no_open":
        return "已按 --no-open 跳过自动打开报告。"
    if reason == "environment":
        return "已根据 BUTIAN_NO_OPEN 跳过自动打开报告。"
    if reason == "first_scan_done":
        return "已跳过自动打开报告（首次扫描已完成）。"
    return "已跳过自动打开报告。"


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
    report_js = read_text(REPORT_JS).rstrip()
    report_js = (
        report_js.replace("__SECRET_TYPE_LABELS__", json_for_script(SECRET_TYPE_LABELS))
        .replace(
            "__SENSITIVE_TYPE_LABELS__", json_for_script(SENSITIVE_TYPE_LABELS)
        )
    )
    report_js = script_asset_for_html(report_js)

    blob = json_for_script(data)
    html = (
        tpl.replace("__REPORT_CSS__", report_css)
        .replace("__REPORT_DATA__", blob)
        .replace("__REPORT_JS__", report_js)
    )
    placeholders = [
        marker
        for marker in (
            "__REPORT_CSS__",
            "__REPORT_DATA__",
            "__REPORT_JS__",
            "__SECRET_TYPE_LABELS__",
            "__SENSITIVE_TYPE_LABELS__",
        )
        if marker in html
    ]
    if placeholders:
        missing = ", ".join(placeholders)
        raise SystemExit(f"HTML report still contains placeholders: {missing}")

    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"报告已生成: {out}")
    print("HTML 报告已保存，之后也可以从 content 目录重新查看。")
    should_open, reason = open_decision(args, out)
    if should_open:
        if open_report(out):
            _mark_first_scan_done(out)
            print("已尝试在默认浏览器中打开报告。")
        else:
            print("未能自动打开报告，请手动打开上面的路径。")
    else:
        print(skipped_open_message(reason))


if __name__ == "__main__":
    main()
