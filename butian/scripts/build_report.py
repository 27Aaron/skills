#!/usr/bin/env python3
"""Inject analysis JSON into the HTML template -> a standalone security report.

Usage:
    build_report.py <analysis.json> [output.html]
    build_report.py --no-open <analysis.json> [output.html]

The analysis JSON is produced by analyze_scan.py and may be lightly reviewed by
the agent after interpreting scan.py output.
Schema (all sections optional except project):

{
  "generated_at": "2026-06-02 12:00:00",
  "scan_seconds": 3.2,
  "project": {
    "path": "/path/to/project",
    "name": "my-project",
    "ecosystems": ["npm"],
    "lockfiles": ["package-lock.json"],
    "git_repo": true,
    "git_branch": "main",
    "total_packages": 142,
    "total_vulnerabilities": 5
  },
  "risk_summary": { "critical": 0, "high": 2, "medium": 3, "low": 1, "info": 0 },
  "hygiene": {
    "gitignore_exists": true,
    "gitignore_missing": [".env", "*.pem"],
    "tracked_secrets": [{ "file": "src/config.ts", "line": 12, "type": "generic_api_key", "preview": "api_key=***" }],
    "sensitive_tracked": [{ "file": ".env", "type": "env_file", "size": 128 }]
  },
  "outdated": [{ "package": "react", "current": "18.2.0", "latest": "19.1.0", "ecosystem": "npm" }],
  "top_issues": [{ "rank": 1, "tier": "red|yellow|green", "severity": "critical|high|medium|low|info",
                   "package": "name", "version": "1.0.0", "advisory_id": "GHSA-xxx",
                   "summary": "一句普通用户能看懂的风险说明，不要堆 CVE/GHSA 编号" }],
  "green": [{
    "name": "升级 next 到 15.5.2",
    "type": "dependency_upgrade",          // dependency_upgrade | gitignore_fix | git_rm_cached
    "severity": "high",
    "summary": "...",
    "fix_commands": [{ "label": "升级 next", "cmd": "npm install next@>=15.5.2" }],
    "fix_config": {                        // 供 agent 在用户确认后执行；网页不直接执行
      "type": "upgrade",                   // upgrade | gitignore | git_rm_cached
      "ecosystem": "npm", "manager": "npm",
      "package": "next", "version": "15.5.2"
    }
  }],
  "yellow": [{
    "name": "硬编码 API Key",
    "type": "secret_exposure",
    "severity": "high",
    "path": "src/config.ts",               // 用于定位源文件
    "file": "src/config.ts",
    "content_profile": "文件描述",
    "why_manual": "为什么需要人工判断",
    "disposal": "处置路径",
    "risk": "风险提示",
    "fix_commands": [{ "label": "...", "cmd": "..." }]
  }],
  "red": [{
    "name": "密钥已入 git 历史",
    "type": "secret_in_history",
    "severity": "critical",
    "path": ".env.production",
    "why_keep": "为什么需要专业处理",
    "indirect_release": "具体处理步骤",
    "risk": "风险说明"
  }],
  "summary": {                              // 必填；网页也会兜底生成，但 agent 应主动写
    "tldr": "一句话摘要，给产品经理快速判断是否影响发布；不要写 critical/medium/CVE/GHSA 列表",
    "detail": "更完整的报告总结，用普通人能看懂的语言解释风险范围、是否需要马上安排、谁来确认；证据编号留给漏洞表。",
    "tier_stats": { "green": "3 项可由 agent 处理", "yellow": "2 项需人工判断", "red": "1 项高危" },
    "priority": ["1. ...", "2. ..."]
  }
}
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
ASSETS_DIR = os.path.join(HERE, "..", "assets")
TEMPLATE = os.path.join(ASSETS_DIR, "report_template.html")
REPORT_CSS = os.path.join(ASSETS_DIR, "report.css")
REPORT_JS = os.path.join(ASSETS_DIR, "report.js")


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
        description="Build a standalone 补天 HTML report",
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
