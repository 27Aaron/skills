#!/usr/bin/env python3
"""Run the complete Butian local audit pipeline.

Usage:
    python3 scripts/run_audit.py [project_path]
    python3 scripts/run_audit.py --no-root-discovery [project_path]
    python3 scripts/run_audit.py --skip-outdated [project_path]

Pipeline:
  detect -> scan -> analyze -> report -> visualize
"""

import argparse
import json
import logging
import os
import re
import subprocess
import sys
from collections import defaultdict

logger = logging.getLogger(__name__)

HERE = os.path.dirname(os.path.abspath(__file__))

try:
    from .scan import CAPABILITY_BOUNDARY, HYGIENE_ONLY_NOTICE, setup_logging
except ImportError:
    from scan import (  # pyright: ignore[reportMissingImports]
        CAPABILITY_BOUNDARY,
        HYGIENE_ONLY_NOTICE,
        setup_logging,
    )

def script_path(name):
    return os.path.join(HERE, name)


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Run Butian local audit pipeline")
    parser.add_argument("project_path", nargs="?", default=".")
    parser.add_argument(
        "--no-root-discovery",
        action="store_true",
        help="scan the provided path directly instead of walking up to a repo root",
    )
    parser.add_argument(
        "--skip-outdated",
        action="store_true",
        help="skip package-manager outdated checks for faster vulnerability-only scans",
    )
    parser.add_argument(
        "--skip-hygiene",
        action="store_true",
        help="skip gitignore, tracked sensitive file, and hardcoded secret checks",
    )
    parser.add_argument(
        "--max-secret-files",
        type=int,
        default=None,
        help="maximum number of candidate files to scan for hardcoded secrets",
    )
    parser.add_argument(
        "--include-packages",
        action="store_true",
        help="include the full package list in scan output JSON",
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="do not open the generated HTML report in the default browser",
    )
    parser.add_argument(
        "--final-report",
        action="store_true",
        help="force generate Markdown report (use on the last re-scan after all fixes)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="输出详细日志到 stderr",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="输出调试级别日志",
    )
    parser.add_argument(
        "--follow-symlinks",
        action="store_true",
        help="跟随符号链接扫描",
    )
    return parser.parse_args(argv)


def run_json(cmd):
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        if result.stdout:
            print(result.stdout, file=sys.stderr, end="")
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="")
        raise SystemExit(result.returncode)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        print(result.stdout, file=sys.stderr, end="")
        print(f"Failed to parse JSON from {' '.join(cmd)}: {exc}", file=sys.stderr)
        raise SystemExit(1)


def run_text(cmd, echo=True):
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )
    if echo and result.stdout:
        print(result.stdout, end="")
    if echo and result.stderr:
        print(result.stderr, file=sys.stderr, end="")
    if result.returncode != 0:
        raise SystemExit(result.returncode)
    return result.stdout


def display_width(value):
    width = 0
    for char in str(value):
        code = ord(char)
        if (
            0x1100 <= code <= 0x11FF
            or 0x2E80 <= code <= 0xA4CF
            or 0xAC00 <= code <= 0xD7A3
            or 0xF900 <= code <= 0xFAFF
            or 0xFE10 <= code <= 0xFE6F
            or 0xFF00 <= code <= 0xFFEF
            or 0x1F300 <= code <= 0x1FAFF
        ):
            width += 2
        else:
            width += 1
    return width


def fit_cell(value, width, align="left"):
    text = str(value)
    gap = max(0, width - display_width(text))
    if align == "center":
        left = gap // 2
        return " " * left + text + " " * (gap - left)
    if align == "right":
        return " " * gap + text
    return text + " " * gap


def table(headers, rows, min_widths=None, aligns=None):
    min_widths = min_widths or []
    aligns = aligns or []
    widths = []
    for index, header in enumerate(headers):
        values = [header] + [row[index] for row in rows]
        widths.append(
            max(
                min_widths[index] if index < len(min_widths) else 0,
                *(display_width(value) for value in values),
            )
        )
    top = "┌" + "┬".join("─" * width for width in widths) + "┐"
    sep = "├" + "┼".join("─" * width for width in widths) + "┤"
    bottom = "└" + "┴".join("─" * width for width in widths) + "┘"
    lines = [top]
    lines.append(
        "│"
        + "│".join(
            fit_cell(header, widths[i], "center") for i, header in enumerate(headers)
        )
        + "│"
    )
    for row in rows:
        lines.append(sep)
        lines.append(
            "│"
            + "│".join(
                fit_cell(value, widths[i], aligns[i] if i < len(aligns) else "left")
                for i, value in enumerate(row)
            )
            + "│"
        )
    lines.append(bottom)
    return "\n".join(lines)


def relative_path(path: str, project_path: str) -> str:
    if not path:
        return "-"
    try:
        rel = os.path.relpath(os.path.abspath(path), os.path.abspath(project_path))
    except ValueError:
        return path
    return rel if not rel.startswith("..") else path


def version_key(value):
    parts = re.findall(r"\d+", str(value or ""))
    return tuple(int(part) for part in parts)


def best_fixed_version(issues):
    versions = []
    for issue in issues:
        for version in issue.get("fixed_versions") or issue.get("fix_versions") or []:
            text = str(version)
            if text and text not in versions:
                versions.append(text)
    if not versions:
        return "待确认"
    versions.sort(key=version_key)
    if len(versions) == 1:
        return versions[0]
    return f"{versions[-1]}（含 {versions[0]} 等多个修复）"


def risk_nature(issues):
    tags = []
    patterns = [
        ("中间件/代理绕过", ("middleware", "proxy bypass", "bypass")),
        ("SSRF", ("server-side request forgery", "ssrf")),
        ("XSS", ("xss", "cross-site scripting")),
        (
            "DoS",
            (
                "denial of service",
                "dos",
                "connection exhaustion",
                "large numeric range",
            ),
        ),
        ("URL 主机混淆", ("host confusion",)),
        ("路径穿越", ("path traversal",)),
        ("缓存风险", ("cache",)),
        ("buffer 边界缺失", ("buffer", "bounds")),
    ]
    text = " ".join(
        str(issue.get(key) or "")
        for issue in issues
        for key in ("advisory_summary", "summary", "description", "title", "type")
    ).lower()
    for label, needles in patterns:
        if any(needle in text for needle in needles):
            tags.append(label)
    if not tags:
        tags.append("依赖漏洞")
    suffix = f" 共 {len(issues)} 条" if len(issues) > 1 else ""
    return "、".join(tags) + suffix


def mode_label(scan_mode):
    labels = {
        "full_dependency_scan": "完整依赖漏洞扫描",
        "hygiene_only": "仓库卫生扫描",
    }
    return labels.get(scan_mode, "安全扫描")


def quote_line(text):
    return f"> {text}"


def format_risk_rows(risk_summary):
    labels = [
        ("critical", "🔴 紧急 (Critical)"),
        ("high", "🟠 高风险 (High)"),
        ("medium", "🟡 中风险 (Medium)"),
        ("low", "🔵 低风险 (Low)"),
    ]
    rows = [
        [label, str(int(risk_summary.get(key) or 0))]
        for key, label in labels
        if risk_summary.get(key)
    ]
    return rows or [["✅ 未发现风险", "0"]]


def format_focus(analysis, scan_mode=None):
    if scan_mode == "hygiene_only":
        return HYGIENE_ONLY_NOTICE

    issues = analysis.get("top_issues") or []
    if not issues:
        return "未发现需要优先处理的依赖漏洞。"

    priority = [
        issue
        for issue in issues
        if str(issue.get("severity") or "").lower() in {"critical", "high"}
    ]
    focus_source = priority or issues
    groups = defaultdict(list)
    for issue in focus_source:
        package = issue.get("package") or issue.get("name") or "未知依赖"
        version = issue.get("version") or "-"
        groups[(package, version)].append(issue)

    ranked = sorted(
        groups.items(),
        key=lambda item: (
            -len(item[1]),
            item[0][0],
            item[0][1],
        ),
    )[:6]
    selected_count = sum(len(items) for _, items in ranked)
    total_priority = len(priority) if priority else len(issues)
    noun = "紧急/高风险项" if priority else "已确认风险项"
    lines = [
        f"核心风险集中在 {len(ranked)} 个包（{total_priority} 个{noun}中它们占 {selected_count} 个）：",
        "",
        table(
            ["包", "当前", "建议升到", "风险性质"],
            [
                [package, version, best_fixed_version(items), risk_nature(items)]
                for (package, version), items in ranked
            ],
            min_widths=[15, 8, 30, 36],
        ),
    ]

    medium = [
        issue
        for issue in issues
        if str(issue.get("severity") or "").lower() == "medium"
    ]
    if medium:
        medium_packages = []
        for issue in medium:
            package = issue.get("package") or issue.get("name") or "未知依赖"
            if package not in medium_packages:
                medium_packages.append(package)
        lines.extend(
            [
                "",
                f"中风险 {len(medium)} 个集中在 {', '.join(medium_packages[:6])}。",
            ]
        )
    return "\n".join(lines)


def format_human_summary(summary, scan, analysis, args):
    project = analysis.get("project") or scan.get("project") or {}
    project_path = project.get("path") or os.getcwd()
    risk_summary = analysis.get("risk_summary") or {}
    hygiene = analysis.get("hygiene") or scan.get("hygiene") or {}
    scan_mode = (
        summary.get("scan_mode")
        or (scan.get("scan_config") or {}).get("scan_mode")
        or "-"
    )
    total_packages = project.get("total_packages") or analysis.get("package_count") or 0
    ecosystems = project.get("ecosystems") or []
    dependency_unit = f" {' / '.join(ecosystems)} 包" if ecosystems else "依赖包"
    secret_count = len(hygiene.get("tracked_secrets") or [])
    sensitive_count = len(hygiene.get("sensitive_tracked") or [])
    missing_count = len(hygiene.get("gitignore_missing") or [])
    gitignore_label = (
        ".gitignore 完整"
        if not missing_count
        else f".gitignore 缺少 {missing_count} 条规则"
    )
    errors = analysis.get("errors") or summary.get("errors") or []
    error_label = "无" if not errors else f"{len(errors)} 个"
    html_state = "未自动打开" if args.no_open else "已自动尝试打开"
    scope_notice = (
        ["", "⚠️ 扫描范围", "", quote_line(HYGIENE_ONLY_NOTICE)]
        if scan_mode == "hygiene_only"
        else []
    )

    lines = [
        f"⏺ 扫描完成 ✅ 模式：{scan_mode}（{mode_label(scan_mode)}）。",
        *scope_notice,
        "",
        "📊 风险总览",
        "",
        table(
            ["影响程度", "数量"],
            format_risk_rows(risk_summary),
            min_widths=[20, 6],
            aligns=["center", "left"],
        ),
        "",
        f"- 总依赖：{total_packages} 个{dependency_unit}",
        f"- 已确认风险项：{analysis.get('vulnerability_count', len(analysis.get('top_issues') or []))} 个",
        f"- 仓库卫生：{secret_count} 个硬编码凭证 / {sensitive_count} 个跟踪的敏感文件 / {gitignore_label}",
        f"- 过期依赖：{analysis.get('outdated_count', len(analysis.get('outdated') or []))} 个（仅作维护信号，不算漏洞）",
        f"- 扫描错误：{error_label}",
        "",
        "⚠️ 能力边界",
        "",
        quote_line(CAPABILITY_BOUNDARY),
        "",
        "🚨 重点关注（按修复优先级）",
        "",
        format_focus(analysis, scan_mode=scan_mode),
        "",
        "📁 报告路径",
        "",
        f"- {'最终' if args.final_report else ''}Markdown 审计报告：{relative_path(summary.get('markdown_report'), project_path) if summary.get('markdown_report') else '复扫未生成（首次扫描已有）'}",
        f"- HTML 报告（{html_state}）：{relative_path(summary.get('html_report'), project_path)}",
        f"- analysis JSON：{relative_path(summary.get('analysis_file'), project_path)}",
        "",
        quote_line(
            "如果存在紧急/高风险项，建议先处理有明确修复版本的依赖；过期依赖作为维护信号，放在风险项修复验证之后排期。"
        ),
    ]
    return "\n".join(lines)


def build_scan_cmd(args, preflight_file):
    cmd = [
        sys.executable,
        script_path("scan.py"),
        "--preflight",
        preflight_file,
    ]
    if args.skip_outdated:
        cmd.append("--skip-outdated")
    if args.skip_hygiene:
        cmd.append("--skip-hygiene")
    if args.include_packages:
        cmd.append("--include-packages")
    if args.max_secret_files is not None:
        cmd.extend(["--max-secret-files", str(args.max_secret_files)])
    if args.verbose:
        cmd.append("--verbose")
    if args.debug:
        cmd.append("--debug")
    if args.follow_symlinks:
        cmd.append("--follow-symlinks")
    return cmd


def main():
    args = parse_args(sys.argv[1:])
    # Early logging to stderr; file logging set up after scan produces output_file
    setup_logging()
    logger.info("补天审计流水线开始: 路径=%s", args.project_path)

    # Step 1: preflight
    preflight_cmd = [
        sys.executable,
        script_path("detect.py"),
        "--compact",
    ]
    if args.no_root_discovery:
        preflight_cmd.append("--no-root-discovery")
    preflight_cmd.append(args.project_path)
    preflight = run_json(preflight_cmd)
    logger.info(
        "预检完成: 模式=%s, 输出=%s",
        preflight.get("recommended_scan_mode", "-"),
        preflight["output_file"],
    )

    # Step 2: scan
    scan = run_json(build_scan_cmd(args, preflight["output_file"]))
    scan_mode = scan.get("scan_config", {}).get("scan_mode", "unknown")

    # Set up file logging now that we know the workspace layout
    scan_log_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(scan["output_file"]))),
        "logs",
    )
    butian_logger = logging.getLogger("butian")
    if not any(isinstance(h, logging.FileHandler) for h in butian_logger.handlers):
        os.makedirs(scan_log_dir, exist_ok=True)
        fh = logging.FileHandler(
            os.path.join(scan_log_dir, "run_audit.log"), encoding="utf-8",
        )
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            "%Y-%m-%d %H:%M:%S",
        ))
        fh.setLevel(logging.DEBUG)
        butian_logger.addHandler(fh)
    vuln_count = len(scan.get("vulnerabilities") or [])
    logger.info(
        "扫描完成: 模式=%s, 依赖=%d, 风险项=%d, 过期=%d, 错误=%d",
        scan_mode,
        scan.get("package_count", 0),
        vuln_count,
        len(scan.get("outdated") or []),
        len(scan.get("errors") or []),
    )

    # Step 3: analyze
    analysis_path = os.path.join(
        os.path.dirname(os.path.abspath(scan["output_file"])),
        "analysis.json",
    )
    run_text(
        [
            sys.executable,
            script_path("analyze.py"),
            scan["output_file"],
            analysis_path,
        ],
        echo=False,
    )

    with open(analysis_path, "r", encoding="utf-8") as handle:
        analysis = json.load(handle)

    risk_summary = analysis.get("risk_summary") or {}
    logger.info(
        "分析完成: c=%d h=%d m=%d l=%d info=%d",
        risk_summary.get("critical", 0), risk_summary.get("high", 0),
        risk_summary.get("medium", 0), risk_summary.get("low", 0),
        risk_summary.get("info", 0),
    )

    # Step 4: Markdown report
    butian_dir = os.path.join(analysis["project"]["path"], ".butian")
    first_scan_marker = os.path.join(butian_dir, ".first-scan-done")
    skip_markdown = os.path.exists(first_scan_marker) and not args.final_report

    if skip_markdown:
        markdown_path = None
        logger.info("跳过 Markdown 报告（非首次扫描）")
    else:
        markdown_path = os.path.join(
            analysis["project"]["path"],
            "docs",
            "butian",
            f"security-report-{str(analysis.get('generated_at', 'unknown-date'))[:19].replace(' ', '_').replace(':', '')}.md",
        )
        run_text(
            [
                sys.executable,
                script_path("report.py"),
                analysis_path,
                markdown_path,
            ],
            echo=False,
        )
        logger.info("Markdown 报告已生成: %s", markdown_path)

    # Step 5: HTML report
    html_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(analysis_path))),
        "content",
        "security-report.html",
    )
    build_report_cmd = [
        sys.executable,
        script_path("visualize.py"),
        analysis_path,
        html_path,
    ]
    if args.no_open:
        build_report_cmd.append("--no-open")
    run_text(
        build_report_cmd,
        echo=True,
    )
    logger.info("HTML 报告已生成: %s", html_path)

    summary = {
        "preflight_file": preflight["output_file"],
        "scan_file": scan["output_file"],
        "analysis_file": analysis_path,
        "markdown_report": markdown_path,
        "html_report": html_path,
        "scan_mode": scan_mode,
        "risk_summary": analysis.get("risk_summary", {}),
        "errors": analysis.get("errors", []),
    }

    print(format_human_summary(summary, scan, analysis, args))
    logger.info("补天审计流水线完成")
    return 0


if __name__ == "__main__":
    sys.exit(main())
