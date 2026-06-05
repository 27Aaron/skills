#!/usr/bin/env python3
"""Run the complete 补天 local audit pipeline.

Usage:
    python3 scripts/run_audit.py [project_path]
    python3 scripts/run_audit.py --no-root-discovery [project_path]
    python3 scripts/run_audit.py --skip-outdated [project_path]

Pipeline:
  preflight -> scan -> analyze_scan -> render_markdown -> build_report
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
CAPABILITY_BOUNDARY = (
    "安全往往不是最显眼的需求，却是产品长期稳定运行的底线。"
    "补天 会优先帮助你发现依赖漏洞、过期依赖和仓库卫生风险，"
    "让容易被忽视的供应链问题更早暴露出来。"
    "但它不能替代代码审计、渗透测试或部署安全评估；"
    "代码层面的权限、业务逻辑、SQL 注入、XSS 等问题仍需单独复核。"
)


def script_path(name):
    return os.path.join(HERE, name)


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Run 补天 local audit pipeline")
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
        "--api-concurrency",
        type=int,
        default=None,
        help="number of concurrent official vulnerability source batch requests",
    )
    parser.add_argument(
        "--outdated-concurrency",
        type=int,
        default=None,
        help="number of concurrent outdated dependency checks",
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
        "--compact",
        action="store_true",
        help="print compact final JSON summary",
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="do not open the generated HTML report in the default browser",
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


def relative_path(path, project_path):
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
        ("critical", "🔴 严重 (Critical)"),
        ("high", "🟠 高危 (High)"),
        ("medium", "🟡 中危 (Medium)"),
        ("low", "🔵 低危 (Low)"),
        ("info", "⚪ 信息 (Info)"),
    ]
    rows = [
        [label, str(int(risk_summary.get(key) or 0))]
        for key, label in labels
        if risk_summary.get(key)
    ]
    return rows or [["✅ 未发现风险", "0"]]


def format_focus(analysis):
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
    noun = "严重/高危项" if priority else "已确认漏洞"
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
                f"中危 {len(medium)} 个集中在 {', '.join(medium_packages[:6])}。",
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

    lines = [
        f"⏺ 扫描完成 ✅ 模式：{scan_mode}（{mode_label(scan_mode)}）。",
        "",
        "📊 风险总览",
        "",
        table(
            ["严重度", "数量"],
            format_risk_rows(risk_summary),
            min_widths=[20, 6],
            aligns=["center", "left"],
        ),
        "",
        f"- 总依赖：{total_packages} 个{dependency_unit}",
        f"- 已确认漏洞：{analysis.get('vulnerability_count', len(analysis.get('top_issues') or []))} 个",
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
        format_focus(analysis),
        "",
        "📁 报告路径",
        "",
        f"- Markdown 审计报告：{relative_path(summary.get('markdown_report'), project_path)}",
        f"- HTML 报告（{html_state}）：{relative_path(summary.get('html_report'), project_path)}",
        f"- analysis JSON：{relative_path(summary.get('analysis_file'), project_path)}",
        "",
        quote_line(
            "如果存在严重/高危项，建议先处理有明确修复版本的依赖；过期依赖作为维护信号，放在漏洞修复验证之后排期。"
        ),
        "",
        "---",
        '如果你想继续修复，在对话里回 修复 / OK / 可以修 即可。我会按"主要修复（严重/高危有明确修复版本）→ 次要修复（过期依赖与中危）"的顺序处理，每步执行后跑构建验证。',
    ]
    return "\n".join(lines)


def build_scan_cmd(args, preflight_file):
    cmd = [
        sys.executable,
        script_path("scan.py"),
        "--preflight",
        preflight_file,
        "--compact",
    ]
    if args.skip_outdated:
        cmd.append("--skip-outdated")
    if args.skip_hygiene:
        cmd.append("--skip-hygiene")
    if args.include_packages:
        cmd.append("--include-packages")
    if args.api_concurrency is not None:
        cmd.extend(["--api-concurrency", str(args.api_concurrency)])
    if args.outdated_concurrency is not None:
        cmd.extend(["--outdated-concurrency", str(args.outdated_concurrency)])
    if args.max_secret_files is not None:
        cmd.extend(["--max-secret-files", str(args.max_secret_files)])
    return cmd


def main():
    args = parse_args(sys.argv[1:])

    preflight_cmd = [
        sys.executable,
        script_path("preflight.py"),
        "--compact",
    ]
    if args.no_root_discovery:
        preflight_cmd.append("--no-root-discovery")
    preflight_cmd.append(args.project_path)
    preflight = run_json(preflight_cmd)

    scan = run_json(build_scan_cmd(args, preflight["output_file"]))

    analysis_path = os.path.join(
        os.path.dirname(os.path.abspath(scan["output_file"])),
        "analysis.json",
    )
    run_text(
        [
            sys.executable,
            script_path("analyze_scan.py"),
            scan["output_file"],
            analysis_path,
        ],
        echo=False,
    )

    with open(analysis_path, "r", encoding="utf-8") as handle:
        analysis = json.load(handle)
    markdown_path = os.path.join(
        analysis["project"]["path"],
        "docs",
        f"security-report-{str(analysis.get('generated_at', 'unknown-date'))[:10]}.md",
    )
    run_text(
        [
            sys.executable,
            script_path("render_markdown.py"),
            analysis_path,
            markdown_path,
        ],
        echo=False,
    )

    html_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(analysis_path))),
        "content",
        "security-report.html",
    )
    build_report_cmd = [
        sys.executable,
        script_path("build_report.py"),
        analysis_path,
        html_path,
    ]
    if args.no_open:
        build_report_cmd.append("--no-open")
    run_text(
        build_report_cmd,
        echo=False,
    )

    summary = {
        "preflight_file": preflight["output_file"],
        "scan_file": scan["output_file"],
        "analysis_file": analysis_path,
        "markdown_report": markdown_path,
        "html_report": html_path,
        "scan_mode": scan.get("scan_config", {}).get("scan_mode"),
        "risk_summary": analysis.get("risk_summary", {}),
        "errors": analysis.get("errors", []),
    }

    if args.compact:
        print(json.dumps(summary, ensure_ascii=False, separators=(",", ":")))
    else:
        print(format_human_summary(summary, scan, analysis, args))
    return 0


if __name__ == "__main__":
    sys.exit(main())
