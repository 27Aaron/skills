#!/usr/bin/env python3
"""运行完整的本地审计流水线。

用法：
    python3 scripts/run_audit.py [project_path]
    python3 scripts/run_audit.py --no-root-discovery [project_path]
    python3 scripts/run_audit.py --skip-outdated [project_path]
    py -3 scripts/run_audit.py [project_path]  # Windows

流水线：
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

logger = logging.getLogger("butian.scripts.run_audit")

HERE = os.path.dirname(os.path.abspath(__file__))

try:
    from .scan import (
        CAPABILITY_BOUNDARY,
        HYGIENE_ONLY_NOTICE,
        run_dir_from_output_file,
        setup_logging,
    )
except ImportError:
    from scan import (  # pyright: ignore[reportMissingImports]
        CAPABILITY_BOUNDARY,
        HYGIENE_ONLY_NOTICE,
        run_dir_from_output_file,
        setup_logging,
    )


def script_path(name):
    return os.path.join(HERE, name)


def parse_args(argv):
    parser = argparse.ArgumentParser(description="运行本地审计流水线")
    parser.add_argument("project_path", nargs="?", default=".")
    parser.add_argument(
        "--no-root-discovery",
        action="store_true",
        help="直接扫描传入路径，不向上查找项目根目录",
    )
    parser.add_argument(
        "--skip-outdated",
        action="store_true",
        help="跳过包管理器 outdated 检查，加快只看漏洞的扫描",
    )
    parser.add_argument(
        "--allow-project-exec",
        action="store_true",
        help="允许 outdated 检查执行项目内工具（例如 .venv/bin/python）",
    )
    parser.add_argument(
        "--skip-hygiene",
        action="store_true",
        help="跳过 gitignore、被跟踪敏感文件和硬编码密钥检查",
    )
    parser.add_argument(
        "--max-secret-files",
        type=int,
        default=None,
        help="硬编码密钥候选文件的最大扫描数量",
    )
    parser.add_argument(
        "--include-packages",
        action="store_true",
        help="在 scan 输出 JSON 中包含完整包列表",
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="兼容旧参数；报告始终只在终端展示路径，不自动打开浏览器",
    )
    parser.add_argument(
        "--final-report",
        action="store_true",
        help="使用 security-report-final-* 文件名生成修复后的收尾报告",
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


def absolute_path(path: str) -> str:
    if not path:
        return "-"
    return os.path.abspath(path)


def report_run_dir(analysis, scan=None):
    for source in (analysis, scan or {}):
        workspace = source.get("butian_workspace") or {}
        run_dir = workspace.get("run_dir")
        if run_dir:
            return os.path.abspath(run_dir)
    output_file = (scan or {}).get("output_file")
    if output_file:
        return os.path.abspath(run_dir_from_output_file(output_file))
    raise ValueError("无法从分析结果中确定报告运行目录")


def report_run_id(run_dir):
    return os.path.basename(os.path.normpath(run_dir))


def report_date_dir_name(run_dir):
    run_id = report_run_id(run_dir)
    match = re.match(r"^(\d{4})(\d{2})(\d{2})", run_id)
    if match:
        return f"{match.group(1)}-{match.group(2)}{match.group(3)}"
    return "unknown-date"


def report_basename(final_report=False):
    return "security-report-final" if final_report else "security-report"


def report_output_dir(analysis, run_dir):
    project_path = (analysis.get("project") or {}).get("path") or os.getcwd()
    return os.path.join(
        project_path,
        "docs",
        "butian",
        report_date_dir_name(run_dir),
    )


def markdown_report_path(analysis, run_dir, final_report=False):
    return os.path.join(
        report_output_dir(analysis, run_dir),
        f"{report_basename(final_report=final_report)}.md",
    )


def html_report_path(analysis, run_dir, final_report=False):
    return os.path.join(
        report_output_dir(analysis, run_dir),
        f"{report_basename(final_report=final_report)}.html",
    )


def version_key(value):
    parts = re.findall(r"\d+", str(value or ""))
    return tuple(int(part) for part in parts)


def compare_versions(a, b):
    left = version_key(a)
    right = version_key(b)
    for index in range(max(len(left), len(right))):
        delta = (left[index] if index < len(left) else 0) - (
            right[index] if index < len(right) else 0
        )
        if delta:
            return delta
    return 0


def best_fixed_version(issues):
    versions = []
    current_version = ""
    for issue in issues:
        current_version = (
            current_version
            or issue.get("version")
            or issue.get("current_version")
            or issue.get("current")
            or ""
        )
        for version in issue.get("fixed_versions") or issue.get("fix_versions") or []:
            text = str(version)
            if text and text not in versions:
                versions.append(text)
    if not versions:
        return "待确认"
    if version_key(current_version):
        versions = [
            version for version in versions if compare_versions(version, current_version) > 0
        ]
    if not versions:
        return "待确认"

    current_major = version_key(current_version)[0] if version_key(current_version) else None
    same_major = [
        version
        for version in versions
        if current_major is not None and version_key(version)[0:1] == (current_major,)
    ]
    versions = same_major or versions
    versions.sort(key=version_key)
    return versions[-1]


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
        "hygiene_only": "仓库安检",
    }
    return labels.get(scan_mode, "安全扫描")


def quote_line(text):
    return f"> {text}"


def has_vulnerability_source_errors(analysis):
    for error in analysis.get("errors") or []:
        if str(error.get("step") or "") == "vulnerability_check":
            return True
    return False


def format_risk_rows(risk_summary):
    labels = [
        ("critical", "🔴 紧急 (Critical)"),
        ("high", "🟠 高风险 (High)"),
        ("medium", "🟡 中风险 (Medium)"),
        ("low", "🟢 低风险 (Low)"),
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
        if has_vulnerability_source_errors(analysis):
            return (
                "本次未命中需要优先处理的依赖漏洞，但官方漏洞源检查存在失败，"
                "不能当作完整的安全结论；请先查看扫描错误，确认 OSV/NVD/EPSS "
                "等数据源恢复后再复扫。"
            )
        risk_summary = analysis.get("risk_summary") or {}
        if any(
            int(risk_summary.get(key) or 0)
            for key in ("critical", "high", "medium", "low")
        ):
            return (
                "本次分析中存在风险计数，但缺少可展示的明细；请查看 analysis.json "
                "和扫描错误，确认报告生成链路是否完整。"
            )
        return "未发现需要优先处理的依赖漏洞。"

    priority = [
        issue
        for issue in issues
        if str(issue.get("severity") or "").lower() in {"critical", "high"}
    ]
    focus_source = priority or issues
    groups = defaultdict(list)
    for issue in focus_source:
        package = (
            issue.get("package")
            or issue.get("name")
            or issue.get("title")
            or "未知依赖"
        )
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
    subject_label = "包"
    lines = [
        f"核心风险集中在 {len(ranked)} 个{subject_label}（{total_priority} 个{noun}中它们占 {selected_count} 个）：",
        "",
        table(
            [subject_label, "当前", "建议升到", "风险性质"],
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
    dependency_issue_count = analysis.get(
        "vulnerability_count", len(analysis.get("top_issues") or [])
    )
    confirmed_issue_count = dependency_issue_count
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
    markdown_label = "最终 Markdown" if args.final_report else "Markdown"
    if summary.get("html_report"):
        html_report_line = (
            f"- HTML 报告（不会自动打开）："
            f"{absolute_path(summary.get('html_report'))}"
        )
    else:
        html_report_line = "- HTML 报告：未生成"
    scope_notice = (
        ["", "⚠️ 扫描范围", "", quote_line(HYGIENE_ONLY_NOTICE)]
        if scan_mode == "hygiene_only"
        else []
    )

    count_lines = [
        f"- 总依赖：{total_packages} 个{dependency_unit}",
        f"- 已确认风险项：{confirmed_issue_count} 个",
        f"- 仓库安检：{secret_count} 个硬编码凭证 / {sensitive_count} 个跟踪的敏感文件 / {gitignore_label}",
        f"- 过期依赖：{analysis.get('outdated_count', len(analysis.get('outdated') or []))} 个（建议按维护窗口评估升级）",
        f"- 扫描错误：{error_label}",
    ]
    closing_note = "报告只保存到本地路径，不会自动打开；想看细节可以打开上面的 Markdown 或 HTML。需要修复时，请在当前交互里选择要处理的项。"

    report_path_lines = [
        (
            f"- {markdown_label} 审计报告："
            f"{absolute_path(summary.get('markdown_report')) if summary.get('markdown_report') else '复扫未生成（首次扫描已有）'}"
        ),
        html_report_line,
        f"- analysis JSON：{absolute_path(summary.get('analysis_file'))}",
    ]
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
        *count_lines,
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
        *report_path_lines,
        "",
        quote_line(closing_note),
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
    if args.allow_project_exec:
        cmd.append("--allow-project-exec")
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


def build_visualize_cmd(args, analysis_path, html_path):
    cmd = [
        sys.executable,
        script_path("visualize.py"),
        analysis_path,
        html_path,
        "--no-open",
    ]
    return cmd


def main():
    args = parse_args(sys.argv[1:])
    # 先启用 stderr 日志；scan.json 固定运行目录后再追加文件日志。
    setup_logging()
    logger.info("审计流水线开始: 路径=%s", args.project_path)

    # 预检先固定本次运行工作区，再让下游阶段写入产物路径。
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

    scan = run_json(build_scan_cmd(args, preflight["output_file"]))
    scan_mode = scan.get("scan_config", {}).get("scan_mode", "unknown")

    # 工作区布局确定后，追加本次运行范围内的文件日志。
    scan_log_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(scan["output_file"]))),
        "logs",
    )
    butian_logger = logging.getLogger("butian")
    if not any(isinstance(h, logging.FileHandler) for h in butian_logger.handlers):
        os.makedirs(scan_log_dir, exist_ok=True)
        fh = logging.FileHandler(
            os.path.join(scan_log_dir, "run_audit.log"),
            encoding="utf-8",
        )
        fh.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                "%Y-%m-%d %H:%M:%S",
            )
        )
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

    # analysis 是报告和修复计划使用的确定性 JSON 契约。
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
        risk_summary.get("critical", 0),
        risk_summary.get("high", 0),
        risk_summary.get("medium", 0),
        risk_summary.get("low", 0),
        risk_summary.get("info", 0),
    )

    run_dir = report_run_dir(analysis, scan)

    markdown_path = markdown_report_path(
        analysis, run_dir, final_report=args.final_report
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

    # 项目 Markdown 和 HTML 每次都重新生成到 docs/butian/<日期>/，
    # 终端摘要只展示路径，不自动打开浏览器。
    html_path = html_report_path(analysis, run_dir, final_report=args.final_report)
    os.makedirs(os.path.dirname(html_path), exist_ok=True)
    build_report_cmd = build_visualize_cmd(args, analysis_path, html_path)
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
    logger.info("审计流水线完成")
    return 0


if __name__ == "__main__":
    sys.exit(main())
