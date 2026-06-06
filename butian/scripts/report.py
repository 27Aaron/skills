#!/usr/bin/env python3
"""Render a Markdown security report from analysis JSON.

Usage:
    python3 scripts/report.py .butian/<timestamp>/assets/analysis.json
    python3 scripts/report.py analysis.json docs/security-report-YYYY-MM-DD.md
"""

import argparse
import json
import logging
import os
import re
import string
import sys

logger = logging.getLogger("butian.scripts.report")

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_PATH = os.path.join(HERE, "..", "templates", "report.md")

try:
    from .scan import CAPABILITY_BOUNDARY, HYGIENE_ONLY_NOTICE, setup_logging
except ImportError:
    from scan import (  # pyright: ignore[reportMissingImports]
        CAPABILITY_BOUNDARY,
        HYGIENE_ONLY_NOTICE,
        setup_logging,
    )

SEVERITY_LABELS = {
    "critical": "紧急",
    "high": "高风险",
    "medium": "中风险",
    "low": "低风险",
    "info": "待确认",
}


def to_list(value):
    if not value:
        return []
    if isinstance(value, list):
        return [x for x in value if x]
    return [value]


def text(value):
    return str(value if value is not None else "").strip()


def cell(value):
    return text(value).replace("|", "\\|").replace("\n", " ")


def clean_version(value):
    return text(value).removeprefix("v")


def outdated_update_target(item):
    return (
        item.get("wanted")
        or item.get("update")
        or item.get("latest")
        or item.get("latestVersion")
    )


def is_outdated_item(item):
    current = clean_version(item.get("current") or item.get("version"))
    target = clean_version(outdated_update_target(item))
    return bool(target and current != target)


def date_from_analysis(analysis):
    generated_at = text(analysis.get("generated_at"))
    match = re.match(r"^\d{4}-\d{2}-\d{2}", generated_at)
    return match.group(0) if match else "unknown-date"


def datetime_from_analysis(analysis):
    """Extract filesystem-safe datetime string (YYYYMMDD-HHMM) from analysis."""
    generated_at = text(analysis.get("generated_at"))
    # generated_at format: "2026-06-06 00:45:27"
    cleaned = re.sub(r"[^\d]", "", generated_at)  # "20260606004527"
    if len(cleaned) >= 12:
        return f"{cleaned[:4]}{cleaned[4:6]}{cleaned[6:8]}-{cleaned[8:10]}{cleaned[10:12]}"
    return date_from_analysis(analysis)


def default_output_path(analysis):
    project = analysis.get("project") or {}
    project_path = project.get("path") or os.getcwd()
    docs_dir = os.path.join(project_path, "docs", "butian")
    os.makedirs(docs_dir, exist_ok=True)
    return os.path.join(
        docs_dir, f"security-report-{datetime_from_analysis(analysis)}.md"
    )


def severity_label(value):
    return SEVERITY_LABELS.get(text(value).lower(), "待确认")


def is_hygiene_only(analysis):
    return (analysis.get("scan_config") or {}).get("scan_mode") == "hygiene_only"


def security_ids(item):
    values = []

    def push(value):
        if not value:
            return
        if isinstance(value, list):
            for nested in value:
                push(nested)
            return
        for part in re.split(r"[,，\s]+", str(value)):
            part = part.strip()
            if part and part.upper().startswith("GHSA-") and part not in values:
                values.append(part)

    push(item.get("advisory_id"))
    push(item.get("advisory_ids"))
    push(item.get("aliases"))
    push(item.get("advisory_aliases"))
    return values


def render_summary(analysis):
    summary = analysis.get("summary") or {}
    lines = []
    lines.append(f"- TL;DR：{text(summary.get('tldr')) or '本次扫描没有生成摘要。'}")
    if summary.get("detail"):
        lines.append(f"- 详细说明：{text(summary.get('detail'))}")
    if is_hygiene_only(analysis):
        lines.append(f"- 扫描范围：{HYGIENE_ONLY_NOTICE}")
    lines.append(f"- 能力边界：{CAPABILITY_BOUNDARY}")
    priority = to_list(summary.get("priority"))
    if priority:
        lines.append("- 优先级建议：")
        for item in priority:
            lines.append(f"  - {text(item)}")
    lines.append("")
    return "\n".join(lines)


def render_vulnerabilities(analysis):
    issues = analysis.get("top_issues") or []
    if not issues:
        if is_hygiene_only(analysis):
            return f"本次未执行依赖漏洞扫描：{HYGIENE_ONLY_NOTICE}\n"
        return "未命中已确认的依赖风险项。\n"

    lines = [
        "| 影响程度 | 依赖名称 | 当前版本 | GHSA | 修复版本 | 说明 |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in issues:
        ids = "、".join(security_ids(item)) or "-"
        fixed = "、".join(map(str, to_list(item.get("fixed_versions")))) or "待确认"
        lines.append(
            "| "
            + " | ".join(
                [
                    cell(severity_label(item.get("severity"))),
                    cell(item.get("package") or item.get("name") or "-"),
                    cell(item.get("version") or "-"),
                    cell(ids),
                    cell(fixed),
                    cell(item.get("summary") or item.get("match_summary") or "-"),
                ]
            )
            + " |"
        )
    lines.append("")
    return "\n".join(lines)


def render_hygiene(analysis):
    hygiene = analysis.get("hygiene") or {}
    secrets = hygiene.get("tracked_secrets") or []
    sensitive = hygiene.get("sensitive_tracked") or []
    missing = hygiene.get("gitignore_missing") or []
    workspace = analysis.get("butian_workspace") or {}
    gitignore_state = workspace.get("gitignore") or {}

    lines = []
    if not secrets and not sensitive and not missing:
        lines.append(
            "没有发现硬编码密钥、被 git 跟踪的敏感文件或缺失的敏感文件忽略规则。"
        )
    else:
        lines.append(
            f"- 硬编码密钥：发现 {len(secrets)} 处疑似明文凭证。"
            if secrets
            else "- 硬编码密钥：没有发现疑似明文凭证。"
        )
        lines.append(
            f"- 敏感文件跟踪：发现 {len(sensitive)} 个被 git 跟踪的敏感文件。"
            if sensitive
            else "- 敏感文件跟踪：没有发现被 git 跟踪的敏感文件。"
        )
        lines.append(
            f"- .gitignore：建议补充 {len(missing)} 条规则（{'、'.join(map(str, missing))}）。"
            if missing
            else "- .gitignore：没有发现需要补充的敏感文件忽略规则。"
        )
    if gitignore_state:
        preexisting = "是" if gitignore_state.get("preexisting") else "否"
        added = "是" if gitignore_state.get("added_butian_entry") else "否"
        lines.append(
            f"- 工作区忽略规则：扫描前是否已有 .gitignore：{preexisting}；本次是否新增 `.butian/`：{added}。"
        )
    if secrets:
        lines.append("")
        lines.append("| 位置 | 类型 | 可信度 | 脱敏预览 |")
        lines.append("| --- | --- | --- | --- |")
        for item in secrets:
            location = item.get("file") or "-"
            if item.get("line"):
                location = f"{location}:{item['line']}"
            lines.append(
                f"| {cell(location)} | {cell(item.get('type'))} | {cell(item.get('confidence'))} | {cell(item.get('preview'))} |"
            )
    if sensitive:
        lines.append("")
        lines.append("| 文件 | 类型 | 大小 |")
        lines.append("| --- | --- | --- |")
        for item in sensitive:
            lines.append(
                f"| {cell(item.get('file'))} | {cell(item.get('type'))} | {cell(item.get('size'))} |"
            )
    lines.append("")
    return "\n".join(lines)


def render_outdated(analysis):
    outdated = [
        item for item in analysis.get("outdated") or [] if is_outdated_item(item)
    ]
    if is_hygiene_only(analysis):
        return (
            f"本次未执行依赖版本维护检查：{HYGIENE_ONLY_NOTICE}\n\n"
            "提醒：过期依赖只是维护信号，不代表一定存在漏洞；真正的安全优先级仍以命中风险项为准。\n"
        )
    if not outdated:
        return (
            "没有检测到明确的过期依赖，或当前包管理器没有返回可用结果。\n\n"
            "提醒：过期依赖只是维护信号，不代表一定存在漏洞；真正的安全优先级仍以命中风险项为准。\n"
        )

    lines = [
        "这里列出的是版本维护信号，不等同于已确认风险项；安全优先级仍以「命中风险项」部分为准。",
        "",
        "| 依赖名称 | 当前版本 | 最近版本 | 建议 |",
        "| --- | --- | --- | --- |",
    ]
    for item in outdated:
        package = item.get("package") or item.get("name") or "该依赖"
        current = item.get("current") or item.get("version") or ""
        wanted = item.get("wanted") or item.get("update") or ""
        latest = item.get("latest") or item.get("latestVersion") or ""
        target = (
            f"{wanted} / {latest}"
            if wanted and latest and wanted != latest
            else wanted or latest
        )
        recommendation_target = latest or wanted or target
        if current and recommendation_target:
            summary = (
                f"{package} 当前版本为 {current}，"
                f"建议升级到最新版本 {recommendation_target}。"
            )
        elif recommendation_target:
            summary = f"{package} 建议升级到最新版本 {recommendation_target}。"
        else:
            summary = f"{package} 需要复核版本状态"
        row = [
            cell(package),
            cell(current or "-"),
            cell(target or "-"),
            cell(summary),
        ]
        lines.append(f"| {row[0]} | {row[1]} | {row[2]} | {row[3]} |")
    lines.append("")
    return "\n".join(lines)


def render_manual_items(analysis):
    items = (analysis.get("red") or []) + (analysis.get("yellow") or [])
    if not items:
        return "没有需要额外人工确认的事项。\n"

    lines = []
    for index, item in enumerate(items, 1):
        lines.append(f"### {index}. {text(item.get('name')) or '待确认事项'}")
        if item.get("severity"):
            lines.append(f"- 影响程度：{severity_label(item.get('severity'))}")
        if item.get("path") or item.get("file"):
            lines.append(f"- 位置：`{text(item.get('path') or item.get('file'))}`")
        why = (
            item.get("why_manual")
            or item.get("why_keep")
            or item.get("problem")
            or item.get("risk_note")
        )
        risk = item.get("risk") or item.get("impact") or item.get("business_impact")
        action = (
            item.get("disposal")
            or item.get("indirect_release")
            or item.get("action")
            or item.get("recommendation")
        )
        if why:
            lines.append(f"- 为什么要关注：{text(why)}")
        if risk:
            lines.append(f"- 可能影响：{text(risk)}")
        if action:
            lines.append(f"- 建议动作：{text(action)}")
        lines.append("")
    return "\n".join(lines)


def render_errors(analysis):
    errors = analysis.get("errors") or []
    if not errors:
        return "没有记录到扫描错误。\n"
    lines = []
    for item in errors:
        lines.append(
            f"- [{text(item.get('step')) or 'unknown'}] {text(item.get('message'))}"
        )
    lines.append("")
    return "\n".join(lines)


def render_next_steps(analysis):
    priority = to_list((analysis.get("summary") or {}).get("priority"))
    dependency_fixes = [
        item
        for item in (analysis.get("green") or analysis.get("green_items") or [])
        if item.get("type") == "dependency_upgrade"
    ]
    lines = []
    if priority:
        for item in priority:
            lines.append(f"- {text(item)}")
    else:
        lines.append(
            "- 阅读报告后再决定是否修复；修复前需要明确确认修复范围和升级策略。"
        )
    if dependency_fixes:
        lines.append("- 依赖修复后必须重新运行补天扫描，确认风险项是否真正消失。")
        lines.append(
            "- 修复脚本只执行普通包管理器升级；如果复扫仍出现同名旧版本，报告中会标注父依赖信息，"
            "可继续升级父依赖来解除锁定。"
        )
    lines.append("")
    return "\n".join(lines)


def load_template():
    with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
        return string.Template(f.read())


def render_markdown(analysis):
    project = analysis.get("project") or {}
    risk_summary = analysis.get("risk_summary") or {}
    logger.info(
        "render_markdown: 项目=%s, 风险项=%d",
        project.get("name") or "-",
        sum(risk_summary.values()),
    )
    tpl = load_template()
    return (
        tpl.substitute(
            project_name=text(project.get("name")) or "-",
            project_path=text(project.get("path")) or "-",
            generated_at=text(analysis.get("generated_at")) or "-",
            scan_seconds=text(analysis.get("scan_seconds")) or "-",
            summary=render_summary(analysis),
            vulnerabilities=render_vulnerabilities(analysis),
            hygiene=render_hygiene(analysis),
            outdated=render_outdated(analysis),
            manual_items=render_manual_items(analysis),
            errors=render_errors(analysis),
            next_steps=render_next_steps(analysis),
        ).rstrip()
        + "\n"
    )


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Render a Markdown security report from analysis JSON",
    )
    parser.add_argument("analysis_json")
    parser.add_argument("output_markdown", nargs="?")
    return parser.parse_args(argv)


def main():
    args = parse_args(sys.argv[1:])

    src = args.analysis_json
    log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(src))), "logs")
    setup_logging(log_dir=log_dir, log_file="report.log")
    logger.info("report.py 开始: analysis=%s", src)

    with open(src, "r", encoding="utf-8") as handle:
        analysis = json.load(handle)

    out = args.output_markdown or default_output_path(analysis)
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w", encoding="utf-8") as handle:
        handle.write(render_markdown(analysis))

    logger.info("Markdown 报告已写入: %s", out)
    print(f"Markdown 报告已生成: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
