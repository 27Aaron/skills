#!/usr/bin/env python3
"""Render a Markdown security report from 补天 analysis JSON.

Usage:
    python3 scripts/render_markdown.py .butian/<timestamp>/assets/analysis.json
    python3 scripts/render_markdown.py analysis.json docs/security-report-YYYY-MM-DD.md
"""

import json
import os
import re
import sys

SEVERITY_LABELS = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}
CAPABILITY_BOUNDARY = (
    "安全往往不是最显眼的需求，却是产品长期稳定运行的底线。"
    "补天 会优先帮助你发现依赖漏洞、过期依赖和仓库卫生风险，"
    "让容易被忽视的供应链问题更早暴露出来。"
    "但它不能替代代码审计、渗透测试或部署安全评估；"
    "代码层面的权限、业务逻辑、SQL 注入、XSS 等问题仍需单独复核。"
)


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


def default_output_path(analysis):
    project = analysis.get("project") or {}
    project_path = project.get("path") or os.getcwd()
    docs_dir = os.path.join(project_path, "docs")
    os.makedirs(docs_dir, exist_ok=True)
    return os.path.join(docs_dir, f"security-report-{date_from_analysis(analysis)}.md")


def severity_label(value):
    return SEVERITY_LABELS.get(text(value).lower(), text(value) or "信息")


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
    lines = [
        "## 报告总结",
        "",
        f"- TL;DR：{text(summary.get('tldr')) or '本次扫描没有生成摘要。'}",
    ]
    if summary.get("detail"):
        lines.append(f"- 详细说明：{text(summary.get('detail'))}")
    lines.append(f"- 能力边界：{CAPABILITY_BOUNDARY}")
    priority = to_list(summary.get("priority"))
    if priority:
        lines.append("- 优先级建议：")
        for item in priority:
            lines.append(f"  - {text(item)}")
    lines.append("")
    return lines


def render_vulnerabilities(analysis):
    issues = analysis.get("top_issues") or []
    lines = ["## 命中漏洞", ""]
    if not issues:
        lines.extend(["未命中已确认的依赖漏洞。", ""])
        return lines

    lines.extend(
        [
            "| 严重度 | 包名 | 当前版本 | GHSA | 修复版本 | 说明 |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
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
    return lines


def render_hygiene(analysis):
    hygiene = analysis.get("hygiene") or {}
    secrets = hygiene.get("tracked_secrets") or []
    sensitive = hygiene.get("sensitive_tracked") or []
    missing = hygiene.get("gitignore_missing") or []
    workspace = analysis.get("butian_workspace") or {}
    gitignore_state = workspace.get("gitignore") or {}

    lines = ["## 仓库卫生扫描", ""]
    if not secrets and not sensitive and not missing:
        lines.append("没有发现硬编码密钥、被 git 跟踪的敏感文件或缺失的敏感文件忽略规则。")
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
        lines.append(f"- 补天 工作区忽略规则：扫描前是否已有 .gitignore：{preexisting}；本次是否新增 `.butian/`：{added}。")
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
            lines.append(f"| {cell(item.get('file'))} | {cell(item.get('type'))} | {cell(item.get('size'))} |")
    lines.append("")
    return lines


def render_outdated(analysis):
    outdated = [item for item in analysis.get("outdated") or [] if is_outdated_item(item)]
    lines = ["## 过期依赖", ""]
    if not outdated:
        lines.extend(
            [
                "没有检测到明确的过期依赖，或当前包管理器没有返回可用结果。",
                "",
                "提醒：过期依赖只是维护信号，不代表一定存在漏洞；真正的安全优先级仍以命中漏洞为准。",
                "",
            ]
        )
        return lines

    lines.append(
        "这里列出的是版本维护信号，不等同于已确认漏洞；安全优先级仍以“命中漏洞”部分为准。"
    )
    lines.append("")
    lines.extend(
        [
            "| 包名 | 当前版本 | 可更新到 | 生态 | 建议 |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
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
        if current and wanted and latest and wanted != latest:
            summary = (
                f"{package} 当前版本为 {current}，"
                f"建议更新到最新版本 {wanted} / {latest}。"
            )
        elif current and target:
            summary = f"{package} 当前版本为 {current}，建议更新到最新版本 {target}。"
        elif target:
            summary = f"{package} 建议更新到最新版本 {target}。"
        else:
            summary = f"{package} 需要复核版本状态"
        row = [
            cell(package),
            cell(current or "-"),
            cell(target or "-"),
            cell(item.get("ecosystem") or "-"),
            cell(summary),
        ]
        lines.append(
            f"| {row[0]} | {row[1]} | {row[2]} | {row[3]} | {row[4]} |"
        )
    lines.append("")
    return lines


def render_manual_items(analysis):
    items = (analysis.get("red") or []) + (analysis.get("yellow") or [])
    lines = ["## 需要人工确认的事项", ""]
    if not items:
        lines.extend(["没有需要额外人工确认的事项。", ""])
        return lines

    for index, item in enumerate(items, 1):
        lines.append(f"### {index}. {text(item.get('name')) or '待确认事项'}")
        if item.get("severity"):
            lines.append(f"- 严重度：{severity_label(item.get('severity'))}")
        if item.get("path") or item.get("file"):
            lines.append(f"- 位置：`{text(item.get('path') or item.get('file'))}`")
        why = item.get("why_manual") or item.get("why_keep") or item.get("problem") or item.get("risk_note")
        risk = item.get("risk") or item.get("impact") or item.get("business_impact")
        action = item.get("disposal") or item.get("indirect_release") or item.get("action") or item.get("recommendation")
        if why:
            lines.append(f"- 为什么要关注：{text(why)}")
        if risk:
            lines.append(f"- 可能影响：{text(risk)}")
        if action:
            lines.append(f"- 建议动作：{text(action)}")
        lines.append("")
    return lines


def render_errors(analysis):
    errors = analysis.get("errors") or []
    lines = ["## 扫描错误", ""]
    if not errors:
        lines.extend(["没有记录到扫描错误。", ""])
        return lines
    for item in errors:
        lines.append(f"- [{text(item.get('step')) or 'unknown'}] {text(item.get('message'))}")
    lines.append("")
    return lines


def render_next_steps(analysis):
    priority = to_list((analysis.get("summary") or {}).get("priority"))
    lines = ["## 下一步建议", ""]
    if priority:
        for item in priority:
            lines.append(f"- {text(item)}")
    else:
        lines.append("- 阅读报告后再决定是否修复；需要处理时，在对话里明确回复“可以修 / 修复 / OK / Yes”。")
    lines.append("")
    return lines


def render_markdown(analysis):
    project = analysis.get("project") or {}
    lines = [
        "# 安全扫描报告",
        "",
        f"- 项目：{text(project.get('name')) or '-'}",
        f"- 路径：`{text(project.get('path')) or '-'}`",
        f"- 生成时间：{text(analysis.get('generated_at')) or '-'}",
        f"- 扫描耗时：{text(analysis.get('scan_seconds')) or '-'} 秒",
        "",
    ]
    lines.extend(render_summary(analysis))
    lines.extend(render_vulnerabilities(analysis))
    lines.extend(render_hygiene(analysis))
    lines.extend(render_outdated(analysis))
    lines.extend(render_manual_items(analysis))
    lines.extend(render_errors(analysis))
    lines.extend(render_next_steps(analysis))
    return "\n".join(lines).rstrip() + "\n"


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1

    src = sys.argv[1]
    with open(src, "r", encoding="utf-8") as handle:
        analysis = json.load(handle)

    out = sys.argv[2] if len(sys.argv) > 2 else default_output_path(analysis)
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w", encoding="utf-8") as handle:
        handle.write(render_markdown(analysis))

    print(f"Markdown 报告已生成: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
