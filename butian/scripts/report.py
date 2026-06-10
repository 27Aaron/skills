#!/usr/bin/env python3
"""根据 analysis JSON 渲染 Markdown 安全报告。

Usage:
    python3 scripts/report.py .butian/<timestamp>/assets/analysis.json
    python3 scripts/report.py analysis.json docs/butian/security-report-<run-id>.md
"""

import argparse
import html
import json
import logging
import os
import re
import string
import sys
from urllib.parse import quote

logger = logging.getLogger("butian.scripts.report")

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_PATH = os.path.join(HERE, "..", "templates", "report.md")

try:
    from .labels import SECRET_TYPE_LABELS, SENSITIVE_TYPE_LABELS
    from .scan import CAPABILITY_BOUNDARY, HYGIENE_ONLY_NOTICE, setup_logging
except ImportError:
    from labels import (  # pyright: ignore[reportMissingImports]
        SECRET_TYPE_LABELS,
        SENSITIVE_TYPE_LABELS,
    )
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

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d+$", flags=re.IGNORECASE)
GHSA_ID_RE = re.compile(
    r"^GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$", flags=re.IGNORECASE
)
OSV_ID_RE = re.compile(r"^[A-Z][A-Z0-9]+-[A-Z0-9][A-Z0-9_.-]*$", flags=re.IGNORECASE)
JAVASCRIPT_PROTOCOL_RE = re.compile(r"\bjavascript\s*:", flags=re.IGNORECASE)


def to_list(value):
    if not value:
        return []
    if isinstance(value, list):
        return [x for x in value if x]
    return [value]


def text(value):
    return str(value if value is not None else "").strip()


def markdown_text(value):
    escaped = html.escape(text(value), quote=False)
    return JAVASCRIPT_PROTOCOL_RE.sub("javascript&#58;", escaped)


def cell(value):
    # Markdown helper 是最后一层转义；分析器文本进入管道表格前，
    # 需要在这里让 HTML、危险协议、表格分隔符和换行失效。
    return markdown_text(value).replace("|", "\\|").replace("\n", " ")


def inline_code(value):
    value = text(value)
    if not value:
        return "-"
    max_backticks = max(
        (len(match.group(0)) for match in re.finditer(r"`+", value)), default=0
    )
    fence = "`" * (max_backticks + 1)
    if max_backticks:
        return f"{fence} {value} {fence}"
    return f"{fence}{value}{fence}"


def clean_version(value):
    return text(value).removeprefix("v")


def version_parts(value):
    match = re.search(r"\d+(?:\.\d+){0,3}", text(value))
    if not match:
        return []
    return [int(part) for part in match.group(0).split(".")]


def pseudo_version_timestamp(value):
    match = re.search(r"-(\d{14})-[0-9A-Fa-f]+$", text(value))
    return int(match.group(1)) if match else None


def compare_versions(a, b):
    left = version_parts(a)
    right = version_parts(b)
    for index in range(max(len(left), len(right))):
        delta = (left[index] if index < len(left) else 0) - (
            right[index] if index < len(right) else 0
        )
        if delta:
            return delta
    left_timestamp = pseudo_version_timestamp(a)
    right_timestamp = pseudo_version_timestamp(b)
    if left_timestamp is not None and right_timestamp is not None:
        return left_timestamp - right_timestamp
    return 0


def best_fixed_version(versions, current_version):
    unique_versions = []
    for version in to_list(versions):
        version = text(version)
        if version and version not in unique_versions:
            unique_versions.append(version)
    if not unique_versions:
        return "待确认"

    if version_parts(current_version):
        candidates = [
            version
            for version in unique_versions
            if compare_versions(version, current_version) > 0
        ]
    else:
        candidates = unique_versions
    if not candidates:
        return "待确认"

    current_major = version_parts(current_version)[0] if version_parts(current_version) else None
    same_major = [
        version
        for version in candidates
        if current_major is not None and version_parts(version)[0:1] == [current_major]
    ]
    candidates = same_major or candidates
    return sorted(candidates, key=lambda version: version_parts(version))[-1]


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
    """从 analysis 中提取适合文件系统使用的时间字符串（YYYYMMDD-HHMM）。"""
    generated_at = text(analysis.get("generated_at"))
    cleaned = re.sub(r"[^\d]", "", generated_at)
    if len(cleaned) >= 12:
        return (
            f"{cleaned[:4]}{cleaned[4:6]}{cleaned[6:8]}-{cleaned[8:10]}{cleaned[10:12]}"
        )
    return date_from_analysis(analysis)


def default_output_path(analysis):
    project = analysis.get("project") or {}
    project_path = project.get("path") or os.getcwd()
    workspace = analysis.get("butian_workspace") or {}
    run_dir = workspace.get("run_dir")
    report_id = (
        os.path.basename(os.path.normpath(run_dir))
        if run_dir
        else datetime_from_analysis(analysis)
    )
    docs_dir = os.path.join(project_path, "docs", "butian")
    os.makedirs(docs_dir, exist_ok=True)
    return os.path.join(docs_dir, f"security-report-{report_id}.md")


def severity_label(value):
    return SEVERITY_LABELS.get(text(value).lower(), "待确认")


def secret_type_label(value):
    key = text(value)
    return SECRET_TYPE_LABELS.get(key, key or "密钥")


def sensitive_type_label(value):
    key = text(value)
    return SENSITIVE_TYPE_LABELS.get(key, key or "敏感文件")


def structured_finding_label(item):
    if item.get("kind") == "maintenance_advice":
        return "建议"
    return severity_label(item.get("severity"))


def is_hygiene_only(analysis):
    return (analysis.get("scan_config") or {}).get("scan_mode") == "hygiene_only"


def has_vulnerability_errors(analysis):
    for item in analysis.get("errors") or []:
        step = text(item.get("step")).lower()
        message = text(item.get("message")).lower()
        if step == "vulnerability_check" or "vulnerability_check" in message:
            return True
    return False


def normalize_security_id(value):
    value = text(value).strip("()[]{}.,;")
    if CVE_ID_RE.match(value):
        return value.upper()
    if GHSA_ID_RE.match(value):
        return value
    if OSV_ID_RE.match(value):
        return value
    return ""


def security_ids(item):
    cves = []
    ghsas = []
    others = []

    def add(bucket, value):
        key = value.lower()
        if not any(existing.lower() == key for existing in bucket):
            bucket.append(value)

    def push(value):
        if not value:
            return
        if isinstance(value, list):
            for nested in value:
                push(nested)
            return
        for part in re.split(r"[,，\s]+", str(value)):
            part = normalize_security_id(part)
            if not part:
                continue
            if CVE_ID_RE.match(part):
                add(cves, part.upper())
            elif GHSA_ID_RE.match(part):
                add(ghsas, part)
            else:
                add(others, part)

    push(item.get("cve_ids"))
    push(item.get("cve_id"))
    push(item.get("advisory_id"))
    push(item.get("advisory_ids"))
    push(item.get("aliases"))
    push(item.get("advisory_aliases"))
    return cves + ghsas + others


def security_id_url(security_id):
    value = text(security_id)
    if CVE_ID_RE.match(value):
        return f"https://www.cve.org/CVERecord?id={value.upper()}"
    return f"https://osv.dev/vulnerability/{quote(value, safe='-._~')}"


def markdown_link_label(value):
    return text(value).replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]")


def security_id_markdown(security_id):
    # 安全编号必须保持可点击。CVE 使用 CVE 记录页；
    # GHSA/OSV 风格编号使用 OSV。
    value = text(security_id)
    if not value:
        return ""
    return f"[{markdown_link_label(value)}]({security_id_url(value)})"


def security_ids_markdown(item):
    values = [security_id_markdown(security_id) for security_id in security_ids(item)]
    return "、".join(value for value in values if value) or "-"


def number_or_none(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number


def compact_number(value, digits=2):
    number = number_or_none(value)
    if number is None:
        return ""
    rendered = f"{number:.{digits}f}"
    return rendered.rstrip("0").rstrip(".")


def percent_text(value, digits=2):
    number = number_or_none(value)
    if number is None:
        return ""
    return f"{compact_number(number * 100, digits)}%"


def short_date(value):
    value = text(value)
    match = re.match(r"^(\d{4}-\d{2}-\d{2})", value)
    if match:
        return match.group(1)
    match = re.match(r"^(\d{4}-\d{2})", value)
    return match.group(1) if match else value


def aggregate_enrichments(item):
    enrichments = item.get("cve_enrichments")
    if not isinstance(enrichments, list):
        return {}

    result = {
        "max_epss": None,
        "max_epss_percentile": None,
        "epss_date": "",
        "best_cvss_score": None,
        "cvss_vector": "",
        "cwe_ids": [],
        "kev_listed": False,
        "kev_date_added": "",
        "kev_due_date": "",
        "kev_required_action": "",
        "ransomware": False,
        "published_at": "",
    }
    for enrichment in enrichments:
        if not isinstance(enrichment, dict):
            continue

        epss = number_or_none(enrichment.get("epss"))
        percentile = number_or_none(enrichment.get("epssPercentile"))
        if percentile is not None and (
            result["max_epss_percentile"] is None
            or percentile > result["max_epss_percentile"]
        ):
            result["max_epss_percentile"] = percentile
            result["max_epss"] = epss
            result["epss_date"] = short_date(enrichment.get("epssScoreDate"))
        elif result["max_epss"] is None and epss is not None:
            result["max_epss"] = epss
            result["epss_date"] = short_date(enrichment.get("epssScoreDate"))

        for cwe_id in enrichment.get("cweIds") or []:
            cwe_id = text(cwe_id)
            if cwe_id and cwe_id not in result["cwe_ids"]:
                result["cwe_ids"].append(cwe_id)

        if enrichment.get("kevListed"):
            result["kev_listed"] = True
        if enrichment.get("kevDateAdded"):
            result["kev_date_added"] = short_date(enrichment.get("kevDateAdded"))
        if enrichment.get("kevDueDate"):
            result["kev_due_date"] = short_date(enrichment.get("kevDueDate"))
        if enrichment.get("kevRequiredAction"):
            result["kev_required_action"] = text(enrichment.get("kevRequiredAction"))
        if text(enrichment.get("kevKnownRansomwareCampaignUse")).lower() == "known":
            result["ransomware"] = True
        if enrichment.get("nvdPublishedAt") and (
            not result["published_at"]
            or text(enrichment.get("nvdPublishedAt")) < result["published_at"]
        ):
            result["published_at"] = short_date(enrichment.get("nvdPublishedAt"))

        for metric in enrichment.get("cvssMetrics") or []:
            if not isinstance(metric, dict):
                continue
            score = number_or_none(metric.get("baseScore"))
            if score is not None and (
                result["best_cvss_score"] is None or score > result["best_cvss_score"]
            ):
                result["best_cvss_score"] = score
                result["cvss_vector"] = text(metric.get("vector"))
    return result


def enrichment_summary(item):
    signals = aggregate_enrichments(item)
    if not signals:
        return ""

    parts = []
    epss = signals.get("max_epss")
    percentile = signals.get("max_epss_percentile")
    if epss is not None or percentile is not None:
        value = percentile if percentile is not None else epss
        digits = 1 if percentile is not None else 2
        parts.append(f"EPSS {percent_text(value, digits=digits)}")

    if signals.get("best_cvss_score") is not None:
        score = compact_number(signals["best_cvss_score"], digits=1)
        parts.append(f"CVSS {score}")

    if signals.get("cwe_ids"):
        parts.append("、".join(signals["cwe_ids"]))

    if signals.get("kev_listed"):
        parts.append("CISA KEV")

    if signals.get("published_at"):
        parts.append(f"NVD {signals['published_at']}")

    return "；".join(parts)


def render_summary(analysis):
    summary = analysis.get("summary") or {}
    lines = []
    lines.append(
        f"- TL;DR：{markdown_text(summary.get('tldr')) or '本次扫描没有生成摘要。'}"
    )
    if summary.get("detail"):
        lines.append(f"- 详细说明：{markdown_text(summary.get('detail'))}")
    if is_hygiene_only(analysis):
        lines.append(f"- 扫描范围：{HYGIENE_ONLY_NOTICE}")
    lines.append(f"- 能力边界：{CAPABILITY_BOUNDARY}")
    priority = to_list(summary.get("priority"))
    if priority:
        lines.append("- 优先级建议：")
        for item in priority:
            lines.append(f"  - {markdown_text(item)}")
    lines.append("")
    return "\n".join(lines)


def render_vulnerabilities(analysis):
    issues = analysis.get("top_issues") or []
    if not issues:
        if is_hygiene_only(analysis):
            return f"本次未执行依赖漏洞扫描：{HYGIENE_ONLY_NOTICE}\n"
        if has_vulnerability_errors(analysis):
            return (
                "依赖漏洞检查不完整，不能证明无风险。请先复查扫描错误，"
                "补齐失败的官方漏洞源检查后再确认最终结论。\n"
            )
        return "未命中已确认的依赖风险项。\n"

    lines = [
        "| 影响程度 | 依赖名称 | 当前版本 | 修复版本 | 安全编号 |",
        "| --- | --- | --- | --- | --- |",
    ]
    for item in issues:
        ids = security_ids_markdown(item)
        fixed = best_fixed_version(
            item.get("fixed_versions")
            or item.get("fix_versions")
            or item.get("patched_versions"),
            item.get("version"),
        )
        lines.append(
            "| "
            + " | ".join(
                [
                    cell(severity_label(item.get("severity"))),
                    cell(item.get("package") or item.get("name") or "-"),
                    cell(item.get("version") or "-"),
                    cell(fixed),
                    cell(ids),
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
    structured_groups = [
        ("GitHub Actions 工作流安全", hygiene.get("workflow_checks") or []),
        ("依赖配置与维护", hygiene.get("repository_checks") or []),
        ("IaC / 容器 / 部署配置", hygiene.get("iac_checks") or []),
    ]
    structured_count = sum(len(items) for _, items in structured_groups)
    lines = []
    if not secrets and not sensitive and not missing and not structured_count:
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
        if structured_count:
            advice_count = sum(
                1
                for _, items in structured_groups
                for item in items
                if str(item.get("severity") or "").lower() == "info"
            )
            risk_like_count = structured_count - advice_count
            lines.append(
                f"- 本地配置检查：发现 {risk_like_count} 个需要确认的仓库安检项，"
                f"{advice_count} 条建议。"
            )
    if secrets:
        lines.append("")
        lines.append("| 位置 | 类型 | 可信度 | 证据预览 |")
        lines.append("| --- | --- | --- | --- |")
        for item in secrets:
            location = item.get("file") or "-"
            if item.get("line"):
                location = f"{location}:{item['line']}"
            lines.append(
                f"| {cell(location)} | {cell(secret_type_label(item.get('type')))} | {cell(item.get('confidence'))} | {cell(item.get('preview'))} |"
            )
    if sensitive:
        lines.append("")
        lines.append("| 文件 | 类型 | 大小 |")
        lines.append("| --- | --- | --- |")
        for item in sensitive:
            lines.append(
                f"| {cell(item.get('file'))} | {cell(sensitive_type_label(item.get('type')))} | {cell(item.get('size'))} |"
            )
    for title, items in structured_groups:
        if not items:
            continue
        lines.append("")
        lines.append(f"### {title}")
        lines.append("")
        include_evidence = title != "依赖配置与维护"
        if include_evidence:
            lines.append("| 等级 | 位置 | 检查项 | 依据 | 处理 |")
            lines.append("| --- | --- | --- | --- | --- |")
        else:
            lines.append("| 等级 | 位置 | 检查项 | 处理 |")
            lines.append("| --- | --- | --- | --- |")
        for item in items:
            location = item.get("file") or "-"
            if item.get("line"):
                location = f"{location}:{item['line']}"
            row = [
                cell(structured_finding_label(item)),
                cell(location),
                cell(item.get("title") or item.get("id") or "-"),
            ]
            if include_evidence:
                row.append(cell(item.get("evidence") or "-"))
            row.append(cell(item.get("recommendation") or "-"))
            lines.append(
                "| "
                + " | ".join(row)
                + " |"
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
            "提醒：过期依赖用于版本维护规划；处理顺序仍以当前风险项和发布窗口为准。\n"
        )
    if not outdated:
        return (
            "没有检测到明确的过期依赖，或当前包管理器没有返回可用结果。\n\n"
            "提醒：过期依赖用于版本维护规划；处理顺序仍以当前风险项和发布窗口为准。\n"
        )

    lines = [
        "这里列出的是版本维护优化项；建议结合版本跨度、兼容性和发布窗口分批处理。",
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


def _server_summary_value(server, key, default=0):
    return (server.get("summary") or {}).get(key, default)


def _server_fixed_versions(item):
    values = item.get("fixed_versions") or []
    if not values:
        return "-"
    return ", ".join(inline_code(value) for value in values)


def _server_section_errors(analysis):
    seen = set()
    errors = []
    for error in (analysis.get("server_errors") or []) + (analysis.get("errors") or []):
        step = str(error.get("step") or "")
        if not (step.startswith("server") or step == "vulnerability_check"):
            continue
        key = (step, error.get("message"), error.get("code"))
        if key in seen:
            continue
        seen.add(key)
        errors.append(error)
    return errors


def render_server_environment(analysis):
    server = analysis.get("server") or {}
    if not server:
        return "未启用服务器运行环境扫描。"

    distro = server.get("distro") or (server.get("summary") or {}).get("distro") or {}
    kernel = analysis.get("server_kernel") or server.get("kernel") or {}
    lines = [
        "### 服务器概览",
        "",
        f"- 发行版：{cell(distro.get('pretty_name') or distro.get('ecosystem') or '-')}",
        f"- 运行内核：{inline_code(kernel.get('kernel_release') or kernel.get('version') or '-')}",
        f"- 系统包数量：{_server_summary_value(server, 'package_count')}",
        f"- 已确认服务器风险：{_server_summary_value(server, 'confirmed_count')}",
        f"- 维护建议：{_server_summary_value(server, 'maintenance_count')}",
        f"- 对外监听端口：{_server_summary_value(server, 'public_port_count')}",
        f"- 运行服务：{_server_summary_value(server, 'service_count')}",
        f"- 安全更新线索：{_server_summary_value(server, 'native_security_update_count')}",
        "",
        "### 已确认风险",
        "",
    ]

    issues = analysis.get("server_issues") or []
    if issues:
        lines.extend(["| 包 | 当前版本 | 证据 | 修复版本 |", "| --- | --- | --- | --- |"])
        for item in issues:
            package = item.get("package") or item.get("name") or "服务器软件"
            source = item.get("source_package") or ""
            source_text = f"源包 {source}；" if source else ""
            ids = security_ids_markdown(item)
            evidence = (
                source_text
                + (
                    item.get("summary")
                    or item.get("advisory_summary")
                    or "命中发行版包坐标确认的已知漏洞。"
                )
            )
            if ids != "-":
                evidence = f"{evidence} {ids}"
            lines.append(
                "| "
                + " | ".join(
                    [
                        cell(package),
                        cell(item.get("version") or "-"),
                        cell(evidence),
                        cell(_server_fixed_versions(item)),
                    ]
                )
                + " |"
            )
    else:
        lines.append("没有检测到证据闭环的服务器风险。")

    maintenance = analysis.get("server_maintenance") or []
    priority = [
        item
        for item in maintenance
        if item.get("severity") in {"critical", "high", "medium"}
    ]
    lines.extend(["", "### 建议优先处理", ""])
    if priority:
        for item in priority:
            lines.append(
                f"- **{cell(item.get('title') or '维护建议')}**："
                f"{cell(item.get('recommendation') or item.get('summary') or '-')}"
            )
    else:
        lines.append("没有需要从维护建议中单独提前处理的项目。")

    native_updates = [
        item for item in maintenance if item.get("category") == "native_security_update"
    ]
    lines.extend(["", "### 安全更新线索", ""])
    if native_updates:
        for item in native_updates:
            lines.append(
                f"- **{cell(item.get('title') or '系统安全更新')}**："
                f"{cell(item.get('summary') or item.get('recommendation') or '-')}"
            )
    else:
        lines.append("没有采集到明确的包管理器安全更新线索。")

    lines.extend(["", "### 暴露服务和监听端口", ""])
    ports = analysis.get("server_ports") or server.get("ports") or []
    public_ports = [port for port in ports if port.get("public")]
    if public_ports:
        lines.extend(["| 地址 | 端口 | 进程 |", "| --- | --- | --- |"])
        for port in public_ports:
            lines.append(
                f"| {cell(port.get('address') or '-')} | "
                f"{cell(port.get('port') or '-')} | "
                f"{cell(port.get('process') or '-')} |"
            )
    else:
        lines.append("没有采集到公网监听端口。")

    hardening = [
        item for item in maintenance if item.get("category") != "native_security_update"
    ]
    lines.extend(["", "### SSH / 防火墙 / 系统加固建议", ""])
    if hardening:
        for item in hardening:
            lines.append(
                f"- **{cell(item.get('title') or '系统加固建议')}**："
                f"{cell(item.get('summary') or item.get('recommendation') or '-')}"
            )
    else:
        lines.append("没有采集到需要单独提示的 SSH、防火墙或系统加固建议。")

    errors = _server_section_errors(analysis)
    lines.extend(["", "### 覆盖说明和采集失败项", ""])
    if errors:
        for error in errors:
            lines.append(
                f"- {cell(error.get('message') or error.get('code') or '服务器扫描覆盖不足')}"
            )
    else:
        lines.append("服务器采集和漏洞数据源没有返回需要单独说明的错误。")

    return "\n".join(lines)


def is_low_evidence_server_item(item):
    """判断服务器弱证据线索是否不应提升为人工 finding。

    低证据服务器线索不进入人工 finding，因为服务器扫描是可选能力，
    不能把已确认项目风险和推断出的主机维护信号混在一起。
    """
    if not isinstance(item, dict):
        return False

    server_fields = [
        item.get("source"),
        item.get("scope"),
        item.get("origin"),
        item.get("domain"),
        item.get("category"),
        item.get("kind"),
        item.get("type"),
        item.get("scanner"),
    ]
    server_text = " ".join(text(value).lower() for value in server_fields)
    serverish = any(marker in server_text for marker in ("server", "linux", "服务器"))

    evidence_fields = [
        item.get("kind"),
        item.get("type"),
        item.get("evidence_level"),
        item.get("confidence"),
        item.get("match_status"),
        item.get("reason"),
        item.get("why_manual"),
        item.get("evidence"),
    ]
    evidence_text = " ".join(text(value).lower() for value in evidence_fields)
    low_markers = (
        "low_evidence",
        "low evidence",
        "low-confidence",
        "low confidence",
        "weak",
        "inferred",
        "unconfirmed",
        "cpe_only",
        "cpe-only",
        "service_version",
        "service version",
        "banner",
        "docker_tag_guess",
        "docker tag guess",
        "低证据",
        "推断",
        "服务版本",
        "docker 模糊",
    )
    return serverish and (
        item.get("low_evidence") is True
        or item.get("confirmed") is False
        or any(marker in evidence_text for marker in low_markers)
    )


def render_manual_items(analysis):
    items = [
        item
        for item in (analysis.get("red") or []) + (analysis.get("yellow") or [])
        if not is_low_evidence_server_item(item)
    ]
    if not items:
        return "没有需要额外人工确认的事项。\n"

    lines = []
    for index, item in enumerate(items, 1):
        lines.append(f"### {index}. {markdown_text(item.get('name')) or '待确认事项'}")
        if item.get("severity"):
            lines.append(f"- 影响程度：{severity_label(item.get('severity'))}")
        if item.get("path") or item.get("file"):
            lines.append(f"- 位置：{inline_code(item.get('path') or item.get('file'))}")
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
            lines.append(f"- 为什么要关注：{markdown_text(why)}")
        if risk:
            lines.append(f"- 可能影响：{markdown_text(risk)}")
        if action:
            lines.append(f"- 建议动作：{markdown_text(action)}")
        lines.append("")
    return "\n".join(lines)


def render_errors(analysis):
    errors = analysis.get("errors") or []
    if not errors:
        return "没有记录到扫描错误。\n"
    lines = []
    for item in errors:
        step = markdown_text(item.get("step")) or "unknown"
        message = markdown_text(item.get("message"))
        lines.append(
            f"- [{step}] {message}"
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
            lines.append(f"- {markdown_text(item)}")
    else:
        lines.append(
            "- 阅读报告后再决定是否修复；修复前需要明确确认修复范围和升级策略。"
        )
    if dependency_fixes:
        lines.append("- 依赖修复后必须重新运行扫描，确认风险项是否真正消失。")
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
    # 模板占位符是渲染器契约，和 report.md 共享；
    # 新增占位符时这里和模板必须同步。
    return (
        tpl.substitute(
            project_name=text(project.get("name")) or "-",
            project_path=text(project.get("path")) or "-",
            generated_at=text(analysis.get("generated_at")) or "-",
            scan_seconds=text(analysis.get("scan_seconds")) or "-",
            summary=render_summary(analysis),
            server_environment=render_server_environment(analysis),
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
        description="根据 analysis JSON 渲染 Markdown 安全报告",
    )
    parser.add_argument("analysis_json")
    parser.add_argument("output_markdown", nargs="?")
    return parser.parse_args(argv)


def main():
    args = parse_args(sys.argv[1:])

    src = args.analysis_json
    log_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(src))), "logs"
    )
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
