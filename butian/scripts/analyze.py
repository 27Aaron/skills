#!/usr/bin/env python3
"""Build deterministic analysis JSON from scan.py output.

Usage:
    python3 scripts/analyze.py .butian/<timestamp>/assets/scan.json
    python3 scripts/analyze.py scan.json output-analysis.json

The agent may still review and refine business-facing wording after this
script runs, but the required schema, risk counters, and issue lists should
come from this deterministic baseline.
"""

import argparse
import json
import os
import re
import sys

try:
    from .scan import run_dir_from_output_file
except ImportError:
    from scan import run_dir_from_output_file  # pyright: ignore[reportMissingImports]

SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

SEVERITY_LABELS = {
    "critical": "紧急",
    "high": "高风险",
    "medium": "中风险",
    "low": "低风险",
}

SECRET_TYPE_LABELS = {
    "aws_access_key": "AWS 访问密钥",
    "private_key": "私钥",
    "slack_token": "Slack Token",
    "github_token": "GitHub Token",
    "openai_key": "OpenAI API Key",
    "generic_password": "疑似密码",
    "generic_api_key": "疑似 API Key",
}

SENSITIVE_TYPE_LABELS = {
    "env_file": "环境变量文件",
    "private_key": "私钥或证书文件",
    "database": "本地数据库或转储文件",
    "log": "日志文件",
    "credentials": "凭证文件",
    "ssh_key": "SSH 私钥",
}
HYGIENE_ONLY_NOTICE = (
    "当前项目没有发现补天支持的依赖文件，暂不支持依赖漏洞扫描；"
    "本次只做仓库卫生扫描，检查硬编码密钥、敏感文件跟踪和 .gitignore 风险。"
)


def normalize_severity(value):
    value = str(value or "info").lower()
    return value if value in SEVERITY_ORDER else "info"


def severity_rank(item):
    return SEVERITY_ORDER.get(normalize_severity(item.get("severity")), 0)


def to_list(value):
    if not value:
        return []
    if isinstance(value, list):
        return [x for x in value if x]
    return [value]


def default_output_path(scan_path):
    run_dir = run_dir_from_output_file(scan_path)
    assets_dir = os.path.join(run_dir, "assets")
    os.makedirs(assets_dir, exist_ok=True)
    return os.path.join(assets_dir, "analysis.json")


def clean_advisory_summary(summary):
    text = re.sub(r"\s+", " ", str(summary or "")).strip()
    return re.sub(r"^[^:：]{1,80}[:：]\s*", "", text)


def advisory_issue_phrase(summary):
    text = clean_advisory_summary(summary)
    lower = text.lower()
    if not text:
        return "已有确认公开漏洞，需要结合公告评估影响范围"
    if "large numeric range" in lower and "max" in lower:
        return "大范围数字展开可能绕过 max 限制，带来拒绝服务风险"
    if "host confusion" in lower and "percent-encoded" in lower:
        return "对百分号编码的 authority 分隔符处理不当，可能造成主机解析混淆"
    if "path traversal" in lower and "percent-encoded" in lower:
        return "对百分号编码的点号路径处理不当，可能造成路径穿越"
    if "server-side request forgery" in lower:
        if "websocket" in lower:
            return "WebSocket upgrade 场景存在服务端请求伪造风险"
        return "存在服务端请求伪造风险"
    if "middleware" in lower and "proxy bypass" in lower:
        if "pages router" in lower and "i18n" in lower:
            return "Pages Router 使用 i18n 时存在中间件/代理绕过风险"
        if "segment-prefetch" in lower:
            if "incomplete fix" in lower or "follow-up" in lower:
                return "segment-prefetch 路由相关绕过修复不完整，仍可能绕过中间件/代理"
            return "App Router 的 segment-prefetch 路由可能绕过中间件/代理"
        if "dynamic route" in lower:
            return "动态路由参数注入场景可能绕过中间件/代理"
        return "存在中间件/代理绕过风险"
    if "connection exhaustion" in lower:
        return "使用 Cache Components 时可能因连接耗尽造成拒绝服务"
    if "image optimization api" in lower and "denial of service" in lower:
        return "Image Optimization API 存在拒绝服务风险"
    if "denial of service" in lower or re.search(r"\bdos\b", lower):
        return "存在拒绝服务风险"
    if "cache" in lower:
        return "存在缓存可信度风险"
    return f"公告摘要：{text}"


def vulnerability_summary(item):
    package = item.get("package") or item.get("name") or "该依赖"
    version = item.get("version")
    fixed = to_list(item.get("fixed_versions"))
    fixed_text = (
        f"建议升级到 {'、'.join(map(str, fixed))} 或更高版本。"
        if fixed
        else "建议确认官方修复版本后再安排升级。"
    )
    version_text = f" {version}" if version else ""
    return f"{package}{version_text} {advisory_issue_phrase(item.get('advisory_summary') or item.get('summary'))}；{fixed_text}"


def sort_items(items):
    return sorted(
        items,
        key=lambda item: (
            -severity_rank(item),
            str(item.get("package") or item.get("name") or ""),
            str(item.get("version") or ""),
        ),
    )


def build_top_issues(scan):
    issues = []
    for vuln in scan.get("vulnerabilities") or []:
        item = dict(vuln)
        item["severity"] = normalize_severity(item.get("severity"))
        item["tier"] = (
            "red"
            if item["severity"] in {"critical", "high"}
            else "yellow"
            if item["severity"] == "medium"
            else "green"
        )
        item["name"] = item.get("package") or item.get("name") or "依赖漏洞"
        item["advisory_summary"] = item.get("summary") or ""
        item["summary"] = vulnerability_summary(item)
        issues.append(item)

    ranked = sort_items(issues)
    for index, item in enumerate(ranked, 1):
        item["rank"] = index
    return ranked


def build_hygiene_items(scan):
    hygiene = scan.get("hygiene") or {}
    red = []
    yellow = []
    green = []

    for secret in hygiene.get("tracked_secrets") or []:
        secret_type = secret.get("type") or "secret"
        confidence = secret.get("confidence") or "medium"
        severity = "high" if confidence == "high" else "medium"
        location = secret.get("file") or "-"
        if secret.get("line"):
            location = f"{location}:{secret['line']}"
        label = SECRET_TYPE_LABELS.get(secret_type, secret_type)
        yellow.append(
            {
                "name": f"疑似硬编码凭证：{location}",
                "type": "secret_exposure",
                "severity": severity,
                "path": secret.get("file") or "",
                "file": secret.get("file") or "",
                "line": secret.get("line"),
                "secret_type": secret_type,
                "confidence": confidence,
                "preview": secret.get("preview"),
                "why_manual": f"扫描在 {location} 发现{label}特征，需要研发确认是否是真实可用凭证。",
                "risk": "如果该凭证真实可用，泄露后可能造成未授权访问或数据暴露。",
                "disposal": "先确认是否真实有效；如有效，先轮换或撤销，再移除代码中的明文。",
            }
        )

    for sensitive in hygiene.get("sensitive_tracked") or []:
        file_type = sensitive.get("type") or "sensitive"
        severity = (
            "high"
            if file_type in {"env_file", "private_key", "credentials", "ssh_key"}
            else "medium"
        )
        label = SENSITIVE_TYPE_LABELS.get(file_type, file_type)
        target = red if severity == "high" else yellow
        target.append(
            {
                "name": f"敏感文件已被 git 跟踪：{sensitive.get('file') or '-'}",
                "type": "sensitive_file_tracked",
                "severity": severity,
                "path": sensitive.get("file") or "",
                "file": sensitive.get("file") or "",
                "content_profile": label,
                "why_keep": f"{label}不应默认进入代码仓库，需要确认是否包含真实凭证、数据或内部日志。",
                "risk": "如果文件包含真实敏感内容，仓库访问者可能直接拿到凭证或业务数据。",
                "indirect_release": "先确认文件内容；如包含敏感信息，先轮换相关凭证，再从当前跟踪中移除，历史清理需单独确认。",
            }
        )

    missing_rules = hygiene.get("gitignore_missing") or []
    if missing_rules:
        yellow.append(
            {
                "name": ".gitignore 缺少敏感文件保护规则",
                "type": "gitignore_missing",
                "severity": "low",
                "path": ".gitignore",
                "why_manual": "缺少忽略规则不代表已经泄露，但会提高后续误提交敏感文件的概率。",
                "risk": "未来新增 .env、证书、数据库或日志文件时，可能被意外提交。",
                "disposal": f"建议补充这些规则：{'、'.join(map(str, missing_rules))}。",
            }
        )
        green.append(
            {
                "name": "补充 .gitignore 敏感文件规则",
                "type": "gitignore_fix",
                "severity": "low",
                "summary": f"补充 {'、'.join(map(str, missing_rules))}，降低后续误提交概率。",
                "fix_config": {
                    "type": "gitignore",
                    "patterns": missing_rules,
                },
            }
        )

    return red, yellow, green


def build_dependency_fix_items(top_issues):
    green = []
    seen = set()
    for issue in top_issues:
        package = issue.get("package") or issue.get("name")
        fixed = to_list(issue.get("fixed_versions"))
        if not package or not fixed:
            continue
        key = (issue.get("ecosystem"), package, tuple(map(str, fixed)))
        if key in seen:
            continue
        seen.add(key)
        green.append(
            {
                "name": f"升级 {package}",
                "type": "dependency_upgrade",
                "severity": issue.get("severity", "info"),
                "package": package,
                "version": issue.get("version"),
                "ecosystem": issue.get("ecosystem"),
                "summary": f"{package} 有明确修复版本，建议升级到 {'、'.join(map(str, fixed))} 或更高版本后运行测试。",
                "fix_config": {
                    "type": "upgrade",
                    "ecosystem": issue.get("ecosystem"),
                    "package": package,
                    "fixed_versions": fixed,
                },
            }
        )
    return green


def count_risks(*groups):
    summary = {key: 0 for key in SEVERITY_ORDER}
    for group in groups:
        for item in group:
            severity = normalize_severity(item.get("severity"))
            summary[severity] += 1
    return summary


def build_summary(scan, analysis):
    project = scan.get("project") or {}
    hygiene = scan.get("hygiene") or {}
    scan_config = scan.get("scan_config") or {}
    hygiene_only = scan_config.get("scan_mode") == "hygiene_only"
    risk_summary = analysis["risk_summary"]
    critical_high = risk_summary["critical"] + risk_summary["high"]
    vuln_count = len(analysis["top_issues"])
    secret_count = len(hygiene.get("tracked_secrets") or [])
    sensitive_count = len(hygiene.get("sensitive_tracked") or [])
    missing_count = len(hygiene.get("gitignore_missing") or [])
    outdated_count = len(scan.get("outdated") or [])
    errors = scan.get("errors") or []

    if hygiene_only:
        tldr = "本次没有发现补天支持的依赖文件，因此未执行依赖漏洞扫描；报告结论仅覆盖仓库卫生风险。"
    elif critical_high and vuln_count:
        tldr = "发现需要优先安排的依赖安全风险，建议先处理紧急和高风险漏洞，再确认仓库中的敏感信息迹象。"
    elif secret_count or sensitive_count:
        tldr = "未发现高优先级依赖漏洞，但仓库里有凭证或敏感文件迹象，需要研发确认。"
    elif vuln_count:
        tldr = "发现已确认依赖漏洞，当前以中风险或低风险为主，建议按维护窗口分批升级。"
    elif errors:
        tldr = (
            "本次扫描暂未确认安全风险，但有部分检查失败，结论需要复核后再作为发布依据。"
        )
    else:
        tldr = "本次扫描没有发现明确安全风险，可作为当前项目状态记录。"

    if hygiene_only:
        detail = (
            f"本次检查覆盖项目 {project.get('name') or '-'}。{HYGIENE_ONLY_NOTICE}"
            f"仓库卫生方面，发现疑似硬编码凭证 {secret_count} 处、"
            f"被 git 跟踪的敏感文件 {sensitive_count} 个、建议补充的 .gitignore 规则 {missing_count} 条。"
        )
    else:
        detail = (
            f"本次检查覆盖项目 {project.get('name') or '-'}，识别到 "
            f"{project.get('total_packages', scan.get('package_count', 0)) or 0} 个依赖包，"
            f"命中 {vuln_count} 个已确认漏洞。仓库卫生方面，发现疑似硬编码凭证 {secret_count} 处、"
            f"被 git 跟踪的敏感文件 {sensitive_count} 个、建议补充的 .gitignore 规则 {missing_count} 条。"
            f"过期依赖 {outdated_count} 个仅作为维护信号，不等同于漏洞。"
        )

    priority = []
    if hygiene_only:
        priority.append(HYGIENE_ONLY_NOTICE)
    elif critical_high:
        priority.append(
            f"优先处理 {critical_high} 个紧急/高风险项，先升级有明确修复版本的依赖，再运行测试或构建。"
        )
    elif vuln_count:
        priority.append(
            f"按影响程度处理 {vuln_count} 个已确认依赖漏洞，优先选择兼容范围内的修复版本。"
        )
    if secret_count or sensitive_count:
        priority.append(
            "安排研发确认凭证和敏感文件是否真实有效；如有效，先轮换或撤销，再清理代码中的明文。"
        )
    if missing_count:
        priority.append("补充 .gitignore 敏感文件规则，降低后续误提交概率。")
    if outdated_count:
        priority.append("过期依赖按维护计划处理，不要在没有漏洞证据时当作安全事故。")
    if errors:
        priority.append(
            "复查扫描错误，补齐失败的官方漏洞源、包管理器或工具链检查后再确认最终结论。"
        )
    if not priority:
        priority.append(
            "当前没有需要立即处理的明确风险，建议保留报告作为本次检查记录。"
        )

    return {
        "tldr": tldr,
        "detail": detail,
        "priority": priority,
        "tier_stats": {
            "red": f"{len(analysis['red'])} 项优先处理",
            "yellow": f"{len(analysis['yellow'])} 项需要人工确认",
            "green": f"{len(analysis['green'])} 项可作为修复计划",
        },
    }


def build_analysis(scan, source_scan_file=None, output_file=None):
    top_issues = build_top_issues(scan)
    red, yellow, hygiene_green = build_hygiene_items(scan)
    dependency_green = build_dependency_fix_items(top_issues)
    green = dependency_green + hygiene_green

    analysis = {
        "generated_at": scan.get("generated_at"),
        "scan_seconds": scan.get("scan_seconds"),
        "project": scan.get("project") or {},
        "scan_config": scan.get("scan_config") or {},
        "source_scan_file": source_scan_file,
        "output_file": output_file,
        "risk_summary": count_risks(top_issues, red, yellow),
        "hygiene": scan.get("hygiene") or {},
        "outdated": scan.get("outdated") or [],
        "top_issues": top_issues,
        "red": sort_items(red),
        "yellow": sort_items(yellow),
        "green": sort_items(green),
        "errors": scan.get("errors") or [],
        "package_count": scan.get(
            "package_count", (scan.get("project") or {}).get("total_packages", 0)
        ),
        "vulnerability_count": len(top_issues),
        "outdated_count": len(scan.get("outdated") or []),
        "package_sources": scan.get("package_sources") or [],
        "butian_workspace": scan.get("butian_workspace") or {},
    }
    analysis["summary"] = build_summary(scan, analysis)
    return analysis


def write_json(path, data):
    output_dir = os.path.dirname(os.path.abspath(path))
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Build deterministic analysis JSON from scan.py output",
    )
    parser.add_argument("scan_json")
    parser.add_argument("output_json", nargs="?")
    return parser.parse_args(argv)


def main():
    args = parse_args(sys.argv[1:])

    scan_path = args.scan_json
    output_path = args.output_json or default_output_path(scan_path)

    with open(scan_path, "r", encoding="utf-8") as handle:
        scan = json.load(handle)

    analysis = build_analysis(
        scan,
        source_scan_file=os.path.abspath(scan_path),
        output_file=output_path,
    )
    write_json(output_path, analysis)
    print(f"analysis 已生成: {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
