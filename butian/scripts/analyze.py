#!/usr/bin/env python3
"""从 scan.py 输出构建确定性的 analysis JSON。

Usage:
    python3 scripts/analyze.py .butian/<timestamp>/assets/scan.json
    python3 scripts/analyze.py scan.json output-analysis.json

脚本运行后，后续流程仍可复核并润色面向业务的文案；
但必需 schema、风险计数和问题列表应来自这个确定性基线。
"""

import argparse
import json
import logging
import os
import re
import sys

ANALYSIS_SCHEMA_VERSION = "1.0.0"

logger = logging.getLogger("butian.scripts.analyze")

try:
    from .labels import SECRET_TYPE_LABELS, SENSITIVE_TYPE_LABELS
    from .scan import HYGIENE_ONLY_NOTICE, run_dir_from_output_file, setup_logging
except ImportError:
    from labels import (  # pyright: ignore[reportMissingImports]
        SECRET_TYPE_LABELS,
        SENSITIVE_TYPE_LABELS,
    )
    from scan import (  # pyright: ignore[reportMissingImports]
        HYGIENE_ONLY_NOTICE,
        run_dir_from_output_file,
        setup_logging,
    )

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

DEPENDENCY_UPGRADE_SCOPE_NOTE = "该建议只覆盖包管理器可解析的普通升级；修复后必须复扫。"

TRANSITIVE_RESIDUAL_GUIDANCE = (
    "如果复扫仍出现同名旧版本，通常是间接依赖被父包锁定；需要升级父依赖、等待上游修复，"
    "或在用户确认后把锁住旧子依赖的父依赖升级到 latest。"
)

STRUCTURED_HYGIENE_GROUPS = (
    "workflow_checks",
    "repository_checks",
    "iac_checks",
)


def normalize_severity(value):
    value = str(value or "info").lower()
    return value if value in SEVERITY_ORDER else "info"


def severity_rank(item):
    return SEVERITY_ORDER.get(normalize_severity(item.get("severity")), 0)


def number_or_zero(value):
    if isinstance(value, bool) or value is None:
        return 0.0
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return 0.0


def to_list(value):
    if not value:
        return []
    if isinstance(value, list):
        return [x for x in value if x]
    return [value]


def unique_values(values):
    result = []
    for value in values or []:
        if value is None:
            continue
        text_value = str(value)
        if text_value and text_value not in result:
            result.append(text_value)
    return result


def security_ids_for_issue(item):
    ids = []

    def push(value):
        if isinstance(value, list):
            for entry in value:
                push(entry)
            return
        if value is None:
            return
        for part in re.split(r"[,，\s]+", str(value)):
            part = part.strip()
            if part and part not in ids:
                ids.append(part)

    for field in (
        "cve_id",
        "cve_ids",
        "advisory_id",
        "advisory_ids",
        "aliases",
        "advisory_aliases",
    ):
        push(item.get(field))
    return ids


def canonical_security_id(item):
    ids = security_ids_for_issue(item)
    for pattern in (
        r"^CVE-\d{4}-\d+",
        r"^GHSA-",
        r"^GO-\d{4}-\d+",
        r"^PYSEC-",
        r"^RUSTSEC-",
    ):
        for security_id in ids:
            if re.match(pattern, security_id, re.IGNORECASE):
                return security_id.upper()
    return ids[0].upper() if ids else ""


def version_key(value):
    parts = re.findall(r"\d+", str(value or ""))
    return tuple(int(part) for part in parts)


def highest_version(values):
    versions = unique_values(values)
    if not versions:
        return ""
    return sorted(versions, key=version_key)[-1]


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
    summary = (
        f"{package}{version_text} "
        f"{advisory_issue_phrase(item.get('advisory_summary') or item.get('summary'))}；"
        f"{fixed_text}"
    )
    context = item.get("dependency_context") or {}
    if context.get("kind") == "nested_locked":
        parents = unique_values(
            [entry.get("parent") for entry in context.get("locations") or []]
        )
        parent_text = "、".join(parents[:3]) if parents else "上游父依赖"
        if len(parents) > 3:
            parent_text += f" 等 {len(parents)} 个父依赖"
        summary += f" 检测到该旧版本属于被父依赖锁定的嵌套副本，父依赖：{parent_text}。"
        top_versions = unique_values(context.get("top_level_versions") or [])
        if top_versions:
            summary += f" 顶层 {package} 当前版本为 {'、'.join(top_versions)}。"
        # 展示 semver 范围分析。
        target_ver = str(item.get("target_version") or "")
        for loc in (context.get("locations") or [])[:1]:
            parent_range = loc.get("parent_range")
            if parent_range and target_ver:
                in_range = _semver_satisfies(target_ver, parent_range)
                hint = (
                    "在范围内，只需重新解析 lockfile"
                    if in_range
                    else "不在范围内，需升级父依赖"
                )
                summary += f' {parent_text} 声明 {package}: "{parent_range}"，修复版本 {target_ver} {hint}。'
            elif parent_range:
                summary += f' {parent_text} 声明 {package}: "{parent_range}"。'
    return summary


def sort_items(items):
    return sorted(
        items,
        key=lambda item: (
            -severity_rank(item),
            -item_max_epss_percentile(item),
            -item_best_cvss_score(item),
            str(item.get("package") or item.get("name") or ""),
            str(item.get("version") or ""),
        ),
    )


def item_max_epss_percentile(item):
    values = []
    for enrichment in item.get("cve_enrichments") or []:
        if isinstance(enrichment, dict):
            values.append(number_or_zero(enrichment.get("epssPercentile")))
    return max(values or [0.0])


def item_best_cvss_score(item):
    scores = [number_or_zero(item.get("cvss"))]
    for enrichment in item.get("cve_enrichments") or []:
        if not isinstance(enrichment, dict):
            continue
        scores.append(number_or_zero(enrichment.get("bestCvssScore")))
        for metric in enrichment.get("cvssMetrics") or []:
            if isinstance(metric, dict):
                scores.append(number_or_zero(metric.get("baseScore")))
    return max(scores or [0.0])


def merge_list_field(target, source, field):
    merged = unique_values(to_list(target.get(field)) + to_list(source.get(field)))
    if merged:
        target[field] = merged


def merge_duplicate_issue(target, source):
    if severity_rank(source) > severity_rank(target):
        target["severity"] = source.get("severity")
    if item_best_cvss_score(source) > item_best_cvss_score(target):
        target["cvss"] = source.get("cvss")

    for field in (
        "fixed_versions",
        "fix_versions",
        "patched_versions",
        "aliases",
        "advisory_aliases",
        "advisory_ids",
        "cve_ids",
        "risk_signals",
        "enrichment_sources",
    ):
        merge_list_field(target, source, field)

    advisory_ids = unique_values(
        to_list(target.get("advisory_ids"))
        + to_list(target.get("advisory_id"))
        + to_list(source.get("advisory_id"))
    )
    if advisory_ids:
        target["advisory_ids"] = advisory_ids

    aliases = unique_values(
        to_list(target.get("aliases"))
        + to_list(source.get("aliases"))
        + security_ids_for_issue(source)
    )
    if aliases:
        target["aliases"] = aliases

    if not target.get("cve_id") and source.get("cve_id"):
        target["cve_id"] = source.get("cve_id")
    if not target.get("advisory_id") and source.get("advisory_id"):
        target["advisory_id"] = source.get("advisory_id")

    enrichments = []
    seen = set()
    for enrichment in to_list(target.get("cve_enrichments")) + to_list(
        source.get("cve_enrichments")
    ):
        if not isinstance(enrichment, dict):
            continue
        key = (
            enrichment.get("cveId")
            or enrichment.get("id")
            or json.dumps(enrichment, sort_keys=True, ensure_ascii=False)
        )
        if key in seen:
            continue
        seen.add(key)
        enrichments.append(enrichment)
    if enrichments:
        target["cve_enrichments"] = enrichments
    return target


def dedupe_vulnerabilities(vulnerabilities):
    merged = []
    by_key = {}
    for vuln in vulnerabilities or []:
        item = dict(vuln)
        key = (
            str(item.get("ecosystem") or "").lower(),
            str(item.get("package") or item.get("name") or "").lower(),
            str(item.get("version") or ""),
            canonical_security_id(item),
        )
        if key[-1] and key in by_key:
            merge_duplicate_issue(by_key[key], item)
            continue
        by_key[key] = item
        merged.append(item)
    return merged


def _parse_version(version_str):
    """将 "1.2.3" 解析为 (1, 2, 3)，并去掉预发布标签。"""
    parts = version_str.lstrip("v").split(".")
    result = []
    for part in parts:
        num = ""
        for ch in part:
            if ch.isdigit():
                num += ch
            else:
                break
        result.append(int(num) if num else 0)
    while len(result) < 3:
        result.append(0)
    return tuple(result[:3])


def _semver_satisfies(version, range_str):
    """检查 *version* 是否满足 npm 风格 semver 范围 *range_str*。

    覆盖 package.json 依赖声明中最常见的模式：
    ^、~、>=、>、<=、<、精确版本、*、x 范围和 || 并集。
    """
    range_str = range_str.strip()
    if not range_str or range_str == "*" or range_str == "latest":
        return True

    # 并集（||）：任一子范围命中即可。
    if "||" in range_str:
        return any(
            _semver_satisfies(version, part.strip()) for part in range_str.split("||")
        )

    # 空格分隔的交集，例如 ">=1.0.0 <2.0.0"。
    tokens = range_str.split()
    if len(tokens) > 1:
        return all(_semver_satisfies(version, t) for t in tokens)

    ver = _parse_version(version)

    # caret 范围：^X.Y.Z。
    if range_str.startswith("^"):
        base = _parse_version(range_str[1:])
        if base[0] > 0:
            return ver >= base and ver[0] == base[0]
        if base[1] > 0:
            return ver >= base and ver[0] == 0 and ver[1] == base[1]
        return ver == base

    # tilde 范围：~X.Y.Z。
    if range_str.startswith("~"):
        base = _parse_version(range_str[1:])
        return ver >= base and ver[0] == base[0] and ver[1] == base[1]

    # 比较操作符：>=、>、<=、<。
    if range_str.startswith(">="):
        return ver >= _parse_version(range_str[2:])
    if range_str.startswith(">"):
        return ver > _parse_version(range_str[1:])
    if range_str.startswith("<="):
        return ver <= _parse_version(range_str[2:])
    if range_str.startswith("<"):
        return ver < _parse_version(range_str[1:])

    # x 范围："1.x"、"1.2.x"。
    cleaned = range_str.lower().replace("x", "0")
    if cleaned != range_str.lower():
        base = _parse_version(cleaned)
        # "1.x" 类似 ^1.0.0，"1.2.x" 类似 ~1.2.0。
        parts = range_str.lower().split(".")
        if len(parts) == 2:
            return ver >= base and ver[0] == base[0]
        return ver >= base and ver[0] == base[0] and ver[1] == base[1]

    # 精确版本。
    return ver == _parse_version(range_str)


def _parent_dep_range(lock_data, parent_lock_path, child_name, project_path=None):
    """读取父依赖为 *child_name* 声明的 semver 范围。

    先检查 lockfile 的 ``packages`` 条目（``requires`` 优先于
    ``dependencies``），再兜底到 ``node_modules/<parent>/package.json``。
    返回范围字符串（如 "^8.4.0"）或 None。
    """
    packages = lock_data.get("packages") or {}
    parent_meta = packages.get(parent_lock_path) or {}

    # lockfile v2/v3 的 requires 字段（声明范围）。
    for field in ("requires", "dependencies"):
        deps = parent_meta.get(field)
        if isinstance(deps, dict):
            dep_range = deps.get(child_name)
            if isinstance(dep_range, str):
                return dep_range

    # 兜底：从 node_modules 读取。
    if parent_lock_path:
        pkg_json_path = parent_lock_path.replace("/", os.sep)
        pkg_json_path = os.path.join(pkg_json_path, "package.json")
        if project_path:
            pkg_json_path = os.path.join(project_path, pkg_json_path)
        try:
            with open(pkg_json_path, "r", encoding="utf-8") as f:
                pkg_json = json.load(f)
            for field in ("dependencies", "devDependencies", "peerDependencies"):
                deps = pkg_json.get(field)
                if isinstance(deps, dict):
                    dep_range = deps.get(child_name)
                    if isinstance(dep_range, str):
                        return dep_range
        except (OSError, json.JSONDecodeError):
            pass

    return None


def _npm_package_name_at(parts, index):
    if index >= len(parts):
        return None
    name = parts[index]
    if name.startswith("@") and index + 1 < len(parts):
        return f"{name}/{parts[index + 1]}"
    return name


def _npm_names_from_lock_path(path):
    parts = [part for part in str(path or "").split("/") if part]
    names = []
    index = 0
    while index < len(parts):
        if parts[index] != "node_modules":
            index += 1
            continue
        name = _npm_package_name_at(parts, index + 1)
        if name:
            names.append(name)
            index += 3 if name.startswith("@") else 2
        else:
            index += 1
    return names


def _npm_lock_path_for_names(names):
    """构造类似 'node_modules/next/node_modules/postcss' 的 lockfile 路径。"""
    path = ""
    for name in names:
        path = f"{path}/node_modules/{name}" if path else f"node_modules/{name}"
    return path


def _is_top_level_npm_lock_path(path):
    return len(_npm_names_from_lock_path(path)) == 1


def dependency_context_for_issue(scan, issue):
    """描述 npm 漏洞是否来自被锁定的嵌套副本。"""
    if issue.get("ecosystem") != "npm":
        return None
    package = issue.get("package") or issue.get("name")
    version = str(issue.get("version") or "")
    project_path = (scan.get("project") or {}).get("path")
    if not package or not version or not project_path:
        return None
    lock_path = os.path.join(project_path, "package-lock.json")
    if not os.path.isfile(lock_path):
        return None
    try:
        with open(lock_path, "r", encoding="utf-8") as handle:
            lock_data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None

    locations = []
    top_level_versions = []
    for key, meta in (lock_data.get("packages") or {}).items():
        names = _npm_names_from_lock_path(key)
        if not names or names[-1] != package:
            continue
        found_version = str((meta or {}).get("version") or "")
        if _is_top_level_npm_lock_path(key) and found_version:
            top_level_versions.append(found_version)
        if found_version != version or len(names) < 2:
            continue
        # 读取父依赖为该子依赖声明的 semver 范围。
        parent_lock_path = _npm_lock_path_for_names(names[:-1])
        parent_range = _parent_dep_range(
            lock_data, parent_lock_path, package, project_path=project_path
        )
        locations.append(
            {
                "path": key,
                "parent": names[-2],
                "parent_lock_path": parent_lock_path,
                "parent_range": parent_range,
                "version": found_version,
                "note": "被父依赖锁定的嵌套副本",
            }
        )
    if not locations:
        return None
    return {
        "kind": "nested_locked",
        "note": "被父依赖锁定的嵌套副本",
        "locations": locations,
        "top_level_versions": unique_values(top_level_versions),
    }


def build_top_issues(scan):
    raw = scan.get("vulnerabilities") or []
    logger.debug("build_top_issues: %d 个原始漏洞记录", len(raw))
    issues = []
    for vuln in dedupe_vulnerabilities(raw):
        item = dict(vuln)
        item["severity"] = normalize_severity(item.get("severity"))
        # 红黄绿分组是报告契约。除非模板、修复计划和文档同步调整，
        # 否则不要改变影响程度路由。
        item["tier"] = (
            "red"
            if item["severity"] in {"critical", "high"}
            else "yellow"
            if item["severity"] == "medium"
            else "green"
        )
        item["name"] = item.get("package") or item.get("name") or "依赖漏洞"
        item["advisory_summary"] = item.get("summary") or ""
        context = dependency_context_for_issue(scan, item)
        if context:
            item["dependency_context"] = context
        item["summary"] = vulnerability_summary(item)
        issues.append(item)

    ranked = sort_items(issues)
    for index, item in enumerate(ranked, 1):
        item["rank"] = index
    logger.info("build_top_issues: 排序后 %d 个风险项", len(ranked))
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
                "code_context": secret.get("code_context") or [],
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
                "why_manual": "补齐忽略规则可以降低后续误提交敏感文件的概率。",
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

    for group_name in STRUCTURED_HYGIENE_GROUPS:
        for finding in hygiene.get(group_name) or []:
            severity = normalize_severity(finding.get("severity"))
            item = {
                "name": finding.get("title") or finding.get("id") or "仓库安检项",
                "type": "local_repository_check",
                "severity": severity,
                "path": finding.get("file") or "",
                "file": finding.get("file") or "",
                "line": finding.get("line"),
                "category": finding.get("category") or group_name,
                "source_id": finding.get("id"),
                "kind": finding.get("kind"),
                "confidence": finding.get("confidence"),
                "evidence": finding.get("evidence"),
                "why_manual": finding.get("detail") or "本地规则发现该项需要人工确认。",
                "risk": finding.get("detail") or "需要结合项目场景确认影响。",
                "disposal": finding.get("recommendation")
                or "请安排负责人确认并按项目策略修正。",
                "source": finding.get("source") or "builtin",
            }
            if finding.get("fix_config"):
                item["fix_config"] = finding["fix_config"]
            if severity in {"critical", "high"}:
                red.append(item)
            elif severity == "medium":
                yellow.append(item)
            else:
                green.append(
                    {
                        **item,
                        "summary": item["disposal"],
                    }
                )

    logger.info(
        "build_hygiene_items: red=%d, yellow=%d, green=%d",
        len(red),
        len(yellow),
        len(green),
    )
    return red, yellow, green


def build_dependency_fix_items(top_issues):
    green = []
    groups = {}
    for issue in top_issues:
        package = issue.get("package") or issue.get("name")
        if not package:
            continue
        key = (issue.get("ecosystem") or "", package)
        groups.setdefault(key, []).append(issue)

    for (ecosystem, package), issues in groups.items():
        fixed_versions = []
        fixed_versions_by_advisory = {}
        advisory_ids = []
        current_versions = []
        missing_fixed = False
        for issue in issues:
            issue_advisory_ids = to_list(
                issue.get("advisory_ids")
                or issue.get("advisory_id")
                or issue.get("cve_id")
                or issue.get("match_summary")
                or "unknown"
            )
            fixed = unique_values(to_list(issue.get("fixed_versions")))
            for advisory_id in issue_advisory_ids:
                if advisory_id not in advisory_ids:
                    advisory_ids.append(advisory_id)
                fixed_versions_by_advisory[advisory_id] = fixed
            if fixed:
                fixed_versions.extend(fixed)
            else:
                missing_fixed = True
            if issue.get("version"):
                current_versions.append(issue.get("version"))

        target_version = highest_version(fixed_versions)
        if not target_version:
            continue
        # Go 版本需要 v 前缀（如 v1.2.3，而不是 1.2.3）；
        # OSV 有时会省略，这里统一规范化，保证下游工具
        # 和报告始终看到正确的 Go 版本格式。
        if ecosystem == "go":
            fixed_versions = [
                v if v.startswith("v") else f"v{v}" for v in fixed_versions
            ]
            for aid, fvs in fixed_versions_by_advisory.items():
                fixed_versions_by_advisory[aid] = [
                    v if v.startswith("v") else f"v{v}" for v in fvs
                ]
            target_version = (
                target_version
                if target_version.startswith("v")
                else f"v{target_version}"
            )
        highest_issue = sort_items(issues)[0]
        summary = (
            f"{package} 命中 {len(issues)} 个风险项，建议升级到 {target_version} "
            f"或更高版本后运行测试。{DEPENDENCY_UPGRADE_SCOPE_NOTE}"
        )
        if missing_fixed:
            summary += " 其中部分公告未给出明确修复版本，需升级后复扫确认。"
        # fix_config 是 fix.py 消费的机器契约；说明文案可以独立润色，
        # 但这些字段必须保持适合自动化消费。
        green.append(
            {
                "name": f"升级 {package}",
                "type": "dependency_upgrade",
                "severity": highest_issue.get("severity", "info"),
                "package": package,
                "version": unique_values(current_versions)[0]
                if current_versions
                else None,
                "ecosystem": ecosystem,
                "summary": summary,
                "fix_config": {
                    "type": "upgrade",
                    "ecosystem": ecosystem,
                    "package": package,
                    "current_versions": unique_values(current_versions),
                    "target_version": target_version,
                    "fixed_versions": unique_values(fixed_versions),
                    "advisory_ids": advisory_ids,
                    "fixed_versions_by_advisory": fixed_versions_by_advisory,
                    "upgrade_scope": "direct_package",
                    "residual_guidance": TRANSITIVE_RESIDUAL_GUIDANCE,
                },
                "dependency_context": highest_issue.get("dependency_context"),
            }
        )
    logger.info("build_dependency_fix_items: %d 个升级建议", len(green))
    return green


def count_risks(*groups):
    summary = {key: 0 for key in SEVERITY_ORDER}
    for group in groups:
        for item in group:
            severity = normalize_severity(item.get("severity"))
            summary[severity] += 1
    return summary


def merge_risk_summaries(*summaries):
    merged = {key: 0 for key in SEVERITY_ORDER}
    for summary in summaries:
        for key in merged:
            merged[key] += int((summary or {}).get(key) or 0)
    return merged


def risk_summary_for_items(items, fallback=None):
    summary = count_risks(items or [])
    known = sum(summary[key] for key in ("critical", "high", "medium", "low"))
    if items and known == 0 and fallback:
        return fallback
    return summary


def is_maintenance_advice(item):
    return item.get("kind") == "maintenance_advice"


def project_dependency_scope(project, scan):
    count = project.get("total_packages", scan.get("package_count", 0)) or 0
    ecosystems = unique_values(project.get("ecosystems") or [])
    if not ecosystems:
        ecosystems = unique_values(
            [
                item.get("ecosystem")
                for item in scan.get("package_sources") or []
                if isinstance(item, dict)
            ]
        )
    ecosystem = "、".join(map(str, ecosystems[:3]))
    if count and ecosystem:
        return f"{count} 个 {ecosystem} 依赖"
    if count:
        return f"{count} 个依赖"
    if ecosystem:
        return f"{ecosystem} 依赖"
    return "项目依赖"


def package_focus_text(issues, limit=4):
    packages = unique_values(
        [item.get("package") or item.get("name") for item in issues or []]
    )
    if not packages:
        return ""
    visible = "、".join(map(str, packages[:limit]))
    if len(packages) > limit:
        visible += f" 等 {len(packages)} 个包"
    return f"，涉及 {visible}"


def summary_hygiene_signal_phrase(
    secret_count, sensitive_count, missing_count, local_check_count
):
    if not (secret_count or sensitive_count or missing_count or local_check_count):
        return "仓库安检未发现凭证或敏感文件问题"
    parts = []
    if secret_count:
        parts.append(f"{secret_count} 处疑似硬编码凭证需要确认")
    if sensitive_count:
        parts.append(f"{sensitive_count} 个被跟踪敏感文件需要确认")
    if missing_count:
        parts.append(f"{missing_count} 条 .gitignore 规则待补充")
    if local_check_count:
        parts.append(f"{local_check_count} 个本地配置/工作流项待确认")
    return "另有 " + "、".join(parts)


def hygiene_detail_sentences(
    secret_count,
    sensitive_count,
    missing_count,
    local_check_count,
    maintenance_advice_count,
):
    parts = []
    if secret_count:
        parts.append(f"{secret_count} 处疑似硬编码凭证")
    if sensitive_count:
        parts.append(f"{sensitive_count} 个被 git 跟踪的敏感文件")
    if missing_count:
        parts.append(f"{missing_count} 条 .gitignore 待补充规则")

    sentences = []
    if parts:
        sentences.append(f"仓库安检发现 {'、'.join(parts)}。")
    else:
        sentences.append(
            "仓库安检未发现疑似硬编码凭证、敏感文件跟踪或 .gitignore 缺失。"
        )
    if local_check_count:
        sentences.append(f"本地配置/工作流待确认 {local_check_count} 个。")
    if maintenance_advice_count:
        sentences.append(f"依赖维护建议 {maintenance_advice_count} 条。")
    return sentences


def is_outdated_skip_error(error):
    step = str((error or {}).get("step") or "").lower()
    message = str((error or {}).get("message") or "")
    return step == "outdated_check" and (
        "跳过" in message or "默认不执行" in message or "allow-project-exec" in message
    )


def is_vulnerability_source_error(error):
    step = str((error or {}).get("step") or "").lower()
    message = str((error or {}).get("message") or "").lower()
    return any(
        token in step or token in message
        for token in (
            "vulnerability",
            "osv",
            "nvd",
            "cisa",
            "kev",
            "epss",
            "漏洞源",
        )
    )


def dependency_upgrade_targets(green_items, limit=3):
    targets = []
    for item in green_items or []:
        if item.get("type") != "dependency_upgrade":
            continue
        package = item.get("package") or item.get("name")
        if not package:
            continue
        fix_config = item.get("fix_config") or {}
        target = fix_config.get("target_version") or item.get("target_version")
        text = f"{package} 到 {target}" if target else str(package)
        if text not in targets:
            targets.append(text)
    if not targets:
        return ""
    visible = "、".join(targets[:limit])
    if len(targets) > limit:
        visible += f" 等 {len(targets)} 个依赖"
    return visible


def secret_location_phrase(secrets, limit=2):
    files = unique_values([item.get("file") for item in secrets or []])
    if not files:
        return ""
    visible = "、".join(map(str, files[:limit]))
    if len(files) > limit:
        visible += f" 等 {len(files)} 个文件"
    return visible


def build_summary(scan, analysis):
    project = scan.get("project") or {}
    hygiene = scan.get("hygiene") or {}
    scan_config = scan.get("scan_config") or {}
    hygiene_only = scan_config.get("scan_mode") == "hygiene_only"
    dependency_issue_count = len(analysis.get("top_issues") or [])
    vuln_count = dependency_issue_count
    risk_summary = analysis["risk_summary"]
    dependency_risk_summary = analysis.get(
        "dependency_risk_summary"
    ) or risk_summary_for_items(analysis.get("top_issues") or [], risk_summary)
    confirmed_risk_summary = dependency_risk_summary
    critical_high = confirmed_risk_summary["critical"] + confirmed_risk_summary["high"]
    medium_low = confirmed_risk_summary["medium"] + confirmed_risk_summary["low"]
    local_critical_high = max(
        0,
        int(risk_summary.get("critical") or 0)
        + int(risk_summary.get("high") or 0)
        - critical_high,
    )
    secret_count = len(hygiene.get("tracked_secrets") or [])
    sensitive_count = len(hygiene.get("sensitive_tracked") or [])
    missing_count = len(hygiene.get("gitignore_missing") or [])
    structured_hygiene_items = [
        item
        for group_name in STRUCTURED_HYGIENE_GROUPS
        for item in (hygiene.get(group_name) or [])
    ]
    maintenance_advice_count = sum(
        1 for item in structured_hygiene_items if is_maintenance_advice(item)
    )
    local_check_count = len(structured_hygiene_items) - maintenance_advice_count
    outdated_count = len(scan.get("outdated") or [])
    errors = scan.get("errors") or []
    outdated_skip_errors = [item for item in errors if is_outdated_skip_error(item)]
    other_errors = [item for item in errors if not is_outdated_skip_error(item)]
    vulnerability_errors = [
        item for item in other_errors if is_vulnerability_source_error(item)
    ]
    dependency_fix_count = len(
        [
            item
            for item in analysis.get("green") or []
            if item.get("type") == "dependency_upgrade"
        ]
    )
    dependency_scope = project_dependency_scope(project, scan)
    hygiene_signal = summary_hygiene_signal_phrase(
        secret_count, sensitive_count, missing_count, local_check_count
    )

    if hygiene_only:
        tldr = "本次没有发现当前支持的依赖文件，因此未执行依赖漏洞扫描；报告结论仅覆盖仓库安检范围。"
    elif critical_high and vuln_count:
        tldr = (
            f"本次在 {dependency_scope}中命中 {vuln_count} 个已确认依赖风险项，"
            f"其中 {critical_high} 个需要优先处理；{hygiene_signal}。"
        )
    elif vuln_count and medium_low:
        tldr = (
            f"本次在 {dependency_scope}中命中 {vuln_count} 个已确认依赖风险项，"
            f"以中低风险为主；{hygiene_signal}。"
        )
    elif vuln_count:
        tldr = (
            f"本次在 {dependency_scope}中命中 {vuln_count} 个已确认依赖风险项，"
            f"但严重度数据不足；{hygiene_signal}。"
        )
    elif local_critical_high:
        tldr = "仓库安检发现需要优先处理的本地安全配置风险，建议先处理工作流、凭证、容器或供应链高风险项。"
    elif secret_count or sensitive_count:
        tldr = "未发现高优先级依赖漏洞，但仓库里有凭证或敏感文件迹象，需要研发确认。"
    elif vulnerability_errors or other_errors:
        tldr = (
            "本次扫描暂未确认安全风险，但有部分检查失败，结论需要复核后再作为发布依据。"
        )
    elif outdated_skip_errors:
        tldr = (
            "本次未命中已确认依赖风险项；过期依赖检查未执行，版本维护结论需要补跑确认。"
        )
    else:
        tldr = "本次扫描没有发现明确安全风险，可作为当前项目状态记录。"

    if hygiene_only:
        detail = (
            f"本次检查覆盖项目 {project.get('name') or '-'}。{HYGIENE_ONLY_NOTICE}"
            f"仓库安检方面，发现疑似硬编码凭证 {secret_count} 处、"
            f"被 git 跟踪的敏感文件 {sensitive_count} 个、建议补充的 .gitignore 规则 {missing_count} 条、"
            f"本地配置/工作流检查项 {local_check_count} 个、建议 {maintenance_advice_count} 条。"
        )
    else:
        detail_parts = [
            f"本次检查覆盖项目 {project.get('name') or '-'}，识别到 {dependency_scope}，"
            f"命中 {vuln_count} 个已确认依赖风险项{package_focus_text(analysis.get('top_issues') or [])}。"
        ]
        detail_parts.extend(
            hygiene_detail_sentences(
                secret_count,
                sensitive_count,
                missing_count,
                local_check_count,
                maintenance_advice_count,
            )
        )
        if outdated_count:
            detail_parts.append(
                f"过期依赖 {outdated_count} 个，建议按维护窗口和兼容性评估安排升级。"
            )
        elif outdated_skip_errors:
            detail_parts.append("过期依赖检查未执行：默认不运行项目包管理器命令。")
        detail = "".join(detail_parts)

    if vulnerability_errors:
        if "依赖漏洞检查不完整" not in tldr:
            tldr = f"{tldr} 依赖漏洞检查不完整，需补齐失败项后再作为发布依据。"
        detail = (
            f"{detail}另外，本次有官方漏洞源或工具链检查失败；失败项补齐前，"
            "报告只代表成功完成的检查项。"
        )
    elif other_errors:
        if "部分检查失败" not in tldr:
            tldr = f"{tldr} 注意：本次有部分检查失败，需复核后再判断剩余风险。"
        detail = f"{detail}另外，本次有部分检查失败；失败项补齐前，报告只代表成功完成的检查项。"

    priority = []
    if hygiene_only:
        priority.append(HYGIENE_ONLY_NOTICE)
    elif critical_high:
        targets = dependency_upgrade_targets(analysis.get("green") or [])
        if targets:
            priority.append(f"先升级 {targets}，完成后重新运行扫描。")
        else:
            priority.append(
                f"优先处理 {critical_high} 个紧急/高风险项，先处理有明确修复版本或官方处置路径的项。"
            )
    elif local_critical_high:
        priority.append(
            "优先处理仓库安检中的高风险本地配置项，例如工作流权限、凭证、容器或供应链配置。"
        )
    elif vuln_count:
        priority.append(
            f"按影响程度处理 {vuln_count} 个已确认依赖风险项，先处理有明确修复版本或官方处置路径的项。"
        )
    if secret_count or sensitive_count:
        location = secret_location_phrase(hygiene.get("tracked_secrets") or [])
        prefix = f"确认 {location} 中的凭证线索" if location else "确认凭证和敏感文件"
        priority.append(
            f"{prefix}是否真实有效；如有效，先轮换或撤销，再清理代码中的明文。"
        )
    if missing_count:
        priority.append("补充 .gitignore 敏感文件规则，降低后续误提交概率。")
    if outdated_count:
        # 过期依赖是维护信号，不是已确认漏洞；
        # 不要把它们计入红黄风险总数。
        priority.append(
            "过期依赖按维护计划处理，结合版本跨度、兼容性和发布窗口分批升级。"
        )
    if dependency_fix_count:
        priority.append(
            "依赖修复后必须重新运行扫描；如果仍出现同名旧版本，通常是间接依赖被父包锁定，"
            "需要询问用户是否确认升级父依赖到 latest。"
        )
    if outdated_skip_errors:
        priority.append(
            "需要过期依赖结论时，显式允许项目包管理器命令后补跑版本维护检查。"
        )
    if vulnerability_errors:
        priority.append(
            "复查扫描错误，补齐失败的官方漏洞源或工具链检查后再确认最终结论。"
        )
    elif other_errors:
        priority.append("复查扫描错误，补齐失败的检查项后再确认最终结论。")
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
    project = scan.get("project") or {}
    scan_mode = (scan.get("scan_config") or {}).get("scan_mode", "unknown")
    logger.info(
        "build_analysis 开始: 项目=%s, 模式=%s",
        project.get("name") or "-",
        scan_mode,
    )

    top_issues = build_top_issues(scan)
    red, yellow, hygiene_green = build_hygiene_items(scan)
    dependency_green = build_dependency_fix_items(top_issues)
    green = dependency_green + hygiene_green
    dependency_risk_summary = count_risks(top_issues)
    local_risk_summary = count_risks(red, yellow)

    analysis = {
        "schema_version": ANALYSIS_SCHEMA_VERSION,
        "generated_at": scan.get("generated_at"),
        "scan_seconds": scan.get("scan_seconds"),
        "project": scan.get("project") or {},
        "scan_config": scan.get("scan_config") or {},
        "source_scan_file": source_scan_file,
        "output_file": output_file,
        "risk_summary": merge_risk_summaries(
            dependency_risk_summary, local_risk_summary
        ),
        "dependency_risk_summary": dependency_risk_summary,
        "local_risk_summary": local_risk_summary,
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

    risk_summary = analysis["risk_summary"]
    logger.info(
        "build_analysis 完成: %d 个风险项 (c=%d h=%d m=%d l=%d), %d 过期, %d 错误",
        len(top_issues),
        risk_summary.get("critical", 0),
        risk_summary.get("high", 0),
        risk_summary.get("medium", 0),
        risk_summary.get("low", 0),
        analysis["outdated_count"],
        len(analysis["errors"]),
    )
    return analysis


def write_json(path, data):
    output_dir = os.path.dirname(os.path.abspath(path))
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    logger.debug("write_json: %s", path)


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
    log_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(scan_path))), "logs"
    )
    setup_logging(log_dir=log_dir, log_file="analyze.log")
    output_path = args.output_json or default_output_path(scan_path)
    logger.info("analyze.py 开始: scan=%s, output=%s", scan_path, output_path)

    with open(scan_path, "r", encoding="utf-8") as handle:
        scan = json.load(handle)

    analysis = build_analysis(
        scan,
        source_scan_file=os.path.abspath(scan_path),
        output_file=output_path,
    )
    write_json(output_path, analysis)
    logger.info("analysis 已写入: %s", output_path)
    print(f"analysis 已生成: {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
