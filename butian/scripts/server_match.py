#!/usr/bin/env python3
"""Match Linux server package assets against official vulnerability sources."""

from __future__ import annotations

from typing import Any

try:
    from . import scan
except ImportError:  # pragma: no cover
    import scan  # type: ignore


OSV_SERVER_ECOSYSTEM_PREFIXES = ("Ubuntu:", "Debian:", "Alpine:")

# Unsupported server ecosystems are coverage gaps, not clean results. Keep
# explicit errors so reports do not turn an OSV support limit into "no risk".


def _candidate_assets(server_assets: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for item in server_assets.get("packages") or []:
        if item.get("ecosystem") and item.get("name") and item.get("version"):
            result.append(item)
    kernel = server_assets.get("kernel") or {}
    if (
        kernel.get("queryable")
        and kernel.get("ecosystem")
        and kernel.get("name")
        and kernel.get("version")
    ):
        result.append(kernel)
    return result


def _is_osv_queryable_ecosystem(ecosystem: str) -> bool:
    text = str(ecosystem or "")
    return any(text.startswith(prefix) for prefix in OSV_SERVER_ECOSYSTEM_PREFIXES)


def _query_asset(asset: dict[str, Any]) -> dict[str, Any] | None:
    if not _is_osv_queryable_ecosystem(str(asset.get("ecosystem") or "")):
        return None
    installed_name = str(asset.get("name") or "").strip()
    query_name = str(asset.get("source_name") or installed_name).strip()
    if not query_name:
        return None
    query = dict(asset)
    query["name"] = query_name
    if installed_name and installed_name != query_name:
        query["installed_name"] = installed_name
    return query


def queryable_assets(server_assets: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        query
        for query in (_query_asset(item) for item in _candidate_assets(server_assets))
        if query
    ]


def _unsupported_ecosystem_errors(
    server_assets: dict[str, Any],
) -> list[dict[str, str]]:
    counts: dict[str, int] = {}
    for asset in _candidate_assets(server_assets):
        ecosystem = str(asset.get("ecosystem") or "").strip()
        if ecosystem and not _is_osv_queryable_ecosystem(ecosystem):
            counts[ecosystem] = counts.get(ecosystem, 0) + 1
    return [
        {
            "step": "vulnerability_check",
            "message": (
                f"OSV 暂不支持服务器 ecosystem {ecosystem} 的发行版包坐标，"
                f"已跳过 {count} 个包；该结果不能解释为这些包没有漏洞。"
            ),
        }
        for ecosystem, count in sorted(counts.items())
    ]


def _severity_from_cvss(score: float | int | str | None) -> str:
    try:
        value = float(score) if score is not None else None
    except (TypeError, ValueError):
        return "medium"
    if value is None:
        return "medium"
    if value >= 9:
        return "critical"
    if value >= 7:
        return "high"
    if value >= 4:
        return "medium"
    return "low"


def _cve_aliases(osv_record: dict[str, Any]) -> list[str]:
    aliases = []
    values = [osv_record.get("id"), *(osv_record.get("aliases") or [])]
    for value in values:
        text = str(value or "").upper()
        if text.startswith("CVE-") and text not in aliases:
            aliases.append(text)
    return aliases


def _as_enrichment_list(value: Any) -> list[dict[str, Any]]:
    if not value:
        return []
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _cvss_score(entry: dict[str, Any]) -> str | float | int | None:
    if entry.get("cvssScore") is not None:
        return entry.get("cvssScore")
    if entry.get("cvss_score") is not None:
        return entry.get("cvss_score")
    if entry.get("bestCvssScore") is not None:
        return entry.get("bestCvssScore")
    metrics = entry.get("cvssMetrics") or []
    scores = []
    for metric in metrics:
        try:
            scores.append(float(metric.get("baseScore")))
        except (AttributeError, TypeError, ValueError):
            pass
    return max(scores) if scores else None


def _best_cvss(enrichments: list[dict[str, Any]]) -> float | None:
    scores = []
    for item in enrichments or []:
        try:
            score = _cvss_score(item)
            if score is not None:
                scores.append(float(score))
        except (TypeError, ValueError):
            pass
    return max(scores) if scores else None


def _best_severity(enrichments: list[dict[str, Any]], cvss: float | None) -> str:
    for item in enrichments or []:
        severity = str(
            item.get("bestCvssSeverity")
            or item.get("baseSeverity")
            or item.get("severity")
            or ""
        ).lower()
        if severity in {"critical", "high", "medium", "low"}:
            return severity
    return _severity_from_cvss(cvss)


def _cwes(enrichments: list[dict[str, Any]]) -> list[str]:
    result = []
    for entry in enrichments:
        for key in ("cwes", "cwe", "cweIds"):
            value = entry.get(key)
            values = value if isinstance(value, list) else [value]
            for cwe in values:
                if cwe and cwe not in result:
                    result.append(cwe)
    return result


def _enrichment_value(enrichments: list[dict[str, Any]], key: str) -> Any:
    for entry in enrichments:
        if entry.get(key) not in {None, ""}:
            return entry.get(key)
    return None


def build_confirmed_issue(
    asset: dict[str, Any],
    osv_record: dict[str, Any],
    cve_enrichments: dict[str, Any],
) -> dict[str, Any]:
    source_name = asset.get("name") or ""
    installed_name = asset.get("installed_name") or source_name
    aliases = _cve_aliases(osv_record)
    enrichments = []
    for cve in aliases:
        enrichments.extend(_as_enrichment_list(cve_enrichments.get(cve)))
    cvss = _best_cvss(enrichments)
    fixed_versions = []
    try:
        fixed_versions = scan.extract_osv_fixed_versions(osv_record, asset)
    except Exception:
        fixed_versions = []
    summary = f"{source_name} {asset.get('version')} 命中发行版包坐标确认的已知漏洞。"
    if source_name and source_name != installed_name:
        summary = (
            f"{installed_name} {asset.get('version')} 的源包 {source_name} "
            "命中发行版包坐标确认的已知漏洞。"
        )
    return {
        "scope": "server",
        "category": "server_package_vulnerability",
        "asset_type": asset.get("asset_type") or "system_package",
        "package": installed_name,
        "name": installed_name,
        "source_package": source_name if source_name != installed_name else "",
        "version": asset.get("version") or "",
        "ecosystem": asset.get("ecosystem") or "",
        "package_type": asset.get("package_type") or "",
        "severity": _best_severity(enrichments, cvss),
        "confidence": "confirmed",
        "advisory_id": osv_record.get("id") or (aliases[0] if aliases else ""),
        "aliases": aliases or (osv_record.get("aliases") or []),
        "cve_id": aliases[0] if aliases else "",
        "advisory_summary": osv_record.get("summary")
        or osv_record.get("details")
        or "",
        "summary": summary,
        "cvss": cvss,
        "cwe": _cwes(enrichments),
        "fixed_versions": fixed_versions,
        "kev_listed": bool(_enrichment_value(enrichments, "kevListed")),
        "epss": _enrichment_value(enrichments, "epss"),
        "epss_percentile": _enrichment_value(enrichments, "epssPercentile"),
        "evidence": asset.get("evidence") or [],
    }


def filter_reportable_issues(issues: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [item for item in issues if item.get("confidence") == "confirmed"]


def _extract_osv_matches(
    data: dict[str, Any], assets: list[dict[str, Any]]
) -> list[tuple[dict[str, Any], str]]:
    records = []
    results = data.get("results") if isinstance(data, dict) else []
    if not isinstance(results, list):
        return records
    for asset, result in zip(assets, results):
        if not isinstance(result, dict):
            continue
        for vuln in result.get("vulns") or []:
            if isinstance(vuln, dict) and vuln.get("id"):
                records.append((asset, str(vuln["id"])))
    return records


def _unique_cves(records: list[tuple[dict[str, Any], dict[str, Any]]]) -> list[str]:
    cve_ids = []
    for _, record in records:
        for cve in _cve_aliases(record):
            if cve not in cve_ids:
                cve_ids.append(cve)
    return cve_ids


def _merge_enrichments(*sources: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    merged: dict[str, list[dict[str, Any]]] = {}
    for source in sources:
        for cve, value in (source or {}).items():
            merged.setdefault(cve, []).extend(_as_enrichment_list(value))
    return merged


def match_server_vulnerabilities(
    server_assets: dict[str, Any], *, project_path: str
) -> dict[str, Any]:
    errors = _unsupported_ecosystem_errors(server_assets)
    assets = queryable_assets(server_assets)
    matches: list[tuple[dict[str, Any], str]] = []
    for start in range(0, len(assets), 100):
        batch_assets = assets[start : start + 100]
        try:
            data = scan.fetch_osv_querybatch(batch_assets)
            matches.extend(_extract_osv_matches(data, batch_assets))
        except Exception as exc:
            errors.append(
                scan.official_source_error("OSV", "服务器包批量查询", str(exc))
            )

    details: dict[str, dict[str, Any]] = {}
    records: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for asset, vuln_id in matches:
        if vuln_id not in details:
            try:
                details[vuln_id] = scan.fetch_osv_vulnerability(vuln_id)
            except Exception as exc:
                errors.append(
                    scan.official_source_error("OSV", f"{vuln_id} 详情查询", str(exc))
                )
                continue
        records.append((asset, details[vuln_id]))

    cve_ids = _unique_cves(records)
    nvd = scan.fetch_nvd_enrichments(cve_ids, errors) if cve_ids else {}
    kev = (
        scan.fetch_cisa_kev_enrichments(cve_ids, errors, project_path)
        if cve_ids
        else {}
    )
    epss = scan.fetch_epss_enrichments(cve_ids, errors) if cve_ids else {}
    enrichments = _merge_enrichments(nvd, kev, epss)

    issues = [
        build_confirmed_issue(asset, record, enrichments) for asset, record in records
    ]
    return {
        "confirmed_issues": filter_reportable_issues(issues),
        "asset_count": len(assets),
        "errors": errors,
    }
