#!/usr/bin/env python3
"""Convert analysis.json to SARIF v2.1.0 format.

Usage:
    python3 scripts/sarif.py .butian/<timestamp>/assets/analysis.json
    python3 scripts/sarif.py analysis.json output.sarif.json
"""

import argparse
import json
import os
import sys

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "main/sarif-2.1/schema/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"

SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

SEVERITY_TO_SARIF_RANK = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 5.0,
    "low": 3.0,
    "info": 1.0,
}


def _sarif_level(severity):
    """Map butian severity to SARIF level."""
    return SEVERITY_TO_SARIF_LEVEL.get(str(severity or "info").lower(), "note")


def _sarif_rank(severity):
    """Map butian severity to SARIF rank."""
    return SEVERITY_TO_SARIF_RANK.get(str(severity or "info").lower(), 1.0)


def sarif_rule_from_vulnerability(vuln, index):
    """Create a SARIF rule from a vulnerability dict."""
    rule_id = vuln.get("advisory_id") or vuln.get("cve_id") or f"butian-vuln-{index}"
    rule = {
        "id": rule_id,
        "name": vuln.get("package", "unknown"),
        "shortDescription": {
            "text": vuln.get("summary") or vuln.get("match_summary") or "依赖漏洞",
        },
        "fullDescription": {
            "text": vuln.get("summary") or vuln.get("advisory_summary") or "",
        },
        "properties": {
            "tags": ["security", "vulnerability"],
        },
        "defaultConfiguration": {
            "level": _sarif_level(vuln.get("severity")),
        },
    }
    help_uri = None
    rid = vuln.get("advisory_id") or vuln.get("cve_id") or ""
    if rid.startswith("GHSA-"):
        help_uri = f"https://github.com/advisories/{rid}"
    elif rid.startswith("CVE-"):
        help_uri = f"https://nvd.nist.gov/vuln/detail/{rid}"
    elif rid.startswith("OSV-"):
        help_uri = f"https://osv.dev/vulnerability/{rid}"
    if help_uri:
        rule["helpUri"] = help_uri
    return rule


def sarif_result_from_vulnerability(vuln, rule_index):
    """Create a SARIF result from a vulnerability dict."""
    rule_id = (
        vuln.get("advisory_id") or vuln.get("cve_id") or f"butian-vuln-{rule_index}"
    )
    ecosystem = vuln.get("ecosystem", "")
    return {
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "level": _sarif_level(vuln.get("severity")),
        "message": {
            "text": vuln.get("summary") or vuln.get("match_summary") or "依赖漏洞",
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": ecosystem,
                    },
                    "region": {},
                },
            }
        ],
        "properties": {
            "package": vuln.get("package", ""),
            "version": vuln.get("version", ""),
            "ecosystem": ecosystem,
            "severity": vuln.get("severity", "info"),
            "fixed_versions": vuln.get("fixed_versions", []),
        },
        "rank": _sarif_rank(vuln.get("severity")),
    }


def sarif_result_from_secret(secret):
    """Create a SARIF result from a hardcoded secret finding."""
    return {
        "ruleId": f"butian-secret-{secret.get('type', 'unknown')}",
        "level": "warning" if secret.get("confidence") == "high" else "note",
        "message": {
            "text": f"疑似硬编码{secret.get('type', '凭证')}: {secret.get('file', '')}:{secret.get('line', '')}",
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": secret.get("file", ""),
                    },
                    "region": {
                        "startLine": secret.get("line", 1),
                    },
                },
            }
        ],
        "properties": {
            "secret_type": secret.get("type", ""),
            "confidence": secret.get("confidence", "medium"),
        },
    }


def sarif_rule_from_secret_type(stype):
    """Create a SARIF rule for a secret type."""
    return {
        "id": f"butian-secret-{stype}",
        "name": f"Hardcoded {stype}",
        "shortDescription": {"text": f"检测到硬编码{stype}"},
        "properties": {"tags": ["security", "secret"]},
        "defaultConfiguration": {"level": "warning"},
    }


def sarif_result_from_sensitive(item):
    """Create a SARIF result from a sensitive file finding."""
    return {
        "ruleId": f"butian-sensitive-{item.get('type', 'unknown')}",
        "level": "warning",
        "message": {
            "text": f"敏感文件已被 git 跟踪: {item.get('file', '')}",
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": item.get("file", ""),
                    },
                },
            }
        ],
        "properties": {
            "file_type": item.get("type", ""),
        },
    }


def build_sarif(analysis):
    """Build complete SARIF v2.1.0 document from analysis JSON."""
    rules = []
    results = []
    rule_id_to_index = {}

    def _ensure_rule(rule_id, rule_factory):
        if rule_id not in rule_id_to_index:
            rule_id_to_index[rule_id] = len(rules)
            rules.append(rule_factory())
        return rule_id_to_index[rule_id]

    # --- Vulnerabilities ---
    for i, vuln in enumerate(analysis.get("top_issues") or []):
        rule_id = vuln.get("advisory_id") or vuln.get("cve_id") or f"butian-vuln-{i}"
        idx = _ensure_rule(
            rule_id,
            lambda rid=rule_id, ii=i: sarif_rule_from_vulnerability(
                {**vuln, "advisory_id": rid, "cve_id": rid}, ii
            ),
        )
        results.append(sarif_result_from_vulnerability(vuln, idx))

    # --- Hardcoded secrets ---
    hygiene = analysis.get("hygiene") or {}
    for secret in hygiene.get("tracked_secrets") or []:
        stype = secret.get("type", "unknown")
        rule_id = f"butian-secret-{stype}"
        _ensure_rule(rule_id, lambda st=stype: sarif_rule_from_secret_type(st))
        results.append(sarif_result_from_secret(secret))

    # --- Sensitive files tracked ---
    for item in hygiene.get("sensitive_tracked") or []:
        ftype = item.get("type", "unknown")
        rule_id = f"butian-sensitive-{ftype}"
        _ensure_rule(
            rule_id,
            lambda ft=ftype: {
                "id": f"butian-sensitive-{ft}",
                "name": f"Sensitive file: {ft}",
                "shortDescription": {"text": f"敏感文件类型: {ft}"},
                "properties": {"tags": ["security", "sensitive-file"]},
                "defaultConfiguration": {"level": "warning"},
            },
        )
        results.append(sarif_result_from_sensitive(item))

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "补天 (Butian)",
                        "version": "1.0.0",
                        "semanticVersion": "1.0.0",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": analysis.get("generated_at", ""),
                    }
                ],
            }
        ],
    }


def default_output_path(analysis_path):
    """Default SARIF output next to analysis.json."""
    base_dir = os.path.dirname(os.path.abspath(analysis_path))
    return os.path.join(base_dir, "results.sarif.json")


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Convert analysis JSON to SARIF v2.1.0",
    )
    parser.add_argument("analysis_json", help="analysis.json 路径")
    parser.add_argument("output_sarif", nargs="?", help="输出 SARIF 文件路径")
    return parser.parse_args(argv)


def main():
    args = parse_args(sys.argv[1:])

    with open(args.analysis_json, "r", encoding="utf-8") as f:
        analysis = json.load(f)

    sarif = build_sarif(analysis)
    out = args.output_sarif or default_output_path(args.analysis_json)

    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(sarif, f, ensure_ascii=False, indent=2)
        f.write("\n")

    print(f"SARIF 已生成: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
