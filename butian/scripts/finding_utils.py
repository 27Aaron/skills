"""Shared helpers for local repository security findings."""

from __future__ import annotations

import os
from typing import Iterable

DEFAULT_EXCLUDE_DIRS = {
    ".git",
    ".butian",
    ".claude",
    "node_modules",
    ".next",
    ".turbo",
    ".vercel",
    "dist",
    "build",
    "coverage",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".svelte-kit",
    ".venv",
    "venv",
    ".idea",
    ".vscode",
    "target",
    "vendor",
    "bower_components",
    ".cache",
    ".tox",
    ".eggs",
}

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_CONFIDENCES = {"high", "medium", "low"}


def relpath(path: str, project_path: str) -> str:
    try:
        return os.path.relpath(path, project_path)
    except ValueError:
        return path


def read_text(path: str, max_bytes: int = 1024 * 1024) -> str:
    try:
        if os.path.getsize(path) > max_bytes:
            return ""
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            return handle.read()
    except OSError:
        return ""


def iter_files(
    project_path: str,
    *,
    suffixes: Iterable[str] | None = None,
    names: Iterable[str] | None = None,
    max_files: int = 2000,
    exclude_dirs: Iterable[str] | None = None,
):
    suffix_set = {s.lower() for s in suffixes or []}
    name_set = {n.lower() for n in names or []}
    excluded = set(DEFAULT_EXCLUDE_DIRS if exclude_dirs is None else exclude_dirs)
    count = 0
    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in excluded]
        for filename in files:
            if count >= max_files:
                return
            lowered = filename.lower()
            path = os.path.join(root, filename)
            if suffix_set and not any(lowered.endswith(s) for s in suffix_set):
                if lowered not in name_set:
                    continue
            elif name_set and lowered not in name_set and not suffix_set:
                continue
            count += 1
            yield path


def line_for_text(path: str, needle: str) -> int | None:
    if not needle:
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            for line_no, line in enumerate(handle, 1):
                if needle in line:
                    return line_no
    except OSError:
        return None
    return None


def evidence_snippet(value: str | None, max_len: int = 180) -> str:
    value = " ".join(str(value or "").strip().split())
    if len(value) <= max_len:
        return value
    if max_len <= 3:
        return "." * max(0, max_len)
    return value[: max_len - 3] + "..."


def make_finding(
    finding_id: str,
    *,
    category: str,
    severity: str,
    confidence: str,
    file: str = "",
    line: int | None = None,
    title: str,
    detail: str,
    evidence: str = "",
    recommendation: str,
    source: str = "builtin",
    fixable: bool = False,
    **extra,
):
    severity = severity if severity in VALID_SEVERITIES else "info"
    confidence = confidence if confidence in VALID_CONFIDENCES else "low"
    finding = {
        "id": finding_id,
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "file": file or "",
        "line": line,
        "title": title,
        "detail": detail,
        "evidence": evidence_snippet(evidence),
        "recommendation": recommendation,
        "source": source,
        "fixable": bool(fixable),
    }
    finding.update({k: v for k, v in extra.items() if v is not None})
    return finding


def dedupe_findings(findings):
    seen = set()
    result = []
    for finding in findings or []:
        key = (
            finding.get("id"),
            finding.get("file"),
            finding.get("line"),
            finding.get("evidence"),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result
