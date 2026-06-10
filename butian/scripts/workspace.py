#!/usr/bin/env python3
"""本地工作区和项目边界工具。"""

from __future__ import annotations

import fnmatch
import os
import re
import time

BUTIAN_DIR = ".butian"
CACHE_DIR_NAME = "cache"
BUTIAN_GITIGNORE_ENTRY = ".butian/"
BUTIAN_GITIGNORE_EXTRA_ENTRIES = (
    "docs/butian/*/security-report.md",
    "docs/butian/*/security-report.html",
    "docs/butian/*/security-report-final.md",
    "docs/butian/*/security-report-final.html",
)
BUTIAN_ASSETS_DIR = "assets"

PROJECT_ROOT_MARKERS = (
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "uv.lock",
    "requirements.txt",
    "Pipfile.lock",
    "go.sum",
    "Cargo.lock",
    "package.json",
    "pyproject.toml",
    "go.mod",
    "Cargo.toml",
    "composer.json",
    "Gemfile",
)

_GITIGNORE_STATUS_BY_PROJECT = {}
_PROTECTED_SCAN_ROOTS = {
    os.path.abspath(os.sep),
    "/Applications",
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/home",
    "/Library",
    "/lib",
    "/lib64",
    "/opt",
    "/private",
    "/private/var",
    "/proc",
    "/root",
    "/sbin",
    "/System",
    "/tmp",
    "/usr",
    "/var",
}
_HOME_DIR = os.path.expanduser("~")
if _HOME_DIR and _HOME_DIR != "~":
    _PROTECTED_SCAN_ROOTS.add(os.path.abspath(_HOME_DIR))


def _looks_like_windows_drive_root(path):
    text = str(path or "").strip()
    return bool(re.fullmatch(r"[A-Za-z]:[\\/]*", text))


def _is_filesystem_root(path):
    if _looks_like_windows_drive_root(path):
        return True
    absolute = os.path.abspath(path)
    return os.path.dirname(absolute) == absolute


def _protected_scan_roots():
    roots = set()
    for root in _PROTECTED_SCAN_ROOTS:
        roots.add(os.path.abspath(root))
        roots.add(os.path.realpath(root))
    return roots


def has_gitignore_entry(content, entry):
    normalized = str(entry or "").strip().rstrip("/")
    candidates = {normalized, f"{normalized}/"}
    for line in content.splitlines():
        stripped = line.strip()
        if stripped in candidates:
            return True
    return False


def has_butian_gitignore_entry(content):
    return has_gitignore_entry(content, BUTIAN_GITIGNORE_ENTRY)


def inspect_butian_gitignore(project_path):
    gitignore_path = os.path.join(project_path, ".gitignore")
    try:
        with open(gitignore_path, "r", encoding="utf-8") as handle:
            content = handle.read()
    except FileNotFoundError:
        content = ""

    required_entries = [BUTIAN_GITIGNORE_ENTRY] + list(BUTIAN_GITIGNORE_EXTRA_ENTRIES)
    missing_entries = [
        entry for entry in required_entries if not has_gitignore_entry(content, entry)
    ]
    return {
        "path": gitignore_path,
        "preexisting": os.path.isfile(gitignore_path),
        "had_butian_entry": has_butian_gitignore_entry(content),
        "missing_entries": missing_entries,
    }


def ensure_butian_gitignore(project_path):
    status = inspect_butian_gitignore(project_path)
    gitignore_path = status["path"]
    try:
        with open(gitignore_path, "r", encoding="utf-8") as handle:
            content = handle.read()
    except FileNotFoundError:
        content = ""

    required_entries = [BUTIAN_GITIGNORE_ENTRY] + list(BUTIAN_GITIGNORE_EXTRA_ENTRIES)
    missing_entries = [
        entry for entry in required_entries if not has_gitignore_entry(content, entry)
    ]
    if not missing_entries:
        status.update(
            {
                "added_butian_entry": False,
                "added_entries": [],
                "missing_entries": [],
                "exists_after": True,
            }
        )
        _GITIGNORE_STATUS_BY_PROJECT[os.path.abspath(project_path)] = status
        return gitignore_path

    prefix = ""
    if content and not content.endswith("\n"):
        prefix = "\n"
    elif content:
        prefix = "\n"

    with open(gitignore_path, "a", encoding="utf-8") as handle:
        header = (
            ""
            if "Local security scan workspace" in content
            else "# Local security scan workspace\n"
        )
        entries = "\n".join(missing_entries)
        handle.write(f"{prefix}{header}{entries}\n")
    added_entry = any(entry == BUTIAN_GITIGNORE_ENTRY for entry in missing_entries)
    status.update(
        {
            "added_butian_entry": added_entry,
            "added_entries": missing_entries,
            "missing_entries": [],
            "exists_after": True,
        }
    )
    _GITIGNORE_STATUS_BY_PROJECT[os.path.abspath(project_path)] = status
    return gitignore_path


def butian_gitignore_status(project_path):
    project_path = os.path.abspath(project_path)
    if project_path in _GITIGNORE_STATUS_BY_PROJECT:
        return _GITIGNORE_STATUS_BY_PROJECT[project_path]
    status = inspect_butian_gitignore(project_path)
    status.update(
        {
            "added_butian_entry": False,
            "added_entries": [],
            "exists_after": status["preexisting"],
        }
    )
    _GITIGNORE_STATUS_BY_PROJECT[project_path] = status
    return status


def ensure_butian_workspace(project_path):
    workspace = os.path.join(project_path, BUTIAN_DIR)
    os.makedirs(workspace, exist_ok=True)
    ensure_butian_gitignore(project_path)
    return workspace


def _latest_existing_run(workspace):
    """返回最新一次运行目录路径；没有历史运行时返回 None。"""
    if not os.path.isdir(workspace):
        return None
    run_id_pattern = re.compile(r"^\d{8}-\d{4}(?:\d{2})?(?:-\d+)?$")
    candidates = sorted(
        (
            d
            for d in os.listdir(workspace)
            if os.path.isdir(os.path.join(workspace, d)) and run_id_pattern.match(d)
        ),
        reverse=True,
    )
    return os.path.join(workspace, candidates[0]) if candidates else None


def make_run_id():
    return time.strftime("%Y%m%d-%H%M%S")


def ensure_butian_run(project_path, run_id=None):
    workspace = ensure_butian_workspace(project_path)

    base_run_id = run_id or make_run_id()
    if run_id is not None:
        run_dir = os.path.join(workspace, base_run_id)
        os.makedirs(run_dir, exist_ok=True)
    else:
        suffix = 1
        while True:
            candidate = base_run_id if suffix == 1 else f"{base_run_id}-{suffix}"
            run_dir = os.path.join(workspace, candidate)
            try:
                os.mkdir(run_dir)
                break
            except FileExistsError:
                suffix += 1
    os.makedirs(os.path.join(run_dir, BUTIAN_ASSETS_DIR), exist_ok=True)
    return run_dir


def run_dir_from_output_file(output_file):
    output_file = os.path.abspath(output_file)
    parent = os.path.basename(os.path.dirname(output_file))
    if parent == BUTIAN_ASSETS_DIR:
        return os.path.dirname(os.path.dirname(output_file))
    return os.path.dirname(output_file)


def ensure_project_run_dir(project_path, run_dir):
    project_workspace = os.path.realpath(os.path.join(project_path, BUTIAN_DIR))
    run_real = os.path.realpath(run_dir)
    try:
        if os.path.commonpath([project_workspace, run_real]) != project_workspace:
            raise ValueError
    except ValueError as exc:
        raise ValueError(
            "preflight 中的运行目录必须位于项目 .butian 工作区内。"
        ) from exc
    return run_dir


def default_asset_path(project_path, filename, preflight=None):
    if preflight:
        workspace = preflight.get("butian_workspace") or {}
        run_dir = workspace.get("run_dir") or (
            run_dir_from_output_file(preflight["output_file"])
            if preflight.get("output_file")
            else ensure_butian_run(project_path)
        )
        run_dir = ensure_project_run_dir(project_path, run_dir)
        os.makedirs(os.path.join(run_dir, BUTIAN_ASSETS_DIR), exist_ok=True)
        ensure_butian_gitignore(project_path)
    else:
        run_dir = ensure_butian_run(project_path)
    return os.path.join(run_dir, BUTIAN_ASSETS_DIR, filename)


def is_protected_project_path(path):
    if _looks_like_windows_drive_root(path):
        return True
    absolute = os.path.abspath(path)
    real = os.path.realpath(path)
    if _is_filesystem_root(absolute) or _is_filesystem_root(real):
        return True
    protected_roots = _protected_scan_roots()
    return absolute in protected_roots or real in protected_roots


def ensure_safe_project_path(project_path):
    if is_protected_project_path(project_path):
        raise ValueError(
            "只扫描项目目录，不能把系统目录或用户主目录作为 project_path。"
            "请切换到具体代码仓库后重新运行。"
        )


def gitignore_rules(content):
    rules = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rules.add(line.lower().rstrip("/"))
    return rules


def _gitignore_rule_matches(rule, target):
    rule = rule.strip().lower().rstrip("/")
    target = target.strip().lower().rstrip("/")
    if not rule or not target:
        return False
    if rule == target or rule.lstrip("/") == target:
        return True
    if fnmatch.fnmatchcase(target, rule):
        return True
    if rule.startswith("**/") and _gitignore_rule_matches(rule[3:], target):
        return True
    if "/" not in rule and fnmatch.fnmatchcase(os.path.basename(target), rule):
        return True
    return False


def gitignore_ignores(content, pattern):
    norm = pattern.strip().lower().rstrip("/")
    state = False
    for line in content.splitlines():
        line = line.strip().lower().rstrip("/")
        if not line or line.startswith("#"):
            continue
        negated = line.startswith("!")
        rule = line[1:] if negated else line
        if _gitignore_rule_matches(rule, norm):
            state = not negated
    return state


def find_project_root(start_path="."):
    """向上查找最近的项目标记；找不到时用 .git 作为兜底。"""
    path = os.path.abspath(start_path)
    if os.path.isfile(path):
        path = os.path.dirname(path)
    original = path
    git_root = ""
    for _ in range(20):
        if any(
            os.path.isfile(os.path.join(path, marker))
            for marker in PROJECT_ROOT_MARKERS
        ):
            return path
        if not git_root and os.path.exists(os.path.join(path, ".git")):
            git_root = path
            break
        parent = os.path.dirname(path)
        if parent == path:
            break
        path = parent
    return git_root or original
