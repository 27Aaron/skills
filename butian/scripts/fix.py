#!/usr/bin/env python3
"""Dependency fix executor for Butian.

Usage (standalone):
    python3 scripts/fix.py <analysis.json> --strategy fixed
    python3 scripts/fix.py <analysis.json> --strategy latest

Library helpers:
    from fix import build_upgrade_commands, execute_fixes, extract_fixable_items
"""

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys

logger = logging.getLogger("butian")


def _parse_version(version_str):
    """Parse "1.2.3" into (1, 2, 3), stripping pre-release tags."""
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
    """Check if *version* satisfies an npm-style semver range (simplified)."""
    range_str = range_str.strip()
    if not range_str or range_str in ("*", "latest"):
        return True
    if "||" in range_str:
        return any(_semver_satisfies(version, r.strip()) for r in range_str.split("||"))
    ver = _parse_version(version)
    if range_str.startswith("^"):
        base = _parse_version(range_str[1:])
        if base[0] > 0:
            return ver >= base and ver[0] == base[0]
        if base[1] > 0:
            return ver >= base and ver[0] == 0 and ver[1] == base[1]
        return ver == base
    if range_str.startswith("~"):
        base = _parse_version(range_str[1:])
        return ver >= base and ver[0] == base[0] and ver[1] == base[1]
    if range_str.startswith(">="):
        return ver >= _parse_version(range_str[2:])
    if range_str.startswith(">"):
        return ver > _parse_version(range_str[1:])
    if range_str.startswith("<="):
        return ver <= _parse_version(range_str[2:])
    if range_str.startswith("<"):
        return ver < _parse_version(range_str[1:])
    return ver == _parse_version(range_str)


# ---------------------------------------------------------------------------
# Ecosystem upgrade command builders
# ---------------------------------------------------------------------------

# Maps ecosystem name to a fixed-version upgrade command builder.
# Each builder receives (package, version) and returns a command list.


def _go_version(ver):
    """Ensure Go version has 'v' prefix (Go requires v1.2.3, not 1.2.3)."""
    if ver and not ver.startswith("v"):
        return f"v{ver}"
    return ver


def _pypi_manager(project_path):
    """Detect Python package manager from lockfile presence."""
    if os.path.isfile(os.path.join(project_path, "uv.lock")):
        return "uv"
    if os.path.isfile(os.path.join(project_path, "poetry.lock")):
        return "poetry"
    if os.path.isfile(os.path.join(project_path, "Pipfile.lock")):
        return "pipenv"
    return None


def _pypi_fixed_cmd(pkg, ver, project_path="."):
    """Build fixed-version install command for the detected Python package manager."""
    mgr = _pypi_manager(project_path)
    if mgr == "uv":
        return ["uv", "add", f"{pkg}=={ver}"]
    if mgr == "poetry":
        return ["poetry", "add", f"{pkg}@{ver}"]
    if mgr == "pipenv":
        return ["pipenv", "install", f"{pkg}=={ver}"]
    return None


def _pypi_latest_cmd(pkg, project_path="."):
    """Build latest-version upgrade command for the detected Python package manager."""
    mgr = _pypi_manager(project_path)
    if mgr == "uv":
        return ["uv", "add", pkg]
    if mgr == "poetry":
        return ["poetry", "add", f"{pkg}@latest"]
    if mgr == "pipenv":
        return ["pipenv", "install", pkg]
    return None


_UPGRADE_BUILDERS = {
    "npm": lambda pkg, ver: ["npm", "install", f"{pkg}@{ver}"],
    "pnpm": lambda pkg, ver: ["pnpm", "add", f"{pkg}@{ver}"],
    "yarn": lambda pkg, ver: ["yarn", "add", f"{pkg}@{ver}"],
    "go": lambda pkg, ver: ["go", "get", f"{pkg}@{_go_version(ver)}"],
    "crates-io": lambda pkg, ver: ["cargo", "update", "-p", pkg, "--precise", ver],
}


def _latest_commands(ecosystem, package, project_path=None):
    """Build commands to upgrade a package to its latest version."""
    if ecosystem == "npm":
        return ["npm", "install", f"{package}@latest"]
    if ecosystem == "pnpm":
        return ["pnpm", "add", f"{package}@latest"]
    if ecosystem == "yarn":
        return ["yarn", "add", f"{package}@latest"]
    if ecosystem == "pypi":
        return _pypi_latest_cmd(package, project_path or ".")
    if ecosystem == "go":
        return ["go", "get", f"{package}@latest"]
    if ecosystem == "crates-io":
        return ["cargo", "update", "-p", package]
    return None


# ---------------------------------------------------------------------------
# Bulk latest upgrades
# ---------------------------------------------------------------------------


def build_all_latest_commands(project_path):
    """Build commands to upgrade ALL project dependencies to latest versions.

    The latest strategy is intentionally broad: it upgrades every detected
    dependency in a supported ecosystem, not only packages tied to advisories.

    Detects ecosystems from project files and generates bulk-upgrade
    commands for each detected ecosystem.

    Returns:
        list of (label, command_list) tuples
    """
    commands = []

    # --- Node.js (npm / pnpm / yarn) ---
    pkg_json_path = os.path.join(project_path, "package.json")
    if os.path.isfile(pkg_json_path):
        try:
            with open(pkg_json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            data = {}
        all_deps = []
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            for name in data.get(key) or {}:
                if name not in all_deps:
                    all_deps.append(name)
        if all_deps:
            pnpm_lock = os.path.join(project_path, "pnpm-lock.yaml")
            yarn_lock = os.path.join(project_path, "yarn.lock")
            if os.path.isfile(pnpm_lock):
                commands.append(("all-deps", ["pnpm", "update", "--latest"]))
            elif os.path.isfile(yarn_lock):
                commands.append(("all-deps", ["yarn", "upgrade"]))
            else:
                args = [f"{dep}@latest" for dep in all_deps]
                commands.append(("all-deps", ["npm", "install"] + args))

    # --- Python ---
    poetry_lock = os.path.join(project_path, "poetry.lock")
    uv_lock = os.path.join(project_path, "uv.lock")
    pipfile_lock = os.path.join(project_path, "Pipfile.lock")

    if os.path.isfile(poetry_lock):
        commands.append(("all-deps", ["poetry", "update"]))
    elif os.path.isfile(uv_lock):
        commands.append(("all-deps", ["uv", "lock", "--upgrade"]))
    elif os.path.isfile(pipfile_lock):
        commands.append(("all-deps", ["pipenv", "update"]))

    # --- Go ---
    if os.path.isfile(os.path.join(project_path, "go.sum")):
        commands.append(("all-deps", ["go", "get", "-u", "./..."]))

    # --- Rust ---
    if os.path.isfile(os.path.join(project_path, "Cargo.lock")):
        commands.append(("all-deps", ["cargo", "update"]))

    return commands


# ---------------------------------------------------------------------------
# Extract fixable items from analysis
# ---------------------------------------------------------------------------


def extract_fixable_items(analysis):
    """Return list of items with type='dependency_upgrade' and a target_version.

    Each item has:
      - package, ecosystem, version (current), target_version
      - fixed_versions, advisory_ids
      - severity, summary
    """
    items = analysis.get("green") or analysis.get("green_items") or []
    fixable = []
    for item in items:
        if item.get("type") != "dependency_upgrade":
            continue
        fc = item.get("fix_config") or {}
        if not fc.get("target_version"):
            continue
        fixable.append(
            {
                "package": fc.get("package") or item.get("package"),
                "ecosystem": fc.get("ecosystem"),
                "current_version": (fc.get("current_versions") or [None])[0],
                "current_versions": fc.get("current_versions") or [],
                "target_version": fc["target_version"],
                "fixed_versions": fc.get("fixed_versions", []),
                "advisory_ids": fc.get("advisory_ids", []),
                "severity": item.get("severity", "info"),
                "summary": item.get("summary", ""),
            }
        )
    return fixable


def extract_dependabot_config_items(analysis):
    """Return generated Dependabot config items from analysis green items."""
    items = analysis.get("green") or analysis.get("green_items") or []
    configs = []
    for item in items:
        fc = item.get("fix_config") or {}
        if fc.get("type") != "dependabot_config":
            continue
        path = fc.get("path") or ".github/dependabot.yml"
        content = fc.get("content") or ""
        if not content:
            continue
        configs.append({"path": path, "content": content})
    return configs


def _safe_project_file(project_path, rel_path):
    normalized = str(rel_path or "").replace("\\", "/").lstrip("/")
    parts = [part for part in normalized.split("/") if part]
    if not parts or ".." in parts:
        return None
    root = os.path.abspath(project_path)
    target = os.path.abspath(os.path.join(root, *parts))
    try:
        if os.path.commonpath([root, target]) != root:
            return None
    except ValueError:
        return None
    return target


def execute_dependabot_config_fixes(analysis, project_path):
    """Create generated Dependabot config files without overwriting user files."""
    items = extract_dependabot_config_items(analysis)
    if not items:
        return [], [("dependabot", "没有可创建的 Dependabot 配置。")]

    successes = []
    failures = []
    for item in items:
        rel_path = item["path"]
        target = _safe_project_file(project_path, rel_path)
        if not target:
            failures.append((rel_path, "目标路径不安全"))
            continue
        if os.path.exists(target):
            failures.append((rel_path, "文件已存在，未覆盖"))
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(item["content"])
        successes.append(rel_path)
        print(f"  ✅ 已创建 {rel_path}")
    return successes, failures


# ---------------------------------------------------------------------------
# Build upgrade commands
# ---------------------------------------------------------------------------


def build_upgrade_commands(fix_items, strategy, ecosystem=None, project_path=None):
    """Build upgrade commands for fixable items.

    Args:
        fix_items: list from extract_fixable_items()
        strategy: "minimal" | "latest"
        ecosystem: if set, filter to this ecosystem only
        project_path: project root (used to detect uv vs pip)

    Returns:
        list of (package, command_list) tuples
    """
    project_path = project_path or "."
    commands = []
    for item in fix_items:
        eco = item.get("ecosystem")
        if ecosystem and eco != ecosystem:
            continue
        pkg = item["package"]

        if strategy == "minimal":
            if eco == "pypi":
                cmd = _pypi_fixed_cmd(pkg, item["target_version"], project_path)
            else:
                builder = _UPGRADE_BUILDERS.get(eco)
                if not builder:
                    continue
                cmd = builder(pkg, item["target_version"])
        elif strategy == "latest":
            cmd = _latest_commands(eco, pkg, project_path)
        else:
            continue

        if cmd:
            commands.append((pkg, cmd))
    return commands


# ---------------------------------------------------------------------------
# npm parent upgrades for nested residuals
# ---------------------------------------------------------------------------


def _npm_package_name_at(parts, index):
    if index >= len(parts):
        return None
    name = parts[index]
    if name.startswith("@") and index + 1 < len(parts):
        return f"{name}/{parts[index + 1]}"
    return name


def _npm_package_name_from_lock_path(path):
    parts = [part for part in str(path or "").split("/") if part]
    indices = [index for index, part in enumerate(parts) if part == "node_modules"]
    if not indices:
        return None
    return _npm_package_name_at(parts, indices[-1] + 1)


def _npm_parent_name_from_lock_path(path):
    parts = [part for part in str(path or "").split("/") if part]
    indices = [index for index, part in enumerate(parts) if part == "node_modules"]
    if len(indices) < 2:
        return None
    return _npm_package_name_at(parts, indices[-2] + 1)


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
    path = ""
    for name in names:
        name_path = name.replace("/", os.sep).replace(os.sep, "/")
        path = (
            f"{path}/node_modules/{name_path}" if path else f"node_modules/{name_path}"
        )
    return path


def _npm_parent_lock_path(path):
    names = _npm_names_from_lock_path(path)
    if len(names) <= 1:
        return ""
    return _npm_lock_path_for_names(names[:-1])


def _npm_dep_lock_path_from(package_key, dependency):
    dep_path = dependency.replace("/", os.sep).replace(os.sep, "/")
    return (
        f"{package_key}/node_modules/{dep_path}"
        if package_key
        else f"node_modules/{dep_path}"
    )


def _resolve_npm_dependency(packages, package_key, dependency):
    current = package_key
    while True:
        candidate = _npm_dep_lock_path_from(current, dependency)
        if candidate in packages:
            return candidate
        if not current:
            return None
        current = _npm_parent_lock_path(current)


def _root_dependency_names(lock_data, package_json):
    names = []
    root_meta = (lock_data.get("packages") or {}).get("") or {}
    for source in (root_meta, package_json or {}):
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = source.get(key) or {}
            if not isinstance(deps, dict):
                continue
            for name in deps:
                if name not in names:
                    names.append(name)
    return names


def _direct_root_for_npm_lock_path(lock_data, package_json, target_lock_path):
    packages = lock_data.get("packages") or {}
    root_names = _root_dependency_names(lock_data, package_json)
    for root_name in root_names:
        root_path = _resolve_npm_dependency(packages, "", root_name)
        if not root_path:
            continue
        if root_path == target_lock_path:
            return root_name
        stack = [root_path]
        seen = set()
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            if current == target_lock_path:
                return root_name
            meta = packages.get(current) or {}
            for dep_name in meta.get("dependencies") or {}:
                dep_path = _resolve_npm_dependency(packages, current, dep_name)
                if dep_path and dep_path not in seen:
                    stack.append(dep_path)
    return None


def _load_json_file(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def build_npm_parent_upgrade_plan(analysis, project_path=None):
    """Build npm parent-upgrade actions for vulnerable nested lockfile entries.

    Parent-upgrade is a second-round repair. It should be used after a normal
    upgrade plus rescan proves that an old nested npm copy is still locked by a
    parent package.
    """
    project_path = project_path or (analysis.get("project") or {}).get("path") or "."
    lock_path = os.path.join(project_path, "package-lock.json")
    package_json_path = os.path.join(project_path, "package.json")
    plan = {"upgrades": [], "unfixable": [], "skipped": []}
    if not os.path.isfile(lock_path):
        plan["skipped"].append("未找到 package-lock.json，无法自动分析父依赖。")
        return plan

    lock_data = _load_json_file(lock_path)
    package_json = (
        _load_json_file(package_json_path) if os.path.isfile(package_json_path) else {}
    )
    packages = lock_data.get("packages") or {}
    fix_items = {
        item["package"]: item
        for item in extract_fixable_items(analysis)
        if item.get("ecosystem") == "npm" and item.get("package")
    }

    seen = set()
    for lock_key, meta in packages.items():
        package = _npm_package_name_from_lock_path(lock_key)
        if not package or package not in fix_items:
            continue
        item = fix_items[package]
        version = str((meta or {}).get("version") or "")
        current_versions = {
            str(value)
            for value in (item.get("current_versions") or [item.get("current_version")])
            if value
        }
        if current_versions and version not in current_versions:
            continue
        parent = _npm_parent_name_from_lock_path(lock_key)
        if not parent:
            plan["skipped"].append(
                f"{package}@{version} 是顶层依赖，普通升级应优先处理。"
            )
            continue
        parent_lock_path = _npm_parent_lock_path(lock_key)
        upgrade_package = _direct_root_for_npm_lock_path(
            lock_data, package_json, parent_lock_path
        )
        if not upgrade_package:
            key = (parent, package, version)
            if key not in seen:
                seen.add(key)
                plan["unfixable"].append(
                    {
                        "parent": parent,
                        "package": package,
                        "current_version": version,
                        "target_version": item["target_version"],
                        "note": f"{parent} > {package}@{version} 无法追溯到 package.json 中的根依赖",
                    }
                )
            continue

        key = (upgrade_package, parent, package, version)
        if key in seen:
            continue
        seen.add(key)
        plan["upgrades"].append(
            {
                "upgrade_package": upgrade_package,
                "immediate_parent": parent,
                "parent_lock_path": parent_lock_path,
                "package": package,
                "current_version": version,
                "target_version": item["target_version"],
                "lock_path": lock_key,
            }
        )
    return plan


def build_force_residual_overrides(analysis, project_path=None):
    """Build npm overrides map for unfixable nested residuals.

    force-residual writes a durable npm policy into package.json. Use it only
    after parent-upgrade cannot trace a safer root dependency update.

    Returns a dict with:
      - overrides: {package_name: target_version_or_ref, ...}
      - items: list of dicts with package, current_version, target_version, note
      - skipped: list of strings explaining what was skipped
    """
    project_path = project_path or (analysis.get("project") or {}).get("path") or "."
    package_json_path = os.path.join(project_path, "package.json")

    result = {"overrides": {}, "items": [], "skipped": []}

    if not os.path.isfile(package_json_path):
        result["skipped"].append("未找到 package.json，无法写入 overrides。")
        return result

    # Reuse parent-upgrade analysis so overrides only target entries that cannot
    # be traced back to a safer root dependency update.
    plan = build_npm_parent_upgrade_plan(analysis, project_path)
    unfixable = list(plan.get("unfixable") or [])

    if not unfixable:
        # Fallback: all fixable npm items (covers standalone usage)
        fix_items = extract_fixable_items(analysis)
        npm_items = [i for i in fix_items if i.get("ecosystem") == "npm"]
        for item in npm_items:
            unfixable.append(
                {
                    "parent": "(unknown)",
                    "package": item["package"],
                    "current_version": item.get("current_version")
                    or (item.get("current_versions") or [None])[0],
                    "target_version": item["target_version"],
                    "note": "analysis.json 中的可修复项",
                }
            )

    if not unfixable:
        result["skipped"].append("没有需要强制覆盖的残留依赖。")
        return result

    # Root dependencies need the "$pkg" self-reference form; hardcoding their
    # versions can trigger npm override conflicts.
    pkg_json = (
        _load_json_file(package_json_path) if os.path.isfile(package_json_path) else {}
    )
    root_deps = set()
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        root_deps.update((pkg_json.get(key) or {}).keys())

    for entry in unfixable:
        pkg = entry["package"]
        target = entry["target_version"]
        if pkg and target:
            if pkg in root_deps:
                result["overrides"][pkg] = f"${pkg}"
            else:
                result["overrides"][pkg] = target
            result["items"].append(entry)

    return result


def execute_force_residual_fixes(analysis, project_path):
    """Force-update unfixable nested residuals via npm overrides."""
    result = build_force_residual_overrides(analysis, project_path)

    if result["skipped"] or not result["overrides"]:
        skipped_text = "; ".join(result["skipped"] or ["没有残留依赖"])
        return [], [("force-residual", skipped_text)]

    package_json_path = os.path.join(project_path, "package.json")

    with open(package_json_path, "r", encoding="utf-8") as f:
        pkg_data = json.load(f)

    # Preserve existing user overrides; this strategy may only add or replace
    # the generated keys needed for the confirmed residual items.
    existing_overrides = pkg_data.get("overrides") or {}
    new_overrides = result["overrides"]
    merged = {**existing_overrides, **new_overrides}
    pkg_data["overrides"] = merged

    with open(package_json_path, "w", encoding="utf-8") as f:
        json.dump(pkg_data, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print("  已写入 package.json overrides:")
    for pkg, ver in sorted(new_overrides.items()):
        print(f'    - "{pkg}": "{ver}"')

    # Materialize overrides into package-lock.json so the follow-up scan sees
    # the enforced dependency graph.
    print("  正在运行 npm install...")
    ok, err = _run_npm_install(project_path)
    if ok:
        print("  ✅ npm install 完成")
        return list(new_overrides.keys()), []
    else:
        return [], [("npm install", err)]


def build_parent_upgrade_commands(plan):
    """Build commands: upgrade parent to latest, then upgrade child to target."""
    commands = []
    seen_parents = set()
    seen_children = set()
    for entry in plan.get("upgrades") or []:
        parent = entry["upgrade_package"]
        if parent not in seen_parents:
            seen_parents.add(parent)
            commands.append((parent, ["npm", "install", f"{parent}@latest"]))
        child = entry["package"]
        target = entry["target_version"]
        if child not in seen_children:
            seen_children.add(child)
            commands.append((child, ["npm", "install", f"{child}@{target}"]))
    # After all upgrades, dedupe to hoist satisfied nested copies
    if seen_parents or seen_children:
        commands.append(("npm dedupe", ["npm", "dedupe"]))
    return commands


def execute_parent_upgrade_fixes(analysis, project_path):
    """Upgrade parent and child dependencies for nested npm residuals."""
    plan = build_npm_parent_upgrade_plan(analysis, project_path)
    commands = build_parent_upgrade_commands(plan)
    if not commands:
        skipped = "; ".join(
            plan.get("skipped")
            or [e.get("note", "") for e in (plan.get("unfixable") or [])]
            or ["没有可升级的父依赖"]
        )
        return [], [("npm parent-upgrade", skipped)]

    print("  已生成升级计划:")
    for entry in plan.get("upgrades") or []:
        print(
            f"    - {entry['upgrade_package']}@latest + "
            f"{entry['package']}@{entry['target_version']} "
            f"(清理 {entry['immediate_parent']} > {entry['package']}@{entry['current_version']})"
        )
    for entry in plan.get("unfixable") or []:
        print(
            f"    - ⚠ {entry['parent']} > {entry['package']}@{entry['current_version']}: "
            f"{entry['note']}"
        )

    successes, failures = execute_fixes(commands, project_path)
    if failures:
        return successes, failures

    # Post-upgrade cleanup: delete stale nested entries from lockfile and node_modules,
    # then re-run npm install to force re-resolution.
    lock_path = os.path.join(project_path, "package-lock.json")
    removed = _cleanup_stale_nested(lock_path, project_path, plan)
    if removed:
        print("  正在重新解析 lockfile...")
        ok, err = _run_npm_install(project_path)
        if ok:
            print("  ✅ lockfile 已重新解析")
        else:
            return successes, [("npm install", err)]

    return successes, []


def _cleanup_stale_nested(lock_path, project_path, plan):
    """Remove stale nested lockfile entries and node_modules directories."""
    if not os.path.isfile(lock_path):
        return []
    try:
        with open(lock_path, "r", encoding="utf-8") as f:
            lock_data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []
    packages = lock_data.get("packages") or {}
    removed = []
    for entry in plan.get("upgrades") or []:
        lock_key = entry.get("lock_path")
        if not lock_key or lock_key not in packages:
            continue
        target = _nested_lock_target(project_path, lock_key)
        if not target:
            continue
        del packages[lock_key]
        removed.append(lock_key)
        # Remove the cached nested copy as well; otherwise npm can keep stale
        # node_modules content even after the lockfile path is removed.
        if os.path.exists(target):
            shutil.rmtree(target, ignore_errors=True)
    if removed:
        with open(lock_path, "w", encoding="utf-8") as f:
            json.dump(lock_data, f, indent=2, ensure_ascii=False)
        for item in removed:
            print(f"    - 已清理 {item}")
    return removed


def _nested_lock_target(project_path, lock_key):
    normalized = str(lock_key or "").replace("\\", "/")
    parts = [part for part in normalized.split("/") if part]
    if not parts or parts[0] != "node_modules" or ".." in parts:
        return None
    target = os.path.abspath(os.path.join(project_path, *parts))
    root = os.path.abspath(project_path)
    try:
        if os.path.commonpath([root, target]) != root:
            return None
    except ValueError:
        return None
    return target


def _run_npm_install(project_path):
    """Run npm install and return (ok, error_message)."""
    try:
        result = subprocess.run(
            ["npm", "install"],
            cwd=project_path,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
        )
        if result.returncode == 0:
            return True, ""
        return False, result.stderr.strip() or "npm install failed"
    except FileNotFoundError:
        return False, "npm not found"


# ---------------------------------------------------------------------------
# Execute fixes
# ---------------------------------------------------------------------------


def execute_fixes(commands, project_path):
    """Run upgrade commands sequentially. Returns (successes, failures)."""
    successes = []
    failures = []
    for pkg, cmd in commands:
        try:
            result = subprocess.run(
                cmd,
                cwd=project_path,
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
            )
            if result.returncode == 0:
                successes.append(pkg)
                logger.info("修复成功: %s", " ".join(cmd))
                print(f"  ✅ {' '.join(cmd)}")
            else:
                err_msg = result.stderr.strip() or "unknown error"
                failures.append((pkg, err_msg))
                logger.error("修复失败: %s — %s", " ".join(cmd), err_msg[:200])
                print(f"  ❌ {' '.join(cmd)}")
                if result.stderr:
                    for line in result.stderr.strip().split("\n")[:3]:
                        print(f"     {line}")
        except FileNotFoundError:
            err_msg = f"command not found: {cmd[0]}"
            failures.append((pkg, err_msg))
            logger.error("修复失败: %s 未安装", cmd[0])
            print(f"  ❌ {cmd[0]} 未安装")
    return successes, failures


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Execute selected Butian dependency fixes"
    )
    parser.add_argument(
        "analysis_json", help="path to .butian/<run>/assets/analysis.json"
    )
    parser.add_argument(
        "--strategy",
        required=True,
        choices=[
            "fixed",
            "minimal",
            "latest",
            "parent-upgrade",
            "force-residual",
            "dependabot",
        ],
        help=(
            "'fixed'/'minimal' upgrades to known fixed versions; "
            "'latest' upgrades to latest versions; "
            "'parent-upgrade' upgrades root parent dependencies for nested residuals; "
            "'force-residual' forces override versions for untraceable nested residuals; "
            "'dependabot' creates generated .github/dependabot.yml"
        ),
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="actually execute the generated fix plan; omitted means dry-run",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the generated fix plan without modifying the project",
    )
    return parser.parse_args(argv)


def strategy_label(strategy):
    if strategy in {"fixed", "minimal"}:
        return "升级到已修复版本"
    if strategy == "latest":
        return "全部依赖升级到最新版本"
    if strategy == "parent-upgrade":
        return "升级父依赖"
    if strategy == "force-residual":
        return "强制覆盖残留依赖"
    if strategy == "dependabot":
        return "创建 Dependabot 配置"
    return "升级到最新版本"


def normalize_strategy(strategy):
    return "minimal" if strategy == "fixed" else strategy


def should_execute(args):
    """Return True only when the user explicitly opted into mutation.

    Dry-run is the safety boundary for the standalone CLI; AskUserQuestion
    confirmation happens before callers pass --yes.
    """
    return bool(getattr(args, "yes", False)) and not bool(
        getattr(args, "dry_run", False)
    )


def print_execution_plan(strategy, project_path, commands=None, note=""):
    label = strategy_label(strategy)
    print()
    print(f"执行计划：{label}")
    print(f"项目路径：{project_path}")
    if note:
        print(f"说明：{note}")
    if commands:
        print("将执行的命令：")
        for pkg, cmd in commands:
            print(f"  - {pkg}: {' '.join(cmd)}")
    else:
        print("将根据 analysis.json 计算需要修改的项目文件或依赖。")
    print()
    print(
        "默认不会修改项目。确认无误后追加 --yes 才会真正执行；"
        "使用 --dry-run 可显式只看计划。"
    )


def post_fix_guidance(strategy):
    """Return human-readable guidance for the required verification scan."""
    if strategy == "latest":
        return [
            "全部依赖已升级到最新版本，请重新运行补天扫描验证结果。",
            "跨大版本升级可能引入兼容性变化；请运行项目测试、构建或启动检查。",
            "如果复扫仍出现同名旧版本（通常来自嵌套依赖），报告会标注父依赖信息。",
        ]
    if strategy == "parent-upgrade":
        return [
            "父依赖和子依赖升级已完成，请重新运行补天扫描验证结果。",
            "升级后复扫会生成新报告，打开 HTML 报告查看最终修复状态。",
            "部分父依赖升到 latest 可能带来兼容性变化；请运行项目测试、构建或启动检查。",
            "如果复扫仍有残留（通常来自无法追溯的间接依赖），需要等待上游修复或人工评估。",
        ]
    if strategy == "force-residual":
        return [
            "强制覆盖已完成，请重新运行补天扫描验证结果。",
            "npm overrides 已写入 package.json，强制所有嵌套实例使用指定版本。",
            "请运行项目测试、构建或启动检查，确认 overrides 不会导致兼容性问题。",
            "overrides 是永久性的版本约束，已记录在 package.json 中，后续 npm install 会自动遵守。",
        ]
    if strategy == "dependabot":
        return [
            "Dependabot 配置创建成功后，请提交 .github/dependabot.yml 到 GitHub。",
            "推送后 GitHub 会按 schedule 检查对应生态，并为可更新依赖创建 PR。",
            "如仓库使用私有 registry，需要再按 GitHub 文档补充 registries 和凭据配置。",
        ]
    label = strategy_label(strategy)
    return [
        f"{label}已完成，请重新运行补天扫描验证结果。",
        "本脚本只执行普通包管理器升级，不会自动改父依赖链。",
        "如果复扫仍出现同名旧版本，报告会标注父依赖信息，可继续升级父依赖。",
    ]


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)

    with open(args.analysis_json, "r", encoding="utf-8") as f:
        analysis = json.load(f)

    strategy = normalize_strategy(args.strategy)
    project_path = analysis.get("project", {}).get("path") or "."

    # latest upgrades all detected dependencies and is not a targeted advisory fix.
    if strategy == "latest":
        commands = build_all_latest_commands(project_path)
        if not commands:
            logger.info("未发现可升级的依赖")
            print("没有发现可升级的依赖。")
            return 0
        if not should_execute(args):
            print_execution_plan(strategy, project_path, commands)
            return 0
        print()
        label = strategy_label(strategy)
        logger.info("开始%s: 升级全部依赖到最新版本", label)
        print(f"正在执行{label}...")
        successes, failures = execute_fixes(commands, project_path)
        logger.info("升级完成: %d 成功, %d 失败", len(successes), len(failures))
        print()
        if successes:
            print(f"  成功升级 {len(successes)} 个包")
        if failures:
            print(f"  失败 {len(failures)} 个:")
            for pkg, err in failures:
                print(f"    - {pkg}: {err}")
        print()
        for line in post_fix_guidance(strategy):
            print(f"  {line}")
        return 1 if failures else 0

    # parent-upgrade follows a rescan-confirmed npm nested residual.
    if strategy == "parent-upgrade":
        if not should_execute(args):
            print_execution_plan(
                strategy,
                project_path,
                note="会分析 npm package-lock.json 中的父依赖链，并升级相关父依赖。",
            )
            return 0
        print()
        print("正在升级父依赖和残留子依赖到最新版本...")
        successes, failures = execute_parent_upgrade_fixes(analysis, project_path)
        print()
        if successes:
            print(f"  成功升级 {len(successes)} 个依赖")
        if failures:
            print(f"  失败 {len(failures)} 个:")
            for pkg, err in failures:
                print(f"    - {pkg}: {err}")
        print()
        for line in post_fix_guidance(strategy):
            print(f"  {line}")
        return 1 if failures else 0

    # force-residual leaves package.json policy behind and must stay explicit.
    if strategy == "force-residual":
        if not should_execute(args):
            print_execution_plan(
                strategy,
                project_path,
                note="会写入 package.json overrides，并重新运行 npm install。",
            )
            return 0
        print()
        print("正在通过 npm overrides 强制覆盖残留依赖...")
        successes, failures = execute_force_residual_fixes(analysis, project_path)
        print()
        if successes:
            print(f"  成功覆盖 {len(successes)} 个依赖")
        if failures:
            print(f"  失败 {len(failures)} 个:")
            for pkg, err in failures:
                print(f"    - {pkg}: {err}")
        print()
        for line in post_fix_guidance(strategy):
            print(f"  {line}")
        return 1 if failures else 0

    # dependabot writes governance configuration, not dependency upgrade output.
    if strategy == "dependabot":
        if not should_execute(args):
            items = extract_dependabot_config_items(analysis)
            commands = [
                (item.get("path") or ".github/dependabot.yml", ["write-file"])
                for item in items
            ]
            print_execution_plan(
                strategy,
                project_path,
                commands,
                note="会创建缺失的 Dependabot 配置文件，不会覆盖已有文件。",
            )
            return 0
        print()
        print("正在创建 Dependabot 配置...")
        successes, failures = execute_dependabot_config_fixes(analysis, project_path)
        print()
        if successes:
            print(f"  成功创建 {len(successes)} 个文件")
        if failures:
            print(f"  失败 {len(failures)} 个:")
            for path, err in failures:
                print(f"    - {path}: {err}")
        print()
        if successes:
            for line in post_fix_guidance(strategy):
                print(f"  {line}")
        elif failures:
            print("  未创建 Dependabot 配置，请先处理上面的失败原因。")
        return 1 if failures else 0

    # minimal/fixed is the targeted path generated from analysis fix_config.
    fix_items = extract_fixable_items(analysis)
    if not fix_items:
        logger.info("未发现可修复的漏洞")
        print("没有发现可修复的漏洞。")
        return 0

    commands = build_upgrade_commands(fix_items, strategy, project_path=project_path)

    if not commands:
        logger.info("没有匹配到可执行的升级命令")
        print("没有匹配到可执行的升级命令。")
        return 0

    if not should_execute(args):
        print_execution_plan(strategy, project_path, commands)
        return 0

    print()
    label = strategy_label(strategy)
    logger.info("开始%s: %d 个包", label, len(commands))
    print(f"正在执行{label}...")

    successes, failures = execute_fixes(commands, project_path)

    logger.info("修复完成: %d 成功, %d 失败", len(successes), len(failures))
    print()
    if successes:
        print(f"  成功升级 {len(successes)} 个包")
    if failures:
        print(f"  失败 {len(failures)} 个:")
        for pkg, err in failures:
            print(f"    - {pkg}: {err}")
    print()
    for line in post_fix_guidance(strategy):
        print(f"  {line}")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main() or 0)
