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
import subprocess
import sys

logger = logging.getLogger("butian")

# ---------------------------------------------------------------------------
# Ecosystem → upgrade command builders
# ---------------------------------------------------------------------------

# Maps ecosystem name to a fixed-version upgrade command builder.
# Each builder receives (package, version) and returns a command list.

_UPGRADE_BUILDERS = {
    "npm": lambda pkg, ver: ["npm", "install", f"{pkg}@{ver}"],
    "pnpm": lambda pkg, ver: ["pnpm", "add", f"{pkg}@{ver}"],
    "yarn": lambda pkg, ver: ["yarn", "add", f"{pkg}@{ver}"],
    "pypi": lambda pkg, ver: [sys.executable, "-m", "pip", "install", f"{pkg}=={ver}"],
    "go": lambda pkg, ver: ["go", "get", f"{pkg}@{ver}"],
    "crates-io": lambda pkg, ver: ["cargo", "update", "-p", pkg, "--precise", ver],
}


def _latest_commands(ecosystem, package):
    """Build commands to upgrade a package to its latest version."""
    if ecosystem == "npm":
        return ["npm", "install", f"{package}@latest"]
    if ecosystem == "pnpm":
        return ["pnpm", "add", f"{package}@latest"]
    if ecosystem == "yarn":
        return ["yarn", "add", f"{package}@latest"]
    if ecosystem == "pypi":
        return [sys.executable, "-m", "pip", "install", "--upgrade", package]
    if ecosystem == "go":
        return ["go", "get", f"{package}@latest"]
    if ecosystem == "crates-io":
        return ["cargo", "update", "-p", package]
    return None


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


# ---------------------------------------------------------------------------
# Build upgrade commands
# ---------------------------------------------------------------------------


def build_upgrade_commands(fix_items, strategy, ecosystem=None):
    """Build upgrade commands for fixable items.

    Args:
        fix_items: list from extract_fixable_items()
        strategy: "minimal" | "latest"
        ecosystem: if set, filter to this ecosystem only

    Returns:
        list of (package, command_list) tuples
    """
    commands = []
    for item in fix_items:
        eco = item.get("ecosystem")
        if ecosystem and eco != ecosystem:
            continue
        pkg = item["package"]
        builder = _UPGRADE_BUILDERS.get(eco)
        if not builder:
            continue

        if strategy == "minimal":
            ver = item["target_version"]
            cmd = builder(pkg, ver)
        elif strategy == "latest":
            cmd = _latest_commands(eco, pkg)
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
        path = f"{path}/node_modules/{name_path}" if path else f"node_modules/{name_path}"
    return path


def _npm_parent_lock_path(path):
    names = _npm_names_from_lock_path(path)
    if len(names) <= 1:
        return ""
    return _npm_lock_path_for_names(names[:-1])


def _npm_dep_lock_path_from(package_key, dependency):
    dep_path = dependency.replace("/", os.sep).replace(os.sep, "/")
    return f"{package_key}/node_modules/{dep_path}" if package_key else f"node_modules/{dep_path}"


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
            for dep_name in (meta.get("dependencies") or {}):
                dep_path = _resolve_npm_dependency(packages, current, dep_name)
                if dep_path and dep_path not in seen:
                    stack.append(dep_path)
    return None


def _load_json_file(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def build_npm_parent_upgrade_plan(analysis, project_path=None):
    """Build npm parent-upgrade actions for vulnerable nested lockfile entries."""
    project_path = project_path or (analysis.get("project") or {}).get("path") or "."
    lock_path = os.path.join(project_path, "package-lock.json")
    package_json_path = os.path.join(project_path, "package.json")
    plan = {"upgrades": [], "child_updates": [], "skipped": []}
    if not os.path.isfile(lock_path):
        plan["skipped"].append("未找到 package-lock.json，无法自动分析父依赖。")
        return plan

    lock_data = _load_json_file(lock_path)
    package_json = _load_json_file(package_json_path) if os.path.isfile(package_json_path) else {}
    packages = lock_data.get("packages") or {}
    fix_items = {
        item["package"]: item
        for item in extract_fixable_items(analysis)
        if item.get("ecosystem") == "npm" and item.get("package")
    }
    seen = set()
    child_seen = set()
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
            plan["skipped"].append(
                f"{parent} > {package}@{version} 无法追溯到 package.json 中的根父依赖。"
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
        if package not in child_seen:
            child_seen.add(package)
            plan["child_updates"].append(package)
    return plan


def build_parent_upgrade_commands(plan):
    commands = []
    seen_parents = set()
    seen_children = set()
    for entry in plan.get("upgrades") or []:
        # Upgrade parent dependency to latest
        parent = entry["upgrade_package"]
        if parent not in seen_parents:
            seen_parents.add(parent)
            commands.append((parent, ["npm", "install", f"{parent}@latest"]))
        # Upgrade child dependency to latest
        child = entry["package"]
        if child not in seen_children:
            seen_children.add(child)
            commands.append((child, ["npm", "install", f"{child}@latest"]))
    return commands


def execute_parent_upgrade_fixes(analysis, project_path):
    """Upgrade parent and child dependencies to latest for nested npm residuals."""
    plan = build_npm_parent_upgrade_plan(analysis, project_path)
    commands = build_parent_upgrade_commands(plan)
    if not commands:
        skipped = "; ".join(plan.get("skipped") or ["没有可升级的父依赖"])
        return [], [("npm parent-upgrade", skipped)]
    print("  已生成升级计划:")
    for entry in plan.get("upgrades") or []:
        print(
            "    - "
            f"{entry['upgrade_package']}@latest + "
            f"{entry['package']}@latest "
            f"(清理 {entry['immediate_parent']} > {entry['package']}@{entry['current_version']})"
        )
    return execute_fixes(commands, project_path)


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
        choices=["fixed", "minimal", "latest", "parent-upgrade"],
        help=(
            "'fixed'/'minimal' upgrades to known fixed versions; "
            "'latest' upgrades to latest versions; "
            "'parent-upgrade' upgrades root parent dependencies for nested residuals"
        ),
    )
    return parser.parse_args(argv)


def strategy_label(strategy):
    if strategy in {"fixed", "minimal"}:
        return "升级到已修复版本"
    if strategy == "parent-upgrade":
        return "升级父依赖"
    return "升级到最新版本"


def normalize_strategy(strategy):
    return "minimal" if strategy == "fixed" else strategy


def post_fix_guidance(strategy):
    """Return human-readable guidance for the required verification scan."""
    if strategy == "parent-upgrade":
        return [
            "父依赖和子依赖已升级到最新版本，请重新运行补天扫描验证结果。",
            "升级后复扫会生成新报告，打开 HTML 报告查看最终修复状态。",
            "父依赖和子依赖都升到 latest 可能带来兼容性变化；请运行项目测试、构建或启动检查。",
            "如果复扫仍有残留，说明上游父依赖最新版可能仍未放开该子依赖，需要等待上游修复或人工评估。",
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

    fix_items = extract_fixable_items(analysis)
    if not fix_items:
        logger.info("未发现可修复的漏洞")
        print("没有发现可修复的漏洞。")
        return 0

    strategy = normalize_strategy(args.strategy)
    project_path = analysis.get("project", {}).get("path") or "."
    if strategy == "parent-upgrade":
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
        return 0

    commands = build_upgrade_commands(fix_items, strategy)

    if not commands:
        logger.info("没有匹配到可执行的升级命令")
        print("没有匹配到可执行的升级命令。")
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

    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
