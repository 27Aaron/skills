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
# npm overrides for confirmed forced updates
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


def build_npm_override_plan(analysis, project_path=None):
    """Build parent-scoped npm overrides for vulnerable nested lockfile entries."""
    project_path = project_path or (analysis.get("project") or {}).get("path") or "."
    lock_path = os.path.join(project_path, "package-lock.json")
    plan = {"overrides": [], "global_overrides": [], "skipped": []}
    if not os.path.isfile(lock_path):
        plan["skipped"].append("未找到 package-lock.json，无法自动生成 npm overrides。")
        return plan

    with open(lock_path, "r", encoding="utf-8") as handle:
        lock_data = json.load(handle)
    packages = lock_data.get("packages") or {}
    fix_items = {
        item["package"]: item
        for item in extract_fixable_items(analysis)
        if item.get("ecosystem") == "npm" and item.get("package")
    }
    seen = set()
    global_seen = set()
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
                f"{package}@{version} 是顶层依赖，普通升级应优先处理，不自动添加 overrides。"
            )
            continue
        key = (parent, package, item["target_version"])
        if key in seen:
            continue
        seen.add(key)
        plan["overrides"].append(
            {
                "parent": parent,
                "package": package,
                "current_version": version,
                "target_version": item["target_version"],
                "lock_path": lock_key,
            }
        )
        global_key = (package, item["target_version"])
        if global_key not in global_seen:
            global_seen.add(global_key)
            plan["global_overrides"].append(
                {
                    "package": package,
                    "target_version": item["target_version"],
                }
            )
    return plan


def _root_dependency_spec(package_json, package):
    for key in (
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ):
        deps = package_json.get(key) or {}
        if isinstance(deps, dict) and package in deps:
            return deps[package]
    return None


def apply_npm_overrides(project_path, plan):
    """Write parent-scoped overrides into package.json. Returns True when changed."""
    entries = plan.get("overrides") or []
    global_entries = plan.get("global_overrides") or []
    if not entries and not global_entries:
        return False
    package_json_path = os.path.join(project_path, "package.json")
    with open(package_json_path, "r", encoding="utf-8") as handle:
        package_json = json.load(handle)

    overrides = package_json.setdefault("overrides", {})
    if not isinstance(overrides, dict):
        raise ValueError(
            "package.json overrides must be an object before Butian can update it"
        )

    changed = False
    for entry in entries:
        parent = entry["parent"]
        package = entry["package"]
        target_version = entry["target_version"]
        parent_override = overrides.get(parent)
        if parent_override is None:
            overrides[parent] = {package: target_version}
            changed = True
            continue
        if not isinstance(parent_override, dict):
            overrides[parent] = {".": parent_override, package: target_version}
            changed = True
            continue
        if parent_override.get(package) != target_version:
            parent_override[package] = target_version
            changed = True

    for entry in global_entries:
        package = entry["package"]
        target_version = entry["target_version"]
        target_spec = (
            f"${package}"
            if _root_dependency_spec(package_json, package)
            else target_version
        )
        if overrides.get(package) != target_spec:
            overrides[package] = target_spec
            changed = True

    if changed:
        with open(package_json_path, "w", encoding="utf-8") as handle:
            json.dump(package_json, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
    return changed


def _run_npm_install(project_path):
    result = subprocess.run(
        ["npm", "install"],
        cwd=project_path,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        return False, result.stderr.strip() or "npm install failed"
    return True, ""


def execute_override_fixes(analysis, project_path):
    """Apply confirmed npm overrides and refresh the lockfile."""
    plan = build_npm_override_plan(analysis, project_path)
    if not plan.get("overrides"):
        skipped = "; ".join(plan.get("skipped") or ["没有可写入的 overrides"])
        return [], [("npm overrides", skipped)]

    try:
        changed = apply_npm_overrides(project_path, plan)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [], [("package.json", str(exc))]

    successes = [
        f"{entry['parent']} > {entry['package']}@{entry['target_version']}"
        for entry in plan["overrides"]
    ]
    if changed:
        print("  已写入 package.json overrides:")
        for item in successes:
            print(f"    - {item}")
    else:
        print("  package.json overrides 已包含目标规则。")

    ok, err_msg = _run_npm_install(project_path)
    if not ok:
        return [], [("npm install", err_msg)]
    print("  ✅ npm install")
    residual_plan = build_npm_override_plan(analysis, project_path)
    if residual_plan.get("overrides"):
        lock_path = os.path.join(project_path, "package-lock.json")
        print("  检测到 lockfile 中仍有嵌套旧版本，正在重建 package-lock.json...")
        try:
            os.remove(lock_path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            return [], [("package-lock.json", str(exc))]
        ok, err_msg = _run_npm_install(project_path)
        if not ok:
            return [], [("npm install", err_msg)]
        print("  ✅ package-lock.json 已重建")
        final_plan = build_npm_override_plan(analysis, project_path)
        if final_plan.get("overrides"):
            remaining = ", ".join(
                f"{entry['parent']} > {entry['package']}@{entry['current_version']}"
                for entry in final_plan["overrides"]
            )
            return successes, [("npm overrides", f"强制更新后仍有残留: {remaining}")]
    return successes, []


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
        choices=["fixed", "minimal", "latest", "overrides"],
        help=(
            "'fixed'/'minimal' upgrades to known fixed versions; "
            "'latest' upgrades to latest versions; "
            "'overrides' applies confirmed npm overrides for nested residuals"
        ),
    )
    return parser.parse_args(argv)


def strategy_label(strategy):
    if strategy in {"fixed", "minimal"}:
        return "升级到已修复版本"
    if strategy == "overrides":
        return "强制覆盖更新"
    return "升级到最新版本"


def normalize_strategy(strategy):
    return "minimal" if strategy == "fixed" else strategy


def post_fix_guidance(strategy):
    """Return human-readable guidance for the required verification scan."""
    if strategy == "overrides":
        return [
            "强制覆盖更新已执行完毕后，请重新运行补天扫描验证结果。",
            "这会强制改变父依赖解析到的子依赖版本，可能带来兼容性问题；请运行项目测试、构建或启动检查。",
            "如果复扫仍有残留，需要继续追踪父依赖版本或等待上游发布修复。",
        ]
    label = strategy_label(strategy)
    return [
        f"{label}已执行完毕后，请重新运行补天扫描验证结果。",
        "本脚本只执行普通包管理器升级，不会自动改父依赖链，也不会自动添加 overrides/resolutions。",
        "如果复扫仍出现同名旧版本，通常是间接依赖被父包锁定；需要升级父依赖、等待上游修复，或询问用户是否确认强制覆盖更新。",
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
    if strategy == "overrides":
        print()
        print("正在执行强制覆盖更新...")
        successes, failures = execute_override_fixes(analysis, project_path)
        print()
        if successes:
            print(f"  成功写入 {len(successes)} 条 overrides 并刷新 lockfile")
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
