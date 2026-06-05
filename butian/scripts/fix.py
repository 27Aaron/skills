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
    parser = argparse.ArgumentParser(description="Execute selected Butian dependency fixes")
    parser.add_argument("analysis_json", help="path to .butian/<run>/assets/analysis.json")
    parser.add_argument(
        "--strategy",
        required=True,
        choices=["fixed", "minimal", "latest"],
        help="'fixed'/'minimal' upgrades to known fixed versions; 'latest' upgrades to latest versions",
    )
    return parser.parse_args(argv)


def strategy_label(strategy):
    return "升级到已修复版本" if strategy == "minimal" else "升级到最新版本"


def normalize_strategy(strategy):
    return "minimal" if strategy == "fixed" else strategy


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

    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
