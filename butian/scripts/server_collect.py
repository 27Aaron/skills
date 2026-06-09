#!/usr/bin/env python3
"""Collect read-only Linux server inventory over SSH."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from typing import Any


def command_plan(include_docker_metadata: bool = False) -> list[dict[str, str]]:
    commands = [
        {"id": "os_release", "command": "cat /etc/os-release"},
        {"id": "uname_r", "command": "uname -r"},
        {"id": "uname_m", "command": "uname -m"},
        {"id": "hostname", "command": "hostname"},
        {
            "id": "dpkg_packages",
            "command": "if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f='${Package}\\t${Version}\\t${Architecture}\\t${source:Package}\\n'; fi",
        },
        {
            "id": "rpm_packages",
            "command": "if command -v rpm >/dev/null 2>&1; then rpm -qa --queryformat '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n'; fi",
        },
        {
            "id": "apk_packages",
            "command": "if command -v apk >/dev/null 2>&1; then apk info -vv; fi",
        },
        {
            "id": "apt_upgradable",
            "command": "if command -v apt >/dev/null 2>&1; then apt list --upgradable; fi",
        },
        {
            "id": "dnf_updateinfo",
            "command": "if command -v dnf >/dev/null 2>&1; then dnf updateinfo list security; fi",
        },
        {
            "id": "yum_updateinfo",
            "command": "if command -v yum >/dev/null 2>&1; then yum updateinfo list security; fi",
        },
        {
            "id": "zypper_patches",
            "command": "if command -v zypper >/dev/null 2>&1; then zypper --non-interactive list-patches --category security; fi",
        },
        {
            "id": "services",
            "command": "if command -v systemctl >/dev/null 2>&1; then systemctl list-units --type=service --state=running --no-pager; fi",
        },
        {
            "id": "ports",
            "command": "if command -v ss >/dev/null 2>&1; then ss -lntup; elif command -v netstat >/dev/null 2>&1; then netstat -lntup; fi",
        },
        {
            "id": "nginx_v",
            "command": "if command -v nginx >/dev/null 2>&1; then nginx -v 2>&1; fi",
        },
        {
            "id": "openssl_v",
            "command": "if command -v openssl >/dev/null 2>&1; then openssl version -a; fi",
        },
        {
            "id": "ssh_v",
            "command": "if command -v ssh >/dev/null 2>&1; then ssh -V 2>&1; fi",
        },
    ]
    if include_docker_metadata:
        commands.extend(
            [
                {
                    "id": "docker_version",
                    "command": "if command -v docker >/dev/null 2>&1; then docker version --format '{{json .}}'; fi",
                },
                {
                    "id": "docker_ps",
                    "command": "if command -v docker >/dev/null 2>&1; then docker ps --format '{{json .}}'; fi",
                },
            ]
        )
    return commands


def _ssh_base(target: str, port: int = 22, identity: str = "") -> list[str]:
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-p", str(port)]
    if identity:
        cmd.extend(["-i", identity])
    cmd.append(target)
    return cmd


def run_ssh_command(
    target: str,
    remote_command: str,
    *,
    port: int = 22,
    identity: str = "",
    timeout: int = 20,
) -> dict[str, Any]:
    result = subprocess.run(
        [*_ssh_base(target, port=port, identity=identity), remote_command],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=timeout,
    )
    return {
        "command": remote_command,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def collect_server_inventory(
    target: str,
    *,
    port: int = 22,
    identity: str = "",
    include_docker_metadata: bool = False,
) -> dict[str, Any]:
    outputs = {}
    errors = []
    for item in command_plan(include_docker_metadata=include_docker_metadata):
        try:
            result = run_ssh_command(
                target, item["command"], port=port, identity=identity
            )
        except (subprocess.SubprocessError, OSError) as exc:
            result = {
                "command": item["command"],
                "returncode": 255,
                "stdout": "",
                "stderr": str(exc),
            }
        outputs[item["id"]] = result
        if result["returncode"] != 0:
            errors.append(
                {
                    "step": "server_collect",
                    "command_id": item["id"],
                    "message": result["stderr"] or f"returncode {result['returncode']}",
                }
            )
    return {
        "target": target,
        "collected_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "collection_mode": "ssh",
        "outputs": outputs,
        "errors": errors,
    }


def read_inventory_file(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def write_inventory(path: str, data: dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "target", nargs="?", default="", help="SSH target, e.g. user@host"
    )
    parser.add_argument(
        "--output", default="", help="Write collected inventory JSON here"
    )
    parser.add_argument("--ssh-port", type=int, default=22, help="SSH port")
    parser.add_argument("--identity", default="", help="SSH private key path")
    parser.add_argument(
        "--include-docker-metadata",
        action="store_true",
        help="Collect container names, image tags, and port mappings only",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.target:
        raise SystemExit("target is required")
    inventory = collect_server_inventory(
        args.target,
        port=args.ssh_port,
        identity=args.identity,
        include_docker_metadata=args.include_docker_metadata,
    )
    if args.output:
        write_inventory(args.output, inventory)
    else:
        json.dump(inventory, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
