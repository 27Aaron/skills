#!/usr/bin/env python3
"""通过 SSH 只读采集 Linux 服务器 inventory。"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import shlex
import subprocess
import sys
import time
from typing import Any


def command_plan(include_docker_metadata: bool = False) -> list[dict[str, str]]:
    """返回采集 inventory 使用的受限远程命令。

    只读 SSH 采集绝不能安装、升级、重启、使用 sudo，
    也不能进入容器文件系统。Docker 模式只读取宿主机可见元数据。
    """
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
            "id": "sshd_config",
            "command": "if command -v sshd >/dev/null 2>&1; then out=$(sshd -T 2>&1); rc=$?; if [ \"$rc\" -eq 0 ]; then printf '%s\\n' \"$out\" | awk 'tolower($1) ~ /^(passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|permitrootlogin|permitemptypasswords)$/ {print}'; else printf '%s\\n' \"$out\" >&2; exit \"$rc\"; fi; else awk 'tolower($1) ~ /^(passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|permitrootlogin|permitemptypasswords)$/ {print}' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null; fi",
        },
        {
            "id": "ufw_status",
            "command": "if command -v ufw >/dev/null 2>&1; then ufw status verbose; fi",
        },
        {
            "id": "firewalld_status",
            "command": "if command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --state; firewall-cmd --list-all; fi",
        },
        {
            "id": "nft_rules",
            "command": "if command -v nft >/dev/null 2>&1; then nft list ruleset; fi",
        },
        {
            "id": "iptables_rules",
            "command": "if command -v iptables >/dev/null 2>&1; then iptables -S; fi",
        },
        {
            "id": "ip6tables_rules",
            "command": "if command -v ip6tables >/dev/null 2>&1; then ip6tables -S; fi",
        },
        {
            "id": "nginx_v",
            "command": "if command -v nginx >/dev/null 2>&1; then nginx -v 2>&1; fi",
        },
        {
            "id": "apache_v",
            "command": "if command -v apache2 >/dev/null 2>&1; then apache2 -v 2>&1; elif command -v httpd >/dev/null 2>&1; then httpd -v 2>&1; fi",
        },
        {
            "id": "caddy_v",
            "command": "if command -v caddy >/dev/null 2>&1; then caddy version 2>&1; fi",
        },
        {
            "id": "tomcat_v",
            "command": "if command -v catalina.sh >/dev/null 2>&1; then catalina.sh version 2>&1; elif command -v version.sh >/dev/null 2>&1; then version.sh 2>&1; fi",
        },
        {
            "id": "openssl_v",
            "command": "if command -v openssl >/dev/null 2>&1; then openssl version -a; fi",
        },
        {
            "id": "gnutls_v",
            "command": "if command -v gnutls-cli >/dev/null 2>&1; then gnutls-cli --version 2>&1; fi",
        },
        {
            "id": "ssh_v",
            "command": "if command -v ssh >/dev/null 2>&1; then ssh -V 2>&1; fi",
        },
        {
            "id": "mysql_v",
            "command": "if command -v mysql >/dev/null 2>&1; then mysql --version 2>&1; fi",
        },
        {
            "id": "mariadb_v",
            "command": "if command -v mariadb >/dev/null 2>&1; then mariadb --version 2>&1; fi",
        },
        {
            "id": "postgres_v",
            "command": "if command -v psql >/dev/null 2>&1; then psql --version 2>&1; fi",
        },
        {
            "id": "mongo_v",
            "command": "if command -v mongod >/dev/null 2>&1; then mongod --version 2>&1; fi",
        },
        {
            "id": "redis_v",
            "command": "if command -v redis-server >/dev/null 2>&1; then redis-server --version 2>&1; fi",
        },
        {
            "id": "elasticsearch_v",
            "command": "if command -v elasticsearch >/dev/null 2>&1; then elasticsearch --version 2>&1; fi",
        },
        {
            "id": "docker_version",
            "command": "if command -v docker >/dev/null 2>&1; then docker --version 2>&1; fi",
        },
        {
            "id": "containerd_v",
            "command": "if command -v containerd >/dev/null 2>&1; then containerd --version 2>&1; fi",
        },
        {
            "id": "runc_v",
            "command": "if command -v runc >/dev/null 2>&1; then runc --version 2>&1; fi",
        },
        {
            "id": "podman_v",
            "command": "if command -v podman >/dev/null 2>&1; then podman --version 2>&1; fi",
        },
        {
            "id": "node_v",
            "command": "if command -v node >/dev/null 2>&1; then node --version 2>&1; fi",
        },
        {
            "id": "python_v",
            "command": "if command -v python3 >/dev/null 2>&1; then python3 --version 2>&1; elif command -v python >/dev/null 2>&1; then python --version 2>&1; fi",
        },
        {
            "id": "java_v",
            "command": "if command -v java >/dev/null 2>&1; then java -version 2>&1; fi",
        },
        {
            "id": "php_v",
            "command": "if command -v php >/dev/null 2>&1; then php -v 2>&1; fi",
        },
        {
            "id": "ruby_v",
            "command": "if command -v ruby >/dev/null 2>&1; then ruby -v 2>&1; fi",
        },
        {
            "id": "go_v",
            "command": "if command -v go >/dev/null 2>&1; then go version 2>&1; fi",
        },
        {
            "id": "rabbitmq_v",
            "command": "if command -v rabbitmqctl >/dev/null 2>&1; then rabbitmqctl version 2>&1; fi",
        },
        {
            "id": "kafka_v",
            "command": "if command -v kafka-topics.sh >/dev/null 2>&1; then kafka-topics.sh --version 2>&1; elif command -v kafka-server-start.sh >/dev/null 2>&1; then kafka-server-start.sh --version 2>&1; fi",
        },
        {
            "id": "haproxy_v",
            "command": "if command -v haproxy >/dev/null 2>&1; then haproxy -v 2>&1; fi",
        },
        {
            "id": "envoy_v",
            "command": "if command -v envoy >/dev/null 2>&1; then envoy --version 2>&1; fi",
        },
        {
            "id": "traefik_v",
            "command": "if command -v traefik >/dev/null 2>&1; then traefik version 2>&1; fi",
        },
        {
            "id": "git_v",
            "command": "if command -v git >/dev/null 2>&1; then git --version 2>&1; fi",
        },
        {
            "id": "curl_v",
            "command": "if command -v curl >/dev/null 2>&1; then curl --version 2>&1; fi",
        },
        {
            "id": "wget_v",
            "command": "if command -v wget >/dev/null 2>&1; then wget --version 2>&1; fi",
        },
        {
            "id": "cron_v",
            "command": "if command -v cron >/dev/null 2>&1; then cron -V 2>&1; elif command -v crond >/dev/null 2>&1; then crond -V 2>&1; fi",
        },
        {
            "id": "systemd_v",
            "command": "if command -v systemctl >/dev/null 2>&1; then systemctl --version 2>&1; fi",
        },
        {
            "id": "grafana_v",
            "command": "if command -v grafana-server >/dev/null 2>&1; then grafana-server -v 2>&1; fi",
        },
        {
            "id": "prometheus_v",
            "command": "if command -v prometheus >/dev/null 2>&1; then prometheus --version 2>&1; fi",
        },
    ]
    if include_docker_metadata:
        commands.extend(
            [
                {
                    "id": "docker_ps",
                    "command": "if command -v docker >/dev/null 2>&1; then docker ps --format '{{json .}}'; fi",
                },
            ]
        )
    return commands


def default_ssh_config_path() -> str:
    return os.path.expanduser("~/.ssh/config")


def _target_looks_unsafe(target: str) -> bool:
    text = str(target or "").strip()
    return (
        not text
        or text.startswith("-")
        or any(char.isspace() for char in text)
        or any(marker in text for marker in ("/", "\\", "*", "?"))
    )


def _normalize_ssh_port(port: int | str) -> int:
    try:
        value = int(port)
    except (TypeError, ValueError) as exc:
        raise ValueError("SSH 端口必须是 1 到 65535 之间的整数。") from exc
    if value < 1 or value > 65535:
        raise ValueError("SSH 端口必须是 1 到 65535 之间的整数。")
    return value


def _read_ssh_config_entries(path: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    with open(path, "r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                parts = shlex.split(line, comments=True)
            except ValueError:
                continue
            if not parts:
                continue
            key = parts[0].lower()
            values = parts[1:]
            if key in {"host", "match"}:
                current = None
                if key == "host" and values:
                    current = {"patterns": values, "options": {}}
                    entries.append(current)
                continue
            if current is None or not values:
                continue
            options = current["options"]
            value = " ".join(values)
            if key == "identityfile":
                options.setdefault(key, []).append(value)
            else:
                options[key] = value
    return entries


def _find_ssh_config_entry(target: str, ssh_config: str = "") -> dict[str, Any]:
    config_path = os.path.abspath(
        os.path.expanduser(ssh_config or default_ssh_config_path())
    )
    if not os.path.exists(config_path):
        return {}
    matched_options: dict[str, Any] = {}
    matched = False
    for entry in _read_ssh_config_entries(config_path):
        patterns = entry.get("patterns", [])
        if not any(fnmatch.fnmatchcase(target, pattern) for pattern in patterns):
            continue
        matched = True
        for key, value in (entry.get("options") or {}).items():
            if key == "identityfile":
                matched_options.setdefault(key, []).extend(value or [])
            elif key not in matched_options:
                matched_options[key] = value
    if not matched:
        return {}
    return {"config": config_path, "options": matched_options}


def resolve_ssh_policy(
    target: str,
    *,
    port: int = 22,
    identity: str = "",
    ssh_config: str = "",
) -> dict[str, Any]:
    ssh_target = str(target or "").strip()
    if _target_looks_unsafe(ssh_target):
        raise ValueError(
            "SSH 目标不能为空，不能以 '-' 开头，也不能包含空白、路径或通配符。"
        )
    ssh_port = _normalize_ssh_port(port)
    policy = {
        "target": ssh_target,
        "port": ssh_port,
        "identity": identity or "",
        "ssh_config": ssh_config or "",
        "options": {},
    }
    matched = _find_ssh_config_entry(ssh_target, ssh_config=ssh_config)
    if matched:
        policy["ssh_config"] = matched.get("config") or policy["ssh_config"]
        policy["options"] = matched.get("options") or {}
    return policy


def _identity_secret_values(policy: dict[str, Any]) -> set[str]:
    values = set()
    identity = str(policy.get("identity") or "").strip()
    if identity:
        values.add(identity)
        values.add(os.path.expanduser(identity))
        values.add(os.path.abspath(os.path.expanduser(identity)))
    for value in (policy.get("options") or {}).get("identityfile") or []:
        text = str(value or "").strip()
        if not text:
            continue
        values.add(text)
        values.add(os.path.expanduser(text))
        values.add(os.path.abspath(os.path.expanduser(text)))
    return values


def _redact_identity_text(value: str, secrets: set[str]) -> str:
    text = str(value or "")
    for secret in sorted(secrets, key=len, reverse=True):
        if secret:
            text = text.replace(secret, "[redacted-identity]")
    return text


def _redact_command_result(result: dict[str, Any], secrets: set[str]) -> dict[str, Any]:
    cleaned = dict(result)
    cleaned["stdout"] = _redact_identity_text(cleaned.get("stdout") or "", secrets)
    cleaned["stderr"] = _redact_identity_text(cleaned.get("stderr") or "", secrets)
    return cleaned


def _ssh_base(
    target: str,
    *,
    port: int = 22,
    identity: str = "",
    ssh_config: str = "",
) -> list[str]:
    ssh_port = _normalize_ssh_port(port)
    cmd = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "PubkeyAuthentication=yes",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "ConnectTimeout=10",
    ]
    if ssh_config:
        cmd.extend(["-F", os.path.abspath(os.path.expanduser(ssh_config))])
    if ssh_port != 22:
        cmd.extend(["-p", str(ssh_port)])
    if identity:
        cmd.extend(["-i", identity, "-o", "IdentitiesOnly=yes"])
    cmd.append(target)
    return cmd


def run_ssh_command(
    target: str,
    remote_command: str,
    *,
    port: int = 22,
    identity: str = "",
    ssh_config: str = "",
    timeout: int = 20,
) -> dict[str, Any]:
    result = subprocess.run(
        [
            *_ssh_base(target, port=port, identity=identity, ssh_config=ssh_config),
            remote_command,
        ],
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
    ssh_config: str = "",
    include_docker_metadata: bool = False,
) -> dict[str, Any]:
    policy = resolve_ssh_policy(
        target, port=port, identity=identity, ssh_config=ssh_config
    )
    ssh_target = policy.get("target") or str(target or "").strip()
    ssh_port = policy.get("port") or port
    ssh_identity = policy.get("identity") or identity
    ssh_config = policy.get("ssh_config") or ssh_config
    identity_secrets = _identity_secret_values(policy)
    outputs = {}
    errors = []
    for item in command_plan(include_docker_metadata=include_docker_metadata):
        try:
            result = run_ssh_command(
                ssh_target,
                item["command"],
                port=ssh_port,
                identity=ssh_identity,
                ssh_config=ssh_config,
            )
        except (subprocess.SubprocessError, OSError) as exc:
            result = {
                "command": item["command"],
                "returncode": 255,
                "stdout": "",
                "stderr": _redact_identity_text(str(exc), identity_secrets),
            }
        result = _redact_command_result(result, identity_secrets)
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
        "target": ssh_target,
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
        "target",
        nargs="?",
        default="",
        help="SSH target, e.g. user@203.0.113.10 or prod-web",
    )
    parser.add_argument(
        "--output", default="", help="Write collected inventory JSON here"
    )
    parser.add_argument("--ssh-port", type=int, default=22, help="SSH port")
    parser.add_argument("--identity", default="", help="SSH private key path")
    parser.add_argument(
        "--ssh-config",
        default="",
        help="Optional SSH config path",
    )
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
        ssh_config=args.ssh_config,
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
