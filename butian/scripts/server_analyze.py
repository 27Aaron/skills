#!/usr/bin/env python3
"""Build reportable server analysis from assets and vulnerability matches."""

from __future__ import annotations

import os
import re
from typing import Any

SENSITIVE_PUBLIC_SERVICE_ALIASES = {
    "redis-server": "redis",
    "redis": "redis",
    "mysqld": "mysql",
    "mysql": "mysql",
    "mariadbd": "mariadb",
    "mariadb": "mariadb",
    "postgres": "postgresql",
    "postgresql": "postgresql",
    "postmaster": "postgresql",
    "mongod": "mongodb",
    "mongodb": "mongodb",
    "memcached": "memcached",
    "elasticsearch": "elasticsearch",
}

SENSITIVE_PUBLIC_PORTS = {
    6379: "redis",
    3306: "mysql",
    5432: "postgresql",
    27017: "mongodb",
    11211: "memcached",
    9200: "elasticsearch",
}


def docker_maintenance_items(containers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items = []
    for container in containers or []:
        if not container.get("explicit_old_tag"):
            continue
        image = container.get("image") or ""
        name = container.get("name") or "-"
        items.append(
            {
                "scope": "server",
                "category": "docker_image_maintenance",
                "severity": "low",
                "confidence": "maintenance",
                "title": f"Docker 容器 {name} 使用旧镜像标签 {image}",
                "summary": "该结论只基于容器名和显式镜像标签，不扫描容器内部文件系统，也不确认容器内 CVE。",
                "evidence": [f"docker ps 显示镜像 {image}"],
                "recommendation": "建议升级镜像标签，或使用专门的镜像扫描流程单独确认。",
            }
        )
    return items


def _process_basename(process: str) -> str:
    text = str(process or "").lower().strip()
    text = text.split()[0] if text else ""
    text = os.path.basename(text)
    return re.sub(r"[^a-z0-9_.:-].*$", "", text)


def _sensitive_service_name(process: str, port: int | None = None) -> str:
    normalized = _process_basename(process)
    if normalized in SENSITIVE_PUBLIC_SERVICE_ALIASES:
        return SENSITIVE_PUBLIC_SERVICE_ALIASES[normalized]
    for alias, service in SENSITIVE_PUBLIC_SERVICE_ALIASES.items():
        if normalized.startswith(f"{alias}-") or normalized.startswith(f"{alias}:"):
            return service
    if port in SENSITIVE_PUBLIC_PORTS:
        return SENSITIVE_PUBLIC_PORTS[int(port)]
    return ""


def public_service_maintenance_items(
    ports: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    items = []
    seen = set()
    for port in ports or []:
        port_number = port.get("port")
        try:
            port_number = int(port_number) if port_number is not None else None
        except (TypeError, ValueError):
            port_number = None
        service = _sensitive_service_name(str(port.get("process") or ""), port_number)
        if not port.get("public") or not service:
            continue
        key = (service, port.get("address"), port_number)
        if key in seen:
            continue
        seen.add(key)
        items.append(
            {
                "scope": "server",
                "category": "public_sensitive_service",
                "severity": "low",
                "confidence": "maintenance",
                "service": service,
                "title": f"{service} 服务对公网监听 {port.get('address')}:{port_number}",
                "summary": "本次未确认该服务存在 CVE，但该端口暴露需要确认防火墙、安全组和认证配置。",
                "evidence": [
                    port.get("raw")
                    or f"{port.get('process') or service} {port.get('address')}:{port_number}"
                ],
                "recommendation": "建议确认网络访问控制和服务认证配置。",
            }
        )
    return items


def _has_public_ssh_port(ports: list[dict[str, Any]]) -> bool:
    for port in ports or []:
        process = _process_basename(str(port.get("process") or ""))
        port_number = port.get("port")
        try:
            port_number = int(port_number) if port_number is not None else None
        except (TypeError, ValueError):
            port_number = None
        if port.get("public") and (port_number == 22 or process.startswith("sshd")):
            return True
    return False


def _maintenance_item(
    *,
    category: str,
    title: str,
    summary: str,
    evidence: list[str],
    recommendation: str,
    severity: str = "low",
) -> dict[str, Any]:
    return {
        "scope": "server",
        "category": category,
        "severity": severity,
        "confidence": "maintenance",
        "title": title,
        "summary": summary,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def ssh_maintenance_items(
    ssh: dict[str, Any], ports: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    options = ssh.get("options") or {}
    if not options:
        return []
    items = []
    public_ssh = _has_public_ssh_port(ports)
    password_auth = str(options.get("PasswordAuthentication") or "").lower()
    keyboard_auth = str(options.get("KbdInteractiveAuthentication") or "").lower()
    pubkey_auth = str(options.get("PubkeyAuthentication") or "").lower()
    root_login = str(options.get("PermitRootLogin") or "").lower()
    empty_passwords = str(options.get("PermitEmptyPasswords") or "").lower()

    if password_auth == "yes":
        items.append(
            _maintenance_item(
                category="ssh_password_authentication",
                title="SSH 允许密码登录",
                summary="这不是已确认 CVE，但公网服务器保留密码登录会增加弱密码和爆破风险。",
                evidence=["PasswordAuthentication yes"],
                recommendation="建议确认密钥登录可用后，将 PasswordAuthentication 调整为 no。",
                severity="medium" if public_ssh else "low",
            )
        )
    if keyboard_auth == "yes":
        items.append(
            _maintenance_item(
                category="ssh_keyboard_interactive_authentication",
                title="SSH 允许交互式认证",
                summary="交互式认证可能继续通过 PAM 或二次认证流程接受密码类登录，需要结合实际登录方案确认。",
                evidence=["KbdInteractiveAuthentication yes"],
                recommendation="如果没有 PAM、二次验证或堡垒机集成需求，建议关闭交互式认证。",
            )
        )
    if pubkey_auth == "no":
        items.append(
            _maintenance_item(
                category="ssh_pubkey_authentication",
                title="SSH 未启用密钥登录",
                summary="密钥登录通常比密码登录更适合公开服务器，也便于后续关闭密码登录。",
                evidence=["PubkeyAuthentication no"],
                recommendation="建议启用 PubkeyAuthentication，并为日常账号配置 authorized_keys。",
                severity="medium",
            )
        )
    if root_login == "yes":
        items.append(
            _maintenance_item(
                category="ssh_root_login",
                title="root 账号允许直接 SSH 登录",
                summary="root 直接登录会放大凭证泄漏或爆破成功后的影响范围。",
                evidence=["PermitRootLogin yes"],
                recommendation="建议改为普通用户密钥登录后按需提权，或至少禁止 root 密码登录。",
                severity="medium" if public_ssh else "low",
            )
        )
    if empty_passwords == "yes":
        items.append(
            _maintenance_item(
                category="ssh_empty_passwords",
                title="SSH 允许空密码登录",
                summary="空密码登录属于高风险配置，即使只作为维护建议也应优先确认。",
                evidence=["PermitEmptyPasswords yes"],
                recommendation="建议立即将 PermitEmptyPasswords 调整为 no，并确认系统账号不存在空密码。",
                severity="medium",
            )
        )
    return items


def firewall_maintenance_items(
    firewall: dict[str, Any], ports: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    public_ports = [port for port in ports or [] if port.get("public")]
    if not public_ports or firewall.get("has_active_firewall"):
        return []
    evidence = [
        port.get("raw")
        or f"{port.get('process') or '-'} {port.get('address')}:{port.get('port')}"
        for port in public_ports[:5]
    ]
    tools = firewall.get("tools") or {}
    inactive_tools = [
        name
        for name, tool in tools.items()
        if tool.get("available") and not (tool.get("active") or tool.get("has_rules"))
    ]
    if inactive_tools:
        evidence.append(f"未发现启用规则：{', '.join(inactive_tools)}")
    return [
        _maintenance_item(
            category="firewall_posture",
            title="存在公网监听端口，但未确认主机防火墙启用",
            summary="这不是已确认 CVE，但公网端口需要确认云安全组、主机防火墙和服务访问控制是否匹配预期。",
            evidence=evidence,
            recommendation="建议确认 ufw、firewalld、nftables、iptables/ip6tables 或云安全组规则，只开放业务必需端口。",
            severity="medium",
        )
    ]


def build_server_analysis(
    server_assets: dict[str, Any], matched: dict[str, Any]
) -> dict[str, Any]:
    confirmed = [
        item
        for item in (matched.get("confirmed_issues") or [])
        if item.get("confidence") == "confirmed"
    ]
    containers = (server_assets.get("docker") or {}).get("containers") or []
    ports = server_assets.get("ports") or []
    ssh = server_assets.get("ssh") or {}
    firewall = server_assets.get("firewall") or {}
    maintenance = docker_maintenance_items(
        containers
    ) + public_service_maintenance_items(ports)
    maintenance += ssh_maintenance_items(ssh, ports)
    maintenance += firewall_maintenance_items(firewall, ports)
    errors = []
    errors.extend(server_assets.get("errors") or [])
    errors.extend(matched.get("errors") or [])
    return {
        "summary": {
            "distro": server_assets.get("distro") or {},
            "package_count": len(server_assets.get("packages") or []),
            "confirmed_count": len(confirmed),
            "maintenance_count": len(maintenance),
            "container_count": len(containers),
            "public_port_count": len([p for p in ports if p.get("public")]),
        },
        "confirmed_issues": confirmed,
        "maintenance_items": maintenance,
        "ports": ports,
        "docker": server_assets.get("docker") or {"containers": []},
        "kernel": server_assets.get("kernel") or {},
        "errors": errors,
    }
