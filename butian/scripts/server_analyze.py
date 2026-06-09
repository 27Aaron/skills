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


def public_service_maintenance_items(ports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items = []
    seen = set()
    for port in ports or []:
        port_number = port.get("port")
        try:
            port_number = int(port_number)
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


def build_server_analysis(
    server_assets: dict[str, Any], matched: dict[str, Any]
) -> dict[str, Any]:
    confirmed = [
        item
        for item in (matched.get("confirmed_issues") or [])
        if item.get("confidence") == "confirmed"
    ]
    containers = ((server_assets.get("docker") or {}).get("containers") or [])
    ports = server_assets.get("ports") or []
    maintenance = docker_maintenance_items(containers) + public_service_maintenance_items(ports)
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
