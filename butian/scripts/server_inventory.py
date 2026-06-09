#!/usr/bin/env python3
"""把只读 Linux 服务器 inventory 解析成可报告资产。"""

from __future__ import annotations

import json
import re
from typing import Any

SUPPORTED_DISTROS = {
    "ubuntu",
    "debian",
    "alpine",
    "rhel",
    "rocky",
    "almalinux",
    "sles",
    "opensuse",
    "opensuse-leap",
    "opensuse-tumbleweed",
    "amzn",
    "ol",
}

# 不支持或为空的 inventory 保留为覆盖缺口错误；
# 它们绝不能证明服务器没有漏洞包或暴露服务。

PUBLIC_ADDRESSES = {"0.0.0.0", "::", "*"}

SSHD_OPTION_KEYS = {
    "passwordauthentication": "PasswordAuthentication",
    "kbdinteractiveauthentication": "KbdInteractiveAuthentication",
    "pubkeyauthentication": "PubkeyAuthentication",
    "permitrootlogin": "PermitRootLogin",
    "permitemptypasswords": "PermitEmptyPasswords",
}

OLD_IMAGE_VERSION_HINTS = {
    "nginx": (1, 20),
    "redis": (6, 0),
    "mysql": (8, 0),
    "mariadb": (10, 6),
    "postgres": (13, 0),
    "postgresql": (13, 0),
    "node": (16, 0),
}


def _strip_quotes(value: str) -> str:
    value = str(value or "").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _major_version(version_id: str) -> str:
    return str(version_id or "").split(".", 1)[0]


def parse_os_release(raw: str) -> dict[str, Any]:
    fields: dict[str, str] = {}
    for line in str(raw or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        fields[key.lower()] = _strip_quotes(value)

    distro_id = fields.get("id", "").lower()
    version_id = fields.get("version_id", "")
    codename = fields.get("version_codename", "")
    major = _major_version(version_id)

    family = "unknown"
    package_type = "unknown"
    ecosystem = ""
    supported = distro_id in SUPPORTED_DISTROS

    if distro_id == "ubuntu":
        family = "debian"
        package_type = "deb"
        ecosystem = f"Ubuntu:{version_id}:LTS" if version_id else "Ubuntu"
    elif distro_id == "debian":
        family = "debian"
        package_type = "deb"
        ecosystem = f"Debian:{major}" if major else "Debian"
    elif distro_id == "alpine":
        family = "alpine"
        package_type = "apk"
        minor = ".".join(version_id.split(".")[:2])
        ecosystem = f"Alpine:v{minor}" if minor else "Alpine"
    elif distro_id in {"sles", "opensuse", "opensuse-leap"}:
        family = "suse"
        package_type = "rpm"
        ecosystem = f"SUSE:{major}" if major else "SUSE"
    elif distro_id == "opensuse-tumbleweed":
        family = "suse"
        package_type = "rpm"
        ecosystem = "SUSE:Tumbleweed"
    elif distro_id == "amzn":
        family = "amazon"
        package_type = "rpm"
        ecosystem = f"Amazon Linux:{major}" if major else "Amazon Linux"
    elif distro_id == "ol":
        family = "oracle"
        package_type = "rpm"
        ecosystem = f"Oracle Linux:{major}" if major else "Oracle Linux"
    elif distro_id == "centos" and "stream" in (
        f"{fields.get('name', '')} {fields.get('pretty_name', '')}".lower()
    ):
        family = "rhel"
        package_type = "rpm"
        ecosystem = f"CentOS Stream:{major}" if major else "CentOS Stream"
        supported = True
    elif distro_id in {"rhel", "rocky", "almalinux"}:
        family = "rhel"
        package_type = "rpm"
        names = {
            "rhel": "Red Hat Enterprise Linux",
            "rocky": "Rocky Linux",
            "almalinux": "AlmaLinux",
        }
        base_name = names.get(distro_id, "Red Hat Enterprise Linux")
        ecosystem = f"{base_name}:{major}" if major else base_name

    return {
        "id": distro_id,
        "id_like": fields.get("id_like", "").lower().split(),
        "name": fields.get("name", ""),
        "pretty_name": fields.get("pretty_name", ""),
        "version_id": version_id,
        "major_version": major,
        "codename": codename,
        "family": family,
        "package_type": package_type,
        "ecosystem": ecosystem,
        "supported": supported,
    }


def _purl(
    type_name: str, distro_id: str, name: str, version: str, arch: str = ""
) -> str:
    distro = re.sub(r"[^a-z0-9_.-]+", "-", str(distro_id or "").lower()).strip("-")
    package = str(name or "").strip()
    rendered = f"pkg:{type_name}/{distro}/{package}@{version}"
    if arch:
        rendered += f"?arch={arch}"
    return rendered


def _package_asset(
    name: str,
    version: str,
    distro: dict[str, Any],
    *,
    arch: str = "",
    source_name: str = "",
) -> dict[str, Any]:
    package_type = distro.get("package_type") or "unknown"
    distro_id = distro.get("id") or ""
    return {
        "asset_type": "system_package",
        "package_type": package_type,
        "ecosystem": distro.get("ecosystem") or "",
        "distro_id": distro_id,
        "name": name,
        "source_name": source_name or name,
        "version": version,
        "architecture": arch,
        "purl": _purl(package_type, distro_id, name, version, arch),
        "evidence": [{"source": "package_manager", "summary": f"{name} {version}"}],
    }


def parse_dpkg_packages(raw: str, distro: dict[str, Any]) -> list[dict[str, Any]]:
    packages = []
    for line in str(raw or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        name, version, arch = [part.strip() for part in parts[:3]]
        source_name = parts[3].strip() if len(parts) > 3 and parts[3].strip() else name
        if source_name in {"(none)", "<none>"}:
            source_name = name
        if name and version:
            packages.append(
                _package_asset(
                    name,
                    version,
                    distro,
                    arch=arch,
                    source_name=source_name,
                )
            )
    return packages


def parse_rpm_packages(raw: str, distro: dict[str, Any]) -> list[dict[str, Any]]:
    packages = []
    for line in str(raw or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        name, version = [part.strip() for part in parts[:2]]
        arch = parts[2].strip() if len(parts) > 2 else ""
        if name and version:
            packages.append(
                _package_asset(name, version, distro, arch=arch, source_name=name)
            )
    return packages


def parse_apk_packages(raw: str, distro: dict[str, Any]) -> list[dict[str, Any]]:
    packages = []
    pattern = re.compile(r"^([A-Za-z0-9_+.-]+)-(\d[^ ]*)\s+-\s+")
    for line in str(raw or "").splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        name, version = match.groups()
        packages.append(_package_asset(name, version, distro, source_name=name))
    return packages


def build_kernel_asset(
    kernel_release: str, packages: list[dict[str, Any]]
) -> dict[str, Any]:
    release = str(kernel_release or "").strip()
    candidates = []
    kernel_names = {
        "kernel",
        "kernel-core",
        "kernel-default",
        "kernel-default-base",
        "linux-lts",
        "linux-virt",
    }
    for package in packages or []:
        name = str(package.get("name") or "")
        version = str(package.get("version") or "")
        if name == f"linux-image-{release}" or (
            name.startswith("linux-image-") and release and release in name
        ):
            candidates.append(package)
        elif (
            name in kernel_names
            and version
            and (version in release or release.startswith(version))
        ):
            candidates.append(package)

    if candidates:
        selected = dict(candidates[0])
        selected["asset_type"] = "kernel_package"
        selected["kernel_release"] = release
        selected["queryable"] = True
        evidence = list(selected.get("evidence") or [])
        evidence.append({"source": "uname -r", "summary": release})
        selected["evidence"] = evidence
        return selected

    return {
        "asset_type": "kernel_package",
        "name": "kernel",
        "version": release,
        "kernel_release": release,
        "queryable": False,
        "evidence": [{"source": "uname -r", "summary": release}],
    }


def _stdout(inventory: dict[str, Any], key: str) -> str:
    return str(((inventory.get("outputs") or {}).get(key) or {}).get("stdout") or "")


def _endpoint_from_token(token: str) -> tuple[str, int] | None:
    token = str(token or "").strip()
    if not token or token.endswith(":*"):
        return None
    if token.startswith("[") and "]:" in token:
        address, port = token.rsplit("]:", 1)
        address = address[1:]
    elif ":" in token:
        address, port = token.rsplit(":", 1)
    else:
        return None
    if not port.isdigit():
        return None
    address = address.strip("[]") or "*"
    return address, int(port)


def parse_listening_ports(raw: str) -> list[dict[str, Any]]:
    ports = []
    for line in str(raw or "").splitlines():
        if "LISTEN" not in line and "UNCONN" not in line:
            continue
        endpoint = None
        for token in line.split():
            endpoint = _endpoint_from_token(token)
            if endpoint:
                break
        if not endpoint:
            continue
        address, port = endpoint
        proc_match = re.search(r'"([^"]+)"', line)
        if proc_match:
            process = proc_match.group(1)
        else:
            pid_match = re.search(r"\b\d+/([^\s]+)", line)
            process = pid_match.group(1) if pid_match else ""
        normalized = address.strip("[]")
        ports.append(
            {
                "address": normalized,
                "port": port,
                "process": process,
                "public": normalized in PUBLIC_ADDRESSES,
                "raw": line.strip(),
            }
        )
    return ports


def parse_sshd_config(raw: str) -> dict[str, Any]:
    options: dict[str, str] = {}
    evidence = []
    for line in str(raw or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        key = SSHD_OPTION_KEYS.get(parts[0].lower())
        if not key:
            continue
        value = parts[1].lower()
        options[key] = value
        evidence.append(stripped)
    return {
        "available": bool(options),
        "options": options,
        "evidence": evidence,
    }


def _output_result(inventory: dict[str, Any], key: str) -> dict[str, Any]:
    return dict(((inventory.get("outputs") or {}).get(key) or {}))


def _firewall_tool(raw: str, *, active: bool = False, has_rules: bool = False) -> dict[str, Any]:
    text = str(raw or "").strip()
    return {
        "available": bool(text),
        "active": bool(active),
        "has_rules": bool(has_rules),
        "summary": text[:500],
    }


def _iptables_has_rules(raw: str) -> bool:
    for line in str(raw or "").splitlines():
        stripped = line.strip()
        if stripped.startswith(("-A ", "-I ", "-N ")):
            return True
    return False


def parse_firewall_posture(inventory: dict[str, Any]) -> dict[str, Any]:
    ufw_raw = str(_output_result(inventory, "ufw_status").get("stdout") or "")
    firewalld_raw = str(
        _output_result(inventory, "firewalld_status").get("stdout") or ""
    )
    nft_raw = str(_output_result(inventory, "nft_rules").get("stdout") or "")
    iptables_raw = str(_output_result(inventory, "iptables_rules").get("stdout") or "")
    ip6tables_raw = str(
        _output_result(inventory, "ip6tables_rules").get("stdout") or ""
    )

    ufw_active = "status: active" in ufw_raw.lower()
    firewalld_active = firewalld_raw.splitlines()[:1] == ["running"]
    nft_has_rules = bool(nft_raw.strip())
    iptables_has_rules = _iptables_has_rules(iptables_raw)
    ip6tables_has_rules = _iptables_has_rules(ip6tables_raw)

    tools = {
        "ufw": _firewall_tool(ufw_raw, active=ufw_active, has_rules=ufw_active),
        "firewalld": _firewall_tool(
            firewalld_raw,
            active=firewalld_active,
            has_rules=firewalld_active,
        ),
        "nftables": _firewall_tool(nft_raw, has_rules=nft_has_rules),
        "iptables": _firewall_tool(iptables_raw, has_rules=iptables_has_rules),
        "ip6tables": _firewall_tool(ip6tables_raw, has_rules=ip6tables_has_rules),
    }
    return {
        "tools": tools,
        "has_active_firewall": any(
            tool.get("active") or tool.get("has_rules") for tool in tools.values()
        ),
    }


def _split_image(image: str) -> tuple[str, str]:
    image = str(image or "").strip()
    leaf = image.rsplit("/", 1)[-1]
    if ":" not in leaf:
        return leaf, ""
    name, tag = leaf.rsplit(":", 1)
    return name, tag


def version_tuple(value: str) -> tuple[int, ...]:
    match = re.match(r"^v?(\d+(?:\.\d+)*)", str(value or "").strip())
    if not match:
        return ()
    return tuple(int(part) for part in match.group(1).split("."))


def is_explicit_old_image_tag(image_name: str, image_tag: str) -> bool:
    threshold = OLD_IMAGE_VERSION_HINTS.get(str(image_name or "").lower())
    parsed = version_tuple(image_tag)
    if threshold and parsed and len(parsed) < len(threshold):
        parsed = parsed + (0,) * (len(threshold) - len(parsed))
    return bool(threshold and parsed and parsed < threshold)


def parse_docker_ps(raw: str) -> list[dict[str, Any]]:
    containers = []
    for line in str(raw or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        image = item.get("Image") or item.get("image") or ""
        image_name, image_tag = _split_image(image)
        containers.append(
            {
                "id": item.get("ID") or item.get("Id") or item.get("id") or "",
                "name": item.get("Names") or item.get("Name") or item.get("name") or "",
                "image": image,
                "image_name": image_name,
                "image_tag": image_tag,
                "ports": item.get("Ports") or item.get("ports") or "",
                "explicit_old_tag": is_explicit_old_image_tag(image_name, image_tag),
            }
        )
    return containers


def parse_packages_for_distro(
    inventory: dict[str, Any], distro: dict[str, Any]
) -> list[dict[str, Any]]:
    if not distro.get("supported"):
        return []
    package_type = distro.get("package_type")
    if package_type == "deb":
        return parse_dpkg_packages(_stdout(inventory, "dpkg_packages"), distro)
    if package_type == "rpm":
        return parse_rpm_packages(_stdout(inventory, "rpm_packages"), distro)
    if package_type == "apk":
        return parse_apk_packages(_stdout(inventory, "apk_packages"), distro)
    return []


def build_server_assets(inventory: dict[str, Any]) -> dict[str, Any]:
    distro = parse_os_release(_stdout(inventory, "os_release"))
    errors = list(inventory.get("errors") or [])
    if not distro.get("id") or not distro.get("supported"):
        errors.append(
            {
                "step": "server_inventory",
                "code": "unsupported_distro",
                "message": "Unsupported or unrecognized Linux distribution; system package vulnerability queries were skipped.",
                "distro_id": distro.get("id") or "",
            }
        )

    packages = parse_packages_for_distro(inventory, distro)
    if (
        distro.get("supported")
        and distro.get("package_type") != "unknown"
        and not packages
    ):
        errors.append(
            {
                "step": "server_inventory",
                "code": "empty_package_inventory",
                "message": "System package inventory is empty or unavailable; this cannot be treated as no risk.",
                "package_type": distro.get("package_type") or "",
            }
        )

    ports = parse_listening_ports(_stdout(inventory, "ports"))
    ssh = parse_sshd_config(_stdout(inventory, "sshd_config"))
    firewall = parse_firewall_posture(inventory)
    kernel = build_kernel_asset(_stdout(inventory, "uname_r").strip(), packages)
    docker_containers = parse_docker_ps(_stdout(inventory, "docker_ps"))
    return {
        "target": inventory.get("target") or "",
        "collection_mode": inventory.get("collection_mode") or "unknown",
        "distro": distro,
        "packages": packages,
        "kernel": kernel,
        "ports": ports,
        "ssh": ssh,
        "firewall": firewall,
        "docker": {"containers": docker_containers},
        "errors": errors,
    }
