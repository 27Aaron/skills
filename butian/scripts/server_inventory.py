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

SERVICE_VERSION_SOURCES = {
    "nginx_v": {
        "name": "nginx",
        "category": "web",
        "source": "nginx -v",
        "patterns": [r"nginx/(v?\d[^\s,;)]*)"],
        "package_names": ("nginx", "nginx-core", "nginx-full", "nginx-light"),
    },
    "apache_v": {
        "name": "apache",
        "category": "web",
        "source": "apache2/httpd -v",
        "patterns": [r"Apache/([0-9][^\s)]*)"],
        "package_names": ("apache2", "httpd"),
    },
    "caddy_v": {
        "name": "caddy",
        "category": "web",
        "source": "caddy version",
        "patterns": [r"^v?([0-9][^\s]*)"],
        "package_names": ("caddy",),
    },
    "tomcat_v": {
        "name": "tomcat",
        "category": "web",
        "source": "catalina.sh version",
        "patterns": [r"Server version:\s*Apache Tomcat/([0-9][^\s]*)"],
        "package_names": ("tomcat", "tomcat*", "tomcat9", "tomcat10"),
    },
    "openssl_v": {
        "name": "openssl",
        "category": "tls",
        "source": "openssl version -a",
        "patterns": [r"\bOpenSSL\s+(v?\d[^\s,;)]*)"],
        "package_names": ("openssl", "libssl3", "libssl3t64"),
    },
    "gnutls_v": {
        "name": "gnutls",
        "category": "tls",
        "source": "gnutls-cli --version",
        "patterns": [r"gnutls-cli\s+([0-9][^\s]*)", r"GnuTLS\s+([0-9][^\s]*)"],
        "package_names": ("gnutls", "gnutls-bin", "libgnutls30", "gnutls28"),
    },
    "ssh_v": {
        "name": "openssh",
        "category": "remote_access",
        "source": "ssh -V",
        "patterns": [r"\bOpenSSH[_\s](v?\d[^\s,;)]*)"],
        "package_names": ("openssh", "openssh-server", "openssh-client"),
    },
    "mysql_v": {
        "name": "mysql",
        "category": "database",
        "source": "mysql --version",
        "patterns": [r"Distrib\s+([0-9][^\s,]*)", r"mysql\s+Ver\s+([0-9][^\s]*)"],
        "package_names": ("mysql", "mysql-server", "mysql-client", "mysql-community-server"),
    },
    "mariadb_v": {
        "name": "mariadb",
        "category": "database",
        "source": "mariadb --version",
        "patterns": [r"Distrib\s+([0-9][^\s,]*)", r"mariadb\s+Ver\s+([0-9][^\s]*)"],
        "package_names": ("mariadb", "mariadb-server", "mariadb-client"),
    },
    "postgres_v": {
        "name": "postgresql",
        "category": "database",
        "source": "psql --version",
        "patterns": [r"\(PostgreSQL\)\s+([0-9][^\s]*)"],
        "package_names": ("postgresql", "postgresql-*", "postgresql-client", "postgresql-client-*"),
    },
    "mongo_v": {
        "name": "mongodb",
        "category": "database",
        "source": "mongod --version",
        "patterns": [r"db version v?([0-9][^\s]*)", r'"version"\s*:\s*"([0-9][^"]*)"'],
        "package_names": ("mongodb", "mongodb-org", "mongodb-server", "mongod"),
    },
    "redis_v": {
        "name": "redis",
        "category": "database",
        "source": "redis-server --version",
        "patterns": [r"\bv=([0-9][^\s]*)"],
        "package_names": ("redis", "redis-server", "redis-tools"),
    },
    "elasticsearch_v": {
        "name": "elasticsearch",
        "category": "database",
        "source": "elasticsearch --version",
        "patterns": [r"Version:\s*([0-9][^,\s]*)"],
        "package_names": ("elasticsearch",),
    },
    "docker_version": {
        "name": "docker",
        "category": "container",
        "source": "docker version",
        "patterns": [r"Docker version\s+([^,\s]+)", r'"Version"\s*:\s*"(v?\d[^"]*)"'],
        "package_names": ("docker", "docker-ce", "docker.io", "moby-engine"),
    },
    "containerd_v": {
        "name": "containerd",
        "category": "container",
        "source": "containerd --version",
        "patterns": [r"\bcontainerd\b.*\s([0-9]+(?:\.[0-9]+)+[^\s]*)"],
        "package_names": ("containerd", "containerd.io"),
    },
    "runc_v": {
        "name": "runc",
        "category": "container",
        "source": "runc --version",
        "patterns": [r"runc version\s+([0-9][^\s]*)"],
        "package_names": ("runc",),
    },
    "podman_v": {
        "name": "podman",
        "category": "container",
        "source": "podman --version",
        "patterns": [r"podman version\s+([0-9][^\s]*)"],
        "package_names": ("podman",),
    },
    "node_v": {
        "name": "node",
        "category": "runtime",
        "source": "node --version",
        "patterns": [r"^v?([0-9][^\s]*)"],
        "package_names": ("node", "nodejs"),
    },
    "python_v": {
        "name": "python",
        "category": "runtime",
        "source": "python --version",
        "patterns": [r"Python\s+([0-9][^\s]*)"],
        "package_names": ("python", "python3", "python3.*"),
    },
    "java_v": {
        "name": "java",
        "category": "runtime",
        "source": "java -version",
        "patterns": [r'version\s+"([^"]+)"'],
        "package_names": ("java", "openjdk*", "java-*", "temurin-*"),
    },
    "php_v": {
        "name": "php",
        "category": "runtime",
        "source": "php -v",
        "patterns": [r"PHP\s+([0-9][^\s]*)"],
        "package_names": ("php", "php-cli", "php-fpm", "php*"),
    },
    "ruby_v": {
        "name": "ruby",
        "category": "runtime",
        "source": "ruby -v",
        "patterns": [r"ruby\s+([0-9][^\s]*)"],
        "package_names": ("ruby", "ruby-full", "ruby*"),
    },
    "go_v": {
        "name": "go",
        "category": "runtime",
        "source": "go version",
        "patterns": [r"go version go([0-9][^\s]*)"],
        "package_names": ("golang", "golang-go", "go"),
    },
    "rabbitmq_v": {
        "name": "rabbitmq",
        "category": "message_queue",
        "source": "rabbitmqctl version",
        "patterns": [r"^([0-9]+(?:\.[0-9]+)+[^\s]*)"],
        "package_names": ("rabbitmq", "rabbitmq-server"),
    },
    "kafka_v": {
        "name": "kafka",
        "category": "message_queue",
        "source": "kafka --version",
        "patterns": [r"^([0-9]+(?:\.[0-9]+)+[^\s]*)"],
        "package_names": ("kafka", "apache-kafka", "confluent-kafka"),
    },
    "haproxy_v": {
        "name": "haproxy",
        "category": "proxy_gateway",
        "source": "haproxy -v",
        "patterns": [r"HAProxy version\s+([0-9][^\s]*)"],
        "package_names": ("haproxy",),
    },
    "envoy_v": {
        "name": "envoy",
        "category": "proxy_gateway",
        "source": "envoy --version",
        "patterns": [r"version:\s*([0-9][^/\s]*)"],
        "package_names": ("envoy", "envoyproxy"),
    },
    "traefik_v": {
        "name": "traefik",
        "category": "proxy_gateway",
        "source": "traefik version",
        "patterns": [r"Version:\s*([0-9][^\s]*)"],
        "package_names": ("traefik",),
    },
    "git_v": {
        "name": "git",
        "category": "ops",
        "source": "git --version",
        "patterns": [r"git version\s+([0-9][^\s]*)"],
        "package_names": ("git",),
    },
    "curl_v": {
        "name": "curl",
        "category": "ops",
        "source": "curl --version",
        "patterns": [r"curl\s+([0-9][^\s]*)"],
        "package_names": ("curl", "libcurl4", "libcurl"),
    },
    "wget_v": {
        "name": "wget",
        "category": "ops",
        "source": "wget --version",
        "patterns": [r"GNU Wget\s+([0-9][^\s]*)"],
        "package_names": ("wget",),
    },
    "cron_v": {
        "name": "cron",
        "category": "ops",
        "source": "cron/crond -V",
        "patterns": [r"(?:cron|crond).*?([0-9]+(?:\.[0-9]+)+[^\s]*)"],
        "package_names": ("cron", "cronie", "crond"),
    },
    "systemd_v": {
        "name": "systemd",
        "category": "ops",
        "source": "systemctl --version",
        "patterns": [r"systemd\s+([0-9][^\s]*)"],
        "package_names": ("systemd",),
    },
    "grafana_v": {
        "name": "grafana",
        "category": "panel",
        "source": "grafana-server -v",
        "patterns": [r"(?:Version|version)\s+([0-9][^\s]*)"],
        "package_names": ("grafana", "grafana-enterprise"),
    },
    "prometheus_v": {
        "name": "prometheus",
        "category": "panel",
        "source": "prometheus --version",
        "patterns": [r"version\s+([0-9][^\s]*)"],
        "package_names": ("prometheus",),
    },
}

COMMON_PACKAGE_COMPONENTS = [
    {"name": "nginx", "category": "web", "package_names": ("nginx", "nginx-core", "nginx-full", "nginx-light")},
    {"name": "openssh", "category": "remote_access", "package_names": ("openssh", "openssh-server", "openssh-client")},
    {"name": "openssl", "category": "tls", "package_names": ("openssl", "libssl3", "libssl3t64", "libssl*")},
    {"name": "gnutls", "category": "tls", "package_names": ("gnutls", "gnutls-bin", "libgnutls30", "gnutls28")},
    {"name": "nss", "category": "tls", "package_names": ("nss", "libnss3", "nss-util")},
    {"name": "apache", "category": "web", "package_names": ("apache2", "httpd")},
    {"name": "tomcat", "category": "web", "package_names": ("tomcat", "tomcat*", "tomcat9", "tomcat10")},
    {"name": "mysql", "category": "database", "package_names": ("mysql", "mysql-server", "mysql-client", "mysql-community-server")},
    {"name": "mariadb", "category": "database", "package_names": ("mariadb", "mariadb-server", "mariadb-client")},
    {"name": "postgresql", "category": "database", "package_names": ("postgresql", "postgresql-*", "postgresql-client", "postgresql-client-*")},
    {"name": "mongodb", "category": "database", "package_names": ("mongodb", "mongodb-org", "mongodb-server", "mongod")},
    {"name": "redis", "category": "database", "package_names": ("redis", "redis-server", "redis-tools")},
    {"name": "elasticsearch", "category": "database", "package_names": ("elasticsearch",)},
    {"name": "docker", "category": "container", "package_names": ("docker", "docker-ce", "docker.io", "moby-engine")},
    {"name": "containerd", "category": "container", "package_names": ("containerd", "containerd.io")},
    {"name": "runc", "category": "container", "package_names": ("runc",)},
    {"name": "podman", "category": "container", "package_names": ("podman",)},
    {"name": "node", "category": "runtime", "package_names": ("node", "nodejs")},
    {"name": "python", "category": "runtime", "package_names": ("python", "python3", "python3.*")},
    {"name": "java", "category": "runtime", "package_names": ("java", "openjdk*", "java-*", "temurin-*")},
    {"name": "php", "category": "runtime", "package_names": ("php", "php-cli", "php-fpm", "php*")},
    {"name": "ruby", "category": "runtime", "package_names": ("ruby", "ruby-full", "ruby*")},
    {"name": "go", "category": "runtime", "package_names": ("golang", "golang-go", "go")},
    {"name": "rabbitmq", "category": "message_queue", "package_names": ("rabbitmq", "rabbitmq-server")},
    {"name": "kafka", "category": "message_queue", "package_names": ("kafka", "apache-kafka", "confluent-kafka")},
    {"name": "haproxy", "category": "proxy_gateway", "package_names": ("haproxy",)},
    {"name": "envoy", "category": "proxy_gateway", "package_names": ("envoy", "envoyproxy")},
    {"name": "traefik", "category": "proxy_gateway", "package_names": ("traefik",)},
    {"name": "caddy", "category": "proxy_gateway", "package_names": ("caddy",)},
    {"name": "git", "category": "ops", "package_names": ("git",)},
    {"name": "curl", "category": "ops", "package_names": ("curl", "libcurl4", "libcurl")},
    {"name": "wget", "category": "ops", "package_names": ("wget",)},
    {"name": "sudo", "category": "ops", "package_names": ("sudo",)},
    {"name": "cron", "category": "ops", "package_names": ("cron", "cronie", "crond")},
    {"name": "systemd", "category": "ops", "package_names": ("systemd",)},
    {"name": "jenkins", "category": "panel", "package_names": ("jenkins",)},
    {"name": "gitlab", "category": "panel", "package_names": ("gitlab", "gitlab-ee", "gitlab-ce")},
    {"name": "grafana", "category": "panel", "package_names": ("grafana", "grafana-enterprise")},
    {"name": "prometheus", "category": "panel", "package_names": ("prometheus",)},
    {"name": "nexus", "category": "panel", "package_names": ("nexus", "nexus-repository-manager", "nexus3")},
    {"name": "harbor", "category": "panel", "package_names": ("harbor",)},
]


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


def _firewall_tool(
    raw: str, *, active: bool = False, has_rules: bool = False
) -> dict[str, Any]:
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


def parse_running_services(raw: str) -> list[dict[str, Any]]:
    services = []
    for line in str(raw or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("UNIT "):
            continue
        parts = stripped.split(None, 4)
        if len(parts) < 4 or not parts[0].endswith(".service"):
            continue
        services.append(
            {
                "name": parts[0],
                "load": parts[1],
                "active": parts[2],
                "sub": parts[3],
                "description": parts[4] if len(parts) > 4 else "",
                "raw": stripped,
            }
        )
    return services


def _package_matches(package: dict[str, Any], names: tuple[str, ...]) -> bool:
    candidates = {
        str(package.get("name") or "").lower(),
        str(package.get("source_name") or "").lower(),
    }
    for expected in names:
        name = str(expected or "").lower()
        if not name:
            continue
        if name.endswith("*"):
            prefix = name[:-1]
            if any(candidate.startswith(prefix) for candidate in candidates):
                return True
        elif name in candidates:
            return True
    return False


def _package_link(package: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": package.get("name") or "",
        "source_name": package.get("source_name") or package.get("name") or "",
        "version": package.get("version") or "",
        "ecosystem": package.get("ecosystem") or "",
        "package_type": package.get("package_type") or "",
        "purl": package.get("purl") or "",
    }


def _linked_package(
    packages: list[dict[str, Any]], package_names: tuple[str, ...]
) -> dict[str, Any]:
    for package in packages or []:
        if _package_matches(package, package_names):
            return _package_link(package)
    return {}


def _first_version(raw: str, patterns: list[str]) -> str:
    for pattern in patterns:
        match = re.search(pattern, str(raw or ""), flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return ""


def parse_package_software_components(
    packages: list[dict[str, Any]], existing: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    versions = []
    seen_names = {str(item.get("name") or "").lower() for item in existing or []}
    for spec in COMMON_PACKAGE_COMPONENTS:
        name = spec["name"]
        if name.lower() in seen_names:
            continue
        linked = _linked_package(packages, spec["package_names"])
        if not linked:
            continue
        versions.append(
            {
                "name": name,
                "category": spec["category"],
                "version": linked.get("version") or "",
                "source": "package inventory",
                "raw": f"{linked.get('name') or name} {linked.get('version') or ''}".strip(),
                "linked_package": linked,
            }
        )
        seen_names.add(name.lower())
    return versions


def parse_software_versions(
    inventory: dict[str, Any], packages: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    versions = []
    errors = []
    for output_key, spec in SERVICE_VERSION_SOURCES.items():
        raw = _stdout(inventory, output_key)
        version = _first_version(raw, spec["patterns"])
        if not version:
            continue
        linked = _linked_package(packages, spec["package_names"])
        item = {
            "name": spec["name"],
            "category": spec.get("category") or "",
            "version": version,
            "source": spec["source"],
            "raw": raw.strip().splitlines()[0] if raw.strip() else "",
            "linked_package": linked,
        }
        versions.append(item)
        if not linked:
            errors.append(
                {
                    "step": "server_inventory",
                    "code": "unlinked_service_version",
                    "message": (
                        f"{spec['source']} 返回了 {spec['name']} {version}，"
                        "但未能关联到发行版包坐标；不能作为已确认漏洞。"
                    ),
                    "name": spec["name"],
                    "version": version,
                }
            )
    versions.extend(parse_package_software_components(packages, versions))
    return versions, errors


def parse_apt_upgradable(raw: str) -> list[dict[str, Any]]:
    updates = []
    pattern = re.compile(
        r"^(?P<name>[A-Za-z0-9_.+:-]+)/\S+\s+"
        r"(?P<fixed>\S+)\s+\S+\s+\[upgradable from:\s*(?P<current>[^\]]+)\]"
    )
    for line in str(raw or "").splitlines():
        match = pattern.search(line.strip())
        if not match:
            continue
        updates.append(
            {
                "manager": "apt",
                "name": match.group("name"),
                "current_version": match.group("current").strip(),
                "fixed_version": match.group("fixed").strip(),
                "raw": line.strip(),
            }
        )
    return updates


RPM_ARCHES = {
    "aarch64",
    "i386",
    "i486",
    "i586",
    "i686",
    "noarch",
    "ppc64le",
    "s390x",
    "src",
    "x86_64",
}


def _split_rpm_update_package_token(line: str) -> tuple[str, str]:
    for token in reversed(str(line or "").split()):
        if token.lower() in RPM_ARCHES:
            continue
        match = re.match(r"(?P<name>.+?)-(?P<version>(?:\d+:)?\d\S*)$", token)
        if match:
            return match.group("name"), match.group("version")
    return "", ""


def _parse_rpm_security_updates(raw: str, manager: str) -> list[dict[str, Any]]:
    updates = []
    for line in str(raw or "").splitlines():
        stripped = line.strip()
        if not stripped or "sec" not in stripped.lower():
            continue
        package_name, fixed_version = _split_rpm_update_package_token(stripped)
        if not package_name:
            continue
        updates.append(
            {
                "manager": manager,
                "name": package_name,
                "fixed_version": fixed_version,
                "raw": stripped,
            }
        )
    return updates


def parse_zypper_security_patches(raw: str) -> list[dict[str, Any]]:
    updates = []
    for line in str(raw or "").splitlines():
        stripped = line.strip()
        if not stripped or "|" not in stripped or "security" not in stripped.lower():
            continue
        parts = [part.strip() for part in stripped.split("|")]
        if not parts or parts[0].lower() == "repository":
            continue
        name = parts[1] if len(parts) > 1 and parts[1] else parts[0]
        updates.append(
            {
                "manager": "zypper",
                "name": name,
                "fixed_version": name,
                "raw": stripped,
            }
        )
    return updates


def parse_native_security_updates(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    updates = []
    updates.extend(parse_apt_upgradable(_stdout(inventory, "apt_upgradable")))
    updates.extend(
        _parse_rpm_security_updates(_stdout(inventory, "dnf_updateinfo"), "dnf")
    )
    updates.extend(
        _parse_rpm_security_updates(_stdout(inventory, "yum_updateinfo"), "yum")
    )
    updates.extend(parse_zypper_security_patches(_stdout(inventory, "zypper_patches")))
    seen = set()
    deduped = []
    for item in updates:
        key = (
            item.get("manager"),
            item.get("name"),
            item.get("fixed_version"),
            item.get("raw"),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


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
    services = parse_running_services(_stdout(inventory, "services"))
    ssh = parse_sshd_config(_stdout(inventory, "sshd_config"))
    firewall = parse_firewall_posture(inventory)
    kernel = build_kernel_asset(_stdout(inventory, "uname_r").strip(), packages)
    docker_containers = parse_docker_ps(_stdout(inventory, "docker_ps"))
    software_versions, version_errors = parse_software_versions(inventory, packages)
    errors.extend(version_errors)
    native_security_updates = parse_native_security_updates(inventory)
    return {
        "target": inventory.get("target") or "",
        "collection_mode": inventory.get("collection_mode") or "unknown",
        "distro": distro,
        "packages": packages,
        "kernel": kernel,
        "software_versions": software_versions,
        "native_security_updates": native_security_updates,
        "services": services,
        "ports": ports,
        "ssh": ssh,
        "firewall": firewall,
        "docker": {"containers": docker_containers},
        "errors": errors,
    }
