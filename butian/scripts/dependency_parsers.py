#!/usr/bin/env python3
"""依赖生态检测和 lockfile 解析器。"""

from __future__ import annotations

import json
import os
import re
import xml.etree.ElementTree as ET

# ---------------------------------------------------------------------------
# 依赖生态检测和包提取
# ---------------------------------------------------------------------------

LOCKFILE_MAP = {
    "npm": ["package-lock.json"],
    "pnpm": ["pnpm-lock.yaml"],
    "yarn": ["yarn.lock"],
    "pypi": ["poetry.lock", "uv.lock", "requirements.txt", "Pipfile.lock"],
    "go": ["go.sum"],
    "crates-io": ["Cargo.lock"],
    "packagist": ["composer.lock"],
    "rubygems": ["Gemfile.lock"],
    "pub": ["pubspec.lock"],
    "hex": ["mix.lock"],
    "nuget": ["packages.lock.json", "packages.config"],
    "maven": ["pom.xml"],
}


def detect_ecosystems(project_path):
    ecosystems, lockfiles = [], {}
    for eco, names in LOCKFILE_MAP.items():
        for lf in names:
            if os.path.isfile(os.path.join(project_path, lf)):
                ecosystems.append(eco)
                lockfiles[eco] = lf
                break
    return ecosystems, lockfiles


def _tomllib():
    try:
        import tomllib

        return tomllib
    except ImportError:
        return None


def normalized_plain_version(value):
    version = str(value or "").strip()
    return version[1:] if re.match(r"^v(?=\d)", version) else version


# --- npm ---


def parse_npm_lock(project_path):
    path = os.path.join(project_path, "package-lock.json")
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []
    pkgs = []
    seen = set()
    packages = data.get("packages")
    if isinstance(packages, dict):
        root_info = packages.get("") if isinstance(packages.get(""), dict) else {}
        root_deps = set()
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            root_deps.update((root_info.get(section) or {}).keys())
        for key, info in packages.items():
            if not key or not isinstance(info, dict):
                continue
            name = npm_lock_package_name(key)
            version = str(info.get("version") or "").strip()
            if not name or not version:
                continue
            item_key = (name, version, key)
            if item_key in seen:
                continue
            seen.add(item_key)
            pkgs.append(
                {
                    "ecosystem": "npm",
                    "name": name,
                    "version": version,
                    "is_direct": key == f"node_modules/{name}" and name in root_deps,
                    "source": "package-lock.json",
                }
            )
        return pkgs

    def walk_dependencies(deps, direct=False):
        if not isinstance(deps, dict):
            return
        for name, info in deps.items():
            if not isinstance(info, dict):
                continue
            version = str(info.get("version") or "").strip()
            if version:
                item_key = (name, version)
                if item_key not in seen:
                    seen.add(item_key)
                    pkgs.append(
                        {
                            "ecosystem": "npm",
                            "name": name,
                            "version": version,
                            "is_direct": direct,
                            "source": "package-lock.json",
                        }
                    )
            walk_dependencies(info.get("dependencies"), direct=False)

    walk_dependencies(data.get("dependencies"), direct=True)
    return pkgs


def npm_lock_package_name(key):
    marker = "node_modules/"
    text = str(key or "").strip("/")
    if marker not in text:
        return ""
    return text.rsplit(marker, 1)[1].strip("/")


# --- pnpm ---


def parse_pnpm_lock(project_path):
    path = os.path.join(project_path, "pnpm-lock.yaml")
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError:
        return []
    pkgs, seen = [], set()
    # pnpm v9: packages section uses "'@scope/name@version':" or "name@version:"
    in_packages = False
    for line in content.split("\n"):
        stripped = line.rstrip()
        if stripped == "packages:":
            in_packages = True
            continue
        if in_packages:
            # Lines starting with 2+ spaces are package entries
            m = re.match(r"^  (?:'([^']+)'|([^:\s]+)):", stripped)
            if m:
                entry = (m.group(1) or m.group(2)).lstrip("/")
                entry = entry.split("(", 1)[0]
                # Parse "name@version" from entry (may include @scope)
                pm = re.match(r"^(.+?)@(\d[^@]*)$", entry)
                if pm:
                    name, ver = pm.group(1).strip("'\""), pm.group(2)
                    if (name, ver) not in seen:
                        seen.add((name, ver))
                        pkgs.append(
                            {
                                "ecosystem": "npm",
                                "name": name,
                                "version": ver,
                                "is_direct": False,
                                "source": "pnpm-lock.yaml",
                            }
                        )
            elif stripped and not stripped.startswith("  "):
                in_packages = False
    # 兜底：带 importers 的旧格式。
    if not pkgs:
        for m in re.finditer(
            r"^\s+['\"/]([^@'\"/]+)@([^'\"/:]+)", content, re.MULTILINE
        ):
            name, ver = m.group(1), m.group(2)
            if (name, ver) not in seen:
                seen.add((name, ver))
                pkgs.append(
                    {
                        "ecosystem": "npm",
                        "name": name,
                        "version": ver,
                        "is_direct": False,
                        "source": "pnpm-lock.yaml",
                    }
                )
    return pkgs


# --- yarn ---


def parse_yarn_lock(project_path):
    path = os.path.join(project_path, "yarn.lock")
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError:
        return []
    # 通过 __metadata 判断 Yarn Berry（v2+）。
    is_berry = "__metadata:" in content or bool(
        re.search(r'^"[^"]+@npm:[^"]+":', content, re.MULTILINE)
    )
    if is_berry:
        return _parse_yarn_lock_berry(content)
    return _parse_yarn_lock_v1(content)


def _parse_yarn_lock_v1(content):
    """解析 Yarn v1 classic lockfile。"""
    pkgs, seen = [], set()
    current_names = []
    for raw in content.splitlines():
        line = raw.rstrip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith(" ") and line.endswith(":"):
            header = line[:-1].strip().strip('"')
            current_names = []
            for desc in re.split(r",\s*", header):
                desc = desc.strip().strip('"')
                name = _yarn_v1_descriptor_name(desc)
                if name and name not in current_names:
                    current_names.append(name)
            continue
        if current_names:
            m = re.match(r'\s+version\s+"([^"]+)"', line)
            if not m:
                continue
            ver = m.group(1)
            for name in current_names:
                if (name, ver) not in seen:
                    seen.add((name, ver))
                    pkgs.append(
                        {
                            "ecosystem": "npm",
                            "name": name,
                            "version": ver,
                            "is_direct": False,
                            "source": "yarn.lock",
                        }
                    )
            current_names = []
    return pkgs


def _yarn_v1_descriptor_name(desc):
    if not desc:
        return ""
    if desc.startswith("@"):
        parts = desc.split("@")
        if len(parts) >= 3:
            return "@" + parts[1]
        return desc
    return desc.split("@", 1)[0]


def _parse_yarn_lock_berry(content):
    """解析 Yarn Berry（v2+）lockfile。

    Berry 格式使用类似下面的 descriptor：
      "@scope/pkg@npm:1.2.3":
        version: 1.2.3
    """
    pkgs, seen = [], set()
    current_names = []
    for raw in content.splitlines():
        line = raw.rstrip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith(" ") and line.endswith(":"):
            header = line[:-1].strip().strip('"')
            current_names = []
            for desc in re.split(r",\s*", header):
                desc = desc.strip().strip('"')
                name = _yarn_berry_descriptor_name(desc)
                if name == "__metadata":
                    continue
                if name and name not in current_names:
                    current_names.append(name)
            continue
        if current_names:
            m = re.match(r'\s+version:\s*"?([^"\s]+)"?', line)
            if not m:
                continue
            ver = m.group(1)
            if not ver or not re.match(r"\d", ver):
                continue
            for name in current_names:
                if (name, ver) not in seen:
                    seen.add((name, ver))
                    pkgs.append(
                        {
                            "ecosystem": "npm",
                            "name": name,
                            "version": ver,
                            "is_direct": False,
                            "source": "yarn.lock",
                        }
                    )
            current_names = []
    return pkgs


def _yarn_berry_descriptor_name(desc):
    """从 Yarn Berry descriptor 中提取包名。

    示例：
      "lodash@npm:^4.0.0" -> "lodash"
      "@scope/pkg@npm:1.2.3" -> "@scope/pkg"
    """
    if not desc:
        return ""
    desc = re.split(
        r"@(?:npm|patch|file|link|portal|workspace):",
        desc,
        maxsplit=1,
    )[0]
    if desc.startswith("@"):
        parts = desc.split("@")
        if len(parts) >= 3:
            return "@" + parts[1]
        return desc
    return desc.split("@", 1)[0]


# --- PHP / Packagist ---


def parse_composer_lock(project_path):
    path = os.path.join(project_path, "composer.lock")
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    pkgs, seen = [], set()
    for section_name in ("packages", "packages-dev"):
        for info in data.get(section_name) or []:
            if not isinstance(info, dict):
                continue
            name = str(info.get("name") or "").strip().lower()
            version = normalized_plain_version(info.get("version"))
            if not name or not version:
                continue
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)
            pkgs.append(
                {
                    "ecosystem": "packagist",
                    "name": name,
                    "version": version,
                    "is_direct": False,
                    "source": "composer.lock",
                }
            )
    return pkgs


# --- Ruby / RubyGems ---


def normalized_rubygems_version(value):
    version = str(value or "").strip()
    return re.sub(
        r"-(?:x86|x86_64|x64|aarch64|arm64|arm|java|universal)(?:-[A-Za-z0-9_]+)*$",
        "",
        version,
    )


def parse_gemfile_lock(project_path):
    path = os.path.join(project_path, "Gemfile.lock")
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        return []

    pkgs, seen = [], set()
    in_gem_section = False
    in_specs = False
    for raw in lines:
        line = raw.rstrip("\n")
        if line == "GEM":
            in_gem_section = True
            in_specs = False
            continue
        if in_gem_section and line and not line.startswith(" "):
            in_gem_section = False
            in_specs = False
            continue
        if in_gem_section and line == "  specs:":
            in_specs = True
            continue
        if not in_specs:
            continue

        match = re.match(r"^    ([^\s(]+) \(([^)]+)\)$", line)
        if not match:
            continue
        name = match.group(1).strip()
        version = normalized_rubygems_version(match.group(2))
        if not name or not version:
            continue
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        pkgs.append(
            {
                "ecosystem": "rubygems",
                "name": name,
                "version": version,
                "is_direct": False,
                "source": "Gemfile.lock",
            }
        )
    return pkgs


# --- Dart / Flutter Pub ---


def parse_pubspec_lock(project_path):
    path = os.path.join(project_path, "pubspec.lock")
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        return []

    pkgs, seen = [], set()
    in_packages = False
    current_name = ""
    current_version = ""
    current_source = ""

    def flush_current():
        if not current_name or not current_version or current_source != "hosted":
            return
        key = (current_name, current_version)
        if key in seen:
            return
        seen.add(key)
        pkgs.append(
            {
                "ecosystem": "pub",
                "name": current_name,
                "version": current_version,
                "is_direct": False,
                "source": "pubspec.lock",
            }
        )

    for raw in lines:
        line = raw.rstrip("\n")
        if line.strip() == "packages:":
            in_packages = True
            continue
        if not in_packages:
            continue
        if line and not line.startswith(" "):
            flush_current()
            break

        package_match = re.match(r"^  ([A-Za-z0-9_.-]+):\s*$", line)
        if package_match:
            flush_current()
            current_name = package_match.group(1)
            current_version = ""
            current_source = ""
            continue

        if current_name:
            source_match = re.match(r"^\s+source:\s*['\"]?([^'\"\s]+)['\"]?\s*$", line)
            if source_match:
                current_source = source_match.group(1)
                continue
            version_match = re.match(
                r"^\s+version:\s*['\"]?([^'\"\s]+)['\"]?\s*$", line
            )
            if version_match:
                current_version = version_match.group(1)

    flush_current()
    return pkgs


# --- Elixir / Erlang Hex ---


def parse_mix_lock(project_path):
    path = os.path.join(project_path, "mix.lock")
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError:
        return []

    pkgs, seen = [], set()
    for match in re.finditer(
        r'"([^"]+)"\s*:\s*\{:hex\s*,\s*(?::([A-Za-z0-9_.-]+)|"([^"]+)")\s*,\s*"([^"]+)"',
        content,
    ):
        lock_name = match.group(1).strip()
        entry_name = (match.group(2) or match.group(3) or lock_name).strip()
        version = match.group(4).strip()
        if not entry_name or not version:
            continue
        key = (entry_name, version)
        if key in seen:
            continue
        seen.add(key)
        pkgs.append(
            {
                "ecosystem": "hex",
                "name": entry_name,
                "version": version,
                "is_direct": False,
                "source": "mix.lock",
            }
        )
    return pkgs


# --- .NET / NuGet ---


def parse_packages_lock_json(project_path):
    path = os.path.join(project_path, "packages.lock.json")
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    pkgs = []
    dependencies = data.get("dependencies") or {}
    if not isinstance(dependencies, dict):
        return []
    for target_packages in dependencies.values():
        if not isinstance(target_packages, dict):
            continue
        for name, info in target_packages.items():
            if not isinstance(info, dict):
                continue
            version = str(info.get("resolved") or "").strip()
            if not name or not version:
                continue
            pkgs.append(
                {
                    "ecosystem": "nuget",
                    "name": str(name),
                    "version": version,
                    "is_direct": str(info.get("type") or "").lower() == "direct",
                    "source": "packages.lock.json",
                }
            )
    return pkgs


def parse_packages_config(project_path):
    path = os.path.join(project_path, "packages.config")
    if not os.path.isfile(path):
        return []
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return []

    pkgs = []
    for package in root.findall(".//package"):
        name = str(package.get("id") or "").strip()
        version = str(package.get("version") or "").strip()
        if not name or not version:
            continue
        pkgs.append(
            {
                "ecosystem": "nuget",
                "name": name,
                "version": version,
                "is_direct": True,
                "source": "packages.config",
            }
        )
    return pkgs


def parse_nuget(project_path):
    pkgs, seen = [], set()
    for parser in (parse_packages_lock_json, parse_packages_config):
        for pkg in parser(project_path):
            key = (
                pkg["ecosystem"],
                str(pkg["name"]).lower(),
                pkg["version"],
            )
            if key in seen:
                continue
            seen.add(key)
            pkgs.append(pkg)
    return pkgs


# --- JVM / Maven ---


def xml_local_name(tag):
    return str(tag or "").rsplit("}", 1)[-1]


def xml_child_text(element, name):
    for child in list(element):
        if xml_local_name(child.tag) == name:
            return str(child.text or "").strip()
    return ""


def xml_direct_children(element, name):
    return [child for child in list(element) if xml_local_name(child.tag) == name]


def is_exact_dependency_version(version):
    version = str(version or "").strip()
    if not version or version.startswith("${") or re.search(r"[\[\](),]", version):
        return False
    return bool(re.match(r"^[0-9][0-9A-Za-z._+-]*$", version))


def is_exact_maven_coordinate_part(value):
    text = str(value or "").strip()
    if not text or "${" in text or "}" in text:
        return False
    return bool(re.match(r"^[A-Za-z0-9_.-]+$", text))


def parse_maven_pom(project_path):
    path = os.path.join(project_path, "pom.xml")
    if not os.path.isfile(path):
        return []
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return []

    pkgs, seen = [], set()
    direct_dependencies = []
    for dependencies in xml_direct_children(root, "dependencies"):
        direct_dependencies.extend(xml_direct_children(dependencies, "dependency"))
    for dependency in direct_dependencies:
        group_id = xml_child_text(dependency, "groupId")
        artifact_id = xml_child_text(dependency, "artifactId")
        version = xml_child_text(dependency, "version")
        if (
            not is_exact_maven_coordinate_part(group_id)
            or not is_exact_maven_coordinate_part(artifact_id)
            or not is_exact_dependency_version(version)
        ):
            continue
        name = f"{group_id}:{artifact_id}"
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        pkgs.append(
            {
                "ecosystem": "maven",
                "name": name,
                "version": version,
                "is_direct": True,
                "source": "pom.xml",
            }
        )
    return pkgs


# --- Python ---


def parse_requirements_txt(project_path):
    """解析 requirements.txt，并支持更完整的 PEP 440 写法。

    支持：
    - PEP 440 版本约束：>=、<=、~=、!=、===、>、<
    - 注释和空行
    - -r / --requirement include（递归深度最多 5 层）
    - Extras 写法：package[extra1,extra2]==1.0
    - 环境标记（分号后的部分）
    - 反斜杠行续接

    漏洞匹配只纳入 == 或 === 固定版本的包。
    """
    project_root = os.path.realpath(project_path)
    path = os.path.join(project_root, "requirements.txt")
    if not os.path.isfile(path):
        return []

    pkgs = []
    seen = set()
    visited = set()

    def _safe_requirements_file(filepath):
        real_path = os.path.realpath(filepath)
        try:
            if os.path.commonpath([project_root, real_path]) != project_root:
                return ""
        except ValueError:
            return ""
        if not os.path.isfile(real_path):
            return ""
        try:
            if os.path.getsize(real_path) > 1024 * 1024:
                return ""
        except OSError:
            return ""
        return real_path

    def _parse_file(filepath, depth=0):
        if depth > 5:
            return
        filepath = _safe_requirements_file(filepath)
        if not filepath or filepath in visited:
            return
        visited.add(filepath)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except OSError:
            return

        # 处理行续接（行尾反斜杠）。
        merged_lines = []
        current = ""
        for raw_line in lines:
            raw_line = raw_line.rstrip("\n")
            if raw_line.endswith("\\"):
                current += raw_line[:-1]
                continue
            current += raw_line
            merged_lines.append(current)
            current = ""
        if current:
            merged_lines.append(current)

        for line in merged_lines:
            line = line.strip()

            # 跳过空行和注释。
            if not line or line.startswith("#"):
                continue

            # 处理 -r / --requirement 引用。
            if line.startswith("-r ") or line.startswith("--requirement "):
                parts = line.split(None, 1)
                if len(parts) == 2:
                    include_path = parts[1].strip()
                    if not os.path.isabs(include_path):
                        include_path = os.path.join(
                            os.path.dirname(filepath), include_path
                        )
                    _parse_file(include_path, depth + 1)
                continue

            # 跳过其他 pip 参数（-i、--index-url、-e 等）。
            if line.startswith("-"):
                continue

            # 移除环境标记（分号之后）。
            line = line.split(";", 1)[0].strip()
            if not line:
                continue

            # Parse: name[extras] specifier version
            m = re.match(
                r"^([A-Za-z0-9_.-]+)"
                r"(?:\[[^\]]*\])?"  # optional extras
                r"\s*(===|==|~=|>=|<=|!=|>|<)\s*"
                r"([0-9][0-9A-Za-z.*+!_-]*)",
                line,
            )
            if not m:
                continue

            name = m.group(1).lower()
            specifier = m.group(2)
            version = m.group(3)

            # 漏洞匹配只使用精确版本。
            if specifier not in {"==", "==="} or "*" in version:
                continue

            key = (name, version)
            if key not in seen:
                seen.add(key)
                pkgs.append(
                    {
                        "ecosystem": "pypi",
                        "name": name,
                        "version": version,
                        "specifier": specifier,
                        "is_direct": True,
                        "source": "requirements.txt",
                    }
                )

    _parse_file(path)
    return pkgs


def parse_pipfile_lock(project_path):
    path = os.path.join(project_path, "Pipfile.lock")
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    pkgs = []
    for section_name, is_direct in (("default", True), ("develop", False)):
        section = data.get(section_name) or {}
        for name, info in section.items():
            if isinstance(info, str):
                version = info
            elif isinstance(info, dict):
                version = info.get("version", "")
            else:
                version = ""
            version = str(version or "").strip()
            specifier = ""
            if version.startswith("=="):
                specifier = "=="
                version = version[2:]
            elif version.startswith("="):
                specifier = "="
                version = version[1:]
            if not version:
                continue
            pkgs.append(
                {
                    "ecosystem": "pypi",
                    "name": name.lower(),
                    "version": version,
                    "specifier": specifier or "==",
                    "is_direct": is_direct,
                    "source": "Pipfile.lock",
                }
            )
    return pkgs


def _parse_toml_lock(path, source_name):
    tl = _tomllib()
    if not tl:
        return _parse_toml_lock_fallback(path, source_name)
    try:
        with open(path, "rb") as f:
            data = tl.load(f)
    except Exception:
        return []
    pkgs = []
    for pkg in data.get("package", []):
        pkgs.append(
            {
                "ecosystem": "pypi",
                "name": pkg.get("name", "").lower(),
                "version": pkg.get("version", ""),
                "is_direct": False,
                "source": source_name,
            }
        )
    return pkgs


def _parse_toml_lock_fallback(path, source_name):
    pkgs = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError:
        return []
    for m in re.finditer(
        r'\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"', content
    ):
        pkgs.append(
            {
                "ecosystem": "pypi",
                "name": m.group(1).lower(),
                "version": m.group(2),
                "is_direct": False,
                "source": source_name,
            }
        )
    return pkgs


def parse_poetry_lock(project_path):
    path = os.path.join(project_path, "poetry.lock")
    return _parse_toml_lock(path, "poetry.lock") if os.path.isfile(path) else []


def parse_uv_lock(project_path):
    path = os.path.join(project_path, "uv.lock")
    return _parse_toml_lock(path, "uv.lock") if os.path.isfile(path) else []


def parse_pypi(project_path):
    pkgs = []
    for parser in (
        parse_poetry_lock,
        parse_uv_lock,
        parse_pipfile_lock,
        parse_requirements_txt,
    ):
        pkgs.extend(parser(project_path))
    return pkgs


# --- Go ---


def parse_go_sum(project_path):
    path = os.path.join(project_path, "go.sum")
    if not os.path.isfile(path):
        return []
    pkgs, seen = [], set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2:
                    name, ver = parts[0], parts[1].split("/")[0]
                    if (name, ver) not in seen:
                        seen.add((name, ver))
                        pkgs.append(
                            {
                                "ecosystem": "go",
                                "name": name,
                                "version": ver,
                                "is_direct": False,
                                "source": "go.sum",
                            }
                        )
    except OSError:
        pass
    return pkgs


# --- Rust ---


def parse_cargo_lock(project_path):
    path = os.path.join(project_path, "Cargo.lock")
    if not os.path.isfile(path):
        return []
    tl = _tomllib()
    if not tl:
        return _parse_cargo_lock_fallback(path)
    try:
        with open(path, "rb") as f:
            data = tl.load(f)
    except Exception:
        return []
    pkgs = []
    for pkg in data.get("package", []):
        if pkg.get("source"):
            pkgs.append(
                {
                    "ecosystem": "crates-io",
                    "name": pkg.get("name", ""),
                    "version": pkg.get("version", ""),
                    "is_direct": False,
                    "source": "Cargo.lock",
                }
            )
    return pkgs


def _parse_cargo_lock_fallback(path):
    pkgs = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError:
        return []
    for m in re.finditer(
        r'\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"\s*\nsource\s*=\s*"([^"]+)"',
        content,
    ):
        pkgs.append(
            {
                "ecosystem": "crates-io",
                "name": m.group(1),
                "version": m.group(2),
                "is_direct": False,
                "source": "Cargo.lock",
            }
        )
    return pkgs


PARSERS = {
    "npm": parse_npm_lock,
    "pnpm": parse_pnpm_lock,
    "yarn": parse_yarn_lock,
    "pypi": parse_pypi,
    "go": parse_go_sum,
    "crates-io": parse_cargo_lock,
    "packagist": parse_composer_lock,
    "rubygems": parse_gemfile_lock,
    "pub": parse_pubspec_lock,
    "hex": parse_mix_lock,
    "nuget": parse_nuget,
    "maven": parse_maven_pom,
}


def extract_packages(project_path, ecosystems):
    all_pkgs, seen = [], set()
    for eco in ecosystems:
        parser = PARSERS.get(eco)
        if not parser:
            continue
        for pkg in parser(project_path):
            key = (pkg["ecosystem"], pkg["name"], pkg["version"])
            if key not in seen:
                seen.add(key)
                all_pkgs.append(pkg)
    return all_pkgs


def package_source_summary(packages):
    counts = {}
    for pkg in packages:
        key = (pkg.get("ecosystem", ""), pkg.get("source", ""))
        counts[key] = counts.get(key, 0) + 1
    return [
        {"ecosystem": eco, "source": source, "count": count}
        for (eco, source), count in sorted(counts.items())
    ]


def package_version_index(packages):
    index = {}
    for pkg in packages or []:
        ecosystem = pkg.get("ecosystem")
        name = pkg.get("name")
        version = pkg.get("version")
        if not ecosystem or not name or not version:
            continue
        key = (str(ecosystem).lower(), str(name).lower())
        index.setdefault(key, version)
    return index


def current_version_for(version_index, ecosystem, package):
    if not version_index or not ecosystem or not package:
        return ""
    return version_index.get((str(ecosystem).lower(), str(package).lower()), "")


def clean_version(value):
    return str(value or "").strip().lstrip("v")
