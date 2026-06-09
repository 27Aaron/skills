"""Local repository governance and supply-chain checks."""

from __future__ import annotations

import json
import os
import re
import subprocess

try:
    from .finding_utils import (
        dedupe_findings,
        iter_files,
        line_for_text,
        make_finding,
        read_text,
        relpath,
    )
except ImportError:  # pragma: no cover
    from finding_utils import (  # pyright: ignore[reportMissingImports]
        dedupe_findings,
        iter_files,
        line_for_text,
        make_finding,
        read_text,
        relpath,
    )


DEPENDABOT_SUPPORTED_PACKAGE_ECOSYSTEMS = (
    "bazel",
    "bun",
    "bundler",
    "cargo",
    "composer",
    "conda",
    "deno",
    "devcontainers",
    "docker",
    "docker-compose",
    "dotnet-sdk",
    "helm",
    "mix",
    "julia",
    "elm",
    "gitsubmodule",
    "github-actions",
    "gomod",
    "gradle",
    "maven",
    "nix",
    "npm",
    "nuget",
    "opentofu",
    "pip",
    "pre-commit",
    "pub",
    "rust-toolchain",
    "sbt",
    "swift",
    "terraform",
    "uv",
    "vcpkg",
)

DEPENDABOT_ECOSYSTEMS = {
    "bazel": "bazel",
    "bun": "bun",
    "bundler": "bundler",
    "cargo": "cargo",
    "composer": "composer",
    "conda": "conda",
    "deno": "deno",
    "devcontainers": "devcontainers",
    "docker": "docker",
    "docker-compose": "docker-compose",
    "dotnet-sdk": "dotnet-sdk",
    "helm": "helm",
    "hex": "mix",
    "mix": "mix",
    "julia": "julia",
    "elm": "elm",
    "gitsubmodule": "gitsubmodule",
    "github-actions": "github-actions",
    "npm": "npm",
    "pnpm": "npm",
    "yarn": "npm",
    "node": "npm",
    "javascript": "npm",
    "typescript": "npm",
    "nuget": "nuget",
    "opentofu": "opentofu",
    "pip": "pip",
    "pypi": "pip",
    "pipenv": "pip",
    "pip-compile": "pip",
    "poetry": "pip",
    "python": "pip",
    "pre-commit": "pre-commit",
    "pub": "pub",
    "rust-toolchain": "rust-toolchain",
    "sbt": "sbt",
    "swift": "swift",
    "terraform": "terraform",
    "uv": "uv",
    "vcpkg": "vcpkg",
    "go": "gomod",
    "gomod": "gomod",
    "gradle": "gradle",
    "maven": "maven",
    "nix": "nix",
    "crates-io": "cargo",
}

DEPENDABOT_HINT_NAMES = {
    ".gitmodules",
    ".pre-commit-config.yaml",
    ".pre-commit-config.yml",
    "build.properties",
    "build.sbt",
    "bun.lock",
    "cargo.lock",
    "cargo.toml",
    "chart.yaml",
    "composer.json",
    "composer.lock",
    "containerfile",
    "deno.json",
    "deno.jsonc",
    "devcontainer.json",
    "docker-compose.yaml",
    "docker-compose.yml",
    "dockerfile",
    "elm.json",
    "environment.yaml",
    "environment.yml",
    "flake.lock",
    "flake.nix",
    "gemfile",
    "gemfile.lock",
    "global.json",
    "go.mod",
    "go.sum",
    "gradle.lockfile",
    "gradle-wrapper.properties",
    "manifest.toml",
    "mix.exs",
    "mix.lock",
    "module.bazel",
    "module.bazel.lock",
    "package-lock.json",
    "package.json",
    "package.resolved",
    "package.swift",
    "packages.config",
    "pipfile",
    "pipfile.lock",
    "plugins.sbt",
    "pnpm-lock.yaml",
    "pom.xml",
    "poetry.lock",
    "project.toml",
    "pubspec.lock",
    "pubspec.yaml",
    "pyproject.toml",
    "requirements.txt",
    "rust-toolchain",
    "rust-toolchain.toml",
    "uv.lock",
    "vcpkg-configuration.json",
    "vcpkg.json",
    "workspace",
    "workspace.bazel",
    "yarn.lock",
}
DEPENDABOT_HINT_SUFFIXES = (
    ".csproj",
    ".fsproj",
    ".gradle",
    ".kts",
    ".props",
    ".scala",
    ".tf",
    ".tofu",
    ".vbproj",
    ".yml",
    ".yaml",
)
DEPENDABOT_WEEKLY_INTERVAL = "weekly"

REGISTRY_CONFIG_FILES = (
    ".npmrc",
    ".pypirc",
    "pip.conf",
    "pip.ini",
    "poetry.toml",
    ".cargo/config",
    ".cargo/config.toml",
)
TOKEN_RE = re.compile(
    r"(?i)(?:_authToken|token|password|secret|apikey|api[_-]?key)\s*[=:]\s*['\"]?[^'\"\s]{8,}"
)
REGISTRY_SOURCE_RE = re.compile(
    r"(?i)^\s*(?:\[\[?tool\.poetry\.source\]?\]|\[(?:source|registries)\.|@[^:\s]+:registry|registry|registries\.[A-Za-z0-9_.-]+\.index|index|index-url|extra-index-url|repository|index-servers|replace-with)(?:\s*[=:]\s*\S+)?"
)
REGISTRY_INSECURE_RE = re.compile(
    r"(?i)^\s*(?:strict-ssl\s*=\s*false|trusted-host\s*=.+|verify_ssl\s*=\s*false|sslverify\s*=\s*false)"
)
SUSPICIOUS_SCRIPT_RE = re.compile(
    r"(?i)(curl|wget).+\|\s*(sh|bash)|base64\s+(-d|--decode)|chmod\s+\+x|/etc/profile|\.bashrc|\.zshrc"
)
DEPENDABOT_ECOSYSTEM_RE = re.compile(
    r"package-ecosystem\s*:\s*['\"]?([^'\"\s#]+)"
)


def _exists_any(project_path, candidates):
    return any(
        os.path.exists(os.path.join(project_path, candidate))
        for candidate in candidates
    )


def _dependabot_text(project_path):
    for candidate in (".github/dependabot.yml", ".github/dependabot.yaml"):
        path = os.path.join(project_path, candidate)
        if os.path.isfile(path):
            return path, read_text(path)
    return "", ""


def _dependabot_directory(rel_file):
    directory = os.path.dirname(str(rel_file or "").replace(os.sep, "/"))
    return f"/{directory}" if directory else "/"


def _add_dependabot_entry(entries, package_ecosystem, rel_file, directory=None):
    if not package_ecosystem:
        return
    entries.append(
        {
            "package-ecosystem": package_ecosystem,
            "directory": directory or _dependabot_directory(rel_file),
        }
    )


def _dependabot_entries_for_file(rel_file):
    rel = str(rel_file or "").replace(os.sep, "/")
    lower = rel.lower()
    name = os.path.basename(lower)
    entries = []

    if lower.startswith(".github/workflows/") and name.endswith((".yml", ".yaml")):
        _add_dependabot_entry(entries, "github-actions", rel, directory="/")
    if name == ".gitmodules":
        _add_dependabot_entry(entries, "gitsubmodule", rel, directory="/")
    if name in {".pre-commit-config.yaml", ".pre-commit-config.yml"}:
        _add_dependabot_entry(entries, "pre-commit", rel)
    if name in {"module.bazel", "module.bazel.lock", "workspace", "workspace.bazel"}:
        _add_dependabot_entry(entries, "bazel", rel)
    if name == "bun.lock":
        _add_dependabot_entry(entries, "bun", rel)
    if name in {"gemfile", "gemfile.lock"}:
        _add_dependabot_entry(entries, "bundler", rel)
    if name in {"cargo.toml", "cargo.lock"}:
        _add_dependabot_entry(entries, "cargo", rel)
    if name in {"composer.json", "composer.lock"}:
        _add_dependabot_entry(entries, "composer", rel)
    if name in {"environment.yml", "environment.yaml"}:
        _add_dependabot_entry(entries, "conda", rel)
    if name in {"deno.json", "deno.jsonc"}:
        _add_dependabot_entry(entries, "deno", rel)
    if name == "devcontainer.json" or lower.endswith("/.devcontainer/devcontainer.json"):
        _add_dependabot_entry(entries, "devcontainers", rel, directory="/")
    if name in {"dockerfile", "containerfile"}:
        _add_dependabot_entry(entries, "docker", rel)
    if name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
        _add_dependabot_entry(entries, "docker-compose", rel)
    if name == "global.json":
        _add_dependabot_entry(entries, "dotnet-sdk", rel)
    if name == "chart.yaml":
        _add_dependabot_entry(entries, "helm", rel)
    if name in {"mix.exs", "mix.lock"}:
        _add_dependabot_entry(entries, "mix", rel)
    if name in {"project.toml", "manifest.toml"}:
        _add_dependabot_entry(entries, "julia", rel)
    if name == "elm.json":
        _add_dependabot_entry(entries, "elm", rel)
    if name in {"go.mod", "go.sum"}:
        _add_dependabot_entry(entries, "gomod", rel)
    if name in {"build.gradle", "build.gradle.kts", "gradle.lockfile", "gradle-wrapper.properties"}:
        _add_dependabot_entry(entries, "gradle", rel)
    if lower == "gradle/libs.versions.toml":
        _add_dependabot_entry(entries, "gradle", rel)
    if name == "pom.xml":
        _add_dependabot_entry(entries, "maven", rel)
    if name in {"flake.lock", "flake.nix"}:
        _add_dependabot_entry(entries, "nix", rel)
    if name in {"package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"}:
        _add_dependabot_entry(entries, "npm", rel)
    if (
        name.endswith((".csproj", ".vbproj", ".fsproj"))
        or name in {"packages.config", "directory.packages.props"}
    ):
        _add_dependabot_entry(entries, "nuget", rel)
    if name.endswith(".tofu") or name == ".terraform.lock.hcl":
        _add_dependabot_entry(entries, "opentofu", rel)
    if (
        name in {"pipfile", "pipfile.lock", "poetry.lock", "pyproject.toml"}
        or name.startswith("requirements") and name.endswith(".txt")
    ):
        _add_dependabot_entry(entries, "pip", rel)
    if name == "uv.lock":
        _add_dependabot_entry(entries, "uv", rel)
    if name in {"pubspec.yaml", "pubspec.lock"}:
        _add_dependabot_entry(entries, "pub", rel)
    if name in {"rust-toolchain", "rust-toolchain.toml"}:
        _add_dependabot_entry(entries, "rust-toolchain", rel)
    if (
        name == "build.sbt"
        or lower.startswith("project/") and name in {"plugins.sbt", "build.properties"}
        or lower.startswith("project/") and name.endswith(".scala")
    ):
        _add_dependabot_entry(entries, "sbt", rel)
    if name in {"package.swift", "package.resolved"}:
        _add_dependabot_entry(entries, "swift", rel)
    if name.endswith(".tf") or name == "terragrunt.hcl":
        _add_dependabot_entry(entries, "terraform", rel)
    if name in {"vcpkg.json", "vcpkg-configuration.json"}:
        _add_dependabot_entry(entries, "vcpkg", rel)
    return entries


def _dedupe_dependabot_entries(entries):
    order = {value: index for index, value in enumerate(DEPENDABOT_SUPPORTED_PACKAGE_ECOSYSTEMS)}
    seen = set()
    result = []
    for entry in sorted(
        entries or [],
        key=lambda item: (
            order.get(item.get("package-ecosystem"), 999),
            item.get("directory") or "/",
        ),
    ):
        key = (entry.get("package-ecosystem"), entry.get("directory") or "/")
        if not key[0] or key in seen:
            continue
        seen.add(key)
        result.append(
            {"package-ecosystem": key[0], "directory": key[1]}
        )
    return result


def detect_dependabot_updates(project_path, ecosystems=None):
    entries = []
    for ecosystem in ecosystems or []:
        expected = DEPENDABOT_ECOSYSTEMS.get(ecosystem)
        if expected:
            _add_dependabot_entry(entries, expected, "", directory="/")

    for path in iter_files(
        project_path,
        suffixes=DEPENDABOT_HINT_SUFFIXES,
        names=DEPENDABOT_HINT_NAMES,
        max_files=5000,
    ):
        entries.extend(_dependabot_entries_for_file(relpath(path, project_path)))
    return _dedupe_dependabot_entries(entries)


def build_dependabot_config(project_path, ecosystems=None):
    entries = detect_dependabot_updates(project_path, ecosystems=ecosystems)
    if not entries:
        return ""
    lines = ["version: 2", "updates:"]
    for entry in entries:
        lines.extend(
            [
                f'  - package-ecosystem: "{entry["package-ecosystem"]}"',
                f'    directory: "{entry["directory"]}"',
                "    schedule:",
                f'      interval: "{DEPENDABOT_WEEKLY_INTERVAL}"',
            ]
        )
    return "\n".join(lines) + "\n"


def _is_github_remote_url(url):
    value = str(url or "").strip().lower()
    return (
        value.startswith("git@github.com:")
        or value.startswith("https://github.com/")
        or value.startswith("http://github.com/")
        or value.startswith("ssh://git@github.com/")
        or value.startswith("git://github.com/")
        or "://git@github.com/" in value
        or "://github.com/" in value
        or "@github.com:" in value
    )


def github_remote_evidence(project_path):
    try:
        result = subprocess.run(
            ["git", "config", "--get-regexp", r"^remote\..*\.url$"],
            cwd=project_path,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=3,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if result.returncode not in (0, 1):
        return ""
    for line in result.stdout.splitlines():
        key, _, url = line.partition(" ")
        if not key or not url or not _is_github_remote_url(url):
            continue
        parts = key.split(".")
        remote = parts[1] if len(parts) > 2 else "remote"
        return f"GitHub remote {remote}: {url.strip()}"
    return ""


def _dependabot_has_ecosystem(dependabot, package_ecosystem):
    if not dependabot or not package_ecosystem:
        return False
    return package_ecosystem in {
        match.group(1)
        for match in DEPENDABOT_ECOSYSTEM_RE.finditer(str(dependabot))
    }


def _has_lockfile_for_manifest(project_path, manifest):
    checks = {
        "package.json": ("package-lock.json", "pnpm-lock.yaml", "yarn.lock"),
        "pyproject.toml": ("poetry.lock", "uv.lock"),
        "go.mod": ("go.sum",),
        "Cargo.toml": ("Cargo.lock",),
    }
    return _exists_any(project_path, checks.get(manifest, ()))


def _package_script_findings(project_path):
    path = os.path.join(project_path, "package.json")
    if not os.path.isfile(path):
        return []
    try:
        data = json.loads(read_text(path))
    except json.JSONDecodeError:
        return []
    scripts = data.get("scripts") if isinstance(data, dict) else {}
    if not isinstance(scripts, dict):
        return []
    findings = []
    for name, command in scripts.items():
        if name not in {"preinstall", "install", "postinstall", "prepare"}:
            continue
        if not SUSPICIOUS_SCRIPT_RE.search(str(command)):
            continue
        findings.append(
            make_finding(
                "supply_chain.suspicious_install_script",
                category="supply_chain",
                severity="high",
                confidence="medium",
                file="package.json",
                line=line_for_text(path, str(command)),
                title="package.json 安装脚本存在高风险行为",
                detail="安装阶段自动下载远程脚本、解码执行或修改 shell 配置，会放大依赖安装阶段的供应链风险。",
                evidence=f"{name}: {command}",
                recommendation="改为固定版本包或本地脚本；如必须下载远程内容，需要固定 URL、校验 checksum/signature，并让用户确认。",
            )
        )
    return findings


def _registry_config_findings(project_path):
    findings = []
    for rel in REGISTRY_CONFIG_FILES:
        path = os.path.join(project_path, rel)
        if not os.path.isfile(path):
            continue
        text = read_text(path)
        if TOKEN_RE.search(text):
            match = TOKEN_RE.search(text)
            findings.append(
                make_finding(
                    "supply_chain.registry_token_config",
                    category="supply_chain",
                    severity="high",
                    confidence="high",
                    file=rel,
                    line=text[: match.start()].count("\n") + 1 if match else 1,
                    title="包管理器配置中出现认证凭据",
                    detail="registry 配置文件中的 token、password 或 secret 可能让包发布、安装或私有源访问凭据随仓库泄露。",
                    evidence=match.group(0) if match else rel,
                    recommendation="把凭据移到本机或 CI secret 管理；如已提交，先轮换凭据，再清理历史记录。",
                )
            )
            continue

        source_match = _first_config_line(text, REGISTRY_SOURCE_RE)
        insecure_match = _first_config_line(text, REGISTRY_INSECURE_RE)
        if insecure_match:
            line_no, evidence = insecure_match
            findings.append(
                make_finding(
                    "supply_chain.registry_insecure_tls",
                    category="supply_chain",
                    severity="medium",
                    confidence="high",
                    file=rel,
                    line=line_no,
                    title="包管理器配置降低 registry TLS 校验",
                    detail="关闭严格 TLS 校验或信任额外主机，会降低依赖下载链路的完整性保护。",
                    evidence=evidence,
                    recommendation="移除 strict-ssl=false、trusted-host 或类似例外；必须使用内网源时，优先配置受信任证书。",
                )
            )
        if source_match:
            line_no, evidence = source_match
            findings.append(
                make_finding(
                    "supply_chain.registry_config_present",
                    category="supply_chain",
                    severity="low",
                    confidence="medium",
                    file=rel,
                    line=line_no,
                    title="仓库包含包管理器 registry 配置",
                    detail="registry 配置可能改变依赖来源；需要确认是否为团队认可的源，避免依赖混淆或误用私有源。",
                    evidence=evidence,
                    recommendation="确认 registry 域名和 scope 配置符合团队预期；不要在文件中保存认证凭据。",
                )
            )
    return findings


def _first_config_line(text, pattern):
    for line_no, line in enumerate(str(text or "").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        if pattern.search(stripped):
            return line_no, stripped
    return None


def scan_repository_checks(project_path: str, ecosystems=None):
    findings = []
    ecosystems = ecosystems or []

    dependabot_path, dependabot = _dependabot_text(project_path)
    has_github_actions = os.path.isdir(
        os.path.join(project_path, ".github", "workflows")
    )
    dependabot_entries = detect_dependabot_updates(project_path, ecosystems)
    github_evidence = github_remote_evidence(project_path)
    if not dependabot and github_evidence and dependabot_entries:
        content = build_dependabot_config(project_path, ecosystems)
        ecosystem_names = [
            entry["package-ecosystem"] for entry in dependabot_entries
        ]
        visible = "、".join(ecosystem_names[:8])
        if len(ecosystem_names) > 8:
            visible += f" 等 {len(ecosystem_names)} 个生态"
        detail = (
            "检测到仓库 remote 指向 GitHub，且项目包含 Dependabot 支持的依赖生态"
            "或 GitHub Actions 配置；可用 Dependabot 定期创建版本更新 PR。"
        )
        recommendation = (
            ".github/dependabot.yml，"
            f"建议创建覆盖 {visible} 的配置；推送到 GitHub 后，Dependabot 会按 schedule 检查更新。"
        )
        findings.append(
            make_finding(
                "repo.missing_dependabot",
                category="repo_governance",
                severity="info",
                confidence="high",
                file=".github/dependabot.yml",
                line=None,
                title="配置 Dependabot",
                detail=detail,
                evidence=github_evidence,
                recommendation=recommendation,
                fixable=True,
                fix_config={
                    "type": "dependabot_config",
                    "path": ".github/dependabot.yml",
                    "content": content,
                    "ecosystems": ecosystem_names,
                },
                kind="maintenance_advice",
            )
        )
    elif has_github_actions and not _dependabot_has_ecosystem(
        dependabot, "github-actions"
    ):
        findings.append(
            make_finding(
                "repo.dependabot_missing_github_actions",
                category="repo_governance",
                severity="info",
                confidence="high",
                file=relpath(dependabot_path, project_path),
                line=1,
                title="维护 workflow 中的 Action 版本",
                detail="这里用于检查 workflow 里 uses: 引用的 Action 版本；更新节奏由 Dependabot 的 schedule 控制。",
                evidence="",
                recommendation="建议在 dependabot.yml 中加入 package-ecosystem: github-actions，directory 设为 /，用于维护 .github/workflows 中引用的 Action 版本。",
                kind="maintenance_advice",
            )
        )

    checked_ecosystems = _dedupe_dependabot_entries(
        [
            {
                "package-ecosystem": entry["package-ecosystem"],
                "directory": "/",
            }
            for entry in dependabot_entries
        ]
    )
    for entry in checked_ecosystems:
        expected = entry["package-ecosystem"]
        if (
            dependabot
            and expected
            and not _dependabot_has_ecosystem(dependabot, expected)
        ):
            findings.append(
                make_finding(
                    "repo.dependabot_missing_ecosystem",
                    category="repo_governance",
                    severity="info",
                    confidence="medium",
                    file=relpath(dependabot_path, project_path),
                    line=1,
                    title="覆盖当前依赖生态",
                    detail=f"本项目检测到 Dependabot 支持的 {expected} 配置，但 dependabot.yml 未覆盖该生态；补齐后可以让依赖版本维护有固定提醒。",
                    evidence="",
                    recommendation="可补充对应 package-ecosystem，让依赖版本维护有固定提醒。",
                    kind="maintenance_advice",
                )
            )

    for manifest in ("package.json", "pyproject.toml", "go.mod", "Cargo.toml"):
        if os.path.isfile(
            os.path.join(project_path, manifest)
        ) and not _has_lockfile_for_manifest(project_path, manifest):
            findings.append(
                make_finding(
                    "supply_chain.lockfile_missing",
                    category="supply_chain",
                    severity="medium",
                    confidence="high",
                    file=manifest,
                    line=1,
                    title="依赖清单缺少对应 lockfile",
                    detail="没有 lockfile 时，安装结果可能随时间漂移，也会降低依赖漏洞扫描的确定性。",
                    evidence=f"{manifest} without lockfile",
                    recommendation="为应用项目提交对应 lockfile；库项目如刻意不提交，需要在 README 或安全说明中写明理由。",
                )
            )

    findings.extend(_package_script_findings(project_path))
    findings.extend(_registry_config_findings(project_path))

    return dedupe_findings(findings)
