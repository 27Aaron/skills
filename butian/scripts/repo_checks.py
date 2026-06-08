"""Local repository governance and supply-chain checks."""

from __future__ import annotations

import json
import os
import re

try:
    from .finding_utils import (
        dedupe_findings,
        line_for_text,
        make_finding,
        read_text,
        relpath,
    )
except ImportError:  # pragma: no cover
    from finding_utils import (  # pyright: ignore[reportMissingImports]
        dedupe_findings,
        line_for_text,
        make_finding,
        read_text,
        relpath,
    )


DEPENDABOT_ECOSYSTEMS = {
    "npm": "npm",
    "pnpm": "npm",
    "yarn": "npm",
    "pypi": "pip",
    "go": "gomod",
    "crates-io": "cargo",
}

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
    has_github_config = os.path.exists(os.path.join(project_path, ".github"))
    has_github_actions = os.path.isdir(
        os.path.join(project_path, ".github", "workflows")
    )
    if not dependabot and has_github_config:
        if has_github_actions:
            detail = "检测到项目使用 GitHub Actions；Dependabot 可定期检查 workflow 中引用的 Action 版本，减少人工维护遗漏。"
            recommendation = (
                "建议新增 .github/dependabot.yml，让 GitHub 按计划检查 .github/workflows 中引用的 Action 版本；"
                "如项目还有 npm、pip 等依赖，再补充对应包管理生态，后续通过 Dependabot PR 或通知处理更新。"
            )
        else:
            detail = "检测到项目已有 .github 配置；补齐 Dependabot 后，依赖版本维护会有固定提醒。"
            recommendation = (
                "建议新增 .github/dependabot.yml，并按项目实际依赖补充对应包管理生态。"
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
                evidence="",
                recommendation=recommendation,
                kind="maintenance_advice",
            )
        )
    elif has_github_actions and "package-ecosystem: github-actions" not in dependabot:
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

    for ecosystem in ecosystems:
        expected = DEPENDABOT_ECOSYSTEMS.get(ecosystem)
        if (
            dependabot
            and expected
            and f"package-ecosystem: {expected}" not in dependabot
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
                    detail=f"本项目检测到 {ecosystem}，但 dependabot.yml 未覆盖对应生态 {expected}；补齐后可以让依赖版本维护有固定提醒。",
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
