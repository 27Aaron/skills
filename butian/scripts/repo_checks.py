"""Local repository governance and supply-chain checks."""

from __future__ import annotations

import json
import os
import re

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


def _release_integrity_hints(project_path):
    hints = (
        "sbom",
        "cyclonedx",
        "spdx",
        "attestation",
        "attest",
        "provenance",
        "cosign",
        "sigstore",
        "slsa",
        "syft",
    )
    for path in iter_files(
        project_path,
        suffixes=(".yml", ".yaml", ".json", ".toml", ".md", ".sh"),
        max_files=800,
    ):
        name = os.path.basename(path).lower()
        if any(hint in name for hint in hints):
            return True
        text = read_text(path, max_bytes=128 * 1024).lower()
        if any(hint in text for hint in hints):
            return True
    return False


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
        else:
            findings.append(
                make_finding(
                    "supply_chain.registry_config_present",
                    category="supply_chain",
                    severity="low",
                    confidence="medium",
                    file=rel,
                    line=1,
                    title="仓库包含包管理器 registry 配置",
                    detail="registry 配置可能改变依赖来源；需要确认是否为团队认可的源，避免依赖混淆或误用私有源。",
                    evidence=rel,
                    recommendation="确认 registry 域名和 scope 配置符合团队预期；不要在文件中保存认证凭据。",
                )
            )
    return findings


def scan_repository_checks(project_path: str, ecosystems=None):
    findings = []
    ecosystems = ecosystems or []

    dependabot_path, dependabot = _dependabot_text(project_path)
    if not dependabot:
        findings.append(
            make_finding(
                "repo.missing_dependabot",
                category="repo_governance",
                severity="info",
                confidence="high",
                file=".github/dependabot.yml",
                line=None,
                title="建议配置 Dependabot",
                detail="Dependabot 可以定期提醒依赖和 GitHub Actions 更新；缺少它不代表当前存在漏洞，只是后续维护更依赖人工记忆。",
                evidence="dependabot.yml not found",
                recommendation="如项目使用 GitHub，可新增本地可审阅的 .github/dependabot.yml，覆盖 github-actions 和主要包管理生态。",
                kind="maintenance_advice",
            )
        )
    elif "package-ecosystem: github-actions" not in dependabot:
        findings.append(
            make_finding(
                "repo.dependabot_missing_github_actions",
                category="repo_governance",
                severity="info",
                confidence="high",
                file=relpath(dependabot_path, project_path),
                line=1,
                title="建议让 Dependabot 覆盖 GitHub Actions",
                detail="Actions 版本同样属于供应链依赖；缺少该配置不代表漏洞，只是少了一条自动更新提醒。",
                evidence="missing package-ecosystem: github-actions",
                recommendation="可在 dependabot.yml 中加入 package-ecosystem: github-actions 和 /.github/workflows 目录。",
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
                    title="建议让 Dependabot 覆盖当前依赖生态",
                    detail=f"本项目检测到 {ecosystem}，但 dependabot.yml 未覆盖对应生态 {expected}；这属于维护建议，不代表当前依赖已存在漏洞。",
                    evidence=f"missing package-ecosystem: {expected}",
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

    if not _release_integrity_hints(project_path):
        findings.append(
            make_finding(
                "release.integrity_hints_missing",
                category="release_integrity",
                severity="info",
                confidence="low",
                file="",
                line=None,
                title="未发现 SBOM、签名或构建来源证明配置迹象",
                detail="这不是漏洞，但面向专业用户或供应链审计时，SBOM、签名、attestation/provenance 能显著提高发布链路可信度。",
                evidence="no sbom/signing/attestation hints",
                recommendation="按项目成熟度评估是否引入 SBOM、cosign/sigstore、SLSA provenance 或发布包签名。",
            )
        )

    return dedupe_findings(findings)
