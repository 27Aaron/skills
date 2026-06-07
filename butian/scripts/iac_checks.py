"""Local IaC, container, and deployment configuration checks."""

from __future__ import annotations

import os
import re

try:
    from .finding_utils import (
        dedupe_findings,
        iter_files,
        make_finding,
        read_text,
        relpath,
    )
except ImportError:  # pragma: no cover
    from finding_utils import (  # pyright: ignore[reportMissingImports]
        dedupe_findings,
        iter_files,
        make_finding,
        read_text,
        relpath,
    )


SENSITIVE_PORTS = {22, 2375, 2376, 3306, 5432, 6379, 27017, 9200, 9300}
SECRET_ENV_RE = re.compile(
    r"(?i)^\s*ENV\s+[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|KEY)[A-Z0-9_]*\s*=", re.MULTILINE
)


def _line_for_regex(text: str, pattern: str) -> int | None:
    regex = re.compile(pattern, re.MULTILINE | re.IGNORECASE)
    match = regex.search(text)
    if not match:
        return None
    return text[: match.start()].count("\n") + 1


def _dockerfiles(project_path):
    return [
        path
        for path in iter_files(project_path, max_files=600)
        if os.path.basename(path).lower() == "dockerfile"
        or os.path.basename(path).lower().startswith("dockerfile.")
    ]


def _check_dockerfile(project_path, path):
    text = read_text(path)
    if not text:
        return []
    rel = relpath(path, project_path)
    findings = []
    for line_no, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if re.match(r"FROM\s+[^#\s]+:latest\b", stripped, re.IGNORECASE):
            findings.append(
                make_finding(
                    "iac.docker_latest_tag",
                    category="iac_container",
                    severity="medium",
                    confidence="high",
                    file=rel,
                    line=line_no,
                    title="Dockerfile 使用 latest 镜像标签",
                    detail="latest 会随时间漂移，构建结果和漏洞暴露面不可复现。",
                    evidence=stripped,
                    recommendation="固定到具体版本标签；高要求发布链路可进一步固定 digest。",
                )
            )
        if re.search(r"\b(curl|wget)\b.+\|\s*(sh|bash)\b", stripped):
            findings.append(
                make_finding(
                    "iac.docker_remote_script_pipe",
                    category="iac_container",
                    severity="high",
                    confidence="high",
                    file=rel,
                    line=line_no,
                    title="Dockerfile 直接执行远程脚本",
                    detail="构建阶段执行未校验远程脚本会把镜像供应链暴露给远端内容变更。",
                    evidence=stripped,
                    recommendation="固定下载版本并校验 checksum/signature，或改用包管理器和可信基础镜像。",
                )
            )
        if re.match(r"ADD\s+https?://", stripped, re.IGNORECASE):
            findings.append(
                make_finding(
                    "iac.docker_remote_add",
                    category="iac_container",
                    severity="medium",
                    confidence="medium",
                    file=rel,
                    line=line_no,
                    title="Dockerfile 使用 ADD 远程 URL",
                    detail="ADD 远程 URL 难以审计完整性，容易造成构建结果漂移。",
                    evidence=stripped,
                    recommendation="先显式下载并校验，再 COPY 进入镜像。",
                )
            )
    if SECRET_ENV_RE.search(text):
        findings.append(
            make_finding(
                "iac.docker_secret_env",
                category="iac_container",
                severity="high",
                confidence="high",
                file=rel,
                line=_line_for_regex(text, SECRET_ENV_RE.pattern),
                title="Dockerfile ENV 中疑似写入敏感值",
                detail="镜像层会记录 ENV，明文 secret 可能被 docker history、镜像仓库或运行时暴露。",
                evidence="ENV <SECRET/TOKEN/PASSWORD/KEY>=...",
                recommendation="改用运行时 secret 注入或平台 secret 管理，不把凭据写进镜像层。",
            )
        )
    if not re.search(r"^\s*USER\s+\S+", text, re.MULTILINE | re.IGNORECASE):
        findings.append(
            make_finding(
                "iac.docker_missing_user",
                category="iac_container",
                severity="low",
                confidence="medium",
                file=rel,
                line=1,
                title="Dockerfile 未声明非 root 用户",
                detail="容器默认 root 运行会放大逃逸或挂载误配置后的影响面。",
                evidence="missing USER",
                recommendation="创建最小权限用户，并在最终阶段使用 USER <app-user>。",
            )
        )
    return findings


def _compose_files(project_path):
    names = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")
    return [path for path in iter_files(project_path, names=names, max_files=500)]


def _check_compose(project_path, path):
    text = read_text(path)
    rel = relpath(path, project_path)
    findings = []
    if re.search(r"privileged\s*:\s*true", text, re.IGNORECASE):
        findings.append(
            make_finding(
                "iac.compose_privileged",
                category="iac_container",
                severity="high",
                confidence="high",
                file=rel,
                line=_line_for_regex(text, r"privileged\s*:\s*true"),
                title="Compose 服务启用了 privileged",
                detail="privileged 容器拥有接近宿主机的能力，误用会显著扩大攻击面。",
                evidence="privileged: true",
                recommendation="移除 privileged；如确有必要，限定到隔离环境并说明原因。",
            )
        )
    if "/var/run/docker.sock" in text:
        findings.append(
            make_finding(
                "iac.compose_docker_socket",
                category="iac_container",
                severity="high",
                confidence="high",
                file=rel,
                line=text[: text.index("/var/run/docker.sock")].count("\n") + 1,
                title="Compose 挂载 Docker socket",
                detail="容器拿到 Docker socket 通常等同于可控制宿主机上的容器环境。",
                evidence="/var/run/docker.sock",
                recommendation="避免挂载 Docker socket；必须使用时放到专用隔离 runner 或只读受控代理。",
            )
        )
    port_re = re.compile(r"(?:(?:0\.0\.0\.0:)?|\s-\s*['\"]?)(\d+):(\d+)")
    for match in port_re.finditer(text):
        host_port = int(match.group(1))
        target_port = int(match.group(2))
        if host_port in SENSITIVE_PORTS or target_port in SENSITIVE_PORTS:
            findings.append(
                make_finding(
                    "iac.compose_public_database_port",
                    category="iac_container",
                    severity="medium",
                    confidence="medium",
                    file=rel,
                    line=text[: match.start()].count("\n") + 1,
                    title="Compose 暴露敏感服务端口",
                    detail="数据库、缓存或 Docker API 端口暴露到宿主机接口后，部署环境稍有不慎就可能被外部访问。",
                    evidence=match.group(0),
                    recommendation="改为仅服务间网络访问，或绑定到 127.0.0.1 并用防火墙限制来源。",
                )
            )
            break
    return findings


def _looks_like_k8s(text):
    return "apiVersion:" in text and "kind:" in text


def _check_kubernetes(project_path, path):
    text = read_text(path)
    if not _looks_like_k8s(text):
        return []
    rel = relpath(path, project_path)
    checks = [
        (
            "iac.k8s_secret_data",
            r"kind:\s*Secret[\s\S]*(data|stringData)\s*:",
            "Kubernetes Secret 中包含内联数据",
            "Secret manifest 中的 data/stringData 仍会进入仓库历史，需要确认是否为真实密钥。",
            "把真实 secret 移到集群或平台 secret 管理；仓库里只保留模板。",
            "high",
        ),
        (
            "iac.k8s_privileged",
            r"privileged\s*:\s*true",
            "Kubernetes 容器启用 privileged",
            "privileged 容器会扩大节点级攻击面。",
            "移除 privileged，改用最小 capabilities。",
            "high",
        ),
        (
            "iac.k8s_hostpath",
            r"hostPath\s*:",
            "Kubernetes 使用 hostPath",
            "hostPath 会把节点文件系统暴露给容器，需严格限制路径和只读权限。",
            "优先使用 PVC/config/secret；必须 hostPath 时限定路径、权限和运行节点。",
            "medium",
        ),
        (
            "iac.k8s_host_network",
            r"hostNetwork\s*:\s*true",
            "Kubernetes 使用 hostNetwork",
            "hostNetwork 会绕过部分网络隔离，提升横向移动风险。",
            "除网络组件外避免使用 hostNetwork。",
            "medium",
        ),
        (
            "iac.k8s_run_as_root",
            r"runAsUser\s*:\s*0",
            "Kubernetes 容器显式 root 运行",
            "root 用户会扩大容器逃逸或挂载误配置后的影响面。",
            "配置 runAsNonRoot: true 和非 0 runAsUser。",
            "medium",
        ),
    ]
    findings = []
    for finding_id, pattern, title, detail, recommendation, severity in checks:
        if re.search(pattern, text, re.IGNORECASE):
            findings.append(
                make_finding(
                    finding_id,
                    category="iac_container",
                    severity=severity,
                    confidence="high",
                    file=rel,
                    line=_line_for_regex(text, pattern),
                    title=title,
                    detail=detail,
                    evidence=pattern.replace("\\s*", " "),
                    recommendation=recommendation,
                )
            )
    return findings


def _check_terraform(project_path, path):
    text = read_text(path)
    rel = relpath(path, project_path)
    findings = []
    if path.endswith((".tfvars", ".tfstate", ".tfstate.backup")):
        findings.append(
            make_finding(
                "iac.terraform_sensitive_file",
                category="iac_container",
                severity="high" if path.endswith(".tfstate") else "medium",
                confidence="high",
                file=rel,
                line=1,
                title="Terraform 敏感状态或变量文件在仓库中",
                detail="tfstate/tfvars 常包含资源 ID、输出值或变量，可能间接暴露凭据和基础设施结构。",
                evidence=os.path.basename(path),
                recommendation="确认文件是否应被 Git 跟踪；真实状态和敏感变量应进入远端 state backend 或 secret 管理。",
            )
        )
    if "0.0.0.0/0" in text:
        ports = {int(p) for p in re.findall(r"(?:from_port|to_port)\s*=\s*(\d+)", text)}
        if ports & SENSITIVE_PORTS:
            findings.append(
                make_finding(
                    "iac.terraform_public_sensitive_port",
                    category="iac_container",
                    severity="high",
                    confidence="high",
                    file=rel,
                    line=text[: text.index("0.0.0.0/0")].count("\n") + 1,
                    title="Terraform 对公网开放敏感端口",
                    detail="SSH、数据库、缓存或搜索服务端口向 0.0.0.0/0 开放，需要确认是否仅用于临时调试。",
                    evidence="0.0.0.0/0 with sensitive port",
                    recommendation="限制到可信网段、安全组或 VPN；生产环境避免公网开放敏感管理端口。",
                )
            )
    return findings


def scan_iac_checks(project_path: str):
    findings = []
    for path in _dockerfiles(project_path):
        findings.extend(_check_dockerfile(project_path, path))
    for path in _compose_files(project_path):
        findings.extend(_check_compose(project_path, path))
    for path in iter_files(project_path, suffixes=(".yml", ".yaml"), max_files=800):
        findings.extend(_check_kubernetes(project_path, path))
    for path in iter_files(
        project_path, suffixes=(".tf", ".tfvars", ".tfstate", ".backup"), max_files=800
    ):
        if path.endswith(".tfstate.backup") or path.endswith(
            (".tf", ".tfvars", ".tfstate")
        ):
            findings.extend(_check_terraform(project_path, path))
    return dedupe_findings(findings)
