"""本地 GitHub Actions 工作流安全检查。"""

from __future__ import annotations

import os
import re

try:
    from .finding_utils import (
        dedupe_findings,
        evidence_snippet,
        line_for_text,
        make_finding,
        read_text,
        relpath,
    )
except ImportError:  # pragma: no cover - script execution fallback
    from finding_utils import (  # pyright: ignore[reportMissingImports]
        dedupe_findings,
        evidence_snippet,
        line_for_text,
        make_finding,
        read_text,
        relpath,
    )


WORKFLOW_DIR = os.path.join(".github", "workflows")
RISKY_TRIGGERS = ("pull_request_target", "workflow_run", "issue_comment")
PR_TRIGGERS = ("pull_request", "pull_request_target")
UNTRUSTED_CONTEXT_RE = re.compile(
    r"\$\{\{\s*(github\.event\.|github\.head_ref|inputs\.)[^}]+}}"
)


def workflow_files(project_path):
    workflows = os.path.join(project_path, WORKFLOW_DIR)
    if not os.path.isdir(workflows):
        return []
    return [
        os.path.join(workflows, name)
        for name in sorted(os.listdir(workflows))
        if name.endswith((".yml", ".yaml"))
    ]


def _has_trigger(text: str, trigger: str) -> bool:
    return bool(re.search(rf"(^|\s|\[|,){re.escape(trigger)}(\s|:|,|\])", text))


def _has_any_trigger(text: str, triggers) -> bool:
    return any(_has_trigger(text, trigger) for trigger in triggers)


def _line_for_regex(path: str, pattern: str) -> int | None:
    regex = re.compile(pattern)
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            for line_no, line in enumerate(handle, 1):
                if regex.search(line):
                    return line_no
    except OSError:
        return None
    return None


def scan_workflows(project_path: str):
    findings = []
    for path in workflow_files(project_path):
        text = read_text(path)
        if not text:
            continue
        rel = relpath(path, project_path)

        if re.search(r"^\s*permissions:\s*write-all\s*$", text, re.MULTILINE):
            evidence = re.search(
                r"^\s*permissions:\s*write-all\s*$", text, re.MULTILINE
            )
            findings.append(
                make_finding(
                    "actions.permissions_write_all",
                    category="github_actions",
                    severity="high",
                    confidence="high",
                    file=rel,
                    line=text[: evidence.start()].count("\n") + 1 if evidence else None,
                    title="GitHub Actions 权限过宽",
                    detail="workflow 使用 write-all，会扩大任一 action 或脚本被利用后的写入影响面。",
                    evidence=evidence.group(0)
                    if evidence
                    else "permissions: write-all",
                    recommendation="把顶层 permissions 设为 contents: read，再按 job 精确增加必要写权限。",
                )
            )

        if not re.search(r"^\s*permissions\s*:", text, re.MULTILINE):
            findings.append(
                make_finding(
                    "actions.missing_permissions",
                    category="github_actions",
                    severity="low",
                    confidence="medium",
                    file=rel,
                    line=1,
                    title="建议声明 GITHUB_TOKEN 最小权限边界",
                    detail="未显式声明 permissions 时，token 权限会依赖仓库或组织默认值；在有 action 或脚本的 workflow 中，明确最小权限能降低误用后的影响面。",
                    evidence="missing permissions:",
                    recommendation="在 workflow 顶层增加 permissions: contents: read，并在需要写权限的 job 中单独放开。",
                )
            )

        risky_trigger = _has_any_trigger(text, RISKY_TRIGGERS)
        if risky_trigger and "actions/checkout" in text:
            findings.append(
                make_finding(
                    "actions.risky_trigger_checkout",
                    category="github_actions",
                    severity="high",
                    confidence="high",
                    file=rel,
                    line=line_for_text(path, "actions/checkout"),
                    title="高风险触发器与 checkout 组合",
                    detail="pull_request_target、workflow_run 或 issue_comment 场景如果处理不可信代码，可能让外部输入接触 secret 或写权限。",
                    evidence="actions/checkout under risky trigger",
                    recommendation="避免在高风险 trigger 下 checkout 未受信任 PR 代码；必须使用时固定 ref、限制 permissions，并人工复核脚本输入。",
                )
            )
            if not re.search(r"persist-credentials\s*:\s*false", text):
                findings.append(
                    make_finding(
                        "actions.checkout_persist_credentials",
                        category="github_actions",
                        severity="medium",
                        confidence="medium",
                        file=rel,
                        line=line_for_text(path, "actions/checkout"),
                        title="高风险 checkout 未关闭凭据持久化",
                        detail="actions/checkout 默认会持久化 token；在高风险 trigger 中应显式关闭，降低后续脚本误用 token 的概率。",
                        evidence="persist-credentials not set to false",
                        recommendation="在 actions/checkout 的 with 中加入 persist-credentials: false，并按需单独传入低权限凭据。",
                    )
                )

        run_block_indent = None
        for line_no, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            indent = len(line) - len(line.lstrip(" "))
            in_run_block = run_block_indent is not None
            if in_run_block and stripped and indent <= run_block_indent:
                run_block_indent = None
                in_run_block = False

            if (in_run_block or "run:" in line) and UNTRUSTED_CONTEXT_RE.search(line):
                findings.append(
                    make_finding(
                        "actions.untrusted_context_in_run",
                        category="github_actions",
                        severity="high",
                        confidence="high",
                        file=rel,
                        line=line_no,
                        title="不可信 GitHub 上下文直接进入 shell",
                        detail="PR 标题、issue 内容、输入参数等上下文可能包含 shell 元字符，直接插入 run 脚本存在注入风险。",
                        evidence=line.strip(),
                        recommendation="先把表达式写入 env，再在 shell 中用带引号的变量读取，或改成 action 参数处理。",
                    )
                )
            if not in_run_block and re.search(r"\brun\s*:\s*[|>]", line):
                run_block_indent = indent

            if re.search(r"\b(curl|wget)\b.+\|\s*(sh|bash)\b", line):
                findings.append(
                    make_finding(
                        "actions.remote_script_pipe",
                        category="github_actions",
                        severity="medium",
                        confidence="high",
                        file=rel,
                        line=line_no,
                        title="workflow 直接执行远程脚本",
                        detail="curl/wget 管道到 shell 缺少完整性校验，远端脚本被替换时会直接在 runner 上执行。",
                        evidence=line.strip(),
                        recommendation="下载固定版本并校验 checksum/signature，或使用可信 action/包管理器替代。",
                    )
                )

        if _has_any_trigger(text, PR_TRIGGERS) and re.search(
            r"runs-on\s*:\s*(\[.*self-hosted.*\]|self-hosted)", text
        ):
            line = _line_for_regex(
                path, r"runs-on\s*:\s*(\[.*self-hosted.*\]|self-hosted)"
            )
            findings.append(
                make_finding(
                    "actions.self_hosted_pr_runner",
                    category="github_actions",
                    severity="high",
                    confidence="medium",
                    file=rel,
                    line=line,
                    title="PR workflow 使用 self-hosted runner",
                    detail="PR 触发的 self-hosted runner 可能让不可信代码接触内部网络、缓存、凭据或宿主机资源。",
                    evidence=evidence_snippet(
                        "self-hosted runner on pull request trigger"
                    ),
                    recommendation="公开或可 fork 仓库避免在 PR 上使用 self-hosted runner；必须使用时隔离 runner 并限制 secret 与网络访问。",
                )
            )
    return dedupe_findings(findings)
