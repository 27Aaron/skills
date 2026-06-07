#!/usr/bin/env python3
"""Project security scanner.

Collects security-related data and outputs JSON for agent analysis:
  1. Repository security checks (gitignore, sensitive file tracking, hardcoded secrets)
  2. Dependency ecosystem detection and package coordinate extraction
  3. Vulnerability checks via OSV, NVD, CISA KEV, and FIRST EPSS
  4. Outdated dependency checks

The scan is read-only: the script only creates/updates the .butian/ local
workspace and ensures .gitignore covers that directory.

Usage:
    python3 scan.py --preflight <preflight_json>
    python3 scan.py [project_path]              # auto-detect project root
    python3 scan.py --no-root-discovery <path>  # scan the given path directly
    python3 scan.py <path>
    python3 scan.py --skip-outdated <path>      # skip slower outdated checks
    python3 scan.py --include-packages <path>   # include full package listing
    python3 scan.py                             # equivalent to python3 scan.py .

Official vulnerability sources:
  OSV       POST https://api.osv.dev/v1/querybatch
  OSV       GET  https://api.osv.dev/v1/vulns/{id}
  NVD       GET  https://services.nvd.nist.gov/rest/json/cves/2.0?cveIds=...
  CISA KEV  GET  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  EPSS      GET  https://api.first.org/data/v1/epss?cve=...

  OSV query example: {"queries": [{"package": {"ecosystem":"npm","name":"next"}, "version":"15.5.1"}]}
  Supported ecosystems: JavaScript/TypeScript (npm/pnpm/yarn), Python (pypi), Go, Rust (crates-io)
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

try:
    from .iac_checks import scan_iac_checks
    from .repo_checks import scan_repository_checks
    from .workflow_checks import scan_workflows
except ImportError:  # pragma: no cover - direct script execution
    from iac_checks import scan_iac_checks  # pyright: ignore[reportMissingImports]
    from repo_checks import (
        scan_repository_checks,  # pyright: ignore[reportMissingImports]
    )
    from workflow_checks import scan_workflows  # pyright: ignore[reportMissingImports]

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL_PREFIX = "https://api.osv.dev/v1/vulns/"
NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_JSON_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
EPSS_API_URL = "https://api.first.org/data/v1/epss"
HTTP_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36"
)
BUTIAN_DIR = ".butian"
CACHE_DIR_NAME = "cache"

BUTIAN_GITIGNORE_ENTRY = ".butian/"
BUTIAN_GITIGNORE_EXTRA_ENTRIES = ("docs/butian",)
BUTIAN_ASSETS_DIR = "assets"
BUTIAN_CONTENT_DIR = "content"
_GITIGNORE_STATUS_BY_PROJECT = {}
HYGIENE_ONLY_NOTICE = (
    "当前项目未发现支持的依赖文件，暂无法执行依赖漏洞扫描；"
    "本次仅做仓库安检，检查硬编码密钥、敏感文件跟踪、.gitignore、"
    "GitHub Actions、仓库治理/供应链和 IaC/容器配置风险。"
)
CAPABILITY_BOUNDARY = (
    "安全往往不是最显眼的需求，却是产品长期稳定运行的底线。"
    "此 Skill 会帮助你发现依赖漏洞、过期依赖和仓库暴露风险，"
    "帮助团队更早暴露容易被忽视的供应链问题。"
    "但它不能替代代码审计、渗透测试或部署安全评估；"
    "业务逻辑、权限控制、SQL 注入、XSS 等代码层风险仍需单独复核。"
)


def has_butian_gitignore_entry(content):
    for line in content.splitlines():
        stripped = line.strip()
        if stripped in {".butian", BUTIAN_GITIGNORE_ENTRY}:
            return True
    return False


def inspect_butian_gitignore(project_path):
    gitignore_path = os.path.join(project_path, ".gitignore")
    try:
        with open(gitignore_path, "r", encoding="utf-8") as handle:
            content = handle.read()
    except FileNotFoundError:
        content = ""

    return {
        "path": gitignore_path,
        "preexisting": os.path.isfile(gitignore_path),
        "had_butian_entry": has_butian_gitignore_entry(content),
    }


def ensure_butian_gitignore(project_path):
    status = inspect_butian_gitignore(project_path)
    gitignore_path = status["path"]
    try:
        with open(gitignore_path, "r", encoding="utf-8") as handle:
            content = handle.read()
    except FileNotFoundError:
        content = ""

    added_entry = False
    if has_butian_gitignore_entry(content):
        status.update(
            {
                "added_butian_entry": False,
                "exists_after": True,
            }
        )
        _GITIGNORE_STATUS_BY_PROJECT[os.path.abspath(project_path)] = status
        return gitignore_path

    prefix = ""
    if content and not content.endswith("\n"):
        prefix = "\n"
    elif content:
        prefix = "\n"

    with open(gitignore_path, "a", encoding="utf-8") as handle:
        entries = "\n".join(
            [BUTIAN_GITIGNORE_ENTRY] + list(BUTIAN_GITIGNORE_EXTRA_ENTRIES)
        )
        handle.write(f"{prefix}# Butian local workspace\n{entries}\n")
    added_entry = True
    status.update(
        {
            "added_butian_entry": added_entry,
            "exists_after": True,
        }
    )
    _GITIGNORE_STATUS_BY_PROJECT[os.path.abspath(project_path)] = status
    return gitignore_path


def butian_gitignore_status(project_path):
    project_path = os.path.abspath(project_path)
    if project_path in _GITIGNORE_STATUS_BY_PROJECT:
        return _GITIGNORE_STATUS_BY_PROJECT[project_path]
    status = inspect_butian_gitignore(project_path)
    status.update(
        {
            "added_butian_entry": False,
            "exists_after": status["preexisting"],
        }
    )
    return status


def ensure_butian_workspace(project_path):
    workspace = os.path.join(project_path, BUTIAN_DIR)
    os.makedirs(workspace, exist_ok=True)
    ensure_butian_gitignore(project_path)
    return workspace


def _latest_existing_run(workspace):
    """Return the path of the most recent run directory, or None."""
    if not os.path.isdir(workspace):
        return None
    candidates = sorted(
        (
            d
            for d in os.listdir(workspace)
            if os.path.isdir(os.path.join(workspace, d)) and re.match(r"\d{8}-\d{4}", d)
        ),
        reverse=True,
    )
    return os.path.join(workspace, candidates[0]) if candidates else None


def make_run_id():
    return time.strftime("%Y%m%d-%H%M")


def ensure_butian_run(project_path, run_id=None):
    workspace = ensure_butian_workspace(project_path)

    # Reuse: if no explicit run_id and a previous run exists, reuse it
    if run_id is None:
        latest = _latest_existing_run(workspace)
        if latest:
            os.makedirs(os.path.join(latest, BUTIAN_ASSETS_DIR), exist_ok=True)
            os.makedirs(os.path.join(latest, BUTIAN_CONTENT_DIR), exist_ok=True)
            return latest

    base_run_id = run_id or make_run_id()
    run_dir = os.path.join(workspace, base_run_id)
    suffix = 2
    while os.path.exists(run_dir) and run_id is None:
        run_dir = os.path.join(workspace, f"{base_run_id}-{suffix}")
        suffix += 1
    os.makedirs(os.path.join(run_dir, BUTIAN_ASSETS_DIR), exist_ok=True)
    os.makedirs(os.path.join(run_dir, BUTIAN_CONTENT_DIR), exist_ok=True)
    return run_dir


def run_dir_from_output_file(output_file):
    output_file = os.path.abspath(output_file)
    parent = os.path.basename(os.path.dirname(output_file))
    if parent == BUTIAN_ASSETS_DIR:
        return os.path.dirname(os.path.dirname(output_file))
    return os.path.dirname(output_file)


def default_asset_path(project_path, filename, preflight=None):
    if preflight:
        workspace = preflight.get("butian_workspace") or {}
        run_dir = workspace.get("run_dir") or (
            run_dir_from_output_file(preflight["output_file"])
            if preflight.get("output_file")
            else ensure_butian_run(project_path)
        )
        os.makedirs(os.path.join(run_dir, BUTIAN_ASSETS_DIR), exist_ok=True)
        os.makedirs(os.path.join(run_dir, BUTIAN_CONTENT_DIR), exist_ok=True)
        ensure_butian_gitignore(project_path)
    else:
        run_dir = ensure_butian_run(project_path)
    return os.path.join(run_dir, BUTIAN_ASSETS_DIR, filename)


# ---------------------------------------------------------------------------
# Secret detection patterns
# ---------------------------------------------------------------------------

# --- Cloud Provider Keys ---
_CLOUD_PROVIDER_PATTERNS = [
    # AWS
    ("aws_access_key", r"(?<![A-Za-z0-9/+=])AKIA[0-9A-Z]{16}(?![A-Za-z0-9/+=])"),
    (
        "aws_secret_key",
        r"(?:AWS|aws|Amazon)?[_\s-]?(?:Secret|SECRET|secret)[_\s-]?(?:Access|ACCESS|access)[_\s-]?(?:Key|KEY|key)[_\s-]*[:=]\s*[\"']?[A-Za-z0-9/+=]{40}[\"']?",
    ),
    ("aws_session_token", r"ASIA[0-9A-Z]{16}"),
    # Google Cloud (GCP)
    ("gcp_service_account", r"\"type\"\s*:\s*\"service_account\""),
    ("gcp_api_key", r"AIza[0-9A-Za-z_-]{35}"),
    ("gcp_oauth_token", r"ya29\.[0-9A-Za-z_-]+"),
    # Microsoft Azure
    (
        "azure_client_secret",
        r"(?:azure|AZURE)[_\s-]?(?:client|CLIENT)[_\s-]?(?:secret|SECRET)[_\s-]*[:=]\s*[\"']?[A-Za-z0-9@#$%^&*\-_.+!]{34,}[\"']?",
    ),
    (
        "azure_connection_string",
        r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
    ),
    ("azure_sas_token", r"sv=\d{4}-\d{2}-\d{2}&[a-z]+=.{20,}"),
    # Alibaba Cloud (阿里云)
    ("aliyun_access_key", r"LTAI[0-9A-Za-z]{12,20}"),
    (
        "aliyun_secret_key",
        r"(?:ALIBABA|ALICLOUD|ALIYUN|aliyun|alibaba)[_\s-]?(?:SECRET|secret|ACCESS|access)[_\s-]?KEY[_\s-]*[:=]\s*[\"']?[A-Za-z0-9/+=]{30}[\"']?",
    ),
    # Tencent Cloud (腾讯云)
    ("tencent_secret_id", r"(?:AKID|TC3)[A-Za-z0-9]{32}"),
    # Huawei Cloud (华为云)
    (
        "huawei_access_key",
        r"(?:HUAWEI|hw|HW)[_\s-]?(?:ACCESS|access)[_\s-]?KEY[_\s-]*[:=]\s*[\"']?[A-Za-z0-9]{20,}[\"']?",
    ),
    (
        "huawei_secret_key",
        r"(?:HUAWEI|hw|HW)[_\s-]?(?:SECRET|secret)[_\s-]?KEY[_\s-]*[:=]\s*[\"']?[A-Za-z0-9]{30,}[\"']?",
    ),
    # Oracle Cloud (OCI)
    ("oracle_api_key", r"ocid1\.[a-z]+(?:\.[a-z0-9]*){3,}"),
    # DigitalOcean
    (
        "digitalocean_token",
        r"dop_v1_[a-f0-9]{64}|do_v1_[a-f0-9]{64}|doo_v1_[a-f0-9]{64}",
    ),
    # Linode / Akamai (requires context)
    (
        "linode_api_key",
        r"(?:linode|akamai|LINODE)[_\s-]?(?:api|token|key)(?:[_\s-]?(?:key|token|id|secret))?[_\s-]*[:=]\s*[\"']?[0-9a-f]{64}[\"']?",
    ),
    # Vultr (requires context)
    (
        "vultr_api_key",
        r"(?:vultr|VULTR)[_\s-]?(?:api|token|key)(?:[_\s-]?(?:key|token|id|secret))?[_\s-]*[:=]\s*[\"']?[A-Za-z0-9]{36}[\"']?",
    ),
    # Cloudflare
    ("cloudflare_api_key", r"v1\.0-[a-f0-9]{24}-[a-f0-9]{146}"),
    ("cloudflare_origin_ca", r"-----BEGIN ORIGIN " r"CERTIFICATE-----"),
    # Heroku (requires context to avoid matching random UUIDs)
    (
        "heroku_api_key",
        r"(?:heroku|HEROKU)[_\s-]?(?:api|token|key)(?:[_\s-]?(?:key|token|id|secret))?[_\s-]*[:=]\s*[\"']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[\"']?",
    ),
]

# --- SaaS / Third-Party Service Tokens ---
_SAAS_PATTERNS = [
    # GitHub
    ("github_token", r"gh[pousr]_[A-Za-z0-9_]{36,}"),
    ("github_oauth", r"gho_[A-Za-z0-9]{36}"),
    ("github_app_token", r"(?:ghu_|ghs_)[A-Za-z0-9_]{36}"),
    ("github_refresh_token", r"ghr_[A-Za-z0-9_]{36}"),
    # GitLab
    ("gitlab_token", r"glpat-[A-Za-z0-9\-_]{20,}"),
    # Slack
    ("slack_token", r"xox[baprs]-[A-Za-z0-9-]+"),
    (
        "slack_webhook",
        r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
    ),
    # Discord
    ("discord_token", r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}"),
    (
        "discord_bot_token",
        r"(?:BOT[_\s]+)?TOKEN\s*[:=]\s*[\"']?[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}",
    ),
    (
        "discord_webhook",
        r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
    ),
    # Stripe
    ("stripe_secret_key", r"sk_live_[0-9a-zA-Z]{24,}"),
    ("stripe_publishable_key", r"pk_live_[0-9a-zA-Z]{24,}"),
    ("stripe_restricted_key", r"rk_live_[0-9a-zA-Z]{24,}"),
    # Twilio
    ("twilio_api_key", r"SK[0-9a-fA-F]{32}"),
    ("twilio_account_sid", r"AC[a-z0-9]{32}"),
    # SendGrid
    ("sendgrid_api_key", r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
    # Mailgun
    ("mailgun_api_key", r"key-[0-9a-zA-Z]{32}"),
    # Mailchimp
    ("mailchimp_api_key", r"(?<![A-Za-z0-9])[a-f0-9]{32}-us[0-9]{1,2}(?![A-Za-z0-9])"),
    # Square
    ("square_access_token", r"sq0atp-[0-9A-Za-z\-_]{22}"),
    ("square_oauth_secret", r"sq0csp-[0-9A-Za-z\-_]{43}"),
    # Shopify
    (
        "shopify_token",
        r"shpat_[a-fA-F0-9]{10,}|shpca_[a-fA-F0-9]{10,}|shppa_[a-fA-F0-9]{10,}|shss_[a-fA-F0-9]{10,}",
    ),
    # PayPal
    ("paypal_bearer_token", r"access_token\$production\$[a-z0-9]{30,}"),
    # Braintree
    ("braintree_token", r"access_token\$production\$[a-z0-9]{20,}\$[a-f0-9]{32}"),
    # Firebase / Google
    (
        "firebase_key",
        r"[Ff]irebase[_\s-]?[Kk]ey\s*[:=]\s*[\"']?[A-Za-z0-9_-]{20,}",
    ),
    # Datadog (requires context)
    (
        "datadog_api_key",
        r"(?:datadog|DATADOG|DD)[_\s-]?(?:api|client)[_\s-]?key(?:[_\s-]?(?:key|token|id|secret))?[_\s-]*[:=]\s*[\"']?[a-f0-9]{32}[\"']?",
    ),
    (
        "datadog_app_key",
        r"(?:datadog|DATADOG|DD)[_\s-]?(?:app|application)[_\s-]?key(?:[_\s-]?(?:key|token|id|secret))?[_\s-]*[:=]\s*[\"']?[a-f0-9]{40}[\"']?",
    ),
    # New Relic
    ("newrelic_key", r"(?:NRAK|NRAL|NRRN|NRIO|NRMG|NRUS)[A-Za-z0-9]{20,}"),
    # PagerDuty
    (
        "pagerduty_token",
        r"(?:pagerduty|PAGERDUTY)[_\s-]?token\s*[:=]\s*[\"']?[A-Za-z0-9_-]{20,}[\"']?|pd[_-]?token\s*[:=]\s*[\"']?[A-Za-z0-9_-]{20,}[\"']?",
    ),
    # Grafana (requires context)
    (
        "grafana_api_key",
        r"(?:grafana|GRAFANA)[_\s-]?(?:api|token|key)(?:[_\s-]?(?:key|token|id|secret))?[_\s-]*[:=]\s*[\"']?eyJ[A-Za-z0-9+/]+=*\.eyJ[A-Za-z0-9+/]+=*\.[A-Za-z0-9+/]+=*",
    ),
    # NPM
    ("npm_token", r"//registry\.npmjs\.org/:_authToken=[0-9a-f-]{36}"),
    ("npmrc_auth_token", r"npm_[A-Za-z0-9]{36,}"),
    # Docker
    ("docker_hub_token", r"dckr_pat_[A-Za-z0-9_-]{20,}"),
    # Terraform
    ("terraform_token", r"[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9\-\.]{50,}"),
    # CircleCI
    ("circleci_token", r"CCIRERES_[A-Za-z0-9]{22,}"),
    # Travis CI (requires context)
    (
        "travis_token",
        r"(?:travis|TRAVIS)[_\s-]?(?:ci|token|api|key)(?:[_\s-]?(?:key|token|id|secret))?[_\s-]*[:=]\s*[\"']?[A-Za-z0-9]{22,}[\"']?",
    ),
    # Buildkite
    ("buildkite_token", r"bkua_[a-f0-9]{40}"),
    # Jenkins (requires context)
    (
        "jenkins_token",
        r"(?:jenkins|JENKINS)[_\s-]?(?:token|api|key|password)(?:[_\s-]?(?:key|token|id|secret))?[_\s-]*[:=]\s*[\"']?[0-9a-f]{40}[\"']?",
    ),
    # JFrog / Artifactory
    ("jfrog_token", r"(?:cmVmd[tnMA])\.[A-Za-z0-9_-]{20,}"),
    # Postman
    ("postman_api_key", r"PMAK-[A-Za-z0-9-]{30,}"),
    # OpenAI / LLM Providers
    ("openai_key", r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    ("anthropic_key", r"sk-ant-[A-Za-z0-9_-]{20,}"),
    # Note: google_ai_key uses same AIza prefix as gcp_api_key — already covered above
    ("huggingface_token", r"hf_[A-Za-z0-9]{34}"),
    ("replicate_token", r"r8_[A-Za-z0-9]{30,}"),
    # PyPI
    ("pypi_token", r"pypi-AgEIcH[0-9A-Za-z-_]{50,}"),
    # Rubygems
    ("rubygems_token", r"rubygems_[A-Za-z0-9]{20,}"),
    # NuGet
    ("nuget_api_key", r"oy2[a-z0-9]{43}"),
    # Sonar
    ("sonar_token", r"squ_[0-9a-f]{40}"),
    # Atlassian (JIRA / Confluence) (requires context)
    (
        "atlassian_token",
        r"(?:atlassian|jira|confluence|bitbucket|ATLASSIAN|JIRA)[_\s-]?(?:token|api|key|pat)(?:[_\s-]?(?:key|token|id|secret))?[_\s-]*[:=]\s*[\"']?[A-Za-z0-9]{24}[\"']?",
    ),
    # Notion
    ("notion_token", r"(?:secret|ntn)_[A-Za-z0-9]{30,}"),
    # Linear
    ("linear_api_key", r"lin_api_[A-Za-z0-9_]{30,}"),
    # Airtable
    ("airtable_api_key", r"key[A-Za-z0-9]{14}"),
    # Asana (requires context to avoid matching version strings)
    (
        "asana_token",
        r"(?:asana|ASANA)[_\s-]?(?:token|api|key|pat)(?:[_\s-]?(?:key|token|id|secret))?[_\s-]*[:=]\s*[\"']?(?:1|2)/[0-9]+:[A-Za-z0-9]+[\"']?",
    ),
    # Fastly (requires context)
    (
        "fastly_api_key",
        r"(?:fastly|FASTLY)[_\s-]?(?:api|token|key)(?:[_\s-]?(?:key|token|id|secret))?[_\s-]*[:=]\s*[\"']?[A-Za-z0-9_-]{32}[\"']?",
    ),
    # Ngrok (requires context)
    (
        "ngrok_token",
        r"(?:ngrok|NGROK)[_\s-]?(?:token|api|key)(?:[_\s-]?(?:key|token|id|secret))?[_\s-]*[:=]\s*[\"']?[A-Za-z0-9_-]{30,}[\"']?",
    ),
    # Sentry
    ("sentry_token", r"sntrys_[A-Za-z0-9_-]{40,}"),
    # Databricks
    ("databricks_token", r"dapi[a-f0-9]{32}"),
    # MongoDB
    (
        "mongodb_connection",
        r"mongodb(?:\+srv)?://[A-Za-z0-9_:%-]+:[A-Za-z0-9_:%-]+@[A-Za-z0-9._-]+",
    ),
    # PostgreSQL
    (
        "postgres_connection",
        r"postgres(?:ql)?://[A-Za-z0-9_:%-]+:[A-Za-z0-9_:%-]+@[A-Za-z0-9._-]+",
    ),
    # MySQL
    ("mysql_connection", r"mysql://[A-Za-z0-9_:%-]+:[A-Za-z0-9_:%-]+@[A-Za-z0-9._-]+"),
    # Redis
    ("redis_connection", r"redis://:[A-Za-z0-9_:%-]+@[A-Za-z0-9._-]+"),
    # RabbitMQ
    ("amqp_connection", r"amqp://[A-Za-z0-9_:%-]+:[A-Za-z0-9_:%-]+@[A-Za-z0-9._-]+"),
    # Kafka
    (
        "kafka_connection",
        r"(?:kafka|confluent)[_\s-]?(?:bootstrap|broker|server|sas[lw]|secret|password)[_\s-]?(?:password|secret|key|token|id)[_\s-]*[:=]\s*[\"']?[A-Za-z0-9_-]{10,}",
    ),
]

# --- Generic / Heuristic Patterns (lower confidence, user judges) ---
_GENERIC_PATTERNS = [
    # Private keys (all variants)
    (
        "private_key",
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?:\sBLOCK)?-----",
    ),
    # Generic passwords
    (
        "generic_password",
        r"""(?:password|passwd|pwd|pass_word)\s*[:=]\s*["'][^"']{4,}["']""",
    ),
    # Generic API keys
    (
        "generic_api_key",
        r"""(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?key|auth[_-]?token)\s*[:=]\s*["'][^"']{8,}["']""",
    ),
    # Generic token assignments
    (
        "generic_token",
        r"""(?:token|bearer|jwt|access_token|refresh_token|id_token|session_token|csrf_token)\s*[:=]\s*["'][A-Za-z0-9_\-\.]{20,}["']""",
    ),
    # Bearer token in Authorization header
    (
        "bearer_token",
        r"""[Aa]uthorization\s*[:=]\s*["']?Bearer\s+[A-Za-z0-9_\-\.]{20,}["']?""",
    ),
    # Generic secret assignments
    (
        "generic_secret",
        r"""(?:secret|SECRET|Secret)[_-]?(?:key|KEY|Key|token|TOKEN|Token|id|ID|Id)\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}["']""",
    ),
    # Base64-encoded potential secrets
    (
        "base64_secret",
        r"""(?:secret|token|key|password|credential|auth)[_-]?(?:encoded|base64|b64)\s*[:=]\s*["'][A-Za-z0-9+/=]{24,}["']""",
    ),
    # Hardcoded connection strings
    (
        "connection_string",
        r"""(?i)(?:connection[_-]?string|conn[_-]?str|database[_-]?url|db[_-]?url)\s*[:=]\s*["'][^"']{10,}["']""",
    ),
    # Encryption keys
    (
        "encryption_key",
        r"""(?:encryption|encrypt|cipher|aes|rsa|des)[_-]?key\s*[:=]\s*["'][A-Za-z0-9+/=]{16,}["']""",
    ),
    # Webhook URLs with embedded secrets
    (
        "webhook_url",
        r"""https?://[^/\s"']+/webhook[s]?/[A-Za-z0-9_\-]{20,}""",
    ),
    # JWT-like patterns
    (
        "jwt_token",
        r"""eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}""",
    ),
    # Generic sk- prefix catch-all (MiniMax, DeepSeek, Moonshot, Zhipu, etc.)
    # Many LLM/API providers use sk- as key prefix; medium confidence, user judges
    # Excludes sk-proj- (openai_key) and sk-ant- (anthropic_key) already matched above
    # \b ensures sk- is not part of a longer word (e.g. "mask-composite" in CSS)
    (
        "generic_sk_key",
        r"""\bsk-(?!proj-|ant-)[A-Za-z0-9_-]{8,}""",
    ),
]

SECRET_PATTERNS = _CLOUD_PROVIDER_PATTERNS + _SAAS_PATTERNS + _GENERIC_PATTERNS
SECRET_REGEXES = [(name, re.compile(pattern)) for name, pattern in SECRET_PATTERNS]
SECRET_SKIP_MARKERS = (
    "example",
    "placeholder",
    "your_",
    "todo",
    "sample",
    "changeme",
    "replace_",
    "insert_",
    "put_your",
    "FIXME",
    "REPLACE",
    "<your",
    "dummy",
    "fake",
    "mock",
    "stub",
    "redacted",
    "<masked>",
    "********",
    "sanitized",
    "[secret]",
)
# Markers that are too short / ambiguous — require word boundary check
SECRET_SKIP_WORD_MARKERS = (
    "xxx",
    "test",
    "default",
)
HIGH_CONFIDENCE_SECRET_TYPES = {
    # Cloud providers (with unique prefixes)
    "aws_access_key",
    "aws_session_token",
    "gcp_service_account",
    "gcp_api_key",
    "gcp_oauth_token",
    "azure_connection_string",
    "azure_sas_token",
    "aliyun_access_key",
    "tencent_secret_id",
    "oracle_api_key",
    "digitalocean_token",
    "cloudflare_api_key",
    "cloudflare_origin_ca",
    # Crypto / keys
    "private_key",
    # SaaS tokens (with unique prefixes)
    "github_token",
    "github_oauth",
    "github_app_token",
    "github_refresh_token",
    "gitlab_token",
    "slack_token",
    "slack_webhook",
    "discord_token",
    "discord_bot_token",
    "discord_webhook",
    "stripe_secret_key",
    "stripe_restricted_key",
    "twilio_api_key",
    "twilio_account_sid",
    "sendgrid_api_key",
    "mailgun_api_key",
    "square_access_token",
    "square_oauth_secret",
    "shopify_token",
    "newrelic_key",
    "npm_token",
    "npmrc_auth_token",
    "docker_hub_token",
    "openai_key",
    "anthropic_key",
    "huggingface_token",
    "replicate_token",
    "pypi_token",
    "sonar_token",
    "sentry_token",
    "databricks_token",
    "mongodb_connection",
    "postgres_connection",
    "mysql_connection",
    "redis_connection",
    "amqp_connection",
    "jwt_token",
    "bearer_token",
    "webhook_url",
}

SENSITIVE_FILE_PATTERNS = [
    # Environment / config files
    ("env_file", r"(^|/)\.env(\.[\w-]+)?$"),
    ("envrc", r"(^|/)\.envrc$"),
    ("npmrc", r"(^|/)\.npmrc$"),
    ("pypirc", r"(^|/)\.pypirc$"),
    ("netrc", r"(^|/)\.netrc$"),
    ("gem_credentials", r"(^|/)\.gem/credentials$"),
    # Private keys / certificates
    ("private_key", r"\.(pem|key|p12|pfx|jks|keystore|pub|gpg|pgp|asc|ppk)$"),
    (
        "ssh_key",
        r"(^|/)(?:id_(?:rsa|ed25519|ecdsa)|ssh_host_[a-z0-9_]+_key)(?:\.pub)?$",
    ),
    ("kubeconfig", r"(^|/)kubeconfig$|(^|/)\.kube/config$"),
    ("docker_cfg", r"(^|/)\.dockercfg$|(^|/)config\.json$"),
    # Database files
    ("database", r"\.(sqlite|sqlite3|db|dump|rdb|redis|bson)$"),
    # Credentials / service accounts
    ("credentials", r"(^|/)credentials\.json$"),
    ("credentials", r"(^|/)service-account.*\.json$"),
    ("credentials", r"(^|/)client_secret.*\.json$"),
    ("credentials", r"(^|/)sa-key\.json$"),
    ("aws_credentials", r"(^|/)\.aws/credentials$"),
    ("gcp_credentials", r"(^|/)gcloud[-_]?(?:credentials|config|token)$"),
    ("azure_credentials", r"(^|/)azureProfile\.json$"),
    ("terraform_state", r"(^|/)terraform\.tfstate(\.backup)?$"),
    ("terraform_vars", r"(^|/)terraform\.tfvars$"),
    ("ansible_vault", r"(^|/)vault[_-]?password\.txt$"),
    # Build / CI secrets
    ("ci_secrets", r"(^|/)secrets\.yml$|(^|/)secrets\.yaml$|(^|/)secrets\.json$"),
    ("gradle_properties", r"(^|/)gradle\.properties$"),
    ("maven_settings", r"(^|/)settings\.xml$"),
    # Logs (may contain leaked secrets)
    ("log", r"\.log$"),
    # Dump / export files
    ("dump", r"\.(sql|pgdump|mysqldump|mongoexport|jsonl|csv)$"),
    # App config with potential secrets
    (
        "app_config",
        r"(^|/)(?:application|app)\.(?:yml|yaml|properties|conf)(?:\.[\w-]+)?$",
    ),
    # Backup files
    ("backup", r"\.(bak|backup|old|orig|save|swp)$"),
    # History files (may contain pasted secrets)
    (
        "history",
        r"(^|/)\.(?:bash_history|zsh_history|python_history|node_repl_history|mysql_history|psql_history)$",
    ),
]
SENSITIVE_FILE_REGEXES = [
    (file_type, re.compile(pattern)) for file_type, pattern in SENSITIVE_FILE_PATTERNS
]

ENV_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")
PROJECT_ROOT_MARKERS = (
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "uv.lock",
    "requirements.txt",
    "Pipfile.lock",
    "go.sum",
    "Cargo.lock",
    "package.json",
    "pyproject.toml",
    "go.mod",
    "Cargo.toml",
    "composer.json",
    "Gemfile",
)

# 敏感文件类型 → 对应的 .gitignore 规则（只按实际发现的文件推荐，不一股脑全加）
SENSITIVE_TO_GITIGNORE = {
    "env_file": [".env", ".env.*"],
    "envrc": [".envrc"],
    "npmrc": [".npmrc"],
    "pypirc": [".pypirc"],
    "netrc": [".netrc"],
    "gem_credentials": [".gem/credentials"],
    "private_key": [
        "*.pem",
        "*.key",
        "*.p12",
        "*.pfx",
        "*.jks",
        "*.keystore",
        "*.pub",
        "*.gpg",
        "*.pgp",
        "*.asc",
        "*.ppk",
    ],
    "ssh_key": [
        "id_rsa",
        "id_rsa.pub",
        "id_ed25519",
        "id_ed25519.pub",
        "id_ecdsa",
        "id_ecdsa.pub",
        "ssh_host_*_key",
    ],
    "kubeconfig": ["kubeconfig", ".kube/config"],
    "docker_cfg": [".dockercfg", "config.json"],
    "database": [
        "*.sqlite",
        "*.sqlite3",
        "*.db",
        "*.dump",
        "*.rdb",
        "*.redis",
        "*.bson",
    ],
    "credentials": [
        "credentials.json",
        "service-account*.json",
        "client_secret*.json",
        "sa-key.json",
    ],
    "aws_credentials": [".aws/credentials"],
    "gcp_credentials": ["gcloud-credentials", "gcloud-config", "gcloud-token"],
    "azure_credentials": ["azureProfile.json"],
    "terraform_state": [
        "terraform.tfstate",
        "terraform.tfstate.backup",
        "terraform.tfvars",
    ],
    "ansible_vault": ["vault-password.txt", "vault_password.txt"],
    "ci_secrets": ["secrets.yml", "secrets.yaml", "secrets.json"],
    "gradle_properties": ["gradle.properties"],
    "maven_settings": ["settings.xml"],
    "log": ["*.log"],
    "dump": ["*.sql", "*.pgdump", "*.mysqldump", "*.mongoexport", "*.jsonl"],
    "app_config": [
        "application.yml",
        "application.yaml",
        "application.properties",
        "application.conf",
    ],
    "backup": ["*.bak", "*.backup", "*.old", "*.orig", "*.save", "*.swp"],
    "history": [
        ".bash_history",
        ".zsh_history",
        ".python_history",
        ".node_repl_history",
        ".mysql_history",
        ".psql_history",
    ],
}

EXCLUDE_DIRS = {
    ".git",
    ".butian",
    ".claude",
    "node_modules",
    ".next",
    ".turbo",
    ".vercel",
    "dist",
    "build",
    "coverage",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".svelte-kit",
    ".venv",
    "venv",
    ".idea",
    ".vscode",
    "target",
    "vendor",
    "bower_components",
    ".cache",
    ".tox",
    ".eggs",
    ".cargo",
    ".npm",
    ".pnpm-store",
    ".yarn",
}

SCAN_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".mjs",
    ".cjs",
    ".go",
    ".rs",
    ".rb",
    ".php",
    ".java",
    ".kt",
    ".swift",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".cs",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".html",
    ".css",
    ".scss",
    ".less",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def run_cmd(cmd, timeout=60, cwd=None):
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
        )
        return r.stdout.strip()
    except Exception:
        return ""


def run_cmd_checked(cmd, timeout=60, cwd=None, errors=None, step="command"):
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        if errors is not None:
            errors.append({"step": step, "message": f"命令不可用：{cmd[0]}"})
        return ""
    except subprocess.TimeoutExpired:
        if errors is not None:
            errors.append({"step": step, "message": f"命令超时：{' '.join(cmd)}"})
        return ""
    except OSError as e:
        if errors is not None:
            errors.append(
                {"step": step, "message": f"命令执行失败：{' '.join(cmd)}: {e}"}
            )
        return ""

    stdout = r.stdout.strip()
    if r.returncode != 0 and not stdout:
        if errors is not None:
            msg = (r.stderr or "无 stderr 输出").strip()
            errors.append({"step": step, "message": f"{' '.join(cmd)} 失败：{msg}"})
        return ""
    return stdout


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(verbose=False, debug=False, log_dir=None, log_file="scan.log"):
    """Configure butian logging to stderr and optional log file.

    Args:
        verbose: If True, set stderr to INFO level.
        debug: If True, set stderr and file to DEBUG level.
        log_dir: Directory for log file. If None, no file logging.
        log_file: Log file name within log_dir (default "scan.log").

    Returns:
        logging.Logger: The configured 'butian' logger.
    """
    logger = logging.getLogger("butian")
    # Avoid duplicate handlers on repeated calls
    if logger.handlers:
        return logger
    # Keep logger at DEBUG so file handler can capture all messages;
    # stderr handler controls what the user sees on console.
    logger.setLevel(logging.DEBUG)

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(logging.Formatter(_LOG_FORMAT, _LOG_DATE_FORMAT))
    if debug:
        stderr_handler.setLevel(logging.DEBUG)
    elif verbose:
        stderr_handler.setLevel(logging.INFO)
    else:
        stderr_handler.setLevel(logging.WARNING)
    logger.addHandler(stderr_handler)

    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, log_file)
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setFormatter(logging.Formatter(_LOG_FORMAT, _LOG_DATE_FORMAT))
        file_handler.setLevel(logging.DEBUG)
        logger.addHandler(file_handler)

    return logger


# ---------------------------------------------------------------------------
# Binary / symlink helpers
# ---------------------------------------------------------------------------


def is_binary_file(filepath):
    """Check if a file is binary by reading its first 8KB for NUL bytes."""
    try:
        with open(filepath, "rb") as f:
            chunk = f.read(8192)
        return b"\x00" in chunk
    except OSError:
        return True


# ---------------------------------------------------------------------------
# Local cache
# ---------------------------------------------------------------------------


def cache_dir(project_path, source):
    """Return the cache directory for a given source (osv/nvd/epss/kev)."""
    base = os.path.join(project_path, BUTIAN_DIR, CACHE_DIR_NAME, source)
    os.makedirs(base, exist_ok=True)
    return base


def cache_read(cache_path, ttl_seconds=86400):
    """Read from cache if not expired. Returns data dict or None."""
    if not os.path.isfile(cache_path):
        return None
    try:
        mtime = os.path.getmtime(cache_path)
        if time.time() - mtime > ttl_seconds:
            return None
        with open(cache_path, "r", encoding="utf-8") as f:
            entry = json.load(f)
        return entry.get("data")
    except (json.JSONDecodeError, OSError, KeyError):
        return None


def cache_write(cache_path, data, source="unknown", key=""):
    """Write data to cache with metadata."""
    entry = {
        "cached_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "ttl_seconds": 86400,
        "source": source,
        "key": key,
        "data": data,
    }
    try:
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(entry, f, ensure_ascii=False, separators=(",", ":"))
    except OSError:
        pass


def cache_clean(project_path, ttl_seconds=86400):
    """Remove expired cache entries."""
    cache_base = os.path.join(project_path, BUTIAN_DIR, CACHE_DIR_NAME)
    if not os.path.isdir(cache_base):
        return
    now = time.time()
    try:
        for source_name in os.listdir(cache_base):
            source_path = os.path.join(cache_base, source_name)
            if not os.path.isdir(source_path):
                continue
            for fname in os.listdir(source_path):
                fpath = os.path.join(source_path, fname)
                try:
                    if now - os.path.getmtime(fpath) > ttl_seconds:
                        os.remove(fpath)
                except OSError:
                    pass
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Progress reporter
# ---------------------------------------------------------------------------


def gitignore_rules(content):
    rules = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rules.add(line.lower().rstrip("/"))
    return rules


def gitignore_ignores(content, pattern):
    norm = pattern.strip().lower().rstrip("/")
    state = False
    for line in content.splitlines():
        line = line.strip().lower().rstrip("/")
        if not line or line.startswith("#"):
            continue
        if line == norm:
            state = True
        elif line == "!" + norm:
            state = False
    return state


def find_project_root(start_path="."):
    """Walk up to find the nearest project marker, with .git as a fallback."""
    path = os.path.abspath(start_path)
    if os.path.isfile(path):
        path = os.path.dirname(path)
    original = path
    git_root = ""
    for _ in range(20):
        if any(
            os.path.isfile(os.path.join(path, marker))
            for marker in PROJECT_ROOT_MARKERS
        ):
            return path
        if not git_root and os.path.exists(os.path.join(path, ".git")):
            git_root = path
            break
        parent = os.path.dirname(path)
        if parent == path:
            break
        path = parent
    return git_root or original


def is_env_template(path):
    name = os.path.basename(path).lower()
    return name.startswith(".env") and (
        name in {".env.example", ".env.sample", ".env.template", ".env.dist"}
        or name.endswith(ENV_TEMPLATE_SUFFIXES)
    )


def is_env_secret_scan_file(name):
    lowered = os.path.basename(name).lower()
    return lowered == ".envrc" or lowered == ".env" or lowered.startswith(".env.")


def sensitive_file_type(path):
    if is_env_template(path):
        return ""
    for file_type, pattern in SENSITIVE_FILE_REGEXES:
        if pattern.search(path):
            return file_type
    return ""


def is_git_worktree(path):
    return run_cmd(["git", "rev-parse", "--is-inside-work-tree"], cwd=path) == "true"


# ---------------------------------------------------------------------------
# Step 1: Repository security checks
# ---------------------------------------------------------------------------


def check_gitignore(project_path, sensitive_tracked):
    """Check .gitignore: only recommend rules for sensitive file types actually found."""
    gitignore_path = os.path.join(project_path, ".gitignore")
    gitignore_exists = os.path.isfile(gitignore_path)
    if not gitignore_exists:
        content = ""
    else:
        with open(gitignore_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

    # Collect types of sensitive files actually found in the project
    found_types = set()
    for item in sensitive_tracked:
        found_types.add(item.get("type", ""))
    # Also check if .env files exist (even if not tracked)
    for name in (".env", ".env.local", ".env.production", ".env.development"):
        if os.path.isfile(os.path.join(project_path, name)):
            found_types.add("env_file")

    missing = []
    for ftype, patterns in SENSITIVE_TO_GITIGNORE.items():
        if ftype not in found_types:
            continue
        for pat in patterns:
            if not gitignore_ignores(content, pat):
                missing.append(pat)
    return gitignore_exists, missing


def check_sensitive_tracked(project_path):
    output = run_cmd(["git", "ls-files"], cwd=project_path)
    if not output:
        return []
    findings = []
    for f in output.split("\n"):
        if not f.strip():
            continue
        ftype = sensitive_file_type(f)
        if not ftype:
            continue
        full = os.path.join(project_path, f)
        size = 0
        try:
            size = os.path.getsize(full)
        except OSError:
            pass
        findings.append({"file": f, "type": ftype, "size": size})
    return findings


# ---------------------------------------------------------------------------
# Entropy-based secret detection engine
# ---------------------------------------------------------------------------

# Shannon entropy thresholds
_BASE64_ENTROPY_THRESHOLD = 4.5  # base64 chars: max ~6.0
_HEX_ENTROPY_THRESHOLD = 3.0  # hex chars: max ~4.0
_GENERIC_ENTROPY_THRESHOLD = 4.2  # generic high-entropy: mixed charset
_MIN_SECRET_LENGTH = 20  # minimum candidate length for entropy check
_MAX_SECRET_LENGTH = 500  # skip unreasonably long strings

# Key names that hint at a secret value (used for contextual entropy scanning)
_SECRET_HINT_KEYWORDS = (
    "key",
    "token",
    "secret",
    "password",
    "passwd",
    "pwd",
    "credential",
    "auth",
    "private",
    "api",
    "access",
    "refresh",
    "session",
    "bearer",
    "apikey",
    "access_key",
    "secret_key",
    "client_secret",
    "app_secret",
    "encryption_key",
    "signing_key",
    "admin_key",
    "database_url",
    "connection_string",
    "dsn",
    "encrypt",
    "certificate",
    "license",
)


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _is_base64(s: str) -> bool:
    """Check if a string looks like base64-encoded data."""
    return bool(re.fullmatch(r"[A-Za-z0-9+/=]+", s)) and len(s) % 4 <= 1


def _is_hex(s: str) -> bool:
    """Check if a string is hex-encoded."""
    return bool(re.fullmatch(r"[0-9a-fA-F]+", s))


def _extract_assignment_value(line: str) -> tuple[str, str] | None:
    """Extract KEY=VALUE or KEY: VALUE from a line. Returns (key, value) or None."""
    m = re.match(
        r"""^\s*([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*["']?([^\s"']+)["']?\s*$""",
        line,
    )
    if m:
        return m.group(1), m.group(2)
    return None


def entropy_check_value(value: str) -> dict | None:
    """Analyze a value string for high entropy indicating a possible secret.

    Returns a dict with ``entropy_type`` and ``entropy`` score, or *None*.
    """
    if not value or len(value) < _MIN_SECRET_LENGTH or len(value) > _MAX_SECRET_LENGTH:
        return None

    # Skip obvious non-secrets
    if value.lower() in ("true", "false", "null", "none", "undefined", "yes", "no"):
        return None
    if re.fullmatch(r"[0-9]+", value):  # pure numbers
        return None
    if re.fullmatch(r"[a-z]+", value):  # pure lowercase word
        return None
    if re.fullmatch(r"[A-Z]+", value):  # pure uppercase word
        return None

    entropy = _shannon_entropy(value)

    # Check encoding type and apply appropriate threshold
    if _is_base64(value) and entropy >= _BASE64_ENTROPY_THRESHOLD:
        return {"entropy_type": "base64_high_entropy", "entropy": round(entropy, 2)}
    if _is_hex(value) and len(value) >= 32 and entropy >= _HEX_ENTROPY_THRESHOLD:
        return {"entropy_type": "hex_high_entropy", "entropy": round(entropy, 2)}
    if entropy >= _GENERIC_ENTROPY_THRESHOLD:
        return {"entropy_type": "generic_high_entropy", "entropy": round(entropy, 2)}

    return None


def scan_entropy_for_line(line: str) -> list[dict]:
    """Scan a single line for high-entropy values.

    Checks:
      1. Assignment values where the key hints at a secret (lower threshold).
      2. Standalone quoted strings that exhibit very high entropy.

    Returns a list of dicts with ``entropy_type``, ``entropy``, ``key``,
    ``value_preview``.
    """
    results: list[dict] = []
    stripped = line.strip()

    # 1. KEY = VALUE / KEY: VALUE patterns
    assignment = _extract_assignment_value(stripped)
    if assignment:
        key, value = assignment
        key_lower = key.lower()
        is_hinted = any(h in key_lower for h in _SECRET_HINT_KEYWORDS)
        if is_hinted:
            info = entropy_check_value(value)
            if info:
                results.append(
                    {
                        **info,
                        "key": key,
                        "value_preview": _mask_entropy_value(value),
                    }
                )
            return results  # only check the first assignment per line

    # 2. Quoted high-entropy strings (standalone, no key context)
    for m in re.finditer(r"""["']([A-Za-z0-9+/=_\-]{24,})["']""", stripped):
        value = m.group(1)
        info = entropy_check_value(value)
        if info and info["entropy"] >= 4.7:  # stricter threshold without key hint
            results.append(
                {
                    **info,
                    "key": "",
                    "value_preview": _mask_entropy_value(value),
                }
            )

    # 3. Unquoted high-entropy values in env-like lines
    env_match = re.match(
        r"""^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.+)$""", stripped
    )
    if env_match:
        key = env_match.group(1)
        value = env_match.group(2).strip().strip("\"'")
        key_lower = key.lower()
        is_hinted = any(h in key_lower for h in _SECRET_HINT_KEYWORDS)
        if is_hinted:
            info = entropy_check_value(value)
            if info:
                results.append(
                    {
                        **info,
                        "key": key,
                        "value_preview": _mask_entropy_value(value),
                    }
                )

    return results


def _mask_entropy_value(value: str) -> str:
    """Mask a value for safe display."""
    if len(value) <= 12:
        return "***"
    return value[:6] + "..." + value[-4:]


# ---------------------------------------------------------------------------
# Secret preview & scanning
# ---------------------------------------------------------------------------


def secret_preview(secret_type, match_text):
    if secret_type == "private_key":
        return "-----BEGIN *** PRIVATE KEY-----"

    if secret_type in {
        "generic_password",
        "generic_api_key",
        "generic_token",
        "generic_secret",
        "base64_secret",
        "connection_string",
        "encryption_key",
    }:
        masked = re.sub(
            r"""([:=]\s*["']?)[^"']+(["']?)$""",
            r"\1***\2",
            match_text,
        )
        return masked if masked != match_text else "***"

    if secret_type in HIGH_CONFIDENCE_SECRET_TYPES:
        if len(match_text) <= 12:
            return "***"
        return match_text[:7] + "..." + match_text[-4:]

    if len(match_text) <= 8:
        return "***"
    if len(match_text) <= 24:
        return match_text[:4] + "..." + match_text[-4:]
    return match_text[:15] + "..." + match_text[-10:]


def scan_secrets(
    project_path, max_files=500, max_bytes=1024 * 1024, follow_symlinks=False
):
    findings = []
    entropy_findings = []
    count = 0
    for root, dirs, files in os.walk(project_path, followlinks=follow_symlinks):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for fname in files:
            if count >= max_files:
                break
            ext = os.path.splitext(fname)[1].lower()
            if ext not in SCAN_EXTENSIONS and not is_env_secret_scan_file(fname):
                continue
            fpath = os.path.join(root, fname)
            # Skip symlinks unless explicitly following
            if not follow_symlinks and os.path.islink(fpath):
                continue
            # Skip binary files
            if is_binary_file(fpath):
                continue
            try:
                if os.path.getsize(fpath) > max_bytes:
                    continue
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    for line_num, line in enumerate(f, 1):
                        stripped = line.strip()
                        if stripped.startswith("#") or stripped.startswith("//"):
                            continue
                        lowered = stripped.lower()
                        # Skip lines containing placeholder markers (substring match)
                        if any(x in lowered for x in SECRET_SKIP_MARKERS):
                            continue
                        # Skip lines containing word-boundary markers (e.g. 'xxx', 'test')
                        # These are too ambiguous for substring matching
                        if any(
                            re.search(rf"\b{re.escape(m)}\b", lowered)
                            for m in SECRET_SKIP_WORD_MARKERS
                        ):
                            continue

                        # --- Phase 1: Regex pattern matching ---
                        for secret_type, pattern in SECRET_REGEXES:
                            m = pattern.search(line)
                            if m:
                                preview = secret_preview(secret_type, m.group(0))
                                rel = os.path.relpath(fpath, project_path)
                                findings.append(
                                    {
                                        "file": rel,
                                        "line": line_num,
                                        "type": secret_type,
                                        "preview": preview,
                                        "confidence": "high"
                                        if secret_type in HIGH_CONFIDENCE_SECRET_TYPES
                                        else "medium",
                                    }
                                )

                        # --- Phase 2: Entropy-based detection ---
                        if is_env_secret_scan_file(fname) or ext in (
                            ".env",
                            ".yaml",
                            ".yml",
                            ".toml",
                            ".ini",
                            ".cfg",
                            ".conf",
                            ".py",
                            ".js",
                            ".ts",
                            ".go",
                            ".rs",
                            ".sh",
                            ".bash",
                            ".zsh",
                            ".fish",
                        ):
                            for einfo in scan_entropy_for_line(line):
                                rel = os.path.relpath(fpath, project_path)
                                entropy_findings.append(
                                    {
                                        "file": rel,
                                        "line": line_num,
                                        "type": einfo["entropy_type"],
                                        "preview": einfo["value_preview"],
                                        "key": einfo.get("key", ""),
                                        "entropy": einfo["entropy"],
                                        "confidence": "low",
                                    }
                                )
            except (OSError, UnicodeDecodeError):
                continue
            count += 1

    # Merge: deduplicate regex findings.
    # Same (file, line) already matched by a high-confidence pattern suppresses
    # lower-confidence matches on that line to avoid duplicate reports.
    seen = set()
    high_conf_locations = set()
    deduped = []
    for f in findings:
        key = (f["file"], f["line"], f["type"])
        loc = (f["file"], f["line"])
        if key in seen:
            continue
        # Skip low/medium confidence if a high-confidence match already covers this line
        if f.get("confidence") != "high" and loc in high_conf_locations:
            continue
        seen.add(key)
        if f.get("confidence") == "high":
            high_conf_locations.add(loc)
        deduped.append(f)

    # Deduplicate entropy findings and suppress those already caught by regex
    regex_hit_keys = {(f["file"], f["line"]) for f in deduped}
    entropy_deduped = []
    entropy_seen: set[tuple[str, int, str]] = set()
    for ef in entropy_findings:
        ekey = (ef["file"], ef["line"], ef["type"])
        if ekey in entropy_seen:
            continue
        # Skip if this file+line already has a regex match (regex is more specific)
        if (ef["file"], ef["line"]) in regex_hit_keys:
            continue
        entropy_seen.add(ekey)
        entropy_deduped.append(ef)

    return deduped + entropy_deduped


def scan_hygiene(
    project_path, max_secret_files=500, follow_symlinks=False, ecosystems=None
):
    # Scan sensitive files first, then use findings to drive gitignore recommendations
    sensitive_tracked = check_sensitive_tracked(project_path)
    tracked_secrets = scan_secrets(
        project_path, max_files=max_secret_files, follow_symlinks=follow_symlinks
    )
    gitignore_exists, gitignore_missing = check_gitignore(
        project_path, sensitive_tracked
    )
    repository_checks = scan_repository_checks(
        project_path, ecosystems=ecosystems or []
    )
    workflow_checks = scan_workflows(project_path)
    iac_checks = scan_iac_checks(project_path)
    return {
        "gitignore_exists": gitignore_exists,
        "gitignore_missing": gitignore_missing,
        "tracked_secrets": tracked_secrets,
        "sensitive_tracked": sensitive_tracked,
        "repository_checks": repository_checks,
        "workflow_checks": workflow_checks,
        "iac_checks": iac_checks,
        "coverage": {
            "builtin_rules": [
                "secrets",
                "sensitive_files",
                "gitignore",
                "github_actions",
                "repo_governance",
                "supply_chain",
                "iac_container",
            ],
        },
    }


# ---------------------------------------------------------------------------
# Step 2: Ecosystem detection & package extraction
# ---------------------------------------------------------------------------

LOCKFILE_MAP = {
    "npm": ["package-lock.json"],
    "pnpm": ["pnpm-lock.yaml"],
    "yarn": ["yarn.lock"],
    "pypi": ["poetry.lock", "uv.lock", "requirements.txt", "Pipfile.lock"],
    "go": ["go.sum"],
    "crates-io": ["Cargo.lock"],
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
    deps = data.get("dependencies") or data.get("packages") or {}
    if "dependencies" in data:
        for name, info in deps.items():
            pkgs.append(
                {
                    "ecosystem": "npm",
                    "name": name,
                    "version": info.get("version", ""),
                    "is_direct": False,
                    "source": "package-lock.json",
                }
            )
    else:
        for key, info in deps.items():
            if not key:
                continue
            name = npm_lock_package_name(key)
            if not name:
                continue
            pkgs.append(
                {
                    "ecosystem": "npm",
                    "name": name,
                    "version": info.get("version", ""),
                    "is_direct": not info.get("dev", True) and not info.get("resolved"),
                    "source": "package-lock.json",
                }
            )
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
    # Fallback: older format with importers
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
    # Detect Yarn Berry (v2+) by checking for __metadata field
    is_berry = "__metadata:" in content or bool(
        re.search(r'^"[^"]+@npm:[^"]+":', content, re.MULTILINE)
    )
    if is_berry:
        return _parse_yarn_lock_berry(content)
    return _parse_yarn_lock_v1(content)


def _parse_yarn_lock_v1(content):
    """Parse Yarn v1 (classic) lockfile format."""
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
    """Parse Yarn Berry (v2+) lockfile format.

    Berry format uses descriptors like:
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
    """Extract package name from Yarn Berry descriptor.

    Examples:
      "lodash@npm:^4.0.0" → "lodash"
      "@scope/pkg@npm:1.2.3" → "@scope/pkg"
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


# --- Python ---


def parse_requirements_txt(project_path):
    """Parse requirements.txt with enhanced PEP 440 support.

    Supports:
    - PEP 440 specifiers: >=, <=, ~=, !=, ===, >, <
    - Comments and blank lines
    - -r / --requirement includes (recursive, max depth 5)
    - Extras with brackets: package[extra1,extra2]==1.0
    - Environment markers (after ;)
    - Line continuations with backslash

    Only packages with == or === exact versions are included for
    vulnerability matching.
    """
    path = os.path.join(project_path, "requirements.txt")
    if not os.path.isfile(path):
        return []

    pkgs = []
    seen = set()

    def _parse_file(filepath, depth=0):
        if depth > 5:
            return
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except OSError:
            return

        # Handle line continuations (backslash at end of line)
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

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            # Handle -r / --requirement includes
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

            # Skip other pip flags (-i, --index-url, -e, etc.)
            if line.startswith("-"):
                continue

            # Remove environment markers (after ;)
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

            # Only exact versions for vulnerability matching
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


# ---------------------------------------------------------------------------
# Step 3: Vulnerability check via official sources
# ---------------------------------------------------------------------------

OSV_ECOSYSTEMS = {
    "npm": "npm",
    "pypi": "PyPI",
    "go": "Go",
    "crates-io": "crates.io",
}


def _cvss_to_severity(vector):
    """Parse CVSS vector string → severity level.

    Strategy (in priority order):
    1. Parse explicit baseScore if embedded in the vector string.
    2. Compute a simplified CVSS 3.x base score from the vector metrics
       and map to severity using standard thresholds.
    3. Fall back to None if the vector cannot be parsed.
    """
    if not vector or "CVSS:" not in vector:
        return None
    try:
        parts: dict[str, str] = {}
        for pair in vector.split("/"):
            if ":" in pair and not pair.startswith("CVSS:"):
                k, v = pair.split(":", 1)
                parts[k] = v

        # --- Strategy 1: use explicit baseScore from the vector -----------
        raw_score = parts.get("baseScore")
        if raw_score:
            try:
                score = float(raw_score)
                if score >= 9.0:
                    return "critical"
                if score >= 7.0:
                    return "high"
                if score >= 4.0:
                    return "medium"
                return "low"
            except (TypeError, ValueError):
                pass

        # --- Strategy 2: compute base score using the CVSS 3.x formula -----
        # Full spec formula from FIRST CVSS v3.1:
        # https://www.first.org/cvss/v3.1/specification-document

        # Impact Sub-Score (ISS)
        c = parts.get("C", "N")
        i = parts.get("I", "N")
        a = parts.get("A", "N")

        cia_value = {"N": 0.0, "L": 0.22, "H": 0.56}
        iss = 1.0 - (
            (1.0 - cia_value.get(c, 0.0))
            * (1.0 - cia_value.get(i, 0.0))
            * (1.0 - cia_value.get(a, 0.0))
        )
        if iss <= 0.0:
            return "low"

        # Impact — formula differs between Scope Changed / Unchanged
        scope = parts.get("S", "U")
        if scope == "C":
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss

        # Exploitability
        av = parts.get("AV", "N")
        ac = parts.get("AC", "L")
        pr = parts.get("PR", "N")
        ui = parts.get("UI", "N")

        av_value = {"N": 0.85, "A": 0.62, "P": 0.20, "L": 0.55}
        ac_value = {"L": 0.77, "H": 0.44}
        # PR value depends on Scope
        if scope == "C":
            pr_value = {"N": 0.85, "L": 0.68, "H": 0.50}
        else:
            pr_value = {"N": 0.85, "L": 0.62, "H": 0.27}
        ui_value = {"N": 0.85, "R": 0.62}

        exploitability = (
            8.22
            * av_value.get(av, 0.85)
            * ac_value.get(ac, 0.77)
            * pr_value.get(pr, 0.85)
            * ui_value.get(ui, 0.85)
        )

        # Roundup function from the CVSS spec (round up to 1 decimal place)
        def _roundup(x):
            return math.ceil(x * 10) / 10.0

        # Base Score
        if impact <= 0:
            base_score = 0.0
        elif scope == "C":
            base_score = _roundup(min(1.08 * (impact + exploitability), 10.0))
        else:
            base_score = _roundup(min(impact + exploitability, 10.0))

        if base_score >= 9.0:
            return "critical"
        if base_score >= 7.0:
            return "high"
        if base_score >= 4.0:
            return "medium"
        return "low"
    except Exception:
        return None


def best_advisory_alias(aliases):
    aliases = [a for a in aliases if a]
    for alias in aliases:
        if str(alias).upper().startswith("CVE-"):
            return alias
    for alias in aliases:
        if not str(alias).upper().startswith("GHSA-"):
            return alias
    return aliases[0] if aliases else ""


def normalize_cve_id(value):
    text = str(value or "").strip().upper()
    return text if re.match(r"^CVE-\d{4}-\d{4,}$", text) else ""


def extract_cve_aliases(values):
    cves = []
    for value in values or []:
        cve = normalize_cve_id(value)
        if cve and cve not in cves:
            cves.append(cve)
    return cves


def unique_nonempty(values):
    result = []
    for value in values or []:
        if value is None:
            continue
        text = str(value).strip()
        if text and text not in result:
            result.append(text)
    return result


def to_string_or_none(value):
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def to_decimal_string(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return (
            str(value)
            if value == value and value not in (float("inf"), float("-inf"))
            else None
        )
    if isinstance(value, str) and value.strip():
        try:
            float(value)
        except ValueError:
            return None
        return value.strip()
    return None


def iso_date_or_none(value):
    text = to_string_or_none(value)
    if not text:
        return None
    if re.match(r"^\d{4}-\d{2}-\d{2}$", text):
        return f"{text}T00:00:00.000Z"
    if text.endswith("Z"):
        return text
    if "T" in text:
        return f"{text}Z"
    return text


def official_source_error(source, action, error):
    return {
        "step": "vulnerability_check",
        "message": f"{source} {action}失败：{error}",
    }


def _request_with_retry(req, timeout=120, max_retries=2, backoff_delays=(1, 3)):
    """Execute a urllib request with exponential backoff retry on transient errors.

    Retries on: HTTPError (5xx, 429), URLError, TimeoutError, OSError.
    Does NOT retry on 4xx (except 429).
    """
    last_exc = None
    for attempt in range(max_retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
            return json.loads(raw)
        except urllib.error.HTTPError as e:
            if e.code == 429 or e.code >= 500:
                last_exc = e
            else:
                raise
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last_exc = e
        if attempt < max_retries:
            time.sleep(
                backoff_delays[attempt]
                if attempt < len(backoff_delays)
                else backoff_delays[-1]
            )
    if last_exc is not None:
        raise last_exc
    raise RuntimeError("request failed without captured exception")


def post_json(url, payload, timeout=120):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": HTTP_USER_AGENT,
        },
        method="POST",
    )
    return _request_with_retry(req, timeout=timeout)


def get_json(url, timeout=120):
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": HTTP_USER_AGENT,
        },
        method="GET",
    )
    return _request_with_retry(req, timeout=timeout)


def osv_ecosystem_for(ecosystem):
    return OSV_ECOSYSTEMS.get(str(ecosystem or "").lower(), ecosystem)


def normalized_ecosystem(value):
    text = str(value or "").strip().lower()
    if text in {"pypi", "python"}:
        return "pypi"
    if text in {"crates.io", "crates-io", "rust"}:
        return "crates-io"
    if text in {"golang", "go"}:
        return "go"
    return text


def normalized_package_name(ecosystem, name):
    text = str(name or "").strip()
    if normalized_ecosystem(ecosystem) == "pypi":
        return re.sub(r"[-_.]+", "-", text.lower())
    if normalized_ecosystem(ecosystem) in {"npm", "crates-io"}:
        return text.lower()
    return text


def package_matches_affected(package, affected):
    affected_package = affected.get("package") if isinstance(affected, dict) else {}
    if not isinstance(affected_package, dict) or not affected_package:
        return True
    package_ecosystem = package.get("ecosystem")
    affected_ecosystem = affected_package.get("ecosystem")
    if normalized_ecosystem(package_ecosystem) != normalized_ecosystem(
        affected_ecosystem
    ):
        return False
    return normalized_package_name(
        package_ecosystem, package.get("name")
    ) == normalized_package_name(
        affected_ecosystem,
        affected_package.get("name"),
    )


def osv_query_for_package(package):
    query: dict[str, Any] = {
        "package": {
            "ecosystem": osv_ecosystem_for(package.get("ecosystem")),
            "name": package.get("name", ""),
        }
    }
    version = str(package.get("version") or "").strip()
    if version:
        query["version"] = version
    return query


def fetch_osv_querybatch(batch):
    payload = {"queries": [osv_query_for_package(package) for package in batch]}
    return post_json(OSV_QUERYBATCH_URL, payload)


def fetch_osv_vulnerability(vuln_id):
    return get_json(f"{OSV_VULN_URL_PREFIX}{urllib.parse.quote(str(vuln_id), safe='')}")


def parse_osv_query_results(data, batch):
    results = data.get("results") if isinstance(data, dict) else []
    if not isinstance(results, list):
        return []
    matched = []
    for index, package in enumerate(batch):
        result = (
            results[index]
            if index < len(results) and isinstance(results[index], dict)
            else {}
        )
        for vuln in result.get("vulns") or []:
            if isinstance(vuln, dict) and vuln.get("id"):
                matched.append((package, str(vuln["id"])))
    return matched


def extract_osv_fixed_versions(osv_record, package):
    fixed = []
    for affected in osv_record.get("affected") or []:
        if not isinstance(affected, dict) or not package_matches_affected(
            package, affected
        ):
            continue
        for version_range in affected.get("ranges") or []:
            if not isinstance(version_range, dict):
                continue
            for event in version_range.get("events") or []:
                if isinstance(event, dict) and event.get("fixed"):
                    fixed.append(event["fixed"])
    return unique_nonempty(fixed)


def extract_osv_cvss(osv_record):
    for severity in osv_record.get("severity") or []:
        if isinstance(severity, dict) and severity.get("score"):
            return str(severity["score"])
    return None


def first_english_description(value):
    if not isinstance(value, list):
        return None
    for item in value:
        if (
            isinstance(item, dict)
            and item.get("lang") == "en"
            and isinstance(item.get("value"), str)
            and item["value"].strip()
        ):
            return item["value"].strip()
    return None


def extract_cwe_ids(weaknesses):
    cwes = []
    if not isinstance(weaknesses, list):
        return cwes
    for weakness in weaknesses:
        if not isinstance(weakness, dict):
            continue
        for description in weakness.get("description") or []:
            if not isinstance(description, dict):
                continue
            value = str(description.get("value") or "").strip().upper()
            if re.match(r"^CWE-\d+$", value) and value not in cwes:
                cwes.append(value)
    return cwes


def normalize_cvss_metric(source, metric):
    if not isinstance(metric, dict) or not isinstance(metric.get("cvssData"), dict):
        return None
    cvss_data = metric["cvssData"]
    base_score = to_decimal_string(cvss_data.get("baseScore"))
    base_severity = to_string_or_none(cvss_data.get("baseSeverity"))
    return {
        "source": "nvd",
        "version": to_string_or_none(cvss_data.get("version"))
        or source.replace("cvssMetricV", ""),
        "vector": to_string_or_none(cvss_data.get("vectorString")),
        "baseScore": base_score,
        "baseSeverity": base_severity,
        "exploitabilityScore": to_decimal_string(metric.get("exploitabilityScore")),
        "impactScore": to_decimal_string(metric.get("impactScore")),
    }


def extract_cvss_metrics(metrics):
    if not isinstance(metrics, dict):
        return []
    result = []
    for key, value in metrics.items():
        if not key.startswith("cvssMetric") or not isinstance(value, list):
            continue
        for metric in value:
            normalized = normalize_cvss_metric(key, metric)
            if normalized:
                result.append(normalized)
    return result


def select_best_cvss_metric(metrics):
    def score(metric):
        try:
            return float(metric.get("baseScore") or 0)
        except (TypeError, ValueError):
            return 0

    return sorted(metrics, key=score, reverse=True)[0] if metrics else None


def parse_nvd_vulnerability_entry(entry):
    if not isinstance(entry, dict) or not isinstance(entry.get("cve"), dict):
        return None
    cve = entry["cve"]
    cve_id = normalize_cve_id(cve.get("id"))
    if not cve_id:
        return None
    cvss_metrics = extract_cvss_metrics(cve.get("metrics"))
    best_cvss = select_best_cvss_metric(cvss_metrics)
    description = first_english_description(cve.get("descriptions"))
    return {
        "cveId": cve_id,
        "title": description.split(".")[0] if description else None,
        "description": description,
        "cvssMetrics": cvss_metrics,
        "bestCvssScore": best_cvss.get("baseScore") if best_cvss else None,
        "bestCvssSeverity": best_cvss.get("baseSeverity") if best_cvss else None,
        "cweIds": extract_cwe_ids(cve.get("weaknesses")),
        "nvdPublishedAt": iso_date_or_none(cve.get("published")),
        "nvdModifiedAt": iso_date_or_none(cve.get("lastModified")),
    }


def parse_nvd_response(data):
    enrichments = {}
    vulnerabilities = data.get("vulnerabilities") if isinstance(data, dict) else []
    for entry in vulnerabilities or []:
        patch = parse_nvd_vulnerability_entry(entry)
        if patch:
            enrichments[patch["cveId"]] = patch
    return enrichments


def parse_cisa_kev_catalog(data):
    enrichments = {}
    vulnerabilities = data.get("vulnerabilities") if isinstance(data, dict) else []
    for entry in vulnerabilities or []:
        if not isinstance(entry, dict):
            continue
        cve_id = normalize_cve_id(entry.get("cveID"))
        if not cve_id:
            continue
        enrichments[cve_id] = {
            "cveId": cve_id,
            "title": to_string_or_none(entry.get("vulnerabilityName")),
            "description": to_string_or_none(entry.get("shortDescription")),
            "cweIds": unique_nonempty(
                entry.get("cwes") if isinstance(entry.get("cwes"), list) else []
            ),
            "kevListed": True,
            "kevDateAdded": iso_date_or_none(entry.get("dateAdded")),
            "kevDueDate": iso_date_or_none(entry.get("dueDate")),
            "kevKnownRansomwareCampaignUse": to_string_or_none(
                entry.get("knownRansomwareCampaignUse")
            ),
            "kevRequiredAction": to_string_or_none(entry.get("requiredAction")),
            "kevVendorProject": to_string_or_none(entry.get("vendorProject")),
            "kevProduct": to_string_or_none(entry.get("product")),
            "kevNotes": to_string_or_none(entry.get("notes")),
        }
    return enrichments


def parse_epss_response(data):
    enrichments = {}
    rows = data.get("data") if isinstance(data, dict) else []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        cve_id = normalize_cve_id(row.get("cve"))
        if not cve_id:
            continue
        enrichments[cve_id] = {
            "cveId": cve_id,
            "epss": to_decimal_string(row.get("epss")),
            "epssPercentile": to_decimal_string(row.get("percentile")),
            "epssScoreDate": iso_date_or_none(row.get("date")),
            "epssModelVersion": to_string_or_none(row.get("model_version")),
        }
    return enrichments


def chunked(values, size):
    values = list(values or [])
    for index in range(0, len(values), size):
        yield values[index : index + size]


def fetch_nvd_enrichments(cve_ids, errors):
    enrichments = {}
    for chunk in chunked(cve_ids, 100):
        params = urllib.parse.urlencode({"cveIds": ",".join(chunk)})
        try:
            data = get_json(f"{NVD_CVE_API_URL}?{params}")
            enrichments.update(parse_nvd_response(data))
        except (
            urllib.error.HTTPError,
            urllib.error.URLError,
            json.JSONDecodeError,
            TimeoutError,
            OSError,
        ) as e:
            errors.append(official_source_error("NVD", "CVE 查询", e))
    return enrichments


def _kev_cache_path(project_path):
    base = os.path.join(project_path, BUTIAN_DIR, CACHE_DIR_NAME, "kev")
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, "catalog.json")


def _load_kev_cache(project_path):
    cache_path = _kev_cache_path(project_path)
    try:
        mtime = os.path.getmtime(cache_path)
    except OSError:
        return None
    if time.time() - mtime > 86400:
        return None
    try:
        with open(cache_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _save_kev_cache(data, project_path):
    cache_path = _kev_cache_path(project_path)
    try:
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except OSError:
        pass


def fetch_cisa_kev_enrichments(cve_ids, errors, project_path):
    if not cve_ids:
        return {}
    data = _load_kev_cache(project_path)
    if data is None:
        try:
            data = get_json(CISA_KEV_JSON_URL)
            _save_kev_cache(data, project_path)
        except (
            urllib.error.HTTPError,
            urllib.error.URLError,
            json.JSONDecodeError,
            TimeoutError,
            OSError,
        ) as e:
            errors.append(official_source_error("CISA KEV", "目录查询", e))
            return {}
    try:
        kev = parse_cisa_kev_catalog(data)
    except Exception:
        return {}
    wanted = set(cve_ids)
    return {cve_id: patch for cve_id, patch in kev.items() if cve_id in wanted}


def fetch_epss_enrichments(cve_ids, errors):
    enrichments = {}
    for chunk in chunked(cve_ids, 100):
        params = urllib.parse.urlencode({"cve": ",".join(chunk)})
        try:
            data = get_json(f"{EPSS_API_URL}?{params}")
            enrichments.update(parse_epss_response(data))
        except (
            urllib.error.HTTPError,
            urllib.error.URLError,
            json.JSONDecodeError,
            TimeoutError,
            OSError,
        ) as e:
            errors.append(official_source_error("FIRST EPSS", "CVE 查询", e))
    return enrichments


def merge_cve_patch(target, patch):
    for key, value in (patch or {}).items():
        if key == "cveId":
            continue
        if key in {"cweIds", "cvssMetrics"}:
            merged = target.setdefault(key, [])
            for item in value or []:
                if item not in merged:
                    merged.append(item)
            continue
        if key == "kevListed":
            target[key] = bool(value) or bool(target.get(key))
            continue
        if value is not None and value != "":
            target[key] = value


def fetch_cve_enrichments(cve_ids, errors, project_path=None):
    cve_ids = unique_nonempty([normalize_cve_id(cve_id) for cve_id in cve_ids])
    enrichments = {
        cve_id: {
            "cveId": cve_id,
            "cvssMetrics": [],
            "cweIds": [],
            "kevListed": False,
        }
        for cve_id in cve_ids
    }
    sources = [
        fetch_nvd_enrichments(cve_ids, errors),
        fetch_cisa_kev_enrichments(cve_ids, errors, project_path=project_path),
        fetch_epss_enrichments(cve_ids, errors),
    ]
    for source in sources:
        for cve_id, patch in source.items():
            target = enrichments.setdefault(
                cve_id,
                {"cveId": cve_id, "cvssMetrics": [], "cweIds": [], "kevListed": False},
            )
            merge_cve_patch(target, patch)
    return enrichments


def severity_from_enrichments(osv_record, cve_enrichments):
    best_metric = None
    for enrichment in cve_enrichments:
        for metric in enrichment.get("cvssMetrics") or []:
            if not metric:
                continue
            if best_metric is None:
                best_metric = metric
                continue
            try:
                current = float(metric.get("baseScore") or 0)
                previous = float(best_metric.get("baseScore") or 0)
            except (TypeError, ValueError):
                current, previous = 0, 0
            if current > previous:
                best_metric = metric
    if best_metric:
        severity = str(best_metric.get("baseSeverity") or "").lower()
        if severity in {"critical", "high", "medium", "low"}:
            return severity, best_metric.get("baseScore")

    cvss_vector = extract_osv_cvss(osv_record)
    return _cvss_to_severity(cvss_vector) or "unknown", cvss_vector


def number_or_none(value):
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed == parsed else None


def build_risk_signals(fixed_versions, cve_enrichments):
    signals = ["affected_version_match"]
    signals.append("fixed_version_available" if fixed_versions else "no_fixed_version")
    max_cvss = max(
        [0]
        + [
            number_or_none(metric.get("baseScore")) or 0
            for enrichment in cve_enrichments
            for metric in (enrichment.get("cvssMetrics") or [])
            if isinstance(metric, dict)
        ]
    )
    if max_cvss >= 9:
        signals.append("cvss_critical")
    elif max_cvss >= 7:
        signals.append("cvss_high")
    max_epss_percentile = max(
        [0]
        + [
            number_or_none(enrichment.get("epssPercentile")) or 0
            for enrichment in cve_enrichments
        ]
    )
    if max_epss_percentile >= 0.95:
        signals.append("epss_high_percentile")
    elif max_epss_percentile >= 0.9:
        signals.append("epss_elevated_percentile")
    if any(enrichment.get("kevListed") for enrichment in cve_enrichments):
        signals.append("cisa_kev")
    if any(
        str(enrichment.get("kevKnownRansomwareCampaignUse") or "").lower() == "known"
        for enrichment in cve_enrichments
    ):
        signals.append("ransomware_campaign")
    return signals


def build_official_vulnerability(package, osv_record, cve_enrichments_by_id):
    aliases = unique_nonempty(
        (osv_record.get("aliases") or []) + [osv_record.get("id")]
    )
    cve_ids = extract_cve_aliases(aliases)
    cve_enrichments = [
        cve_enrichments_by_id[cve_id]
        for cve_id in cve_ids
        if cve_id in cve_enrichments_by_id
    ]
    fixed_versions = extract_osv_fixed_versions(osv_record, package)
    severity, cvss = severity_from_enrichments(osv_record, cve_enrichments)
    package_version = str(package.get("version") or "").strip()
    package_name = package.get("name", "")
    advisory_id = osv_record.get("id", "")
    coordinate = (
        f"{package_name}@{package_version}" if package_version else package_name
    )
    return {
        "package": package_name,
        "version": package_version,
        "ecosystem": package.get("ecosystem", ""),
        "affected": True,
        "match_reason": "osv_query_match",
        "match_summary": f"{coordinate} matched {advisory_id} in OSV official data.",
        "confidence": "high",
        "advisory_id": advisory_id,
        "aliases": aliases,
        "cve_id": cve_ids[0] if cve_ids else best_advisory_alias(aliases),
        "severity": severity,
        "cvss": cvss,
        "fixed_versions": fixed_versions,
        "summary": osv_record.get("summary") or osv_record.get("details") or "",
        "risk_signals": build_risk_signals(fixed_versions, cve_enrichments),
        "cve_enrichments": cve_enrichments,
        "vulnerability_source": "official-osv",
        "enrichment_sources": ["nvd", "cisa-kev", "first-epss"],
    }


def check_vulnerability_batch(batch_no, batch, project_path=None):
    try:
        data = fetch_osv_querybatch(batch)
    except urllib.error.HTTPError as e:
        return [], [
            {
                "step": "vulnerability_check",
                "message": f"第 {batch_no} 批 OSV querybatch 返回 HTTP {e.code}",
            }
        ]
    except urllib.error.URLError as e:
        return [], [
            {
                "step": "vulnerability_check",
                "message": f"第 {batch_no} 批 OSV querybatch 连接失败：{e.reason}",
            }
        ]
    except (json.JSONDecodeError, TimeoutError, OSError) as e:
        return [], [
            {
                "step": "vulnerability_check",
                "message": f"第 {batch_no} 批 OSV querybatch 响应解析失败：{e}",
            }
        ]

    errors = []
    matches = parse_osv_query_results(data, batch)
    if not matches:
        return [], errors

    details: dict[str, dict[str, Any]] = {}
    detail_pairs = []
    for package, vuln_id in matches:
        if vuln_id not in details:
            try:
                details[vuln_id] = fetch_osv_vulnerability(vuln_id)
            except (
                urllib.error.HTTPError,
                urllib.error.URLError,
                json.JSONDecodeError,
                TimeoutError,
                OSError,
            ) as e:
                errors.append(official_source_error("OSV", f"{vuln_id} 详情查询", e))
                continue
        detail_pairs.append((package, details[vuln_id]))

    cve_ids = []
    for _, detail in detail_pairs:
        aliases = unique_nonempty((detail.get("aliases") or []) + [detail.get("id")])
        cve_ids.extend(extract_cve_aliases(aliases))
    cve_enrichments = fetch_cve_enrichments(cve_ids, errors, project_path=project_path)

    vulns = [
        build_official_vulnerability(package, detail, cve_enrichments)
        for package, detail in detail_pairs
    ]
    return vulns, errors


def check_vulnerabilities(
    packages, batch_size=100, errors=None, concurrency=1, project_path=None
):
    if not packages:
        return []
    if errors is None:
        errors = []
    queryable_packages = []
    skipped = []
    for package in packages:
        if package.get("name") and str(package.get("version") or "").strip():
            queryable_packages.append(package)
        else:
            skipped.append(package)
    if skipped:
        examples = unique_nonempty(
            package.get("name") or package.get("package") for package in skipped
        )[:8]
        suffix = f"：{'、'.join(examples)}" if examples else ""
        errors.append(
            {
                "step": "package_extraction",
                "message": (
                    f"已跳过 {len(skipped)} 个缺少版本的依赖坐标，"
                    f"避免仅按包名误报漏洞{suffix}"
                ),
            }
        )
    packages = queryable_packages
    if not packages:
        return []
    batches = [
        (i // batch_size + 1, packages[i : i + batch_size])
        for i in range(0, len(packages), batch_size)
    ]
    workers = max(1, min(int(concurrency or 1), len(batches), 16))

    if workers == 1:
        results = []
        for batch_no, batch in batches:
            vulns, batch_errors = check_vulnerability_batch(
                batch_no, batch, project_path=project_path
            )
            results.append((batch_no, vulns, batch_errors))
    else:
        results = []
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_batch = {
                executor.submit(
                    check_vulnerability_batch, batch_no, batch, project_path
                ): batch_no
                for batch_no, batch in batches
            }
            for future in as_completed(future_to_batch):
                batch_no = future_to_batch[future]
                try:
                    vulns, batch_errors = future.result()
                except Exception as e:
                    vulns = []
                    batch_errors = [
                        {
                            "step": "vulnerability_check",
                            "message": f"第 {batch_no} 批官方漏洞源检查失败：{e}",
                        }
                    ]
                results.append((batch_no, vulns, batch_errors))

    all_vulns = []
    for _, vulns, batch_errors in sorted(results, key=lambda x: x[0]):
        all_vulns.extend(vulns)
        errors.extend(batch_errors)
    return all_vulns


# ---------------------------------------------------------------------------
# Step 4: Outdated check
# ---------------------------------------------------------------------------


def run_outdated_task(index, task):
    local_errors = []
    try:
        items = task(local_errors)
    except Exception as e:
        items = []
        local_errors.append({"step": "outdated_check", "message": str(e)})
    return index, items, local_errors


def check_outdated(project_path, ecosystems, errors=None, concurrency=4, packages=None):
    if errors is None:
        errors = []
    version_index = package_version_index(packages)
    tasks = []
    if "npm" in ecosystems:
        tasks.append(
            lambda task_errors: _outdated_json(
                "npm",
                ["npm", "outdated", "--json"],
                project_path,
                task_errors,
                version_index,
            )
        )
    if "pnpm" in ecosystems:
        tasks.append(
            lambda task_errors: _outdated_json(
                "pnpm",
                ["pnpm", "outdated", "--json"],
                project_path,
                task_errors,
                version_index,
            )
        )
    if "yarn" in ecosystems:
        tasks.append(lambda task_errors: _yarn_outdated(project_path, task_errors))
    if "pypi" in ecosystems:
        tasks.append(lambda task_errors: _pip_outdated(project_path, task_errors))
    if "go" in ecosystems:
        tasks.append(lambda task_errors: _go_outdated(project_path, task_errors))
    if "crates-io" in ecosystems:
        tasks.append(lambda task_errors: _cargo_outdated(project_path, task_errors))

    if not tasks:
        return []

    workers = max(1, min(int(concurrency or 1), len(tasks), 8))
    if workers == 1:
        results = [run_outdated_task(i, task) for i, task in enumerate(tasks)]
    else:
        results = []
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_index = {
                executor.submit(run_outdated_task, i, task): i
                for i, task in enumerate(tasks)
            }
            for future in as_completed(future_to_index):
                index = future_to_index[future]
                try:
                    results.append(future.result())
                except Exception as e:
                    results.append(
                        (
                            index,
                            [],
                            [{"step": "outdated_check", "message": str(e)}],
                        )
                    )

    outdated = []
    for _, items, task_errors in sorted(results, key=lambda x: x[0]):
        outdated.extend(item for item in items if is_outdated_item(item))
        errors.extend(task_errors)
    return outdated


def outdated_target(item):
    return item.get("wanted") or item.get("latest") or ""


def is_outdated_item(item):
    current = clean_version(item.get("current") or item.get("version"))
    target = clean_version(outdated_target(item))
    return bool(target and current != target)


def outdated_item(eco, package, data, version_index=None):
    current = (
        data.get("current") or data.get("currentVersion") or data.get("version") or ""
    )
    if not current:
        current = current_version_for(version_index, eco, package)
    return {
        "package": package,
        "current": current,
        "wanted": data.get("wanted") or data.get("update") or "",
        "latest": data.get("latest") or data.get("latestVersion") or "",
        "ecosystem": eco,
    }


def _outdated_json(eco, cmd, cwd, errors=None, version_index=None):
    output = run_cmd_checked(
        cmd, cwd=cwd, timeout=60, errors=errors, step="outdated_check"
    )
    if not output:
        return []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        if errors is not None:
            errors.append(
                {
                    "step": "outdated_check",
                    "message": f"{cmd[0]} outdated 输出不是有效 JSON",
                }
            )
        return []
    if isinstance(data, list):
        return [
            outdated_item(
                eco,
                p.get("name") or p.get("packageName", ""),
                p,
                version_index=version_index,
            )
            for p in data
        ]
    return [
        outdated_item(
            eco, n, v if isinstance(v, dict) else {}, version_index=version_index
        )
        for n, v in data.items()
    ]


def _yarn_outdated(cwd, errors=None):
    output = run_cmd_checked(
        ["yarn", "outdated", "--json"],
        cwd=cwd,
        timeout=60,
        errors=errors,
        step="outdated_check",
    )
    if not output:
        return []
    result = []
    for line in output.split("\n"):
        try:
            d = json.loads(line)
            if d.get("type") == "table":
                for row in d.get("data", {}).get("body", []):
                    if len(row) >= 4:
                        result.append(
                            {
                                "package": row[0],
                                "current": row[1],
                                "latest": row[3],
                                "ecosystem": "npm",
                            }
                        )
        except json.JSONDecodeError:
            continue
    return result


def project_python_executable(cwd):
    candidates = []
    for dirname in (".venv", "venv", "env"):
        base = os.path.join(cwd, dirname)
        if not os.path.isfile(os.path.join(base, "pyvenv.cfg")):
            continue
        candidates.extend(
            [
                os.path.join(base, "bin", "python3"),
                os.path.join(base, "bin", "python"),
                os.path.join(base, "Scripts", "python.exe"),
            ]
        )
    for candidate in candidates:
        if os.path.isfile(candidate) and (
            os.name == "nt" or os.access(candidate, os.X_OK)
        ):
            return candidate
    return ""


def _pip_outdated(cwd, errors=None):
    # uv-managed projects: use uv pip list for outdated check
    if os.path.isfile(os.path.join(cwd, "uv.lock")):
        output = run_cmd_checked(
            ["uv", "pip", "list", "--outdated", "--format=json"],
            cwd=cwd,
            timeout=60,
            errors=errors,
            step="outdated_check",
        )
        if not output:
            return []
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            if errors is not None:
                errors.append(
                    {
                        "step": "outdated_check",
                        "message": "uv pip list --outdated 输出不是有效 JSON",
                    }
                )
            return []
        return [
            {
                "package": p.get("name", ""),
                "current": p.get("version", ""),
                "latest": p.get("latest_version", p.get("latest", "")),
                "ecosystem": "pypi",
            }
            for p in data
            if isinstance(p, dict)
        ]

    python = project_python_executable(cwd)
    if not python:
        if errors is not None:
            errors.append(
                {
                    "step": "outdated_check",
                    "message": "未发现项目本地虚拟环境，已跳过 PyPI 过期依赖检查，避免扫描系统 Python 环境",
                }
            )
        return []
    output = run_cmd_checked(
        [python, "-m", "pip", "list", "--outdated", "--format=json"],
        cwd=cwd,
        timeout=60,
        errors=errors,
        step="outdated_check",
    )
    if not output:
        return []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        if errors is not None:
            errors.append(
                {
                    "step": "outdated_check",
                    "message": "pip list --outdated 输出不是有效 JSON",
                }
            )
        return []
    return [
        {
            "package": p.get("name", ""),
            "current": p.get("version", ""),
            "latest": p.get("latest_version", ""),
            "ecosystem": "pypi",
        }
        for p in data
    ]


def _go_outdated(cwd, errors=None):
    output = run_cmd_checked(
        ["go", "list", "-u", "-m", "-json", "all"],
        cwd=cwd,
        timeout=120,
        errors=errors,
        step="outdated_check",
    )
    if not output:
        return []
    result = []
    for d in iter_json_objects(output):
        if d.get("Update"):
            result.append(
                {
                    "package": d.get("Path", ""),
                    "current": d.get("Version", ""),
                    "latest": d["Update"].get("Version", ""),
                    "ecosystem": "go",
                }
            )
    return result


def iter_json_objects(text):
    decoder = json.JSONDecoder()
    pos = 0
    length = len(text)
    while pos < length:
        while pos < length and text[pos].isspace():
            pos += 1
        if pos >= length:
            break
        try:
            obj, pos = decoder.raw_decode(text, pos)
        except json.JSONDecodeError:
            break
        if isinstance(obj, dict):
            yield obj


def _cargo_outdated(cwd, errors=None):
    probe = run_cmd_checked(
        ["cargo", "outdated", "--help"],
        cwd=cwd,
        timeout=30,
        errors=None,
        step="outdated_check",
    )
    if not probe:
        if errors is not None:
            errors.append(
                {
                    "step": "outdated_check",
                    "message": "未发现 cargo-outdated 子命令，已跳过 Rust 过期依赖检查；安装 cargo-outdated 后可获得维护视图",
                }
            )
        return []

    output = run_cmd_checked(
        ["cargo", "outdated"],
        cwd=cwd,
        timeout=120,
        errors=errors,
        step="outdated_check",
    )
    if not output:
        return []
    result = []
    for line in output.split("\n"):
        parts = line.split()
        if len(parts) >= 3 and parts[0] != "Name":
            result.append(
                {
                    "package": parts[0],
                    "current": parts[1],
                    "latest": parts[-1],
                    "ecosystem": "crates-io",
                }
            )
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Local project scanner")
    parser.add_argument("project_path", nargs="?", default=".")
    parser.add_argument(
        "--preflight",
        help="reuse a preflight JSON file to choose project path and scan mode",
    )
    parser.add_argument(
        "--output",
        help="write JSON to this path instead of the default temp-file path",
    )
    parser.add_argument(
        "--no-root-discovery",
        action="store_true",
        help="scan the provided path directly instead of walking up to a repo root",
    )
    parser.add_argument(
        "--skip-outdated",
        action="store_true",
        help="skip package-manager outdated checks for faster vulnerability-only scans",
    )
    parser.add_argument(
        "--skip-hygiene",
        action="store_true",
        help="skip gitignore, tracked sensitive file, and hardcoded secret checks",
    )
    parser.add_argument(
        "--max-secret-files",
        type=int,
        default=500,
        help="maximum number of candidate files to scan for hardcoded secrets",
    )
    parser.add_argument(
        "--include-packages",
        action="store_true",
        help="include the full package list in output JSON",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="输出详细日志到 stderr",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="输出调试级别日志到 stderr 和日志文件",
    )
    parser.add_argument(
        "--follow-symlinks",
        action="store_true",
        help="跟随符号链接扫描（默认跳过）",
    )
    return parser.parse_args(argv)


def load_preflight(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def default_output_path(project_path, preflight=None):
    return default_asset_path(project_path, "scan.json", preflight=preflight)


def write_json_output(path, text):
    output_dir = os.path.dirname(os.path.abspath(path))
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.write("\n")


def main():
    started = time.time()
    args = parse_args(sys.argv[1:])
    try:
        preflight = load_preflight(args.preflight) if args.preflight else None
    except (json.JSONDecodeError, OSError) as e:
        print(f"Failed to read preflight JSON: {e}", file=sys.stderr)
        return 2

    preflight_project_path = (preflight or {}).get("project", {}).get("path")
    if preflight_project_path:
        project_path = os.path.abspath(preflight_project_path)
    else:
        start = args.project_path
        project_path = (
            os.path.abspath(start)
            if args.no_root_discovery
            else find_project_root(start)
        )
    preflight_scan_mode = (preflight or {}).get("recommended_scan_mode")
    preflight_hygiene_only = preflight_scan_mode == "hygiene_only"
    output_file = args.output or default_output_path(project_path, preflight=preflight)
    errors = []
    # Setup logging
    log_dir = os.path.join(os.path.dirname(os.path.dirname(output_file)), "logs")
    logger = setup_logging(verbose=args.verbose, debug=args.debug, log_dir=log_dir)
    logger.info("开始扫描项目: %s", project_path)
    step_seconds = {}

    # Step 1: detect ecosystems
    step_started = time.time()
    if preflight_hygiene_only:
        ecosystems, lockfiles = [], {}
        logger.info("Step 1/5 生态检测: 跳过 (hygiene_only 模式)")
    else:
        try:
            ecosystems, lockfiles = detect_ecosystems(project_path)
        except Exception as e:
            ecosystems, lockfiles = [], {}
            errors.append({"step": "ecosystem_detection", "message": str(e)})
            logger.error("Step 1/5 生态检测失败: %s", e)
    step_seconds["ecosystem_detection"] = round(time.time() - step_started, 3)
    logger.info(
        "Step 1/5 生态检测完成: %s (lockfile: %s), 耗时 %.3fs",
        ecosystems or "无",
        list(lockfiles.values()) or "无",
        step_seconds["ecosystem_detection"],
    )
    scan_mode = preflight_scan_mode or (
        "full_dependency_scan" if ecosystems else "hygiene_only"
    )
    logger.info("扫描模式: %s", scan_mode)
    skip_dependency_checks = scan_mode == "hygiene_only"

    # Step 2: parse package coordinates
    step_started = time.time()
    if skip_dependency_checks:
        packages = []
        logger.info("Step 2/5 依赖提取: 跳过 (hygiene_only 模式)")
    else:
        try:
            packages = extract_packages(project_path, ecosystems)
            logger.info(
                "Step 2/5 依赖提取完成: %d 个包, 耗时 %.3fs",
                len(packages),
                round(time.time() - step_started, 3),
            )
        except Exception as e:
            packages = []
            errors.append({"step": "package_extraction", "message": str(e)})
            logger.error("Step 2/5 依赖提取失败: %s", e)
    if not skip_dependency_checks and not packages:
        sources = "、".join(lockfiles.values()) or "依赖文件"
        errors.append(
            {
                "step": "package_extraction",
                "message": (
                    f"已发现 {sources}，但没有提取到带精确版本的依赖坐标；"
                    "本次不会仅按包名匹配漏洞，requirements.txt 范围约束需要 lockfile "
                    "或 == / === 精确版本才能确认受影响版本。"
                ),
            }
        )
    step_seconds["package_extraction"] = round(time.time() - step_started, 3)

    # Step 3-5: independent I/O-heavy checks run in parallel.

    # Note: steps 4 and 5 run in parallel
    def run_hygiene_step():
        step_started = time.time()
        if args.skip_hygiene:
            logger.info("Step 3/5 仓库安检: 跳过 (--skip-hygiene)")
            return (
                "hygiene",
                {"skipped": True},
                [],
                round(time.time() - step_started, 3),
            )
        try:
            secret_file_limit = max(0, int(args.max_secret_files or 0))
            logger.info(
                "Step 3/5 仓库安检开始 (max_secret_files=%d)...", secret_file_limit
            )
            result = scan_hygiene(
                project_path,
                max_secret_files=secret_file_limit,
                follow_symlinks=args.follow_symlinks,
                ecosystems=ecosystems,
            )
            n_secrets = len(result.get("tracked_secrets") or [])
            n_sensitive = len(result.get("sensitive_tracked") or [])
            logger.info(
                "Step 3/5 仓库安检完成: %d 密钥, %d 敏感文件, 耗时 %.3fs",
                n_secrets,
                n_sensitive,
                round(time.time() - step_started, 3),
            )
            return "hygiene", result, [], round(time.time() - step_started, 3)
        except Exception as e:
            logger.error("Step 3/5 仓库安检失败: %s", e)
            return (
                "hygiene",
                {},
                [{"step": "hygiene", "message": str(e)}],
                round(
                    time.time() - step_started,
                    3,
                ),
            )

    def run_vulnerability_step():
        step_started = time.time()
        if skip_dependency_checks:
            logger.info("Step 4/5 漏洞检测: 跳过 (hygiene_only 模式)")
            return "vulnerabilities", [], [], round(time.time() - step_started, 3)
        step_errors = []
        try:
            api_workers = min(4, (os.cpu_count() or 1))
            logger.info(
                "Step 4/5 漏洞检测开始: %d 个包, 并发 %d...", len(packages), api_workers
            )
            result = check_vulnerabilities(
                packages,
                errors=step_errors,
                concurrency=api_workers,
                project_path=project_path,
            )
            logger.info(
                "Step 4/5 漏洞检测完成: %d 个风险项, 耗时 %.3fs",
                len(result),
                round(time.time() - step_started, 3),
            )
        except Exception as e:
            result = []
            step_errors.append({"step": "vulnerability_check", "message": str(e)})
            logger.error("Step 4/5 漏洞检测失败: %s", e)
        return (
            "vulnerabilities",
            result,
            step_errors,
            round(time.time() - step_started, 3),
        )

    def run_outdated_step():
        step_started = time.time()
        if skip_dependency_checks or args.skip_outdated:
            logger.info("Step 5/5 过时依赖: 跳过")
            return "outdated", [], [], round(time.time() - step_started, 3)
        step_errors = []
        try:
            outdated_workers = min(4, (os.cpu_count() or 1))
            logger.info(
                "Step 5/5 过时依赖检测开始: 生态 %s, 并发 %d...",
                ecosystems,
                outdated_workers,
            )
            result = check_outdated(
                project_path,
                ecosystems,
                errors=step_errors,
                concurrency=outdated_workers,
                packages=packages,
            )
            logger.info(
                "Step 5/5 过时依赖检测完成: %d 个过时, 耗时 %.3fs",
                len(result),
                round(time.time() - step_started, 3),
            )
        except Exception as e:
            result = []
            step_errors.append({"step": "outdated_check", "message": str(e)})
            logger.error("Step 5/5 过时依赖检测失败: %s", e)
        return "outdated", result, step_errors, round(time.time() - step_started, 3)

    logger.info("Step 3-5 并行执行开始...")
    hygiene, vulnerabilities, outdated = {}, [], []
    parallel_steps = [run_hygiene_step, run_vulnerability_step, run_outdated_step]
    with ThreadPoolExecutor(max_workers=len(parallel_steps)) as executor:
        futures = [executor.submit(step) for step in parallel_steps]
        for future in as_completed(futures):
            name, result, step_errors, elapsed = future.result()
            step_seconds[name] = elapsed
            errors.extend(step_errors)
            if name == "hygiene":
                hygiene = result
            elif name == "vulnerabilities":
                vulnerabilities = result
            elif name == "outdated":
                outdated = result

    logger.info("并行步骤全部完成")
    git_repo = is_git_worktree(project_path)
    git_branch = (
        run_cmd(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=project_path)
        if git_repo
        else ""
    )

    output = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "scan_seconds": round(time.time() - started, 1),
        "project": {
            "path": project_path,
            "name": os.path.basename(project_path),
            "ecosystems": ecosystems,
            "lockfiles": list(lockfiles.values()),
            "git_repo": git_repo,
            "git_branch": git_branch or None,
            "total_packages": len(packages),
            "total_vulnerabilities": len(vulnerabilities),
        },
        "scan_config": {
            "api_concurrency": min(4, (os.cpu_count() or 1)),
            "outdated_concurrency": min(4, (os.cpu_count() or 1)),
            "preflight_file": os.path.abspath(args.preflight)
            if args.preflight
            else None,
            "scan_mode": scan_mode,
            "skip_dependency_checks": skip_dependency_checks,
            "skip_hygiene": bool(args.skip_hygiene),
            "skip_outdated": bool(args.skip_outdated),
            "include_packages": bool(args.include_packages),
            "max_secret_files": max(0, int(args.max_secret_files or 0)),
            "vulnerability_sources": (
                []
                if skip_dependency_checks
                else ["osv", "nvd", "cisa-kev", "first-epss"]
            ),
        },
        "output_file": output_file,
        "butian_workspace": {
            "gitignore": (
                ((preflight or {}).get("butian_workspace") or {}).get("gitignore")
                or butian_gitignore_status(project_path)
            ),
        },
        "step_seconds": step_seconds,
        "hygiene": hygiene,
        "package_count": len(packages),
        "package_sources": package_source_summary(packages),
        "vulnerabilities": vulnerabilities,
        "vulnerability_count": len(vulnerabilities),
        "outdated": outdated,
        "outdated_count": len(outdated),
        "errors": errors,
    }
    if args.include_packages:
        output["packages"] = packages

    text = json.dumps(output, ensure_ascii=False, indent=2)
    write_json_output(output_file, text)
    logger.info("结果已写入: %s (%d bytes)", output_file, len(text))
    print(text)

    total_seconds = round(time.time() - started, 1)
    logger.info(
        "扫描完成: 总耗时 %.1fs, %d 风险项, %d 过时, %d 错误",
        total_seconds,
        len(vulnerabilities),
        len(outdated),
        len(errors),
    )


if __name__ == "__main__":
    sys.exit(main() or 0)
