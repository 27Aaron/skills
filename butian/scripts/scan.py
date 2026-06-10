#!/usr/bin/env python3
"""项目安全扫描器。

采集项目范围内的安全数据，并输出 JSON 供后续分析。
扫描器会先识别依赖生态和精确包坐标。
仓库安检、漏洞和过期依赖检查随后独立运行，
因为它们依赖不同的本地文件、包管理器和官方数据源。

扫描对项目代码和依赖文件只读：它只创建/更新本地报告工作区，
并静默确保 .gitignore 忽略生成报告。

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
  Supported ecosystems: npm/pnpm/yarn, PyPI, Go, crates.io, Packagist,
  RubyGems, Pub, Hex, NuGet, and Maven
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
from concurrent.futures import ThreadPoolExecutor, as_completed

SCAN_SCHEMA_VERSION = "1.0.0"

try:
    from .cache import cache_clean, cache_dir, cache_read, cache_write
    from .dependency_parsers import (
        LOCKFILE_MAP,
        PARSERS,
        _parse_cargo_lock_fallback,
        _parse_toml_lock,
        _parse_toml_lock_fallback,
        _parse_yarn_lock_berry,
        _parse_yarn_lock_v1,
        _tomllib,
        _yarn_berry_descriptor_name,
        _yarn_v1_descriptor_name,
        clean_version,
        current_version_for,
        detect_ecosystems,
        extract_packages,
        is_exact_dependency_version,
        is_exact_maven_coordinate_part,
        normalized_plain_version,
        normalized_rubygems_version,
        npm_lock_package_name,
        package_source_summary,
        package_version_index,
        parse_cargo_lock,
        parse_composer_lock,
        parse_gemfile_lock,
        parse_go_sum,
        parse_maven_pom,
        parse_mix_lock,
        parse_npm_lock,
        parse_nuget,
        parse_packages_config,
        parse_packages_lock_json,
        parse_pipfile_lock,
        parse_pnpm_lock,
        parse_poetry_lock,
        parse_pubspec_lock,
        parse_pypi,
        parse_requirements_txt,
        parse_uv_lock,
        parse_yarn_lock,
        xml_child_text,
        xml_direct_children,
        xml_local_name,
    )
    from .iac_checks import scan_iac_checks
    from .repo_checks import scan_repository_checks
    from .vulnerability_sources import (
        CISA_KEV_JSON_URL,
        EPSS_API_URL,
        HTTP_USER_AGENT,
        NVD_CVE_API_URL,
        OSV_ECOSYSTEMS,
        OSV_QUERYBATCH_URL,
        OSV_VULN_URL_PREFIX,
        _cvss_to_severity,
        _kev_cache_path,
        _load_kev_cache,
        _request_with_retry,
        _save_kev_cache,
        best_advisory_alias,
        build_official_vulnerability,
        build_risk_signals,
        check_vulnerabilities,
        check_vulnerability_batch,
        chunked,
        cvss_score_to_severity,
        extract_cve_aliases,
        extract_cvss_metrics,
        extract_cwe_ids,
        extract_osv_cvss,
        extract_osv_fixed_versions,
        fetch_cisa_kev_enrichments,
        fetch_cve_enrichments,
        fetch_epss_enrichments,
        fetch_nvd_enrichments,
        fetch_osv_querybatch,
        fetch_osv_vulnerability,
        first_english_description,
        get_json,
        iso_date_or_none,
        merge_cve_patch,
        normalize_cve_id,
        normalize_cvss_metric,
        normalized_ecosystem,
        normalized_package_name,
        number_or_none,
        official_source_error,
        osv_ecosystem_for,
        osv_query_for_package,
        package_matches_affected,
        parse_cisa_kev_catalog,
        parse_epss_response,
        parse_nvd_response,
        parse_nvd_vulnerability_entry,
        parse_osv_query_results,
        post_json,
        select_best_cvss_metric,
        severity_from_enrichments,
        to_decimal_string,
        to_string_or_none,
        unique_nonempty,
    )
    from .workflow_checks import scan_workflows
    from .workspace import (
        _GITIGNORE_STATUS_BY_PROJECT,
        BUTIAN_ASSETS_DIR,
        BUTIAN_DIR,
        BUTIAN_GITIGNORE_ENTRY,
        BUTIAN_GITIGNORE_EXTRA_ENTRIES,
        CACHE_DIR_NAME,
        butian_gitignore_status,
        default_asset_path,
        ensure_butian_gitignore,
        ensure_butian_run,
        ensure_butian_workspace,
        ensure_safe_project_path,
        find_project_root,
        gitignore_ignores,
        gitignore_rules,
        has_butian_gitignore_entry,
        has_gitignore_entry,
        inspect_butian_gitignore,
        is_protected_project_path,
        make_run_id,
        run_dir_from_output_file,
    )
except ImportError:  # pragma: no cover - direct script execution
    from cache import (  # pyright: ignore[reportMissingImports]
        cache_clean,
        cache_dir,
        cache_read,
        cache_write,
    )
    from dependency_parsers import (  # pyright: ignore[reportMissingImports]
        LOCKFILE_MAP,
        PARSERS,
        _parse_cargo_lock_fallback,
        _parse_toml_lock,
        _parse_toml_lock_fallback,
        _parse_yarn_lock_berry,
        _parse_yarn_lock_v1,
        _tomllib,
        _yarn_berry_descriptor_name,
        _yarn_v1_descriptor_name,
        clean_version,
        current_version_for,
        detect_ecosystems,
        extract_packages,
        is_exact_dependency_version,
        is_exact_maven_coordinate_part,
        normalized_plain_version,
        normalized_rubygems_version,
        npm_lock_package_name,
        package_source_summary,
        package_version_index,
        parse_cargo_lock,
        parse_composer_lock,
        parse_gemfile_lock,
        parse_go_sum,
        parse_maven_pom,
        parse_mix_lock,
        parse_npm_lock,
        parse_nuget,
        parse_packages_config,
        parse_packages_lock_json,
        parse_pipfile_lock,
        parse_pnpm_lock,
        parse_poetry_lock,
        parse_pubspec_lock,
        parse_pypi,
        parse_requirements_txt,
        parse_uv_lock,
        parse_yarn_lock,
        xml_child_text,
        xml_direct_children,
        xml_local_name,
    )
    from iac_checks import scan_iac_checks  # pyright: ignore[reportMissingImports]
    from repo_checks import (
        scan_repository_checks,  # pyright: ignore[reportMissingImports]
    )
    from vulnerability_sources import (  # pyright: ignore[reportMissingImports]
        CISA_KEV_JSON_URL,
        EPSS_API_URL,
        HTTP_USER_AGENT,
        NVD_CVE_API_URL,
        OSV_ECOSYSTEMS,
        OSV_QUERYBATCH_URL,
        OSV_VULN_URL_PREFIX,
        _cvss_to_severity,
        _kev_cache_path,
        _load_kev_cache,
        _request_with_retry,
        _save_kev_cache,
        best_advisory_alias,
        build_official_vulnerability,
        build_risk_signals,
        check_vulnerabilities,
        check_vulnerability_batch,
        chunked,
        cvss_score_to_severity,
        extract_cve_aliases,
        extract_cvss_metrics,
        extract_cwe_ids,
        extract_osv_cvss,
        extract_osv_fixed_versions,
        fetch_cisa_kev_enrichments,
        fetch_cve_enrichments,
        fetch_epss_enrichments,
        fetch_nvd_enrichments,
        fetch_osv_querybatch,
        fetch_osv_vulnerability,
        first_english_description,
        get_json,
        iso_date_or_none,
        merge_cve_patch,
        normalize_cve_id,
        normalize_cvss_metric,
        normalized_ecosystem,
        normalized_package_name,
        number_or_none,
        official_source_error,
        osv_ecosystem_for,
        osv_query_for_package,
        package_matches_affected,
        parse_cisa_kev_catalog,
        parse_epss_response,
        parse_nvd_response,
        parse_nvd_vulnerability_entry,
        parse_osv_query_results,
        post_json,
        select_best_cvss_metric,
        severity_from_enrichments,
        to_decimal_string,
        to_string_or_none,
        unique_nonempty,
    )
    from workflow_checks import scan_workflows  # pyright: ignore[reportMissingImports]
    from workspace import (  # pyright: ignore[reportMissingImports]
        _GITIGNORE_STATUS_BY_PROJECT,
        BUTIAN_ASSETS_DIR,
        BUTIAN_DIR,
        BUTIAN_GITIGNORE_ENTRY,
        BUTIAN_GITIGNORE_EXTRA_ENTRIES,
        CACHE_DIR_NAME,
        butian_gitignore_status,
        default_asset_path,
        ensure_butian_gitignore,
        ensure_butian_run,
        ensure_butian_workspace,
        ensure_safe_project_path,
        find_project_root,
        gitignore_ignores,
        gitignore_rules,
        has_butian_gitignore_entry,
        has_gitignore_entry,
        inspect_butian_gitignore,
        is_protected_project_path,
        make_run_id,
        run_dir_from_output_file,
    )

HYGIENE_ONLY_NOTICE = (
    "当前项目未发现支持的依赖文件，暂无法执行依赖漏洞扫描；"
    "本次仅做仓库安检，检查硬编码密钥、敏感文件跟踪、.gitignore、"
    "GitHub Actions、依赖配置与维护和 IaC/容器配置风险。"
)
CAPABILITY_BOUNDARY = (
    "安全往往不是最显眼的需求，却是产品长期稳定运行的底线。"
    "此报告基于本地可确认的依赖和仓库证据，帮助你发现应用依赖漏洞、"
    "过期依赖和仓库暴露风险，并把可处理的问题整理成清晰的修复线索。"
    "它不能替代代码审计、渗透测试或完整安全评估；业务逻辑、权限控制、"
    "输入校验、SQL 注入、XSS 等代码层风险仍需结合业务场景复核。"
    "安全的价值不只在于发现问题，更在于让团队知道风险在哪里、先处理什么，"
    "以及如何让每一次修复都成为系统可靠性的积累。"
)
# ---------------------------------------------------------------------------
# 密钥检测模式
# ---------------------------------------------------------------------------

# --- 云服务商密钥 ---
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
    # Alibaba Cloud
    ("aliyun_access_key", r"LTAI[0-9A-Za-z]{12,20}"),
    (
        "aliyun_secret_key",
        r"(?:ALIBABA|ALICLOUD|ALIYUN|aliyun|alibaba)[_\s-]?(?:SECRET|secret|ACCESS|access)[_\s-]?KEY[_\s-]*[:=]\s*[\"']?[A-Za-z0-9/+=]{30}[\"']?",
    ),
    # Tencent Cloud
    ("tencent_secret_id", r"(?:AKID|TC3)[A-Za-z0-9]{32}"),
    # Huawei Cloud
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
    # Linode / Akamai（需要上下文）
    (
        "linode_api_key",
        r"(?:linode|akamai|LINODE)[_\s-]?(?:api|token|key)(?:[_\s-]?(?:key|token|id|secret))?[_\s-]*[:=]\s*[\"']?[0-9a-f]{64}[\"']?",
    ),
    # Vultr（需要上下文）
    (
        "vultr_api_key",
        r"(?:vultr|VULTR)[_\s-]?(?:api|token|key)(?:[_\s-]?(?:key|token|id|secret))?[_\s-]*[:=]\s*[\"']?[A-Za-z0-9]{36}[\"']?",
    ),
    # Cloudflare
    ("cloudflare_api_key", r"v1\.0-[a-f0-9]{24}-[a-f0-9]{146}"),
    ("cloudflare_origin_ca", r"-----BEGIN ORIGIN " r"CERTIFICATE-----"),
    # Heroku（需要上下文，避免误匹配随机 UUID）
    (
        "heroku_api_key",
        r"(?:heroku|HEROKU)[_\s-]?(?:api|token|key)(?:[_\s-]?(?:key|token|id|secret))?[_\s-]*[:=]\s*[\"']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[\"']?",
    ),
]

# --- SaaS / 第三方服务 Token ---
_SAAS_PATTERNS = [
    # GitHub
    (
        "github_fine_grained_pat",
        r"github_pat_[A-Za-z0-9_]{20,}_[A-Za-z0-9_]{40,}",
    ),
    ("github_token", r"gh[pousr]_[A-Za-z0-9_]{36,}"),
    ("github_oauth", r"gho_[A-Za-z0-9]{36}"),
    ("github_app_token", r"(?:ghu_|ghs_)[A-Za-z0-9_]{36}"),
    ("github_refresh_token", r"ghr_[A-Za-z0-9_]{36}"),
    # GitLab
    ("gitlab_token", r"glpat-[A-Za-z0-9\-_]{20,}"),
    ("gitlab_runner_token", r"glrt-[A-Za-z0-9\-_]{20,}"),
    ("gitlab_deploy_token", r"gldt-[A-Za-z0-9\-_]{20,}"),
    # 带稳定前缀的平台 / 密钥管理 token
    ("hashicorp_vault_token", r"hv[bs]\.[A-Za-z0-9_-]{20,}"),
    ("pulumi_token", r"pul-[A-Za-z0-9]{30,}"),
    # LLM / AI 服务商密钥
    ("groq_api_key", r"gsk_[A-Za-z0-9]{20,}"),
    # 需要上下文的平台密钥。这里故意要求产品名靠近 token/key 文案，
    # 避免普通随机字符串造成噪声。
    (
        "cloudflare_api_token",
        r"(?i)(?:cloudflare|CF)[_\s-]?(?:api[_\s-]?)?(?:token|key)[_\s-]*[:=]\s*[\"']?[A-Za-z0-9_.-]{24,}[\"']?",
    ),
    (
        "vercel_token",
        r"(?i)vercel[_\s-]?(?:auth[_\s-]?)?(?:token|key)[_\s-]*[:=]\s*[\"']?[A-Za-z0-9_.-]{24,}[\"']?",
    ),
    (
        "netlify_token",
        r"(?i)netlify[_\s-]?(?:auth[_\s-]?)?(?:token|key)[_\s-]*[:=]\s*[\"']?[A-Za-z0-9_.-]{24,}[\"']?",
    ),
    (
        "railway_token",
        r"(?i)railway[_\s-]?(?:api[_\s-]?)?(?:token|key)[_\s-]*[:=]\s*[\"']?[A-Za-z0-9_.-]{24,}[\"']?",
    ),
    (
        "render_token",
        r"(?i)render[_\s-]?(?:api[_\s-]?)?(?:token|key)[_\s-]*[:=]\s*[\"']?[A-Za-z0-9_.-]{24,}[\"']?",
    ),
    (
        "snyk_token",
        r"(?i)snyk[_\s-]?(?:api[_\s-]?)?(?:token|key)[_\s-]*[:=]\s*[\"']?[A-Za-z0-9_.-]{24,}[\"']?",
    ),
    (
        "resend_api_key",
        r"(?i)resend[_\s-]?(?:api[_\s-]?)?(?:key|token)[_\s-]*[:=]\s*[\"']?[A-Za-z0-9_.-]{24,}[\"']?",
    ),
    (
        "clerk_secret_key",
        r"(?i)clerk[_\s-]?(?:secret[_\s-]?)?(?:key|token)[_\s-]*[:=]\s*[\"']?sk_(?:live|prod)_[A-Za-z0-9_-]{20,}[\"']?",
    ),
    (
        "supabase_service_role_key",
        r"(?i)supabase[_\s-]?service[_\s-]?role[_\s-]?(?:key|token)[_\s-]*[:=]\s*[\"']?eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}[\"']?",
    ),
    (
        "algolia_admin_key",
        r"(?i)algolia[_\s-]?(?:admin[_\s-]?)?(?:api[_\s-]?)?(?:key|token)[_\s-]*[:=]\s*[\"']?[A-Za-z0-9]{24,}[\"']?",
    ),
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
    # Datadog（需要上下文）
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
    # Grafana（需要上下文）
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
    # Travis CI（需要上下文）
    (
        "travis_token",
        r"(?:travis|TRAVIS)[_\s-]?(?:ci|token|api|key)(?:[_\s-]?(?:key|token|id|secret))?[_\s-]*[:=]\s*[\"']?[A-Za-z0-9]{22,}[\"']?",
    ),
    # Buildkite
    ("buildkite_token", r"bkua_[a-f0-9]{40}"),
    # Jenkins（需要上下文）
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
    # google_ai_key 与 gcp_api_key 共用 AIza 前缀，上面已覆盖。
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
    # Atlassian（JIRA / Confluence，需要上下文）
    (
        "atlassian_token",
        r"(?:atlassian|jira|confluence|bitbucket|ATLASSIAN|JIRA)[_\s-]?(?:token|api|key|pat)(?:[_\s-]?(?:key|token|id|secret))?[_\s-]*[:=]\s*[\"']?[A-Za-z0-9]{24}[\"']?",
    ),
    # Notion
    ("notion_token", r"(?:secret|ntn)_[A-Za-z0-9]{30,}"),
    # Linear
    ("linear_api_key", r"lin_api_[A-Za-z0-9_]{30,}"),
    # Airtable
    ("airtable_api_key", r"(?<![A-Za-z0-9])key[A-Za-z0-9]{14}(?![A-Za-z0-9])"),
    # Asana（需要上下文，避免误匹配版本字符串）
    (
        "asana_token",
        r"(?:asana|ASANA)[_\s-]?(?:token|api|key|pat)(?:[_\s-]?(?:key|token|id|secret))?[_\s-]*[:=]\s*[\"']?(?:1|2)/[0-9]+:[A-Za-z0-9]+[\"']?",
    ),
    # Fastly（需要上下文）
    (
        "fastly_api_key",
        r"(?:fastly|FASTLY)[_\s-]?(?:api|token|key)(?:[_\s-]?(?:key|token|id|secret))?[_\s-]*[:=]\s*[\"']?[A-Za-z0-9_-]{32}[\"']?",
    ),
    # Ngrok（需要上下文）
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

# --- 通用 / 启发式模式（置信度较低，由用户判断） ---
_GENERIC_PATTERNS = [
    # 私钥（所有变体）
    (
        "private_key",
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?:\sBLOCK)?-----",
    ),
    # 通用密码
    (
        "generic_password",
        r"""(?:password|passwd|pwd|pass_word)\s*[:=]\s*["'][^"']{4,}["']""",
    ),
    # 通用 API 密钥
    (
        "generic_api_key",
        r"""(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?key|auth[_-]?token)\s*[:=]\s*["'][^"']{8,}["']""",
    ),
    # 通用 token 赋值
    (
        "generic_token",
        r"""(?:token|bearer|jwt|access_token|refresh_token|id_token|session_token|csrf_token)\s*[:=]\s*["'][A-Za-z0-9_\-\.]{20,}["']""",
    ),
    # Authorization header 中的 Bearer token
    (
        "bearer_token",
        r"""[Aa]uthorization\s*[:=]\s*["']?Bearer\s+[A-Za-z0-9_\-\.]{20,}["']?""",
    ),
    # 通用 secret 赋值
    (
        "generic_secret",
        r"""(?:secret|SECRET|Secret)[_-]?(?:key|KEY|Key|token|TOKEN|Token|id|ID|Id)\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}["']""",
    ),
    # Base64 编码的疑似密钥
    (
        "base64_secret",
        r"""(?:secret|token|key|password|credential|auth)[_-]?(?:encoded|base64|b64)\s*[:=]\s*["'][A-Za-z0-9+/=]{24,}["']""",
    ),
    # 硬编码连接字符串
    (
        "connection_string",
        r"""(?i)(?:connection[_-]?string|conn[_-]?str|database[_-]?url|db[_-]?url)\s*[:=]\s*["'][^"']{10,}["']""",
    ),
    (
        "basic_auth_url",
        r"""https?://[A-Za-z0-9._~%+-]+:[^@\s"']{8,}@[A-Za-z0-9._-]+""",
    ),
    (
        "netrc_password",
        r"""(?i)\bmachine\s+\S+.*\blogin\s+\S+.*\bpassword\s+\S{8,}""",
    ),
    # 加密密钥
    (
        "encryption_key",
        r"""(?:encryption|encrypt|cipher|aes|rsa|des)[_-]?key\s*[:=]\s*["'][A-Za-z0-9+/=]{16,}["']""",
    ),
    # 内嵌密钥的 Webhook URL
    (
        "webhook_url",
        r"""https?://[^/\s"']+/webhook[s]?/[A-Za-z0-9_\-]{20,}""",
    ),
    # JWT 形态模式
    (
        "jwt_token",
        r"""eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}""",
    ),
    # 通用 sk- 前缀兜底（MiniMax、DeepSeek、Moonshot、Zhipu 等）。
    # 很多 LLM/API 服务商使用 sk- 作为密钥前缀；中等置信度，由用户判断。
    # 排除上方已匹配的 sk-proj-（openai_key）和 sk-ant-（anthropic_key）。
    # \b 确保 sk- 不是更长单词的一部分，例如 CSS 中的 "mask-composite"。
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
# 过短或含义模糊的标记必须做单词边界检查。
SECRET_SKIP_WORD_MARKERS = (
    "xxx",
    "test",
    "default",
)
SECRET_FIXTURE_FILE_MARKER = "butian: allow-secret-fixtures"
HIGH_CONFIDENCE_SECRET_TYPES = {
    # 云服务商（带唯一前缀）
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
    # 加密材料 / 密钥
    "private_key",
    # SaaS token（带唯一前缀）
    "github_token",
    "github_fine_grained_pat",
    "github_oauth",
    "github_app_token",
    "github_refresh_token",
    "gitlab_token",
    "gitlab_runner_token",
    "gitlab_deploy_token",
    "hashicorp_vault_token",
    "pulumi_token",
    "groq_api_key",
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
    # 环境 / 配置文件
    ("env_file", r"(^|/)\.env(\.[\w-]+)?$"),
    ("envrc", r"(^|/)\.envrc$"),
    ("npmrc", r"(^|/)\.npmrc$"),
    ("pypirc", r"(^|/)\.pypirc$"),
    ("netrc", r"(^|/)\.netrc$"),
    ("gem_credentials", r"(^|/)\.gem/credentials$"),
    # 私钥 / 证书
    ("private_key", r"\.(pem|key|p12|pfx|jks|keystore|pub|gpg|pgp|asc|ppk)$"),
    (
        "ssh_key",
        r"(^|/)(?:id_(?:rsa|ed25519|ecdsa)|ssh_host_[a-z0-9_]+_key)(?:\.pub)?$",
    ),
    ("kubeconfig", r"(^|/)kubeconfig$|(^|/)\.kube/config$"),
    ("docker_cfg", r"(^|/)\.dockercfg$|(^|/)config\.json$"),
    # 数据库文件
    ("database", r"\.(sqlite|sqlite3|db|dump|rdb|redis|bson)$"),
    # 凭证 / 服务账号
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
    # 构建 / CI 密钥
    ("ci_secrets", r"(^|/)secrets\.yml$|(^|/)secrets\.yaml$|(^|/)secrets\.json$"),
    ("gradle_properties", r"(^|/)gradle\.properties$"),
    ("maven_settings", r"(^|/)settings\.xml$"),
    # 日志（可能包含泄漏密钥）
    ("log", r"\.log$"),
    # dump / 导出文件
    ("dump", r"\.(sql|pgdump|mysqldump|mongoexport|jsonl|csv)$"),
    # 可能包含密钥的应用配置
    (
        "app_config",
        r"(^|/)(?:application|app)\.(?:yml|yaml|properties|conf)(?:\.[\w-]+)?$",
    ),
    # 备份文件
    ("backup", r"\.(bak|backup|old|orig|save|swp)$"),
    # 历史文件（可能包含粘贴过的密钥）
    (
        "history",
        r"(^|/)\.(?:bash_history|zsh_history|python_history|node_repl_history|mysql_history|psql_history)$",
    ),
]
SENSITIVE_FILE_REGEXES = [
    (file_type, re.compile(pattern)) for file_type, pattern in SENSITIVE_FILE_PATTERNS
]

ENV_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")

# 敏感文件类型只有在匹配到真实文件后，才映射到 .gitignore 规则。
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
    ".json",
    ".jsonc",
    ".json5",
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
    ".hcl",
    ".tf",
    ".tfvars",
    ".ini",
    ".cfg",
    ".conf",
    ".properties",
    ".xml",
    ".gradle",
    ".kts",
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".html",
    ".css",
    ".scss",
    ".less",
}

SECRET_SCAN_FILENAMES = {
    ".env",
    ".envrc",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "dockerfile",
    "makefile",
    "procfile",
    "jenkinsfile",
    "fastfile",
    "rakefile",
    "gemfile",
    "gradle.properties",
    "settings.xml",
    "application.properties",
    "application.yml",
    "application.yaml",
}

SECRET_SCAN_EXCLUDED_FILENAMES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "uv.lock",
    "pipfile.lock",
    "cargo.lock",
    "go.sum",
    "composer.lock",
    "gemfile.lock",
    "bun.lock",
    "bun.lockb",
}

SECRET_SCAN_SENSITIVE_TYPES = {
    "env_file",
    "envrc",
    "npmrc",
    "pypirc",
    "netrc",
    "gem_credentials",
    "private_key",
    "ssh_key",
    "kubeconfig",
    "docker_cfg",
    "credentials",
    "aws_credentials",
    "gcp_credentials",
    "azure_credentials",
    "terraform_vars",
    "ansible_vault",
    "ci_secrets",
    "gradle_properties",
    "maven_settings",
    "app_config",
}

# ---------------------------------------------------------------------------
# 通用工具
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
# 日志
# ---------------------------------------------------------------------------

_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(verbose=False, debug=False, log_dir=None, log_file="scan.log"):
    """配置扫描日志输出到 stderr 和可选日志文件。

    参数：
        verbose: 为 True 时，stderr 使用 INFO 级别。
        debug: 为 True 时，stderr 和文件都使用 DEBUG 级别。
        log_dir: 日志文件目录；为 None 时不写文件日志。
        log_file: log_dir 内的日志文件名，默认 "scan.log"。

    返回：
        已配置好的 "butian" logger。
    """
    logger = logging.getLogger("butian")
    # 避免重复调用时添加重复 handler。
    if logger.handlers:
        return logger
    # logger 保持 DEBUG，方便文件 handler 捕获全部消息；
    # stderr handler 负责控制用户在终端看到的内容。
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
# 二进制 / 符号链接工具
# ---------------------------------------------------------------------------


def is_binary_file(filepath):
    """读取文件前 8KB，判断是否包含 NUL 字节以识别二进制文件。"""
    try:
        with open(filepath, "rb") as f:
            chunk = f.read(8192)
        return b"\x00" in chunk
    except OSError:
        return True


def declares_secret_fixture_file(filepath, max_header_bytes=4096):
    """文件显式声明自己是密钥测试夹具时返回 True。"""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as handle:
            header = handle.read(max_header_bytes)
    except OSError:
        return False
    return SECRET_FIXTURE_FILE_MARKER in header


# ---------------------------------------------------------------------------
# 密钥扫描文件选择
# ---------------------------------------------------------------------------


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


def should_scan_secret_file(path, project_path=None):
    rel = os.path.relpath(path, project_path) if project_path else path
    normalized = rel.replace(os.sep, "/")
    name = os.path.basename(normalized).lower()
    ext = os.path.splitext(name)[1].lower()

    if name in SECRET_SCAN_EXCLUDED_FILENAMES:
        return False
    if name.endswith(".lock") or name.endswith(".lockb"):
        return False
    if name in SECRET_SCAN_FILENAMES:
        return True
    if name.startswith("dockerfile."):
        return True
    if is_env_secret_scan_file(name):
        return True
    if ext in SCAN_EXTENSIONS:
        return True
    return sensitive_file_type(normalized) in SECRET_SCAN_SENSITIVE_TYPES


def is_git_worktree(path):
    return run_cmd(["git", "rev-parse", "--is-inside-work-tree"], cwd=path) == "true"


# ---------------------------------------------------------------------------
# 仓库安全检查
# ---------------------------------------------------------------------------


def check_gitignore(project_path, sensitive_tracked):
    """检查 .gitignore，只针对实际出现的敏感文件类型给出建议。"""
    gitignore_path = os.path.join(project_path, ".gitignore")
    gitignore_exists = os.path.isfile(gitignore_path)
    if not gitignore_exists:
        content = ""
    else:
        with open(gitignore_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

    # 收集项目中实际发现的敏感文件类型。
    found_types = set()
    for item in sensitive_tracked:
        found_types.add(item.get("type", ""))
    # 同时检查 .env 文件是否存在，即使它没有被 git 跟踪。
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


def git_ls_files(project_path, errors=None):
    try:
        result = subprocess.run(
            ["git", "ls-files"],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=project_path,
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        if errors is not None:
            errors.append(
                {
                    "step": "hygiene.git_ls_files",
                    "message": "命令不可用：git，无法确认被 Git 跟踪的敏感文件。",
                }
            )
        return ""
    except subprocess.TimeoutExpired:
        if errors is not None:
            errors.append(
                {
                    "step": "hygiene.git_ls_files",
                    "message": "git ls-files 超时，无法确认被 Git 跟踪的敏感文件。",
                }
            )
        return ""
    except OSError as exc:
        if errors is not None:
            errors.append(
                {
                    "step": "hygiene.git_ls_files",
                    "message": f"git ls-files 执行失败，无法确认被 Git 跟踪的敏感文件：{exc}",
                }
            )
        return ""

    stdout = result.stdout.strip()
    if result.returncode == 0:
        return stdout

    stderr = (result.stderr or "").strip()
    if "not a git repository" in stderr.lower():
        return ""
    if errors is not None:
        message = stderr or "无 stderr 输出"
        errors.append(
            {
                "step": "hygiene.git_ls_files",
                "message": f"git ls-files 失败，无法确认被 Git 跟踪的敏感文件：{message}",
            }
        )
    return ""


def check_sensitive_tracked(project_path, errors=None):
    output = git_ls_files(project_path, errors=errors)
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
# 基于熵值的密钥检测引擎
# ---------------------------------------------------------------------------

# 熵值是未知 token 格式的兜底信号。服务商特征正则更精确，
# 因此仍然作为主要证据。

# Shannon 熵值阈值
_BASE64_ENTROPY_THRESHOLD = 4.5  # base64 chars: max ~6.0
_HEX_ENTROPY_THRESHOLD = 3.0  # hex chars: max ~4.0
_GENERIC_ENTROPY_THRESHOLD = 4.2  # generic high-entropy: mixed charset
_MIN_SECRET_LENGTH = 20  # minimum candidate length for entropy check
_MAX_SECRET_LENGTH = 500  # skip unreasonably long strings

# 暗示密钥值的键名（用于上下文熵值扫描）。
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
    """计算字符串的 Shannon 熵值。"""
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
    """判断字符串是否像 base64 编码数据。"""
    return bool(re.fullmatch(r"[A-Za-z0-9+/=]+", s)) and len(s) % 4 <= 1


def _is_hex(s: str) -> bool:
    """判断字符串是否像十六进制编码数据。"""
    return bool(re.fullmatch(r"[0-9a-fA-F]+", s))


def _extract_assignment_value(line: str) -> tuple[str, str] | None:
    """从单行中提取 KEY=VALUE 或 KEY: VALUE，返回 (key, value) 或 None。"""
    m = re.match(
        r"""^\s*([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*["']?([^\s"']+)["']?\s*$""",
        line,
    )
    if m:
        return m.group(1), m.group(2)
    return None


def _secret_candidate_value(text: str) -> str:
    m = re.search(r"""[=:]\s*["']?([^"'\s#]+)""", str(text or ""))
    return m.group(1) if m else str(text or "")


def is_placeholder_secret_candidate(text: str) -> bool:
    candidate = _secret_candidate_value(text).lower()
    if not candidate:
        return False
    if any(marker.lower() in candidate for marker in SECRET_SKIP_MARKERS):
        return True
    return any(
        re.search(rf"\b{re.escape(marker.lower())}\b", candidate)
        for marker in SECRET_SKIP_WORD_MARKERS
    )


def looks_like_code_reference(value: str) -> bool:
    """判断候选值是否更像代码引用，而不是密钥字符串。"""
    text = str(value or "").strip()
    if not text:
        return False
    if not re.fullmatch(r"[A-Za-z0-9_.$\[\]().]+", text):
        return False
    if any(ch in text for ch in "()[]"):
        return bool(re.search(r"[A-Za-z_$][A-Za-z0-9_$]*\s*\(", text) or "." in text)
    return False


def entropy_check_value(value: str) -> dict | None:
    """分析字符串是否具备高熵特征，判断它是否可能是密钥。

    命中时返回包含 ``entropy_type`` 和 ``entropy`` 的字典，否则返回 *None*。
    """
    if not value or len(value) < _MIN_SECRET_LENGTH or len(value) > _MAX_SECRET_LENGTH:
        return None
    if looks_like_code_reference(value):
        return None

    # 跳过明显不是密钥的值。
    if value.lower() in ("true", "false", "null", "none", "undefined", "yes", "no"):
        return None
    if re.fullmatch(r"[0-9]+", value):  # 纯数字
        return None
    if re.fullmatch(r"[a-z]+", value):  # 纯小写单词
        return None
    if re.fullmatch(r"[A-Z]+", value):  # 纯大写单词
        return None

    entropy = _shannon_entropy(value)

    # 检查编码类型，并应用对应阈值。
    if _is_base64(value) and entropy >= _BASE64_ENTROPY_THRESHOLD:
        return {"entropy_type": "base64_high_entropy", "entropy": round(entropy, 2)}
    if _is_hex(value) and len(value) >= 32 and entropy >= _HEX_ENTROPY_THRESHOLD:
        return {"entropy_type": "hex_high_entropy", "entropy": round(entropy, 2)}
    if entropy >= _GENERIC_ENTROPY_THRESHOLD:
        return {"entropy_type": "generic_high_entropy", "entropy": round(entropy, 2)}

    return None


def scan_entropy_for_line(line: str) -> list[dict]:
    """扫描单行中的高熵值。

    检查：
      1. key 暗示密钥的赋值（阈值较低）。
      2. 独立出现且熵值很高的引号字符串。

    返回包含 ``entropy_type``、``entropy``、``key``、``value``、
    ``value_preview`` 的字典列表。
    """
    results: list[dict] = []
    stripped = line.strip()

    # 1. KEY = VALUE / KEY: VALUE 模式。
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
                        "value": value,
                        "value_preview": _mask_entropy_value(value),
                    }
                )
            return results  # 每行只检查第一个赋值。

    # 2. 带引号的高熵字符串（独立出现，没有 key 上下文）。
    for m in re.finditer(r"""["']([A-Za-z0-9+/=_\-]{24,})["']""", stripped):
        value = m.group(1)
        info = entropy_check_value(value)
        if info and info["entropy"] >= 4.7:  # 没有 key 提示时使用更严格阈值。
            results.append(
                {
                    **info,
                    "key": "",
                    "value": value,
                    "value_preview": _mask_entropy_value(value),
                }
            )

    # 3. env 风格行中的无引号高熵值。
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
                        "value": value,
                        "value_preview": _mask_entropy_value(value),
                    }
                )

    return results


def _mask_entropy_value(value: str) -> str:
    """脱敏值，便于安全展示。"""
    if len(value) <= 12:
        return "***"
    return value[:6] + "..." + value[-4:]


def _soft_mask_value(value: str, mask_chars: int = 4) -> str:
    """只脱敏中间少量字符，同时保留足够文本方便定位。"""
    if not value:
        return value
    if len(value) <= mask_chars:
        return "*" * len(value)
    hidden = min(mask_chars, max(3, len(value) // 4))
    visible = len(value) - hidden
    left = max(1, visible // 2)
    right = visible - left
    return value[:left] + ("*" * hidden) + (value[-right:] if right else "")


_ASSIGNMENT_VALUE_RE = re.compile(
    r"""(?P<prefix>[:=]\s*["']?)(?P<value>[^"'\s#]+)(?P<suffix>["']?)"""
)


# ---------------------------------------------------------------------------
# 密钥预览和扫描
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
        "basic_auth_url",
        "netrc_password",
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


def soft_secret_preview(secret_type, match_text):
    """局部脱敏模板文件证据，同时不隐藏其所在位置。"""
    # 模板文件保留可定位证据，方便新手找到具体占位符行，
    # 同时继续脱敏足够字符，保证报告安全。
    if secret_type == "private_key":
        return "-----BEGIN **** PRIVATE KEY-----"

    masked = _ASSIGNMENT_VALUE_RE.sub(
        lambda match: (
            f"{match.group('prefix')}"
            f"{_soft_mask_value(match.group('value'))}"
            f"{match.group('suffix')}"
        ),
        match_text,
        count=1,
    )
    if masked != match_text:
        return masked

    return _soft_mask_value(match_text)


def should_reveal_secret_evidence(path):
    # 模板文件也可能误放真实凭据；报告只保留强脱敏定位信息。
    return False


def soft_mask_secret_context_line(line):
    masked = line
    for secret_type, pattern in SECRET_REGEXES:
        masked = pattern.sub(
            lambda match, kind=secret_type: soft_secret_preview(kind, match.group(0)),
            masked,
        )
    return masked


def mask_secret_context_line(line):
    masked = line
    for secret_type, pattern in SECRET_REGEXES:
        masked = pattern.sub(
            lambda match, kind=secret_type: secret_preview(kind, match.group(0)),
            masked,
        )

    assignment = _extract_assignment_value(masked.strip())
    if assignment:
        key, _ = assignment
        if any(hint in key.lower() for hint in _SECRET_HINT_KEYWORDS):
            masked = re.sub(
                r"""([:=]\s*["']?)[^"'\s#]+(["']?)""",
                r"\1***\2",
                masked,
                count=1,
            )
    return masked


def build_secret_code_context(
    lines,
    line_num,
    match_text="",
    preview="",
    reveal=False,
    soft_mask=False,
    radius=2,
):
    if not lines or not line_num:
        return []

    start = max(1, line_num - radius)
    end = line_num + radius
    context = []
    for idx in range(start, end + 1):
        content = lines[idx - 1].rstrip("\n").rstrip("\r") if idx <= len(lines) else ""
        if content and not reveal:
            content = (
                soft_mask_secret_context_line(content)
                if soft_mask
                else mask_secret_context_line(content)
            )
            if idx == line_num and match_text and preview:
                content = content.replace(match_text, preview, 1)
        context.append(
            {
                "line": idx,
                "content": content,
                "match": idx == line_num,
            }
        )
    return context


def scan_secrets(
    project_path,
    max_files=500,
    max_bytes=1024 * 1024,
    follow_symlinks=False,
    stats=None,
):
    findings = []
    entropy_findings = []
    count = 0
    limit = 500 if max_files is None else max(0, int(max_files))
    secret_scan_stats = {
        "max_files": limit,
        "candidate_files": 0,
        "scanned_files": 0,
        "skipped_by_limit": 0,
        "skipped_fixture_files": 0,
        "skipped_too_large": 0,
        "skipped_unreadable": 0,
    }
    for root, dirs, files in os.walk(project_path, followlinks=follow_symlinks):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for fname in files:
            fpath = os.path.join(root, fname)
            ext = os.path.splitext(fname)[1].lower()
            if not should_scan_secret_file(fpath, project_path):
                continue
            # 未开启 follow-symlinks 时跳过符号链接。
            if not follow_symlinks and os.path.islink(fpath):
                continue
            # 跳过二进制文件。
            if is_binary_file(fpath):
                continue
            secret_scan_stats["candidate_files"] += 1
            if declares_secret_fixture_file(fpath):
                secret_scan_stats["skipped_fixture_files"] += 1
                continue
            if count >= limit:
                secret_scan_stats["skipped_by_limit"] += 1
                continue
            try:
                if os.path.getsize(fpath) > max_bytes:
                    secret_scan_stats["skipped_too_large"] += 1
                    continue
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    file_lines = f.readlines()
                    soft_mask_evidence = should_reveal_secret_evidence(fpath)
                    rel = os.path.relpath(fpath, project_path)
                    for line_num, line in enumerate(file_lines, 1):
                        stripped = line.strip()
                        is_npmrc = os.path.basename(fpath).lower() == ".npmrc"
                        if stripped.startswith("#") or (
                            stripped.startswith("//") and not is_npmrc
                        ):
                            continue
                        # --- 第 1 阶段：正则模式匹配 ---
                        for secret_type, pattern in SECRET_REGEXES:
                            m = pattern.search(line)
                            if m:
                                match_text = m.group(0)
                                if is_placeholder_secret_candidate(match_text):
                                    continue
                                preview = (
                                    soft_secret_preview(secret_type, match_text)
                                    if soft_mask_evidence
                                    else secret_preview(secret_type, match_text)
                                )
                                findings.append(
                                    {
                                        "file": rel,
                                        "line": line_num,
                                        "type": secret_type,
                                        "preview": preview,
                                        "code_context": build_secret_code_context(
                                            file_lines,
                                            line_num,
                                            match_text=match_text,
                                            preview=preview,
                                            soft_mask=soft_mask_evidence,
                                        ),
                                        "confidence": "high"
                                        if secret_type in HIGH_CONFIDENCE_SECRET_TYPES
                                        else "medium",
                                    }
                                )

                        # --- 第 2 阶段：基于熵值检测 ---
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
                                match_text = einfo.get("value") or ""
                                if is_placeholder_secret_candidate(match_text):
                                    continue
                                preview = (
                                    _soft_mask_value(match_text)
                                    if soft_mask_evidence and match_text
                                    else einfo["value_preview"]
                                )
                                entropy_findings.append(
                                    {
                                        "file": rel,
                                        "line": line_num,
                                        "type": einfo["entropy_type"],
                                        "preview": preview,
                                        "code_context": build_secret_code_context(
                                            file_lines,
                                            line_num,
                                            match_text=match_text,
                                            preview=preview,
                                            soft_mask=soft_mask_evidence,
                                        ),
                                        "key": einfo.get("key", ""),
                                        "entropy": einfo["entropy"],
                                        "confidence": "low",
                                    }
                                )
            except (OSError, UnicodeDecodeError):
                secret_scan_stats["skipped_unreadable"] += 1
                continue
            count += 1
            secret_scan_stats["scanned_files"] = count

    # 正则命中优先于熵值命中。同一行中，服务商形态 token
    # 比泛化随机字符串证据更强。
    seen = set()
    high_conf_locations = set()
    deduped = []
    for f in findings:
        key = (f["file"], f["line"], f["type"])
        loc = (f["file"], f["line"])
        if key in seen:
            continue
        # 如果高置信命中已经覆盖这一行，跳过低/中置信命中。
        if f.get("confidence") != "high" and loc in high_conf_locations:
            continue
        seen.add(key)
        if f.get("confidence") == "high":
            high_conf_locations.add(loc)
        deduped.append(f)

    # 对熵值命中去重，并抑制已被正则捕获的项。
    regex_hit_keys = {(f["file"], f["line"]) for f in deduped}
    entropy_deduped = []
    entropy_seen: set[tuple[str, int, str]] = set()
    for ef in entropy_findings:
        ekey = (ef["file"], ef["line"], ef["type"])
        if ekey in entropy_seen:
            continue
        # 如果同一文件同一行已有正则命中，跳过熵值命中（正则更具体）。
        if (ef["file"], ef["line"]) in regex_hit_keys:
            continue
        entropy_seen.add(ekey)
        entropy_deduped.append(ef)

    if stats is not None:
        stats.clear()
        stats.update(secret_scan_stats)

    return deduped + entropy_deduped


def scan_hygiene(
    project_path, max_secret_files=500, follow_symlinks=False, ecosystems=None
):
    errors = []
    # 先扫描敏感文件，再根据命中结果生成 gitignore 建议。
    sensitive_tracked = check_sensitive_tracked(project_path, errors=errors)
    secret_scan_stats = {}
    tracked_secrets = scan_secrets(
        project_path,
        max_files=max_secret_files,
        follow_symlinks=follow_symlinks,
        stats=secret_scan_stats,
    )
    if secret_scan_stats.get("skipped_by_limit"):
        errors.append(
            {
                "step": "hygiene.secret_scan_limit",
                "message": (
                    f"硬编码凭证扫描达到 --max-secret-files={secret_scan_stats.get('max_files')} 上限："
                    f"已扫描 {secret_scan_stats.get('scanned_files')} 个候选文件，"
                    f"跳过 {secret_scan_stats.get('skipped_by_limit')} 个候选文件；"
                    "请提高上限后复扫，避免遗漏凭证。"
                ),
            }
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
        "errors": errors,
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
            "secret_scan": secret_scan_stats,
        },
    }


# ---------------------------------------------------------------------------
# 过期依赖检查
# ---------------------------------------------------------------------------


def run_outdated_task(index, task):
    local_errors = []
    try:
        items = task(local_errors)
    except Exception as e:
        items = []
        local_errors.append({"step": "outdated_check", "message": str(e)})
    return index, items, local_errors


def check_outdated(
    project_path,
    ecosystems,
    errors=None,
    concurrency=4,
    packages=None,
    allow_project_exec=False,
):
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
        tasks.append(
            lambda task_errors: _pip_outdated(
                project_path,
                task_errors,
                allow_project_exec=allow_project_exec,
            )
        )
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


def _pip_outdated(cwd, errors=None, *, allow_project_exec=False):
    # uv 管理的项目：使用 uv pip list 做过期检查。
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
    if not allow_project_exec:
        if errors is not None:
            errors.append(
                {
                    "step": "outdated_check",
                    "message": "已跳过 PyPI 过期依赖检查：发现项目本地虚拟环境，但默认不执行项目内 Python；如需执行请显式传入 --allow-project-exec。",
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
# 主流程
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
        "--allow-project-exec",
        action="store_true",
        help="allow outdated checks to execute project-local tools such as .venv/bin/python",
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
    try:
        ensure_safe_project_path(project_path)
        output_file = args.output or default_output_path(
            project_path, preflight=preflight
        )
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2
    errors = []
    # 输出路径确定运行目录后再初始化日志。
    log_dir = os.path.join(os.path.dirname(os.path.dirname(output_file)), "logs")
    logger = setup_logging(verbose=args.verbose, debug=args.debug, log_dir=log_dir)
    logger.info("开始扫描项目: %s", project_path)
    step_seconds = {}

    # 先检测生态和 lockfile，再判断是否存在可扫描依赖。
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

    # 只解析精确包坐标；只有范围的 manifest 不参与漏洞匹配。
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

    # 第 3-5 类检查彼此独立且 I/O 较重，可以并行运行。
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
            return (
                "hygiene",
                result,
                result.get("errors") or [],
                round(time.time() - step_started, 3),
            )
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
                allow_project_exec=args.allow_project_exec,
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
        "schema_version": SCAN_SCHEMA_VERSION,
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
