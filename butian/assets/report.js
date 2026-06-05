const RAW = window.__BUTIAN_REPORT_DATA__ || {};
const toList = (value) => {
  if (!value) return [];
  if (Array.isArray(value)) {
    return value.filter((x) => x != null && x !== "");
  }
  return String(value)
    .split(/\n+/)
    .map((x) => x.trim())
    .filter(Boolean);
};
const CAPABILITY_BOUNDARY =
  "安全往往不是最显眼的需求，却是产品长期稳定运行的底线。补天 会优先帮助你发现依赖漏洞、过期依赖和仓库卫生风险，让容易被忽视的供应链问题更早暴露出来。但它不能替代代码审计、渗透测试或部署安全评估；代码层面的权限、业务逻辑、SQL 注入、XSS 等问题仍需单独复核。";

// ---- Normalize: accept common field name variations from different agents ----
const DATA = (() => {
  const d = Object.assign({}, RAW);
  // Arrays: green|green_items, yellow|yellow_items, red|red_items
  d.green = d.green || d.green_items || [];
  d.yellow = d.yellow || d.yellow_items || [];
  d.red = d.red || d.red_items || [];
  d.vulns =
    d.vulns ||
    d.vulnerabilities ||
    d.all_issues ||
    d.top5 ||
    d.top_issues ||
    [];
  d.errors = d.errors || [];
  d.hygiene = d.hygiene || {};
  d.outdated = toList(d.outdated).filter(isRenderableOutdated);
  d.outdated_count = d.outdated.length;
  d.scan_config = d.scan_config || {};
  // Normalize items inside arrays: title→name, light→tier, current_version→version, etc.
  const normItem = (it) => {
    if (!it) return it;
    it.name = it.name || it.title || it.summary || "";
    it.tier = it.tier || it.light || "";
    it.version = it.version || it.current_version || "";
    it.path = it.path || it.file_path || it.file || "";
    it.file = it.file || it.file_path || it.path || "";
    it.severity = String(it.severity || "info").toLowerCase();
    if (!["critical", "high", "medium", "low", "info"].includes(it.severity)) {
      it.severity = "info";
    }
    if (!it.tier && it.light) it.tier = it.light;
    // advisory_id: string or array → always string
    if (Array.isArray(it.advisory_ids) && !it.advisory_id) {
      it.advisory_id = it.advisory_ids.join(", ");
    }
    // risk_note → risk mapping
    if (!it.risk && it.risk_note) it.risk = it.risk_note;
    if (!it.summary && it.description) it.summary = it.description;
    return it;
  };
  d.green = d.green.map(normItem);
  d.yellow = d.yellow.map(normItem);
  d.red = d.red.map(normItem);
  d.vulns = d.vulns.map(normItem);
  // Project: total_packages or total_dependencies
  d.project = d.project || {};
  d.project.total_packages =
    d.project.total_packages ||
    d.project.total_dependencies ||
    d.package_count ||
    0;
  d.project.total_vulnerabilities =
    d.project.total_vulnerabilities || d.vulnerability_count || 0;
  // Summary: may be top-level or nested
  d.summary = d.summary || {};
  d.summary.tldr =
    d.summary.tldr ||
    d.summary.tl_dr ||
    d.summary.one_liner ||
    d.summary.overview ||
    "";
  d.summary.detail =
    d.summary.detail || d.summary.details || d.summary.explanation || "";
  if (d.summary.detail) {
    d.summary.detail = String(d.summary.detail).replace(
      /过期依赖\s*\d+\s*个/g,
      `过期依赖 ${d.outdated.length} 个`,
    );
  }
  if (Array.isArray(d.recommendations) && !d.summary.priority) {
    d.summary.priority = d.recommendations;
  }
  if (d.priority_items && !d.summary.priority) {
    d.summary.priority = d.priority_items;
  }
  d.summary.priority = toList(d.summary.priority);
  // Risk summary: compute only when missing. Explicit all-zero summaries mean "no confirmed risk".
  if (!d.risk_summary) {
    const rs = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    [...d.green, ...d.yellow, ...d.red, ...d.vulns].forEach((it) => {
      const s = (it.severity || "info").toLowerCase();
      if (s in rs) rs[s]++;
      else rs.info++;
    });
    d.risk_summary = rs;
  } else {
    const rs = d.risk_summary;
    ["critical", "high", "medium", "low", "info"].forEach((k) => {
      rs[k] = Number(rs[k] || 0);
    });
  }
  if (!d.summary.tldr) {
    const rs = d.risk_summary || {};
    const riskTotal =
      (rs.critical || 0) + (rs.high || 0) + (rs.medium || 0) + (rs.low || 0);
    if (rs.critical || 0 || rs.high || 0) {
      d.summary.tldr =
        "这次扫描发现会影响发布判断的高优先级风险，建议先安排严重和高危项。";
    } else if (riskTotal) {
      d.summary.tldr = "这次扫描发现一些中低风险项，建议按影响范围分批处理。";
    } else if (d.errors && d.errors.length) {
      d.summary.tldr = "这次扫描暂未确认风险，但有部分检查失败，结论需要复核。";
    } else {
      d.summary.tldr =
        "这次扫描没有发现明确风险，可以把这份报告作为当前项目安全状态记录。";
    }
  }
  if (!d.summary.detail) {
    const confirmed = d.vulns.length;
    const hygieneIssues =
      (d.hygiene.tracked_secrets || []).length +
      (d.hygiene.sensitive_tracked || []).length +
      (d.hygiene.gitignore_missing || []).length;
    const outdatedCount = d.outdated.length;
    d.summary.detail = `本报告面向产品经理和项目负责人：本次检查覆盖依赖漏洞、仓库卫生和过期依赖。已确认漏洞 ${confirmed} 个，仓库卫生待关注项 ${hygieneIssues} 个，过期依赖 ${outdatedCount} 个。`;
  }
  if (!d.summary.priority || !d.summary.priority.length) {
    const priority = [];
    const criticalHigh =
      (d.risk_summary.critical || 0) + (d.risk_summary.high || 0);
    if (criticalHigh) {
      priority.push(
        `优先安排 ${criticalHigh} 个严重/高危项，先升级有修复版本的依赖，再跑测试确认没有影响功能。`,
      );
    } else if (d.vulns && d.vulns.length) {
      priority.push(
        `处理 ${d.vulns.length} 个已确认依赖漏洞，按严重度从高到低分批升级。`,
      );
    }
    if (d.yellow && d.yellow.length) {
      priority.push(
        `安排研发或运维确认 ${d.yellow.length} 个待判断事项，重点看密钥、配置和可疑依赖来源。`,
      );
    }
    if (d.red && d.red.length) {
      priority.push(
        `对 ${d.red.length} 个高风险事项按报告步骤处理，涉及凭证时先轮换，再评估是否需要清理 git 历史。`,
      );
    }
    if (d.errors && d.errors.length) {
      priority.push(
        "复查扫描错误，补齐失败的官方漏洞源、包管理器或工具链检查后再确认最终结论。",
      );
    }
    if (!priority.length) {
      priority.push(
        "当前没有需要立即处理的明确风险，可以保留报告作为这次检查的结论。",
      );
    }
    d.summary.priority = priority;
  }
  return d;
})();

const esc = (s) =>
  String(s == null ? "" : s).replace(
    /[&<>"]/g,
    (c) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
      })[c],
  );

function safeHref(value) {
  try {
    const url = new URL(String(value || ""), window.location.href);
    return ["http:", "https:"].includes(url.protocol) ? url.href : "";
  } catch {
    return "";
  }
}

function copyBtn(text) {
  return `<button class="copy" data-cmd="${btoa(unescape(encodeURIComponent(text)))}">复制</button>`;
}

function cmdBlock(c) {
  const label = c.label ? `<div class="cmd-label">${esc(c.label)}</div>` : "";
  return `${label}<div class="cmd">${copyBtn(c.cmd)}${esc(c.cmd)}</div>`;
}

function sevBadge(sev) {
  const cls =
    {
      critical: "sev-critical",
      high: "sev-high",
      medium: "sev-medium",
      low: "sev-low",
      info: "sev-info",
    }[sev] || "sev-info";
  const text =
    {
      critical: "严重",
      high: "高危",
      medium: "中危",
      low: "低危",
      info: "信息",
    }[sev] || sev;
  return `<span class="sev-badge ${cls}">${esc(text)}</span>`;
}

function sectionIcon(kind) {
  const icons = {
    search:
      '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-shield-alert-icon lucide-shield-alert"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>',
    advice:
      '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-file-chart-column-icon lucide-file-chart-column"><path d="M6 22a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h8a2.4 2.4 0 0 1 1.704.706l3.588 3.588A2.4 2.4 0 0 1 20 8v12a2 2 0 0 1-2 2z"/><path d="M14 2v5a1 1 0 0 0 1 1h5"/><path d="M8 18v-1"/><path d="M12 18v-6"/><path d="M16 18v-3"/></svg>',
    fix: '<svg viewBox="0 0 24 24"><path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.4 2.4-3-3Z" /></svg>',
    hygiene:
      '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-brush-cleaning-icon lucide-brush-cleaning"><path d="m16 22-1-4"/><path d="M19 14a1 1 0 0 0 1-1v-1a2 2 0 0 0-2-2h-3a1 1 0 0 1-1-1V4a2 2 0 0 0-4 0v5a1 1 0 0 1-1 1H6a2 2 0 0 0-2 2v1a1 1 0 0 0 1 1"/><path d="M19 14H5l-1.973 6.767A1 1 0 0 0 4 22h16a1 1 0 0 0 .973-1.233z"/><path d="m8 22 1-4"/></svg>',
    review:
      '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-eye-icon lucide-eye"><path d="M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0"/><circle cx="12" cy="12" r="3"/></svg>',
    risk: '<svg viewBox="0 0 24 24"><path d="M20 13c0 5-3.5 7.5-7.7 8.9a1 1 0 0 1-.6 0C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.2-2.7a1.2 1.2 0 0 1 1.6 0C14.5 3.8 17 5 19 5a1 1 0 0 1 1 1Z" /><path d="M12 8v4" /><path d="M12 16h.01" /></svg>',
    long: '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-shield-x-icon lucide-shield-x"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m14.5 9.5-5 5"/><path d="m9.5 9.5 5 5"/></svg>',
    default:
      '<svg viewBox="0 0 24 24"><path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z" /><path d="M14 2v4a2 2 0 0 0 2 2h4" /></svg>',
  };
  return `<span class="section-icon" aria-hidden="true">${icons[kind] || icons.default}</span>`;
}

function tierBadge(tier) {
  const text =
    {
      green: "低风险维护",
      yellow: "需要确认",
      red: "优先处理",
    }[tier] || "事项";
  return `<span class="tier-badge ${esc(tier)}">${text}</span>`;
}

const SEVERITY_RANK = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

function sortBySeverity(items) {
  return (items || [])
    .slice()
    .sort(
      (a, b) =>
        (SEVERITY_RANK[(b.severity || "info").toLowerCase()] || 0) -
        (SEVERITY_RANK[(a.severity || "info").toLowerCase()] || 0),
    );
}

function fieldBlock(label, value) {
  if (!value) return "";
  return `<div class="field"><div class="label">${esc(label)}</div>${esc(value)}</div>`;
}

function normalizeSecurityLanguage(value) {
  return String(value == null ? "" : value)
    .replace(
      /[（(][^）)]*(?:CVE-\d{4}-\d+|GHSA-[A-Za-z0-9-]+)[^）)]*[）)]/gi,
      "",
    )
    .replace(/\bCVE-\d{4}-\d+\b/gi, "")
    .replace(/\bGHSA-[A-Za-z0-9-]+\b/gi, "")
    .replace(/\bcritical\b/gi, "严重")
    .replace(/\bhigh\b/gi, "高危")
    .replace(/\bmedium\b/gi, "中危")
    .replace(/\blow\b/gi, "低危")
    .replace(/\bSSRF\b/g, "服务端访问控制风险")
    .replace(/\bXSS\b/g, "页面安全风险")
    .replace(/\bDoS\b/g, "服务稳定性风险")
    .replace(/中间件绕过/g, "访问控制绕过")
    .replace(/缓存投毒/g, "缓存内容被污染")
    .replace(
      /(\d+)\s*个\s*严重\s*\+\s*(\d+)\s*个\s*中危/g,
      "$1 个严重和 $2 个中危",
    )
    .replace(
      /(\d+)\s*个\s*高危\s*\+\s*(\d+)\s*个\s*中危/g,
      "$1 个高危和 $2 个中危",
    )
    .replace(/\s+([，。；：])/g, "$1")
    .replace(/[，、]\s*[，、]+/g, "，")
    .replace(/\s{2,}/g, " ")
    .trim();
}

function isNoisySecurityText(value) {
  const text = String(value || "");
  return /CVE-\d{4}-\d+|GHSA-[A-Za-z0-9-]+|\bcritical\b|\bmedium\b|\blow\b|\bSSRF\b|\bXSS\b|\bDoS\b/i.test(
    text,
  );
}

function topVulnerabilityGroup() {
  const groups = new Map();
  (DATA.vulns || []).forEach((item) => {
    const name = item.package || item.name || "";
    if (!name) return;
    if (!groups.has(name)) groups.set(name, []);
    groups.get(name).push(item);
  });
  let bestName = "";
  let bestItems = [];
  groups.forEach((items, name) => {
    const currentScore = items.reduce(
      (sum, item) => sum + (SEVERITY_RANK[item.severity] || 0),
      0,
    );
    const bestScore = bestItems.reduce(
      (sum, item) => sum + (SEVERITY_RANK[item.severity] || 0),
      0,
    );
    if (
      items.length > bestItems.length ||
      (items.length === bestItems.length && currentScore > bestScore)
    ) {
      bestName = name;
      bestItems = items;
    }
  });
  return { name: bestName, items: bestItems };
}

function versionParts(value) {
  const match = String(value || "").match(/\d+(?:\.\d+){0,3}/);
  if (!match) return [];
  return match[0].split(".").map((x) => Number(x) || 0);
}

function compareVersions(a, b) {
  const pa = versionParts(a);
  const pb = versionParts(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const delta = (pa[i] || 0) - (pb[i] || 0);
    if (delta) return delta;
  }
  return 0;
}

function bestFixedVersion(versions, currentVersion) {
  const all = toList(versions).filter(Boolean);
  if (!all.length) return "";
  const currentMajor = versionParts(currentVersion)[0];
  const sameMajor = Number.isFinite(currentMajor)
    ? all.filter((v) => versionParts(v)[0] === currentMajor)
    : [];
  const candidates = sameMajor.length ? sameMajor : all;
  return candidates.slice().sort(compareVersions).pop() || "";
}

function commonFixedVersion(items) {
  const versions = [];
  const currentVersion = items && items[0] && items[0].version;
  (items || []).forEach((item) => {
    toList(
      item.fixed_versions || item.fix_versions || item.patched_versions,
    ).forEach((v) => {
      if (v && !versions.includes(v)) versions.push(v);
    });
  });
  return bestFixedVersion(versions, currentVersion);
}

function readableTldr(raw) {
  if (raw && !isNoisySecurityText(raw) && String(raw).length <= 140) {
    return normalizeSecurityLanguage(raw);
  }
  const count =
    (DATA.vulns || []).length || DATA.project.total_vulnerabilities || 0;
  const group = topVulnerabilityGroup();
  if (count) {
    const target = group.name
      ? `${group.name}${group.items[0] && group.items[0].version ? " " + group.items[0].version : ""}`
      : "少数 npm 依赖";
    const fixed = commonFixedVersion(group.items);
    return `本次扫描发现 ${count} 个已确认依赖漏洞，风险主要集中在 ${target}；建议先升级${fixed ? "到 " + fixed : "主要受影响包"}，再处理传递依赖。`;
  }
  return normalizeSecurityLanguage(
    raw || "本次扫描没有发现明确风险，可以把这份报告作为当前项目安全状态记录。",
  );
}

function readableDetail(raw) {
  if (raw && !isNoisySecurityText(raw) && String(raw).length <= 260) {
    return normalizeSecurityLanguage(raw);
  }
  const packages = DATA.project.total_packages || DATA.package_count || 0;
  const vulns = DATA.vulns || [];
  const names = new Set(vulns.map((x) => x.package || x.name).filter(Boolean));
  const group = topVulnerabilityGroup();
  const parts = [];
  if (packages || vulns.length) {
    parts.push(
      `本次扫描覆盖 ${packages || "多个"} 个依赖包，发现 ${vulns.length || DATA.project.total_vulnerabilities || 0} 个已确认漏洞，涉及 ${names.size || "多个"} 个包。`,
    );
  }
  if (group.name) {
    const fixed = commonFixedVersion(group.items);
    parts.push(
      `风险最集中在 ${group.name}${group.items[0] && group.items[0].version ? " " + group.items[0].version : ""}，建议优先固定升级${fixed ? "到 " + fixed : "到官方修复版本"}。`,
    );
  }
  if (names.size > 1) {
    parts.push(
      "其余多为传递依赖问题，可以通过 overrides、锁文件更新或包管理器升级分批处理。",
    );
  }
  if (/lockfile|node_modules|npm ci/i.test(String(raw || ""))) {
    parts.push(
      "另外需要修正 lockfile 和本地安装版本不一致的问题，避免干净环境装回旧版本。",
    );
  }
  if (
    (DATA.hygiene &&
      !toList(DATA.hygiene.tracked_secrets).length &&
      !toList(DATA.hygiene.sensitive_tracked).length) ||
    /仓库卫生.*通过/.test(String(raw || ""))
  ) {
    parts.push("仓库卫生检查没有发现密钥或敏感文件误提交。");
  }
  return normalizeSecurityLanguage(parts.join(""));
}

function readableIssueKind(item) {
  const text = [
    item.type,
    item.summary,
    item.description,
    item.match_summary,
    item.title,
    item.name,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  if (
    /middleware|auth|authentication|authorization|bypass|privilege|访问控制|权限|认证/.test(
      text,
    )
  ) {
    return "可能影响登录、权限或访问控制";
  }
  if (/ssrf|server-side request/.test(text)) {
    return "可能让服务访问不该访问的地址";
  }
  if (/denial|dos|redos|regular expression/.test(text)) {
    return "可能影响服务稳定性";
  }
  if (/xss|cross-site scripting/.test(text)) {
    return "可能影响页面安全";
  }
  if (/cache|缓存/.test(text)) {
    return "可能影响缓存内容可信度";
  }
  if (/path|directory|file|文件/.test(text)) {
    return "可能影响文件访问边界";
  }
  return "可能影响服务安全或稳定性";
}

function impactText(it, tier) {
  if (it.impact || it.business_impact || it.pm_impact) {
    return normalizeSecurityLanguage(
      it.impact || it.business_impact || it.pm_impact,
    );
  }
  const text = [it.type, it.name, it.summary, it.description, it.risk, it.path]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  if (/secret|token|password|credential|key|\.env|凭证|密钥|密码/.test(text)) {
    return "如果该配置进入生产或被外部人员拿到，可能造成未授权访问、数据泄露，或需要紧急轮换密钥。";
  }
  if (/mcp|api/.test(text)) {
    return "如果访问控制没有配置好，外部用户可能调用本不该开放的接口，影响系统数据和服务稳定性。";
  }
  if (/depend|package|vuln|cve|ghsa|依赖|漏洞/.test(text)) {
    return tier === "green"
      ? "当前更像维护风险，不代表已经被攻击；但长期不处理会增加未来升级成本和供应链暴露面。"
      : "如果该依赖被攻击者利用，可能影响用户数据、服务可用性或业务连续性。";
  }
  if (/gitignore|pem|p12|pfx|证书|私钥/.test(text)) {
    return "现在未必已经出问题，但缺少保护规则会提高未来误提交敏感文件的概率。";
  }
  return tier === "red"
    ? "该问题可能直接影响用户数据、线上稳定性或安全合规，应优先安排处理。"
    : "该问题需要结合业务和部署环境确认，避免把潜在风险带到生产环境。";
}

function actionText(it, tier) {
  if (
    it.action ||
    it.recommendation ||
    it.suggested_action ||
    it.suggested_fix ||
    it.disposal ||
    it.indirect_release
  ) {
    return normalizeSecurityLanguage(
      it.action ||
        it.recommendation ||
        it.suggested_action ||
        it.suggested_fix ||
        it.disposal ||
        it.indirect_release,
    );
  }
  if (tier === "green") {
    return "在不影响当前发布节奏的窗口内处理，执行后跑测试或构建验证。";
  }
  if (tier === "red") {
    return "先暂停相关发布或变更，确认影响范围，再按最小风险路径修复；涉及凭证时先轮换，再清理历史记录。";
  }
  return "请产品、研发或运维确认真实使用场景，再决定是否修复、延期或记录为可接受风险。";
}

function problemText(it, tier) {
  if (it.problem || it.why_manual || it.why_keep || it.risk_note) {
    return normalizeSecurityLanguage(
      it.problem || it.why_manual || it.why_keep || it.risk_note,
    );
  }
  if (tier === "green") {
    return "这类事项已有明确处理路径，通常不需要业务判断，但仍建议在代码已保存并可回滚的前提下执行。";
  }
  if (tier === "red") {
    return "这类事项可能已经影响线上安全或用户信任，不能用普通批量修复方式处理。";
  }
  return "扫描工具只能发现迹象，不能知道它在真实业务、部署环境或团队流程中的含义。";
}

function normalizeLinks(value) {
  if (!value) return [];
  const arr = Array.isArray(value) ? value : [value];
  return arr
    .map((x) => {
      if (!x) return null;
      if (typeof x === "string") {
        return { label: x, url: x };
      }
      const url = x.url || x.href || x.link;
      const label = x.label || x.title || x.name || url;
      return url ? { label, url } : null;
    })
    .filter(Boolean);
}

function inferredCaseLinks(it) {
  const text = [it.type, it.name, it.summary, it.description, it.risk, it.path]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  if (/secret|token|password|credential|key|\.env|凭证|密钥|密码/.test(text)) {
    return [
      {
        label: "案例：GitHub 防止密钥泄露",
        url: "https://github.blog/news-insights/product-news/push-protection-is-generally-available-and-free-for-all-public-repositories/",
      },
      {
        label: "处置参考：泄露密钥修复",
        url: "https://docs.github.com/code-security/secret-scanning/working-with-secret-scanning-and-push-protection/remediating-a-leaked-secret",
      },
    ];
  }
  if (/depend|package|vuln|cve|ghsa|依赖|漏洞/.test(text)) {
    return [
      {
        label: "案例：Log4Shell 供应链漏洞",
        url: "https://www.cisa.gov/news-events/news/apache-log4j-vulnerability-guidance",
      },
    ];
  }
  if (/git|pem|p12|pfx|证书|私钥/.test(text)) {
    return [
      {
        label: "参考：移除仓库敏感数据",
        url: "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository",
      },
    ];
  }
  return [];
}

function caseLinks(it) {
  const links = [
    ...normalizeLinks(
      it.case_links || it.caseLinks || it.references || it.links,
    ),
    ...inferredCaseLinks(it),
  ];
  const seen = new Set();
  const unique = links.filter((link) => {
    if (seen.has(link.url)) return false;
    seen.add(link.url);
    return true;
  });
  const linkHtml = unique
    .slice(0, 2)
    .map((link) => {
      const href = safeHref(link.url);
      return href
        ? `<a class="case-link" href="${esc(href)}" target="_blank" rel="noopener">${esc(link.label)}</a>`
        : "";
    })
    .filter(Boolean)
    .join("");
  return linkHtml
    ? `<div class="field"><div class="label">现实案例 / 参考资料</div><div class="case-links">${linkHtml}</div></div>`
    : "";
}

function issueDescription(r) {
  const raw = String(
    r.summary || r.description || r.match_summary || "",
  ).trim();
  if (/[\u4e00-\u9fff]/.test(raw)) return raw;

  const pkg = r.package || r.name || "该依赖";
  const fixed =
    Array.isArray(r.fixed_versions) && r.fixed_versions.length
      ? `建议升级到 ${r.fixed_versions.join("、")} 或更高版本。`
      : "建议查看公告确认修复版本，并优先升级。";
  return `${pkg} 当前版本命中公开漏洞记录。${fixed}`;
}

function severityImpactText(sev) {
  const s = String(sev || "info").toLowerCase();
  if (s === "critical" || s === "high") {
    return "可能影响用户数据、服务稳定性或发布安全，建议优先排期处理。";
  }
  if (s === "medium") {
    return "短期不一定马上出问题，但继续拖延会增加线上风险和后续修复成本。";
  }
  return "更像维护风险，建议跟随近期版本升级一起处理。";
}

function fixedVersionText(r) {
  return Array.isArray(r.fixed_versions) && r.fixed_versions.length
    ? `升级到 ${r.fixed_versions.join("、")} 或更高版本，并完成兼容性验证。`
    : "先确认官方修复版本，再安排升级和兼容性验证。";
}

function shortFixedVersionText(r) {
  const version = bestFixedVersion(
    r.fixed_versions || r.fix_versions || r.patched_versions,
    r.version,
  );
  return version
    ? `建议升级到 ${version} 或更高版本。`
    : "建议研发确认官方修复版本后再安排升级。";
}

function fixedVersionHtml(r) {
  const versions = toList(
    r.fixed_versions || r.fix_versions || r.patched_versions,
  );
  if (!versions.length) return '<span class="fixed-empty">待确认</span>';
  return `<div class="fixed-list">${versions
    .map((version) => `<span class="fixed-chip">${esc(version)}</span>`)
    .join("")}</div>`;
}

function miniFields(fields) {
  return `<div class="mini-fields">${fields
    .filter((x) => x && x.value)
    .map(
      (x) =>
        `<div class="mini-field"><span class="mini-label">${esc(x.label)}</span><span class="mini-value">${esc(x.value)}</span></div>`,
    )
    .join("")}</div>`;
}

function hygieneNote(label, value) {
  return `<div class="hygiene-note"><span>${esc(label)}</span><p>${esc(value)}</p></div>`;
}

function cleanAdvisorySummary(value) {
  return String(value || "")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/^[^:：]{1,80}[:：]\s*/, "");
}

function advisoryIssuePhrase(summary) {
  const text = cleanAdvisorySummary(summary);
  const lower = text.toLowerCase();
  if (!text) return "";
  if (lower.includes("large numeric range") && lower.includes("max")) {
    return "大范围数字展开可能绕过 max 限制，带来拒绝服务风险";
  }
  if (lower.includes("host confusion") && lower.includes("percent-encoded")) {
    return "对百分号编码的 authority 分隔符处理不当，可能造成主机解析混淆";
  }
  if (lower.includes("path traversal") && lower.includes("percent-encoded")) {
    return "对百分号编码的点号路径处理不当，可能造成路径穿越";
  }
  if (lower.includes("server-side request forgery")) {
    return lower.includes("websocket")
      ? "WebSocket upgrade 场景存在服务端请求伪造风险"
      : "存在服务端请求伪造风险";
  }
  if (lower.includes("middleware") && lower.includes("proxy bypass")) {
    if (lower.includes("pages router") && lower.includes("i18n")) {
      return "Pages Router 使用 i18n 时存在中间件/代理绕过风险";
    }
    if (lower.includes("segment-prefetch")) {
      return lower.includes("incomplete fix") || lower.includes("follow-up")
        ? "segment-prefetch 路由相关绕过修复不完整，仍可能绕过中间件/代理"
        : "App Router 的 segment-prefetch 路由可能绕过中间件/代理";
    }
    if (lower.includes("dynamic route")) {
      return "动态路由参数注入场景可能绕过中间件/代理";
    }
    return "存在中间件/代理绕过风险";
  }
  if (lower.includes("connection exhaustion")) {
    return "使用 Cache Components 时可能因连接耗尽造成拒绝服务";
  }
  if (
    lower.includes("image optimization api") &&
    lower.includes("denial of service")
  ) {
    return "Image Optimization API 存在拒绝服务风险";
  }
  if (lower.includes("denial of service") || /\bdos\b/.test(lower)) {
    return "存在拒绝服务风险";
  }
  if (lower.includes("cache")) {
    return "存在缓存可信度风险";
  }
  return `公告摘要：${text}`;
}

function advisorySummaryText(r) {
  const summary =
    r.advisory_summary ||
    r.advisorySummary ||
    r.advisory_title ||
    r.title ||
    (!/命中已确认|已有确认安全风险/.test(String(r.summary || ""))
      ? r.summary
      : "");
  return advisoryIssuePhrase(summary) || readableIssueKind(r);
}

function vulnerabilityExplanation(r) {
  const pkg = r.package || r.name || "该依赖";
  const version = r.version ? ` ${r.version}` : "";
  return esc(
    `${pkg}${version} ${advisorySummaryText(r)}；${shortFixedVersionText(r)}`,
  );
}

function outdatedExplanation(it) {
  const name = it.package || it.name || "该依赖";
  const current = String(it.current || it.version || "").trim();
  const target =
    String(it.latest || it.latestVersion || "").trim() ||
    String(it.wanted || it.update || "").trim() ||
    outdatedDisplayTarget(it);
  if (current && target) {
    return `${name} 当前版本为 ${current}，建议升级到最新版本 ${target}。`;
  }
  if (target) {
    return `${name} 建议升级到最新版本 ${target}。`;
  }
  return `${name} 需要复核版本状态`;
}

function cleanVersion(value) {
  return String(value || "")
    .trim()
    .replace(/^v/i, "");
}

function outdatedUpdateTarget(it) {
  const wanted = String(it.wanted || it.update || "").trim();
  const latest = String(it.latest || it.latestVersion || "").trim();
  return wanted || latest || "";
}

function outdatedDisplayTarget(it) {
  const wanted = String(it.wanted || it.update || "").trim();
  const latest = String(it.latest || it.latestVersion || "").trim();
  if (wanted && latest && wanted !== latest) {
    return `${wanted} / ${latest}`;
  }
  return wanted || latest || "";
}

function isRenderableOutdated(it) {
  const current = cleanVersion(it.current || it.version);
  const target = cleanVersion(outdatedUpdateTarget(it));
  return Boolean(target && current !== target);
}

function securityIds(r) {
  const values = [];
  const push = (v) => {
    if (Array.isArray(v)) {
      v.forEach(push);
      return;
    }
    if (v == null) return;
    String(v)
      .split(/[,，\s]+/)
      .map((x) => x.trim())
      .filter(Boolean)
      .forEach((id) => {
        if (!/^GHSA-/i.test(id)) return;
        if (!values.some((x) => x.toLowerCase() === id.toLowerCase())) {
          values.push(id);
        }
      });
  };

  push(r.advisory_id);
  push(r.advisory_ids);
  push(r.aliases);
  push(r.advisory_aliases);
  push(r.cve_id);
  push(r.cve_ids);

  return values;
}

function securityIdUrl(id) {
  if (/^CVE-\d{4}-\d+/i.test(id)) {
    return `https://www.cve.org/CVERecord?id=${encodeURIComponent(id.toUpperCase())}`;
  }
  return `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
}

// ---- Overview ----
function renderOverview(proj, rs) {
  document.getElementById("meta").textContent = DATA.generated_at
    ? `生成于 ${DATA.generated_at}${DATA.total_seconds ? "　·　总耗时 " + DATA.total_seconds + "s" : DATA.scan_seconds ? "　·　扫描耗时 " + DATA.scan_seconds + "s" : ""}`
    : "";

  // Top severity: highest non-zero level from risk_summary
  const severityOrder = ["critical", "high", "medium", "low", "info"];
  let topSeverity = "";
  for (const s of severityOrder) {
    if (rs && rs[s] && rs[s] > 0) {
      topSeverity = s;
      break;
    }
  }

  const total =
    (rs && rs.critical + rs.high + rs.medium + rs.low + rs.info) || 1;
  const crit = (rs && rs.critical) || 0;
  const high = (rs && rs.high) || 0;
  const med = (rs && rs.medium) || 0;
  const low = (rs && rs.low) || 0;
  const info = (rs && rs.info) || 0;

  const seg = (v, cls) =>
    v > 0
      ? `<i class="seg-${cls}" style="width:${((v / total) * 100).toFixed(2)}%" title="${cls}: ${v}"></i>`
      : "";
  const bar =
    total > 1
      ? seg(crit, "critical") +
        seg(high, "high") +
        seg(med, "medium") +
        seg(low, "low") +
        seg(info, "info")
      : '<i class="seg-low" style="width:100%"></i>';

  const hasAny = crit || high || med || low || info;
  const pills = rs
    ? `<div class="pills">
  ${!hasAny ? `<span class="pill"><span class="dot" style="background:var(--green)"></span>未发现风险 <b>✓</b></span>` : ""}
  ${crit ? `<span class="pill"><span class="dot" style="background:var(--critical)"></span>严重 <b>${crit}</b></span>` : ""}
  ${high ? `<span class="pill"><span class="dot" style="background:var(--high)"></span>高危 <b>${high}</b></span>` : ""}
  ${med ? `<span class="pill"><span class="dot" style="background:var(--medium)"></span>中危 <b>${med}</b></span>` : ""}
  ${low ? `<span class="pill"><span class="dot" style="background:var(--low)"></span>低危 <b>${low}</b></span>` : ""}
  ${info ? `<span class="pill"><span class="dot" style="background:var(--info)"></span>信息 <b>${info}</b></span>` : ""}
</div>`
    : "";

  return `<div class="overview">
  <div class="stats">
    <div class="stat"><div class="k">项目</div><div class="v">${esc(proj.name)}</div></div>
    <div class="stat"><div class="k">生态</div><div class="v">${(proj.ecosystems || []).map(esc).join(", ") || "未检测到"}</div></div>
    <div class="stat"><div class="k">依赖数</div><div class="v">${proj.total_packages || 0}</div></div>
    <div class="stat"><div class="k">风险等级</div><div class="v">${topSeverity ? sevBadge(topSeverity) : '<span style="color:var(--sub)">无</span>'}</div></div>
  </div>
  <div class="bar-label">风险等级分布</div>
  <div class="bar">${bar}</div>
  ${pills}
  <div class="sysgrid">
    <div><span>路径　</span><b>${esc(proj.path)}</b></div>
    <div><span>分支　</span><b>${esc(proj.git_branch || "-")}</b></div>
    <div><span>来源　</span><b>${esc((proj.lockfiles || []).join(", ") || "-")}</b></div>
  </div>
</div>`;
}

// ---- Dense report tables ----
const VULN_SHOW = 7;
const OUTDATED_SHOW = 7;

function packageNameFor(row) {
  return String((row && (row.package || row.name)) || "");
}

function packageColumnWidthStyle(rows) {
  const maxChars = (rows || []).reduce((max, row) => {
    const length = Array.from(packageNameFor(row)).length;
    return Math.max(max, length);
  }, 4);
  const px = Math.min(260, Math.max(132, maxChars * 8 + 30));
  return `--package-col:${px}px;`;
}

function renderTableColgroup(columns) {
  return `<colgroup>${columns
    .map((column) => `<col class="col-${esc(column)}">`)
    .join("")}</colgroup>`;
}

// ---- Vulnerability table (all items) ----

function renderVulnTable(rows) {
  if (!rows || !rows.length) {
    return section(
      "命中漏洞",
      0,
      `<div class="empty">未命中已确认的依赖漏洞。</div>`,
      "",
      "search",
    );
  }
  const sortedRows = sortBySeverity(rows);
  const needToggle = sortedRows.length > VULN_SHOW;
  const body = sortedRows
    .map((r, idx) => {
      const packageName = packageNameFor(r);
      const displayIds = securityIds(r);
      const advHtml =
        displayIds.length > 0
          ? `<div class="adv-list">${displayIds
              .map((id) => {
                const url = securityIdUrl(id);
                return `<a href="${esc(url)}" target="_blank" rel="noopener">${esc(id)}</a>`;
              })
              .join("")}</div>`
          : '<span style="color:var(--sub)">-</span>';
      const cls = needToggle && idx >= VULN_SHOW ? ' class="vuln-extra"' : "";
      const fixedHtml = fixedVersionHtml(r);
      return `<tr${cls}>
  <td class="sev">${sevBadge(r.severity)}</td>
  <td class="package-cell"><b title="${esc(packageName)}">${esc(packageName)}</b></td>
  <td class="ver">${esc(r.version || "")}</td>
  <td class="ver fixed-cell">${fixedHtml}</td>
  <td class="advisory">${advHtml}</td>
  <td class="summary-cell">${vulnerabilityExplanation(r)}</td>
</tr>`;
    })
    .join("");
  const toggle = needToggle
    ? `<tr class="vuln-toggle"><td colspan="6"><button class="fix-btn open" onclick="toggleVulns(this)">显示更多（还有 ${sortedRows.length - VULN_SHOW} 项）</button></td></tr>`
    : "";
  return section(
    "命中漏洞",
    sortedRows.length,
    `<div class="table-scroll"><table class="stable-table vuln-table" style="${packageColumnWidthStyle(sortedRows)}">
  ${renderTableColgroup(["severity", "package", "version", "fixed", "advisory", "summary"])}
  <thead><tr><th>严重程度</th><th>依赖名称</th><th>当前版本</th><th>修复版本</th><th>GHSA</th><th>说明</th></tr></thead>
  <tbody>${body}${toggle}</tbody></table></div>`,
    "",
    "search",
  );
}

function toggleVulns(btn) {
  const table = btn.closest("table");
  table.classList.toggle("vuln-expanded");
  const expanded = table.classList.contains("vuln-expanded");
  const extras = table.querySelectorAll(".vuln-extra");
  btn.setAttribute("aria-expanded", expanded ? "true" : "false");
  btn.textContent = expanded ? "收起" : `显示更多（还有 ${extras.length} 项）`;
}

// ---- Report summary ----
function renderReportSummary(sm) {
  if (!sm || (!sm.priority && !sm.tldr && !sm.detail)) return "";
  const tldr = sm.tldr
    ? `<div class="summary-tldr"><span>TL;DR</span><p>${esc(readableTldr(sm.tldr))}</p></div>`
    : "";
  const detail = sm.detail
    ? `<p class="lead">${esc(readableDetail(sm.detail))}</p>`
    : "";
  const boundary = `<div class="summary-boundary warning"><p>${esc(CAPABILITY_BOUNDARY)}</p></div>`;
  const body = sm.priority
    ? Array.isArray(sm.priority)
      ? sumList(sm.priority)
      : `<p>${esc(sm.priority)}</p>`
    : "";
  return section(
    "报告总结",
    null,
    `<div class="summary">${tldr}${detail}${boundary}${body}</div>`,
    "",
    "advice",
  );
}

// ---- Repository hygiene ----
function renderHygiene(h) {
  h = h || {};
  if (h.skipped || (DATA.scan_config && DATA.scan_config.skip_hygiene)) {
    return section(
      "仓库卫生",
      null,
      `<div class="summary hygiene-summary">${miniFields([
        { label: "事实", value: "本次跳过了仓库卫生检查。" },
        {
          label: "为什么要关注",
          value:
            "仓库卫生主要看密钥、敏感文件和 .gitignore，跳过后这部分不能作为最终结论。",
        },
        {
          label: "建议动作",
          value: "需要完整结论时，重新扫描并不要使用 --skip-hygiene。",
        },
      ])}</div>`,
      "",
      "hygiene",
    );
  }

  const secrets = toList(h.tracked_secrets);
  const sensitive = toList(h.sensitive_tracked);
  const missing = toList(h.gitignore_missing);
  const count = secrets.length + sensitive.length + missing.length;
  const rows = [];
  if (secrets.length) {
    rows.push({
      label: "硬编码密钥",
      value: `发现 ${secrets.length} 处疑似明文凭证，需要研发确认是否是真实可用的密钥。`,
    });
  }
  if (sensitive.length) {
    rows.push({
      label: "敏感文件",
      value: `发现 ${sensitive.length} 个敏感文件已经被 git 跟踪，需要确认是否应该留在仓库。`,
    });
  }
  if (missing.length) {
    rows.push({
      label: ".gitignore",
      value: `.gitignore 建议补充 ${missing.slice(0, 8).join("、")}${missing.length > 8 ? " 等规则" : ""}，避免后续误提交敏感文件。`,
    });
  }
  if (!rows.length) {
    return section(
      "仓库卫生",
      count,
      `<div class="summary hygiene-summary">${hygieneNote(
        "结论",
        "没有发现硬编码密钥、被 git 跟踪的敏感文件或缺失的敏感文件忽略规则。",
      )}</div>`,
      "",
      "hygiene",
    );
  }

  const examples = [
    ...secrets
      .slice(0, 3)
      .map(
        (x) =>
          `${x.file || "-"}${x.line ? ":" + x.line : ""}（${x.type || "secret"}）`,
      ),
    ...sensitive
      .slice(0, 3)
      .map((x) => `${x.file || "-"}（${x.type || "sensitive"}）`),
  ];
  const extra = examples.length
    ? `<div class="field"><div class="label">需要研发确认的位置</div>${esc(examples.join("；"))}</div>`
    : "";

  return section(
    "仓库卫生",
    count,
    `<div class="summary hygiene-summary">${miniFields(rows)}${extra}</div>`,
    "",
    "hygiene",
  );
}

// ---- Outdated dependencies ----
function renderOutdated(items) {
  items = toList(items);
  if (DATA.scan_config && DATA.scan_config.skip_outdated) {
    return section(
      "过期依赖",
      null,
      `<div class="summary outdated-empty">${miniFields([
        { label: "事实", value: "本次为了提速跳过了过期依赖检查。" },
        {
          label: "为什么要关注",
          value: "过期不等于漏洞，但版本长期落后会让未来升级和修复变得更难。",
        },
        {
          label: "建议动作",
          value: "需要完整维护视图时，重新扫描并不要使用 --skip-outdated。",
        },
      ])}</div>`,
      "",
      "long",
    );
  }
  if (!items.length) {
    return section(
      "过期依赖",
      0,
      `<div class="summary outdated-empty">${miniFields([
        {
          label: "结论",
          value: "没有检测到明确的过期依赖，或当前包管理器没有返回可用结果。",
        },
        {
          label: "提醒",
          value:
            "过期依赖只是维护信号，不代表一定存在漏洞；真正的安全优先级仍以命中漏洞为准。",
        },
      ])}</div>`,
      "",
      "long",
    );
  }
  const needToggle = items.length > OUTDATED_SHOW;
  const rows = items
    .map((it, idx) => {
      const packageName = packageNameFor(it);
      const current = String(it.current || it.version || "").trim();
      const cls =
        needToggle && idx >= OUTDATED_SHOW ? ' class="outdated-extra"' : "";
      return `<tr${cls}>
  <td class="package-cell"><b title="${esc(packageName)}">${esc(packageName)}</b></td>
  <td class="ver">${esc(current || "-")}</td>
  <td class="ver">${esc(outdatedDisplayTarget(it) || "-")}</td>
  <td>${esc(it.ecosystem || "-")}</td>
  <td class="summary-cell">${esc(outdatedExplanation(it))}</td>
</tr>`;
    })
    .join("");
  const toggle = needToggle
    ? `<tr class="outdated-toggle"><td colspan="5"><button class="fix-btn open" onclick="toggleOutdated(this)">显示更多（还有 ${items.length - OUTDATED_SHOW} 项）</button></td></tr>`
    : "";
  return section(
    "过期依赖",
    items.length,
    `<div class="table-scroll"><table class="stable-table outdated-table" style="${packageColumnWidthStyle(items)}">
  ${renderTableColgroup(["package", "current", "latest", "ecosystem", "summary"])}
  <thead><tr><th>依赖名称</th><th>当前版本</th><th>最近版本</th><th>生态</th><th>建议</th></tr></thead>
  <tbody>${rows}${toggle}</tbody></table></div>`,
    "",
    "long",
  );
}

function toggleOutdated(btn) {
  const table = btn.closest("table");
  table.classList.toggle("outdated-expanded");
  const expanded = table.classList.contains("outdated-expanded");
  const extras = table.querySelectorAll(".outdated-extra");
  btn.setAttribute("aria-expanded", expanded ? "true" : "false");
  btn.textContent = expanded ? "收起" : `显示更多（还有 ${extras.length} 项）`;
}

// ---- Yellow: manual review ----
function renderYellow(items) {
  if (!items || !items.length) return "";
  const cards = sortBySeverity(items)
    .map((it) => {
      let inner = "";
      inner += fieldBlock("为什么要关注", problemText(it, "yellow"));
      inner += fieldBlock("可能影响", impactText(it, "yellow"));
      inner += fieldBlock("建议动作", actionText(it, "yellow"));
      return card("yellow", it.name, it.severity, it.path || "", inner);
    })
    .join("");
  return section("人工复核", items.length, cards, "", "review");
}

// ---- Red: high-risk ----
function renderRed(items) {
  if (!items || !items.length) return "";
  const cards = sortBySeverity(items)
    .map((it) => {
      let inner = "";
      inner += fieldBlock("为什么要关注", problemText(it, "red"));
      inner += fieldBlock("可能影响", impactText(it, "red"));
      inner += fieldBlock("建议动作", actionText(it, "red"));
      return card("red", it.name, it.severity, it.path || "", inner);
    })
    .join("");
  return section("优先处理的高风险项", items.length, cards, "", "risk");
}

// ---- Errors ----
function renderErrors() {
  if (!DATA.errors || !DATA.errors.length) return "";
  return `<div class="denied"><b>扫描过程中遇到以下问题：</b><br>${DATA.errors.map((e) => esc("[" + e.step + "] " + e.message)).join("<br>")}</div>`;
}

// ---- Shared helpers ----
function card(tier, name, sev, path, inner) {
  const sevHtml = sev ? `<span class="item-sev">${sevBadge(sev)}</span>` : "";
  const route = path
    ? `<span class="item-route" title="${esc(path)}">${esc(path)}</span>`
    : "";
  return `<div class="item ${tier}">
  <div class="item-head" onclick="this.parentNode.classList.toggle('open')">
    <div class="item-main">
      <div class="item-kicker">${tierBadge(tier)}${sevHtml}${route}</div>
      <div class="item-name">${esc(normalizeSecurityLanguage(name))}</div>
    </div>
    <span class="item-badge"></span>
    <span class="chev">▶</span>
  </div>
  <div class="item-body">
    ${inner}
  </div></div>`;
}

function section(title, count, inner, actions, kind) {
  const countHtml =
    count == null ? "" : `<span class="count">${Number(count) || 0} 项</span>`;
  return `<div class="sec"><h2>${sectionIcon(kind)}<span class="section-title">${esc(title)}</span>${countHtml}${actions || ""}</h2>${inner}</div>`;
}

const sumList = (a) =>
  a && a.length
    ? `<div class="summary-list">${a
        .map((x, i) => {
          const text = normalizeSecurityLanguage(
            String(x).replace(/^\s*\d+[.、)]\s*/, ""),
          );
          return `<div class="summary-point"><span class="summary-index">${i + 1}</span><span>${esc(text)}</span></div>`;
        })
        .join("")}</div>`
    : "";

// ---- Mount ----
const app = document.getElementById("app");
app.innerHTML =
  renderOverview(DATA.project || {}, DATA.risk_summary) +
  renderReportSummary(DATA.summary) +
  renderHygiene(DATA.hygiene) +
  renderVulnTable(DATA.vulns) +
  renderOutdated(DATA.outdated) +
  renderRed(DATA.red) +
  renderYellow(DATA.yellow) +
  renderErrors();

// Copy handlers (delegated)
document.addEventListener("click", (e) => {
  const b = e.target.closest(".copy");
  if (!b) return;
  e.stopPropagation();
  const text = decodeURIComponent(escape(atob(b.dataset.cmd)));
  navigator.clipboard.writeText(text).then(() => {
    b.textContent = "已复制";
    b.classList.add("done");
    setTimeout(() => {
      b.textContent = "复制";
      b.classList.remove("done");
    }, 1500);
  });
});
