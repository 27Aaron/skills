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
  "安全往往不是最显眼的需求，却是产品长期稳定运行的底线。此 Skill 会帮助你发现依赖漏洞、过期依赖和仓库暴露风险，帮助团队更早暴露容易被忽视的供应链问题。但它不能替代代码审计、渗透测试或部署安全评估；业务逻辑、权限控制、SQL 注入、XSS 等代码层风险仍需单独复核。";
const HYGIENE_ONLY_NOTICE =
  "当前项目未发现支持的依赖文件，暂无法执行依赖漏洞扫描；本次仅做仓库安检，检查硬编码密钥、敏感文件跟踪、.gitignore、GitHub Actions、依赖配置与维护和 IaC/容器配置风险。";

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
  if (d.scan_config.scan_mode === "hygiene_only") {
    if (!d.summary.priority.includes(HYGIENE_ONLY_NOTICE)) {
      d.summary.priority = [HYGIENE_ONLY_NOTICE, ...d.summary.priority];
    }
    if (!d.summary.tldr || !d.project.total_packages) {
      d.summary.tldr =
        "本次没有发现补天支持的依赖文件，因此未执行依赖漏洞扫描；报告结论仅覆盖仓库安检范围。";
    }
    if (!d.summary.detail || !d.project.total_packages) {
      d.summary.detail = HYGIENE_ONLY_NOTICE;
    }
  }
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
        "发现多项已确认依赖风险项，可能影响发布判断；建议先处理紧急和高风险项，再评估其余。";
    } else if (riskTotal) {
      d.summary.tldr = "发现一些中风险或低风险项，建议按影响范围分批处理。";
    } else if (d.vulns && d.vulns.length) {
      d.summary.tldr =
        "命中已确认风险项，但严重度数据不足，需要结合公告复核影响范围。";
    } else if (d.errors && d.errors.length) {
      d.summary.tldr = "暂未确认风险，但有部分检查失败，结论需要复核。";
    } else {
      d.summary.tldr =
        "本次扫描未发现明确风险。这份报告可以作为当前项目安全状态的基线记录。";
    }
  }
  if (!d.summary.detail) {
    const confirmed = d.vulns.length;
    const hygieneIssues =
      (d.hygiene.tracked_secrets || []).length +
      (d.hygiene.sensitive_tracked || []).length +
      (d.hygiene.gitignore_missing || []).length;
    const projectName = d.project && d.project.name;
    const pkgCount = d.project.total_packages || d.package_count || 0;
    const detailParts = [];
    const covered = projectName
      ? `${projectName} 项目的 ${pkgCount || "多个"} 个依赖包`
      : `${pkgCount || "多个"} 个依赖包`;
    detailParts.push(
      `本次扫描覆盖${covered}，识别出 ${confirmed} 个已确认风险项。`,
    );
    const outdatedText = outdatedDetailText(d.outdated);
    if (outdatedText) detailParts.push(outdatedText);
    const nestedText = nestedLockedSummaryText(d.vulns);
    if (nestedText) detailParts.push(nestedText);
    if (hygieneIssues > 0) {
      detailParts.push(`仓库安检待关注项 ${hygieneIssues} 个。`);
    } else {
      detailParts.push("仓库安检通过。");
    }
    d.summary.detail = detailParts.join("");
  }
  if (!d.summary.priority || !d.summary.priority.length) {
    const priority = [];
    const criticalHigh =
      (d.risk_summary.critical || 0) + (d.risk_summary.high || 0);
    if (criticalHigh) {
      priority.push(
        `优先安排 ${criticalHigh} 个紧急/高风险项，先升级有修复版本的依赖，再跑测试确认没有影响功能。`,
      );
    } else if (d.vulns && d.vulns.length) {
      priority.push(
        `处理 ${d.vulns.length} 个已确认依赖风险项，按影响程度从高到低分批升级。`,
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

function visibleSeverity(sev) {
  const value = String(sev || "").toLowerCase();
  return ["critical", "high", "medium", "low", "info"].includes(value)
    ? value
    : "info";
}

function sevBadge(sev) {
  const visible = visibleSeverity(sev);
  const cls =
    {
      critical: "sev-critical",
      high: "sev-high",
      medium: "sev-medium",
      low: "sev-low",
      info: "sev-info",
    }[visible] || "sev-info";
  const text =
    {
      critical: "紧急",
      high: "高风险",
      medium: "中风险",
      low: "低风险",
      info: "待确认",
    }[visible] || "待确认";
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

function numberOrZero(value) {
  if (typeof value === "boolean" || value === null || value === undefined)
    return 0;
  const n = parseFloat(value);
  return Number.isFinite(n) ? n : 0;
}

function riskSortSignals(item) {
  const a = aggregateEnrichments(item || {});
  return {
    epss: numberOrZero(a.maxEpssPercentile),
    cvss: numberOrZero(a.bestCvssScore),
  };
}

function sortBySeverity(items) {
  return (items || [])
    .slice()
    .sort((a, b) => {
      const severityDelta =
        (SEVERITY_RANK[(b.severity || "info").toLowerCase()] || 0) -
        (SEVERITY_RANK[(a.severity || "info").toLowerCase()] || 0);
      if (severityDelta) return severityDelta;

      const aSignals = riskSortSignals(a);
      const bSignals = riskSortSignals(b);
      const epssDelta = bSignals.epss - aSignals.epss;
      if (epssDelta) return epssDelta;
      const cvssDelta = bSignals.cvss - aSignals.cvss;
      if (cvssDelta) return cvssDelta;

      const nameDelta = packageNameFor(a).localeCompare(packageNameFor(b));
      if (nameDelta) return nameDelta;
      return String(a.version || "").localeCompare(String(b.version || ""));
    });
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
    .replace(/\bcritical\b/gi, "紧急")
    .replace(/\bhigh\b/gi, "高风险")
    .replace(/\bmedium\b/gi, "中风险")
    .replace(/\blow\b/gi, "低风险")
    .replace(/严重\/高危/g, "紧急/高风险")
    .replace(/严重和高危/g, "紧急和高风险")
    .replace(/严重漏洞/g, "紧急漏洞")
    .replace(/严重项/g, "紧急项")
    .replace(/高危/g, "高风险")
    .replace(/中危/g, "中风险")
    .replace(/低危/g, "低风险")
    .replace(/\bSSRF\b/g, "服务端访问控制风险")
    .replace(/\bXSS\b/g, "页面安全风险")
    .replace(/\bDoS\b/g, "服务稳定性风险")
    .replace(/中间件绕过/g, "访问控制绕过")
    .replace(/缓存投毒/g, "缓存内容被污染")
    .replace(
      /(\d+)\s*个\s*紧急\s*\+\s*(\d+)\s*个\s*中风险/g,
      "$1 个紧急和 $2 个中风险",
    )
    .replace(
      /(\d+)\s*个\s*高风险\s*\+\s*(\d+)\s*个\s*中风险/g,
      "$1 个高风险和 $2 个中风险",
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
    return `本次扫描发现 ${count} 个已确认依赖风险项，风险主要集中在 ${target}；建议先升级${fixed ? "到 " + fixed : "主要受影响包"}，再处理传递依赖。`;
  }
  return normalizeSecurityLanguage(
    raw || "本次扫描没有发现明确风险，可以把这份报告作为当前项目安全状态记录。",
  );
}

function readableDetail(raw) {
  // Clean up agent-generated detail: remove zero-value security-check mentions, normalize outdated phrasing
  const cleaned = String(raw || "")
    .replace(
      /仓库(?:卫生|安检)[，、]?\s*发现[^。]*?0\s*[处个][^。]*?0\s*[个条][^。]*?0\s*条[^。]*。?/g,
      "仓库安检通过。",
    )
    .replace(
      /仓库(?:卫生|安检)方面，发现[^。]*?0\s*处[^。]*?0\s*个[^。]*?0\s*条[^。]*。?/g,
      "仓库安检通过。",
    )
    .replace(/仓库(?:卫生|安检)待关注项\s*0\s*个[。，]?/g, "")
    .replace(/疑似硬编码凭证\s*0\s*处[、，]?\s*/g, "")
    .replace(/被\s*git\s*跟踪的敏感文件\s*0\s*个[、，]?\s*/g, "")
    .replace(/建议补充的\s*\.gitignore\s*规则\s*0\s*条[。，]?\s*/g, "")
    .replace(
      /过期依赖\s*(\d+)\s*个[^。]*[。，]/g,
      () => outdatedDetailText(DATA.outdated) || "",
    );
  if (cleaned && !isNoisySecurityText(cleaned) && cleaned.length <= 320) {
    const nestedText = nestedLockedSummaryText(DATA.vulns);
    return normalizeSecurityLanguage(
      nestedText ? cleaned + nestedText : cleaned,
    );
  }
  const packages = DATA.project.total_packages || DATA.package_count || 0;
  const vulns = DATA.vulns || [];
  const names = new Set(vulns.map((x) => x.package || x.name).filter(Boolean));
  const group = topVulnerabilityGroup();
  const projectName = DATA.project && DATA.project.name;
  const outdatedCount = DATA.outdated.length;
  const parts = [];
  if (packages || vulns.length) {
    const covered = projectName
      ? `${projectName} 项目的 ${packages || "多个"} 个依赖包`
      : `${packages || "多个"} 个依赖包`;
    parts.push(
      `本次扫描覆盖${covered}，识别出 ${vulns.length || DATA.project.total_vulnerabilities || 0} 个已确认风险项。`,
    );
  }
  if (group.name) {
    const fixed = commonFixedVersion(group.items);
    parts.push(
      `风险最集中在 ${group.name}${group.items[0] && group.items[0].version ? " " + group.items[0].version : ""}，建议优先升级${fixed ? "到 " + fixed : "到官方修复版本"}。`,
    );
  }
  if (names.size > 1) {
    parts.push(
      "其余多为传递依赖问题，优先升级锁住旧子依赖的父依赖，再重新刷新锁文件。",
    );
  }
  if (/lockfile|node_modules|npm ci/i.test(String(raw || ""))) {
    parts.push(
      "另外需要修正 lockfile 和本地安装版本不一致的问题，避免干净环境装回旧版本。",
    );
  }
  const outdatedText = outdatedDetailText(DATA.outdated);
  if (outdatedText) parts.push(outdatedText);
  const nestedText = nestedLockedSummaryText(DATA.vulns);
  if (nestedText) parts.push(nestedText);
  const hygieneIssues =
    (DATA.hygiene ? toList(DATA.hygiene.tracked_secrets).length : 0) +
    (DATA.hygiene ? toList(DATA.hygiene.sensitive_tracked).length : 0) +
    (DATA.hygiene ? toList(DATA.hygiene.gitignore_missing).length : 0);
  if (hygieneIssues > 0) {
    parts.push(`仓库安检待关注项 ${hygieneIssues} 个。`);
  } else {
    parts.push("仓库安检通过。");
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
      ? "建议纳入版本维护计划；长期不处理会增加未来升级成本和供应链暴露面。"
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

function parseVersion(v) {
  const parts = v
    .replace(/^v/, "")
    .split(".")
    .map((p) => {
      const n = parseInt(p, 10);
      return isNaN(n) ? 0 : n;
    });
  while (parts.length < 3) parts.push(0);
  return parts.slice(0, 3);
}

function versionCmp(a, b) {
  for (let i = 0; i < 3; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return 0;
}

function semverSatisfies(version, range) {
  range = (range || "").trim();
  if (!range || range === "*" || range === "latest") return true;
  if (range.includes("||")) {
    return range.split("||").some((r) => semverSatisfies(version, r.trim()));
  }
  const ver = parseVersion(version);
  if (range.startsWith("^")) {
    const base = parseVersion(range.slice(1));
    if (base[0] > 0) return versionCmp(ver, base) >= 0 && ver[0] === base[0];
    if (base[1] > 0)
      return versionCmp(ver, base) >= 0 && ver[0] === 0 && ver[1] === base[1];
    return versionCmp(ver, base) === 0;
  }
  if (range.startsWith("~")) {
    const base = parseVersion(range.slice(1));
    return (
      versionCmp(ver, base) >= 0 && ver[0] === base[0] && ver[1] === base[1]
    );
  }
  if (range.startsWith(">="))
    return versionCmp(ver, parseVersion(range.slice(2))) >= 0;
  if (range.startsWith(">"))
    return versionCmp(ver, parseVersion(range.slice(1))) > 0;
  if (range.startsWith("<="))
    return versionCmp(ver, parseVersion(range.slice(2))) <= 0;
  if (range.startsWith("<"))
    return versionCmp(ver, parseVersion(range.slice(1))) < 0;
  return versionCmp(ver, parseVersion(range)) === 0;
}

function dependencyContextText(r) {
  const ctx = r.dependency_context || r.dependencyContext || {};
  if (!ctx || ctx.kind !== "nested_locked") return "";
  const locations = Array.isArray(ctx.locations) ? ctx.locations : [];
  const parents = [];
  locations.forEach((item) => {
    const parent = item && item.parent;
    if (parent && !parents.includes(parent)) parents.push(parent);
  });
  const parentText = parents.length
    ? `父依赖：${parents.slice(0, 3).join("、")}${parents.length > 3 ? ` 等 ${parents.length} 个` : ""}`
    : "父依赖待确认";
  const topVersions = toList(ctx.top_level_versions || ctx.topLevelVersions);
  const topText = topVersions.length
    ? `；顶层版本：${topVersions.join("、")}`
    : "";
  // Show semver range analysis from first location
  const firstLoc = locations[0] || {};
  const parentRange = firstLoc.parent_range || firstLoc.parentRange;
  const targetVer = r.target_version || (r.fix_config || {}).target_version;
  let rangeText = "";
  if (parentRange && targetVer) {
    const inRange = semverSatisfies(targetVer, parentRange);
    const hint = inRange
      ? `修复版本 ${targetVer} 在范围内，只需重新解析 lockfile`
      : `修复版本 ${targetVer} 不在范围内，需升级父依赖`;
    rangeText = ` ${parents[0] || "父依赖"} 声明 "${parentRange}"，${hint}。`;
  } else if (parentRange) {
    rangeText = ` ${parents[0] || "父依赖"} 声明 "${parentRange}"。`;
  }
  return `该旧版本属于被父依赖锁定的嵌套副本，${parentText}${topText}。${rangeText}`;
}

// ---- CWE plain-language mapping (user-facing) ----
// CWE plain-language mapping: 969 entries (129 manual + 840 auto-translated)
// Source: MITRE CWE v4.20 (https://cwe.mitre.org/data/index.html)
const CWE_PLAIN = {
  "CWE-5": "存在配置加密相关的问题，可能影响系统安全性",
  "CWE-6": "存在配置不足会话相关的问题，可能影响系统安全性",
  "CWE-7": "存在配置缺少错误相关的问题，可能影响系统安全性",
  "CWE-8": "存在配置相关的问题，可能影响系统安全性",
  "CWE-9": "存在配置权限弱相关的问题，可能影响系统安全性",
  "CWE-11": "存在配置相关的问题，可能影响系统安全性",
  "CWE-12": "存在配置缺少错误相关的问题，可能影响系统安全性",
  "CWE-13": "存在配置密码文件相关的问题，可能影响系统安全性",
  "CWE-14": "存在缓冲区相关的问题，可能影响系统安全性",
  "CWE-15": "存在配置相关的问题，可能影响系统安全性",
  "CWE-20": "存在输入校验不足的问题，攻击者可能通过构造特殊输入绕过安全检查",
  "CWE-22": "存在路径穿越风险，攻击者可能读取或修改服务器上的任意文件",
  "CWE-23": "存在路径穿越相关的问题，可能影响系统安全性",
  "CWE-24": "存在路径穿越文件相关的问题，可能影响系统安全性",
  "CWE-25": "存在路径穿越文件相关的问题，可能影响系统安全性",
  "CWE-26": "存在路径穿越文件相关的问题，可能影响系统安全性",
  "CWE-27": "存在路径穿越文件相关的问题，可能影响系统安全性",
  "CWE-28": "存在路径穿越文件相关的问题，可能影响系统安全性",
  "CWE-29": "存在路径穿越文件相关的问题，可能影响系统安全性",
  "CWE-30": "存在路径穿越文件相关的问题，可能影响系统安全性",
  "CWE-31": "存在路径穿越文件相关的问题，可能影响系统安全性",
  "CWE-32": "存在路径穿越相关的问题，可能影响系统安全性",
  "CWE-33": "存在路径穿越相关的问题，可能影响系统安全性",
  "CWE-34": "存在路径穿越相关的问题，可能影响系统安全性",
  "CWE-35": "存在路径穿越相关的问题，可能影响系统安全性",
  "CWE-36": "存在路径穿越相关的问题，可能影响系统安全性",
  "CWE-37": "存在路径遍历风险（使用特殊字符绕过），攻击者可能访问受限文件",
  "CWE-38": "存在路径穿越相关的问题，可能影响系统安全性",
  "CWE-39": "存在路径穿越相关的问题，可能影响系统安全性",
  "CWE-40": "存在路径穿越相关的问题，可能影响系统安全性",
  "CWE-41": "存在不当路径相关的问题，可能影响系统安全性",
  "CWE-42": "存在文件路径相关的问题，可能影响系统安全性",
  "CWE-43": "存在文件路径相关的问题，可能影响系统安全性",
  "CWE-44": "存在文件路径相关的问题，可能影响系统安全性",
  "CWE-45": "存在文件路径相关的问题，可能影响系统安全性",
  "CWE-46": "存在文件路径相关的问题，可能影响系统安全性",
  "CWE-47": "存在文件路径相关的问题，可能影响系统安全性",
  "CWE-48": "存在文件路径相关的问题，可能影响系统安全性",
  "CWE-49": "存在文件路径相关的问题，可能影响系统安全性",
  "CWE-50": "存在路径相关的问题，可能影响系统安全性",
  "CWE-51": "存在路径相关的问题，可能影响系统安全性",
  "CWE-52": "存在路径相关的问题，可能影响系统安全性",
  "CWE-53": "存在路径相关的问题，可能影响系统安全性",
  "CWE-54": "存在文件路径相关的问题，可能影响系统安全性",
  "CWE-55": "存在目录路径相关的问题，可能影响系统安全性",
  "CWE-56": "存在文件路径相关的问题，可能影响系统安全性",
  "CWE-57": "存在文件路径相关的问题，可能影响系统安全性",
  "CWE-58": "存在文件路径相关的问题，可能影响系统安全性",
  "CWE-59": "存在符号链接攻击风险，攻击者可能通过创建链接读取或篡改敏感文件",
  "CWE-61": "存在链接相关的问题，可能影响系统安全性",
  "CWE-62": "存在链接相关的问题，可能影响系统安全性",
  "CWE-64": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-65": "存在链接相关的问题，可能影响系统安全性",
  "CWE-66": "存在资源不当文件相关的问题，可能影响系统安全性",
  "CWE-67": "存在不当相关的问题，可能影响系统安全性",
  "CWE-69": "存在不当相关的问题，可能影响系统安全性",
  "CWE-71": "存在废弃相关的问题，可能影响系统安全性",
  "CWE-72": "存在不当路径相关的问题，可能影响系统安全性",
  "CWE-73": "存在文件路径相关的问题，可能影响系统安全性",
  "CWE-74": "存在注入攻击风险，攻击者可能通过构造特殊输入执行非预期操作",
  "CWE-75": "存在注入相关的问题，可能影响系统安全性",
  "CWE-76": "存在不当相关的问题，可能影响系统安全性",
  "CWE-77": "存在命令注入风险，攻击者可能在服务器上执行任意系统命令",
  "CWE-78": "存在命令注入风险，攻击者可能在服务器上执行任意系统命令",
  "CWE-79":
    "存在页面脚本注入风险，攻击者可能在网页中植入恶意代码，影响访问用户的数据安全",
  "CWE-80": "存在不当跨站脚本相关的问题，可能影响系统安全性",
  "CWE-81": "存在不当错误相关的问题，可能影响系统安全性",
  "CWE-82": "存在不当相关的问题，可能影响系统安全性",
  "CWE-83": "存在不当相关的问题，可能影响系统安全性",
  "CWE-84": "存在不当相关的问题，可能影响系统安全性",
  "CWE-85": "存在跨站脚本相关的问题，可能影响系统安全性",
  "CWE-86": "存在不当无效相关的问题，可能影响系统安全性",
  "CWE-87": "存在不当跨站脚本相关的问题，可能影响系统安全性",
  "CWE-88": "存在注入不当相关的问题，可能影响系统安全性",
  "CWE-89": "存在数据库注入风险，攻击者可能读取、修改或删除数据库中的数据",
  "CWE-90":
    "存在 LDAP 注入风险，攻击者可能绕过身份验证或获取目录服务中的敏感数据",
  "CWE-91": "存在注入路径相关的问题，可能影响系统安全性",
  "CWE-92": "存在废弃不当相关的问题，可能影响系统安全性",
  "CWE-93": "存在注入不当相关的问题，可能影响系统安全性",
  "CWE-94": "存在代码注入风险，攻击者可能在系统中执行任意代码",
  "CWE-95": "存在注入不当相关的问题，可能影响系统安全性",
  "CWE-96": "存在代码注入不当相关的问题，可能影响系统安全性",
  "CWE-97": "存在不当相关的问题，可能影响系统安全性",
  "CWE-98": "存在不当文件相关的问题，可能影响系统安全性",
  "CWE-99": "存在注入资源不当相关的问题，可能影响系统安全性",
  "CWE-102": "存在校验相关的问题，可能影响系统安全性",
  "CWE-103": "存在不完整相关的问题，可能影响系统安全性",
  "CWE-104": "存在校验相关的问题，可能影响系统安全性",
  "CWE-105": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-106": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-107": "存在校验相关的问题，可能影响系统安全性",
  "CWE-108": "存在未校验相关的问题，可能影响系统安全性",
  "CWE-109": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-110": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-111": "存在不安全相关的问题，可能影响系统安全性",
  "CWE-112": "存在校验缺少相关的问题，可能影响系统安全性",
  "CWE-113":
    "存在 HTTP 响应头注入风险，攻击者可能篡改响应内容或设置恶意 Cookie",
  "CWE-114": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-115": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-116": "存在不当相关的问题，可能影响系统安全性",
  "CWE-117": "存在日志注入风险，攻击者可能向日志中注入虚假内容，干扰安全审计",
  "CWE-118": "存在不正确资源错误相关的问题，可能影响系统安全性",
  "CWE-119": "存在内存越界写入风险，攻击者可能利用它执行任意代码或导致程序崩溃",
  "CWE-120": "存在缓冲区溢出风险，攻击者可能覆写相邻内存导致程序崩溃或被控制",
  "CWE-121": "存在缓冲区溢出相关的问题，可能影响系统安全性",
  "CWE-122": "存在缓冲区溢出相关的问题，可能影响系统安全性",
  "CWE-123": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-124": "存在缓冲区相关的问题，可能影响系统安全性",
  "CWE-125": "存在内存越界读取风险，攻击者可能读取到不应暴露的敏感数据",
  "CWE-126": "存在缓冲区越界读取相关的问题，可能影响系统安全性",
  "CWE-127": "存在缓冲区相关的问题，可能影响系统安全性",
  "CWE-128": "存在错误相关的问题，可能影响系统安全性",
  "CWE-129": "存在校验不当相关的问题，可能影响系统安全性",
  "CWE-130": "存在不当相关的问题，可能影响系统安全性",
  "CWE-131": "存在计算不正确缓冲区相关的问题，可能影响系统安全性",
  "CWE-132": "存在废弃相关的问题，可能影响系统安全性",
  "CWE-134":
    "存在格式化字符串漏洞，攻击者可能读取内存中的敏感数据或导致程序崩溃",
  "CWE-135": "存在计算不正确相关的问题，可能影响系统安全性",
  "CWE-138": "存在不当相关的问题，可能影响系统安全性",
  "CWE-140": "存在不当相关的问题，可能影响系统安全性",
  "CWE-141": "存在不当相关的问题，可能影响系统安全性",
  "CWE-142": "存在不当相关的问题，可能影响系统安全性",
  "CWE-143": "存在不当相关的问题，可能影响系统安全性",
  "CWE-144": "存在不当相关的问题，可能影响系统安全性",
  "CWE-145": "存在不当相关的问题，可能影响系统安全性",
  "CWE-146": "存在不当相关的问题，可能影响系统安全性",
  "CWE-147": "存在不当相关的问题，可能影响系统安全性",
  "CWE-148": "存在不当相关的问题，可能影响系统安全性",
  "CWE-149": "存在不当相关的问题，可能影响系统安全性",
  "CWE-150": "存在输入转义不充分的问题，攻击者可能注入控制字符干扰程序运行",
  "CWE-151": "存在不当相关的问题，可能影响系统安全性",
  "CWE-152": "存在不当相关的问题，可能影响系统安全性",
  "CWE-153": "存在不当相关的问题，可能影响系统安全性",
  "CWE-154": "存在不当相关的问题，可能影响系统安全性",
  "CWE-155": "存在不当相关的问题，可能影响系统安全性",
  "CWE-156": "存在不当相关的问题，可能影响系统安全性",
  "CWE-157": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-158": "存在不当相关的问题，可能影响系统安全性",
  "CWE-159": "存在不当无效相关的问题，可能影响系统安全性",
  "CWE-160": "存在不当相关的问题，可能影响系统安全性",
  "CWE-161": "存在不当相关的问题，可能影响系统安全性",
  "CWE-162": "存在不当相关的问题，可能影响系统安全性",
  "CWE-163": "存在不当相关的问题，可能影响系统安全性",
  "CWE-164": "存在不当相关的问题，可能影响系统安全性",
  "CWE-165": "存在不当相关的问题，可能影响系统安全性",
  "CWE-166": "存在不当缺少相关的问题，可能影响系统安全性",
  "CWE-167": "存在不当相关的问题，可能影响系统安全性",
  "CWE-168": "存在不当相关的问题，可能影响系统安全性",
  "CWE-170": "存在不当相关的问题，可能影响系统安全性",
  "CWE-172": "存在错误相关的问题，可能影响系统安全性",
  "CWE-173": "存在不当相关的问题，可能影响系统安全性",
  "CWE-174": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-175": "存在不当相关的问题，可能影响系统安全性",
  "CWE-176": "存在不当相关的问题，可能影响系统安全性",
  "CWE-177": "存在不当相关的问题，可能影响系统安全性",
  "CWE-178": "存在不当相关的问题，可能影响系统安全性",
  "CWE-179": "存在校验不正确相关的问题，可能影响系统安全性",
  "CWE-180": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-181": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-182": "存在不安全相关的问题，可能影响系统安全性",
  "CWE-183": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-184": "存在不完整相关的问题，可能影响系统安全性",
  "CWE-185": "存在正则表达式缺陷，攻击者可能利用它绕过输入验证",
  "CWE-186": "存在正则表达式相关的问题，可能影响系统安全性",
  "CWE-187": "存在比较相关的问题，可能影响系统安全性",
  "CWE-188": "存在内存相关的问题，可能影响系统安全性",
  "CWE-190": "存在整数溢出风险，可能导致程序计算结果错误或引发安全绕过",
  "CWE-191": "存在整数下溢风险，可能导致程序计算结果错误或引发安全绕过",
  "CWE-192": "存在整数错误相关的问题，可能影响系统安全性",
  "CWE-193": "存在错误相关的问题，可能影响系统安全性",
  "CWE-194": "存在非预期相关的问题，可能影响系统安全性",
  "CWE-195": "存在转换错误相关的问题，可能影响系统安全性",
  "CWE-196": "存在转换错误相关的问题，可能影响系统安全性",
  "CWE-197": "存在错误相关的问题，可能影响系统安全性",
  "CWE-198": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-200": "存在信息泄露风险，攻击者可能获取到不应暴露的内部数据或错误详情",
  "CWE-201": "存在通过发送请求获取内部数据的风险，攻击者可能推断出系统信息",
  "CWE-202": "存在暴露相关的问题，可能影响系统安全性",
  "CWE-203": "存在通过系统行为差异泄露信息的风险，攻击者可能据此推断内部状态",
  "CWE-204": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-205": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-206": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-207": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-208":
    "存在时序攻击风险，攻击者可能通过对比响应时间推测出加密密钥等敏感信息",
  "CWE-209":
    "存在错误信息泄露敏感数据的问题，攻击者可能从报错信息中获取系统内部细节",
  "CWE-210": "存在错误相关的问题，可能影响系统安全性",
  "CWE-211": "存在错误相关的问题，可能影响系统安全性",
  "CWE-212": "存在不当相关的问题，可能影响系统安全性",
  "CWE-213": "存在暴露相关的问题，可能影响系统安全性",
  "CWE-214": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-215": "存在调试信息泄露的问题，生产环境中可能暴露代码路径或内部状态",
  "CWE-216": "存在废弃错误相关的问题，可能影响系统安全性",
  "CWE-217": "存在废弃相关的问题，可能影响系统安全性",
  "CWE-218": "存在废弃相关的问题，可能影响系统安全性",
  "CWE-219": "存在文件相关的问题，可能影响系统安全性",
  "CWE-220": "存在文件相关的问题，可能影响系统安全性",
  "CWE-221": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-222": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-223": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-224": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-225": "存在废弃相关的问题，可能影响系统安全性",
  "CWE-226": "存在敏感信息残留风险，程序可能在内存或日志中留下未清除的敏感数据",
  "CWE-228": "存在不当无效相关的问题，可能影响系统安全性",
  "CWE-229": "存在不当相关的问题，可能影响系统安全性",
  "CWE-230": "存在不当缺少相关的问题，可能影响系统安全性",
  "CWE-231": "存在不当相关的问题，可能影响系统安全性",
  "CWE-232": "存在不当相关的问题，可能影响系统安全性",
  "CWE-233": "存在不当相关的问题，可能影响系统安全性",
  "CWE-234": "存在缺少相关的问题，可能影响系统安全性",
  "CWE-235": "存在不当相关的问题，可能影响系统安全性",
  "CWE-236": "存在不当相关的问题，可能影响系统安全性",
  "CWE-237": "存在不当相关的问题，可能影响系统安全性",
  "CWE-238": "存在不完整不当相关的问题，可能影响系统安全性",
  "CWE-239": "存在不完整相关的问题，可能影响系统安全性",
  "CWE-240": "存在不当相关的问题，可能影响系统安全性",
  "CWE-241": "存在非预期不当相关的问题，可能影响系统安全性",
  "CWE-242": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-243": "存在目录相关的问题，可能影响系统安全性",
  "CWE-244": "存在不当释放内存相关的问题，可能影响系统安全性",
  "CWE-245": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-246": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-247": "存在废弃相关的问题，可能影响系统安全性",
  "CWE-248": "存在异常相关的问题，可能影响系统安全性",
  "CWE-249": "存在废弃路径相关的问题，可能影响系统安全性",
  "CWE-250": "存在以不必要的高权限运行的问题，被攻击后影响范围更大",
  "CWE-252": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-253": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-256": "存在密码明文存储的问题，数据库泄露后攻击者可直接获取用户密码",
  "CWE-257": "存在密码相关的问题，可能影响系统安全性",
  "CWE-258": "存在配置密码文件相关的问题，可能影响系统安全性",
  "CWE-259": "存在硬编码密码的问题，任何拿到代码的人都能获取密码",
  "CWE-260": "存在配置密码文件相关的问题，可能影响系统安全性",
  "CWE-261": "存在密码编码方式不安全的问题，攻击者可能轻易还原原始密码",
  "CWE-262": "存在密码相关的问题，可能影响系统安全性",
  "CWE-263": "存在过期密码相关的问题，可能影响系统安全性",
  "CWE-266": "存在权限不正确相关的问题，可能影响系统安全性",
  "CWE-267": "存在权限不安全相关的问题，可能影响系统安全性",
  "CWE-268": "存在权限相关的问题，可能影响系统安全性",
  "CWE-269": "存在权限管理不当的问题，普通用户可能获得管理员权限",
  "CWE-270": "存在权限错误相关的问题，可能影响系统安全性",
  "CWE-271": "存在权限错误相关的问题，可能影响系统安全性",
  "CWE-272": "存在权限相关的问题，可能影响系统安全性",
  "CWE-273": "存在权限不当相关的问题，可能影响系统安全性",
  "CWE-274": "存在不足权限不当相关的问题，可能影响系统安全性",
  "CWE-276": "存在默认权限设置不正确的问题，敏感资源可能被所有人访问",
  "CWE-277": "存在权限不安全相关的问题，可能影响系统安全性",
  "CWE-278": "存在权限不安全相关的问题，可能影响系统安全性",
  "CWE-279": "存在权限不正确相关的问题，可能影响系统安全性",
  "CWE-280": "存在不足权限不当相关的问题，可能影响系统安全性",
  "CWE-281": "存在权限不当相关的问题，可能影响系统安全性",
  "CWE-282": "存在不当相关的问题，可能影响系统安全性",
  "CWE-283": "存在未验证相关的问题，可能影响系统安全性",
  "CWE-284": "存在访问控制缺陷，未授权的用户可能访问受限功能或数据",
  "CWE-285": "存在授权校验缺陷，用户可能越权访问不属于自己权限的功能",
  "CWE-286": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-287": "存在身份验证缺陷，攻击者可能绕过登录验证冒充其他用户",
  "CWE-288": "存在身份验证绕过的问题，攻击者可能无需登录即可访问受保护的资源",
  "CWE-289": "存在身份验证绕过相关的问题，可能影响系统安全性",
  "CWE-290": "存在身份验证欺骗绕过相关的问题，可能影响系统安全性",
  "CWE-291": "存在身份验证相关的问题，可能影响系统安全性",
  "CWE-292": "存在废弃相关的问题，可能影响系统安全性",
  "CWE-293": "存在身份验证相关的问题，可能影响系统安全性",
  "CWE-294": "存在身份验证绕过相关的问题，可能影响系统安全性",
  "CWE-295": "存在证书验证缺陷，程序可能信任伪造的证书，导致通信被窃听或篡改",
  "CWE-296": "存在证书不当相关的问题，可能影响系统安全性",
  "CWE-297": "存在域名与证书不匹配的问题，程序可能连接到伪造的服务器",
  "CWE-298": "存在证书校验过期相关的问题，可能影响系统安全性",
  "CWE-299": "存在证书不当相关的问题，可能影响系统安全性",
  "CWE-300": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-301": "存在身份验证相关的问题，可能影响系统安全性",
  "CWE-302": "存在身份验证绕过相关的问题，可能影响系统安全性",
  "CWE-303": "存在身份验证不正确相关的问题，可能影响系统安全性",
  "CWE-304": "存在身份验证缺少相关的问题，可能影响系统安全性",
  "CWE-305": "存在身份验证绕过弱相关的问题，可能影响系统安全性",
  "CWE-306": "存在关键功能缺少身份验证的问题，任何人都可以直接调用",
  "CWE-307": "存在登录限制不足的问题，攻击者可以无限次尝试密码",
  "CWE-308": "存在身份验证相关的问题，可能影响系统安全性",
  "CWE-309": "存在身份验证密码相关的问题，可能影响系统安全性",
  "CWE-311": "存在缺少加密的问题，敏感数据可能以明文形式存储或传输",
  "CWE-312": "存在敏感信息明文存储的问题，数据可能被直接读取",
  "CWE-313": "存在文件相关的问题，可能影响系统安全性",
  "CWE-314": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-315": "存在Cookie相关的问题，可能影响系统安全性",
  "CWE-316": "存在内存相关的问题，可能影响系统安全性",
  "CWE-317": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-318": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-319": "存在敏感信息明文传输的问题，数据在传输过程中可能被窃听",
  "CWE-321": "存在硬编码加密密钥的问题，密钥泄露后无法更换，数据保护形同虚设",
  "CWE-322": "存在密钥交换不安全的问题，攻击者可能截获或篡改通信内容",
  "CWE-323": "存在加密相关的问题，可能影响系统安全性",
  "CWE-324": "存在过期相关的问题，可能影响系统安全性",
  "CWE-325": "存在缺少加密步骤的问题，数据传输可能被窃听或篡改",
  "CWE-326": "存在加密强度不足风险，攻击者可能通过暴力破解等方式获取加密数据",
  "CWE-327": "使用了不安全的加密算法，可能导致加密数据被破解",
  "CWE-328": "存在哈希弱相关的问题，可能影响系统安全性",
  "CWE-329": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-330": "存在随机数生成不安全的问题，攻击者可能预测生成结果",
  "CWE-331": "存在不足相关的问题，可能影响系统安全性",
  "CWE-332": "存在不足相关的问题，可能影响系统安全性",
  "CWE-333": "存在不足不当相关的问题，可能影响系统安全性",
  "CWE-334": "存在随机相关的问题，可能影响系统安全性",
  "CWE-335": "存在不正确随机相关的问题，可能影响系统安全性",
  "CWE-336": "存在随机相关的问题，可能影响系统安全性",
  "CWE-337": "存在随机相关的问题，可能影响系统安全性",
  "CWE-338": "使用了不安全的随机数生成方式，攻击者可能预测随机数结果",
  "CWE-339": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-340": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-341": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-342": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-343": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-344": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-345": "存在数据来源校验不足的问题，攻击者可能注入伪造数据",
  "CWE-346": "存在来源校验缺陷，攻击者可能伪造请求来源绕过安全限制",
  "CWE-347": "存在签名验证缺陷，攻击者可能伪造签名绕过完整性检查",
  "CWE-348": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-349": "存在签名验证缺陷，攻击者可能伪造数据绕过完整性检查",
  "CWE-350": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-351": "存在不足相关的问题，可能影响系统安全性",
  "CWE-352": "存在跨站请求伪造风险，攻击者可能诱导用户在不知情的情况下执行操作",
  "CWE-353": "存在完整性缺少相关的问题，可能影响系统安全性",
  "CWE-354": "存在完整性校验不充分的问题，数据可能被篡改而未被发现",
  "CWE-356": "存在不安全相关的问题，可能影响系统安全性",
  "CWE-357": "存在不足相关的问题，可能影响系统安全性",
  "CWE-358": "存在不当相关的问题，可能影响系统安全性",
  "CWE-359": "存在暴露相关的问题，可能影响系统安全性",
  "CWE-360": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-362": "存在并发竞态风险，攻击者可能利用时间差绕过安全检查",
  "CWE-363": "存在竞态条件链接相关的问题，可能影响系统安全性",
  "CWE-364": "存在竞态条件相关的问题，可能影响系统安全性",
  "CWE-365": "存在竞态条件废弃相关的问题，可能影响系统安全性",
  "CWE-366": "存在竞态条件相关的问题，可能影响系统安全性",
  "CWE-367": "存在竞态条件风险，攻击者可能在程序检查和执行之间插入操作绕过验证",
  "CWE-368": "存在竞态条件相关的问题，可能影响系统安全性",
  "CWE-369": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-370": "存在证书缺少相关的问题，可能影响系统安全性",
  "CWE-372": "存在不完整相关的问题，可能影响系统安全性",
  "CWE-373": "存在废弃错误相关的问题，可能影响系统安全性",
  "CWE-374": "存在不可信相关的问题，可能影响系统安全性",
  "CWE-375": "存在不可信相关的问题，可能影响系统安全性",
  "CWE-377":
    "存在临时文件处理不安全的问题，攻击者可能读取或替换临时文件中的数据",
  "CWE-378": "存在权限不安全文件相关的问题，可能影响系统安全性",
  "CWE-379": "存在权限目录不安全相关的问题，可能影响系统安全性",
  "CWE-382": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-383": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-384": "存在会话固定攻击风险，攻击者可能强制用户使用已知的会话标识",
  "CWE-385": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-386": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-390": "存在错误相关的问题，可能影响系统安全性",
  "CWE-391": "存在错误相关的问题，可能影响系统安全性",
  "CWE-392": "存在缺少错误相关的问题，可能影响系统安全性",
  "CWE-393": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-394": "存在非预期相关的问题，可能影响系统安全性",
  "CWE-395": "存在空指针异常相关的问题，可能影响系统安全性",
  "CWE-396": "存在异常相关的问题，可能影响系统安全性",
  "CWE-397": "存在异常相关的问题，可能影响系统安全性",
  "CWE-400": "存在资源耗尽风险，攻击者可能通过构造特殊请求使服务崩溃或无法响应",
  "CWE-401": "存在释放缺少内存相关的问题，可能影响系统安全性",
  "CWE-402": "存在资源相关的问题，可能影响系统安全性",
  "CWE-403": "存在暴露文件相关的问题，可能影响系统安全性",
  "CWE-404": "存在资源未正确释放的问题，可能导致内存泄漏或文件句柄耗尽",
  "CWE-405":
    "存在资源消耗不对称的问题，攻击者用少量资源就能让服务器付出巨大代价",
  "CWE-406": "存在不足相关的问题，可能影响系统安全性",
  "CWE-407": "存在算法性能缺陷，攻击者可能通过构造特殊输入使程序响应极慢",
  "CWE-408": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-409":
    "存在对高压缩数据处理不当的问题，攻击者可能通过解压炸弹耗尽系统资源",
  "CWE-410": "存在不足资源相关的问题，可能影响系统安全性",
  "CWE-412": "存在未限制相关的问题，可能影响系统安全性",
  "CWE-413": "存在资源不当相关的问题，可能影响系统安全性",
  "CWE-414": "存在缺少相关的问题，可能影响系统安全性",
  "CWE-415": "存在重复释放内存的问题，可能导致程序崩溃或被攻击者利用执行代码",
  "CWE-416": "存在已释放内存被再次使用的问题，攻击者可能利用它执行任意代码",
  "CWE-419": "存在未保护相关的问题，可能影响系统安全性",
  "CWE-420": "存在未保护相关的问题，可能影响系统安全性",
  "CWE-421": "存在竞态条件相关的问题，可能影响系统安全性",
  "CWE-422": "存在未保护相关的问题，可能影响系统安全性",
  "CWE-423": "存在废弃相关的问题，可能影响系统安全性",
  "CWE-424": "存在不当路径相关的问题，可能影响系统安全性",
  "CWE-425": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-426": "存在不可信路径相关的问题，可能影响系统安全性",
  "CWE-427": "存在未控制路径相关的问题，可能影响系统安全性",
  "CWE-428": "存在路径相关的问题，可能影响系统安全性",
  "CWE-430": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-431": "存在缺少相关的问题，可能影响系统安全性",
  "CWE-432": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-433": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-434":
    "存在文件上传不限制类型的问题，攻击者可能上传恶意脚本并在服务器上执行",
  "CWE-435": "存在不当相关的问题，可能影响系统安全性",
  "CWE-436": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-437": "存在不完整相关的问题，可能影响系统安全性",
  "CWE-439": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-440": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-441": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-443": "存在废弃相关的问题，可能影响系统安全性",
  "CWE-444": "存在 HTTP 请求走私风险，攻击者可能绕过安全代理或防火墙的检查",
  "CWE-446": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-447": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-448": "存在过时相关的问题，可能影响系统安全性",
  "CWE-449": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-450": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-451": "存在界面欺骗风险，攻击者可能伪造页面内容误导用户操作",
  "CWE-453": "存在初始化不安全默认相关的问题，可能影响系统安全性",
  "CWE-454": "存在初始化相关的问题，可能影响系统安全性",
  "CWE-455": "存在初始化相关的问题，可能影响系统安全性",
  "CWE-456": "存在初始化缺少相关的问题，可能影响系统安全性",
  "CWE-457": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-458": "存在初始化废弃不正确相关的问题，可能影响系统安全性",
  "CWE-459": "存在不完整清理相关的问题，可能影响系统安全性",
  "CWE-460": "存在异常不当清理相关的问题，可能影响系统安全性",
  "CWE-462": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-463": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-464": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-466": "存在指针相关的问题，可能影响系统安全性",
  "CWE-467": "存在指针相关的问题，可能影响系统安全性",
  "CWE-468": "存在不正确指针相关的问题，可能影响系统安全性",
  "CWE-469": "存在指针相关的问题，可能影响系统安全性",
  "CWE-470": "存在不安全相关的问题，可能影响系统安全性",
  "CWE-471": "存在不可变数据被篡改的风险，攻击者可能修改程序运行时状态",
  "CWE-472": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-473": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-474": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-475": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-476": "存在空指针引用风险，攻击者可能导致程序崩溃或服务不可用",
  "CWE-477": "存在过时相关的问题，可能影响系统安全性",
  "CWE-478": "存在缺少默认相关的问题，可能影响系统安全性",
  "CWE-479": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-480": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-481": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-482": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-483": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-484": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-486": "存在比较相关的问题，可能影响系统安全性",
  "CWE-487": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-488": "存在暴露会话相关的问题，可能影响系统安全性",
  "CWE-489": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-491": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-492": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-493": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-494":
    "存在未校验下载内容完整性的问题，攻击者可能在传输过程中替换为恶意代码",
  "CWE-495": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-496": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-497": "存在暴露相关的问题，可能影响系统安全性",
  "CWE-498": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-499": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-500": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-501": "存在信任边界违反的问题，来自不可信来源的数据未经校验就被信任使用",
  "CWE-502":
    "存在反序列化漏洞，攻击者可能通过构造恶意数据在服务器上执行任意代码",
  "CWE-506": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-507": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-508": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-509": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-510": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-511": "存在日志相关的问题，可能影响系统安全性",
  "CWE-512": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-514": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-515": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-516": "存在废弃相关的问题，可能影响系统安全性",
  "CWE-520": "存在配置相关的问题，可能影响系统安全性",
  "CWE-521": "存在密码强度要求不足的问题，用户可能设置过于简单的密码",
  "CWE-522": "存在凭据保护不足的问题，密码或令牌可能被截获或泄露",
  "CWE-523": "存在未保护凭据相关的问题，可能影响系统安全性",
  "CWE-524": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-525": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-526": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-527": "存在暴露相关的问题，可能影响系统安全性",
  "CWE-528": "存在暴露文件相关的问题，可能影响系统安全性",
  "CWE-529": "存在访问控制暴露文件相关的问题，可能影响系统安全性",
  "CWE-530": "存在暴露文件相关的问题，可能影响系统安全性",
  "CWE-531": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-532": "存在敏感信息写入日志的问题，日志文件泄露后可能导致数据泄露",
  "CWE-533": "存在废弃暴露文件相关的问题，可能影响系统安全性",
  "CWE-534": "存在废弃暴露文件相关的问题，可能影响系统安全性",
  "CWE-535": "存在暴露错误相关的问题，可能影响系统安全性",
  "CWE-536": "存在错误相关的问题，可能影响系统安全性",
  "CWE-537": "存在错误相关的问题，可能影响系统安全性",
  "CWE-538": "存在敏感信息写入公开文件的问题，攻击者可能直接读取这些文件",
  "CWE-539": "存在Cookie相关的问题，可能影响系统安全性",
  "CWE-540": "存在源代码中包含敏感信息的问题，代码泄露后密钥或密码也会暴露",
  "CWE-541": "存在文件相关的问题，可能影响系统安全性",
  "CWE-542": "存在废弃暴露清理相关的问题，可能影响系统安全性",
  "CWE-543": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-544": "存在缺少错误相关的问题，可能影响系统安全性",
  "CWE-545": "存在废弃相关的问题，可能影响系统安全性",
  "CWE-546": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-547": "存在硬编码相关的问题，可能影响系统安全性",
  "CWE-548": "存在目录暴露相关的问题，可能影响系统安全性",
  "CWE-549": "存在密码以可逆方式存储的问题，攻击者可能还原出明文密码",
  "CWE-550": "存在错误相关的问题，可能影响系统安全性",
  "CWE-551": "存在授权不正确相关的问题，可能影响系统安全性",
  "CWE-552": "存在文件相关的问题，可能影响系统安全性",
  "CWE-553": "存在目录相关的问题，可能影响系统安全性",
  "CWE-554": "存在配置校验相关的问题，可能影响系统安全性",
  "CWE-555": "存在配置密码文件相关的问题，可能影响系统安全性",
  "CWE-556": "存在配置相关的问题，可能影响系统安全性",
  "CWE-558": "存在日志相关的问题，可能影响系统安全性",
  "CWE-560": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-561": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-562": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-563": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-564": "存在数据库注入相关的问题，可能影响系统安全性",
  "CWE-565":
    "存在依赖 Cookie 但未做完整性校验的问题，攻击者可能篡改 Cookie 内容",
  "CWE-566": "存在授权绕过相关的问题，可能影响系统安全性",
  "CWE-567": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-568": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-570": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-571": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-572": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-573": "存在不当相关的问题，可能影响系统安全性",
  "CWE-574": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-575": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-576": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-577": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-578": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-579": "存在会话相关的问题，可能影响系统安全性",
  "CWE-580": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-581": "存在哈希相关的问题，可能影响系统安全性",
  "CWE-582": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-583": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-584": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-585": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-586": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-587": "存在指针相关的问题，可能影响系统安全性",
  "CWE-588": "存在指针相关的问题，可能影响系统安全性",
  "CWE-589": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-590": "存在内存相关的问题，可能影响系统安全性",
  "CWE-591": "存在不当内存相关的问题，可能影响系统安全性",
  "CWE-592": "存在身份验证废弃绕过相关的问题，可能影响系统安全性",
  "CWE-593": "存在身份验证绕过相关的问题，可能影响系统安全性",
  "CWE-594": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-595": "存在比较相关的问题，可能影响系统安全性",
  "CWE-596": "存在比较废弃不正确相关的问题，可能影响系统安全性",
  "CWE-597": "存在比较相关的问题，可能影响系统安全性",
  "CWE-598": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-599": "存在证书校验缺少相关的问题，可能影响系统安全性",
  "CWE-600": "存在异常相关的问题，可能影响系统安全性",
  "CWE-601": "存在开放重定向风险，攻击者可能将用户引导到恶意网站",
  "CWE-602": "存在客户端强制执行服务端安全策略的问题，攻击者可以绕过客户端检查",
  "CWE-603": "存在身份验证相关的问题，可能影响系统安全性",
  "CWE-605": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-606": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-607": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-608": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-609": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-610": "存在资源相关的问题，可能影响系统安全性",
  "CWE-611": "存在 XML 外部实体注入风险，攻击者可能读取服务器上的任意文件",
  "CWE-612": "存在授权不当相关的问题，可能影响系统安全性",
  "CWE-613": "存在会话过期时间不当的问题，用户退出后其他人可能继续使用其会话",
  "CWE-614": "存在会话Cookie相关的问题，可能影响系统安全性",
  "CWE-615": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-616": "存在不完整上传文件相关的问题，可能影响系统安全性",
  "CWE-617": "存在可触发的断言风险，攻击者可能导致程序异常终止",
  "CWE-618": "存在不安全相关的问题，可能影响系统安全性",
  "CWE-619": "存在注入相关的问题，可能影响系统安全性",
  "CWE-620": "存在未验证密码相关的问题，可能影响系统安全性",
  "CWE-621": "存在错误相关的问题，可能影响系统安全性",
  "CWE-622": "存在校验不当相关的问题，可能影响系统安全性",
  "CWE-623": "存在不安全相关的问题，可能影响系统安全性",
  "CWE-624": "存在正则表达式错误相关的问题，可能影响系统安全性",
  "CWE-625": "存在正则表达式相关的问题，可能影响系统安全性",
  "CWE-626": "存在错误相关的问题，可能影响系统安全性",
  "CWE-627": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-628": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-636": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-637": "存在不必要相关的问题，可能影响系统安全性",
  "CWE-638": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-639": "存在越权访问风险，攻击者可能通过修改参数访问其他用户的数据",
  "CWE-640": "存在密码找回机制不安全的问题，攻击者可能通过它重置他人密码",
  "CWE-641": "存在资源不当文件相关的问题，可能影响系统安全性",
  "CWE-642": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-643": "存在注入不当路径相关的问题，可能影响系统安全性",
  "CWE-644": "存在不当相关的问题，可能影响系统安全性",
  "CWE-645": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-646": "存在文件相关的问题，可能影响系统安全性",
  "CWE-647": "存在授权路径相关的问题，可能影响系统安全性",
  "CWE-648": "存在权限不正确相关的问题，可能影响系统安全性",
  "CWE-649": "存在加密完整性相关的问题，可能影响系统安全性",
  "CWE-650": "存在权限相关的问题，可能影响系统安全性",
  "CWE-651": "存在暴露文件相关的问题，可能影响系统安全性",
  "CWE-652": "存在注入不当相关的问题，可能影响系统安全性",
  "CWE-653": "存在不当相关的问题，可能影响系统安全性",
  "CWE-654": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-655": "存在不足日志相关的问题，可能影响系统安全性",
  "CWE-656": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-657": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-662": "存在不当相关的问题，可能影响系统安全性",
  "CWE-663": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-664": "存在资源不当相关的问题，可能影响系统安全性",
  "CWE-665": "存在初始化不当相关的问题，可能影响系统安全性",
  "CWE-666": "存在资源相关的问题，可能影响系统安全性",
  "CWE-667": "存在不当相关的问题，可能影响系统安全性",
  "CWE-668": "存在资源暴露给错误访问域的问题，内部资源可能被外部用户访问",
  "CWE-669": "存在不正确资源相关的问题，可能影响系统安全性",
  "CWE-670": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-671": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-672": "存在过期资源释放相关的问题，可能影响系统安全性",
  "CWE-673": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-674": "存在无限递归风险，攻击者可能通过特殊输入导致程序栈溢出崩溃",
  "CWE-675": "存在资源相关的问题，可能影响系统安全性",
  "CWE-676": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-680": "存在整数溢出导致缓冲区溢出的风险，可能被利用执行任意代码",
  "CWE-681": "存在转换不正确相关的问题，可能影响系统安全性",
  "CWE-682": "存在计算错误风险，程序可能产生不正确的结果影响安全判断",
  "CWE-683": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-684": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-685": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-686": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-687": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-688": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-689": "存在竞态条件权限资源相关的问题，可能影响系统安全性",
  "CWE-690": "存在空指针相关的问题，可能影响系统安全性",
  "CWE-691": "存在不足相关的问题，可能影响系统安全性",
  "CWE-692": "存在跨站脚本不完整相关的问题，可能影响系统安全性",
  "CWE-693": "存在安全机制绕过风险，攻击者可能绕过现有的防护措施",
  "CWE-694": "存在资源相关的问题，可能影响系统安全性",
  "CWE-695": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-696": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-697": "存在比较不正确相关的问题，可能影响系统安全性",
  "CWE-698": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-703": "存在异常处理不当的问题，程序遇到错误时可能进入不安全状态",
  "CWE-704": "存在转换不正确相关的问题，可能影响系统安全性",
  "CWE-705": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-706": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-707": "存在不当相关的问题，可能影响系统安全性",
  "CWE-708": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-710": "存在不当相关的问题，可能影响系统安全性",
  "CWE-732":
    "存在关键资源权限设置不正确的问题，攻击者可能访问或修改受保护的资源",
  "CWE-733": "存在编译器优化可能移除安全代码的风险，保护机制可能被意外去掉",
  "CWE-749": "暴露了危险功能接口，攻击者可能通过该接口执行不应开放的操作",
  "CWE-754": "存在对异常条件检查不充分的问题，程序可能忽略重要的错误信号",
  "CWE-755":
    "存在异常处理不当的问题，程序遇到错误时可能泄露信息或进入不安全状态",
  "CWE-756": "存在缺少错误相关的问题，可能影响系统安全性",
  "CWE-757": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-758": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-759": "存在哈希相关的问题，可能影响系统安全性",
  "CWE-760": "存在哈希相关的问题，可能影响系统安全性",
  "CWE-761": "存在指针缓冲区相关的问题，可能影响系统安全性",
  "CWE-762": "存在内存相关的问题，可能影响系统安全性",
  "CWE-763": "存在指针释放无效相关的问题，可能影响系统安全性",
  "CWE-764": "存在资源相关的问题，可能影响系统安全性",
  "CWE-765": "存在资源相关的问题，可能影响系统安全性",
  "CWE-766": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-767": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-768": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-769": "存在未控制废弃文件相关的问题，可能影响系统安全性",
  "CWE-770": "存在资源分配无限制风险，攻击者可能耗尽系统资源导致服务不可用",
  "CWE-771": "存在资源缺少相关的问题，可能影响系统安全性",
  "CWE-772": "存在缺少解压保护的问题，攻击者可能通过压缩炸弹使服务崩溃",
  "CWE-773": "存在缺少文件相关的问题，可能影响系统安全性",
  "CWE-774": "存在文件相关的问题，可能影响系统安全性",
  "CWE-775": "存在释放缺少文件相关的问题，可能影响系统安全性",
  "CWE-776": "存在 XML 膨胀攻击风险，攻击者可能通过构造特殊 XML 使服务崩溃",
  "CWE-777": "存在正则表达式相关的问题，可能影响系统安全性",
  "CWE-778": "存在不足日志相关的问题，可能影响系统安全性",
  "CWE-779": "存在过度日志相关的问题，可能影响系统安全性",
  "CWE-780": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-781": "存在校验不当相关的问题，可能影响系统安全性",
  "CWE-782": "存在访问控制不足相关的问题，可能影响系统安全性",
  "CWE-783": "存在错误日志相关的问题，可能影响系统安全性",
  "CWE-784": "存在校验完整性Cookie相关的问题，可能影响系统安全性",
  "CWE-785": "存在缓冲区路径相关的问题，可能影响系统安全性",
  "CWE-786": "存在内存缓冲区相关的问题，可能影响系统安全性",
  "CWE-787": "存在内存越界写入风险，攻击者可能覆写关键数据或执行任意代码",
  "CWE-788": "存在内存越界访问风险，攻击者可能读取或篡改相邻内存数据",
  "CWE-789": "存在内存分配过大风险，攻击者可能导致程序因内存耗尽而崩溃",
  "CWE-790": "存在不当相关的问题，可能影响系统安全性",
  "CWE-791": "存在不完整相关的问题，可能影响系统安全性",
  "CWE-792": "存在不完整相关的问题，可能影响系统安全性",
  "CWE-793": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-794": "存在不完整相关的问题，可能影响系统安全性",
  "CWE-795": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-796": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-797": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-798": "存在硬编码凭据的问题，密码或密钥直接写在代码中，泄露后无法更换",
  "CWE-799": "存在交互频率控制不足的问题，攻击者可能暴力破解密码或刷接口",
  "CWE-804": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-805": "存在不正确缓冲区相关的问题，可能影响系统安全性",
  "CWE-806": "存在缓冲区相关的问题，可能影响系统安全性",
  "CWE-807": "存在不可信相关的问题，可能影响系统安全性",
  "CWE-820": "存在缺少相关的问题，可能影响系统安全性",
  "CWE-821": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-822": "存在不可信指针相关的问题，可能影响系统安全性",
  "CWE-823": "存在指针相关的问题，可能影响系统安全性",
  "CWE-824": "存在指针相关的问题，可能影响系统安全性",
  "CWE-825": "存在指针相关的问题，可能影响系统安全性",
  "CWE-826": "存在资源释放相关的问题，可能影响系统安全性",
  "CWE-827": "存在不当相关的问题，可能影响系统安全性",
  "CWE-828": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-829": "存在不可信相关的问题，可能影响系统安全性",
  "CWE-830": "存在不可信相关的问题，可能影响系统安全性",
  "CWE-831": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-832": "存在资源相关的问题，可能影响系统安全性",
  "CWE-833": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-834": "存在过度相关的问题，可能影响系统安全性",
  "CWE-835": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-836": "存在身份验证密码哈希相关的问题，可能影响系统安全性",
  "CWE-837": "存在不当相关的问题，可能影响系统安全性",
  "CWE-838": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-839": "存在比较相关的问题，可能影响系统安全性",
  "CWE-841": "存在不当相关的问题，可能影响系统安全性",
  "CWE-842": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-843": "存在类型混淆资源相关的问题，可能影响系统安全性",
  "CWE-862": "缺少权限校验，攻击者可能访问到未授权的功能或数据",
  "CWE-863": "存在权限校验不正确的问题，用户可能绕过限制访问未授权资源",
  "CWE-908": "使用了未初始化的资源，可能导致程序行为不可预测",
  "CWE-909": "存在初始化资源缺少相关的问题，可能影响系统安全性",
  "CWE-910": "存在文件相关的问题，可能影响系统安全性",
  "CWE-911": "存在不当相关的问题，可能影响系统安全性",
  "CWE-912": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-913": "存在资源不当相关的问题，可能影响系统安全性",
  "CWE-914": "存在不当相关的问题，可能影响系统安全性",
  "CWE-915": "存在不当相关的问题，可能影响系统安全性",
  "CWE-916": "存在使用弱哈希算法的问题，攻击者可能通过碰撞攻击伪造数据",
  "CWE-917": "存在表达式语言注入风险，攻击者可能通过模板引擎执行任意代码",
  "CWE-918": "存在服务端请求伪造风险，攻击者可能绕过限制访问内部服务或敏感数据",
  "CWE-920": "存在不当相关的问题，可能影响系统安全性",
  "CWE-921": "存在访问控制相关的问题，可能影响系统安全性",
  "CWE-922": "存在不安全存储敏感数据的问题，数据可能被未授权用户访问",
  "CWE-923": "存在不当相关的问题，可能影响系统安全性",
  "CWE-924": "存在跨站请求伪造风险，攻击者可能冒充用户发送请求",
  "CWE-925": "存在验证不当相关的问题，可能影响系统安全性",
  "CWE-926": "存在不当相关的问题，可能影响系统安全性",
  "CWE-927": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-939": "存在授权不当相关的问题，可能影响系统安全性",
  "CWE-940": "存在外部实体引用风险，程序可能加载并执行来自外部的恶意资源",
  "CWE-941": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-942": "存在允许过度权限分配的问题，组件可能获得超出需要的系统权限",
  "CWE-943":
    "存在跨站请求伪造风险（使用 Ajax），攻击者可能通过构造请求冒充用户",
  "CWE-1004": "存在Cookie相关的问题，可能影响系统安全性",
  "CWE-1007": "存在不足相关的问题，可能影响系统安全性",
  "CWE-1021": "存在页面渲染缺陷，攻击者可能篡改网页展示内容",
  "CWE-1022": "存在不可信链接相关的问题，可能影响系统安全性",
  "CWE-1023": "存在比较不完整缺少相关的问题，可能影响系统安全性",
  "CWE-1024": "存在比较相关的问题，可能影响系统安全性",
  "CWE-1025": "存在比较相关的问题，可能影响系统安全性",
  "CWE-1037": "存在处理器优化导致安全措施失效的风险，安全检查可能被绕过",
  "CWE-1038": "存在优化不安全相关的问题，可能影响系统安全性",
  "CWE-1039": "存在不充分相关的问题，可能影响系统安全性",
  "CWE-1041": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1042": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1043": "存在过度相关的问题，可能影响系统安全性",
  "CWE-1044": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1045": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1046": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1047": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1048": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1049": "存在过度相关的问题，可能影响系统安全性",
  "CWE-1050": "存在过度资源相关的问题，可能影响系统安全性",
  "CWE-1051": "存在初始化配置硬编码相关的问题，可能影响系统安全性",
  "CWE-1052": "存在初始化硬编码过度相关的问题，可能影响系统安全性",
  "CWE-1053": "存在缺少相关的问题，可能影响系统安全性",
  "CWE-1054": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1055": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1056": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1057": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1058": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1059": "存在不足相关的问题，可能影响系统安全性",
  "CWE-1060": "存在过度相关的问题，可能影响系统安全性",
  "CWE-1061": "存在不足相关的问题，可能影响系统安全性",
  "CWE-1062": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1063": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1064": "存在签名过度相关的问题，可能影响系统安全性",
  "CWE-1065": "存在资源相关的问题，可能影响系统安全性",
  "CWE-1066": "存在缺少相关的问题，可能影响系统安全性",
  "CWE-1067": "存在过度资源相关的问题，可能影响系统安全性",
  "CWE-1068": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1069": "存在异常相关的问题，可能影响系统安全性",
  "CWE-1070": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1071": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1072": "存在资源相关的问题，可能影响系统安全性",
  "CWE-1073": "存在过度资源相关的问题，可能影响系统安全性",
  "CWE-1074": "存在过度相关的问题，可能影响系统安全性",
  "CWE-1075": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1076": "存在不足相关的问题，可能影响系统安全性",
  "CWE-1077": "存在比较不正确相关的问题，可能影响系统安全性",
  "CWE-1078": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1079": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1080": "存在过度文件相关的问题，可能影响系统安全性",
  "CWE-1082": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1083": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1084": "存在过度文件相关的问题，可能影响系统安全性",
  "CWE-1085": "存在过度相关的问题，可能影响系统安全性",
  "CWE-1086": "存在过度相关的问题，可能影响系统安全性",
  "CWE-1087": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1088": "存在资源相关的问题，可能影响系统安全性",
  "CWE-1089": "存在过度相关的问题，可能影响系统安全性",
  "CWE-1090": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1091": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1092": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1093": "存在过度相关的问题，可能影响系统安全性",
  "CWE-1094": "存在过度资源相关的问题，可能影响系统安全性",
  "CWE-1095": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1096": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1097": "存在比较相关的问题，可能影响系统安全性",
  "CWE-1098": "存在指针相关的问题，可能影响系统安全性",
  "CWE-1099": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1100": "存在不足相关的问题，可能影响系统安全性",
  "CWE-1101": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1102": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1103": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1104": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1105": "存在不足相关的问题，可能影响系统安全性",
  "CWE-1106": "存在不足相关的问题，可能影响系统安全性",
  "CWE-1107": "存在不足相关的问题，可能影响系统安全性",
  "CWE-1108": "存在过度相关的问题，可能影响系统安全性",
  "CWE-1109": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1110": "存在不完整相关的问题，可能影响系统安全性",
  "CWE-1111": "存在不完整相关的问题，可能影响系统安全性",
  "CWE-1112": "存在不完整相关的问题，可能影响系统安全性",
  "CWE-1113": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1114": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1115": "存在日志相关的问题，可能影响系统安全性",
  "CWE-1116": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1117": "存在不足相关的问题，可能影响系统安全性",
  "CWE-1118": "存在不足错误相关的问题，可能影响系统安全性",
  "CWE-1119": "存在过度相关的问题，可能影响系统安全性",
  "CWE-1120": "存在过度相关的问题，可能影响系统安全性",
  "CWE-1121": "存在过度相关的问题，可能影响系统安全性",
  "CWE-1122": "存在过度相关的问题，可能影响系统安全性",
  "CWE-1123": "存在过度相关的问题，可能影响系统安全性",
  "CWE-1124": "存在过度相关的问题，可能影响系统安全性",
  "CWE-1125": "存在过度相关的问题，可能影响系统安全性",
  "CWE-1126": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1127": "存在不足错误相关的问题，可能影响系统安全性",
  "CWE-1164": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1173": "存在校验不当相关的问题，可能影响系统安全性",
  "CWE-1174": "存在配置校验不当相关的问题，可能影响系统安全性",
  "CWE-1176": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1177": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1187": "存在废弃资源相关的问题，可能影响系统安全性",
  "CWE-1188": "存在初始化资源不安全相关的问题，可能影响系统安全性",
  "CWE-1189": "存在资源不当相关的问题，可能影响系统安全性",
  "CWE-1190": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1191": "存在访问控制不当相关的问题，可能影响系统安全性",
  "CWE-1192": "存在不当相关的问题，可能影响系统安全性",
  "CWE-1193": "存在访问控制不可信相关的问题，可能影响系统安全性",
  "CWE-1204": "存在初始化弱相关的问题，可能影响系统安全性",
  "CWE-1209": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1220": "存在访问控制不足相关的问题，可能影响系统安全性",
  "CWE-1221": "存在不正确默认相关的问题，可能影响系统安全性",
  "CWE-1222": "存在不足相关的问题，可能影响系统安全性",
  "CWE-1223": "存在竞态条件相关的问题，可能影响系统安全性",
  "CWE-1224": "存在不当相关的问题，可能影响系统安全性",
  "CWE-1229": "存在资源相关的问题，可能影响系统安全性",
  "CWE-1230": "存在暴露相关的问题，可能影响系统安全性",
  "CWE-1231": "存在不当相关的问题，可能影响系统安全性",
  "CWE-1232": "存在不当相关的问题，可能影响系统安全性",
  "CWE-1233": "存在缺少相关的问题，可能影响系统安全性",
  "CWE-1234": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1235": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-1236": "存在不当文件相关的问题，可能影响系统安全性",
  "CWE-1239": "存在不当相关的问题，可能影响系统安全性",
  "CWE-1240": "存在加密相关的问题，可能影响系统安全性",
  "CWE-1241": "存在随机相关的问题，可能影响系统安全性",
  "CWE-1242": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1243": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1244": "存在不安全相关的问题，可能影响系统安全性",
  "CWE-1245": "存在不当日志相关的问题，可能影响系统安全性",
  "CWE-1246": "存在不当相关的问题，可能影响系统安全性",
  "CWE-1247": "存在不当相关的问题，可能影响系统安全性",
  "CWE-1248": "存在日志相关的问题，可能影响系统安全性",
  "CWE-1249": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1250": "存在不当相关的问题，可能影响系统安全性",
  "CWE-1251": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1252": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1253": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-1254": "存在比较不正确日志相关的问题，可能影响系统安全性",
  "CWE-1255": "存在比较日志相关的问题，可能影响系统安全性",
  "CWE-1256": "存在不当相关的问题，可能影响系统安全性",
  "CWE-1257": "存在访问控制不当内存相关的问题，可能影响系统安全性",
  "CWE-1258": "存在暴露相关的问题，可能影响系统安全性",
  "CWE-1259": "存在不当相关的问题，可能影响系统安全性",
  "CWE-1260": "存在不当内存相关的问题，可能影响系统安全性",
  "CWE-1261": "存在不当相关的问题，可能影响系统安全性",
  "CWE-1262": "存在访问控制不当相关的问题，可能影响系统安全性",
  "CWE-1263": "存在访问控制不当相关的问题，可能影响系统安全性",
  "CWE-1264": "存在不安全日志相关的问题，可能影响系统安全性",
  "CWE-1265": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1266": "存在不当相关的问题，可能影响系统安全性",
  "CWE-1267": "存在过时相关的问题，可能影响系统安全性",
  "CWE-1268": "存在权限相关的问题，可能影响系统安全性",
  "CWE-1269": "存在配置释放相关的问题，可能影响系统安全性",
  "CWE-1270": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-1271": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1272": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1273": "存在凭据相关的问题，可能影响系统安全性",
  "CWE-1274": "存在访问控制不当内存相关的问题，可能影响系统安全性",
  "CWE-1275": "存在不当Cookie相关的问题，可能影响系统安全性",
  "CWE-1276": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-1277": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1278": "存在缺少相关的问题，可能影响系统安全性",
  "CWE-1279": "存在加密相关的问题，可能影响系统安全性",
  "CWE-1280": "存在访问控制相关的问题，可能影响系统安全性",
  "CWE-1281": "存在非预期相关的问题，可能影响系统安全性",
  "CWE-1282": "存在内存相关的问题，可能影响系统安全性",
  "CWE-1283": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1284": "存在校验不当相关的问题，可能影响系统安全性",
  "CWE-1285": "存在校验不当相关的问题，可能影响系统安全性",
  "CWE-1286": "存在校验不当相关的问题，可能影响系统安全性",
  "CWE-1287": "存在校验不当相关的问题，可能影响系统安全性",
  "CWE-1288": "存在校验不当相关的问题，可能影响系统安全性",
  "CWE-1289": "存在校验不当不安全相关的问题，可能影响系统安全性",
  "CWE-1290": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-1291": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1292": "存在转换不正确相关的问题，可能影响系统安全性",
  "CWE-1293": "存在缺少相关的问题，可能影响系统安全性",
  "CWE-1294": "存在不安全相关的问题，可能影响系统安全性",
  "CWE-1295": "存在不必要相关的问题，可能影响系统安全性",
  "CWE-1296": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-1297": "存在未保护相关的问题，可能影响系统安全性",
  "CWE-1298": "存在竞态条件日志相关的问题，可能影响系统安全性",
  "CWE-1299": "存在缺少相关的问题，可能影响系统安全性",
  "CWE-1300": "存在不当相关的问题，可能影响系统安全性",
  "CWE-1301": "存在不足不完整相关的问题，可能影响系统安全性",
  "CWE-1302": "存在缺少相关的问题，可能影响系统安全性",
  "CWE-1303": "存在资源相关的问题，可能影响系统安全性",
  "CWE-1304": "存在配置完整性不当相关的问题，可能影响系统安全性",
  "CWE-1310": "存在缺少相关的问题，可能影响系统安全性",
  "CWE-1311": "存在不当相关的问题，可能影响系统安全性",
  "CWE-1312": "存在缺少相关的问题，可能影响系统安全性",
  "CWE-1313": "存在日志相关的问题，可能影响系统安全性",
  "CWE-1314": "存在缺少相关的问题，可能影响系统安全性",
  "CWE-1315": "存在不当相关的问题，可能影响系统安全性",
  "CWE-1316": "存在未保护相关的问题，可能影响系统安全性",
  "CWE-1317": "存在访问控制不当相关的问题，可能影响系统安全性",
  "CWE-1318": "存在缺少相关的问题，可能影响系统安全性",
  "CWE-1319": "存在注入不当相关的问题，可能影响系统安全性",
  "CWE-1320": "存在不当错误相关的问题，可能影响系统安全性",
  "CWE-1321": "存在原型污染风险，攻击者可能修改程序内置对象，影响运行逻辑",
  "CWE-1322": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1323": "存在不当相关的问题，可能影响系统安全性",
  "CWE-1324": "存在废弃相关的问题，可能影响系统安全性",
  "CWE-1325":
    "存在信任边界管理不当的问题，来自不可信来源的数据被当作可信数据处理",
  "CWE-1326": "存在缺少相关的问题，可能影响系统安全性",
  "CWE-1327": "存在未限制相关的问题，可能影响系统安全性",
  "CWE-1328": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1329": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1330": "存在内存相关的问题，可能影响系统安全性",
  "CWE-1331": "存在资源不当相关的问题，可能影响系统安全性",
  "CWE-1332": "存在不当相关的问题，可能影响系统安全性",
  "CWE-1333": "存在正则表达式相关的问题，可能影响系统安全性",
  "CWE-1334": "存在注入错误相关的问题，可能影响系统安全性",
  "CWE-1335": "存在不正确整数相关的问题，可能影响系统安全性",
  "CWE-1336": "存在不当相关的问题，可能影响系统安全性",
  "CWE-1338": "存在不当相关的问题，可能影响系统安全性",
  "CWE-1339": "存在不足相关的问题，可能影响系统安全性",
  "CWE-1341": "存在资源释放相关的问题，可能影响系统安全性",
  "CWE-1342": "存在暴露相关的问题，可能影响系统安全性",
  "CWE-1351": "存在异常不当相关的问题，可能影响系统安全性",
  "CWE-1357": "存在依赖被篡改组件的风险，程序可能使用了被植入后门的第三方库",
  "CWE-1384": "存在日志中缺少安全事件记录的问题，安全事件可能无法被追踪和审计",
  "CWE-1385": "存在校验缺少相关的问题，可能影响系统安全性",
  "CWE-1386": "存在不安全相关的问题，可能影响系统安全性",
  "CWE-1389": "存在不正确相关的问题，可能影响系统安全性",
  "CWE-1390": "存在弱认证机制的问题，攻击者可能轻易绕过身份验证",
  "CWE-1391": "存在凭据弱相关的问题，可能影响系统安全性",
  "CWE-1392": "存在凭据默认相关的问题，可能影响系统安全性",
  "CWE-1393": "存在密码默认相关的问题，可能影响系统安全性",
  "CWE-1394": "存在加密默认相关的问题，可能影响系统安全性",
  "CWE-1395": "存在依赖包含已知漏洞的组件的问题，攻击者可能利用这些已知漏洞",
  "CWE-1419": "存在初始化不正确资源相关的问题，可能影响系统安全性",
  "CWE-1420": "存在暴露相关的问题，可能影响系统安全性",
  "CWE-1421": "存在暴露相关的问题，可能影响系统安全性",
  "CWE-1422": "存在不正确暴露相关的问题，可能影响系统安全性",
  "CWE-1423": "存在暴露相关的问题，可能影响系统安全性",
  "CWE-1426": "存在校验不当相关的问题，可能影响系统安全性",
  "CWE-1427": "存在不当相关的问题，可能影响系统安全性",
  "CWE-1428": "存在安全缺陷，可能影响系统安全或稳定性",
  "CWE-1429": "存在缺少相关的问题，可能影响系统安全性",
  "CWE-1431": "存在加密相关的问题，可能影响系统安全性",
  "CWE-1434": "存在不安全相关的问题，可能影响系统安全性",
};

function cwePlainDescription(r) {
  const enrichments = Array.isArray(r.cve_enrichments) ? r.cve_enrichments : [];
  for (const e of enrichments) {
    if (!e || !Array.isArray(e.cweIds)) continue;
    for (const cwe of e.cweIds) {
      if (!cwe) continue;
      const normalized = /^CWE-/i.test(String(cwe))
        ? String(cwe).toUpperCase()
        : "CWE-" + String(cwe);
      if (CWE_PLAIN[normalized]) return CWE_PLAIN[normalized];
    }
  }
  return "";
}

function vulnerabilityExplanation(r) {
  const context = dependencyContextText(r);
  if (context) return esc(context);
  const cweDesc = cwePlainDescription(r);
  if (cweDesc) {
    return esc(`当前版本${cweDesc}。${shortFixedVersionText(r)}`);
  }
  return esc(`当前版本${advisorySummaryText(r)}；${shortFixedVersionText(r)}`);
}

function outdatedExplanation(it) {
  const current = String(it.current || it.version || "").trim();
  const target =
    String(it.latest || it.latestVersion || "").trim() ||
    String(it.wanted || it.update || "").trim() ||
    outdatedDisplayTarget(it);
  const majorJump = current && target && isMajorVersionJump(current, target);
  if (current && target) {
    if (majorJump) {
      return `有新版本 ${target} 可用，跨大版本更新建议先阅读更新日志并做兼容性测试。`;
    }
    return `有新版本 ${target} 可用，建议在近期迭代中安排升级。`;
  }
  if (target) {
    return `有新版本 ${target} 可用，建议安排升级。`;
  }
  return "需要复核版本状态";
}

function isMajorVersionJump(current, target) {
  const c = parseVersion(current);
  const t = parseVersion(target);
  if (!c.length || !t.length) return false;
  return Math.abs(t[0] - c[0]) >= 1;
}

function countMajorJumps(items) {
  return (items || []).filter((it) => {
    const current = cleanVersion(it.current || it.version);
    const target = cleanVersion(
      it.latest || it.latestVersion || it.wanted || it.update || "",
    );
    return current && target && isMajorVersionJump(current, target);
  }).length;
}

function nestedLockedSummaryText(vulns) {
  const parents = new Map();
  (vulns || []).forEach((it) => {
    const ctx = it.dependency_context || it.dependencyContext || {};
    if (!ctx || ctx.kind !== "nested_locked") return;
    const locations = Array.isArray(ctx.locations) ? ctx.locations : [];
    locations.forEach((loc) => {
      const parent = loc.parent;
      if (!parent) return;
      if (!parents.has(parent)) parents.set(parent, new Set());
      const pkg = it.package || it.name;
      if (pkg) parents.get(parent).add(pkg);
    });
  });
  if (!parents.size) return "";
  const parentNames = [...parents.keys()];
  const summary =
    parentNames.length <= 3
      ? parentNames.join("、")
      : `${parentNames.slice(0, 3).join("、")} 等 ${parentNames.length} 个`;
  return `其中部分风险项属于被父依赖（${summary}）锁定的嵌套副本，需先升级父依赖才能生效。`;
}

function outdatedDetailText(outdatedItems) {
  const total = (outdatedItems || []).length;
  if (!total) return "";
  const majors = countMajorJumps(outdatedItems);
  const base = `${total} 个依赖有可升级的新版本，建议在后续迭代中逐步安排。`;
  if (majors > 0) {
    return `${base}注意其中 ${majors} 个属于跨大版本升级，需额外关注兼容性。`;
  }
  return base;
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
  const cves = [];
  const ghsas = [];
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
        if (/^CVE-/i.test(id)) {
          if (!cves.some((x) => x.toLowerCase() === id.toLowerCase()))
            cves.push(id);
        } else if (/^GHSA-/i.test(id)) {
          if (!ghsas.some((x) => x.toLowerCase() === id.toLowerCase()))
            ghsas.push(id);
        }
      });
  };

  push(r.cve_id);
  push(r.cve_ids);
  push(r.advisory_id);
  push(r.advisory_ids);
  push(r.aliases);
  push(r.advisory_aliases);

  return [...cves, ...ghsas];
}

function securityIdUrl(id) {
  if (/^CVE-\d{4}-\d+/i.test(id)) {
    return `https://www.cve.org/CVERecord?id=${encodeURIComponent(id.toUpperCase())}`;
  }
  return `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
}

// ---- Signal tags from cve_enrichments ----
function aggregateEnrichments(r) {
  const enrichments = Array.isArray(r.cve_enrichments) ? r.cve_enrichments : [];
  let maxEpss = 0;
  let maxEpssPercentile = 0;
  let epssDate = "";
  const allCweIds = [];
  let kevListed = false;
  let kevDueDate = "";
  let kevDateAdded = "";
  let kevRequiredAction = "";
  let ransomware = false;
  let description = "";
  let publishedAt = "";
  let cvssVector = "";
  let bestCvssVersion = 0;
  let bestCvssScore = 0;
  for (const e of enrichments) {
    if (!e || typeof e !== "object") continue;
    const epss = parseFloat(e.epss) || 0;
    const pct = parseFloat(e.epssPercentile) || 0;
    if (pct > maxEpssPercentile) {
      maxEpss = epss;
      maxEpssPercentile = pct;
      epssDate = e.epssScoreDate || "";
    }
    for (const cwe of Array.isArray(e.cweIds) ? e.cweIds : []) {
      if (cwe && !allCweIds.includes(cwe)) allCweIds.push(cwe);
    }
    if (e.kevListed) kevListed = true;
    if (e.kevDueDate) kevDueDate = e.kevDueDate;
    if (e.kevDateAdded) kevDateAdded = e.kevDateAdded;
    if (e.kevRequiredAction) kevRequiredAction = e.kevRequiredAction;
    if (String(e.kevKnownRansomwareCampaignUse || "").toLowerCase() === "known")
      ransomware = true;
    if (e.description && !description) description = e.description;
    if (e.nvdPublishedAt && (!publishedAt || e.nvdPublishedAt < publishedAt))
      publishedAt = e.nvdPublishedAt;
    const metrics = Array.isArray(e.cvssMetrics) ? e.cvssMetrics : [];
    for (const m of metrics) {
      const v = parseFloat(m.version) || 0;
      if (v > bestCvssVersion && m.vector) {
        bestCvssVersion = v;
        cvssVector = m.vector;
      }
      const s = parseFloat(m.baseScore) || 0;
      if (s > bestCvssScore) bestCvssScore = s;
    }
  }
  return {
    maxEpss,
    maxEpssPercentile,
    epssDate,
    allCweIds,
    kevListed,
    kevDueDate,
    kevDateAdded,
    kevRequiredAction,
    ransomware,
    description,
    publishedAt,
    cvssVector,
    bestCvssScore,
  };
}

function shortDate(iso) {
  if (!iso) return "";
  const m = String(iso).match(/(\d{4})-(\d{2})/);
  return m ? `${m[1]}-${m[2]}` : "";
}

function fullDate(iso) {
  if (!iso) return "";
  const m = String(iso).match(/(\d{4})-(\d{2})-(\d{2})/);
  return m ? `${m[1]}-${m[2]}-${m[3]}` : shortDate(iso);
}

function publishedAgeText(isoDate) {
  if (!isoDate) return "";
  const d = new Date(isoDate);
  const dateStr = fullDate(isoDate);
  if (isNaN(d.getTime())) return dateStr;
  const now = new Date();
  const diffDays = Math.floor((now - d) / (1000 * 60 * 60 * 24));
  if (diffDays < 0) return dateStr;
  if (diffDays < 30) return `${dateStr}（已公开 ${diffDays} 天）`;
  if (diffDays < 365) {
    const months = Math.floor(diffDays / 30);
    return `${dateStr}（已公开 ${months} 个月）`;
  }
  const years = Math.floor(diffDays / 365);
  return `${dateStr}（已公开 ${years} 年+）`;
}

function publishedSignalTag(isoDate) {
  if (!isoDate) return "";
  const d = new Date(isoDate);
  if (isNaN(d.getTime())) return "";
  const diffDays = Math.floor(
    (Date.now() - d.getTime()) / (1000 * 60 * 60 * 24),
  );
  if (diffDays < 0) return "";
  if (diffDays < 30) {
    return '<span class="sig-tag sig-recent">近期公开</span>';
  }
  if (diffDays < 365) {
    const months = Math.max(1, Math.floor(diffDays / 30));
    return `<span class="sig-tag sig-age">已公开 ${months} 个月</span>`;
  }
  return '<span class="sig-tag sig-old">公开超1年</span>';
}

function parseCvssVector(vectorStr) {
  const result = {};
  if (!vectorStr) return result;
  String(vectorStr)
    .split("/")
    .forEach((part) => {
      const idx = part.indexOf(":");
      if (idx > 0) result[part.slice(0, idx)] = part.slice(idx + 1);
    });
  return result;
}

function attackConditionSentence(vectorStr) {
  const v = parseCvssVector(vectorStr);
  const parts = [];
  const avText = {
    N: "攻击者可从公网直接利用此漏洞",
    A: "攻击者需在同一网络内才能利用此漏洞",
    L: "攻击者需本地访问才能利用此漏洞",
    P: "攻击者需物理接触设备才能利用此漏洞",
  };
  const prText = {
    N: "无需登录或权限",
    L: "仅需普通用户权限",
    H: "需要管理员权限",
  };
  const uiText = { N: "无需用户配合", R: "需要用户配合操作" };
  const acText = { L: "利用难度低", H: "利用难度较高", M: "利用难度中等" };
  if (v.AV && avText[v.AV]) parts.push(avText[v.AV]);
  if (v.PR && prText[v.PR]) parts.push(prText[v.PR]);
  if (v.UI && uiText[v.UI]) parts.push(uiText[v.UI]);
  if (v.AC && acText[v.AC]) parts.push(acText[v.AC]);
  if (!parts.length) return "";
  return parts.join("，") + "。";
}

function attackConditionTags(vectorStr) {
  const v = parseCvssVector(vectorStr);
  const tags = [];
  const avMap = {
    N: {
      t: "远程可达",
      d: "攻击者可通过网络直接利用，不需要物理接触或内网访问",
    },
    A: {
      t: "相邻网络",
      d: "攻击者需要在同一网络内（如局域网、蓝牙）才能利用",
    },
    L: { t: "本地访问", d: "攻击者需要本地访问或安装恶意软件才能利用" },
    P: { t: "物理接触", d: "攻击者需要物理接触设备才能利用" },
  };
  if (v.AV && avMap[v.AV])
    tags.push(
      `<span class="cvss-tag" title="${esc(avMap[v.AV].d)}">${avMap[v.AV].t}</span>`,
    );
  const acMap = {
    L: { t: "低复杂度", d: "利用条件简单，不需要特殊配置或时机" },
    H: { t: "高复杂度", d: "利用需要特定条件，如竞态条件或特殊配置" },
    M: { t: "中等复杂度", d: "利用难度中等，需要一定条件" },
  };
  if (v.AC && acMap[v.AC])
    tags.push(
      `<span class="cvss-tag" title="${esc(acMap[v.AC].d)}">${acMap[v.AC].t}</span>`,
    );
  const prMap = {
    N: { t: "无需权限", d: "攻击者不需要任何认证或权限即可利用" },
    L: { t: "低权限", d: "攻击者需要普通用户级别的权限" },
    H: { t: "高权限", d: "攻击者需要管理员级别的权限才能利用" },
  };
  if (v.PR && prMap[v.PR])
    tags.push(
      `<span class="cvss-tag" title="${esc(prMap[v.PR].d)}">${prMap[v.PR].t}</span>`,
    );
  const uiMap = {
    N: { t: "无需交互", d: "不需要受害者进行任何操作即可触发漏洞" },
    R: { t: "需要交互", d: "需要受害者进行点击、打开链接等操作才能触发" },
  };
  if (v.UI && uiMap[v.UI])
    tags.push(
      `<span class="cvss-tag" title="${esc(uiMap[v.UI].d)}">${uiMap[v.UI].t}</span>`,
    );
  if (!tags.length) return "";
  return tags.join("");
}

function riskBadgeRow(a) {
  const tags = [];
  if (a.kevListed) {
    tags.push(
      '<span class="sig-tag sig-kev" title="已被 CISA 列入已知被利用漏洞目录">KEV 已知利用</span>',
    );
  }
  if (a.ransomware) {
    tags.push(
      '<span class="sig-tag sig-ransom" title="已知被勒索软件利用">勒索攻击</span>',
    );
  }
  if (a.maxEpss > 0 || a.maxEpssPercentile > 0) {
    const pct = (a.maxEpssPercentile * 100).toFixed(1);
    const prob = (a.maxEpss * 100).toFixed(2);
    tags.push(
      `<span class="sig-tag sig-epss" title="EPSS 百分位 ${esc(pct)}%，30 天内被利用概率 ${esc(prob)}%">EPSS ${esc(pct)}%</span>`,
    );
  }
  if (a.bestCvssScore > 0) {
    const cls =
      a.bestCvssScore >= 9
        ? "sig-cvss-crit"
        : a.bestCvssScore >= 7
          ? "sig-cvss-high"
          : a.bestCvssScore >= 4
            ? "sig-cvss-med"
            : "sig-cvss-low";
    tags.push(
      `<span class="sig-tag ${cls}">CVSS ${a.bestCvssScore.toFixed(1)}</span>`,
    );
  }
  for (const cwe of a.allCweIds.slice(0, 3)) {
    tags.push(`<span class="sig-tag sig-cwe">${esc(cwe)}</span>`);
  }
  if (a.publishedAt) {
    const tag = publishedSignalTag(a.publishedAt);
    if (tag) tags.push(tag);
  }
  if (!tags.length) return "";
  return `<div class="signal-tags">${tags.join("")}</div>`;
}

function ciaImpactTags(vectorStr) {
  const v = parseCvssVector(vectorStr);
  const tags = [];
  const levelMap = { H: "高", L: "低", N: "无", C: "高", P: "低" };
  const cDesc = {
    H: "可能导致敏感数据泄露给未授权方",
    L: "可能泄露部分非关键信息",
    N: "不影响数据机密性",
  };
  const iDesc = {
    H: "攻击者可篡改或破坏重要数据",
    L: "可能造成轻微数据篡改",
    N: "不影响数据完整性",
  };
  const aDesc = {
    H: "可能导致服务完全不可用",
    L: "可能导致服务短暂中断",
    N: "不影响服务可用性",
  };
  if (v.C && levelMap[v.C])
    tags.push(
      `<span class="cia-tag cia-${v.C.toLowerCase()}" title="${esc(cDesc[v.C] || cDesc.N || "")}">机密性 ${levelMap[v.C]}</span>`,
    );
  if (v.I && levelMap[v.I])
    tags.push(
      `<span class="cia-tag cia-${v.I.toLowerCase()}" title="${esc(iDesc[v.I] || iDesc.N || "")}">完整性 ${levelMap[v.I]}</span>`,
    );
  if (v.A && levelMap[v.A])
    tags.push(
      `<span class="cia-tag cia-${v.A.toLowerCase()}" title="${esc(aDesc[v.A] || aDesc.N || "")}">可用性 ${levelMap[v.A]}</span>`,
    );
  if (!tags.length) return "";
  return tags.join("");
}

function detailField(label, valueHtml) {
  return `<section class="detail-field"><div class="detail-label">${esc(label)}</div><div class="detail-value">${valueHtml}</div></section>`;
}

function detailAction(r) {
  const target = shortFixedVersionText(r);
  const followUp =
    target.includes("建议升级到")
      ? "升级后重新扫描，并完成核心流程兼容性验证。"
      : "处理完成后重新扫描，确认风险状态已经关闭。";
  return `<div class="detail-action"><div class="detail-action-label">建议处理</div><div class="detail-action-text">${esc(target)}${esc(followUp)}</div></div>`;
}

function detailStory(label, valueHtml, actionHtml) {
  const action = actionHtml || "";
  return `<section class="detail-story"><div class="detail-label">${esc(label)}</div><div class="detail-value">${valueHtml}</div>${action}</section>`;
}

function signalTags(r) {
  const a = aggregateEnrichments(r);
  const tags = [];
  if (a.kevListed) {
    tags.push('<span class="sig-tag sig-kev">KEV 已知利用</span>');
  }
  if (a.ransomware) {
    tags.push('<span class="sig-tag sig-ransom">勒索攻击</span>');
  }
  if (a.maxEpss > 0 || a.maxEpssPercentile > 0) {
    const pct = (a.maxEpssPercentile * 100).toFixed(1);
    tags.push(`<span class="sig-tag sig-epss">EPSS ${esc(pct)}%</span>`);
  }
  if (a.kevDueDate) {
    const d = shortDate(a.kevDueDate);
    tags.push(`<span class="sig-tag sig-due">KEV 截止 ${esc(d)}</span>`);
  }
  if (!tags.length) return "";
  return `<div class="signal-tags">${tags.join("")}</div>`;
}

function vulnDetailPanel(r) {
  const a = aggregateEnrichments(r);
  const fields = [];
  let story = "";

  const badges = riskBadgeRow(a);

  if (a.description) {
    story = detailStory("漏洞描述", esc(a.description), detailAction(r));
  }

  if (a.publishedAt) {
    fields.push(
      detailField("发布时间", esc(publishedAgeText(a.publishedAt))),
    );
  }

  if (a.cvssVector) {
    const sentence = attackConditionSentence(a.cvssVector);
    const atkTags = attackConditionTags(a.cvssVector);
    if (sentence || atkTags) {
      const sentenceHtml = sentence
        ? `<div class="attack-sentence">${esc(sentence)}</div>`
        : "";
      const tagsHtml = atkTags
        ? `<div class="attack-tags">${atkTags}</div>`
        : "";
      fields.push(
        detailField("攻击条件", `${sentenceHtml}${tagsHtml}`),
      );
    }
    const ciaTags = ciaImpactTags(a.cvssVector);
    if (ciaTags) {
      fields.push(
        detailField("影响维度", `<div class="impact-tags">${ciaTags}</div>`),
      );
    }
  }

  if (a.maxEpss > 0) {
    const prob = (a.maxEpss * 100).toFixed(2);
    const pct = (a.maxEpssPercentile * 100).toFixed(1);
    const dateStr = shortDate(a.epssDate);
    fields.push(
      detailField(
        "EPSS 利用预测",
        `30 天内被利用概率 <b>${esc(prob)}%</b>，百分位 ${esc(pct)}%${dateStr ? "（评分日期 " + esc(dateStr) + "）" : ""}`,
      ),
    );
  }

  if (a.kevListed) {
    const parts = ["已被 CISA 列入已知被利用漏洞目录"];
    if (a.kevDateAdded)
      parts.push(`收录日期 ${esc(shortDate(a.kevDateAdded))}`);
    if (a.kevDueDate) parts.push(`修复截止 ${esc(shortDate(a.kevDueDate))}`);
    if (a.kevRequiredAction) parts.push(esc(a.kevRequiredAction));
    fields.push(
      detailField("CISA KEV", parts.join("；")),
    );
  }

  if (!story && !fields.length && !badges) return "";
  const header = badges
    ? `<div class="vuln-detail-header"><span>关键信号</span>${badges}</div>`
    : "";
  const facts = fields.length ? `<div class="detail-facts">${fields.join("")}</div>` : "";
  const body =
    story || facts ? `<div class="detail-dossier">${story}${facts}</div>` : "";
  return `<div class="vuln-detail">${header}${body}</div>`;
}

// ---- Overview ----
function renderOverview(proj, rs) {
  document.getElementById("meta").textContent = DATA.generated_at
    ? `生成于 ${DATA.generated_at}${DATA.total_seconds ? "　·　总耗时 " + DATA.total_seconds + "s" : DATA.scan_seconds ? "　·　扫描耗时 " + DATA.scan_seconds + "s" : ""}`
    : "";

  // Top severity: highest visible non-zero level from risk_summary.
  const severityOrder = ["critical", "high", "medium", "low", "info"];
  let topSeverity = "";
  for (const s of severityOrder) {
    if (rs && rs[s] && rs[s] > 0) {
      topSeverity = s;
      break;
    }
  }

  const total =
    (rs && rs.critical + rs.high + rs.medium + rs.low + rs.info) || 0;
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
    total > 0
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
  ${crit ? `<span class="pill"><span class="dot" style="background:var(--critical)"></span>紧急 <b>${crit}</b></span>` : ""}
  ${high ? `<span class="pill"><span class="dot" style="background:var(--high)"></span>高风险 <b>${high}</b></span>` : ""}
  ${med ? `<span class="pill"><span class="dot" style="background:var(--medium)"></span>中风险 <b>${med}</b></span>` : ""}
  ${low ? `<span class="pill"><span class="dot" style="background:var(--low)"></span>低风险 <b>${low}</b></span>` : ""}
  ${info ? `<span class="pill"><span class="dot" style="background:var(--info)"></span>待确认 <b>${info}</b></span>` : ""}
</div>`
    : "";

  return `<div class="overview">
  <div class="stats">
    <div class="stat"><div class="k">项目</div><div class="v">${esc(proj.name)}</div></div>
    <div class="stat"><div class="k">生态</div><div class="v">${(proj.ecosystems || []).map(esc).join(", ") || "未检测到"}</div></div>
    <div class="stat"><div class="k">依赖数</div><div class="v">${proj.total_packages || 0}</div></div>
    <div class="stat"><div class="k">风险等级</div><div class="v">${topSeverity ? sevBadge(topSeverity) : '<span style="color:var(--sub)">无</span>'}</div></div>
  </div>
  <div class="bar-label">风险项分布</div>
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

function measuredTextLength(value) {
  return Array.from(String(value || "")).length;
}

function columnWidth(rows, getter, min, max, charWidth, padding) {
  const maxChars = (rows || []).reduce((longest, row) => {
    return Math.max(longest, measuredTextLength(getter(row)));
  }, 0);
  return Math.min(max, Math.max(min, maxChars * charWidth + padding));
}

function packageColumnWidth(rows) {
  const maxChars = (rows || []).reduce((max, row) => {
    return Math.max(max, measuredTextLength(packageNameFor(row)));
  }, 4);
  return Math.min(260, Math.max(132, maxChars * 8 + 30));
}

function packageColumnWidthStyle(rows) {
  const px = packageColumnWidth(rows);
  return `--package-col:${px}px;`;
}

function outdatedColumnWidthStyle(rows) {
  const packagePx = packageColumnWidth(rows);
  const currentPx = columnWidth(
    rows,
    (row) => row && (row.current || row.version),
    112,
    180,
    9,
    40,
  );
  const latestPx = columnWidth(
    rows,
    (row) => row && outdatedDisplayTarget(row),
    112,
    180,
    9,
    40,
  );
  const targetLeadPx = Math.max(
    620,
    Math.min(760, packagePx + currentPx + latestPx + 240),
  );
  const spacerPx = Math.max(0, targetLeadPx - packagePx - currentPx - latestPx);
  const currentWithSpacePx = currentPx + Math.floor(spacerPx / 2);
  const latestWithSpacePx = latestPx + Math.ceil(spacerPx / 2);
  return [
    `--package-col:${packagePx}px`,
    `--outdated-current-col:${currentWithSpacePx}px`,
    `--outdated-latest-col:${latestWithSpacePx}px`,
  ].join(";");
}

function renderTableColgroup(columns) {
  return `<colgroup>${columns
    .map((column) => `<col class="col-${esc(column)}">`)
    .join("")}</colgroup>`;
}

// ---- Vulnerability table (all items) ----

function renderVulnTable(rows) {
  if (!rows || !rows.length) {
    if (DATA.scan_config && DATA.scan_config.scan_mode === "hygiene_only") {
      return section(
        "当前风险",
        null,
        `<div class="summary vuln-empty">${miniFields([
          { label: "扫描范围", value: HYGIENE_ONLY_NOTICE },
          {
            label: "结论口径",
            value:
              "这不是依赖漏洞扫描通过，而是本次未执行依赖漏洞扫描。仓库安检结论仍可参考。",
          },
        ])}</div>`,
        "",
        "search",
      );
    }
    return section(
      "当前风险",
      0,
      `<div class="empty">未命中已确认的依赖风险项。</div>`,
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
      const extraCls = needToggle && idx >= VULN_SHOW ? " vuln-extra" : "";
      const fixedHtml = fixedVersionHtml(r);
      const detail = vulnDetailPanel(r);
      const hasDetail = detail ? " vuln-row" : "";
      const clickAttr = detail ? ` onclick="toggleVulnDetail(this)"` : "";
      const detailRow = detail
        ? `<tr class="vuln-detail-row${extraCls}"><td colspan="6">${detail}</td></tr>`
        : "";
      return `<tr class="${hasDetail}${extraCls}"${clickAttr}>
  <td class="sev" data-label="影响程度">${sevBadge(r.severity)}</td>
  <td class="package-cell" data-label="依赖名称"><b title="${esc(packageName)}">${esc(packageName)}</b></td>
  <td class="ver" data-label="当前版本">${esc(r.version || "")}</td>
  <td class="ver fixed-cell" data-label="修复版本">${fixedHtml}</td>
  <td class="advisory" data-label="安全编号">${advHtml}</td>
  <td class="summary-cell" data-label="详情">${vulnerabilityExplanation(r)}</td>
</tr>${detailRow}`;
    })
    .join("");
  const toggle = needToggle
    ? `<tr class="vuln-toggle"><td colspan="6"><button class="fix-btn open" onclick="toggleVulns(this)">显示更多（还有 ${sortedRows.length - VULN_SHOW} 项）</button></td></tr>`
    : "";
  return section(
    "当前风险",
    sortedRows.length,
    `<div class="table-scroll"><table class="stable-table vuln-table" style="${packageColumnWidthStyle(sortedRows)}">
  ${renderTableColgroup(["severity", "package", "version", "fixed", "advisory", "summary"])}
  <thead><tr><th>影响程度</th><th>依赖名称</th><th>当前版本</th><th>修复版本</th><th>安全编号</th><th>详情</th></tr></thead>
  <tbody>${body}${toggle}</tbody></table></div>`,
    "",
    "search",
  );
}

function toggleVulns(btn) {
  const table = btn.closest("table");
  table.classList.toggle("vuln-expanded");
  const expanded = table.classList.contains("vuln-expanded");
  const rows = table.querySelectorAll(".vuln-extra:not(.vuln-detail-row)");
  btn.setAttribute("aria-expanded", expanded ? "true" : "false");
  btn.textContent = expanded ? "收起" : `显示更多（还有 ${rows.length} 项）`;
}

function toggleVulnDetail(tr) {
  const next = tr.nextElementSibling;
  if (!next || !next.classList.contains("vuln-detail-row")) return;
  const open = next.classList.toggle("vuln-detail-open");
  tr.classList.toggle("vuln-row-open", open);
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
    `<div class="summary">${tldr}${boundary}${detail}${body}</div>`,
    "",
    "advice",
  );
}

// ---- Repository security checks ----
const SECRET_TYPE_LABELS = {
  aws_access_key: "AWS 访问密钥",
  aws_secret_key: "AWS Secret Key",
  gcp_service_account: "GCP 服务账号",
  gcp_api_key: "GCP API Key",
  azure_client_secret: "Azure 客户端密钥",
  aliyun_access_key: "阿里云 AccessKey",
  tencent_secret_id: "腾讯云 SecretId",
  huawei_access_key: "华为云 Access Key",
  oracle_api_key: "Oracle API Key",
  github_token: "GitHub Token",
  github_fine_grained_pat: "GitHub fine-grained PAT",
  gitlab_token: "GitLab Token",
  gitlab_runner_token: "GitLab Runner Token",
  gitlab_deploy_token: "GitLab Deploy Token",
  slack_token: "Slack Token",
  discord_bot_token: "Discord Bot Token",
  stripe_secret_key: "Stripe 密钥",
  openai_key: "OpenAI API Key",
  anthropic_key: "Anthropic API Key",
  groq_api_key: "Groq API Key",
  hashicorp_vault_token: "HashiCorp Vault Token",
  pulumi_token: "Pulumi Token",
  cloudflare_api_token: "Cloudflare API Token",
  vercel_token: "Vercel Token",
  netlify_token: "Netlify Token",
  railway_token: "Railway Token",
  render_token: "Render Token",
  snyk_token: "Snyk Token",
  resend_api_key: "Resend API Key",
  clerk_secret_key: "Clerk Secret Key",
  supabase_service_role_key: "Supabase service-role key",
  algolia_admin_key: "Algolia Admin API Key",
  generic_sk_key: "LLM/API 密钥 (sk-)",
  generic_password: "疑似密码",
  generic_api_key: "疑似 API Key",
  generic_token: "疑似 Token",
  generic_secret: "疑似 Secret",
  bearer_token: "Bearer Token",
  private_key: "私钥",
  jwt_token: "JWT Token",
  webhook_url: "Webhook URL",
  basic_auth_url: "URL 内嵌账号密码",
  netrc_password: ".netrc 机器密码",
};
const SENSITIVE_TYPE_LABELS = {
  env_file: "环境变量文件",
  private_key: "私钥或证书文件",
  database: "本地数据库或转储文件",
  log: "日志文件",
  credentials: "凭证文件",
  ssh_key: "SSH 私钥",
};

function renderHygiene(h) {
  h = h || {};
  if (h.skipped || (DATA.scan_config && DATA.scan_config.skip_hygiene)) {
    return section(
      "仓库安检",
      null,
      `<div class="summary hygiene-summary">${miniFields([
        { label: "事实", value: "本次跳过了仓库安检。" },
        {
          label: "为什么要关注",
          value:
            "仓库安检主要看密钥、敏感文件和 .gitignore，跳过后这部分不能作为最终结论。",
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
  const localGroups = [
    ["GitHub Actions 工作流安全", toList(h.workflow_checks)],
    ["依赖配置与维护", toList(h.repository_checks)],
    ["IaC / 容器 / 部署配置", toList(h.iac_checks)],
  ];
  const localCount = localGroups.reduce(
    (sum, [, items]) => sum + items.length,
    0,
  );
  const count = secrets.length + sensitive.length + missing.length + localCount;
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
  if (!rows.length && !localCount) {
    return "";
  }

  const basicFindingItems = [
    ...secrets.slice(0, 5).map((x) => {
      const loc = `${x.file || "-"}${x.line ? ":" + x.line : ""}`;
      const label = SECRET_TYPE_LABELS[x.type] || x.type || "密钥";
      const preview = x.preview
        ? `<code class="secret-preview">${esc(x.preview)}</code>`
        : "";
      return `<div class="finding-item"><span class="finding-loc">${esc(loc)}</span><span class="finding-type">${esc(label)}</span>${preview}</div>`;
    }),
    ...sensitive.slice(0, 5).map((x) => {
      const loc = `${x.file || "-"}`;
      const label = SENSITIVE_TYPE_LABELS[x.type] || x.type || "敏感文件";
      return `<div class="finding-item"><span class="finding-loc">${esc(loc)}</span><span class="finding-type">${esc(label)}</span></div>`;
    }),
  ];
  const basicTotal = secrets.length + sensitive.length;
  const basicShown =
    Math.min(secrets.length, 5) + Math.min(sensitive.length, 5);
  const basicExtra =
    basicTotal > basicShown
      ? `<div class="finding-more">…及其他 ${basicTotal - basicShown} 处</div>`
      : "";
  const basicFindings = basicFindingItems.length
    ? `<div class="field"><div class="label">凭证与敏感文件</div><div class="finding-list">${basicFindingItems.join("")}${basicExtra}</div></div>`
    : "";

  const localGroupHtml = localGroups
    .filter(([, items]) => items.length)
    .map(([groupLabel, items]) => {
      const cards = items
        .slice(0, 8)
        .map((x) => {
          const loc = `${x.file || "-"}${x.line ? ":" + x.line : ""}`;
          const badge =
            x.kind === "maintenance_advice"
              ? `<span class="sev-badge sev-low">建议</span>`
              : sevBadge(x.severity);
          const evidence =
            x.evidence && x.kind !== "maintenance_advice"
              ? `<div class="hygiene-finding-note hygiene-finding-context">${esc(x.evidence)}</div>`
              : "";
          const recommendation = x.recommendation
            ? `<p class="hygiene-finding-advice">${esc(x.recommendation)}</p>`
            : "";
          return `<article class="hygiene-finding"><div class="hygiene-finding-top"><div class="hygiene-finding-title">${badge}<b>${esc(x.title || x.id || "仓库安检项")}</b></div><div class="hygiene-finding-loc">${esc(loc)}</div></div><div class="hygiene-finding-body">${evidence}${recommendation}</div></article>`;
        })
        .join("");
      const groupMore =
        items.length > 8
          ? `<div class="finding-more">…及其他 ${items.length - 8} 处</div>`
          : "";
      return `<div class="hygiene-group"><div class="hygiene-group-head"><span>${esc(groupLabel)}</span><b>${items.length} 项</b></div><div class="hygiene-group-list">${cards}${groupMore}</div></div>`;
    })
    .join("");
  const extra = `${basicFindings}${localGroupHtml ? `<div class="hygiene-groups">${localGroupHtml}</div>` : ""}`;
  const rowHtml = rows.length ? miniFields(rows) : "";

  return section(
    "仓库安检",
    count,
    `<div class="summary hygiene-summary">${rowHtml}${extra}</div>`,
    "",
    "hygiene",
  );
}

// ---- Outdated dependencies ----
function renderOutdated(items) {
  items = toList(items);
  if (DATA.scan_config && DATA.scan_config.scan_mode === "hygiene_only") {
    return section(
      "过期依赖",
      null,
      `<div class="summary outdated-empty">${miniFields([
        { label: "扫描范围", value: HYGIENE_ONLY_NOTICE },
        {
          label: "提醒",
          value:
            "本次未执行依赖版本维护检查；需要完整维护视图时，重新扫描并开启过期依赖检查。",
        },
      ])}</div>`,
      "",
      "long",
    );
  }
  if (DATA.scan_config && DATA.scan_config.skip_outdated) {
    return section(
      "过期依赖",
      null,
      `<div class="summary outdated-empty">${miniFields([
        { label: "事实", value: "本次为了提速跳过了过期依赖检查。" },
        {
          label: "为什么要关注",
          value: "版本长期落后会让未来升级、修复和兼容性验证变得更难。",
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
            "过期依赖用于版本维护规划；处理顺序仍以当前风险项和发布窗口为准。",
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
  <td class="package-cell" data-label="依赖名称"><b title="${esc(packageName)}">${esc(packageName)}</b></td>
  <td class="ver" data-label="当前版本">${esc(current || "-")}</td>
  <td class="ver" data-label="最近版本">${esc(outdatedDisplayTarget(it) || "-")}</td>
  <td class="summary-cell" data-label="建议">${esc(outdatedExplanation(it))}</td>
</tr>`;
    })
    .join("");
  const toggle = needToggle
    ? `<tr class="outdated-toggle"><td colspan="4"><button class="fix-btn open" onclick="toggleOutdated(this)">显示更多（还有 ${items.length - OUTDATED_SHOW} 项）</button></td></tr>`
    : "";
  return section(
    "过期依赖",
    items.length,
    `<div class="table-scroll"><table class="stable-table outdated-table" style="${outdatedColumnWidthStyle(items)}">
  ${renderTableColgroup(["package", "current", "latest", "summary"])}
  <thead><tr><th>依赖名称</th><th>当前版本</th><th>最近版本</th><th>建议</th></tr></thead>
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
  return section("待确认事项", items.length, cards, "", "review");
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
  return section("优先处理", items.length, cards, "", "risk");
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
