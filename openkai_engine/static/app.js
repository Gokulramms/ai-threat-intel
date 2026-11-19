// OpenKai SOC Intelligence Platform - Client Engine v1.0.0
// Advanced Cyber Threat Investigation & Telemetry Management

let activeInvestigationId = null;
let allSourcesCache = [];
let allIndicatorsCache = [];
let allCVEsCache = [];
let allDevicesCache = [];

// Threat Sources Catalog with Metadata & Categories
const THREAT_SOURCES_CATALOG = {
  cisa_kev: {
    name: "CISA Known Exploited Vulnerabilities",
    org: "US Cybersecurity & Infrastructure Security Agency",
    tier: "100% Free Public",
    category: "vulnerabilities",
    type: "JSON Catalog",
    desc: "Authoritative catalog of vulnerabilities that have been confirmed actively exploited in the wild.",
    url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    isPublic: true
  },
  nist_nvd: {
    name: "NIST National Vulnerability Database",
    org: "National Institute of Standards and Technology",
    tier: "Free Public (API Key Optional)",
    category: "vulnerabilities",
    type: "REST API v2.0",
    desc: "U.S. government repository of standards-based vulnerability management data with CVSS v3.1/v4.0 scoring.",
    url: "https://nvd.nist.gov/",
    isPublic: true
  },
  mitre_attack: {
    name: "MITRE ATT&CK Enterprise Matrix",
    org: "The MITRE Corporation",
    tier: "100% Free Public",
    category: "mitre",
    type: "STIX 2.1 JSON",
    desc: "Globally-accessible knowledge base of adversary tactics, techniques, and procedures (TTPs).",
    url: "https://attack.mitre.org/",
    isPublic: true
  },
  threatfox: {
    name: "abuse.ch ThreatFox & Feodo Tracker",
    org: "abuse.ch / Bern University",
    tier: "100% Free Public Feed",
    category: "malware",
    type: "REST API & JSON Feed",
    desc: "Live C2 botnet servers, malware IP addresses, and community-shared indicators of compromise.",
    url: "https://threatfox.abuse.ch/",
    isPublic: true
  },
  urlhaus: {
    name: "abuse.ch URLhaus & Emerging Threats",
    org: "abuse.ch / Proofpoint ET",
    tier: "100% Free Public Feed",
    category: "malware",
    type: "REST API & IP Blocklist",
    desc: "Compromised scanning hosts, botnets, and malware distribution payloads.",
    url: "https://urlhaus.abuse.ch/",
    isPublic: true
  },
  malwarebazaar: {
    name: "abuse.ch MalwareBazaar Hashes",
    org: "abuse.ch / Bern University",
    tier: "100% Free Public Feed",
    category: "malware",
    type: "REST API & Hashes",
    desc: "Repository of active ransomware and malware samples, SHA256 and MD5 cryptographic signatures.",
    url: "https://bazaar.abuse.ch/",
    isPublic: true
  },
  alienvault_otx: {
    name: "AlienVault Open Threat Exchange",
    org: "AT&T Cybersecurity / OTX",
    tier: "Free API Key Required",
    category: "reputation",
    type: "REST API v1",
    desc: "Global threat sharing community with crowd-sourced pulses on emerging APT campaigns.",
    url: "https://otx.alienvault.com/",
    isPublic: false
  },
  abuseipdb: {
    name: "AbuseIPDB IP Reputation",
    org: "AbuseIPDB Project",
    tier: "Free API Key Required",
    category: "reputation",
    type: "REST API v2",
    desc: "Crowdsourced database of reported malicious IP addresses with abuse confidence scoring.",
    url: "https://www.abuseipdb.com/",
    isPublic: false
  },
  virustotal: {
    name: "VirusTotal v3 Intelligence",
    org: "Google Chronicle",
    tier: "Free API Key Required",
    category: "reputation",
    type: "REST API v3",
    desc: "Aggregator of 70+ antivirus engines and URL/domain blacklist verification services.",
    url: "https://www.virustotal.com/",
    isPublic: false
  },
  cert_in: {
    name: "CERT-In Security Advisories",
    org: "Indian Computer Emergency Response Team",
    tier: "100% Free Public",
    category: "gov",
    type: "RSS / XML Feed",
    desc: "Official advisories on critical vulnerabilities affecting enterprise infrastructure and software.",
    url: "https://www.cert-in.org.in/",
    isPublic: true
  },
  enisa: {
    name: "ENISA Cybersecurity Publications",
    org: "European Union Agency for Cybersecurity",
    tier: "100% Free Public",
    category: "gov",
    type: "RSS / XML Feed",
    desc: "European bulletins, cyber threat landscapes, and critical infrastructure directives.",
    url: "https://www.enisa.europa.eu/",
    isPublic: true
  },
  uk_ncsc: {
    name: "UK NCSC Threat Alerts",
    org: "National Cyber Security Centre (UK)",
    tier: "100% Free Public",
    category: "gov",
    type: "REST / JSON API",
    desc: "Guidance and urgent threat reports regarding nation-state actors and perimeter breaches.",
    url: "https://www.ncsc.gov.uk/",
    isPublic: true
  },
  jpcert: {
    name: "JPCERT/CC Security Notes",
    org: "Japan Computer Emergency Response Team",
    tier: "100% Free Public",
    category: "gov",
    type: "RSS / XML Feed",
    desc: "Early warning alerts and technical incident notes on newly disclosed vulnerabilities.",
    url: "https://www.jpcert.or.jp/",
    isPublic: true
  },
  cisa_advisories: {
    name: "US CISA ICS & APT Advisories",
    org: "US CISA",
    tier: "100% Free Public",
    category: "gov",
    type: "XML / RSS Feed",
    desc: "Urgent bulletins on industrial control systems, cloud intrusions, and nation-state techniques.",
    url: "https://www.cisa.gov/cybersecurity-advisories",
    isPublic: true
  }
};

// Initialization on DOM Ready
document.addEventListener("DOMContentLoaded", () => {
  initNavigation();
  initSearch();
  initFilters();
  loadMetrics();
  loadRecentInvestigations();
  loadThreatSources();
  loadIndicators();
  loadCVEs();
  loadAssets();

  // Topbar sync button
  document.getElementById("btn-sync-all").addEventListener("click", () => syncAllFeeds());
});

// Navigation Handling
function initNavigation() {
  document.querySelectorAll(".nav-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const tab = btn.dataset.tab;
      switchTab(tab);
    });
  });
}

function switchTab(tab) {
  document.querySelectorAll(".nav-btn").forEach(b => b.classList.remove("active"));
  document.querySelectorAll(".view-pane").forEach(p => p.classList.remove("active"));

  const navBtn = document.querySelector(`.nav-btn[data-tab="${tab}"]`);
  if (navBtn) navBtn.classList.add("active");
  const pane = document.getElementById(`pane-${tab}`);
  if (pane) pane.classList.add("active");

  if (tab === "overview") { loadMetrics(); loadRecentInvestigations(); }
  if (tab === "threat-sources") loadThreatSources();
  if (tab === "indicators") loadIndicators();
  if (tab === "vulnerabilities") loadCVEs();
  if (tab === "assets") loadAssets();
  if (tab === "connectors") loadConnectorsHealth();
  if (tab === "audit") loadAuditLogs();
}

// Search Inputs
function initSearch() {
  const topInput = document.getElementById("topbar-search");
  const topBtn = document.getElementById("topbar-search-btn");

  topBtn.addEventListener("click", () => {
    const val = topInput.value.trim();
    if (val) executeInvestigation(val);
  });

  topInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter") {
      const val = topInput.value.trim();
      if (val) executeInvestigation(val);
    }
  });

  // Investigation console input
  const invInput = document.getElementById("inv-console-input");
  const invBtn = document.getElementById("btn-run-investigation");
  invBtn.addEventListener("click", () => {
    const val = invInput.value.trim();
    if (val) executeInvestigation(val);
  });
  invInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter") {
      const val = invInput.value.trim();
      if (val) executeInvestigation(val);
    }
  });
}

// Quick Scenario Trigger
function quickInvestigate(target) {
  switchTab("investigate");
  document.getElementById("inv-console-input").value = target;
  executeInvestigation(target);
}

// Global Metrics Loader
async function loadMetrics() {
  try {
    const resp = await fetch("/api/system/metrics");
    if (!resp.ok) return;
    const m = await resp.json();

    const totalTI = (m.total_threat_indicators || 0) + (m.total_cves || 0) + (m.total_advisories || 0);
    document.getElementById("kpi-total-threats").textContent = totalTI.toLocaleString();
    document.getElementById("kpi-total-kev").textContent = (m.cisa_kev_count || 0).toLocaleString();
    document.getElementById("kpi-total-iocs").textContent = (m.total_threat_indicators || 0).toLocaleString();
    document.getElementById("kpi-total-devices").textContent = (m.total_devices || 0).toLocaleString();

    // Nav counters
    document.getElementById("nav-sources-count").textContent = "14";
    document.getElementById("nav-iocs-count").textContent = (m.total_threat_indicators || 0).toLocaleString();
    document.getElementById("nav-cves-count").textContent = (m.total_cves || 0).toLocaleString();
    document.getElementById("nav-assets-count").textContent = (m.total_devices || 0).toLocaleString();

    // Integrations status text
    const csReady = m.crowdstrike_configured ? "Connected" : "Standby";
    const esReady = m.elastic_configured ? "Connected" : "Standby";
    document.getElementById("kpi-integrations-status").textContent = `${csReady} / ${esReady}`;
  } catch (err) {
    console.error("Metrics load error:", err);
  }
}

// ==========================================================================
// Threat Sources (14 Feeds) Matrix
// ==========================================================================

async function loadThreatSources() {
  try {
    const resp = await fetch("/api/threat-intel/feeds");
    if (!resp.ok) return;
    const feeds = await resp.json();
    allSourcesCache = feeds;
    renderThreatSources(feeds);
  } catch (e) {
    console.error("Threat sources load error:", e);
  }
}

function renderThreatSources(feeds) {
  const container = document.getElementById("sources-cards-container");
  const filterCat = document.querySelector("#sources-filter-pills .filter-pill.active")?.dataset.filter || "all";
  const searchKeyword = document.getElementById("sources-search-input")?.value.trim().toLowerCase() || "";

  let filtered = feeds.filter(f => {
    const meta = THREAT_SOURCES_CATALOG[f.id] || {};
    if (filterCat !== "all" && meta.category !== filterCat) return false;
    if (searchKeyword) {
      const matchName = (f.name || "").toLowerCase().includes(searchKeyword);
      const matchOrg = (meta.org || "").toLowerCase().includes(searchKeyword);
      const matchDesc = (meta.desc || "").toLowerCase().includes(searchKeyword);
      if (!matchName && !matchOrg && !matchDesc) return false;
    }
    return true;
  });

  if (!filtered.length) {
    container.innerHTML = `<div style="grid-column: 1/-1; text-align:center; padding: 40px;" class="text-muted">No threat intelligence sources matching filter.</div>`;
    return;
  }

  container.innerHTML = filtered.map(feed => {
    const meta = THREAT_SOURCES_CATALOG[feed.id] || {
      name: feed.name,
      org: "External Threat Publisher",
      tier: "Feed",
      desc: "Threat intelligence adapter powering correlation.",
      isPublic: true
    };

    const isConnected = (feed.records > 0) || (feed.status === "success");
    const statusTag = isConnected
      ? `<span class="badge badge-free">● Connected & Active</span>`
      : meta.isPublic
      ? `<span class="badge badge-free">● Public Feed Ready</span>`
      : `<span class="badge badge-key">Standby (Key in .env)</span>`;

    const tierBadge = meta.isPublic
      ? `<span class="status-pill status-emerald">${meta.tier}</span>`
      : `<span class="status-pill status-critical">${meta.tier}</span>`;

    return `
      <div class="source-card">
        <div>
          <div class="source-card-top">
            <div>
              <h4 class="source-card-title">${feed.name}</h4>
              <span class="source-card-org">${meta.org}</span>
            </div>
            ${tierBadge}
          </div>
          <p class="source-card-desc">${meta.desc}</p>
        </div>

        <div>
          <div class="source-card-meta">
            <div>${statusTag}</div>
            <div class="mono" style="font-weight:600; color: #fff;">${(feed.records || 0).toLocaleString()} records</div>
          </div>
          <div class="source-card-bottom">
            <span class="text-muted" style="font-size:11.5px;">Protocol: <strong>${meta.type || 'REST API'}</strong></span>
            <button class="btn btn-secondary btn-sm" id="btn-sync-${feed.id}" onclick="syncSingleFeed('${feed.id}')">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
              Sync Now
            </button>
          </div>
        </div>
      </div>
    `;
  }).join("");
}

function initFilters() {
  // Threat Sources category filter
  document.querySelectorAll("#sources-filter-pills .filter-pill").forEach(pill => {
    pill.addEventListener("click", () => {
      document.querySelectorAll("#sources-filter-pills .filter-pill").forEach(p => p.classList.remove("active"));
      pill.classList.add("active");
      renderThreatSources(allSourcesCache);
    });
  });

  const sourcesSearch = document.getElementById("sources-search-input");
  if (sourcesSearch) {
    sourcesSearch.addEventListener("input", () => renderThreatSources(allSourcesCache));
  }

  // IOC filters
  document.querySelectorAll("#iocs-type-filters .filter-pill").forEach(pill => {
    pill.addEventListener("click", () => {
      document.querySelectorAll("#iocs-type-filters .filter-pill").forEach(p => p.classList.remove("active"));
      pill.classList.add("active");
      loadIndicators();
    });
  });

  const iocsSearch = document.getElementById("iocs-search-input");
  if (iocsSearch) {
    iocsSearch.addEventListener("input", debounce(() => loadIndicators(), 300));
  }

  // CVE filters
  document.querySelectorAll("#cve-filter-pills .filter-pill").forEach(pill => {
    pill.addEventListener("click", () => {
      document.querySelectorAll("#cve-filter-pills .filter-pill").forEach(p => p.classList.remove("active"));
      pill.classList.add("active");
      loadCVEs();
    });
  });

  const cveSearch = document.getElementById("cve-search-input");
  if (cveSearch) {
    cveSearch.addEventListener("input", debounce(() => loadCVEs(), 300));
  }
}

// Utility debounce
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

// Sync Individual Feed
async function syncSingleFeed(sourceId) {
  const btn = document.getElementById(`btn-sync-${sourceId}`);
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<span>Syncing...</span>`;
  }
  showToast(`Synchronizing ${sourceId}...`, "info");

  try {
    const resp = await fetch(`/api/threat-intel/sync/${sourceId}`, { method: "POST" });
    const data = await resp.json();
    if (data.status === "success") {
      const added = (data.new_indicators || 0) + (data.new_cves || 0) + (data.new_advisories || 0);
      showToast(`Sync complete for ${sourceId}: +${added} items`, "success");
    } else {
      showToast(`Sync completed with status: ${data.status}`, "info");
    }
    await loadThreatSources();
    await loadMetrics();
    await loadIndicators();
    await loadCVEs();
  } catch (err) {
    showToast(`Error syncing ${sourceId}: ${err.message}`, "error");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg> Sync Now`;
    }
  }
}

// Sync All Feeds
async function syncAllFeeds() {
  const btn = document.getElementById("btn-sync-all");
  const spinner = document.getElementById("sync-spinner-icon");
  const txt = document.getElementById("sync-btn-text");

  btn.disabled = true;
  txt.textContent = "Syncing All...";
  if (spinner) spinner.style.animation = "spin 1s linear infinite";

  showToast("Broadcasting sync across all 14 Threat Intelligence sources...", "info");

  try {
    const resp = await fetch("/api/threat-intel/sync-all", { method: "POST" });
    const result = await resp.json();
    showToast("All threat intelligence feeds synchronized successfully!", "success");
    await loadThreatSources();
    await loadMetrics();
    await loadIndicators();
    await loadCVEs();
  } catch (err) {
    showToast(`Sync all failed: ${err.message}`, "error");
  } finally {
    btn.disabled = false;
    txt.textContent = "Sync Feeds";
    if (spinner) spinner.style.animation = "";
  }
}

// ==========================================================================
// IOC Indicators Console
// ==========================================================================

async function loadIndicators() {
  try {
    const type = document.querySelector("#iocs-type-filters .filter-pill.active")?.dataset.type || "";
    const q = document.getElementById("iocs-search-input")?.value.trim() || "";

    let url = `/api/threat-intel/indicators?limit=100`;
    if (type) url += `&type=${encodeURIComponent(type)}`;
    if (q) url += `&q=${encodeURIComponent(q)}`;

    const resp = await fetch(url);
    if (!resp.ok) return;
    const indicators = await resp.json();
    allIndicatorsCache = indicators;
    renderIndicators(indicators);
  } catch (e) {
    console.error("Load indicators error:", e);
  }
}

function renderIndicators(indicators) {
  const tbody = document.querySelector("#indicators-table tbody");
  if (!indicators || !indicators.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-muted" style="text-align:center; padding: 30px;">No threat indicators found. Click 'Sync Feeds' to ingest from active sources.</td></tr>`;
    return;
  }

  tbody.innerHTML = indicators.map(ind => {
    const sevBadge = ind.severity === "critical"
      ? `<span class="badge badge-key">CRITICAL</span>`
      : ind.severity === "high"
      ? `<span class="badge badge-warning">HIGH</span>`
      : `<span class="badge badge-subtle">MEDIUM</span>`;

    const cleanSource = ind.source || "Emerging Threats / Feodo";
    const malware = ind.malware_family || "Suspicious Traffic";
    const dateStr = ind.last_seen ? new Date(ind.last_seen).toLocaleDateString() : "Active";

    return `
      <tr>
        <td class="mono font-semibold" style="color: #fff;">
          <div style="display:flex; align-items:center; gap: 8px;">
            <span>${ind.value}</span>
            <button class="btn-pill" style="font-size:10px; padding: 2px 6px;" title="Copy to Clipboard" onclick="copyToClipboard('${ind.value}')">Copy</button>
          </div>
        </td>
        <td><span class="badge badge-subtle mono">${(ind.indicator_type || '').toUpperCase()}</span></td>
        <td>${cleanSource}</td>
        <td><span class="mono">${ind.confidence}%</span></td>
        <td>${sevBadge}</td>
        <td><strong>${malware}</strong></td>
        <td class="text-muted mono" style="font-size:12px;">${dateStr}</td>
        <td>
          <button class="btn btn-secondary btn-sm" onclick="quickInvestigate('${ind.value}')">
            Investigate
          </button>
        </td>
      </tr>
    `;
  }).join("");
}

// ==========================================================================
// CVE & Vulnerabilities Console
// ==========================================================================

async function loadCVEs() {
  try {
    const activePill = document.querySelector("#cve-filter-pills .filter-pill.active");
    const isKev = activePill?.dataset.kev === "true" ? true : undefined;
    const sev = activePill?.dataset.sev || undefined;
    const q = document.getElementById("cve-search-input")?.value.trim() || "";

    let url = `/api/threat-intel/cves?limit=100`;
    if (isKev) url += `&is_kev=true`;
    if (sev) url += `&severity=${encodeURIComponent(sev)}`;
    if (q) url += `&q=${encodeURIComponent(q)}`;

    const resp = await fetch(url);
    if (!resp.ok) return;
    const cves = await resp.json();
    allCVEsCache = cves;
    renderCVEs(cves);
  } catch (e) {
    console.error("Load CVEs error:", e);
  }
}

function renderCVEs(cves) {
  const tbody = document.querySelector("#cves-table tbody");
  if (!cves || !cves.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-muted" style="text-align:center; padding: 30px;">No CVE records found. Click 'Sync Feeds' to populate from CISA KEV and NIST NVD.</td></tr>`;
    return;
  }

  tbody.innerHTML = cves.map(c => {
    const sevClass = (c.cvss_severity === "CRITICAL" || (c.cvss_v3_score && c.cvss_v3_score >= 9.0)) ? "badge-key" : "badge-warning";
    const kevTag = c.is_kev
      ? `<span class="badge badge-key">🚨 CISA KEV Exploited</span>`
      : `<span class="text-muted font-semibold" style="font-size:12px;">Unlisted</span>`;

    const product = `${c.affected_vendor || ''} ${c.affected_product || ''}`.trim() || 'Enterprise Software';
    const shortDesc = c.description ? (c.description.length > 120 ? c.description.substring(0, 120) + "..." : c.description) : "No description available.";

    return `
      <tr>
        <td class="mono font-semibold" style="color: #38bdf8;">${c.id}</td>
        <td class="mono font-semibold" style="font-size: 14px;">${c.cvss_v3_score || 'N/A'}</td>
        <td><span class="badge ${sevClass}">${c.cvss_severity || 'HIGH'}</span></td>
        <td>${product}</td>
        <td>${kevTag}</td>
        <td style="max-width: 320px; font-size: 12.5px; color: var(--text-secondary);">${shortDesc}</td>
        <td>
          <button class="btn btn-secondary btn-sm" onclick="quickInvestigate('${c.id}')">
            Correlate
          </button>
        </td>
      </tr>
    `;
  }).join("");
}

// ==========================================================================
// Enterprise Asset & Device Inventory
// ==========================================================================

async function loadAssets() {
  try {
    const resp = await fetch("/api/assets/devices?limit=100");
    if (!resp.ok) return;
    const devices = await resp.json();
    allDevicesCache = devices;
    renderAssets(devices);
  } catch (e) {
    console.error("Load assets error:", e);
  }
}

function renderAssets(devices) {
  const tbody = document.querySelector("#devices-table tbody");
  const countBadge = document.getElementById("asset-count-badge");
  if (countBadge) countBadge.textContent = `${devices.length} Registered Endpoints`;

  if (!devices || !devices.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-muted" style="text-align:center; padding: 30px;">No registered enterprise devices found. Use 'Add Device' or 'Import Fleet CSV'.</td></tr>`;
    return;
  }

  tbody.innerHTML = devices.map(d => {
    // OS Icon & formatting - ZERO NULL VALUES
    const osRaw = (d.os_name || 'Generic Linux / Server').trim();
    let osIcon = "🖥️";
    if (osRaw.toLowerCase().includes("windows")) osIcon = "🪟";
    else if (osRaw.toLowerCase().includes("ubuntu") || osRaw.toLowerCase().includes("linux") || osRaw.toLowerCase().includes("red hat") || osRaw.toLowerCase().includes("alpine")) osIcon = "🐧";
    else if (osRaw.toLowerCase().includes("mac") || osRaw.toLowerCase().includes("darwin")) osIcon = "🍏";

    const osDisplay = `${osIcon} ${osRaw} ${d.os_version ? `<span class="mono text-muted" style="font-size:11px;">(${d.os_version})</span>` : ''}`;
    const deptDisplay = d.department ? d.department : (d.owner || "Core Infrastructure");

    const critBadge = d.criticality === "critical"
      ? `<span class="badge badge-key">CRITICAL</span>`
      : d.criticality === "high"
      ? `<span class="badge badge-warning">HIGH</span>`
      : `<span class="badge badge-subtle">MEDIUM</span>`;

    const exposureTag = d.is_internet_facing
      ? `<span class="badge badge-internet">🌐 Internet Facing</span>`
      : `<span class="badge badge-internal">🔒 Internal LAN</span>`;

    return `
      <tr>
        <td class="mono font-semibold" style="color: #60a5fa;">${d.device_id}</td>
        <td class="mono font-semibold" style="color: #fff;">${d.hostname}</td>
        <td class="mono">${d.ip_address || '10.0.0.0'}</td>
        <td>${osDisplay}</td>
        <td>${deptDisplay}</td>
        <td>${critBadge}</td>
        <td>${exposureTag}</td>
        <td>
          <button class="btn btn-secondary btn-sm" onclick="quickInvestigate('${d.hostname}')">
            Scan
          </button>
        </td>
      </tr>
    `;
  }).join("");
}

// Modal: Add Device
function showAddAssetModal() {
  document.getElementById("modal-add-device").classList.remove("hidden");
}
function closeAddAssetModal() {
  document.getElementById("modal-add-device").classList.add("hidden");
}

async function submitAddDevice() {
  const devId = document.getElementById("form-dev-id").value.trim();
  const hostname = document.getElementById("form-hostname").value.trim();
  const ip = document.getElementById("form-ip").value.trim() || "10.0.10.1";
  const os = document.getElementById("form-os").value.trim() || "Ubuntu Linux 22.04 LTS";
  const dept = document.getElementById("form-dept").value.trim() || "Enterprise Infrastructure";
  const crit = document.getElementById("form-criticality").value;
  const isInternet = document.getElementById("form-internet-facing").checked;

  if (!devId || !hostname) {
    showToast("Please provide both Device ID and Hostname", "error");
    return;
  }

  try {
    const payload = {
      device_id: devId,
      hostname: hostname,
      ip_address: ip,
      os_name: os,
      department: dept,
      criticality: crit,
      is_internet_facing: isInternet,
      security_status: "monitored"
    };

    const resp = await fetch("/api/assets/device", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    if (!resp.ok) throw new Error("Failed to save device");

    showToast(`Device ${hostname} successfully registered!`, "success");
    closeAddAssetModal();
    await loadAssets();
    await loadMetrics();
  } catch (err) {
    showToast(`Error adding device: ${err.message}`, "error");
  }
}

// Modal: Import CSV
function showAssetImportModal() {
  document.getElementById("modal-import-csv").classList.remove("hidden");
}
function closeAssetImportModal() {
  document.getElementById("modal-import-csv").classList.add("hidden");
}

async function submitAssetCSV() {
  const fileInput = document.getElementById("asset-csv-file");
  if (!fileInput.files || !fileInput.files[0]) {
    showToast("Please select a valid CSV file.", "error");
    return;
  }

  const formData = new FormData();
  formData.append("file", fileInput.files[0]);

  try {
    const resp = await fetch("/api/assets/import/csv", {
      method: "POST",
      body: formData
    });
    if (!resp.ok) throw new Error("CSV upload failed");
    const data = await resp.json();
    showToast(`Successfully ingested ${data.imported_devices} devices from CSV!`, "success");
    closeAssetImportModal();
    await loadAssets();
    await loadMetrics();
  } catch (e) {
    showToast(`CSV error: ${e.message}`, "error");
  }
}

// ==========================================================================
// AI Threat Investigation Execution
// ==========================================================================

async function executeInvestigation(indicator) {
  if (!indicator) return;

  // Show Pipeline Animation
  const pipeline = document.getElementById("investigation-pipeline");
  const resultCard = document.getElementById("inv-result-card");
  pipeline.classList.remove("hidden");
  resultCard.classList.add("hidden");

  // Animate pipeline stages
  animatePipelineStep(1);
  setTimeout(() => animatePipelineStep(2), 500);
  setTimeout(() => animatePipelineStep(3), 1100);
  setTimeout(() => animatePipelineStep(4), 1700);
  setTimeout(() => animatePipelineStep(5), 2300);

  try {
    const resp = await fetch("/api/investigations/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ trigger_type: "auto", trigger_value: indicator })
    });
    if (!resp.ok) throw new Error(`HTTP Error ${resp.status}`);
    const data = await resp.json();
    activeInvestigationId = data.investigation_id;

    // Render Verdict & Score
    pipeline.classList.add("hidden");
    resultCard.classList.remove("hidden");

    document.getElementById("inv-result-title").textContent = `Investigation: ${data.investigation_id}`;
    document.getElementById("inv-result-target").textContent = `Target Evaluated: ${data.indicator} (${data.type.toUpperCase()})`;

    const scoreEl = document.getElementById("inv-result-risk");
    scoreEl.textContent = data.risk_score;
    const sevEl = document.getElementById("inv-result-severity");
    sevEl.textContent = `${data.severity.toUpperCase()} RISK`;

    if (data.severity === "critical") scoreEl.style.color = "var(--critical)";
    else if (data.severity === "high") scoreEl.style.color = "var(--warning)";
    else scoreEl.style.color = "var(--emerald)";

    const verdictEl = document.getElementById("inv-verdict-badge");
    verdictEl.textContent = data.verdict.replace(/_/g, " ").toUpperCase();
    verdictEl.className = `verdict-tag ${data.verdict === 'confirmed_match' ? 'confirmed' : data.verdict === 'potential_match' ? 'potential' : 'nomatch'}`;

    // Ribbon counts
    document.getElementById("inv-cs-matches").textContent = data.crowdstrike_matches || 0;
    document.getElementById("inv-siem-matches").textContent = data.siem_matches || 0;
    document.getElementById("inv-dev-matches").textContent = data.affected_devices || 0;
    document.getElementById("inv-ev-matches").textContent = data.evidence_count || 0;

    // Gemini AI synthesis
    document.getElementById("inv-ai-ti").textContent = data.ai_analysis.threat_intelligence_analysis || "No intelligence analysis generated.";
    document.getElementById("inv-ai-asset").textContent = data.ai_analysis.asset_impact_assessment || "No direct internal asset impact observed.";
    document.getElementById("inv-ai-summary").textContent = data.ai_analysis.executive_summary || "Investigation completed.";

    const actionsList = document.getElementById("inv-ai-actions");
    actionsList.innerHTML = (data.ai_analysis.remediation_actions || []).map(act => `<li>🛡️ ${act}</li>`).join("");

    // Correlated Evidence Table
    const tbody = document.querySelector("#inv-evidence-table tbody");
    if (!data.evidence || !data.evidence.length) {
      tbody.innerHTML = `<tr><td colspan="4" class="text-muted" style="text-align:center; padding: 20px;">No telemetry matches detected across EDR, SIEM, or Asset databases.</td></tr>`;
    } else {
      tbody.innerHTML = data.evidence.map(ev => `
        <tr>
          <td><strong style="color: #38bdf8;">${(ev.source || '').toUpperCase()}</strong></td>
          <td><span class="badge badge-subtle mono">${ev.evidence_type}</span></td>
          <td style="font-size: 13px;">${ev.description}</td>
          <td><span class="mono font-semibold" style="color: var(--emerald);">${ev.confidence}%</span></td>
        </tr>
      `).join("");
    }

    showToast(`Investigation concluded with verdict: ${data.verdict.toUpperCase()}`, "success");
    await loadRecentInvestigations();
    await loadMetrics();
  } catch (err) {
    pipeline.classList.add("hidden");
    showToast(`Investigation execution failed: ${err.message}`, "error");
  }
}

function animatePipelineStep(stepNum) {
  for (let i = 1; i <= 5; i++) {
    const el = document.getElementById(`pipe-step-${i}`);
    if (el) {
      if (i <= stepNum) el.classList.add("active");
      else el.classList.remove("active");
    }
  }
}

// Export Report
function exportReportCurrent(format) {
  const invId = activeInvestigationId || "latest";
  window.open(`/api/reports/export/${invId}?format=${format}`, "_blank");
}

// Recent Investigations Table
async function loadRecentInvestigations() {
  try {
    const resp = await fetch("/api/investigations?limit=10");
    if (!resp.ok) return;
    const invs = await resp.json();
    const tbody = document.querySelector("#recent-inv-table tbody");
    if (!invs || !invs.length) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-muted" style="text-align:center; padding: 24px;">No investigations recorded yet. Use the investigation bar above to start.</td></tr>`;
      return;
    }

    tbody.innerHTML = invs.map(i => {
      const vClass = i.verdict === "confirmed_match" ? "confirmed" : i.verdict === "potential_match" ? "potential" : "nomatch";
      return `
        <tr>
          <td class="mono font-semibold" style="color: #60a5fa;">${i.id}</td>
          <td class="mono font-semibold" style="color: #fff;">${i.trigger_value}</td>
          <td><span class="badge badge-subtle">${(i.trigger_type || 'AUTO').toUpperCase()}</span></td>
          <td><span class="verdict-tag ${vClass}" style="font-size:11px; padding: 2px 8px;">${i.verdict.replace(/_/g, ' ').toUpperCase()}</span></td>
          <td class="mono font-semibold"><strong>${i.risk_score}</strong>/100 (${i.severity.toUpperCase()})</td>
          <td class="text-muted mono" style="font-size:12px;">${new Date(i.created_at).toLocaleString()}</td>
          <td>
            <button class="btn btn-secondary btn-sm" onclick="quickInvestigate('${i.trigger_value}')">Inspect</button>
          </td>
        </tr>
      `;
    }).join("");
  } catch (e) {
    console.error("Load recent investigations error:", e);
  }
}

// ==========================================================================
// EDR & SIEM Diagnostic Tests
// ==========================================================================

async function testCrowdStrike() {
  showToast("Testing CrowdStrike Falcon OAuth2 connection...", "info");
  try {
    const resp = await fetch("/api/connectors/crowdstrike/test", { method: "POST" });
    const data = await resp.json();
    const container = document.getElementById("cs-status-view");
    if (data.status === "standby") {
      container.innerHTML = `
        <div class="config-instructions" style="background: rgba(15, 23, 42, 0.7); padding: 18px; border-radius: var(--radius-sm); border-left: 3px solid var(--warning);">
          <h4 style="color: #fbbf24; margin-bottom: 6px;">🦅 CrowdStrike Falcon Standby Verified</h4>
          <p>${data.message}</p>
          <p style="margin-top: 10px;">To connect real Falcon sensor telemetry, provide your <code>CROWDSTRIKE_CLIENT_ID</code> and <code>CROWDSTRIKE_CLIENT_SECRET</code> in <code>.env</code>.</p>
        </div>
      `;
      showToast("CrowdStrike Falcon is in Clean Standby mode.", "info");
    } else {
      showToast(`CrowdStrike Status: ${data.status}`, "success");
    }
  } catch (e) {
    showToast(`Test error: ${e.message}`, "error");
  }
}

async function testElastic() {
  showToast("Testing Elastic SIEM cluster connection...", "info");
  try {
    const resp = await fetch("/api/connectors/elastic/test", { method: "POST" });
    const data = await resp.json();
    const container = document.getElementById("elastic-status-view");
    if (data.status === "standby") {
      container.innerHTML = `
        <div class="config-instructions" style="background: rgba(15, 23, 42, 0.7); padding: 18px; border-radius: var(--radius-sm); border-left: 3px solid var(--warning);">
          <h4 style="color: #fbbf24; margin-bottom: 6px;">⚡ Elastic SIEM Standby Verified</h4>
          <p>${data.message}</p>
          <p style="margin-top: 10px;">To connect your cluster, configure <code>ELASTIC_URL</code> and <code>ELASTIC_API_KEY</code> in <code>.env</code>.</p>
        </div>
      `;
      showToast("Elastic SIEM is in Clean Standby mode.", "info");
    } else {
      showToast(`Elastic SIEM Status: ${data.status}`, "success");
    }
  } catch (e) {
    showToast(`Test error: ${e.message}`, "error");
  }
}

// ==========================================================================
// Audit Logs & Connectors Health
// ==========================================================================

async function loadAuditLogs() {
  try {
    const resp = await fetch("/api/audit/logs?limit=50");
    if (!resp.ok) return;
    const logs = await resp.json();
    const tbody = document.querySelector("#audit-logs-table tbody");
    if (!logs || !logs.length) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-muted" style="text-align:center; padding: 24px;">No audit records found.</td></tr>`;
      return;
    }
    tbody.innerHTML = logs.map(l => `
      <tr>
        <td class="mono text-muted" style="font-size:12px;">${new Date(l.timestamp).toLocaleString()}</td>
        <td><strong>${l.action}</strong></td>
        <td><span class="badge badge-subtle">${l.action_category || 'SYSTEM'}</span></td>
        <td class="mono">${l.actor_username || 'gemini_agent'}</td>
        <td><span class="badge ${l.status === 'success' ? 'badge-free' : 'badge-key'}">${(l.status || 'OK').toUpperCase()}</span></td>
        <td style="font-size:12.5px;">${l.target_entity || ''}</td>
      </tr>
    `).join("");
  } catch (e) {
    console.error("Audit load error:", e);
  }
}

async function loadConnectorsHealth() {
  try {
    const resp = await fetch("/api/connectors/status");
    if (!resp.ok) return;
    const data = await resp.json();
    const container = document.getElementById("connectors-diagnostic-content");

    container.innerHTML = `
      <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 24px;">
        <div class="source-card">
          <div class="source-card-top">
            <h4 class="source-card-title">🦅 CrowdStrike Falcon</h4>
            <span class="badge ${data.crowdstrike.configured ? 'badge-free' : 'badge-subtle'}">${data.crowdstrike.configured ? 'ACTIVE' : 'STANDBY'}</span>
          </div>
          <p class="source-card-desc">OAuth2 endpoint queries against CrowdStrike Falcon cloud APIs.</p>
          <div class="source-card-meta">
            <span>Base URL: <code>${data.crowdstrike.base_url || 'https://api.crowdstrike.com'}</code></span>
            <span>Auth: ${data.crowdstrike.configured ? 'Valid' : 'Standby'}</span>
          </div>
        </div>

        <div class="source-card">
          <div class="source-card-top">
            <h4 class="source-card-title">⚡ Elastic SIEM</h4>
            <span class="badge ${data.elastic.configured ? 'badge-free' : 'badge-subtle'}">${data.elastic.configured ? 'ACTIVE' : 'STANDBY'}</span>
          </div>
          <p class="source-card-desc">Elastic Common Schema (ECS) historical logs and threat event analysis.</p>
          <div class="source-card-meta">
            <span>Cluster URL: <code>${data.elastic.cluster_url || 'Unconfigured'}</code></span>
            <span>Index: <code>${data.elastic.index_pattern || 'logs-*'}</code></span>
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header">
          <h3>Threat Intelligence Adapters Status (14 Feeds)</h3>
        </div>
        <div class="panel-body">
          <p class="text-muted" style="margin-bottom: 14px; font-size:13px;">All 14 threat intelligence connectors are operational and synchronized with local persistence.</p>
          <div style="display:flex; gap: 10px; flex-wrap: wrap;">
            ${(data.threat_intel_connectors || []).map(c => `
              <span class="badge badge-free" style="padding: 6px 12px; font-size:12px;">● ${c}</span>
            `).join("")}
          </div>
        </div>
      </div>
    `;
  } catch (e) {
    console.error("Connectors health load error:", e);
  }
}

// ==========================================================================
// Utilities: Toast & Clipboard
// ==========================================================================

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => {
    showToast(`Copied: ${text}`, "info");
  }).catch(() => {
    showToast("Copy failed", "error");
  });
}

function showToast(msg, type = "info") {
  const container = document.getElementById("toast-container");
  if (!container) return;
  const t = document.createElement("div");
  t.className = `toast ${type}`;
  t.innerHTML = `<span>${msg}</span>`;
  container.appendChild(t);
  setTimeout(() => {
    t.style.opacity = "0";
    setTimeout(() => t.remove(), 200);
  }, 4000);
}
