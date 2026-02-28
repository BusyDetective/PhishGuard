  // =============================
// PhishGuard Content Script
// Batch ML scanning + Heatmap + Tooltips + Popup Stats
// =============================

let SHOW_HEATMAP = true;

chrome.storage.local.get("settings", (data) => {
  SHOW_HEATMAP = data.settings?.showHeatmap !== false;
});

chrome.storage.onChanged.addListener((changes) => {
  if (changes.settings?.newValue) {
    SHOW_HEATMAP = changes.settings.newValue.showHeatmap !== false;

    if (!SHOW_HEATMAP) {
      clearAllHighlights();
    } else {
      scanAndHighlightAllLinks();
    }
  }
});

// ================= SETTINGS (GLOBAL) =================
const DEFAULT_SETTINGS = {
  blockMode: true,
  blockThreshold: 60
};

let phishguardSettings = { ...DEFAULT_SETTINGS };

chrome.storage.local.get("settings", (data) => {
  if (data.settings) {
    phishguardSettings = { ...phishguardSettings, ...data.settings };
  }
});

// ================= TRUSTED DOMAINS =================
let trustedDomains = [];

chrome.storage.local.get("trustedDomains", (data) => {
  if (Array.isArray(data.trustedDomains)) {
    trustedDomains = data.trustedDomains;
  }
});

function isTrustedDomain(url) {
  try {
    const host = new URL(url).hostname;
    return trustedDomains.some(d => host === d || host.endsWith("." + d));
  } catch {
    return false;
  }
}


// ========== CONFIG ==========
const API_URL = "http://127.0.0.1:8000/scan_batch";
const API_KEY = "TEST-DEV-KEY-12345";

const MAX_TOTAL_LINKS = 500;
const BATCH_SIZE = 50;
const BATCH_DELAY_MS = 200;
const LOCAL_QUICK_THRESHOLD = 80;

// ========== TOOLTIP CSS ==========
const tooltipStyle = document.createElement("style");
tooltipStyle.innerHTML = `
#phishguard-tooltip {
  position: fixed;
  z-index: 2147483647;
  background: #111827;
  color: #e5e7eb;
  border-radius: 8px;
  padding: 10px 12px;
  font-family: system-ui, -apple-system, BlinkMacSystemFont;
  font-size: 12px;
  line-height: 1.4;
  box-shadow: 0 10px 25px rgba(0,0,0,0.3);
  border: 1px solid #374151;
  max-width: 260px;
  pointer-events: none;
  opacity: 0;
  transition: opacity 0.15s ease;
}
#phishguard-tooltip strong {
  color: #facc15;
}
`;
document.head.appendChild(tooltipStyle);

const blockStyle = document.createElement("style");
blockStyle.textContent = `
#phishguard-warning {
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.75);
  z-index: 999999;
  display: flex;
  align-items: center;
  justify-content: center;
  font-family: system-ui, sans-serif;
}

.pg-box {
  background: #111;
  color: #fff;
  padding: 24px;
  border-radius: 12px;
  width: 360px;
  box-shadow: 0 0 30px rgba(255,0,0,0.4);
  text-align: center;
}

.pg-box h2 {
  margin-top: 0;
  color: #ff4d4d;
}

.pg-actions {
  margin-top: 20px;
  display: flex;
  justify-content: space-between;
}

.pg-actions button {
  padding: 10px 16px;
  border: none;
  border-radius: 6px;
  cursor: pointer;
}

#pg-cancel {
  background: #444;
  color: #fff;
}

#pg-proceed {
  background: #ff4d4d;
  color: #fff;
}
`;
document.head.appendChild(blockStyle);

// ========== TOOLTIP ELEMENT ==========
const tooltip = document.createElement("div");
tooltip.id = "phishguard-tooltip";
document.body.appendChild(tooltip);

// ========== UTIL ==========
function normalizeUrl(url) {
  try {
    const u = new URL(url, location.href);
    u.hash = "";
    return u.href;
  } catch {
    return null;
  }
}

function getRiskReasons(data) {
  if (!data) return [];

  // 1️⃣ If reasons already exist, trust them
  if (Array.isArray(data.reasons) && data.reasons.length) {
    return data.reasons.slice(0, 4);
  }

  const reasons = [];

  // 2️⃣ AI-based reasons (your API actually provides these)
  if (typeof data.combined_risk_score === "number") {
    if (data.combined_risk_score >= 80) {
      reasons.push("Extremely high phishing risk (AI)");
    } else if (data.combined_risk_score >= 60) {
      reasons.push("High phishing likelihood (AI)");
    } else if (data.combined_risk_score >= 20) {
      reasons.push("Moderate phishing indicators detected");
    }
  }

  if (data.ai_probability >= 0.6) {
    reasons.push("AI model confidence is high");
  }

  // 3️⃣ Safe fallback (never empty)
  if (!reasons.length) {
    reasons.push("Suspicious link behavior detected");
  }

  return reasons.slice(0, 4);
}


// ========== LOCAL HEURISTIC (OLD LOGIC) ==========
function evaluateLinkLocal(url) {
  let score = 0;
  const lower = url.toLowerCase();

  const keywords = ["login", "verify", "update", "secure", "account", "reset", "bank"];
  keywords.forEach(k => lower.includes(k) && (score += 15));

  if (/[.@]/.test(lower)) score += 20;
  if (lower.length > 120) score += 10;
  if (/\.(tk|ml|ga|cf|gq|xyz|zip|click)$/.test(lower)) score += 40;

  return Math.min(100, score);
}

// ========== BADGE ==========
function insertBadge(link, color) {
  if (link.__phgBadge) return;

  const badge = document.createElement("span");
  badge.className = "phishguard-badge";
  badge.textContent = "!";
  badge.style.background = color;
  badge.style.color = "#000";
  badge.style.fontSize = "10px";
  badge.style.marginLeft = "6px";
  badge.style.padding = "0 4px";
  badge.style.borderRadius = "3px";
  badge.style.fontWeight = "700";

  link.after(badge);
  link.__phgBadge = badge;
}

// ========== TOOLTIP BIND ==========

function bindTooltip(link, data, source) {
  link.addEventListener("mouseenter", (e) => {
    const reasons = getRiskReasons(data);

    tooltip.innerHTML = `
      <strong>⚠ PhishGuard Alert</strong><br>
      <b>Risk score:</b> ${Math.round(data.combined_risk_score ?? data.risk)}%<br>
      ${reasons.map(r => `• ${r}`).join("<br>")}<br>
      <b>Domain:</b> ${new URL(data.url).hostname}<br>
      <b>Source:</b> ${source}<br>
      <span style="color:#9ca3af;">Scanned by PhishGuard</span>
    `;
    tooltip.style.left = e.clientX + 12 + "px";
    tooltip.style.top = e.clientY + 12 + "px";
    tooltip.style.opacity = "1";
  });

  link.addEventListener("mousemove", (e) => {
    tooltip.style.left = e.clientX + 12 + "px";
    tooltip.style.top = e.clientY + 12 + "px";
  });

  link.addEventListener("mouseleave", () => {
    tooltip.style.opacity = "0";
  });
}

function attachLinkData(link, payload) {
  link.__phishguardData = payload;
}

// ========== HIGHLIGHT ==========
function applyHighlight(link, risk, source, aiData = null) {
  link.style.borderRadius = "4px";

  if (!SHOW_HEATMAP) return;

  const payload = {
    url: link.href,
    risk,
    combined_risk_score: risk,
    ai_probability: aiData?.ai_probability ?? null,
    reasons: getRiskReasons(aiData || { url: link.href, combined_risk_score: risk })
  };


  attachLinkData(link, {
    ...payload,
    reasons: payload.reasons || []
  });



  if (risk >= 60) {
  link.classList.add("phishguard-danger");
  link.style.boxShadow = "0 0 0 3px rgba(239,68,68,0.3)";
  insertBadge(link, "#ffb3b3");
  bindTooltip(link, payload, source);
  } else if (risk >= 20) {
    link.classList.add("phishguard-warn");
    link.style.boxShadow = "0 0 0 3px rgba(245,158,11,0.3)";
    insertBadge(link, "#ffe6b3");
    bindTooltip(link, payload, source);
  }
}

function clearAllHighlights() {
  document.querySelectorAll("a").forEach(link => {
    link.classList.remove("phishguard-safe", "phishguard-warn", "phishguard-danger");
    link.style.boxShadow = "";
    link.style.borderRadius = "";
    delete link.__phishguardData;
  });


  document.querySelectorAll(".phishguard-badge").forEach(badge => badge.remove());

  const tooltip = document.getElementById("phishguard-tooltip");
  if (tooltip) tooltip.style.opacity = "0";
}

// ================= BLOCK MODE WARNING UI =================
function showPhishGuardWarning(url, data) {
  const existing = document.getElementById("phishguard-warning");
  const reasons = Array.isArray(data.reasons) && data.reasons.length
    ? data.reasons
    : getRiskReasons(data);
  if (existing) existing.remove();

  const overlay = document.createElement("div");
  overlay.id = "phishguard-warning";
  overlay.innerHTML = `
    <div class="pg-box">
      <h2>⚠️ PhishGuard Warning</h2>
      <p><strong>Risk Score:</strong> ${Math.round(data.combined_risk_score)}%</p>
      <p><strong>Domain:</strong> ${new URL(url).hostname}</p>
      <p>This link is considered <strong>high risk</strong>.</p>
      <p style="text-align:left;margin-top:12px;">
        <strong>Why this link was flagged:</strong><br>
        ${reasons.map(r => `• ${r}`).join("<br>")}
      </p>
      <div class="pg-actions">
        <button id="pg-cancel">Go Back</button>
        <button id="pg-proceed">Proceed Anyway</button>
      </div>
    </div>
  `;

  document.body.appendChild(overlay);

  document.getElementById("pg-cancel").onclick = () => overlay.remove();
  document.getElementById("pg-proceed").onclick = () => {
    overlay.remove();
    window.location.href = url;
  };
}

// ========== BACKEND ==========
async function scanBatch(urls) {
  try {
    const res = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": API_KEY
      },
      body: JSON.stringify({ urls })
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

// ========== LINK COLLECTION ==========
function collectLinks() {
  const anchors = Array.from(document.querySelectorAll("a[href]"));
  const map = new Map();

  for (const a of anchors) {
    const norm = normalizeUrl(a.href);
    if (!norm) continue;
    if (!map.has(norm)) map.set(norm, []);
    map.get(norm).push(a);
    if (map.size >= MAX_TOTAL_LINKS) break;
  }
  return [...map.entries()];
}

// ========== MAIN SCAN ==========
async function scanAndHighlightAllLinks() {
  const pageStats = {
    pageUrl: location.href,
    total: 0,
    high: 0,
    warn: 0,
    domains: {},
    riskReasons: {},
    links: [],
    evidence: []
  };
  const items = collectLinks();
  if (!SHOW_HEATMAP) {
    console.log("PhishGuard: heatmap disabled, skipping highlight visuals");
  }

  // ---- Local heuristic first (OLD LOGIC) ----
  items.forEach(([url, els]) => {
    const localRisk = evaluateLinkLocal(url);

    let adjustedRisk = localRisk;
    if (isTrustedDomain(url)) adjustedRisk = localRisk * 0.2;

    els.forEach(el => {
      attachLinkData(el, {
        url,
        risk: adjustedRisk,
        combined_risk_score: adjustedRisk,
        ai_probability: null,
        reasons: []
      });


      if (adjustedRisk >= LOCAL_QUICK_THRESHOLD) {
        applyHighlight(el, adjustedRisk, "Local heuristic");
      }

    });
  });   

  // ---- AI batch scan ----
  for (let i = 0; i < items.length; i += BATCH_SIZE) {
    const batch = items.slice(i, i + BATCH_SIZE);
    const urls = batch.map(([u]) => u);

    const result = await scanBatch(urls);
    if (!result?.results) continue;

    const resultMap = new Map(result.results.map(r => [r.url, r]));

    batch.forEach(([url, els]) => {
      const r = resultMap.get(url);
      if (!r) return;

      let risk = Math.round(r.combined_risk_score);
      if (isTrustedDomain(url)) risk = risk * 0.2;

      els.forEach(el => {
        el.classList.remove("phishguard-danger", "phishguard-warn");

        attachLinkData(el, {
          url,
          risk,
          combined_risk_score: risk,
          ai_probability: r.ai_probability,
          reasons: [
            risk >= 60 ? "High phishing likelihood (AI)" : "Suspicious link detected",
            r.ai_probability >= 0.6 ? "AI confidence is high" : null
          ].filter(Boolean)
        });

        applyHighlight(el, risk, "AI", r);
      });

    });


    await new Promise(r => setTimeout(r, BATCH_DELAY_MS));
  }

  console.log("PhishGuard finished scanning and highlighting links.");

  document.querySelectorAll("a[href]").forEach(a => {
    const d = a.__phishguardData;

    pageStats.total++;

    let risk = 0;
    let domain;
    let level = "safe";

    try {
      domain = new URL(a.href).hostname;
    } catch {
      return;
    }

    if (d) {
      risk = Math.round(d.combined_risk_score || 0);
    }

    if (risk >= 60) {
      level = "high";
      pageStats.high++;
    } else if (risk >= 20) {
      level = "suspicious";
      pageStats.warn++;
    }
    
    if (domain) {
      pageStats.domains[domain] = (pageStats.domains[domain] || 0) + 1;
    }

    const reasons = (d && typeof d === "object" && Array.isArray(d.reasons))
      ? d.reasons
      : [];

    reasons.forEach(reason => {
      if (!reason) return;
      pageStats.riskReasons[reason] =
        (pageStats.riskReasons[reason] || 0) + 1;
    });


    // ✅ SAFE PUSH
    pageStats.links.push({
      url: d?.url || a.href,
      domain,
      risk,
      level,
      reasons: Array.isArray(d?.reasons) ? d.reasons : []
    });

    // ✅ ADD THIS: per-link evidence for report/PDF
    if (d && Array.isArray(d.reasons) && d.reasons.length) {
      pageStats.evidence.push({
        url: d.url || a.href,
        domain,
        risk,
        level: level.toUpperCase(),
        reasons: d.reasons
      });
    }


  });


  

  // ===== STEP 2.4: CALCULATE OVERALL PAGE RISK =====
  if (pageStats.total > 0) {
    pageStats.overallRisk = Math.round(
      (pageStats.high / pageStats.total) * 100
    );
  } else {
    pageStats.overallRisk = 0;
  }
  pageStats.overallRisk = Number(pageStats.overallRisk || 0);
  try {
    chrome.runtime.sendMessage(
      {
        type: "PHISHGUARD_PAGE_STATS",
        payload: pageStats
      },
      () => {
        if (!chrome.runtime.lastError) {
          console.log("PhishGuard pageStats sent:", pageStats);
        }
      }
    );
  } catch {}
}

// ========== SPA SUPPORT ==========
let debounce;
const observer = new MutationObserver(() => {
  if (!SHOW_HEATMAP) return;
  clearTimeout(debounce);
  debounce = setTimeout(scanAndHighlightAllLinks, 1200);
});

observer.observe(document.documentElement, {
  childList: true,
  subtree: true
});

// ========== INIT ==========
window.addEventListener("load", scanAndHighlightAllLinks);
window.phishguard = { scanNow: scanAndHighlightAllLinks };

// ================= BLOCK MODE =================
document.addEventListener("click", (e) => {
  let el = e.target;

  while (el && el !== document) {
    if (el.tagName === "A" && el.href) break;
    el = el.parentElement;
  }

  if (!el || !el.href) return;

  const data = el.__phishguardData;
  if (!data) return;

  const risk = Math.round(data.combined_risk_score || 0);
  if (!phishguardSettings.blockMode) return;
  if (risk < phishguardSettings.blockThreshold) return;
  if (isTrustedDomain(el.href)) return;

  e.preventDefault();
  e.stopPropagation();

  showPhishGuardWarning(el.href, data);
}, true);

