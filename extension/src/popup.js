function classifyRisk(score) {
  if (score >= 60) return "danger";
  if (score >= 20) return "warn";
  return "safe";
}

// 🔐 Monetization – Entitlement Resolver (Phase 1)
const ENTITLEMENTS = {
  FREE: {
    exportPDF: true,
    exportCSV: false,
    exportJSON: false,
    blockMode: false,
    advancedEvidence: false
  },
  PRO: {
    exportPDF: true,
    exportCSV: true,
    exportJSON: true,
    blockMode: true,
    advancedEvidence: true
  }
};

// 🔐 License System (Phase 3 – v1)
const LICENSE_STORAGE_KEY = "phishguard_license";

const DEFAULT_LICENSE = {
  plan: "FREE",          // FREE | PRO
  source: "local",       // local | webstore | backend
  issuedAt: null,
  expiresAt: null,
  signature: null,
  lastCheckedAt: null
};

let ACTIVE_LICENSE = { ...DEFAULT_LICENSE };

// 🔐 License Validation (Phase 4)
function isLicenseExpired(license) {
  if (!license.expiresAt) return false;
  return Date.now() > license.expiresAt;
}

function isLicenseStructValid(license) {
  return (
    license &&
    typeof license === "object" &&
    typeof license.plan === "string" &&
    ["FREE", "PRO"].includes(license.plan)
  );
}

async function validateLicense(license) {
  if (!isLicenseStructValid(license)) {
    return { valid: false, reason: "invalid_structure" };
  }

  if (isLicenseExpired(license)) {
    return { valid: false, reason: "expired" };
  }

  // Signature required for PRO
  if (license.plan === "PRO") {
    if (!license.signature) {
      return { valid: false, reason: "missing_signature" };
    }

    const payload = canonicalizeLicense(license);
    const expected = await hmacSHA256(payload, LICENSE_SECRET);

    if (expected !== license.signature) {
      return { valid: false, reason: "invalid_signature" };
    }
  }

  return { valid: true };
}


// 🔐 Crypto helpers (Phase 5)
async function hmacSHA256(message, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    enc.encode(message)
  );

  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

function canonicalizeLicense(license) {
  const { signature, ...rest } = license;
  return JSON.stringify(rest);
}

// Resolve entitlements from active license
function canUse(feature) {
  const plan = ACTIVE_LICENSE.plan || "FREE";
  return ENTITLEMENTS[plan]?.[feature] === true;
}

// 🌐 Backend license verification (Phase 6)
async function verifyLicenseWithBackend(license) {
  try {
    const res = await fetch(LICENSE_API_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        plan: license.plan,
        issuedAt: license.issuedAt,
        signature: license.signature
      })
    });

    if (!res.ok) {
      return { valid: false };
    }

    const data = await res.json();
    return data; // { valid: true, expiresAt?, plan? }
  } catch (err) {
    console.warn("PhishGuard backend check failed:", err);
    return { error: "offline" };
  }
}

function shouldRecheckWithBackend(license) {
  if (!license.lastCheckedAt) return true;
  return Date.now() - license.lastCheckedAt > LICENSE_RECHECK_INTERVAL;
}


// 🔒 UI Lock Helper (Phase 2)
function lockFeature(el, message = "Pro feature") {
  if (!el) return;

  el.disabled = true;
  el.classList.add("locked");
  el.title = message;

  el.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    showUpgradeHint(message);
  });
}

function showUpgradeHint(message) {
  const hint = document.createElement("div");
  hint.className = "upgrade-hint";
  hint.textContent = `${message} — Upgrade to Pro`;

  document.body.appendChild(hint);

  setTimeout(() => hint.remove(), 2000);
}

function openUpgradePage() {
  chrome.tabs.create({
    url: "https://phishguard.app/upgrade" // placeholder
  });
}

function updateUpgradeUI() {
  const panel = document.getElementById("upgradePanel");
  if (!panel) return;

  panel.style.display = ACTIVE_LICENSE.plan === "FREE" ? "block" : "none";
}


chrome.storage.local.get(LICENSE_STORAGE_KEY, async (data) => {
  const stored = data[LICENSE_STORAGE_KEY];

  if (!stored) {
    ACTIVE_LICENSE = { ...DEFAULT_LICENSE };
    updateUpgradeUI();
    return;
  }


  const localResult = await validateLicense(stored);

  if (!localResult.valid) {
    console.warn("PhishGuard license invalid:", localResult.reason);
    ACTIVE_LICENSE = { ...DEFAULT_LICENSE };
    updateUpgradeUI();
    chrome.storage.local.remove(LICENSE_STORAGE_KEY);
    return;
  }


  ACTIVE_LICENSE = {
    ...DEFAULT_LICENSE,
    ...stored
  };
  updateUpgradeUI();

  // 🌐 Backend re-validation (non-blocking)
  if (ACTIVE_LICENSE.plan === "PRO" && shouldRecheckWithBackend(ACTIVE_LICENSE)) {
    const backendResult = await verifyLicenseWithBackend(ACTIVE_LICENSE);

    if (backendResult?.valid === false) {
      console.warn("PhishGuard backend rejected license");
      ACTIVE_LICENSE = { ...DEFAULT_LICENSE };
      updateUpgradeUI();
      chrome.storage.local.remove(LICENSE_STORAGE_KEY);
      return;
    }


    if (backendResult?.valid === true) {
      ACTIVE_LICENSE = {
        ...ACTIVE_LICENSE,
        ...backendResult,
        lastCheckedAt: Date.now()
      };

      chrome.storage.local.set({
        [LICENSE_STORAGE_KEY]: ACTIVE_LICENSE
      });
    }
  }
});


// 🔑 Phase 5 – Signature verification (placeholder secret)
const LICENSE_SECRET = "PHISHGUARD_DEV_SECRET_CHANGE_LATER";
// 🌐 Phase 6 – Backend license validation
const LICENSE_API_ENDPOINT = "https://api.phishguard.app/license/verify"; // placeholder
const LICENSE_RECHECK_INTERVAL = 1000 * 60 * 60 * 6; // 6 hours


// 🧪 DEV ONLY – Generate signed PRO license
// (async () => {
//   const license = {
//     plan: "PRO",
//     source: "local",
//     issuedAt: Date.now(),
//     expiresAt: null
//   };
//   license.signature = await hmacSHA256(
//     JSON.stringify(license),
//     LICENSE_SECRET
//   );
//   chrome.storage.local.set({ [LICENSE_STORAGE_KEY]: license });
// })();


// Request stats directly from background
chrome.runtime.sendMessage(
  { type: "PHISHGUARD_GET_PAGE_STATS" },
  (stats) => {
    const pageUrl = document.getElementById("pageUrl");
    const riskScore = document.getElementById("riskScore");
    const highCount = document.getElementById("highCount");
    const warnCount = document.getElementById("warnCount");
    const totalCount = document.getElementById("totalCount");
    const domainsList = document.getElementById("domains");
    const blockToggle = document.getElementById("blockToggle");
    const threshold = document.getElementById("threshold");
    const thresholdValue = document.getElementById("thresholdValue");
    const trustedInput = document.getElementById("trustedInput");
    const addTrusted = document.getElementById("addTrusted");
    const trustedList = document.getElementById("trustedList");

    if (!stats || typeof stats.total !== "number") {
      highCount.textContent = "—";
      warnCount.textContent = "—";
      totalCount.textContent = "—";
      return;
    } else {
      // ✅ Use PAGE-LEVEL overall risk (single source of truth)
      const pageRisk = Math.round(stats.overallRisk || 0);

      riskScore.textContent = `${pageRisk}%`;
      riskScore.className = `risk ${classifyRisk(pageRisk)}`;

      pageUrl.textContent = stats.pageUrl || "Current page";
    }
    {
      highCount.textContent = stats.high;
      warnCount.textContent = stats.warn;
      totalCount.textContent = stats.total;

      domainsList.innerHTML = "";
      Object.entries(stats.domains)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .forEach(([domain, count]) => {
          const li = document.createElement("li");
          li.textContent = `${domain} (${count})`;
          domainsList.appendChild(li);
        });
    }

    
    chrome.storage.local.get("settings", (data) => {
      const settings = data.settings || {
        blockMode: true,
        blockThreshold: 60
      };

      if (!canUse("blockMode")) {
        blockToggle.checked = false;
        lockFeature(blockToggle, "Block Mode");
      } else {
        blockToggle.checked = settings.blockMode;
      }

      threshold.value = settings.blockThreshold;
      thresholdValue.textContent = `${settings.blockThreshold}%`;
    });

    blockToggle.addEventListener("change", () => {
      if (canUse("blockMode")) {
        saveSettings();
      }
    });



    const heatmapToggle = document.getElementById("heatmapToggle");

    chrome.storage.local.get("settings", (data) => {
      const settings = data.settings || {};
      heatmapToggle.checked = settings.showHeatmap !== false;
    });

    heatmapToggle.addEventListener("change", () => {
      chrome.storage.local.get("settings", (data) => {
        chrome.storage.local.set({
          settings: {
            ...data.settings,
            showHeatmap: heatmapToggle.checked
          }
        });

        // 🔥 TELL CONTENT SCRIPT IMMEDIATELY
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          if (!tabs[0]) return;

          chrome.tabs.sendMessage(
            tabs[0].id,
            {
              type: "PHISHGUARD_TOGGLE_HIGHLIGHTS",
              enabled: heatmapToggle.checked
            }
          );
        });
      });
    });
  
    threshold.addEventListener("input", () => {
      thresholdValue.textContent = `${threshold.value}%`;
      saveSettings();
    });

    function saveSettings() {
      chrome.storage.local.set({
        settings: {
          blockMode: blockToggle.checked,
          blockThreshold: Number(threshold.value)
        }
      });
    }
    function renderTrusted(domains) {
      trustedList.innerHTML = "";
      domains.forEach(d => {
        const li = document.createElement("li");
        li.textContent = d;
        li.style.cursor = "pointer";
        li.onclick = () => removeTrusted(d);
        trustedList.appendChild(li);
      });
    }

    chrome.storage.local.get("trustedDomains", (data) => {
      const domains = data.trustedDomains || [];
      renderTrusted(domains);
    });

    addTrusted.onclick = () => {
      const domain = trustedInput.value.trim().toLowerCase();
      if (!domain) return;

      chrome.storage.local.get("trustedDomains", (data) => {
        const domains = new Set(data.trustedDomains || []);
        domains.add(domain);
        const list = [...domains];

        chrome.storage.local.set({ trustedDomains: list }, () => {
          trustedInput.value = "";
          renderTrusted(list);
        });
      });
    };

    function removeTrusted(domain) {
      chrome.storage.local.get("trustedDomains", (data) => {
        const list = (data.trustedDomains || []).filter(d => d !== domain);
        chrome.storage.local.set({ trustedDomains: list }, () => {
          renderTrusted(list);
        });
      });
    }
  }
);

const exportPdfBtn = document.getElementById("exportPdf");

exportPdfBtn.addEventListener("click", () => {
  chrome.runtime.sendMessage(
    {
      type: "PHISHGUARD_EXPORT_PDF",
      pageUrl: document.getElementById("pageUrl").textContent
    },
    (res) => {
      if (!res || res.error) {
        alert("No scan data available yet.");
      }
    }
  );
});

const exportCSVBtn = document.getElementById("exportCSV");
if (exportCSVBtn && !canUse("exportCSV")) {
  lockFeature(exportCSVBtn, "CSV Export");
}

// 🔒 JSON Export (PRO-only)
const exportJSONBtn = document.getElementById("exportJSON");
if (exportJSONBtn && !canUse("exportJSON")) {
  lockFeature(exportJSONBtn, "JSON Export");
}

exportJSONBtn?.addEventListener("click", () => {
  if (!canUse("exportJSON")) return;

  chrome.runtime.sendMessage(
    { type: "PHISHGUARD_GET_PAGE_STATS" },
    (stats) => {
      if (!stats || typeof stats.total !== "number") {
        alert("No scan data available yet.");
        return;
      }

      const blob = new Blob(
        [JSON.stringify(stats, null, 2)],
        { type: "application/json" }
      );

      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `phishguard-report-${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }
  );
});

exportCSVBtn?.addEventListener("click", () => {
  chrome.storage.local.get(["settings"], () => {
    chrome.runtime.sendMessage(
      { type: "PHISHGUARD_GET_PAGE_STATS" },
      (stats) => {
        if (!stats || typeof stats.total !== "number") {
          alert("No scan data available yet.");
          return;
        }

        const rows = [];
        const generatedAt = new Date().toISOString();
        const pageUrl = stats.pageUrl || "";
        const overallRisk = stats.overallRisk ?? "";
        const high = stats.high ?? 0;
        const warn = stats.warn ?? 0;
        const total = stats.total ?? 0;

        // CSV header
        rows.push([
          "Generated At",
          "Page URL",
          "Overall Risk",
          "High Risk",
          "Suspicious",
          "Total Scanned",
          "Domain",
          "Count"
        ]);

        // One row per domain
        Object.entries(stats.domains).forEach(([domain, count]) => {
          rows.push([
            generatedAt,
            pageUrl,
            overallRisk,
            high,
            warn,
            total,
            domain,
            count
          ]);
        });

        const csvContent = rows
          .map(row =>
            row.map(v => `"${String(v).replace(/"/g, '""')}"`).join(",")
          )
          .join("\n");

        const blob = new Blob([csvContent], { type: "text/csv" });
        const url = URL.createObjectURL(blob);

        const a = document.createElement("a");
        a.href = url;
        a.download = `phishguard-report-${Date.now()}.csv`;
        document.body.appendChild(a);
        a.click();

        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      }
    );
  });
});

const upgradeBtn = document.getElementById("upgradeBtn");

upgradeBtn?.addEventListener("click", () => {
  chrome.tabs.create({
    url: "https://phishguard.app/upgrade" // placeholder
  });
});
