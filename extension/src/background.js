importScripts("config.js");

console.log("PhishGuard background worker running...");

// 🔐 License enforcement (Phase 9)
const LICENSE_STORAGE_KEY = "phishguard_license";
let ACTIVE_PLAN = "FREE";

function loadActivePlan() {
  if (!chrome?.storage?.local) {
    console.warn("PhishGuard: chrome.storage not ready");
    return;
  }

  chrome.storage.local.get({ [LICENSE_STORAGE_KEY]: null }, (data) => {
    ACTIVE_PLAN = data[LICENSE_STORAGE_KEY]?.plan || "FREE";
  });
}


// Initial load
loadActivePlan();

// Keep license in sync
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes[LICENSE_STORAGE_KEY]) {
    ACTIVE_PLAN = changes[LICENSE_STORAGE_KEY].newValue?.plan || "FREE";
  }
});

// ================= GLOBAL STATE =================
let latestPageStats = null;

// ================= SINGLE URL SCAN (OLD LOGIC) =================
async function scanURL(url) {
  try {
    const response = await fetch(`${PHISHGUARD_API_URL}/scan_batch`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": PHISHGUARD_API_KEY
      },
      body: JSON.stringify({ urls: [url] })
    });

    console.log("Response status:", response.status);

    if (!response.ok) return null;

    const data = await response.json();
    console.log("Scan result:", data);

    return data.results?.[0] || null;
  } catch (err) {
    console.error("Scan error:", err);
    return null;
  }
}

// ================= AUTO SCAN (OLD LOGIC) =================
async function autoScan(url) {
  const result = await scanURL(url);
  if (!result) return;

  console.log("Final risk score:", result.combined_risk_score);

  chrome.storage.local.set({
    lastScan: {
      url: result.url,
      risk: result.combined_risk_score,
      ai_prediction: result.ai_prediction,
      ai_probability: result.ai_probability,
      scanned_at: Date.now()
    }
  });
}

// ================= TAB EVENTS =================
chrome.tabs.onActivated.addListener((info) => {
  chrome.tabs.get(info.tabId, (tab) => {
    if (tab?.url?.startsWith("http")) {
      console.log("Tab activated:", tab.url);
      autoScan(tab.url);
    }
  });
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab?.url?.startsWith("http")) {
    console.log("Tab updated:", tab.url);
    autoScan(tab.url);
  }
});

// ================= MESSAGE BRIDGE (FINAL FIX) =================
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  console.log("Background received message:", msg.type);

  // 🔒 Pro enforcement for exports
  if (
    (msg.type === "PHISHGUARD_EXPORT_CSV" ||
    msg.type === "PHISHGUARD_EXPORT_JSON") &&
    ACTIVE_PLAN !== "PRO"
  ) {
    sendResponse({ error: "PRO_REQUIRED" });
    return true;
  }

  // Receive stats from content script
  if (msg.type === "PHISHGUARD_PAGE_STATS") {
    latestPageStats = {
      pageUrl: msg.payload.pageUrl,
      overallRisk: msg.payload.overallRisk,
      high: msg.payload.high,
      warn: msg.payload.warn,
      total: msg.payload.total,
      domains: msg.payload.domains,
      riskReasons: msg.payload.riskReasons || {},
      links: msg.payload.links,
      evidence: msg.payload.evidence
    };
    latestPageStats.overallRisk = Number(latestPageStats.overallRisk || 0);
    console.log("Saved pageStats in background:", latestPageStats);
    return;
  }
  if (msg.type === "PHISHGUARD_GET_PAGE_STATS") {
    sendResponse(latestPageStats);
    return true;
  }

  // ✅ Free = basic PDF allowed
  // 🔒 Pro-only sections are gated in report.js
  // ===== EXPORT PDF REPORT (FINAL) =====
  if (msg.type === "PHISHGUARD_EXPORT_PDF") {
    if (!latestPageStats) {
      sendResponse({ error: "No scan data available" });
      return true;
    }
    
    const report = {
      generated_at: new Date().toISOString(),
      pageUrl: msg.pageUrl || "",
      overall_risk: latestPageStats.overallRisk,

      stats: {
        high_risk: latestPageStats.high,
        suspicious: latestPageStats.warn,
        total_scanned: latestPageStats.total
      },

      top_risky_domains: latestPageStats.domains,

      // ✅ PER-LINK EVIDENCE (THIS WAS MISSING)
      evidence: latestPageStats.evidence || [],

      // optional aggregate
      risk_reasons: latestPageStats.riskReasons || {}
    };


    chrome.storage.local.set(
      { phishguard_report: report },
      () => {
        chrome.tabs.create({
          url: chrome.runtime.getURL("src/report.html")
        });
      }
    );

    sendResponse({ success: true });
    return true;
  }
});

// if (msg.type === "PHISHGUARD_UPDATE_SETTINGS") {
//   if (msg.settings?.blockMode === true && ACTIVE_PLAN !== "PRO") {
//     sendResponse({ error: "PRO_REQUIRED" });
//     return true;
//   }
// }
