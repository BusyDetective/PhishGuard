importScripts("config.js");

// Listen to tab updates (navigation changes)
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab.url.startsWith("http")) {

        // Call backend API
        try {
            const response = await fetch(`${PHISHGUARD_API_URL}?url=${encodeURIComponent(tab.url)}`, {
                method: "GET",
                headers: {
                    "x-api-key": PHISHGUARD_API_KEY
                }
            });

            const data = await response.json();

            // Determine icon color based on risk
            let risk = data.combined_risk_score;

            if (risk < 20) {
                chrome.action.setIcon({ tabId, path: "icons/icon16.png" });
            } else if (risk < 60) {
                chrome.action.setIcon({ tabId, path: "icons/icon48.png" });
            } else {
                chrome.action.setIcon({ tabId, path: "icons/icon128.png" });
            }

            // Store result for popup use
            chrome.storage.local.set({ lastScan: data });

        } catch (e) {
            console.error("Auto-scan failed:", e);
        }
    }
});

