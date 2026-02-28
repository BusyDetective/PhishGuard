chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    let url = tabs[0].url;
    document.getElementById("url").textContent = url;

    chrome.storage.local.get("lastScan", (data) => {
        if (!data.lastScan) {
            document.getElementById("risk").textContent = "Scanning...";
            return;
        }

        const result = data.lastScan;
        const score = result.combined_risk_score;

        if (score < 20) {
            document.getElementById("risk").textContent = "SAFE (" + score + "%)";
            document.getElementById("risk").className = "safe";
        } else if (score < 60) {
            document.getElementById("risk").textContent = "WARNING (" + score + "%)";
            document.getElementById("risk").className = "warn";
        } else {
            document.getElementById("risk").textContent = "DANGEROUS (" + score + "%)";
            document.getElementById("risk").className = "danger";
        }
    });
});

