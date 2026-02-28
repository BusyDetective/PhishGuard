const LICENSE_STORAGE_KEY = "phishguard_license";

function getActivePlan(callback) {
  chrome.storage.local.get(LICENSE_STORAGE_KEY, (data) => {
    const license = data[LICENSE_STORAGE_KEY];
    callback(license?.plan || "FREE");
  });
}

function applyReportGating(plan) {
  if (plan !== "PRO") {
    document
      .querySelectorAll("[data-pro-only='true']")
      .forEach(el => el.remove());
  }
}

getActivePlan((plan) => {
  applyReportGating(plan);

  chrome.storage.local.get("phishguard_report", (res) => {
    const data = res.phishguard_report;

    document.getElementById("version").textContent = "1.0.0";

    if (!data) {
      document.body.innerHTML = "<h2>No report data found</h2>";
      return;
    }

    console.log("Loaded report data:", data);

    const overallRisk = Number(data.overallRisk || 0);

    // ===== Branding / Client Info =====
    const brandingMeta = document.getElementById("brandingMeta");

    const scanId =
      "PG-" + new Date(data.generated_at).getTime().toString(36).toUpperCase();

    const clientName = data.client_name || "Internal Scan";

    brandingMeta.textContent =
      `Client: ${clientName} | Scan ID: ${scanId}`;


    const execSummary = document.getElementById("execSummary");

    const riskLevel =
      overallRisk >= 80 ? "CRITICAL" :
      overallRisk >= 60 ? "HIGH" :
      overallRisk >= 30 ? "MODERATE" : "LOW";

    execSummary.innerHTML = `
      This report summarizes the phishing risk assessment for the scanned webpage.
      A total of <strong>${data.stats.total_scanned}</strong> links were analyzed,
      out of which <strong>${data.stats.high_risk}</strong> were identified as
      high risk and <strong>${data.stats.suspicious}</strong> as suspicious.
      <br><br>
      The overall phishing risk for this page is classified as
      <strong>${riskLevel}</strong> (<strong>${overallRisk}%</strong>).
      Users are advised to exercise
      ${
        riskLevel === "CRITICAL" ? "extreme caution" :
        riskLevel === "HIGH" ? "high caution" :
        riskLevel === "MODERATE" ? "moderate caution" :
        "standard caution"
      }
      when interacting with links on this page.
    `;


    document.getElementById("meta").textContent =
      `Generated at ${new Date(data.generated_at).toLocaleString()}
      | Page: ${data.pageUrl}`;

    document.getElementById("generatedAt").textContent =
    new Date(data.generated_at).toLocaleString();

    document.getElementById("high").textContent = data.stats.high_risk;
    document.getElementById("warn").textContent = data.stats.suspicious;
    document.getElementById("total").textContent = data.stats.total_scanned;
    // ===== Core Metrics =====
    const total = data.stats.total_scanned || 1;
    const highPct = Math.round((data.stats.high_risk / total) * 100);
    const warnPct = Math.round((data.stats.suspicious / total) * 100);
    const safePct = Math.max(0, 100 - highPct - warnPct);

    // ===== AI Confidence Score =====
    let confidenceScore = Math.min(
      95,
      Math.round(
        ((data.stats.high_risk + data.stats.suspicious) / total) * 100
      )
    );

    let confidenceLabel = "LOW";
    let confidenceClass = "conf-low";

    if (confidenceScore >= 70) {
      confidenceLabel = "HIGH";
      confidenceClass = "conf-high";
    } else if (confidenceScore >= 40) {
      confidenceLabel = "MEDIUM";
      confidenceClass = "conf-medium";
    }

    const confidenceEl = document.getElementById("confidence");
    if (confidenceEl) {
      confidenceEl.innerHTML = `
        <span class="badge ${confidenceClass}">
          ${confidenceScore}% (${confidenceLabel})
        </span>`;
    }


    let severityLabel = "LOW";
    let severityClass = "low";

    if (overallRisk >= 80) {
      severityLabel = "CRITICAL";
      severityClass = "critical";
    } else if (overallRisk >= 60) {
      severityLabel = "HIGH";
      severityClass = "high";
    } else if (overallRisk >= 30) {
      severityLabel = "MEDIUM";
      severityClass = "medium";
    }

    document.getElementById("overall").innerHTML =
      `<span class="badge ${severityClass}">${overallRisk}%</span>`;

    document.getElementById("severity").innerHTML =
      `<span class="badge ${severityClass}">${severityLabel}</span>`;

    
    const recList = document.getElementById("recommendations");
    if (recList) {
      recList.innerHTML = "";

      if (overallRisk >= 70) {
        recList.innerHTML += "<li>Avoid clicking unknown or shortened links.</li>";
        recList.innerHTML += "<li>Verify website domains before entering credentials.</li>";
        recList.innerHTML += "<li>Enable strict phishing protection and blocking.</li>";
        recList.innerHTML += "<li>Educate users on phishing attack patterns.</li>";
      } else if (overallRisk >= 40) {
        recList.innerHTML += "<li>Exercise caution with external links.</li>";
        recList.innerHTML += "<li>Verify login pages and redirects.</li>";
        recList.innerHTML += "<li>Monitor for suspicious behavior.</li>";
      } else {
        recList.innerHTML += "<li>Current risk level is low.</li>";
        recList.innerHTML += "<li>Maintain standard browsing hygiene.</li>";
      }
    }

    
    const highPctEl = document.getElementById("highPct");
    const warnPctEl = document.getElementById("warnPct");
    const safePctEl = document.getElementById("safePct");

    if (highPctEl && warnPctEl && safePctEl) {
      highPctEl.textContent = highPct;
      warnPctEl.textContent = warnPct;
      safePctEl.textContent = safePct;

      const highBar = document.getElementById("highBar");
      const warnBar = document.getElementById("warnBar");
      const safeBar = document.getElementById("safeBar");

      if (highBar) highBar.style.width = highPct + "%";
      if (warnBar) warnBar.style.width = warnPct + "%";
      if (safeBar) safeBar.style.width = safePct + "%";
    }

    const tbody = document.getElementById("domains");
    tbody.innerHTML = "";

    Object.entries(data.top_risky_domains || {}).forEach(([d, c]) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${d}</td><td>${c}</td>`;
      tbody.appendChild(tr);
    });

    const evidenceTable = document.getElementById("evidence");
    if (evidenceTable) {
      evidenceTable.innerHTML = "";

      (data.evidence || []).slice(0, 50).forEach(item => {
        const tr = document.createElement("tr");

        tr.innerHTML = `
          <td>
            <a href="${item.url}" target="_blank" style="word-break:break-all;">
              ${item.url}
            </a>
          </td>
          <td>${item.domain}</td>
          <td>
            <span class="badge ${
              item.level === "HIGH" ? "danger" : "warn"
            }">${item.level}</span>
          </td>
          <td>${item.reasons.join(", ")}</td>
        `;

        evidenceTable.appendChild(tr);
      });
    }


    // ===== Report Controls =====

    // PDF (uses browser print)
    document.getElementById("btnPrint").onclick = () => {
      setTimeout(() => {
        window.print();
      }, 800);
    };

    // JSON export
    const btnJSON = document.getElementById("btnJSON");
    if (btnJSON) {
      btnJSON.onclick = () => {

        const blob = new Blob(
          [JSON.stringify(data, null, 2)],
          { type: "application/json" }
        );
        downloadBlob(blob, "phishguard-report.json");
      };
    }

    // CSV export
    const btnCSV = document.getElementById("btnCSV");
      if (btnCSV) {
        btnCSV.onclick = () => {
          let csv = "Domain,Count\n";
          Object.entries(data.top_risky_domains || {}).forEach(([d, c]) => {
            csv += `${d},${c}\n`;
          });

          const blob = new Blob([csv], { type: "text/csv" });
          downloadBlob(blob, "phishguard-report.csv");
        };
      }

    function downloadBlob(blob, filename) {
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }
  });
});

