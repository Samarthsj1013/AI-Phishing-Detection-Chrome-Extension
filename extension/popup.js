const API_URL = "https://ai-phishing-detection-chrome-extension-1.onrender.com/analyze";
const REPORT_URL = "https://script.google.com/macros/s/AKfycbxZgWniZ3rlX2R3WKJJ7Z9ZwBNz86Z6XFp-_mlFIvlWa_ZrGRtFqL0M-hPatz3QPyTQnQ/exec";

function truncateURL(url, maxLen = 45) {
  return url.length > maxLen ? url.substring(0, maxLen) + "..." : url;
}

let lastScanURL = "";
let lastScanResult = "";

// Restore last scan result when popup opens
chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
  const url = tabs[0]?.url || "";
  document.getElementById("urlText").textContent = truncateURL(url);

  chrome.storage.local.get(['lastScan'], (stored) => {
    if (stored.lastScan && stored.lastScan.url === url) {
      restoreResult(stored.lastScan);
    }
  });
});

function restoreResult(data) {
  lastScanURL = data.url;
  lastScanResult = data.result;

  const isPhishing = data.result === "Phishing";
  const resultCard = document.getElementById("resultCard");

  resultCard.className = `result-card ${isPhishing ? "phishing" : "safe"}`;
  document.getElementById("resultIcon").textContent = isPhishing ? "⚠️" : "✅";
  document.getElementById("resultText").textContent = isPhishing ? "Phishing Detected" : "Safe Website";

  const conf = data.confidence || 0;
  document.getElementById("confidenceValue").textContent = `${conf}%`;
  document.getElementById("confidenceFill").style.width = `${conf}%`;

  const reasonsSection = document.getElementById("reasonsSection");
  const reasonsList = document.getElementById("reasonsList");
  reasonsList.innerHTML = "";

  if (data.reasons && data.reasons.length > 0 && isPhishing) {
    reasonsSection.classList.remove("hidden");
    data.reasons.forEach(r => {
      const li = document.createElement("li");
      li.className = `impact-${r.impact || "medium"}`;
      li.textContent = r.reason;
      reasonsList.appendChild(li);
    });
  } else {
    reasonsSection.classList.add("hidden");
  }

  document.getElementById("reportSection").classList.remove("hidden");
  document.getElementById("btnText").textContent = "🔍 Scan Again";
}

document.getElementById("scanBtn").addEventListener("click", () => {
  const btn = document.getElementById("scanBtn");
  const btnText = document.getElementById("btnText");
  const resultCard = document.getElementById("resultCard");
  const errorMsg = document.getElementById("errorMsg");

  resultCard.className = "result-card hidden";
  errorMsg.classList.add("hidden");
  document.getElementById("reportSection").classList.add("hidden");
  document.getElementById("reportConfirm").classList.add("hidden");
  document.getElementById("reportBtn").classList.remove("hidden");
  btn.disabled = true;
  btnText.textContent = "⏳ Scanning...";

  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    const url = tabs[0]?.url || "";
    lastScanURL = url;

    fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    })
      .then(res => res.json())
      .then(data => {
        btn.disabled = false;
        btnText.textContent = "🔍 Scan Again";
        lastScanResult = data.result;

        const isPhishing = data.result === "Phishing";

        resultCard.className = `result-card ${isPhishing ? "phishing" : "safe"}`;
        document.getElementById("resultIcon").textContent = isPhishing ? "⚠️" : "✅";
        document.getElementById("resultText").textContent = isPhishing ? "Phishing Detected" : "Safe Website";

        const conf = data.confidence || 0;
        document.getElementById("confidenceValue").textContent = `${conf}%`;
        document.getElementById("confidenceFill").style.width = `${conf}%`;

        // Save last scan for restore
        chrome.storage.local.set({
          lastScan: {
            url,
            result: data.result,
            confidence: data.confidence,
            reasons: data.reasons || []
          }
        });

        // Save to history
        chrome.storage.local.get(['scanHistory'], (result) => {
          const history = result.scanHistory || [];
          history.push({
            url: url.length > 60 ? url.substring(0, 60) + '...' : url,
            result: data.result,
            confidence: data.confidence,
            time: new Date().toLocaleTimeString()
          });
          if (history.length > 20) history.shift();
          chrome.storage.local.set({ scanHistory: history });
          updateHistoryCount();
        });

        const reasonsSection = document.getElementById("reasonsSection");
        const reasonsList = document.getElementById("reasonsList");
        reasonsList.innerHTML = "";

        if (data.reasons && data.reasons.length > 0 && isPhishing) {
          reasonsSection.classList.remove("hidden");
          data.reasons.forEach(r => {
            const li = document.createElement("li");
            li.className = `impact-${r.impact || "medium"}`;
            li.textContent = r.reason;
            reasonsList.appendChild(li);
          });
        } else {
          reasonsSection.classList.add("hidden");
        }

        document.getElementById("reportSection").classList.remove("hidden");
      })
      .catch(err => {
        btn.disabled = false;
        btnText.textContent = "🔍 Scan Website";
        errorMsg.classList.remove("hidden");
        console.error(err);
      });
  });
});

// Report false positive
document.getElementById("reportBtn").addEventListener("click", () => {
  const correctLabel = lastScanResult === "Phishing" ? "Safe" : "Phishing";

  fetch(REPORT_URL, {
    method: "POST",
    headers: { "Content-Type": "text/plain" },
    body: JSON.stringify({
      url: lastScanURL,
      model_result: lastScanResult,
      correct_label: correctLabel,
      note: "Reported via extension"
    })
  }).then(() => {
    document.getElementById("reportBtn").classList.add("hidden");
    document.getElementById("reportConfirm").classList.remove("hidden");
  }).catch(() => {
    document.getElementById("reportConfirm").textContent = "✓ Reported!";
    document.getElementById("reportBtn").classList.add("hidden");
    document.getElementById("reportConfirm").classList.remove("hidden");
  });
});

// History button
document.getElementById('historyBtn').addEventListener('click', () => {
  const historyUrl = chrome.runtime.getURL('history.html');
  chrome.tabs.query({}, (tabs) => {
    const existing = tabs.find(t => t.url === historyUrl);
    if (existing) {
      chrome.tabs.update(existing.id, { active: true });
    } else {
      chrome.tabs.create({ url: historyUrl });
    }
  });
});

function updateHistoryCount() {
  chrome.storage.local.get(['scanHistory'], (result) => {
    const count = (result.scanHistory || []).length;
    const btn = document.getElementById('historyBtn');
    btn.textContent = count > 0 ? `📋 History (${count})` : '📋 History';
  });
}

updateHistoryCount();