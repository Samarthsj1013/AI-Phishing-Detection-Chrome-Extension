const API_URL = "https://ai-phishing-detection-chrome-extension-1.onrender.com/analyze";
function truncateURL(url, maxLen = 45) {
  return url.length > maxLen ? url.substring(0, maxLen) + "..." : url;
}

// Show current tab URL on load
chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
  const url = tabs[0]?.url || "";
  document.getElementById("urlText").textContent = truncateURL(url);
});

document.getElementById("scanBtn").addEventListener("click", () => {
  const btn = document.getElementById("scanBtn");
  const btnText = document.getElementById("btnText");
  const resultCard = document.getElementById("resultCard");
  const errorMsg = document.getElementById("errorMsg");

  // Reset
  resultCard.className = "result-card hidden";
  errorMsg.classList.add("hidden");
  btn.disabled = true;
  btnText.textContent = "⏳ Scanning...";

  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    const url = tabs[0]?.url || "";

    fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    })
      .then(res => res.json())
      .then(data => {
        btn.disabled = false;
        btnText.textContent = "🔍 Scan Again";

        const isPhishing = data.result === "Phishing";

        // Result card
        resultCard.className = `result-card ${isPhishing ? "phishing" : "safe"}`;
        document.getElementById("resultIcon").textContent = isPhishing ? "⚠️" : "✅";
        document.getElementById("resultText").textContent = isPhishing ? "Phishing Detected" : "Safe Website";

        // Confidence bar
        const conf = data.confidence || 0;
        document.getElementById("confidenceValue").textContent = `${conf}%`;
        document.getElementById("confidenceFill").style.width = `${conf}%`;

        // Reasons (SHAP-based)
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
      })
      .catch(err => {
        btn.disabled = false;
        btnText.textContent = "🔍 Scan Website";
        errorMsg.classList.remove("hidden");
        console.error(err);
      });
  });
});