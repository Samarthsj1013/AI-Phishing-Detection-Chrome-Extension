const API_URL = "https://ai-phishing-detection-chrome-extension-1.onrender.com/analyze";

// Listen for tab updates
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  const tab = await chrome.tabs.get(activeInfo.tabId);
  if (tab.url) updateIcon(tab.url, activeInfo.tabId);
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    updateIcon(tab.url, tabId);
  }
});

async function updateIcon(url, tabId) {
  // Skip internal URLs
  if (url.startsWith("chrome://") || url.startsWith("chrome-extension://") || 
      url.startsWith("about:") || url.includes("127.0.0.1") || url.includes("localhost")) {
    chrome.action.setIcon({ tabId, path: { "16": "icons/icon16.png", "48": "icons/icon48.png" } });
    return;
  }

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    const data = await response.json();

    if (data.result === "Phishing") {
      chrome.action.setIcon({ tabId, path: { "16": "icons/icon_red16.png", "48": "icons/icon_red48.png" } });
      chrome.action.setBadgeText({ tabId, text: "!" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#ef4444" });
    } else {
      chrome.action.setIcon({ tabId, path: { "16": "icons/icon_green16.png", "48": "icons/icon_green48.png" } });
      chrome.action.setBadgeText({ tabId, text: "" });
    }
  } catch (e) {
    console.error("Background scan error:", e);
  }
}