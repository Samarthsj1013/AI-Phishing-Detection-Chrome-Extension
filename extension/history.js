function loadHistory() {
  chrome.storage.local.get(['scanHistory'], (result) => {
    const history = result.scanHistory || [];
    const list = document.getElementById('historyList');

    if (history.length === 0) {
      list.innerHTML = '<div class="empty-msg">No scans yet. Start scanning websites!</div>';
      return;
    }

    list.innerHTML = '';
    history.reverse().forEach(item => {
      const div = document.createElement('div');
      div.className = `history-item ${item.result === 'Phishing' ? 'phishing' : 'safe'}`;
      div.innerHTML = `
        <div class="history-url">${item.url}</div>
        <div class="history-meta">
          <span class="history-result ${item.result === 'Phishing' ? 'phishing' : 'safe'}">${item.result}</span>
          <span>${item.confidence}% · ${item.time}</span>
        </div>
      `;
      list.appendChild(div);
    });
  });
}

document.getElementById('clearBtn').addEventListener('click', () => {
  chrome.storage.local.set({ scanHistory: [] }, loadHistory);
});

loadHistory();