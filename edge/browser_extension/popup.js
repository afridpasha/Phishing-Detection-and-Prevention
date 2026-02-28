// Load statistics from storage
chrome.storage.local.get(['blocked', 'scanned'], (result) => {
  document.getElementById('blocked').textContent = result.blocked || 0;
  document.getElementById('scanned').textContent = result.scanned || 0;
});

// Scan current page button
document.getElementById('scanBtn').addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  
  // Send message to background script
  chrome.runtime.sendMessage({
    action: 'analyzeURL',
    url: tab.url
  }, (response) => {
    if (response) {
      const status = document.getElementById('status');
      if (response.action === 'block') {
        status.className = 'status warning';
        status.textContent = '⚠️ Threat Detected!';
      } else {
        status.className = 'status safe';
        status.textContent = '✓ Site is Safe';
      }
    }
  });
});
