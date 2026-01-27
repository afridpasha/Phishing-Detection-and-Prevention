// Popup UI Logic
document.addEventListener('DOMContentLoaded', async () => {
  const statusDiv = document.getElementById('status');
  const scanBtn = document.getElementById('scanBtn');
  const reportBtn = document.getElementById('reportBtn');
  
  // Get current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  
  // Load stats
  const stats = await chrome.storage.local.get(['blocked', 'scanned']);
  document.getElementById('blocked').textContent = stats.blocked || 0;
  document.getElementById('scanned').textContent = stats.scanned || 0;
  
  // Scan current page
  scanBtn.addEventListener('click', async () => {
    scanBtn.textContent = 'Scanning...';
    scanBtn.disabled = true;
    
    const response = await chrome.runtime.sendMessage({
      action: 'analyzeURL',
      url: tab.url
    });
    
    updateStatus(response);
    scanBtn.textContent = 'Scan Current Page';
    scanBtn.disabled = false;
    
    // Update stats
    const newStats = await chrome.storage.local.get(['scanned']);
    await chrome.storage.local.set({ scanned: (newStats.scanned || 0) + 1 });
  });
  
  // Report phishing
  reportBtn.addEventListener('click', () => {
    chrome.tabs.create({
      url: `http://localhost:8000/report?url=${encodeURIComponent(tab.url)}`
    });
  });
  
  function updateStatus(result) {
    if (result.action === 'block') {
      statusDiv.className = 'status danger';
      statusDiv.innerHTML = '<strong>⚠️ DANGER</strong><br>Phishing detected!';
    } else if (result.action === 'warn') {
      statusDiv.className = 'status warning';
      statusDiv.innerHTML = '<strong>⚠️ WARNING</strong><br>Suspicious activity';
    } else {
      statusDiv.className = 'status safe';
      statusDiv.innerHTML = '<strong>✅ SAFE</strong><br>Page appears legitimate';
    }
  }
});
