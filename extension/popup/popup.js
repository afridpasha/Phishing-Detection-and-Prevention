// Phishing Shield 2.0 - Popup Script

// Load stats on popup open
document.addEventListener('DOMContentLoaded', async () => {
  loadStats();
  
  // Set up event listeners
  document.getElementById('checkUrlBtn').addEventListener('click', checkURL);
  document.getElementById('checkTextBtn').addEventListener('click', checkText);
  document.getElementById('screenshotBtn').addEventListener('click', scanPage);
  document.getElementById('protectionToggle').addEventListener('change', toggleProtection);
  document.getElementById('settingsBtn').addEventListener('click', openSettings);
  document.getElementById('reportBtn').addEventListener('click', openReport);
  
  // Enter key support
  document.getElementById('urlInput').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') checkURL();
  });
});

// Load statistics
async function loadStats() {
  const response = await chrome.runtime.sendMessage({ action: 'getStats' });
  
  if (response) {
    document.getElementById('blockedCount').textContent = response.stats.blocked;
    document.getElementById('checkedCount').textContent = response.stats.checked;
    document.getElementById('safeCount').textContent = response.stats.safe;
    document.getElementById('protectionToggle').checked = response.protectionEnabled;
    
    updateStatusIndicator(response.protectionEnabled);
  }
}

// Update status indicator
function updateStatusIndicator(enabled) {
  const indicator = document.getElementById('statusIndicator');
  const statusText = indicator.querySelector('.status-text');
  const statusDot = indicator.querySelector('.status-dot');
  
  if (enabled) {
    statusText.textContent = 'ACTIVE';
    statusDot.style.background = '#10b981';
  } else {
    statusText.textContent = 'DISABLED';
    statusDot.style.background = '#ef4444';
  }
}

// Check URL
async function checkURL() {
  const input = document.getElementById('urlInput');
  const url = input.value.trim();
  
  if (!url) {
    showError('Please enter a URL');
    return;
  }
  
  showLoading('Checking URL...');
  
  const result = await chrome.runtime.sendMessage({
    action: 'checkURL',
    url: url
  });
  
  hideLoading();
  showResult(result, 'URL');
  input.value = '';
}

// Check text (SMS/Email)
async function checkText() {
  const input = document.getElementById('textInput');
  const text = input.value.trim();
  
  if (!text) {
    showError('Please enter text to check');
    return;
  }
  
  showLoading('Analyzing text...');
  
  const result = await chrome.runtime.sendMessage({
    action: 'checkText',
    text: text
  });
  
  hideLoading();
  showResult(result, 'Text');
  input.value = '';
}

// Scan current page
async function scanPage() {
  showLoading('Scanning page...');
  
  // Get current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  
  // Check URL
  const result = await chrome.runtime.sendMessage({
    action: 'checkURL',
    url: tab.url
  });
  
  hideLoading();
  showResult(result, 'Page');
}

// Show result
function showResult(result, type) {
  const container = document.getElementById('resultContainer');
  const icon = document.getElementById('resultIcon');
  const title = document.getElementById('resultTitle');
  const confidence = document.getElementById('resultConfidence');
  const threat = document.getElementById('resultThreat');
  
  const isPhishing = result.is_phishing || result.is_smishing;
  const conf = (result.confidence * 100).toFixed(1);
  
  container.className = 'result-container ' + (isPhishing ? 'phishing' : 'safe');
  icon.textContent = isPhishing ? '🚨' : '✅';
  title.textContent = isPhishing ? `${type} IS PHISHING` : `${type} IS SAFE`;
  confidence.textContent = conf + '%';
  threat.textContent = getThreatLevel(result.confidence);
  
  // Reload stats
  loadStats();
}

function getThreatLevel(confidence) {
  if (confidence > 0.9) return '🔴 CRITICAL';
  if (confidence > 0.7) return '🟠 HIGH';
  if (confidence > 0.5) return '🟡 MEDIUM';
  return '🟢 LOW';
}

// Toggle protection
async function toggleProtection() {
  const response = await chrome.runtime.sendMessage({ action: 'toggleProtection' });
  updateStatusIndicator(response.protectionEnabled);
  
  chrome.notifications.create({
    type: 'basic',
    iconUrl: '../icons/icon128.png',
    title: 'Phishing Shield',
    message: response.protectionEnabled ? 'Protection enabled' : 'Protection disabled'
  });
}

// Open settings
function openSettings() {
  chrome.runtime.openOptionsPage();
}

// Open report
function openReport() {
  chrome.tabs.create({ url: 'http://localhost:5000' });
}

// Show loading
function showLoading(message) {
  const container = document.getElementById('resultContainer');
  container.className = 'result-container';
  container.innerHTML = `
    <div style="text-align: center; padding: 20px;">
      <div class="spinner"></div>
      <p style="margin-top: 10px; color: #6b7280;">${message}</p>
    </div>
  `;
  
  // Add spinner CSS if not exists
  if (!document.getElementById('spinner-style')) {
    const style = document.createElement('style');
    style.id = 'spinner-style';
    style.textContent = `
      .spinner {
        width: 40px;
        height: 40px;
        margin: 0 auto;
        border: 4px solid #e5e7eb;
        border-top-color: #667eea;
        border-radius: 50%;
        animation: spin 0.8s linear infinite;
      }
      @keyframes spin {
        to { transform: rotate(360deg); }
      }
    `;
    document.head.appendChild(style);
  }
}

function hideLoading() {
  const container = document.getElementById('resultContainer');
  container.innerHTML = `
    <div class="result-header">
      <span id="resultIcon"></span>
      <span id="resultTitle"></span>
    </div>
    <div class="result-details">
      <div class="result-row">
        <span>Confidence:</span>
        <span id="resultConfidence"></span>
      </div>
      <div class="result-row">
        <span>Threat Level:</span>
        <span id="resultThreat"></span>
      </div>
    </div>
  `;
}

// Show error
function showError(message) {
  const container = document.getElementById('resultContainer');
  container.className = 'result-container phishing';
  container.innerHTML = `
    <div class="result-header">
      <span>⚠️</span>
      <span>Error</span>
    </div>
    <div class="result-details">
      <p style="padding: 10px 0;">${message}</p>
    </div>
  `;
}
