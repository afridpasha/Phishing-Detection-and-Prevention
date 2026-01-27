// Background Service Worker - Real-time URL Analysis
const API_URL = 'http://localhost:8000/api/v1';
const CACHE_TTL = 3600000; // 1 hour
let urlCache = new Map();

// Quick local check patterns
const SUSPICIOUS_PATTERNS = [
  /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, // IP address
  /[a-z0-9-]+\.(tk|ml|ga|cf|gq)$/i, // Suspicious TLDs
  /@.*http/i, // @ symbol obfuscation
  /paypal.*verify/i, // Brand impersonation
  /account.*suspend/i
];

// Intercept navigation
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId === 0) {
    const url = details.url;
    const result = await analyzeURL(url);
    
    if (result.action === 'block') {
      chrome.tabs.update(details.tabId, {
        url: chrome.runtime.getURL(`warning.html?url=${encodeURIComponent(url)}&score=${result.final_score}`)
      });
    } else if (result.action === 'warn') {
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48"><text y="32" font-size="32">🛡️</text></svg>',
        title: 'Suspicious Website',
        message: `This site may be dangerous. Risk: ${(result.final_score * 100).toFixed(0)}%`
      });
    }
  }
});

async function analyzeURL(url) {
  // Check cache
  if (urlCache.has(url)) {
    const cached = urlCache.get(url);
    if (Date.now() - cached.timestamp < CACHE_TTL) {
      return cached.result;
    }
  }
  
  // Quick local check (<50ms)
  const localScore = quickLocalCheck(url);
  if (localScore > 0.9) {
    return { action: 'block', final_score: localScore, source: 'local' };
  }
  
  // Cloud analysis
  try {
    const response = await fetch(`${API_URL}/analyze/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    
    const result = await response.json();
    urlCache.set(url, { result, timestamp: Date.now() });
    return result;
  } catch (error) {
    console.error('API error:', error);
    return { action: 'allow', final_score: localScore, source: 'local_fallback' };
  }
}

function quickLocalCheck(url) {
  let score = 0;
  for (const pattern of SUSPICIOUS_PATTERNS) {
    if (pattern.test(url)) score += 0.3;
  }
  return Math.min(score, 1.0);
}

// Message handler
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'analyzeURL') {
    analyzeURL(request.url).then(sendResponse);
    return true;
  }
});
