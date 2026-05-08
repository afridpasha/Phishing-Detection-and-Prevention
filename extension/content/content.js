// Phishing Shield 2.0 - Content Script
// Real-time page monitoring and link protection

let shieldActive = true;

// Monitor all clicks AUTOMATICALLY and CHECK BEFORE navigation
document.addEventListener('click', async (e) => {
  if (!shieldActive) return;
  
  const link = e.target.closest('a');
  if (link && link.href) {
    // PREVENT default navigation
    e.preventDefault();
    e.stopPropagation();
    
    const url = link.href;
    console.log('🔗 Link clicked:', url);
    
    // Show checking indicator
    const indicator = showCheckingIndicator();
    
    try {
      // Check URL via background script
      const result = await chrome.runtime.sendMessage({
        action: 'checkURL',
        url: url
      });
      
      console.log('📊 Check result:', result);
      
      // Remove indicator
      if (indicator && indicator.parentNode) {
        indicator.remove();
      }
      
      // Check if phishing
      if (result.is_phishing && result.confidence > 0.5) {
        console.log('🚨 PHISHING DETECTED!');
        console.log('Result details:', result);
        
        // Option 1: Show in-page modal (current behavior)
        // showPhishingWarning(url, result);
        
        // Option 2: Redirect to blocked page with full details (BETTER)
        const blockedPageUrl = chrome.runtime.getURL('popup/blocked.html') + 
             '?url=' + encodeURIComponent(url) + 
             '&confidence=' + encodeURIComponent(result.confidence) +
             '&attack=' + encodeURIComponent(result.attack_type || 'phishing') +
             '&target=' + encodeURIComponent(result.suspected_target || '') +
             '&auto=true';
        
        console.log('🔗 Redirecting to blocked page:', blockedPageUrl);
        window.location.href = blockedPageUrl;
      } else {
        console.log('✅ Safe - navigating...');
        // Safe - navigate
        window.location.href = url;
      }
    } catch (error) {
      console.error('❌ Error checking link:', error);
      // On error, remove indicator and navigate anyway
      if (indicator && indicator.parentNode) {
        indicator.remove();
      }
      window.location.href = url;
    }
  }
}, true);

// Monitor form submissions
document.addEventListener('submit', async (e) => {
  if (!shieldActive) return;
  
  const form = e.target;
  const action = form.action;
  
  if (action) {
    e.preventDefault();
    
    const result = await chrome.runtime.sendMessage({
      action: 'checkURL',
      url: action
    });
    
    if (result.is_phishing) {
      showPhishingWarning(action, result.confidence);
    } else {
      form.submit();
    }
  }
}, true);

// Monitor input fields for sensitive data
document.addEventListener('input', (e) => {
  if (!shieldActive) return;
  
  const input = e.target;
  if (input.type === 'password' || input.type === 'email' || input.name.includes('card')) {
    // Check if page is suspicious
    checkPageSecurity();
  }
});

// Show checking indicator
function showCheckingIndicator() {
  // Remove existing indicator if any
  const existing = document.getElementById('phishing-shield-checking');
  if (existing) existing.remove();
  
  const indicator = document.createElement('div');
  indicator.id = 'phishing-shield-checking';
  indicator.innerHTML = `
    <div class="shield-spinner"></div>
    <span>🛡️ Checking link...</span>
  `;
  document.body.appendChild(indicator);
  return indicator;
}

// Show phishing warning modal
function showPhishingWarning(url, result) {
  const warning = document.createElement('div');
  warning.id = 'phishing-shield-warning';
  warning.innerHTML = `
    <div class="shield-warning-content">
      <div class="shield-warning-icon">🚨</div>
      <h2>PHISHING DETECTED</h2>
      <p>This link has been identified as malicious by Phishing Shield 2.0</p>
      <div class="shield-warning-details">
        <p><strong>URL:</strong> ${escapeHtml(url)}</p>
        <p><strong>Confidence:</strong> ${(result.confidence * 100).toFixed(1)}%</p>
        <p><strong>Threat Level:</strong> ${getThreatLevel(result.confidence)}</p>
        ${result.attack_type ? `<p><strong>Attack Type:</strong> ${result.attack_type}</p>` : ''}
        ${result.suspected_target ? `<p><strong>Impersonating:</strong> ${result.suspected_target}</p>` : ''}
      </div>
      <div class="shield-warning-actions">
        <button id="shield-go-back" class="shield-btn-primary">🛡️ Go Back (Recommended)</button>
        <button id="shield-proceed" class="shield-btn-danger">⚠️ Proceed Anyway (Risky)</button>
      </div>
    </div>
  `;
  
  document.body.appendChild(warning);
  
  document.getElementById('shield-go-back').addEventListener('click', () => {
    warning.remove();
  });
  
  document.getElementById('shield-proceed').addEventListener('click', () => {
    warning.remove();
    window.location.href = url;
  });
}

function getThreatLevel(confidence) {
  if (confidence > 0.9) return '🔴 CRITICAL';
  if (confidence > 0.7) return '🟠 HIGH';
  if (confidence > 0.5) return '🟡 MEDIUM';
  return '🟢 LOW';
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Check page security
async function checkPageSecurity() {
  const url = window.location.href;
  
  // Check for HTTPS
  if (!url.startsWith('https://')) {
    showSecurityAlert('⚠️ This page is not secure (no HTTPS)');
  }
  
  // Check URL
  const result = await chrome.runtime.sendMessage({
    action: 'checkURL',
    url: url
  });
  
  if (result.is_phishing) {
    showSecurityAlert('🚨 This page is flagged as phishing!');
  }
}

function showSecurityAlert(message) {
  const alert = document.createElement('div');
  alert.className = 'shield-security-alert';
  alert.textContent = message;
  document.body.appendChild(alert);
  
  setTimeout(() => alert.remove(), 5000);
}

// Scan page for suspicious content AUTOMATICALLY
function scanPage() {
  // Check for suspicious keywords
  const bodyText = document.body.innerText.toLowerCase();
  const suspiciousKeywords = [
    'verify account', 'suspended', 'urgent action', 'click here immediately', 
    'confirm identity', 'unusual activity', 'security alert', 'verify now',
    'account will be closed', 'update payment', 'confirm your identity',
    're-activate', 'limited time', 'act now', 'claim your prize'
  ];
  
  let suspiciousCount = 0;
  const foundKeywords = [];
  
  for (const keyword of suspiciousKeywords) {
    if (bodyText.includes(keyword)) {
      suspiciousCount++;
      foundKeywords.push(keyword);
    }
  }
  
  // If multiple suspicious keywords found, show warning
  if (suspiciousCount >= 3) {
    showSecurityAlert(`⚠️ WARNING: This page contains ${suspiciousCount} suspicious phrases commonly used in phishing!`);
    console.warn('🛡️ Suspicious keywords detected:', foundKeywords);
  }
  
  // Check for hidden iframes
  const iframes = document.querySelectorAll('iframe[style*="display:none"], iframe[style*="visibility:hidden"]');
  if (iframes.length > 0) {
    showSecurityAlert('⚠️ WARNING: This page contains hidden iframes (common phishing technique)!');
    console.warn('🛡️ Hidden iframes detected:', iframes.length);
  }
  
  // Check for password input fields on non-HTTPS pages
  if (window.location.protocol !== 'https:') {
    const passwordFields = document.querySelectorAll('input[type="password"]');
    if (passwordFields.length > 0) {
      showSecurityAlert('🚨 DANGER: This page is asking for passwords without HTTPS encryption!');
      console.error('🛡️ Password field on non-HTTPS page!');
    }
  }
  
  // Check for forms submitting to different domains
  const forms = document.querySelectorAll('form[action]');
  forms.forEach(form => {
    const action = form.getAttribute('action');
    if (action && action.startsWith('http')) {
      try {
        const formDomain = new URL(action).hostname;
        const pageDomain = window.location.hostname;
        if (formDomain !== pageDomain) {
          showSecurityAlert(`⚠️ WARNING: Form submits to different domain: ${formDomain}`);
          console.warn('🛡️ Cross-domain form detected:', formDomain);
        }
      } catch (e) {}
    }
  });
}

// Auto-scan page on load and when content changes
setTimeout(scanPage, 1000);

// Monitor for dynamic content changes
const observer = new MutationObserver((mutations) => {
  // Debounce: only scan if significant changes
  clearTimeout(window.scanTimeout);
  window.scanTimeout = setTimeout(scanPage, 2000);
});

observer.observe(document.body, {
  childList: true,
  subtree: true
});

console.log('%c🛡️ Phishing Shield 2.0 Content Script Active - FULL AUTO MODE', 'background: #667eea; color: white; padding: 5px 10px; border-radius: 3px; font-weight: bold;');
console.log('%c✅ Monitoring: Links, Forms, Page Content, Passwords, Iframes', 'color: #10b981; font-weight: bold;');
console.log('%c✅ Real-time protection enabled across ALL websites', 'color: #10b981; font-weight: bold;');
console.log('%c🔍 Every link click will be checked AUTOMATICALLY', 'color: #3b82f6; font-weight: bold;');
