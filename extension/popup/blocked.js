// Blocked Page Script - External file to comply with CSP

// Wait for DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
  console.log('DOM loaded, initializing blocked page...');
  initializeBlockedPage();
  
  // Set up button event listeners
  setupButtonListeners();
});

// Also try immediately in case DOMContentLoaded already fired
if (document.readyState === 'loading') {
  console.log('Document still loading, waiting for DOMContentLoaded');
} else {
  console.log('Document already loaded, initializing immediately');
  initializeBlockedPage();
  setupButtonListeners();
}

function initializeBlockedPage() {
  console.log('=== Blocked Page Initialization ===');
  console.log('Full URL:', window.location.href);
  
  // Parse URL parameters
  const params = new URLSearchParams(window.location.search);
  console.log('Raw search string:', window.location.search);
  console.log('URL Parameters:', {
    url: params.get('url'),
    confidence: params.get('confidence'),
    attack: params.get('attack'),
    target: params.get('target'),
    auto: params.get('auto')
  });
  
  // Get parameters with defaults
  const blockedUrl = params.get('url') || 'Unknown URL';
  const confidence = params.get('confidence') || '0.95';
  const attackType = params.get('attack') || 'phishing';
  const suspectedTarget = params.get('target') || '';
  const isAuto = params.get('auto') === 'true';
  
  console.log('Parsed values:', {
    blockedUrl,
    confidence,
    attackType,
    suspectedTarget,
    isAuto
  });

  // Update all fields
  try {
    // Blocked URL
    const urlElement = document.getElementById('blockedUrl');
    if (urlElement) {
      const decodedUrl = decodeURIComponent(blockedUrl);
      urlElement.textContent = decodedUrl;
      console.log('✅ Set blocked URL:', decodedUrl);
    } else {
      console.error('❌ Element blockedUrl not found');
    }
    
    // Confidence
    const confElement = document.getElementById('confidence');
    if (confElement) {
      const confValue = parseFloat(confidence);
      const confText = (confValue * 100).toFixed(1) + '%';
      confElement.textContent = confText;
      console.log('✅ Set confidence:', confText);
    } else {
      console.error('❌ Element confidence not found');
    }
    
    // Detection Time
    const timeElement = document.getElementById('detectionTime');
    if (timeElement) {
      const timeText = new Date().toLocaleString();
      timeElement.textContent = timeText;
      console.log('✅ Set detection time:', timeText);
    } else {
      console.error('❌ Element detectionTime not found');
    }

    // Threat Level
    const conf = parseFloat(confidence);
    const threatElement = document.getElementById('threatLevel');
    if (threatElement) {
      let threatText = '';
      if (conf > 0.9) {
        threatText = '🔴 CRITICAL';
        threatElement.style.color = '#ef4444';
      } else if (conf > 0.7) {
        threatText = '🟠 HIGH';
        threatElement.style.color = '#f59e0b';
      } else if (conf > 0.5) {
        threatText = '🟡 MEDIUM';
        threatElement.style.color = '#eab308';
      } else {
        threatText = '🟢 LOW';
        threatElement.style.color = '#10b981';
      }
      threatElement.textContent = threatText;
      console.log('✅ Set threat level:', threatText);
    } else {
      console.error('❌ Element threatLevel not found');
    }
    
    // Add attack type info if available
    if (attackType && attackType !== 'phishing') {
      const warningList = document.querySelector('.warning-list ul');
      if (warningList) {
        const attackInfo = document.createElement('li');
        attackInfo.textContent = `Attack Type: ${attackType.replace(/_/g, ' ').toUpperCase()}`;
        attackInfo.style.fontWeight = 'bold';
        warningList.insertBefore(attackInfo, warningList.firstChild);
        console.log('✅ Added attack type:', attackType);
      }
    }
    
    // Add suspected target if available
    if (suspectedTarget) {
      const warningList = document.querySelector('.warning-list ul');
      if (warningList) {
        const targetInfo = document.createElement('li');
        targetInfo.textContent = `Impersonating: ${suspectedTarget}`;
        targetInfo.style.color = '#fca5a5';
        targetInfo.style.fontWeight = 'bold';
        warningList.insertBefore(targetInfo, warningList.firstChild);
        console.log('✅ Added suspected target:', suspectedTarget);
      }
    }
    
    // Add auto-detection badge if applicable
    if (isAuto) {
      const subtitle = document.querySelector('.subtitle');
      if (subtitle) {
        const badge = document.createElement('span');
        badge.style.cssText = 'background: rgba(16, 185, 129, 0.2); padding: 5px 15px; border-radius: 20px; font-size: 14px; margin-top: 10px; display: inline-block;';
        badge.textContent = '✅ Detected Automatically';
        subtitle.appendChild(document.createElement('br'));
        subtitle.appendChild(badge);
        console.log('✅ Added auto-detection badge');
      }
    }
    
    console.log('✅ All fields updated successfully');
  } catch (error) {
    console.error('❌ Error updating fields:', error);
    console.error('Error stack:', error.stack);
  }
  
  console.log('=== Initialization Complete ===');
}

function setupButtonListeners() {
  // Go Back button
  const goBackBtn = document.getElementById('shield-go-back');
  if (goBackBtn) {
    goBackBtn.addEventListener('click', goBack);
    console.log('✅ Go Back button listener attached');
  }
  
  // Proceed Anyway button
  const proceedBtn = document.getElementById('shield-proceed');
  if (proceedBtn) {
    proceedBtn.addEventListener('click', proceedAnyway);
    console.log('✅ Proceed Anyway button listener attached');
  }
}

function goBack() {
  console.log('Going back...');
  
  // Send message to background script to handle navigation
  chrome.runtime.sendMessage({ action: 'goBack' }, function(response) {
    if (chrome.runtime.lastError) {
      console.error('Error sending message:', chrome.runtime.lastError);
      // Fallback
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.close();
      }
    } else {
      console.log('✅ Go back message sent');
    }
  });
}

function proceedAnyway() {
  console.log('User wants to proceed anyway');
  const params = new URLSearchParams(window.location.search);
  const blockedUrl = params.get('url');
  
  if (!blockedUrl || blockedUrl === 'Unknown URL') {
    console.error('No URL to proceed to');
    alert('Error: No URL found to navigate to.');
    return;
  }
  
  const decodedUrl = decodeURIComponent(blockedUrl);
  console.log('Decoded URL:', decodedUrl);
  
  const confirmMsg = '⚠️ WARNING: You are about to visit a potentially dangerous website.\n\n' +
                    'This site has been flagged as phishing and may:\n' +
                    '• Steal your passwords\n' +
                    '• Compromise your personal data\n' +
                    '• Install malware\n\n' +
                    'Are you absolutely sure you want to proceed?';
  
  if (confirm(confirmMsg)) {
    console.log('User confirmed, navigating to:', decodedUrl);
    
    // Send message to background script to handle navigation
    chrome.runtime.sendMessage({ 
      action: 'proceedToURL', 
      url: decodedUrl 
    }, function(response) {
      if (chrome.runtime.lastError) {
        console.error('Error sending message:', chrome.runtime.lastError);
        // Fallback to direct navigation
        window.location.href = decodedUrl;
      } else {
        console.log('✅ Navigation message sent');
      }
    });
  } else {
    console.log('User cancelled');
  }
}
