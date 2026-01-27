// Content Script - Analyzes page content
(function() {
  'use strict';
  
  // Check for password fields on HTTP
  if (window.location.protocol === 'http:') {
    const passwordFields = document.querySelectorAll('input[type="password"]');
    if (passwordFields.length > 0) {
      console.warn('⚠️ Password field on insecure HTTP connection!');
      chrome.runtime.sendMessage({
        action: 'securityWarning',
        type: 'http_password',
        url: window.location.href
      });
    }
  }
  
  // Detect suspicious forms
  const forms = document.querySelectorAll('form');
  forms.forEach(form => {
    const action = form.getAttribute('action');
    if (action && action.startsWith('http') && !action.includes(window.location.hostname)) {
      console.warn('⚠️ Form submits to external domain:', action);
    }
  });
  
  // Monitor for dynamic content changes
  const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      mutation.addedNodes.forEach((node) => {
        if (node.nodeName === 'FORM') {
          // New form added dynamically
          console.log('Dynamic form detected');
        }
      });
    });
  });
  
  observer.observe(document.body, { childList: true, subtree: true });
})();
