// Scan page for suspicious links
function scanPageLinks() {
  const links = document.querySelectorAll('a[href]');
  
  links.forEach(link => {
    const href = link.href;
    
    // Quick client-side checks
    const suspiciousPatterns = [
      /paypa1/i,
      /g00gle/i,
      /amaz0n/i,
      /micr0soft/i,
      /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/  // IP address
    ];
    
    const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(href));
    
    if (isSuspicious) {
      // Highlight suspicious link
      link.style.border = '2px solid red';
      link.style.backgroundColor = '#ffcccc';
      link.title = '⚠️ Warning: This link may be suspicious';
      
      // Prevent immediate navigation
      link.addEventListener('click', (e) => {
        e.preventDefault();
        if (confirm('⚠️ Phishing Shield Warning\n\nThis link appears suspicious. Do you want to continue?')) {
          window.location.href = href;
        }
      });
    }
  });
}

// Run scan when page loads
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', scanPageLinks);
} else {
  scanPageLinks();
}

// Re-scan on dynamic content changes
const observer = new MutationObserver(() => {
  scanPageLinks();
});

observer.observe(document.body, {
  childList: true,
  subtree: true
});
