// Warning page script
const params = new URLSearchParams(window.location.search);
const blockedUrl = params.get('url');
const score = params.get('score');

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('blockedUrl').textContent = blockedUrl || 'Unknown URL';
  document.getElementById('riskScore').textContent = score ? (parseFloat(score) * 100).toFixed(0) + '%' : 'N/A';
  
  document.getElementById('goBackBtn').addEventListener('click', () => {
    history.back();
  });
  
  document.getElementById('proceedBtn').addEventListener('click', () => {
    if (confirm('Are you sure? This site is dangerous!')) {
      window.location.href = blockedUrl;
    }
  });
});
