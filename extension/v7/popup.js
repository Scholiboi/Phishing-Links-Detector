// popup.js

document.getElementById('verifyBtn').addEventListener('click', () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (!tab || !tab.url) {
      document.getElementById('result').textContent = 'Could not get tab URL.';
      return;
    }
    document.getElementById('result').textContent = 'Checking...';
    fetch('http://localhost:5000/domain_status', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain: (new URL(tab.url)).hostname })
    })
      .then(resp => {
        if (!resp.ok) throw new Error('Server error');
        return resp.json();
      })
      .then(data => {
        if (data.status === 0) {
          document.getElementById('result').textContent = 'Phishing detected! Redirecting...';
          setTimeout(() => {
            chrome.tabs.update(tab.id, { url: chrome.runtime.getURL('blocked.html') });
          }, 1200);
        } else {
          document.getElementById('result').textContent = 'Site is safe.';
        }
      })
      .catch(e => {
        document.getElementById('result').textContent = 'Error: ' + e.message;
      });
  });
});

// Show cached websites and their status
function renderCacheList() {
  chrome.storage.local.get('domainStatusCache', (result) => {
    const cache = result.domainStatusCache || {};
    const cacheList = document.getElementById('cacheList');
    cacheList.innerHTML = '';
    const entries = Object.entries(cache);
    if (entries.length === 0) {
      cacheList.innerHTML = '<li><em>No cached domains</em></li>';
      return;
    }
    for (const [domain, status] of entries) {
      const li = document.createElement('li');
      li.textContent = `${domain} — ${status === 1 ? 'Whitelisted' : 'Blocked'}`;
      li.style.color = status === 1 ? 'green' : 'red';
      cacheList.appendChild(li);
    }
  });
}

// Render cache list on popup open
document.addEventListener('DOMContentLoaded', renderCacheList);
