// popup.js


document.getElementById('verifyBtn').addEventListener('click', () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    const resultDiv = document.getElementById('result');
    if (!tab || !tab.url) {
      resultDiv.textContent = 'Could not get tab URL.';
      return;
    }
    resultDiv.textContent = 'Checking...';
    fetch('http://localhost:5000/domain_status', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: tab.url })
    })
      .then(resp => {
        if (!resp.ok) throw new Error('Server error');
        return resp.json();
      })
      .then(data => {
        let resultMsg = '';
        if (data.google_flagged) {
          resultMsg += '⚠️ Flagged by Google Safe Browsing!\n';
        } else if (data.google_safe_browsing && data.google_safe_browsing.matches) {
          resultMsg += '⚠️ Google Safe Browsing: Threat detected!\n';
        } else {
          resultMsg += 'Google Safe Browsing: Not flagged.\n';
        }
        resultMsg += `Model: ${data.model_prediction} (${data.model_confidence ? data.model_confidence.toFixed(1) : '?'}% confidence)`;
        if (data.model_status === 0) {
          resultMsg += '\nPhishing detected! Redirecting...';
          resultDiv.textContent = resultMsg;
          setTimeout(() => {
            chrome.tabs.update(tab.id, { url: chrome.runtime.getURL('blocked.html') + `?url=${encodeURIComponent(tab.url)}` });
          }, 1200);
        } else {
          resultDiv.textContent = resultMsg + '\nSite is safe.';
        }
      })
      .catch(e => {
        resultDiv.textContent = 'Error: ' + e.message;
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
