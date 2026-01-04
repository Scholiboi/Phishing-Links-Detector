// popup.js

document.getElementById('verifyBtn').addEventListener('click', () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    const resultDiv = document.getElementById('result');
    const verifyBtn = document.getElementById('verifyBtn');
    
    if (!tab || !tab.url) {
      showResult('Could not get tab URL.', 'danger');
      return;
    }

    // Show loading state
    verifyBtn.textContent = 'Checking...';
    verifyBtn.classList.add('loading');
    verifyBtn.disabled = true;
    showResult('Analyzing site security...', 'checking');

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
        let resultType = 'safe';

        // Check Google Safe Browsing results
        if (data.google_flagged) {
          resultMsg += '⚠️ Flagged by Google Safe Browsing\n';
          resultType = 'danger';
        } else if (data.google_safe_browsing && data.google_safe_browsing.matches) {
          resultMsg += '⚠️ Google Safe Browsing: Threat detected\n';
          resultType = 'danger';
        } else {
          resultMsg += '✓ Google Safe Browsing: Clean\n';
        }

        // Add model prediction
        const confidence = data.model_confidence ? data.model_confidence.toFixed(1) : '?';
        resultMsg += `AI Model: ${data.model_prediction} (${confidence}% confidence)`;

        if (data.model_status === 0) {
          resultMsg += '\n🚨 Phishing detected! Redirecting...';
          resultType = 'danger';
          showResult(resultMsg, resultType);
          
          setTimeout(() => {
            chrome.tabs.update(tab.id, { 
              url: chrome.runtime.getURL('blocked.html') + `?url=${encodeURIComponent(tab.url)}` 
            });
          }, 1500);
        } else {
          resultMsg += '\n✅ Site appears safe';
          showResult(resultMsg, resultType);
        }
      })
      .catch(e => {
        showResult('❌ Error: ' + e.message, 'danger');
      })
      .finally(() => {
        // Reset button state
        verifyBtn.textContent = 'Verify Current Site';
        verifyBtn.classList.remove('loading');
        verifyBtn.disabled = false;
        
        // Refresh cache list after check
        setTimeout(renderCacheList, 500);
      });
  });
});

function showResult(message, type) {
  const resultDiv = document.getElementById('result');
  // Replace problematic symbols with proper Unicode
  let fixedMsg = message
    .replace(/âœ“/g, '✓')
    .replace(/âœ”/g, '✓')
    .replace(/âœ–/g, '✗')
    .replace(/â€¦/g, '...')
    .replace(/âš ï¸/g, '⚠️')
    .replace(/ï¸/g, '') // Remove stray variation selectors
    .replace(/âœ”/g, '✓');
  resultDiv.textContent = fixedMsg;
  resultDiv.className = 'show ' + type;
}

// Show cached websites and their status
function renderCacheList() {
  chrome.storage.local.get('domainStatusCache', (result) => {
    const cache = result.domainStatusCache || {};
    const cacheList = document.getElementById('cacheList');
    cacheList.innerHTML = '';
    
    const entries = Object.entries(cache);
    if (entries.length === 0) {
      // CSS handles the empty state with ::after pseudo-element
      return;
    }

    // Sort entries - blocked first, then alphabetically
    entries.sort(([domainA, statusA], [domainB, statusB]) => {
      if (statusA !== statusB) {
        return statusA - statusB; // 0 (blocked) comes before 1 (safe)
      }
      return domainA.localeCompare(domainB);
    });

    for (const [domain, status] of entries) {
      const li = document.createElement('li');
      
      const domainSpan = document.createElement('span');
      domainSpan.className = 'domain-name';
      domainSpan.textContent = domain;
      domainSpan.title = domain; // Show full domain on hover
      
      const statusSpan = document.createElement('span');
      statusSpan.className = `domain-status ${status === 1 ? 'safe' : 'blocked'}`;
      statusSpan.textContent = status === 1 ? 'Safe' : 'Blocked';
      
      li.appendChild(domainSpan);
      li.appendChild(statusSpan);
      cacheList.appendChild(li);
    }
  });
}

// Render cache list on popup open
document.addEventListener('DOMContentLoaded', renderCacheList);
