// blocked.js

document.addEventListener('DOMContentLoaded', async () => {
  // Automatically verify the site when page loads
  await autoVerifySite();
  
  // Set up continue with risk handler
  const continueRisk = document.getElementById('continueRisk');
  if (continueRisk) {
    continueRisk.addEventListener('click', (e) => {
      e.preventDefault();
      const params = new URLSearchParams(window.location.search);
      const blockedUrl = params.get('url');
      if (blockedUrl) {
        try {
          const decodedUrl = decodeURIComponent(blockedUrl);
          console.log('Decoded URL:', decodedUrl);
          const urlObj = new URL(decodedUrl);
          const domain = urlObj.hostname.replace(/^www\./, "");
          console.log('Extracted domain:', domain);
          
          // Send message to background script to add temporary unlock
          chrome.runtime.sendMessage({
            action: 'temporaryUnlock',
            domain: domain
          }, (response) => {
            console.log('Unlock response:', response);
            // Small delay to ensure unlock is processed
            setTimeout(() => {
              window.location.href = decodedUrl;
            }, 100);
          });
        } catch (err) {
          console.error('Error processing URL:', err);
          showResult('❌ Error processing URL: ' + err.message);
        }
      }
    });
  }
});

async function autoVerifySite() {
  // Get the original blocked URL from the query string
  const params = new URLSearchParams(window.location.search);
  const blockedUrl = params.get('url');
  if (!blockedUrl) {
    showResult('Could not determine blocked site.');
    return;
  }
  
  try {
    const decodedUrl = decodeURIComponent(blockedUrl);
    const urlObj = new URL(decodedUrl);
    const domain = urlObj.hostname.replace(/^www\./, "");
    
    const resp = await fetch('http://localhost:5000/domain_status', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: decodedUrl })
    });
    if (!resp.ok) throw new Error('Server error');
    const data = await resp.json();
    
    if (data.status === 0) {
      showResult(
        `⚠️ This site is flagged as ${data.prediction.toLowerCase()} (${data.confidence.toFixed(1)}% confidence).`
      );
      showReasoning(data.reasoning);
      document.getElementById('actions').style.display = 'block';
    } else {
      // Site is legitimate - add directly to cache to prevent future blocks
      try {
        // Get current cache from storage
        const result = await new Promise((resolve) => {
          chrome.storage.local.get(['domainStatusCache'], resolve);
        });
        
        const cache = result.domainStatusCache || {};
        cache[domain] = 1; // 1 = legitimate
        
        // Save updated cache
        await new Promise((resolve) => {
          chrome.storage.local.set({ domainStatusCache: cache }, resolve);
        });
        
        // Notify background script to update its memory cache
        chrome.runtime.sendMessage({
          action: 'updateCache',
          domain: domain,
          status: 1
        });
        
        console.log(`Added ${domain} to local cache as legitimate`);
      } catch (e) {
        console.warn('Failed to update local cache:', e);
      }
      
      showResult('✅ Site verification passed. Redirecting...');
      setTimeout(() => {
        window.location.href = decodeURIComponent(blockedUrl);
      }, 1500);
    }
  } catch (e) {
    showResult('❌ Verification failed: ' + e.message);
    document.getElementById('actions').style.display = 'block';
  }
}

function showResult(msg) {
  document.getElementById('result').textContent = msg;
}

function showReasoning(reasoning) {
  const reasoningDiv = document.getElementById('reasoning');
  if (!reasoning || reasoning.length === 0) {
    reasoningDiv.style.display = 'none';
    return;
  }
  
  let html = '<h3>Why this site was blocked:</h3><ul>';
  reasoning.forEach(item => {
    const icon = item.impact.includes('increases') ? '🔴' : '🟢';
    html += `<li>${icon} <strong>${item.feature}</strong> (${item.value}): ${item.impact}</li>`;
  });
  html += '</ul>';
  
  reasoningDiv.innerHTML = html;
  reasoningDiv.style.display = 'block';
}
