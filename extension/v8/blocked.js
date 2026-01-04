// blocked.js

document.addEventListener('DOMContentLoaded', async () => {
  // Automatically verify the site when page loads
  await autoVerifySite();
  
  // Set up continue with risk handler
  const continueRisk = document.getElementById('continueRisk');
  if (continueRisk) {
    continueRisk.addEventListener('click', async (e) => {
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
          
          // Show processing message
          showResult('🔓 Temporarily unlocking site...');
          
          // Send message to background script to add temporary unlock
          const response = await new Promise((resolve) => {
            chrome.runtime.sendMessage({
              action: 'temporaryUnlock',
              domain: domain
            }, resolve);
          });
          
          console.log('Unlock response:', response);
          
          if (response && response.success) {
            showResult('✅ Site unlocked for 5 minutes. Redirecting...');
            // Wait a bit longer to ensure unlock is processed
            setTimeout(() => {
              window.location.href = decodedUrl;
            }, 500);
          } else {
            throw new Error('Failed to unlock site');
          }
        } catch (err) {
          console.error('Error processing URL:', err);
          showResult('❌ Error unlocking site: ' + err.message);
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
    
    let resultMsg = '';
    if (data.google_flagged) {
      resultMsg += '⚠️ Flagged by Google Safe Browsing!\n';
    } else if (data.google_safe_browsing && data.google_safe_browsing.matches) {
      resultMsg += '⚠️ Google Safe Browsing: Threat detected!\n';
    } else {
      resultMsg += 'Google Safe Browsing: Not flagged.\n';
    }
    resultMsg += `Model: ${data.model_prediction} (${data.model_confidence.toFixed(1)}% confidence)`;
    if (data.model_status === 0) {
      resultMsg += '\nPhishing detected!';
      showResult(resultMsg);
      showReasoning(data.model_reasoning);
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
      showResult(resultMsg + '\n✅ Site verification passed. Redirecting...');
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
  const resultDiv = document.getElementById('result');
  const statusCard = document.getElementById('statusCard');
  const lines = msg.split('\n');
  
  // Update the main result message
  resultDiv.innerHTML = '';
  
  // Create analysis grid for Google and Model results
  const analysisGrid = document.createElement('div');
  analysisGrid.className = 'analysis-grid';
  
  let googleStatus = '';
  let modelStatus = '';
  let threatDetected = false;
  
  lines.forEach(line => {
    if (line.includes('Google Safe Browsing')) {
      googleStatus = line;
    } else if (line.includes('Model:')) {
      modelStatus = line;
    } else if (line.includes('Phishing detected') || line.includes('Flagged by Google')) {
      threatDetected = true;
    }
  });
  
  // Google Safe Browsing item
  const googleItem = document.createElement('div');
  googleItem.className = 'analysis-item google';
  googleItem.innerHTML = `
    <h4 style="display:flex;align-items:center;gap:6px;">
      <svg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='#4285f4' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><circle cx='11' cy='11' r='8'/><path d='m21 21-4.3-4.3'/></svg>
      Google Safe Browsing
    </h4>
    <div class="value">
      ${googleStatus.includes('Not flagged')
        ? `<svg xmlns='http://www.w3.org/2000/svg' width='18' height='18' viewBox='0 0 24 24' fill='none' stroke='#22c55e' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M20 6 9 17l-5-5'/></svg> Clean`
        : `<svg xmlns='http://www.w3.org/2000/svg' width='18' height='18' viewBox='0 0 24 24' fill='none' stroke='#f59e42' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3l-8.47-14.14a2 2 0 0 0-3.42 0z'/><line x1='12' y1='9' x2='12' y2='13'/><line x1='12' y1='17' x2='12.01' y2='17'/></svg> Flagged`}
    </div>
  `;
  analysisGrid.appendChild(googleItem);

  // Model item
  const modelItem = document.createElement('div');
  modelItem.className = 'analysis-item model';
  const modelMatch = modelStatus.match(/Model: (\w+) \(([0-9.]+)% confidence\)/);
  if (modelMatch) {
    const prediction = modelMatch[1];
    const confidence = modelMatch[2];
    modelItem.innerHTML = `
      <h4 style="display:flex;align-items:center;gap:6px;">
        <svg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='#ff6b35' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><rect x='3' y='3' width='18' height='18' rx='2' ry='2'/><path d='M9 9h6v6H9z'/></svg>
        AI Model Analysis
      </h4>
      <div class="value">
        ${prediction === 'PHISHING'
          ? `<svg xmlns='http://www.w3.org/2000/svg' width='18' height='18' viewBox='0 0 24 24' fill='none' stroke='#ff4757' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><circle cx='12' cy='12' r='10'/><line x1='15' y1='9' x2='9' y2='15'/><line x1='9' y1='9' x2='15' y2='15'/></svg> PHISHING`
          : `<svg xmlns='http://www.w3.org/2000/svg' width='18' height='18' viewBox='0 0 24 24' fill='none' stroke='#22c55e' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M20 6 9 17l-5-5'/></svg> ${prediction}`} (${confidence}%)
      </div>
    `;
  } else {
    modelItem.innerHTML = `
      <h4 style="display:flex;align-items:center;gap:6px;">
        <svg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='#ff6b35' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><rect x='3' y='3' width='18' height='18' rx='2' ry='2'/><path d='M9 9h6v6H9z'/></svg>
        AI Model Analysis
      </h4>
      <div class="value">${modelStatus}</div>
    `;
  }
  analysisGrid.appendChild(modelItem);
  
  resultDiv.appendChild(analysisGrid);
  
  // Update status card styling
  if (threatDetected) {
    statusCard.className = 'status-card threat-detected';
    const threatLevel = document.createElement('div');
    threatLevel.className = 'threat-level';
    threatLevel.innerHTML = `
      <span class="icon">
        <svg xmlns='http://www.w3.org/2000/svg' width='22' height='22' viewBox='0 0 24 24' fill='none' stroke='#ff4757' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><circle cx='12' cy='12' r='10'/><line x1='15' y1='9' x2='9' y2='15'/><line x1='9' y1='9' x2='15' y2='15'/></svg>
      </span>
      <span class="text">Security Threat Detected</span>
    `;
    resultDiv.insertBefore(threatLevel, analysisGrid);
  } else {
    statusCard.className = 'status-card threat-safe';
    const threatLevel = document.createElement('div');
    threatLevel.className = 'threat-level';
    threatLevel.innerHTML = `
      <span class="icon">
        <svg xmlns='http://www.w3.org/2000/svg' width='22' height='22' viewBox='0 0 24 24' fill='none' stroke='#22c55e' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M20 6 9 17l-5-5'/></svg>
      </span>
      <span class="text">Site Verification Complete</span>
    `;
    resultDiv.insertBefore(threatLevel, analysisGrid);
  }
}

function showReasoning(reasoning) {
  const reasoningSection = document.getElementById('reasoning');
  const reasoningList = document.getElementById('reasoningList');
  
  if (!reasoning || reasoning.length === 0) {
    reasoningSection.style.display = 'none';
    return;
  }
  
  reasoningList.innerHTML = '';
  reasoning.forEach(item => {
    const li = document.createElement('li');
    const riskText = item.impact.includes('increases') ? 'Risk Factor' : 'Safety Factor';
    const iconSvg = item.impact.includes('increases')
      ? `<svg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='#ff4757' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><circle cx='12' cy='12' r='10'/><line x1='15' y1='9' x2='9' y2='15'/><line x1='9' y1='9' x2='15' y2='15'/></svg>`
      : `<svg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='#22c55e' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M20 6 9 17l-5-5'/></svg>`;
    li.innerHTML = `
      <span class="icon">${iconSvg}</span>
      <div>
        <span class="feature">${item.feature}</span>
        <span class="value-badge">(${item.value})</span>
        <div style="font-size: 0.9em; color: #666; margin-top: 2px;">
          ${riskText}: ${item.impact}
        </div>
      </div>
    `;
    reasoningList.appendChild(li);
  });
  
  reasoningSection.style.display = 'block';
}
