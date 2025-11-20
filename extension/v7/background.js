// Log tab updates and blocking decisions
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading' && tab.url) {
    console.log(`[Tab Update] Tab ${tabId} loading: ${tab.url}`);
  }
});

// --- CONFIG ---

// --- CONFIG FOR CUSTOM BACKEND ---
const SERVER_BASE = "http://localhost:5000";
const ALL_DOMAINS_URL = `${SERVER_BASE}/all_domains`;
const DOMAIN_STATUS_URL = `${SERVER_BASE}/domain_status`;

let domainStatusCache = {};
let temporaryUnlocks = {}; // Store temporary unlocks with timestamps

// Check if domain is temporarily unlocked
function isTemporarilyUnlocked(domain) {
  const unlock = temporaryUnlocks[domain];
  if (!unlock) return false;
  
  // Check if unlock has expired (5 minutes)
  const now = Date.now();
  if (now - unlock.timestamp > 5 * 60 * 1000) {
    delete temporaryUnlocks[domain];
    return false;
  }
  return true;
}

// Add temporary unlock for domain
function addTemporaryUnlock(domain) {
  temporaryUnlocks[domain] = { timestamp: Date.now() };
  console.log(`[TEMP UNLOCK] ${domain} unlocked for 5 minutes`);
}

// Listen for messages from blocked page
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('[MESSAGE] Received:', message);
  
  if (message.action === 'temporaryUnlock') {
    try {
      addTemporaryUnlock(message.domain);
      console.log('[MESSAGE] Current unlocks:', temporaryUnlocks);
      sendResponse({ success: true });
    } catch (error) {
      console.error('[MESSAGE] Error handling temporaryUnlock:', error);
      sendResponse({ success: false, error: error.message });
    }
    return true; // Keep message channel open
  } 
  
  if (message.action === 'updateCache') {
    try {
      // Update memory cache immediately
      domainStatusCache[message.domain] = message.status;
      console.log(`[CACHE UPDATE] Updated ${message.domain} to status ${message.status}`);
      sendResponse({ success: true });
    } catch (error) {
      console.error('[MESSAGE] Error handling updateCache:', error);
      sendResponse({ success: false, error: error.message });
    }
    return true;
  }
  
  // Unknown message type
  sendResponse({ success: false, error: 'Unknown action' });
  return true;
});

// Fetch all domains and their status from the server and cache them
async function fetchAndCacheAllDomains() {
  try {
    console.log('[CACHE] Fetching all domains from server...');
    const resp = await fetch(ALL_DOMAINS_URL, {
      headers: { 'Accept': 'application/json' },
      mode: 'cors',
      credentials: 'omit'
    });
    const data = await resp.json();
    domainStatusCache = {};
    for (const entry of data) {
      domainStatusCache[entry.domain] = entry.status;
    }
    console.log('[CACHE] Loaded domains:', domainStatusCache);
    // Store in chrome.storage.local for persistence
    chrome.storage.local.set({ domainStatusCache });
  } catch (e) {
    console.error("Failed to fetch all domains from server:", e);
  }
}

// Load cache from storage on startup
async function loadCacheFromStorage() {
  try {
    const result = await chrome.storage.local.get(['domainStatusCache']);
    if (result.domainStatusCache) {
      domainStatusCache = result.domainStatusCache;
      console.log('[CACHE] Loaded cache from storage:', domainStatusCache);
    } else {
      console.log('[CACHE] No cache found in storage, will fetch from server');
    }
  } catch (e) {
    console.error('[CACHE] Failed to load cache from storage:', e);
  }
}

// Check domain status using cache, or query server if not found
async function getDomainStatus(domain, fullUrl = null) {
  // Try cache first for quick domain-based lookup
  if (domainStatusCache.hasOwnProperty(domain)) {
    console.log(`[CACHE HIT] ${domain} found in cache with status: ${domainStatusCache[domain]}`);
    return domainStatusCache[domain];
  }
  
  console.log(`[CACHE MISS] ${domain} not in cache, will be checked by blocked page`);
  // Return 0 (block) to redirect to blocked page for AI analysis
  // The blocked page will handle the XGBoost analysis and cache updating
  return 0;
}

const UPDATE_INTERVAL_MINUTES = 60; // How often to refresh blocklist
const BLOCKLIST_KEY = "blockedDomains";
const BLOCKLIST_TIMESTAMP_KEY = "blockedDomainsTimestamp";
const WHITELIST = ["google.com", "github.com"]; // Add more as needed

// --- HELPERS ---
function getDomainFromUrl(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return null;
  }
}


// Filter only blocklisted domains from the cache
function getBlocklistFromCache() {
  return Object.keys(domainStatusCache).filter(domain => domainStatusCache[domain] === 0);
}


function updateBlockRules() {
  // For Manifest V2, use webRequest API
  if (window.blockedDomainsListener) {
    chrome.webRequest.onBeforeRequest.removeListener(window.blockedDomainsListener);
  }
  
  // Filter for ALL URLs to intercept everything
  const filter = { urls: ["<all_urls>"], types: ["main_frame"] };
  
  window.blockedDomainsListener = function(details) {
      try {
        const urlObj = new URL(details.url);
        
        // Skip processing extension's own URLs to prevent redirect loops
        if (details.url.startsWith(chrome.runtime.getURL(''))) {
          console.log(`[SKIP] Extension URL ignored: ${details.url}`);
          return {};
        }
        
        const domain = urlObj.hostname.replace(/^www\./, "");
        
        console.log(`[REQUEST] Checking domain: ${domain}`);
        
        // Check if temporarily unlocked
        if (isTemporarilyUnlocked(domain)) {
          console.log(`[TEMP ALLOW] ${domain} is temporarily unlocked`);
          return {};
        }
        
        // If not in cache, check with XGBoost model using full URL
        if (!domainStatusCache.hasOwnProperty(domain)) {
          console.log(`[CHECKING] ${domain} not in cache, checking with AI model...`);
          // For performance, we'll still redirect to blocked page immediately
          // The blocked page will do the XGBoost analysis and allow if safe
          const url = encodeURIComponent(details.url);
          return { redirectUrl: chrome.runtime.getURL('blocked.html') + `?url=${url}` };
        }
        
        const status = domainStatusCache[domain];
        if (status === 0) {
          console.log(`[BLOCK] ${domain} is cached as blocked, redirecting to blocked page.`);
          const url = encodeURIComponent(details.url);
          return { redirectUrl: chrome.runtime.getURL('blocked.html') + `?url=${url}` };
        }
        
        console.log(`[ALLOW] ${domain} is whitelisted, allowing navigation.`);
        // Whitelisted: allow
        return {};
      } catch (e) {
        console.error('[ERROR] Failed to process request:', e);
        return {}; // Allow on error
      }
    };
  
  chrome.webRequest.onBeforeRequest.addListener(
    window.blockedDomainsListener,
    filter,
    ["blocking"]
  );
  
  console.log('[SETUP] WebRequest listener installed for all URLs');
}

// ...existing code...


// --- BLOCKLIST FETCHING & REFRESH ---
async function refreshBlocklistAndRules(force = false) {
  // Always fetch and cache all domains from server
  await fetchAndCacheAllDomains();
  updateBlockRules();
}

// --- INIT ---
chrome.runtime.onInstalled.addListener(async () => {
  await loadCacheFromStorage();
  await refreshBlocklistAndRules(true);
  chrome.alarms.create("refreshBlocklist", { periodInMinutes: UPDATE_INTERVAL_MINUTES });
});

chrome.runtime.onStartup.addListener(async () => {
  await loadCacheFromStorage();
  await refreshBlocklistAndRules();
});

// Initialize on first load
(async () => {
  await loadCacheFromStorage();
})();

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "refreshBlocklist") {
    refreshBlocklistAndRules(true);
  }
});
