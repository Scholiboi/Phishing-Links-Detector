

// Static whitelist for allowed domains
const whitelist = [
  "google.com",
  "github.com"
];

// List of domains to block (for demo, block some popular domains except whitelisted)
const allDomainsToBlock = [
  "example.com",
  "facebook.com",
  "twitter.com",
  "youtube.com",
  "instagram.com"
];

const blockedDomains = allDomainsToBlock.filter(domain => !whitelist.includes(domain));

function updateBlockRules(blockedDomains) {
  const rules = blockedDomains.map((domain, i) => ({
    id: i + 1,
    priority: 1,
    action: {
      type: "redirect",
      redirect: { extensionPath: "/blocked.html" }
    },
    condition: {
      urlFilter: domain,
      resourceTypes: ["main_frame"]
    }
  }));
  chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: rules.map(r => r.id),
    addRules: rules
  });
}

// Set blocking rules on extension startup
updateBlockRules(blockedDomains);
