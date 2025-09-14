// Simple Express server for whitelist checking
const express = require('express');
const cors = require('cors');
const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

// Example whitelist
const whitelist = [
  'https://www.google.com',
  'https://www.github.com'
];


app.post('/check', (req, res) => {
  const { url } = req.body;
  // Allow if the URL contains any whitelisted domain
  const whitelisted = whitelist.some(site => {
    try {
      const domain = new URL(site).hostname;
      const urlDomain = new URL(url).hostname;
      return urlDomain.includes(domain);
    } catch {
      return false;
    }
  });
  res.json({ whitelisted });
});

// New endpoint to return whitelist as JSON array
app.get('/whitelist', (req, res) => {
  // Return only the domain part for each whitelisted site
  const domains = whitelist.map(site => {
    try {
      return new URL(site).hostname;
    } catch {
      return site;
    }
  });
  res.json(domains);
});

app.listen(PORT, () => {
  console.log(`Whitelist server running on port ${PORT}`);
});
