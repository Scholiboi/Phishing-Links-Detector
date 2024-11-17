const express = require("express");
const https = require("https");
const http = require("http");
const { URL } = require("url");

const app = express();
const PORT = 3000;

// Function to validate URLs
function isValidUrl(string) {
  try {
    new URL(string);
    return true;
  } catch (_) {
    return false;
  }
}

app.get("/proxy", (req, res) => {
  const targetUrl = req.query.url;

  if (!targetUrl) {
    return res.status(400).send("Error: Missing 'url' query parameter");
  }

  if (!isValidUrl(targetUrl)) {
    return res.status(400).send("Error: Invalid URL");
  }

  const parsedUrl = new URL(targetUrl);
  const protocol = parsedUrl.protocol === "https:" ? https : http;

  // Request the target URL
  const proxyRequest = protocol.request(
    targetUrl,
    {
      headers: {
        "User-Agent": "Mozilla/5.0",
      },
    },
    (proxyResponse) => {
      let body = "";

      // Gather the data chunks
      proxyResponse.on("data", (chunk) => {
        body += chunk;
      });

      // On response end, modify headers and send back
      proxyResponse.on("end", () => {
        // Remove X-Frame-Options and CSP headers
        proxyResponse.headers["x-frame-options"] = null;
        proxyResponse.headers["content-security-policy"] = null;

        res.writeHead(proxyResponse.statusCode, proxyResponse.headers);
        res.end(body.replace(/X-Frame-Options/g, "").replace(/Content-Security-Policy/g, ""));
      });
    }
  );

  proxyRequest.on("error", (err) => {
    console.error("Error fetching target URL:", err.message);
    res.status(500).send("Error fetching the requested page");
  });

  proxyRequest.setTimeout(10000, () => {
    proxyRequest.abort();
    res.status(504).send("Error: Proxy request timed out");
  });

  proxyRequest.end();
});

// Start the server
app.listen(PORT, () => {
  console.log(`Proxy server running on port ${PORT}`);
});
