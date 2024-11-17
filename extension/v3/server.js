const express = require("express");
const puppeteer = require("puppeteer");

const app = express();
const PORT = 3000;

// Middleware to set CORS headers
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*"); // Allow all origins
  res.header("Access-Control-Allow-Methods", "GET, POST"); // Allow specific HTTP methods
  res.header("Access-Control-Allow-Headers", "Content-Type"); // Allow specific headers
  next();
});

app.get("/proxy", async (req, res) => {
    const url = req.query.url;
    if (!url) {
      return res.status(400).send("Missing URL parameter");
    }
  
    try {
      const browser = await puppeteer.launch({
        headless: true,
        args: ["--no-sandbox", "--disable-setuid-sandbox"],
      });
  
      const page = await browser.newPage();
  
      // Navigate to the URL
      await page.goto(url, { waitUntil: "domcontentloaded" });
  
      // Inline CSS and rewrite asset URLs
      const result = await page.evaluate(async (baseUrl) => {
        const inlineCSS = async () => {
          const styleSheets = Array.from(document.styleSheets).filter(
            (sheet) => sheet.href
          );
  
          for (const sheet of styleSheets) {
            try {
              const response = await fetch(sheet.href);
              const cssText = await response.text();
              const styleEl = document.createElement("style");
              styleEl.textContent = cssText;
              document.head.appendChild(styleEl);
            } catch (error) {
              console.warn("Failed to fetch stylesheet:", sheet.href, error);
            }
          }
        };
  
        await inlineCSS();
  
        // Rewrite asset URLs to absolute
        const rewriteURLs = (attribute, tagName) => {
          const elements = document.querySelectorAll(`${tagName}[${attribute}]`);
          elements.forEach((el) => {
            const relativeUrl = el.getAttribute(attribute);
            if (relativeUrl && !relativeUrl.startsWith("http")) {
              try {
                const absoluteUrl = new URL(relativeUrl, baseUrl).href;
                el.setAttribute(attribute, absoluteUrl);
              } catch (e) {
                console.warn("Invalid URL rewrite attempt:", relativeUrl, e);
              }
            }
          });
        };
  
        rewriteURLs("src", "img"); // Rewrite image src attributes
        rewriteURLs("src", "script"); // Rewrite script src attributes
        rewriteURLs("href", "link"); // Rewrite link href attributes
  
        // Remove unnecessary scripts and iframes
        document.querySelectorAll("script, iframe").forEach((el) => el.remove());
  
        const inputs = document.querySelectorAll("input");
        const totalInputs = inputs.length;
        const hiddenInputs = Array.from(inputs).filter(
          (input) => input.type === "hidden"
        ).length;
  
        return {
          dom: document.documentElement.outerHTML,
          inputStats: {
            totalInputs,
            hiddenInputs,
          },
        };
      }, url);
  
      await browser.close();
  
      res.json(result); // Return sanitized DOM with inlined CSS and rewritten asset URLs
    } catch (error) {
      console.error("Error fetching the page:", error);
      res.status(500).send("Error processing the page");
    }
  });
  

  app.listen(PORT, () => console.log(`Proxy server running on port ${PORT}`));
