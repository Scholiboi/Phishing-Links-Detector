document.addEventListener("DOMContentLoaded", () => {
    const urlInput = document.getElementById("urlInput");
    const loadBtn = document.getElementById("loadBtn");
    const clearBtn = document.getElementById("clearBtn");
    const sandboxIframe = document.getElementById("sandboxIframe");
    const statsDiv = document.getElementById("stats");
    const openBtn = document.getElementById("openBtn");

    openBtn.style.display = "none";
    loadBtn.addEventListener("click", async () => {
      const url = urlInput.value.trim();
      if (!isValidUrl(url)) {
        alert("Please enter a valid URL.");
        return;
      }
  
      try {
        // Fetch the sanitized DOM and input field stats from the server
        const response = await fetch(`http://localhost:3000/proxy?url=${encodeURIComponent(url)}`);
        const data = await response.json();
  
        // Display the sanitized DOM in the iframe
        sandboxIframe.srcdoc = data.dom;
  
        // Display the input field stats
        statsDiv.innerHTML = `
          <p>Total Input Fields: ${data.inputStats.totalInputs}</p>
          <p>Hidden Input Fields: ${data.inputStats.hiddenInputs}</p>
        `;
      } catch (error) {
        console.error("Error fetching the page:", error);
        alert("Failed to load the page.");
      }
    });
  
    function isValidUrl(string) {
      try {
        new URL(string);
        return true;
      } catch (_) {
        return false;
      }
    }

    clearBtn.addEventListener("click", () => {
      urlInput.value = "";
      sandboxIframe.srcdoc = "";
      statsDiv.innerHTML = "";
      openBtn.style.display = "none";
    });

    openBtn.addEventListener("click", () => {
      const url = urlInput.value.trim();
      if (!isValidUrl(url)) {
        alert("Please enter a valid URL.");
        return;
      }
      window.open(url, "_blank");
    });

    //only show the open button after the load button has been clicked and the client ha received a response form the server
    loadBtn.addEventListener("click", () => {
      openBtn.style.display = "block";
    });
  });
  