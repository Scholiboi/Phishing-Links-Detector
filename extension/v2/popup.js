document.addEventListener("DOMContentLoaded", () => {
    const urlInput = document.getElementById("urlInput");
    const loadBtn = document.getElementById("loadBtn");
    const sandboxIframe = document.getElementById("sandboxIframe");
  
    // Event listener for the "Load" button
    loadBtn.addEventListener("click", () => {
      const url = urlInput.value.trim();
  
      // Validate the URL entered by the user
      if (isValidUrl(url)) {
        // Set iframe src to load the website through the proxy server
        sandboxIframe.src = `http://localhost:3000/proxy?url=${encodeURIComponent(url)}`;
      } else {
        alert("Please enter a valid URL.");
      }
    });
  
    // Function to check if the URL is valid
    function isValidUrl(string) {
      try {
        new URL(string);
        return true;
      } catch (_) {
        return false;
      }
    }
  });
  