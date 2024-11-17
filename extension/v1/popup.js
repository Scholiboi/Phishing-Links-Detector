document.addEventListener("DOMContentLoaded", () => {
  const urlInput = document.getElementById("urlInput");
  const loadBtn = document.getElementById("loadBtn");
  const sandboxIframe = document.getElementById("sandboxIframe");

  loadBtn.addEventListener("click", () => {
    const url = urlInput.value.trim();
    if (isValidUrl(url)) {
      sandboxIframe.src = url;
    } else {
      alert("Please enter a valid URL.");
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
});