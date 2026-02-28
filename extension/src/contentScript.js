(function() {
  // Capture the current page URL
  let currentUrl = window.location.href;

  chrome.runtime.sendMessage({
    type: "PAGE_URL",
    url: currentUrl
  });

})();

