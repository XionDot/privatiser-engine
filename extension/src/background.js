// Allowed origins for message validation
const ALLOWED_ORIGINS = [
  "https://chat.openai.com",
  "https://chatgpt.com",
  "https://claude.ai",
  "https://gemini.google.com",
  "https://copilot.microsoft.com",
];

function isAllowedSender(sender) {
  if (!sender.tab || !sender.tab.url) return false;
  return ALLOWED_ORIGINS.some((origin) => sender.tab.url.startsWith(origin));
}

// === Context Menu ===
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "privatiser-anonymize",
    title: "Anonymize with Privatiser",
    contexts: ["selection"],
  });

  chrome.contextMenus.create({
    id: "privatiser-anonymize-paste",
    title: "Anonymize & Copy to Clipboard",
    contexts: ["selection"],
  });

  chrome.contextMenus.create({
    id: "privatiser-deanonymize",
    title: "Deanonymize with Privatiser",
    contexts: ["selection"],
  });

  // Set default settings
  chrome.storage.local.get(
    ["auto-intercept", "auto-deanonymize-copy", "show-badge", "store-mapping"],
    (data) => {
      if (data["auto-intercept"] === undefined) chrome.storage.local.set({ "auto-intercept": true });
      if (data["auto-deanonymize-copy"] === undefined) chrome.storage.local.set({ "auto-deanonymize-copy": true });
      if (data["show-badge"] === undefined) chrome.storage.local.set({ "show-badge": true });
      if (data["store-mapping"] === undefined) chrome.storage.local.set({ "store-mapping": false });
    }
  );
});

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (!info.selectionText) return;

  if (info.menuItemId === "privatiser-anonymize" || info.menuItemId === "privatiser-anonymize-paste") {
    chrome.tabs.sendMessage(tab.id, {
      type: "anonymize-selection",
      text: info.selectionText,
    });
  }

  if (info.menuItemId === "privatiser-deanonymize") {
    chrome.tabs.sendMessage(tab.id, {
      type: "deanonymize-selection",
      text: info.selectionText,
    });
  }
});

// Listen for messages from content scripts
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Validate sender is from an allowed AI chat site
  if (!isAllowedSender(sender)) return;

  if (msg.type === "update-badge") {
    chrome.storage.local.get("show-badge", (data) => {
      if (data["show-badge"]) {
        const count = msg.count;
        chrome.action.setBadgeText({ text: count > 0 ? String(count) : "", tabId: sender.tab.id });
        chrome.action.setBadgeBackgroundColor({ color: "#3b82f6", tabId: sender.tab.id });
      }
    });
  }

  if (msg.type === "store-mapping") {
    chrome.storage.local.get("store-mapping", (data) => {
      if (data["store-mapping"]) {
        try {
          if (chrome.storage.session) {
            chrome.storage.session.set({ lastMapping: msg.mapping });
          }
        } catch {}
      }
    });
  }
});
