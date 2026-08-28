/**
 * Content script for AI chat sites.
 * Intercepts paste events (anonymize) and copy events (deanonymize).
 */

let autoIntercept = true;
let autoDeanonymizeCopy = true;
let lastMapping = null;
let enabledCategories = null;
let allowlist = [];
let customWords = [];

// Load settings
chrome.storage.local.get(
  ["auto-intercept", "auto-deanonymize-copy", "enabledCategories", "allowlist", "customWords"],
  (data) => {
    if (data["auto-intercept"] !== undefined) autoIntercept = data["auto-intercept"];
    if (data["auto-deanonymize-copy"] !== undefined) autoDeanonymizeCopy = data["auto-deanonymize-copy"];
    if (data.enabledCategories) enabledCategories = data.enabledCategories;
    if (data.allowlist) allowlist = data.allowlist;
    if (data.customWords) customWords = data.customWords;
  }
);

// Restore mapping from sessionStorage
try {
  const saved = sessionStorage.getItem("privatiser-mapping");
  if (saved) lastMapping = JSON.parse(saved);
} catch {}

// Listen for settings changes
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "settings-changed" && msg.settings) {
    if ("auto-intercept" in msg.settings) autoIntercept = msg.settings["auto-intercept"];
    if ("auto-deanonymize-copy" in msg.settings) autoDeanonymizeCopy = msg.settings["auto-deanonymize-copy"];
    if ("enabledCategories" in msg.settings) enabledCategories = msg.settings.enabledCategories;
    if ("allowlist" in msg.settings) allowlist = msg.settings.allowlist;
    if ("customWords" in msg.settings) customWords = msg.settings.customWords;
  }

  if (msg.type === "anonymize-selection") {
    handleSelectionAnonymize(msg.text);
  }

  if (msg.type === "deanonymize-selection") {
    handleSelectionDeanonymize(msg.text);
  }
});

function getConfig() {
  const config = {};
  if (enabledCategories) config.enabledCategories = enabledCategories;
  if (allowlist && allowlist.length) config.allowlist = allowlist;
  if (customWords && customWords.length) config.customWords = customWords;
  return config;
}

function saveMapping() {
  if (lastMapping) {
    try {
      sessionStorage.setItem("privatiser-mapping", JSON.stringify(lastMapping));
    } catch {}
  }
}

// === Paste Interception (Anonymize) ===
document.addEventListener("paste", (e) => {
  if (!autoIntercept) return;

  const target = e.target;
  if (!isTextInput(target)) return;

  const text = e.clipboardData.getData("text/plain");
  if (!text || !text.trim()) return;

  const p = new Privatiser(getConfig());
  const { result, mapping } = p.anonymize(text);

  if (Object.keys(mapping).length === 0) return;

  e.preventDefault();

  if (target.isContentEditable) {
    document.execCommand("insertText", false, result);
  } else {
    const start = target.selectionStart;
    const end = target.selectionEnd;
    target.value = target.value.slice(0, start) + result + target.value.slice(end);
    target.selectionStart = target.selectionEnd = start + result.length;
    target.dispatchEvent(new Event("input", { bubbles: true }));
  }

  // Merge new mapping with existing (accumulate across multiple pastes)
  lastMapping = lastMapping ? { ...lastMapping, ...mapping } : mapping;
  saveMapping();

  chrome.runtime.sendMessage({ type: "update-badge", count: Object.keys(mapping).length });
  chrome.runtime.sendMessage({ type: "store-mapping", mapping: lastMapping });

  showToast(`Privatiser: anonymized ${Object.keys(mapping).length} item(s)`);
}, true);

// === Copy Interception (Auto-Deanonymize) ===
document.addEventListener("copy", (e) => {
  if (!autoDeanonymizeCopy || !lastMapping) return;

  const selection = window.getSelection();
  if (!selection || selection.isCollapsed) return;

  const text = selection.toString();
  if (!text) return;

  // Check if the copied text contains any pseudonyms
  const pseudonyms = Object.keys(lastMapping);
  const found = pseudonyms.filter((p) => text.includes(p));
  if (found.length === 0) return;

  // Deanonymize the text
  const p = new Privatiser();
  const restored = p.deanonymize(text, lastMapping);

  e.preventDefault();
  e.clipboardData.setData("text/plain", restored);

  showToast(`Privatiser: restored ${found.length} item(s) in copied text`);
}, true);

// === Context Menu Handlers ===
function handleSelectionAnonymize(text) {
  const p = new Privatiser(getConfig());
  const { result, mapping } = p.anonymize(text);

  navigator.clipboard.writeText(result).then(() => {
    showToast(`Copied anonymized text (${Object.keys(mapping).length} items redacted)`);
  });

  lastMapping = lastMapping ? { ...lastMapping, ...mapping } : mapping;
  saveMapping();
  chrome.runtime.sendMessage({ type: "update-badge", count: Object.keys(mapping).length });
  chrome.runtime.sendMessage({ type: "store-mapping", mapping: lastMapping });
}

function handleSelectionDeanonymize(text) {
  if (!lastMapping) {
    showToast("Privatiser: no mapping available to deanonymize");
    return;
  }

  const p = new Privatiser();
  const restored = p.deanonymize(text, lastMapping);
  const pseudonyms = Object.keys(lastMapping);
  const count = pseudonyms.filter((ps) => text.includes(ps)).length;

  navigator.clipboard.writeText(restored).then(() => {
    showToast(`Privatiser: restored ${count} item(s) to clipboard`);
  });
}

// === Toast Notification ===
function showToast(message) {
  const existing = document.getElementById("privatiser-toast");
  if (existing) existing.remove();

  const toast = document.createElement("div");
  toast.id = "privatiser-toast";
  toast.textContent = message;
  document.body.appendChild(toast);

  requestAnimationFrame(() => toast.classList.add("show"));

  setTimeout(() => {
    toast.classList.remove("show");
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// === Helpers ===
function isTextInput(el) {
  if (!el) return false;
  if (el.isContentEditable) return true;
  const tag = el.tagName?.toLowerCase();
  if (tag === "textarea") return true;
  if (tag === "input" && (el.type === "text" || el.type === "search")) return true;
  if (el.getAttribute("role") === "textbox") return true;
  return false;
}
