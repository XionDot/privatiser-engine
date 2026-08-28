// === Safe storage helper (session API not available in all Firefox versions) ===
const sessionStore = {
  get(key, cb) {
    try {
      if (chrome.storage.session) {
        chrome.storage.session.get(key, cb);
      } else {
        cb({});
      }
    } catch { cb({}); }
  },
  set(obj) {
    try {
      if (chrome.storage.session) {
        chrome.storage.session.set(obj);
      }
    } catch {}
  },
};

// === Tab Switching ===
document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach((c) => c.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById(`tab-${tab.dataset.tab}`).classList.add("active");
  });
});

// === Theme ===
const themeBtn = document.getElementById("theme-toggle");

function setTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  themeBtn.textContent = theme === "dark" ? "\u263E" : "\u2600";
  chrome.storage.local.set({ theme });
}

themeBtn.addEventListener("click", () => {
  const curr = document.documentElement.getAttribute("data-theme");
  setTheme(curr === "dark" ? "light" : "dark");
});

chrome.storage.local.get("theme", (data) => {
  if (data.theme) setTheme(data.theme);
});

// === Settings ===
const settingsKeys = ["auto-intercept", "auto-deanonymize-copy", "show-badge", "store-mapping"];
// Load saved settings
chrome.storage.local.get(settingsKeys, (data) => {
  for (const key of settingsKeys) {
    const el = document.getElementById(key);
    if (el && data[key] !== undefined) el.checked = data[key];
  }
});
// Save on change
for (const key of settingsKeys) {
  const el = document.getElementById(key);
  if (el) {
    el.addEventListener("change", () => {
      chrome.storage.local.set({ [key]: el.checked });
      broadcastSettings({ [key]: el.checked });
    });
  }
}

function broadcastSettings(settings) {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]) {
      chrome.tabs.sendMessage(tabs[0].id, {
        type: "settings-changed",
        settings,
      }).catch(() => {});
    }
  });
}

// === Category Toggles ===
const catToggles = document.querySelectorAll(".cat-toggle");

chrome.storage.local.get("enabledCategories", (data) => {
  if (data.enabledCategories) {
    for (const toggle of catToggles) {
      const cat = toggle.dataset.cat;
      if (data.enabledCategories[cat] !== undefined) {
        toggle.checked = data.enabledCategories[cat];
      }
    }
  }
});

for (const toggle of catToggles) {
  toggle.addEventListener("change", () => {
    const categories = {};
    for (const t of catToggles) categories[t.dataset.cat] = t.checked;
    chrome.storage.local.set({ enabledCategories: categories });
    broadcastSettings({ enabledCategories: categories });
  });
}

// === Custom Words ===
const customWordsInput = document.getElementById("custom-words-input");
const customWordsStatus = document.getElementById("custom-words-status");

chrome.storage.local.get("customWords", (data) => {
  if (data.customWords && data.customWords.length > 0) {
    customWordsInput.value = data.customWords.join("\n");
  }
});

document.getElementById("save-custom-words-btn").addEventListener("click", () => {
  const values = customWordsInput.value
    .split("\n")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  chrome.storage.local.set({ customWords: values });
  broadcastSettings({ customWords: values });
  showStatus(customWordsStatus, `Saved ${values.length} item(s).`, "success");
});

// === Allowlist ===
const allowlistInput = document.getElementById("allowlist-input");
const allowlistStatus = document.getElementById("allowlist-status");

chrome.storage.local.get("allowlist", (data) => {
  if (data.allowlist && data.allowlist.length > 0) {
    allowlistInput.value = data.allowlist.join("\n");
  }
});

document.getElementById("save-allowlist-btn").addEventListener("click", () => {
  const values = allowlistInput.value
    .split("\n")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  chrome.storage.local.set({ allowlist: values });
  broadcastSettings({ allowlist: values });
  showStatus(allowlistStatus, `Saved ${values.length} item(s).`, "success");
});

// === Helpers ===
function showStatus(el, msg, type = "") {
  el.textContent = msg;
  el.className = `status ${type}`;
  if (type === "success") setTimeout(() => { el.textContent = ""; }, 3000);
}

async function copyText(text, statusEl, label) {
  try {
    await navigator.clipboard.writeText(text);
    showStatus(statusEl, `${label} copied!`, "success");
  } catch {
    showStatus(statusEl, "Copy failed", "error");
  }
}

function escapeHtml(s) {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

// === State ===
let currentMapping = {};
let currentMappingJson = "";

// === Anonymize ===
const anonInput = document.getElementById("anon-input");
const anonOutput = document.getElementById("anon-output");
const anonStatus = document.getElementById("anon-status");
const mappingSection = document.getElementById("mapping-section");
const mappingCount = document.getElementById("mapping-count");
const mappingBody = document.getElementById("mapping-table").querySelector("tbody");

function getPopupConfig() {
  const enabledCategories = {};
  for (const t of catToggles) enabledCategories[t.dataset.cat] = t.checked;
  const allowlist = allowlistInput.value
    .split("\n")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  const customWords = customWordsInput.value
    .split("\n")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  return { enabledCategories, allowlist, customWords };
}

document.getElementById("anonymize-btn").addEventListener("click", () => {
  const text = anonInput.value;
  if (!text.trim()) {
    showStatus(anonStatus, "Enter some text first.", "error");
    return;
  }

  const p = new Privatiser(getPopupConfig());
  const { result, mapping } = p.anonymize(text);

  anonOutput.value = result;
  currentMapping = mapping;
  currentMappingJson = JSON.stringify(mapping, null, 2);

  // Update table
  mappingBody.innerHTML = "";
  const entries = Object.entries(mapping);
  for (const [pseudo, orig] of entries) {
    const tr = document.createElement("tr");
    const td1 = document.createElement("td");
    td1.textContent = pseudo;
    const td2 = document.createElement("td");
    td2.textContent = orig;
    tr.appendChild(td1);
    tr.appendChild(td2);
    mappingBody.appendChild(tr);
  }

  mappingCount.textContent = entries.length;
  mappingSection.style.display = entries.length > 0 ? "block" : "none";
  showStatus(anonStatus, `Anonymized ${entries.length} item(s).`, "success");

  // Store mapping if setting enabled
  chrome.storage.local.get("store-mapping", (data) => {
    if (data["store-mapping"]) {
      sessionStore.set({ lastMapping: mapping });
    }
  });
});

// Clear
document.getElementById("clear-btn").addEventListener("click", () => {
  anonInput.value = "";
  anonOutput.value = "";
  mappingBody.innerHTML = "";
  mappingSection.style.display = "none";
  currentMapping = {};
  currentMappingJson = "";
  anonStatus.textContent = "";
});

// Paste
document.getElementById("paste-btn").addEventListener("click", async () => {
  try {
    anonInput.value = await navigator.clipboard.readText();
  } catch {
    showStatus(anonStatus, "Clipboard access denied.", "error");
  }
});

// Copy buttons
document.getElementById("copy-output-btn").addEventListener("click", () => {
  copyText(anonOutput.value, anonStatus, "Output");
});

document.getElementById("copy-mapping-btn").addEventListener("click", () => {
  copyText(currentMappingJson, anonStatus, "Mapping");
});

// === Deanonymize ===
const deanonInput = document.getElementById("deanon-input");
const deanonOutput = document.getElementById("deanon-output");
const deanonMapping = document.getElementById("deanon-mapping");
const deanonStatus = document.getElementById("deanon-status");

// Auto-load last mapping
sessionStore.get("lastMapping", (data) => {
  if (data && data.lastMapping) {
    deanonMapping.value = JSON.stringify(data.lastMapping, null, 2);
  }
});

document.getElementById("deanonymize-btn").addEventListener("click", () => {
  const text = deanonInput.value;
  const mapStr = deanonMapping.value.trim();
  if (!text.trim()) { showStatus(deanonStatus, "Enter anonymized text.", "error"); return; }
  if (!mapStr) { showStatus(deanonStatus, "Provide mapping JSON.", "error"); return; }

  let mapping;
  try { mapping = JSON.parse(mapStr); } catch {
    showStatus(deanonStatus, "Invalid JSON.", "error");
    return;
  }

  const p = new Privatiser();
  deanonOutput.value = p.deanonymize(text, mapping);
  showStatus(deanonStatus, "Restored!", "success");
});

document.getElementById("copy-restored-btn").addEventListener("click", () => {
  copyText(deanonOutput.value, deanonStatus, "Text");
});

// Load mapping from file
const loadBtn = document.getElementById("load-mapping-btn");
const fileInput = document.getElementById("mapping-file");
loadBtn.addEventListener("click", () => fileInput.click());
fileInput.addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => { deanonMapping.value = reader.result; };
  reader.readAsText(file);
});

// === Keyboard shortcut: Ctrl/Cmd+Enter ===
document.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
    const activeTab = document.querySelector(".tab.active").dataset.tab;
    if (activeTab === "anonymize") document.getElementById("anonymize-btn").click();
    else if (activeTab === "deanonymize") document.getElementById("deanonymize-btn").click();
  }
});
