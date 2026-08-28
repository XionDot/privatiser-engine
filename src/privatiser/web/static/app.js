// === Tab Switching ===
document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById(`tab-${tab.dataset.tab}`).classList.add('active');
    });
});

// === Theme Toggle ===
const themeToggle = document.getElementById('theme-toggle');
const themeIcon = themeToggle.querySelector('.theme-icon');

function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    themeIcon.textContent = theme === 'dark' ? '\u263E' : '\u2600';
    localStorage.setItem('privatiser-theme', theme);
}

themeToggle.addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme');
    setTheme(current === 'dark' ? 'light' : 'dark');
});

// Restore saved theme
const savedTheme = localStorage.getItem('privatiser-theme');
if (savedTheme) setTheme(savedTheme);

// === State ===
let currentMapping = {};
let currentMappingJson = '';

// === Helper: show status ===
function showStatus(el, message, type = '') {
    el.textContent = message;
    el.className = `status ${type}`;
    if (type === 'success') {
        setTimeout(() => { el.textContent = ''; el.className = 'status'; }, 3000);
    }
}

// === Helper: copy to clipboard ===
async function copyToClipboard(text, statusEl, label) {
    try {
        await navigator.clipboard.writeText(text);
        if (statusEl) showStatus(statusEl, `${label} copied!`, 'success');
    } catch {
        // Fallback
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        if (statusEl) showStatus(statusEl, `${label} copied!`, 'success');
    }
}

// === Anonymize ===
const anonymizeBtn = document.getElementById('anonymize-btn');
const anonInput = document.getElementById('anon-input');
const anonOutput = document.getElementById('anon-output');
const anonStatus = document.getElementById('anon-status');
const mappingCount = document.getElementById('mapping-count');
const mappingTable = document.getElementById('mapping-table').querySelector('tbody');
const mappingJson = document.getElementById('mapping-json');

anonymizeBtn.addEventListener('click', async () => {
    const text = anonInput.value.trim();
    if (!text) {
        showStatus(anonStatus, 'Please enter some text.', 'error');
        return;
    }

    anonymizeBtn.classList.add('loading');
    anonymizeBtn.textContent = 'Processing...';
    showStatus(anonStatus, '');

    try {
        const resp = await fetch('/api/anonymize', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text }),
        });
        const data = await resp.json();

        if (!resp.ok) {
            showStatus(anonStatus, data.error || 'Error', 'error');
            return;
        }

        anonOutput.value = data.result;
        currentMapping = data.mapping;
        currentMappingJson = JSON.stringify(data.mapping, null, 2);

        // Update mapping table
        mappingTable.innerHTML = '';
        for (const [pseudonym, original] of Object.entries(data.mapping)) {
            const tr = document.createElement('tr');
            tr.innerHTML = `<td>${escapeHtml(pseudonym)}</td><td>${escapeHtml(original)}</td>`;
            mappingTable.appendChild(tr);
        }
        mappingCount.textContent = data.count;
        mappingJson.value = currentMappingJson;

        showStatus(anonStatus, `Anonymized ${data.count} item(s).`, 'success');

        // Auto-open mapping section if items found
        if (data.count > 0) {
            document.getElementById('mapping-section').open = true;
        }
    } catch (err) {
        showStatus(anonStatus, `Error: ${err.message}`, 'error');
    } finally {
        anonymizeBtn.classList.remove('loading');
        anonymizeBtn.textContent = 'Anonymize';
    }
});

// === Clear ===
document.getElementById('clear-btn').addEventListener('click', () => {
    anonInput.value = '';
    anonOutput.value = '';
    mappingTable.innerHTML = '';
    mappingJson.value = '';
    mappingCount.textContent = '0';
    currentMapping = {};
    currentMappingJson = '';
    showStatus(anonStatus, '');
});

// === Copy buttons ===
document.getElementById('copy-output-btn').addEventListener('click', () => {
    copyToClipboard(anonOutput.value, anonStatus, 'Output');
});

document.getElementById('copy-mapping-btn').addEventListener('click', () => {
    copyToClipboard(currentMappingJson, anonStatus, 'Mapping');
});

// === Download mapping ===
document.getElementById('download-mapping-btn').addEventListener('click', () => {
    if (!currentMappingJson) return;
    const blob = new Blob([currentMappingJson], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'privatiser-mapping.json';
    a.click();
    URL.revokeObjectURL(url);
});

// === Paste button ===
document.getElementById('paste-btn').addEventListener('click', async () => {
    try {
        const text = await navigator.clipboard.readText();
        anonInput.value = text;
    } catch {
        showStatus(anonStatus, 'Clipboard access denied. Paste manually.', 'error');
    }
});

// === Deanonymize ===
const deanonymizeBtn = document.getElementById('deanonymize-btn');
const deanonInput = document.getElementById('deanon-input');
const deanonOutput = document.getElementById('deanon-output');
const deanonMapping = document.getElementById('deanon-mapping');
const deanonStatus = document.getElementById('deanon-status');

deanonymizeBtn.addEventListener('click', async () => {
    const text = deanonInput.value.trim();
    const mapping = deanonMapping.value.trim();

    if (!text) {
        showStatus(deanonStatus, 'Please enter anonymized text.', 'error');
        return;
    }
    if (!mapping) {
        showStatus(deanonStatus, 'Please provide the mapping JSON.', 'error');
        return;
    }

    deanonymizeBtn.classList.add('loading');
    deanonymizeBtn.textContent = 'Processing...';

    try {
        const resp = await fetch('/api/deanonymize', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text, mapping }),
        });
        const data = await resp.json();

        if (!resp.ok) {
            showStatus(deanonStatus, data.error || 'Error', 'error');
            return;
        }

        deanonOutput.value = data.result;
        showStatus(deanonStatus, 'Restored successfully.', 'success');
    } catch (err) {
        showStatus(deanonStatus, `Error: ${err.message}`, 'error');
    } finally {
        deanonymizeBtn.classList.remove('loading');
        deanonymizeBtn.textContent = 'Deanonymize';
    }
});

// === Copy restored ===
document.getElementById('copy-restored-btn').addEventListener('click', () => {
    copyToClipboard(deanonOutput.value, deanonStatus, 'Restored text');
});

// === Load mapping from file ===
const loadMappingBtn = document.getElementById('load-mapping-btn');
const mappingFileInput = document.getElementById('mapping-file-input');

loadMappingBtn.addEventListener('click', () => mappingFileInput.click());

mappingFileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
        deanonMapping.value = reader.result;
    };
    reader.readAsText(file);
});

// === Utility ===
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// === Keyboard shortcuts ===
document.addEventListener('keydown', (e) => {
    // Ctrl/Cmd + Enter to process
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        const activeTab = document.querySelector('.tab.active').dataset.tab;
        if (activeTab === 'anonymize') anonymizeBtn.click();
        else deanonymizeBtn.click();
    }
});
