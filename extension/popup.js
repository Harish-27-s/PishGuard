/**
 * PhishGuard Chrome MV3 popup – check current tab URL against the API.
 * API base URL is stored in chrome.storage.sync (default: http://localhost:8000).
 */

const DEFAULT_API = 'http://localhost:8000';

const tabUrlEl = document.getElementById('tab-url');
const apiInput = document.getElementById('api-url');
const saveBtn = document.getElementById('save-api');
const checkBtn = document.getElementById('check-btn');
const statusEl = document.getElementById('status');
const resultEl = document.getElementById('result');

let currentTabUrl = '';

function showStatus(message, type) {
  statusEl.textContent = message;
  statusEl.className = 'status ' + (type || 'info');
  statusEl.classList.remove('hidden');
}

function hideStatus() {
  statusEl.classList.add('hidden');
}

function showResult(data) {
  const v = (data.verdict || '').toLowerCase();
  let cls = 'dangerous';
  if (v === 'safe') cls = 'safe';
  else if (v === 'suspicious') cls = 'suspicious';

  const reasons = Array.isArray(data.reasons) ? data.reasons : [];
  const reasonsHtml = reasons.map(function (r) {
    return '<li>' + escapeHtml(r) + '</li>';
  }).join('');

  resultEl.className = 'result ' + cls;
  resultEl.innerHTML =
    '<div class="verdict-row">' +
      '<span class="verdict">' + escapeHtml(data.verdict) + '</span>' +
      '<span class="score">Score: <strong>' + data.score + '</strong> / 100</span>' +
    '</div>' +
    '<p class="source">Source: ' + escapeHtml(data.source || '—') + '</p>' +
    '<ul class="reasons">' + reasonsHtml + '</ul>';
  resultEl.classList.remove('hidden');
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function getApiBase() {
  return new Promise(function (resolve) {
    chrome.storage.sync.get({ apiBaseUrl: DEFAULT_API }, function (items) {
      resolve((items.apiBaseUrl || DEFAULT_API).replace(/\/$/, ''));
    });
  });
}

function setApiBase(url) {
  return new Promise(function (resolve) {
    chrome.storage.sync.set({ apiBaseUrl: url }, resolve);
  });
}

function getCurrentTabUrl() {
  return new Promise(function (resolve, reject) {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      if (!tabs || !tabs[0] || !tabs[0].url) {
        reject(new Error('Could not read current tab URL'));
        return;
      }
      resolve(tabs[0].url);
    });
  });
}

async function init() {
  try {
    const base = await getApiBase();
    apiInput.value = base;

    currentTabUrl = await getCurrentTabUrl();
    tabUrlEl.textContent = currentTabUrl;

    // Auto-check when popup opens (optional convenience)
    // await runCheck();
  } catch (err) {
    tabUrlEl.textContent = 'Unable to read tab URL';
    showStatus(err.message || 'Init error', 'error');
  }
}

saveBtn.addEventListener('click', async function () {
  const url = apiInput.value.trim().replace(/\/$/, '');
  if (!url) {
    showStatus('API URL cannot be empty', 'error');
    return;
  }
  await setApiBase(url);
  showStatus('API URL saved', 'info');
  setTimeout(hideStatus, 1500);
});

checkBtn.addEventListener('click', runCheck);

async function runCheck() {
  hideStatus();
  resultEl.classList.add('hidden');

  if (!currentTabUrl) {
    showStatus('No tab URL available', 'error');
    return;
  }

  // Skip chrome:// and extension pages
  if (/^(chrome|chrome-extension|about|edge|brave):/i.test(currentTabUrl)) {
    showStatus('Cannot check browser internal pages', 'error');
    return;
  }

  checkBtn.disabled = true;
  checkBtn.textContent = 'Checking…';
  showStatus('Sending to API…', 'info');

  try {
    const base = await getApiBase();
    const res = await fetch(base + '/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input: currentTabUrl }),
    });

    if (!res.ok) {
      let detail = 'Request failed (' + res.status + ')';
      try {
        const body = await res.json();
        if (body.detail) detail = body.detail;
      } catch (_) {}
      throw new Error(detail);
    }

    const data = await res.json();
    hideStatus();
    showResult(data);
  } catch (err) {
    showStatus(
      (err && err.message) ||
        'Could not reach API. Is the server running and the URL correct?',
      'error'
    );
  } finally {
    checkBtn.disabled = false;
    checkBtn.textContent = 'Check this page';
  }
}

init();
