// popup.js — user-initiated, current-tab scanning entirely inside the extension.

const SEV_ORDER_LOCAL = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

let lastFindings = [];

// ── Tab switching ─────────────────────────────────────────────────────────────

document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    const name = tab.dataset.tab;
    document.getElementById('scan-view').style.display  = name === 'scan'  ? 'block' : 'none';
    document.getElementById('paste-view').style.display = name === 'paste' ? 'block' : 'none';
    document.getElementById('about-view').style.display = name === 'about' ? 'block' : 'none';
    document.getElementById('filter-row').style.display = name === 'about' ? 'none'  : 'flex';
  });
});

// ── User-initiated current-tab scan ───────────────────────────────────────────

(async function init() {
  document.getElementById('rule-count').textContent = RULES.length;
  await scanCurrentTab();
})();

document.getElementById('rescan-btn').addEventListener('click', scanCurrentTab);

async function scanCurrentTab() {
  showLoading();
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return showError('Cannot access the current tab.');

  if (tab.url) {
    let protocol;
    try { protocol = new URL(tab.url).protocol; } catch (_error) { protocol = ''; }
    if (!['http:', 'https:', 'file:'].includes(protocol)) {
      return showError('Chrome protects this page from extensions. Open a regular web page or use the Paste tab.');
    }
  }

  try {
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      files: ['content.js'],
    });
    const page = await chrome.tabs.sendMessage(tab.id, { type: 'BLINDSPOT_SCAN_PAGE' });
    const findings = [];
    if (page?.extracted?.content) {
      findings.push(...scanContent(page.extracted.content, page.extracted.source).findings);
    }
    for (const surface of page?.surfaces || []) {
      const result = scanContent(surface.text, surface.surface);
      findings.push(...result.findings.map(finding => ({ ...finding, pageSource: surface.surface })));
    }

    const unique = [];
    const seen = new Set();
    for (const finding of findings) {
      const key = `${finding.id}|${finding.matches?.[0] || ''}|${finding.pageSource || ''}`;
      if (seen.has(key)) continue;
      seen.add(key);
      unique.push(finding);
    }

    if (!page?.extracted?.content && !(page?.surfaces || []).length) {
      return showError('No scannable content found on this page. Try the Paste tab.');
    }
    setPill(page?.extracted?.source || 'page surfaces');
    await updateBadge(tab.id, unique);
    renderFindings(unique);
  } catch (_error) {
    showError('Chrome could not grant access to this page. Open a regular web page or use the Paste tab.');
  }
}

async function updateBadge(tabId, findings) {
  const criticalCount = findings.filter(finding => finding.severity === 'CRITICAL').length;
  const text = criticalCount > 0 ? String(criticalCount) : findings.length ? String(findings.length) : '';
  await chrome.action.setBadgeText({ tabId, text });
  if (text) {
    await chrome.action.setBadgeBackgroundColor({
      tabId,
      color: criticalCount > 0 ? '#dc2626' : '#d97706',
    });
  }
}

// ── Severity filter ───────────────────────────────────────────────────────────

document.getElementById('sev-filter').addEventListener('change', () => {
  if (lastFindings.length !== undefined) renderFindings(lastFindings);
});

// ── Paste tab ─────────────────────────────────────────────────────────────────

document.getElementById('paste-scan-btn').addEventListener('click', () => {
  const text = document.getElementById('paste-area').value.trim();
  if (!text) return;
  const { findings } = scanContent(text, 'pasted content');
  renderFindings(findings, document.getElementById('paste-result'));
});

document.getElementById('paste-clear-btn').addEventListener('click', () => {
  document.getElementById('paste-area').value = '';
  document.getElementById('paste-result').innerHTML = '';
});

// ── Helpers ───────────────────────────────────────────────────────────────────

function setPill(source) {
  const pill = document.getElementById('source-pill');
  pill.textContent = source || 'page';
  pill.title = source || '';
}

// ── Renderers ─────────────────────────────────────────────────────────────────

function renderFindings(allFindings, container) {
  lastFindings = allFindings;
  container = container || document.getElementById('scan-results');

  document.getElementById('loading').style.display = 'none';
  container.style.display = 'block';
  container.innerHTML = '';

  const minOrd = parseInt(document.getElementById('sev-filter').value, 10);
  const findings = allFindings.filter(f => (SEV_ORDER_LOCAL[f.severity] ?? 9) <= minOrd);

  if (findings.length === 0) {
    const hasHidden = allFindings.length > 0;
    container.innerHTML = `
      <div class="summary-banner clean">
        <span class="summary-icon">✓</span>
        <div>
          <div class="summary-main" style="color:var(--clean)">No known indicators detected</div>
          <div class="summary-sub">${hasHidden ? `${allFindings.length} finding(s) below selected severity threshold.` : 'No high-confidence indicators from the current ' + RULES.length + '-rule static set. Not a guarantee of safety.'}</div>
        </div>
      </div>`;
    return;
  }

  // Summary banner
  const critCount = findings.filter(f => f.severity === 'CRITICAL').length;
  const banner = document.createElement('div');
  banner.className = `summary-banner ${critCount ? 'has-findings' : 'has-high'}`;
  banner.innerHTML = `
    <span class="summary-icon">${critCount ? '⚠' : '△'}</span>
    <div>
      <div class="summary-main" style="color:${critCount ? 'var(--critical)' : 'var(--high)'}">
        ${findings.length} finding${findings.length !== 1 ? 's' : ''} detected
      </div>
      <div class="summary-sub">${critCount ? `${critCount} CRITICAL` : 'No critical findings'}${findings.length - critCount > 0 ? ` · ${findings.length - critCount} other` : ''}</div>
    </div>`;
  container.appendChild(banner);

  // Finding cards
  for (const f of findings) {
    const card = document.createElement('div');
    card.className = 'finding';

    const hdr = document.createElement('div');
    hdr.className = 'finding-header';
    hdr.innerHTML = `
      <span class="sev-chip ${f.severity}">${f.severity}</span>
      <span class="rule-id">[${esc(f.id)}]</span>
      <span class="finding-name" title="${esc(f.name)}">${esc(f.name)}</span>
      ${f.pageSource ? `<span class="source-tag" title="Detected in page surface">${esc(f.pageSource)}</span>` : ''}
      <span class="chevron">▶</span>`;

    const body = document.createElement('div');
    body.className = 'finding-body';
    body.innerHTML = `
      <div class="finding-atlas">${esc(f.atlas)}</div>
      <div class="finding-note">${esc(f.note)}</div>
      <div class="matches">
        ${(f.matches || []).slice(0, 3).map(m =>
          `<div class="match"><span class="match-arrow">↳</span>${esc(String(m).slice(0, 110))}</div>`
        ).join('')}
      </div>`;

    hdr.addEventListener('click', () => {
      const isOpen = body.classList.toggle('open');
      hdr.querySelector('.chevron').classList.toggle('open', isOpen);
    });

    if (findings.length === 1) {
      body.classList.add('open');
      hdr.querySelector('.chevron').classList.add('open');
    }

    card.appendChild(hdr);
    card.appendChild(body);
    container.appendChild(card);
  }
}

function showLoading() {
  document.getElementById('loading').style.display = 'flex';
  const sr = document.getElementById('scan-results');
  sr.style.display = 'none';
  sr.innerHTML = '';
}

function showError(msg) {
  document.getElementById('loading').style.display = 'none';
  const container = document.getElementById('scan-results');
  container.style.display = 'block';
  container.innerHTML = `
    <div class="info-banner">
      <span class="info-icon">ℹ</span>
      <span>${esc(msg)}</span>
    </div>`;
}

function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
