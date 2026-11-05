// Akis: aktif sekmeyi otomatik al -> hedefi CANLI sor -> PHP surumu cik
//      -> surumu version-tabanli db.json'da sorgula -> risk notu.
import { statusMeta } from './lib/version.js';
import { checkTarget } from './lib/check.js';
import { lookupVersion, listVersions, getMeta } from './lib/lookup.js';

const $ = (s) => document.querySelector(s);
const esc = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// ---------- history (chrome.storage.local) ----------
async function getHistory() {
  const { history = [] } = await chrome.storage.local.get('history');
  return Array.isArray(history) ? history : [];
}
async function pushHistory(entry) {
  const history = (await getHistory()).filter((h) => !(h.host === entry.host && h.version === entry.version));
  history.unshift({ ...entry, at: Date.now() });
  await chrome.storage.local.set({ history: history.slice(0, 25) });
  renderHistory();
}
function renderHistory() {
  getHistory().then((h) => {
    const card = $('#historyCard');
    if (!h.length) { card.hidden = true; return; }
    card.hidden = false;
    $('#history').innerHTML = h
      .map((x) => {
        const m = x.status ? statusMeta(x.status) : { tone: 'neutral', label: '—' };
        return `<li class="t-${m.tone}">
          <span class="h-host">${esc(x.host)}</span>
          <span class="h-ver">${x.version ? 'PHP ' + esc(x.version) : 'gizli'}</span>
          <span class="h-st">${esc(x.status || '')}</span>
          <span class="h-when muted">${new Date(x.at).toLocaleString('tr-TR')}</span>
        </li>`;
      })
      .join('');
  });
}

// ---------- active tab ----------
async function currentTabUrl() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return (tab && tab.url) || null;
  } catch {
    return null;
  }
}

// ---------- rendering ----------
function renderResult(res, vinfo) {
  const card = $('#resultCard');
  card.hidden = false;

  if (!res.ok) {
    card.innerHTML = `
      <div class="result-head t-danger">
        <span class="pill">Hata</span>
        <span class="host">${esc(res.host || '')}</span>
      </div>
      <p class="reason danger">${esc(res.message || 'Kontrol basarisiz.')}</p>
      ${res.url ? `<p class="muted small">Denenen: ${esc(res.url)}</p>` : ''}
    `;
    $('#manualCard').hidden = true;
    return;
  }

  const v = res.version;
  const info = v ? vinfo : null;
  const tone = info ? info.tone : 'neutral';
  const rows = [];
  if (res.httpStatus) rows.push(['HTTP', String(res.httpStatus)]);
  if (res.server) rows.push(['Server', res.server]);
  if (res.xPoweredBy) rows.push(['X-Powered-By', res.xPoweredBy]);
  if (v) rows.push(['PHP surumu', `${v}${res.versionSource ? ` (${res.versionSource})` : ''}`]);
  if (info) rows.push(['Risk', `${info.label} · [${info.source}]`]);

  card.innerHTML = `
    <div class="result-head t-${tone}">
      <span class="pill">${esc(info ? info.label : v ? '—' : 'Version gizli')}</span>
      <span class="host">${esc(res.host)}</span>
    </div>
    <dl class="kv">
      ${rows.map(([k, val]) => `<div class="kv-row"><dt>${esc(k)}</dt><dd>${esc(val)}</dd></div>`).join('')}
      <div class="kv-row"><dt>URL</dt><dd class="url">${esc(res.url)}</dd></div>
    </dl>
    ${info && info.note ? `<p class="reason">${esc(info.note)}</p>` : ''}
    ${res.note ? `<p class="reason warn">${esc(res.note)}</p>` : ''}
    ${!v ? '<p class="reason">PHP surumu gizli — biliyorsan alttan manuel gir.</p>' : ''}
  `;
  $('#manualCard').hidden = Boolean(v);
}

// ---------- actions ----------
async function doCheck(inputOverride) {
  const btn = $('#checkBtn');
  btn.disabled = true;
  btn.textContent = 'Kontrol ediliyor…';
  try {
    let input = inputOverride !== undefined ? inputOverride : $('#target').value;
    if (!input) {
      const u = await currentTabUrl();
      if (u) input = u;
    }
    if (!input) {
      renderResult({ ok: false, message: 'Hedef none — URL yaz ya da target sekmesindeyken ac.' });
      return;
    }
    $('#target').value = input;
    const res = await checkTarget(input);
    let vinfo = null;
    if (res.ok && res.version) vinfo = await lookupVersion(res.version);
    renderResult(res, vinfo);
    if (res.ok) {
      const status = res.version ? (vinfo ? vinfo.status : 'UNABLE_TO_VERIFY') : 'UNABLE_TO_VERIFY';
      await pushHistory({ host: res.host, version: res.version || null, status });
    }
  } finally {
    btn.disabled = false;
    btn.textContent = 'Kontrol';
  }
}

function doManual() {
  const v = $('#manualVer').value.trim();
  if (!v) return;
  lookupVersion(v).then((info) => {
    renderResult(
      { ok: true, host: 'manual', url: 'manuel giris', httpStatus: null, server: null, xPoweredBy: null, version: v, versionSource: 'manual' },
      info,
    );
    void pushHistory({ host: 'manual', version: v, status: info.status });
  });
}

// ---------- version DB list ----------
async function renderDbList() {
  try {
    const items = await listVersions();
    const card = $('#dbCard');
    if (!items.length) { card.hidden = true; return; }
    card.hidden = false;
    $('#dbList').innerHTML = items
      .map((it) => {
        const m = statusMeta(it.status);
        return `<li class="t-${m.tone}">
          <span class="h-host">PHP ${esc(it.branch)}</span>
          <span class="h-ver">${esc(it.note || '')}</span>
          <span class="h-st">${esc(it.status)}</span>
        </li>`;
      })
      .join('');
  } catch {
    $('#dbCard').hidden = true;
  }
}

// ---------- wiring ----------
$('#checkBtn').addEventListener('click', () => doCheck());
$('#target').addEventListener('keydown', (e) => { if (e.key === 'Enter') doCheck(); });
$('#manualBtn').addEventListener('click', doManual);
$('#manualVer').addEventListener('keydown', (e) => { if (e.key === 'Enter') doManual(); });
$('#clearHist').addEventListener('click', async () => {
  await chrome.storage.local.set({ history: [] });
  renderHistory();
});

// init: meta + history + db list + AKTIF SEKME otomatik kontrolu
(async () => {
  getMeta().then((m) => {
    if (m.cve) $('#ruleNote').textContent = `${m.cve} · db guncel ${m.updated}`;
  }).catch(() => {});
  renderHistory();
  renderDbList();

  const u = await currentTabUrl();
  if (u && /^https?:/i.test(u)) {
    $('#target').value = u;
    await doCheck(u);
  } else {
    $('#target').focus();
  }
})();