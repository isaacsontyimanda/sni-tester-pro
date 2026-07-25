// app.js — SNI Tester PRO v4.0.5
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const dialog = window.__TAURI__.dialog;

const store = {
  get(k, d) { try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch { return d; } },
  set(k, v) { localStorage.setItem(k, JSON.stringify(v)); },
};
let sniList       = store.get('sni_list', []);
let selectedPorts = store.get('ports', [443, 80]);
let deepScan      = store.get('deep_scan', false);
let operator      = store.get('operator', 'DESKTOP');
let selectedConcurrency = Math.min(200, Math.max(50, Number(store.get('concurrency', 50)) || 50));
let lastUsedFolder = store.get('last_used_folder', '');

let sessions    = [];
let liveResults = [];
let running = false, deepScanning = false, stopRequested = false;
let startTs = 0, timerId = null;
let testedCount = 0;
let selectedSession = null, statusFilter = null, searchQuery = '';
const APP_VERSION = '4.0.5';
const RELEASE_API = 'https://api.github.com/repos/devisaacson18/sni-tester-pro/releases/latest';
const OFFICIAL_SITE = 'https://sni-tester-pro.vercel.app';

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

function toast(msg) {
  const t = $('toast');
  if (!t) return;
  t.textContent = msg;
  t.classList.remove('hidden');
  clearTimeout(t._h);
  t._h = setTimeout(() => t.classList.add('hidden'), 2200);
}

async function showConfirmDialog(message) {
  const modal = $('confirmModal');
  const messageEl = $('confirmMessage');
  const yesBtn = $('confirmYesBtn');
  const noBtn = $('confirmNoBtn');
  if (!modal || !messageEl || !yesBtn || !noBtn) return false;
  messageEl.textContent = message;
  modal.classList.remove('hidden');
  return new Promise((resolve) => {
    const cleanup = () => {
      modal.classList.add('hidden');
      yesBtn.onclick = null;
      noBtn.onclick = null;
    };
    yesBtn.onclick = () => { cleanup(); resolve(true); };
    noBtn.onclick = () => { cleanup(); resolve(false); };
  });
}

function appendTerminalLine(msg) {
  const list = $('terminalLog');
  const logList = $('logList');
  if (list) {
    if (list.children.length === 1 && list.firstElementChild?.textContent.includes('Aguardando')) {
      list.innerHTML = '';
    }
    const line = document.createElement('div');
    line.className = 'leading-6';
    const match = msg.match(/^\[(.*?)\]\s*(.*)$/);
    const stamp = match ? `[${match[1]}]` : '';
    const body = match ? match[2] : msg;
    const isSuccess = /HTTP 200|HIT|DEEP OK|Sucesso/i.test(body);
    const isFailure = /TIMEOUT|Falha|Hijack|Erro|FAILED/i.test(body);
    const colorClass = isSuccess ? 'text-emerald-400 font-semibold' : isFailure ? 'text-rose-400' : 'text-slate-300';
    line.innerHTML = `<span class="text-slate-500">${esc(stamp)}</span> <span class="${colorClass}">${esc(body)}</span>`;
    list.appendChild(line);
    list.scrollTop = list.scrollHeight;
  }
  if (logList) {
    if (logList.children.length === 1 && logList.firstElementChild?.textContent.includes('Nenhum log')) {
      logList.innerHTML = '';
    }
    const line = document.createElement('div');
    line.className = 'leading-6 text-slate-300';
    line.innerHTML = `<span class="text-slate-500">${esc(new Date().toLocaleTimeString())}</span> <span>${esc(msg)}</span>`;
    logList.appendChild(line);
    logList.scrollTop = logList.scrollHeight;
  }
}

function clearTerminal() {
  const list = $('terminalLog');
  if (!list) return;
  list.innerHTML = '<div class="text-slate-500">&gt; Console limpo. Aguardando nova varredura...</div>';
}

function updateMetrics() {
  if ($('metricLoaded')) $('metricLoaded').textContent = sniList.length;
  if ($('metricTested')) $('metricTested').textContent = testedCount;
  const activeCount = liveResults.filter((r) => r.status === '200 OK').length;
  const deepCount = liveResults.filter((r) => r.isDeepVerified).length;
  const activeEl = $('metricActive');
  if (activeEl) {
    activeEl.textContent = activeCount;
    activeEl.className = `ml-1 font-semibold ${activeCount > 0 ? 'text-emerald-400' : 'text-slate-300'}`;
  }
  const deepWrap = $('metricDeepWrap');
  if (deepWrap) deepWrap.classList.toggle('hidden', !deepScan);
  if ($('metricDeep')) {
    $('metricDeep').textContent = deepCount;
    $('metricDeep').className = `ml-1 font-semibold ${deepCount > 0 ? 'text-amber-400' : 'text-slate-300'}`;
  }
  const latencyValues = liveResults.filter((r) => typeof r.latency === 'number' && Number.isFinite(r.latency)).map((r) => Number(r.latency));
  const avgLatency = latencyValues.length ? Math.round(latencyValues.reduce((acc, v) => acc + v, 0) / latencyValues.length) : 0;
  if ($('metricLatency')) $('metricLatency').textContent = `${avgLatency}ms`;
}

async function openExternal(url) {
  if (!url) return;
  try {
    if (window.__TAURI__?.shell?.open) { await window.__TAURI__.shell.open(url); return; }
    await invoke('open_external_url', { url }); return;
  } catch (err) { console.warn('Fallback:', err); }
  const link = document.createElement('a');
  link.href = url; link.target = '_blank'; link.rel = 'noopener noreferrer';
  document.body.appendChild(link); link.click(); link.remove();
}

document.addEventListener('click', (e) => {
  const anchor = e.target.closest('a[href^="http://"], a[href^="https://"]');
  if (anchor) { e.preventDefault(); openExternal(anchor.href); }
});

const screens = ['main', 'settings', 'results', 'logs', 'find-snis', 'about', 'credits', 'whatsnew'];
function setMenuOpen(open) {
  if (open) {
    const rect = $('menuBtn').getBoundingClientRect();
    const overlay = $('menuOverlay');
    overlay.style.setProperty('--menu-top', `${Math.round(rect.bottom + 8)}px`);
    overlay.style.setProperty('--menu-right', `${Math.round(window.innerWidth - rect.right)}px`);
  }
  $('menuOverlay').classList.toggle('hidden', !open);
  $('menuBtn').classList.toggle('is-open', open);
  $('menuBtn').title = open ? 'Fechar menu' : 'Abrir menu';
  $('menuBtn').setAttribute('aria-label', $('menuBtn').title);
}
function showScreen(name) {
  for (const s of screens) $('screen-' + s)?.classList.toggle('hidden', s !== name);
  if (name === 'results') renderSessions();
  setMenuOpen(false);
}
document.querySelectorAll('.backBtn').forEach((b) => (b.onclick = () => {
  if (selectedSession) { selectedSession = null; renderSessions(); } else showScreen('main');
}));
$('menuBtn').onclick = () => setMenuOpen($('menuOverlay').classList.contains('hidden'));
$('menuCloseBtn').onclick = () => setMenuOpen(false);
$('menuOverlay').onclick = (e) => { if (e.target.id === 'menuOverlay') setMenuOpen(false); };
document.querySelectorAll('.navItem').forEach((b) => (b.onclick = () => showScreen(b.dataset.nav)));

function versionParts(v) {
  return String(v).replace(/^v/i, '').split(/[.+-]/).map((p) => Number.parseInt(p, 10) || 0);
}
function isNewerVersion(cand, curr) {
  const cp = versionParts(cand), cc = versionParts(curr);
  const len = Math.max(cp.length, cc.length);
  for (let i = 0; i < len; i++) {
    if ((cp[i] || 0) !== (cc[i] || 0)) return (cp[i] || 0) > (cc[i] || 0);
  }
  return false;
}
async function checkForUpdates(isSilent = false) {
  const button = $('checkUpdateBtn');
  if (!isSilent && button) {
    button.disabled = true;
    const label = button.querySelector('span');
    if (label) label.textContent = 'Verificando…';
    else button.textContent = 'Verificando…';
  }
  try {
    const response = await fetch(RELEASE_API, { headers: { 'Accept': 'application/vnd.github+json' } });
    if (!response.ok) throw new Error(`Status: ${response.status}`);
    const release = await response.json();
    const latest = (release.tag_name || release.name || '').replace(/^v/i, '').trim();
    const current = String(APP_VERSION || '').replace(/^v/i, '').trim();
    if (latest && isNewerVersion(latest, current)) {
      if (isSilent) toast(`Nova versão v${latest} disponível!`);
      else { toast(`Nova versão v${latest} encontrada. A abrir...`); await openExternal(OFFICIAL_SITE); }
    } else {
      if (!isSilent) toast(`Você está na versão mais recente (v${current}).`);
    }
  } catch (err) {
    console.error('Erro:', err);
    if (!isSilent) toast('Não foi possível verificar. Conecte-se à internet.');
  } finally {
    if (!isSilent && button) {
      button.disabled = false;
      const label = button.querySelector('span');
      if (label) label.textContent = 'Verificar atualizacao';
      else button.textContent = 'Verificar atualizacao';
      setMenuOpen(false);
    }
  }
}
if ($('checkUpdateBtn')) $('checkUpdateBtn').onclick = () => checkForUpdates(false);

const radar = $('radar');
const ctx = radar.getContext('2d');
let targets = [];
function resizeRadar() {
  const dpr = window.devicePixelRatio || 1;
  radar.width = 220 * dpr; radar.height = 220 * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
}
function hexA(hex, a) {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a})`;
}
function drawRadar(ts) {
  const size = 220, c = size / 2, r = c - 10;
  const rotation = ((ts % 5000) / 5000) * 360;
  const color = deepScanning ? '#DAA520' : '#38BDF8';
  ctx.clearRect(0, 0, size, size);
  ctx.fillStyle = 'rgba(255,255,255,0.05)';
  ctx.beginPath(); ctx.arc(c, c, r, 0, 7); ctx.fill();
  ctx.strokeStyle = 'rgba(255,255,255,0.1)'; ctx.lineWidth = 1;
  for (let i = 1; i <= 6; i++) { ctx.beginPath(); ctx.arc(c, c, (r * i) / 6, 0, 7); ctx.stroke(); }
  ctx.strokeStyle = 'rgba(255,255,255,0.2)';
  for (let a = 0; a < 360; a += 30) {
    const rad = (a * Math.PI) / 180;
    ctx.beginPath();
    ctx.moveTo(c + r * 0.9 * Math.cos(rad), c + r * 0.9 * Math.sin(rad));
    ctx.lineTo(c + r * Math.cos(rad), c + r * Math.sin(rad));
    ctx.stroke();
  }
  if (running) {
    for (const [ang, dist] of targets) {
      const trad = (ang * Math.PI) / 180;
      const tx = c + r * dist * Math.cos(trad), ty = c + r * dist * Math.sin(trad);
      const diff = (((rotation - ang) % 360) + 360) % 360;
      const alpha = diff < 45 ? (1 - diff / 45) * 0.8 : 0;
      if (alpha > 0.02) {
        ctx.fillStyle = hexA(color, alpha);
        ctx.beginPath(); ctx.arc(tx, ty, 4, 0, 7); ctx.fill();
        ctx.fillStyle = hexA(color, alpha * 0.3);
        ctx.beginPath(); ctx.arc(tx, ty, 12, 0, 7); ctx.fill();
      }
    }
    for (let i = 0; i < 40; i++) {
      const a0 = ((rotation - 40 + i) * Math.PI) / 180;
      const a1 = ((rotation - 40 + i + 1.5) * Math.PI) / 180;
      ctx.fillStyle = hexA(color, 0.5 * (i / 40));
      ctx.beginPath(); ctx.moveTo(c, c); ctx.arc(c, c, r, a0, a1); ctx.closePath(); ctx.fill();
    }
    const trad2 = (rotation * Math.PI) / 180;
    ctx.strokeStyle = color; ctx.lineWidth = 3; ctx.lineCap = 'round';
    ctx.beginPath(); ctx.moveTo(c, c); ctx.lineTo(c + r * Math.cos(trad2), c + r * Math.sin(trad2)); ctx.stroke();
  }
  ctx.strokeStyle = 'rgba(255,255,255,0.2)'; ctx.lineWidth = 2;
  ctx.beginPath(); ctx.arc(c, c, r, 0, 7); ctx.stroke();
  requestAnimationFrame(drawRadar);
}

async function toggleScan() {
  if (running) {
    stopRequested = true;
    setRunning(false);
    resetPanel();
    try { await invoke('stop_scan'); appendTerminalLine('[sistema] Varredura interrompida.'); }
    catch (e) { toast(String(e)); }
    return;
  }
  if (!sniList.length || !selectedPorts.length) {
    toast('Configure SNIs e portas primeiro');
    showScreen('settings');
    return;
  }
  try {
    stopRequested = false;
    await invoke('start_scan', { snis: sniList, ports: selectedPorts, operator, deepScan, concurrency: selectedConcurrency });
  } catch (e) { toast(String(e)); }
}

function setRunning(v) {
  running = v;
  const actionBtn = $('scanActionBtn');
  if (actionBtn) {
    actionBtn.textContent = v ? 'STOP' : 'START';
    actionBtn.classList.toggle('is-running', v);
  }
  $('radarLabel').textContent = v ? 'EM EXECUCAO' : 'AGUARDANDO';
  const radarStatusText = $('radarStatusText');
  if (radarStatusText) {
    radarStatusText.textContent = v ? 'LIVE' : 'OFF';
    radarStatusText.classList.toggle('radar-live', v);
    radarStatusText.classList.toggle('radar-off', !v);
  }
  const dot = $('statusDot');
  if (dot) dot.className = 'h-2.5 w-2.5 rounded-full ' + (v ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500');
  const terminalDot = $('terminalStatusDot');
  if (terminalDot) terminalDot.className = 'h-2.5 w-2.5 rounded-full ' + (v ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500');
  if (v) {
    targets = Array.from({ length: 6 }, () => [Math.random() * 360, 0.2 + Math.random() * 0.7]);
    startTs = Date.now();
    timerId = setInterval(() => {
      const s = Math.floor((Date.now() - startTs) / 1000);
      $('elapsed').textContent = `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;
    }, 1000);
  } else {
    clearInterval(timerId);
    targets = [];
  }
}
function resetPanel() {
  $('curSni').textContent = 'AGUARDANDO...';
  $('curPort').textContent = '0';
  $('progressBar').style.width = '0%';
  $('progressBar').style.background = '#22d3ee';
  $('progressPct').textContent = '0%';
  $('progressPct').style.color = '#38bdf8';
  $('testedCount').textContent = '0 / 0';
  $('elapsed').textContent = '00:00';
  deepScanning = false;
  testedCount = 0;
  updateMetrics();
}
$('radarWrap').onclick = toggleScan;
$('scanActionBtn').onclick = toggleScan;
$('clearConsoleBtn').onclick = clearTerminal;

await listen('scan-started', () => {
  if (stopRequested) return;
  liveResults = []; testedCount = 0;
  setRunning(true);
});
await listen('scan-state', (e) => {
  if (stopRequested || !running) return;
  const s = e.payload;
  deepScanning = s.isDeepScanning;
  testedCount = s.tested || 0;
  if (s.currentSni) {
    $('curSni').textContent = s.currentSni.toUpperCase();
    $('curPort').textContent = s.currentPort;
    $('curPort').style.color = s.isDeepScanning ? '#f59e0b' : '#22d3ee';
  }
  const pct = Math.round(s.progress * 100);
  $('progressBar').style.width = pct + '%';
  $('progressBar').style.background = s.isDeepScanning ? '#f59e0b' : '#22d3ee';
  $('progressPct').textContent = pct + '%';
  $('progressPct').style.color = s.isDeepScanning ? '#f59e0b' : '#38bdf8';
  $('okBadge').textContent = s.successCount;
  $('vrBadge').textContent = s.verifiedCount;
  const planned = s.total || sniList.length * selectedPorts.length;
  $('testedCount').textContent = `${s.tested} / ${planned}`;
  updateMetrics();
});
await listen('scan-result', (e) => {
  if (stopRequested || !running) return;
  liveResults.push(e.payload);
  updateMetrics();
});
await listen('deep-result', (e) => {
  if (stopRequested || !running) return;
  const d = e.payload;
  const r = liveResults.find((x) => x.id === d.id);
  if (r) {
    r.isDeepVerified = d.isValid;
    r.deepReason = d.reason;
    r.tunnelWorking = d.tunnelWorking;
    r.bytesReceived = d.bytesReceived;
    r.speedKbps = d.speedKbps;
  }
});
await listen('scan-log', (e) => appendTerminalLine(e.payload));
await listen('scan-finished', async () => {
  if (stopRequested) return;
  setRunning(false);
  await invoke('complete_scan');
  if (liveResults.length) {
    sessions.unshift({ id: crypto.randomUUID(), date: Date.now(), operator, results: [...liveResults] });
    await invoke('save_sessions', { sessions });
    toast('Teste salvo em Resultados');
    setTimeout(() => { if (!running) { liveResults = []; resetPanel(); } }, 5000);
  }
});

// ============================================================
// CONFIGURACOES — UI PREMIUM v4.0.5
// ============================================================

let sniSearchQuery = '';
let sniModalOpen = false;

function renderSniList() {
  $('sniCount').textContent = sniList.length;
  updateMetrics();
  const filtered = sniSearchQuery ? sniList.filter((s) => s.includes(sniSearchQuery)) : sniList;
  const maxVisible = 100;
  const visible = filtered.slice(0, maxVisible);
  const remaining = filtered.length - visible.length;
  const infoText = sniList.length === 0
    ? 'Nenhum SNI carregado.'
    : filtered.length === 0
      ? 'Nenhum SNI corresponde à busca.'
      : filtered.length === sniList.length
        ? remaining > 0 ? `Exibindo ${maxVisible} de ${filtered.length} SNIs.` : `Exibindo ${filtered.length} SNIs.`
        : remaining > 0 ? `Exibindo ${maxVisible} de ${filtered.length} SNIs correspondentes de ${sniList.length}.` : `Exibindo ${filtered.length} SNIs correspondentes de ${sniList.length}.`;

  $('sniListEl').innerHTML = `
    <div class="flex items-center justify-between px-1 pb-2 text-[11px] text-slate-500">
      <span class="truncate">${esc(infoText)}</span>
    </div>
  ` + visible.map((s, i) => `
    <div class="sni-row glass-soft rounded-xl border border-slate-800/60 px-3.5 py-2.5 flex justify-between items-center text-xs transition hover:border-slate-700/80 hover:bg-slate-900/40">
      <span class="truncate text-slate-300 font-mono text-[11px]">${esc(s)}</span>
      <button data-i="${i}" class="rmSni flex-shrink-0 w-6 h-6 flex items-center justify-center rounded-lg text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 transition" title="Remover">✕</button>
    </div>`).join('');

  document.querySelectorAll('.rmSni').forEach((b) => (b.onclick = async () => {
    const index = +b.dataset.i;
    if (!(await showConfirmDialog(`Remover "${sniList[index]}" da lista?`))) return;
    sniList.splice(index, 1);
    store.set('sni_list', sniList);
    renderSniList();
  }));
}

function toggleSniSearchModal() {
  sniModalOpen = !sniModalOpen;
  const modal = $('sniSearchModal');
  if (!modal) return;
  if (sniModalOpen) {
    modal.classList.remove('hidden');
    setTimeout(() => {
      const input = $('sniModalInput');
      if (input) { input.focus(); input.value = sniSearchQuery; }
      renderSniModalList();
    }, 50);
  } else {
    modal.classList.add('hidden');
    sniSearchQuery = '';
    renderSniList();
  }
}

function renderSniModalList() {
  const listEl = $('sniModalList');
  const countEl = $('sniModalCount');
  const query = ($('sniModalInput')?.value || '').trim().toLowerCase();
  const filtered = query ? sniList.filter((s) => s.includes(query)) : sniList;
  if (countEl) countEl.textContent = `${filtered.length} encontrado${filtered.length !== 1 ? 's' : ''}`;
  if (!listEl) return;
  if (!filtered.length) {
    listEl.innerHTML = `<div class="text-center py-8 text-slate-500 text-sm">Nenhum SNI encontrado</div>`;
    return;
  }
  listEl.innerHTML = filtered.map((s, i) => `
    <div class="sni-modal-row flex items-center justify-between gap-3 px-3 py-2.5 rounded-xl hover:bg-slate-900/50 hover:border-slate-700/60 transition group">
      <span class="truncate font-mono text-[12px] text-slate-300">${esc(s)}</span>
      <button data-idx="${i}" class="sniModalDel opacity-0 group-hover:opacity-100 flex-shrink-0 w-7 h-7 flex items-center justify-center rounded-lg text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 transition" title="Remover">
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none"><path d="M2 2L10 10M10 2L2 10" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
      </button>
    </div>
  `).join('');

  document.querySelectorAll('.sniModalDel').forEach((b) => (b.onclick = async () => {
    const realIdx = sniList.indexOf(filtered[+b.dataset.idx]);
    if (realIdx === -1) return;
    if (!(await showConfirmDialog(`Remover "${sniList[realIdx]}"?`))) return;
    sniList.splice(realIdx, 1);
    store.set('sni_list', sniList);
    renderSniModalList();
    renderSniList();
  }));
}

if ($('sniSearchIconBtn')) $('sniSearchIconBtn').onclick = toggleSniSearchModal;
if ($('sniModalClose')) $('sniModalClose').onclick = toggleSniSearchModal;
if ($('sniModalOverlay')) $('sniModalOverlay').onclick = (e) => { if (e.target.id === 'sniModalOverlay') toggleSniSearchModal(); };
if ($('sniModalInput')) {
  $('sniModalInput').oninput = () => renderSniModalList();
  $('sniModalInput').onkeydown = (e) => { if (e.key === 'Escape') toggleSniSearchModal(); };
}

$('addSniBtn').onclick = () => {
  const v = $('sniInput').value;
  if (!v.trim()) return;
  const news = v.split(/[\n,]+/).map((s) => s.trim().toLowerCase()).filter(Boolean);
  const before = sniList.length;
  sniList = [...new Set([...sniList, ...news])];
  store.set('sni_list', sniList);
  $('sniInput').value = '';
  renderSniList();
  toast(`+${sniList.length - before} SNIs adicionados`);
};

if ($('clearAllSniBtn')) {
  $('clearAllSniBtn').onclick = async () => {
    if (!sniList.length) return toast('Nenhum SNI para limpar');
    if (!(await showConfirmDialog('Apagar todos os SNIs importados?'))) return;
    sniList = [];
    store.set('sni_list', sniList);
    renderSniList();
    if (sniModalOpen) renderSniModalList();
    toast('Todos os SNIs foram removidos');
  };
}

function toggleDeepScan() {
  deepScan = !deepScan;
  $('deepSwitch').classList.toggle('on', deepScan);
  store.set('deep_scan', deepScan);
  toast(deepScan ? 'Deep Scan ativado' : 'Deep Scan desativado');
  updateMetrics();
}
$('deepSwitch').onclick = toggleDeepScan;
if ($('deepRow')) $('deepRow').onclick = toggleDeepScan;

$('operatorInput').oninput = (e) => {
  operator = e.target.value.trim().toUpperCase() || 'DESKTOP';
  $('operatorBadge').textContent = operator;
  store.set('operator', operator);
};

if ($('operatorSelect')) $('operatorSelect').onchange = (e) => {
  operator = e.target.value.trim().toUpperCase() || 'DESKTOP';
  store.set('operator', operator);
  if ($('operatorBadge')) $('operatorBadge').textContent = operator;
};

if ($('portSelect')) $('portSelect').onchange = (e) => {
  selectedPorts = [parseInt(e.target.value, 10)].filter((n) => Number.isInteger(n) && n > 0 && n < 65536);
  store.set('ports', selectedPorts);
};
$('portsInput').onchange = (e) => {
  selectedPorts = e.target.value.split(',').map((p) => parseInt(p.trim(), 10)).filter((n) => n > 0 && n < 65536);
  store.set('ports', selectedPorts);
  e.target.value = selectedPorts.join(', ');
};
if ($('concurrencyInput')) {
  $('concurrencyInput').value = selectedConcurrency;
  $('concurrencyInput').onchange = (e) => {
    const v = parseInt(e.target.value, 10);
    selectedConcurrency = Math.min(200, Math.max(50, Number.isNaN(v) ? 50 : v));
    e.target.value = selectedConcurrency;
    store.set('concurrency', selectedConcurrency);
  };
}

async function importPaths(paths) {
  if (!paths?.length) return;
  try {
    const extracted = await invoke('import_files', { paths });
    rememberFolder(paths[0]);
    const before = sniList.length;
    sniList = [...new Set([...sniList, ...extracted])];
    store.set('sni_list', sniList);
    renderSniList();
    toast(`Importados ${sniList.length - before} novos SNIs`);
  } catch (e) { toast(String(e)); }
}

function folderFromPath(path) {
  if (typeof path !== 'string') return '';
  const lastSlash = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'));
  return lastSlash > 0 ? path.slice(0, lastSlash) : '';
}
function rememberFolder(path) {
  const folder = folderFromPath(path);
  if (!folder) return;
  lastUsedFolder = folder;
  store.set('last_used_folder', folder);
}
function joinPath(folder, name) {
  if (!folder) return name;
  const sep = folder.includes('\\') && !folder.includes('/') ? '\\' : '/';
  return `${folder}${folder.endsWith('/') || folder.endsWith('\\') ? '' : sep}${name}`;
}

async function chooseFiles() {
  const path = await dialog.open({
    multiple: true,
    defaultPath: lastUsedFolder || undefined,
    filters: [{ name: 'Listas', extensions: ['pdf', 'docx', 'xlsx', 'csv', 'txt', 'sni', 'conf', 'json'] }],
  });
  if (!path) return;
  await importPaths(Array.isArray(path) ? path : [path]);
}
$('importBtn').onclick = chooseFiles;

const dropZone = $('dropZone');
['dragenter', 'dragover'].forEach((event) => dropZone.addEventListener(event, (e) => {
  e.preventDefault(); dropZone.classList.add('drop-active');
}));
['dragleave', 'drop'].forEach((event) => dropZone.addEventListener(event, (e) => {
  e.preventDefault(); dropZone.classList.remove('drop-active');
}));
dropZone.addEventListener('drop', async (e) => {
  const paths = [...e.dataTransfer.files].map((file) => file.path).filter(Boolean);
  if (paths.length) await importPaths(paths);
  else toast('Use o seletor de arquivos neste ambiente');
});

try {
  const appWindow = window.__TAURI__.window.getCurrentWindow();
  await appWindow.onDragDropEvent(async (event) => {
    const payload = event.payload;
    if (payload.type === 'over') dropZone.classList.add('drop-active');
    if (payload.type === 'leave') dropZone.classList.remove('drop-active');
    if (payload.type === 'drop') { dropZone.classList.remove('drop-active'); await importPaths(payload.paths); }
  });
} catch { /* fallback */ }

document.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'o') {
    e.preventDefault(); chooseFiles();
  }
});

// ---------- Resultados ----------
function renderSessions() {
    $('resultsTitle').textContent = selectedSession ? 'Detalhes da Sessão' : 'Resultados';
  $('exportActions').classList.toggle('hidden', !selectedSession);
  $('sessionList').classList.toggle('hidden', !!selectedSession);
  $('sessionDetail').classList.toggle('hidden', !selectedSession);

  if (!selectedSession) {
    $('sessionList').innerHTML = sessions.length
      ? sessions.map((s, i) => {
          const ok = s.results.filter((r) => r.status === '200 OK').length;
          const zr = s.results.filter((r) => r.isDeepVerified).length;
          const dateStr = new Date(s.date).toLocaleString('pt-BR');
          return `<div class="rounded-[24px] border border-slate-800 bg-slate-900/60 p-5 cursor-pointer transition hover:border-slate-700 hover:bg-slate-900/80" data-i="${i}">
            <div class="flex justify-between items-start gap-3">
              <div class="flex-1 min-w-0">
                <p class="text-sm font-semibold text-white">Sessão de ${new Date(s.date).toLocaleDateString('pt-BR')}</p>
                <p class="text-xs text-slate-500 mt-1">🏢 ${esc(s.operator)} · 📅 ${dateStr}</p>
                <div class="flex gap-4 mt-3 text-xs">
                  <span class="text-emerald-400 font-medium">✓ ${ok} ativos</span>
                  <span class="text-cyan-400 font-medium">◆ ${s.results.length} testados</span>
                  <span class="text-slate-500">${zr} verificados</span>
                </div>
              </div>
              <button class="rmSession flex-shrink-0 text-slate-500 hover:text-rose-400 transition p-2">🗑</button>
            </div></div>`;
        }).join('')
      : '<div class="rounded-[24px] border border-slate-800 bg-slate-900/60 p-8 text-center"><p class="text-sm text-slate-400">Nenhum resultado salvo. Execute uma varredura para começar.</p></div>';
    document.querySelectorAll('#sessionList > div').forEach((el) => (el.onclick = (e) => {
      if (e.target.closest('.rmSession')) return;
      selectedSession = sessions[+el.dataset.i];
      renderSessions();
    }));
    document.querySelectorAll('.rmSession').forEach((b) => (b.onclick = async () => {
      if (!(await showConfirmDialog('Excluir esta sessão de resultados?'))) return;
      sessions.splice(+b.dataset.i, 1);
      await invoke('save_sessions', { sessions });
      renderSessions();
    }));
  } else {
    const s = selectedSession;
    const dateStr = new Date(s.date).toLocaleString('pt-BR');
    const totalOk = s.results.filter((r) => r.status === '200 OK').length;
    $('detailHeader').innerHTML = `<div class="flex items-center justify-between">
      <div>
        <p class="text-white font-semibold">Operadora: <span class="text-cyan-400">${esc(s.operator)}</span></p>
        <p class="text-slate-500 text-xs mt-1">${dateStr}</p>
      </div>
      <div class="flex gap-4 text-sm text-right">
        <div><p class="text-slate-500 text-xs">Ativos</p><p class="text-emerald-400 font-bold">${totalOk}</p></div>
        <div><p class="text-slate-500 text-xs">Testados</p><p class="text-cyan-400 font-bold">${s.results.length}</p></div>
      </div>
    </div>`;
    document.querySelector('.fchip')?.classList.add('active-filter');
    renderDetail();
  }
}

function renderDetail() {
  const filtered = selectedSession.results.filter((r) => {
    const matchesStatus = !statusFilter || (statusFilter === 'DEEP' ? r.isDeepVerified : r.status === statusFilter);
    const matchesSearch = !searchQuery || r.sni.toLowerCase().includes(searchQuery);
    return matchesStatus && matchesSearch;
  });
  $('detailList').innerHTML = filtered.length ? filtered.map((r) => {
    const ok = r.status === '200 OK', to = r.status === 'TIMEOUT';
    const statusColor = ok ? 'text-emerald-400' : to ? 'text-amber-400' : 'text-rose-400';
    const statusLabel = ok ? '✓ 200 OK' : to ? '⏱ TIMEOUT' : '✕ FAILED';
    const sub = ok ? `Porta ${r.port} • Latencia ${r.latency}ms` : to ? `Sem resposta (Porta ${r.port})` : `Falha (Porta ${r.port})`;
    const ip = r.resolvedIp ? `<p class="text-[10px] text-slate-500 mt-2 font-mono">${esc(r.resolvedIp).replace(/\n/g, ' | ').replace(/(ipv\d:)/g, '<span class="text-cyan-400">$1</span>')}</p>` : '';
    const zr = r.isDeepVerified ? `<span class="inline-block mt-2 text-[9px] font-semibold text-cyan-400 bg-cyan-500/15 rounded-lg px-2 py-1">◆ Deep Verified</span>` : '';
    return `<div class="rounded-[20px] border border-slate-800 bg-slate-950/50 p-4 flex justify-between items-start gap-3 ${ok ? 'cursor-pointer copySni hover:bg-slate-900' : ''} transition" data-sni="${esc(r.sni)}">
      <div class="min-w-0 flex-1">
        <p class="font-semibold text-sm text-white truncate">${esc(r.sni)}</p>
        <p class="text-xs text-slate-500 mt-1">${sub}</p>${ip}${zr}
      </div>
      <span class="flex-shrink-0 rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs font-medium ${statusColor}">${statusLabel}</span>
    </div>`;
  }).join('') : '<div class="rounded-[20px] border border-slate-800 bg-slate-950/50 p-8 text-center"><p class="text-sm text-slate-400">Nenhum resultado encontrado com estes filtros.</p></div>';
  document.querySelectorAll('.copySni').forEach((el) => (el.onclick = () => {
    navigator.clipboard.writeText(el.dataset.sni);
    toast('SNI copiado!');
  }));
}
$('searchInput').oninput = (e) => { searchQuery = e.target.value.toLowerCase(); renderDetail(); };
document.querySelectorAll('.fchip').forEach((b) => (b.onclick = () => {
  document.querySelectorAll('.fchip').forEach((btn) => btn.classList.remove('active-filter'));
  b.classList.add('active-filter');
  statusFilter = b.dataset.f || null;
  renderDetail();
}));
async function exportSession(format) {
  if (!selectedSession) return;
  const labels = { txt: 'Texto', pdf: 'PDF', json: 'JSON' };
  const now = new Date();
  const timestamp = [now.getFullYear(), String(now.getMonth() + 1).padStart(2, '0'), String(now.getDate()).padStart(2, '0')].join('') + '-' + [String(now.getHours()).padStart(2, '0'), String(now.getMinutes()).padStart(2, '0'), String(now.getSeconds()).padStart(2, '0')].join('');
  const operatorName = operator.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '') || 'desktop';
  const filename = `resultados-${operatorName}-${timestamp}.${format}`;
  const path = await dialog.save({
    defaultPath: joinPath(lastUsedFolder, filename),
    filters: [{ name: labels[format], extensions: [format] }],
  });
  if (!path) return;
  const target = path.toLowerCase().endsWith(`.${format}`) ? path : `${path}.${format}`;
  await invoke('export_results', { path: target, format, results: selectedSession.results });
  rememberFolder(target);
  toast(`Resultados exportados em ${format.toUpperCase()}`);
}
[['exportTxtBtn', 'txt'], ['exportPdfBtn', 'pdf'], ['exportJsonBtn', 'json']]
  .forEach(([id, format]) => { $(id).onclick = () => exportSession(format); });

// ---------- Dicas ----------
const tips = [
  'Use Configurações para importar SNIs e ajustar portas.',
  'O Deep Scan ajuda a reduzir falsos positivos.',
  'Resultados ficam disponíveis no histórico após a varredura.',
  'Clique em um resultado ativo para copiar o SNI.',
  'v4.0.5 traz retry automático e cache DNS para mais velocidade.',
  'A barra de status mostra cores diferentes para scans ativos e inativos.',
  'Se o radar estiver OFF, clique em START para iniciar a varredura.',
  'Você pode filtrar SNIs no modal e remover entries individualmente.',
  'Use múltiplas portas para testar diferentes serviços simultaneamente.',
  'O botão Limpar na aba Console redefine o histórico sem afetar a lista de SNIs.',
];
let tipIdx = Math.floor(Math.random() * tips.length);
function renderTip() {
  const tip = $('tipText');
  if (tip) tip.textContent = tips[tipIdx];
}
setInterval(() => {
  tipIdx = (tipIdx + 1) % tips.length;
  const tip = $('tipText');
  if (!tip) return;
  tip.style.opacity = 0;
  setTimeout(() => { renderTip(); tip.style.opacity = 1; }, 200);
}, 8000);
renderTip();

// ---------- Boot ----------
(async function init() {
  try {
    const appIcon = $('appIcon');
    if (appIcon) {
      const iconUrl = await invoke('app_icon_data_url');
      if (iconUrl) appIcon.src = iconUrl;
    }
  } catch { /* silencioso */ }

  resizeRadar();
  requestAnimationFrame(drawRadar);

  renderSniList();
  updateMetrics();

  try { sessions = await invoke('load_sessions'); } catch { sessions = []; }

  setTimeout(() => checkForUpdates(true), 3000);
})();
