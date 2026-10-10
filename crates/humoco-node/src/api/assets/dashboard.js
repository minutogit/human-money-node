function escapeHtml(s) {
  if (s == null) return '';
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
const $ = id => document.getElementById(id);
const setText = (id, v) => { const el = $(id); if (el && v != null) el.innerText = v; };
const setHtml = (id, h) => { const el = $(id); if (el && h != null) el.innerHTML = h; };
const badge = (c, t) => `<span class="badge badge-${escapeHtml(c)}">${escapeHtml(t)}</span>`;
const codeTag = (t, title) => `<span class="code"${title ? ` title="${escapeHtml(title)}"` : ''}>${escapeHtml(t)}</span>`;
const cTrunc = (h, title) => codeTag(truncateHash(h), title || h);
let currentDashboardData = null;
let currentVoucherDetail = null;
let adminToken = '';
let consecutiveFailures = 0;
let pollIntervalMs = 2000;
let pollTimer = null;
let lastSuccessfulFetchTime = null;
let pendingConfirmCallback = null;
let isPollPaused = false;
let isFetchInProgress = false;

function fallbackCopyTextToClipboard(text) {
  return new Promise((resolve, reject) => {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.top = '0';
      ta.style.left = '0';
      ta.style.width = '1px';
      ta.style.height = '1px';
      ta.style.padding = '0';
      ta.style.border = 'none';
      ta.style.outline = 'none';
      ta.style.boxShadow = 'none';
      ta.style.background = 'transparent';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      const success = document.execCommand('copy');
      document.body.removeChild(ta);
      if (success) {
        resolve();
      } else {
        reject(new Error('execCommand copy failed'));
      }
    } catch (e) {
      reject(e);
    }
  });
}

function copyTextToClipboard(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    return navigator.clipboard.writeText(text).catch(() => fallbackCopyTextToClipboard(text));
  }
  return fallbackCopyTextToClipboard(text);
}

function copyJournalctlCmd() {
  copyTextToClipboard('journalctl -u humoco-node -f')
    .then(() => showToast('Befehl "journalctl -u humoco-node -f" kopiert', 'success'))
    .catch(() => showToast('Kopieren fehlgeschlagen', 'error'));
}

function togglePollPause() {
  isPollPaused = !isPollPaused;
  const btn = $('poll-pause-btn');
  if (btn) {
    if (isPollPaused) {
      btn.innerHTML = '▶️ Live (2s)';
      btn.className = 'btn btn-secondary paused';
      showToast('Dashboard-Aktualisierung pausiert', 'info');
    } else {
      btn.innerHTML = '⏸️ Pause';
      btn.className = 'btn btn-secondary';
      showToast('Live-Aktualisierung wieder aktiv', 'info');
      refreshDashboard();
    }
  }
}

// 15-minute inactivity session timeout with sessionStorage
const ADMIN_TOKEN_KEY = 'humoco_admin_token';
const ADMIN_TOKEN_TS_KEY = 'humoco_admin_token_ts';
const INACTIVITY_TIMEOUT_MS = 15 * 60 * 1000;
let inactivityTimer = null;

function refreshAdminSessionTimestamp() {
  if (adminToken) {
    try {
      sessionStorage.setItem(ADMIN_TOKEN_TS_KEY, String(Date.now()));
    } catch (_) {}
  }
}

function clearAdminSessionStorage() {
  try {
    sessionStorage.removeItem(ADMIN_TOKEN_KEY);
    sessionStorage.removeItem(ADMIN_TOKEN_TS_KEY);
  } catch (_) {}
}

function resetInactivityTimer() {
  if (inactivityTimer) clearTimeout(inactivityTimer);
  if (adminToken) {
    refreshAdminSessionTimestamp();
    inactivityTimer = setTimeout(() => {
      logoutAdminDueToInactivity();
    }, INACTIVITY_TIMEOUT_MS);
  }
}

function checkInactivityOnLoad() {
  try {
    const savedToken = sessionStorage.getItem(ADMIN_TOKEN_KEY);
    const tsStr = sessionStorage.getItem(ADMIN_TOKEN_TS_KEY);
    if (savedToken && tsStr) {
      const ts = parseInt(tsStr, 10);
      if (!isNaN(ts) && Date.now() - ts < INACTIVITY_TIMEOUT_MS) {
        adminToken = savedToken;
        sessionStorage.setItem(ADMIN_TOKEN_TS_KEY, String(Date.now()));
        resetInactivityTimer();
        applyAdminMode();
      } else {
        clearAdminSessionStorage();
      }
    }
  } catch (_) {}
}

function logoutAdminDueToInactivity() {
  if (adminToken) {
    adminToken = '';
    clearAdminSessionStorage();
    if (inactivityTimer) {
      clearTimeout(inactivityTimer);
      inactivityTimer = null;
    }
    applyAdminMode();
    showToast('Admin-Sitzung wegen Inaktivität (15 Min.) beendet', 'info');
    refreshDashboard();
  }
}

['mousedown', 'keydown', 'touchstart', 'scroll'].forEach(evt => {
  window.addEventListener(evt, () => {
    if (adminToken) {
      resetInactivityTimer();
    }
  }, { passive: true });
});
function formatHHMMSS(d) {
  if (!d) return '--:--:--';
  const p = n => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}
async function fetchWithTimeout(url, opts = {}, timeoutMs = 6000) {
  const c = new AbortController();
  const id = setTimeout(() => c.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...opts, signal: c.signal });
    clearTimeout(id);
    return res;
  } catch (e) {
    clearTimeout(id);
    throw e;
  }
}
function showToast(msg, type = 'info') {
  const box = $('toast-container');
  if (!box) return;
  const t = document.createElement('div');
  t.className = `toast toast-${type}`;
  const icon = type === 'success' ? '✅' : (type === 'error' ? '❌' : (type === 'warning' ? '⚠️' : 'ℹ️'));
  t.innerHTML = `<span>${icon}</span><span style="flex:1;">${escapeHtml(msg)}</span>`;
  box.appendChild(t);
  setTimeout(() => {
    t.style.opacity = '0';
    t.style.transform = 'translateY(10px)';
    setTimeout(() => { if (t.parentNode) t.parentNode.removeChild(t); }, 300);
  }, 4000);
}
function showConfirm(title, message, onConfirm) {
  setText('confirm-modal-title', title);
  setText('confirm-modal-message', message);
  pendingConfirmCallback = onConfirm;
  const btn = $('confirm-modal-btn');
  btn.onclick = () => {
    closeModal('confirm-modal');
    if (pendingConfirmCallback) {
      const cb = pendingConfirmCallback;
      pendingConfirmCallback = null;
      cb();
    }
  };
  $('confirm-modal').classList.add('active');
}
function updateDocumentHealthIndicator(level) {
  const baseTitle = 'HuMoCo Node Control Center (v2.0)';
  let emoji = '🟢';
  if (level === 'Crit') { emoji = '🚨'; document.title = '🚨 ' + baseTitle; }
  else if (level === 'Warn') { emoji = '⚠️'; document.title = '⚠️ ' + baseTitle; }
  else { document.title = '🟢 ' + baseTitle; }
  let link = document.querySelector("link[rel*='icon']");
  if (!link) {
    link = document.createElement('link');
    link.rel = 'icon';
    document.head.appendChild(link);
  }
  link.href = 'data:image/svg+xml,' + encodeURIComponent(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">${emoji}</text></svg>`);
}
function updateAdminUI() {
  const btn = $('admin-btn');
  const adminEls = document.querySelectorAll('.admin-only');
  if (adminToken) {
    btn.innerHTML = '🔓 Admin aktiv (Logout)';
    btn.className = 'btn btn-danger';
    adminEls.forEach(el => el.style.display = (el.tagName === 'BUTTON' ? 'inline-flex' : 'block'));
  } else {
    btn.innerHTML = '🔒 Admin-Modus';
    btn.className = 'btn btn-secondary';
    adminEls.forEach(el => el.style.display = 'none');
  }
}
function applyAdminMode() {
  updateAdminUI();
}
function handleAdminBtnClick() {
  if (adminToken) {
    if (inactivityTimer) {
      clearTimeout(inactivityTimer);
      inactivityTimer = null;
    }
    adminToken = '';
    clearAdminSessionStorage();
    applyAdminMode();
    showToast('Admin-Modus abgemeldet', 'info');
    refreshDashboard();
  } else {
    const err = $('admin-auth-error');
    if (err) err.style.display = 'none';
    const input = $('admin-token-input');
    if (input) input.value = '';
    $('admin-modal').classList.add('active');
  }
}
async function submitAdminToken() {
  const val = $('admin-token-input')?.value.trim();
  if (!val) return;
  try {
    const res = await fetchWithTimeout('/dashboard/admin/verify-token', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + val }
    }, 6000);
    if (res.ok) {
      adminToken = val;
      try {
        sessionStorage.setItem(ADMIN_TOKEN_KEY, val);
        sessionStorage.setItem(ADMIN_TOKEN_TS_KEY, String(Date.now()));
      } catch (_) {}
      resetInactivityTimer();
      closeModal('admin-modal');
      applyAdminMode();
      showToast('Admin-Modus aktiviert', 'success');
      refreshDashboard();
    } else {
      const err = $('admin-auth-error');
      if (err) { err.innerText = 'Ungültiges Admin-Token.'; err.style.display = 'block'; }
      showToast('Ungültiges Admin-Token.', 'error');
    }
  } catch (e) {
    const err = $('admin-auth-error');
    if (err) { err.innerText = 'Verbindungsfehler: ' + e.message; err.style.display = 'block'; }
    showToast('Verbindungsfehler: ' + e.message, 'error');
  }
}
async function adminAddMeshPeer() {
  const pInput = $('friend-pubkey-input');
  const lInput = $('friend-label-input');
  const raw = pInput?.value.trim() || '';
  const label = lInput?.value.trim() || '';
  if (!raw) {
    showToast('Bitte Peering-String (pubkey@ip:port) oder NodePubKey eingeben', 'error');
    return;
  }
  if (raw.includes('@')) {
    const parts = raw.split('@');
    if (!parts[0].trim()) {
      showToast('Ungültiger Peering-String: NodePubKey vor "@" fehlt', 'error');
      return;
    }
    if (!parts[1].trim()) {
      showToast('Ungültiger Peering-String: Adresse nach "@" fehlt (z. B. ip:port)', 'error');
      return;
    }
    if (!parts[1].includes(':') || !parts[1].split(':')[1].trim()) {
      showToast('Ungültiger Peering-String: Port fehlt (z. B. pubkey@ip:9090)', 'error');
      return;
    }
  } else if (raw.length < 32) {
    showToast('Ungültiger NodePubKey: Schlüssel ist zu kurz', 'error');
    return;
  }
  const pubkey = raw.includes('@') ? raw.split('@')[0].trim() : raw;
  try {
    const res = await fetchWithTimeout('/dashboard/admin/mesh/peers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + adminToken },
      body: JSON.stringify({ pubkey, label: label || null })
    }, 6000);
    if (res.ok) {
      if (pInput) pInput.value = '';
      if (lInput) lInput.value = '';
      showToast('P2P-Server erfolgreich verbunden', 'success');
      refreshDashboard();
    } else {
      const err = await res.json().catch(() => ({}));
      showToast('Fehler: ' + (err.message || res.statusText), 'error');
    }
  } catch (e) { showToast('Fehler: ' + e.message, 'error'); }
}
function adminAddFriend() {
  return adminAddMeshPeer();
}
function adminRemoveMeshPeer(pubkey) {
  showConfirm(
    'Nachbarknoten trennen',
    `Möchten Sie den Nachbarknoten ${truncateHash(pubkey)} wirklich aus den F2F-Freunden entfernen?`,
    async () => {
      try {
        const res = await fetchWithTimeout('/dashboard/admin/mesh/peers/' + encodeURIComponent(pubkey), {
          method: 'DELETE',
          headers: { 'Authorization': 'Bearer ' + adminToken }
        }, 6000);
        if (res.ok) {
          showToast(`Nachbarknoten ${truncateHash(pubkey)} entfernt`, 'success');
          refreshDashboard();
        } else {
          const err = await res.json().catch(() => ({}));
          showToast('Fehler: ' + (err.message || res.statusText), 'error');
        }
      } catch (e) { showToast('Fehler: ' + e.message, 'error'); }
    }
  );
}
function adminRemoveFriend(pubkey) {
  return adminRemoveMeshPeer(pubkey);
}
function openAddClientFriendModal() {
  const lInput = $('client-friend-label-input');
  const tInput = $('client-friend-token-input');
  if (lInput) lInput.value = '';
  if (tInput) tInput.value = '';
  $('add-client-modal')?.classList.add('active');
}
async function submitAddClientFriend() {
  const lInput = $('client-friend-label-input');
  const tInput = $('client-friend-token-input');
  const label = lInput?.value.trim() || '';
  const token = tInput?.value.trim() || '';
  try {
    const res = await fetchWithTimeout('/dashboard/admin/ingress/clients', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + adminToken },
      body: JSON.stringify({ label, token: token || null })
    }, 6000);
    if (res.ok) {
      const data = await res.json();
      closeModal('add-client-modal');
      showToast('Client-Freund freigeschaltet', 'success');
      refreshDashboard();
      showClientQrModal(data.label, data.token, data.wallet_uri);
    } else {
      const err = await res.json().catch(() => ({}));
      showToast('Fehler: ' + (err.message || res.statusText), 'error');
    }
  } catch (e) { showToast('Fehler: ' + e.message, 'error'); }
}
function adminRemoveClientFriend(tokenHash, label) {
  showConfirm(
    'Client-Freund widerrufen',
    `Möchten Sie den Client-Freund "${label || truncateHash(tokenHash)}" wirklich widerrufen?`,
    async () => {
      try {
        const res = await fetchWithTimeout('/dashboard/admin/ingress/clients/' + encodeURIComponent(tokenHash), {
          method: 'DELETE',
          headers: { 'Authorization': 'Bearer ' + adminToken }
        }, 6000);
        if (res.ok) {
          showToast(`Client ${label || truncateHash(tokenHash)} widerrufen`, 'success');
          refreshDashboard();
        } else {
          const err = await res.json().catch(() => ({}));
          showToast('Fehler: ' + (err.message || res.statusText), 'error');
        }
      } catch (e) { showToast('Fehler: ' + e.message, 'error'); }
    }
  );
}
function showClientQrModal(label, token, tokenHashOrUri) {
  const hasPlaintextToken = !!token && token.trim().length > 0;
  const warnEl = $('client-qr-warning');
  const uriSection = $('client-qr-uri-section');
  const tokenLabelEl = $('client-qr-token-label');
  const hintEl = $('client-qr-hint');

  setText('client-qr-label', label || 'Client');

  if (hasPlaintextToken) {
    // Freshly created client with plaintext token
    const apiPort = currentDashboardData?.config_view?.api_port || 8080;
    const host = window.location.hostname || '127.0.0.1';
    let walletUri = (tokenHashOrUri && tokenHashOrUri.startsWith('humoco://'))
      ? tokenHashOrUri
      : `humoco://${host}:${apiPort}?token=${token}`;

    if (tokenLabelEl) tokenLabelEl.innerText = 'Token:';
    setText('client-qr-token', token);
    setText('client-qr-uri', walletUri);
    if (uriSection) uriSection.style.display = 'block';
    if (warnEl) warnEl.style.display = 'none';
    if (hintEl) hintEl.innerText = '💡 Scannen Sie diesen QR-Code mit der HuMoCo Wallet App oder hinterlegen Sie das Token im PoS-Terminal.';
    const svg = generateQrSvg(walletUri);
    setHtml('client-qr-box', svg);
  } else {
    // Existing client - only token_hash is known
    const hash = tokenHashOrUri || '';
    if (tokenLabelEl) tokenLabelEl.innerText = 'Token-Hash:';
    setText('client-qr-token', hash ? `${hash} (Klartext nicht gespeichert)` : 'Nicht verfügbar');
    setText('client-qr-uri', '');
    if (uriSection) uriSection.style.display = 'none';
    if (warnEl) {
      warnEl.innerHTML = '⚠️ <strong>Sicherheitshinweis:</strong> Das Klartext-Token wurde nur einmalig bei Erstellung angezeigt und wird aus Sicherheitsgründen nicht auf dem Server vorgehalten. Bei Verlust des Tokens bitte einen neuen Client anlegen.';
      warnEl.style.display = 'block';
    }
    if (hintEl) hintEl.innerText = 'ℹ️ Dieser Client ist mit dem obenstehenden Token-Hash auf dem Knoten registriert.';
    setHtml('client-qr-box', '<div style="font-size:2.5rem;padding:1.5rem 0;">🔒</div>');
  }

  $('client-qr-modal')?.classList.add('active');
}
function copyClientUri() {
  const uri = $('client-qr-uri')?.innerText?.trim();
  if (!uri) return;
  copyTextToClipboard(uri).then(
    () => showToast('Wallet-URI in die Zwischenablage kopiert', 'success'),
    () => showToast('Fehler beim Kopieren', 'error')
  );
}
async function adminTopupQuota() {
  const tInput = $('vip-tag-input');
  const aInput = $('vip-amount-input');
  const tag = tInput?.value.trim() || '';
  const amount = aInput ? parseInt(aInput.value, 10) : 0;
  if (!tag || isNaN(amount) || amount <= 0) return;
  try {
    const res = await fetchWithTimeout('/dashboard/admin/quota', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + adminToken },
      body: JSON.stringify({ account_tag: tag, byte_years: amount })
    }, 6000);
    if (res.ok) {
      if (tInput) tInput.value = '';
      if (aInput) aInput.value = '';
      showToast('VIP-Guthaben erfolgreich aufgeladen', 'success');
      refreshDashboard();
    } else {
      const err = await res.json().catch(() => ({}));
      showToast('Fehler: ' + (err.message || res.statusText), 'error');
    }
  } catch (e) { showToast('Fehler: ' + e.message, 'error'); }
}
function prefillVipTopup(tag) {
  if (!adminToken) {
    showToast('Bitte zuerst Admin-Modus aktivieren', 'warning');
    handleAdminBtnClick();
    return;
  }
  const tagInput = $('vip-tag-input');
  const amountInput = $('vip-amount-input');
  if (tagInput) tagInput.value = tag;
  if (amountInput) amountInput.focus();
  showToast(`VIP-Account ${truncateHash(tag)} zum Aufladen ausgewählt`, 'info');
}
const HASH_TAB_MAP = {
  '#cockpit': 'tab-cockpit',
  '#network': 'tab-network',
  '#tiers': 'tab-tiers',
  '#ingress': 'tab-tiers',
  '#vouchers': 'tab-vouchers',
  '#history': 'tab-history',
  '#diagnostics': 'tab-history',
};

function handleHashRouting() {
  const hash = (window.location.hash || '').toLowerCase();
  const tabId = HASH_TAB_MAP[hash];
  if (tabId) {
    switchTab(tabId, false);
  }
}

window.addEventListener('hashchange', handleHashRouting);

function switchTab(tabId, updateHash = true) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  const btn = document.querySelector(`[onclick="switchTab('${tabId}')"]`) || $(`tab-btn-${tabId.replace('tab-', '')}`);
  if (btn) btn.classList.add('active');
  const target = $(tabId);
  if (target) target.classList.add('active');
  if (updateHash !== false) {
    const rawHash = '#' + tabId.replace('tab-', '');
    if (window.location.hash !== rawHash) {
      window.location.hash = rawHash;
    }
  }
}
function copyPeering() {
  const text = $('peering-text')?.innerText || '';
  copyTextToClipboard(text).then(() => {
    const btn = $('copy-btn');
    if (btn) { const o = btn.innerText; btn.innerText = 'Kopiert!'; setTimeout(() => { btn.innerText = o; }, 1500); }
    showToast('Peering-String kopiert', 'success');
  }).catch(() => showToast('Fehler beim Kopieren', 'error'));
}
function copyMyPubkey() {
  const text = $('my-pubkey-text')?.innerText || '';
  copyTextToClipboard(text).then(() => showToast('NodePubKey kopiert', 'success')).catch(() => showToast('Fehler beim Kopieren', 'error'));
}
function copyHealthDiagnosis() {
  const d = currentDashboardData;
  if (!d) {
    showToast('Keine Diagnosedaten verfügbar', 'warning');
    return;
  }
  const driftStr = d.clock_drift_ms != null ? `${d.clock_drift_ms > 0 ? '+' : ''}${d.clock_drift_ms} ms` : 'N/A';
  const inRamLat = d.local_latency?.avg_ms != null ? d.local_latency.avg_ms.toFixed(2) + ' ms' : 'N/A';
  const quorumLat = d.quorum_latency?.avg_ms != null ? d.quorum_latency.avg_ms.toFixed(2) + ' ms' : 'N/A';
  const e2eLat = d.e2e_latency?.avg_ms != null ? d.e2e_latency.avg_ms.toFixed(2) + ' ms' : 'N/A';
  const peersStr = `${d.connected_peers ?? 0}/${d.configured_peers ?? 0} verbunden (Netz N=${(d.active_nodes_count || 0) + 1})`;

  const lines = [
    '=== HuMoCo Node Systemdiagnose ===',
    `Node ID: ${d.node_id || 'unbekannt'}`,
    `Status: ${d.status_badge || d.status || 'unbekannt'}`,
    `Health Level: ${d.health?.level || 'Ok'}`,
    `Clock Drift: ${driftStr}`,
    `Peers: ${peersStr}`,
    `Latenzen: In-RAM ${inRamLat} | Quorum ${quorumLat} | Kasse/E2E ${e2eLat}`,
    ''
  ];

  const items = d.health?.items || [];
  if (items.length > 0) {
    lines.push('Aktive Diagnose-Meldungen:');
    for (const item of items) {
      lines.push(`- [${item.severity}] ${item.code}: ${item.message_de}`);
      if (item.hint_de) {
        lines.push(`  Hinweis: ${item.hint_de}`);
      }
    }
  } else {
    lines.push('Aktive Diagnose-Meldungen: Keine (Alle Systeme nominal)');
  }

  const text = lines.join('\n');
  copyTextToClipboard(text).then(() => {
    showToast('Systemdiagnose in die Zwischenablage kopiert', 'success');
  }).catch(() => {
    showToast('Fehler beim Kopieren der Diagnose', 'error');
  });
}
function closeModal(modalId) {
  const m = $(modalId);
  if (m) m.classList.remove('active');
}
function closeModalOnOverlay(e, modalId) {
  if (e.target.id === modalId) closeModal(modalId);
}
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') document.querySelectorAll('.modal-overlay').forEach(m => m.classList.remove('active'));
});
function copyModalJson() {
  const text = $('modal-json')?.innerText || '';
  copyTextToClipboard(text).then(() => showToast('JSON kopiert', 'success')).catch(() => showToast('Fehler beim Kopieren', 'error'));
}
function copyVoucherJson() {
  if (!currentVoucherDetail) return;
  copyTextToClipboard(JSON.stringify(currentVoucherDetail, null, 2)).then(() => showToast('JSON kopiert', 'success')).catch(() => showToast('Fehler beim Kopieren', 'error'));
}
function toggleVoucherRawJson() {
  const pre = $('voucher-modal-json');
  if (pre) pre.style.display = pre.style.display === 'none' ? 'block' : 'none';
}
function truncateHash(hex) {
  if (!hex || hex.length <= 16) return hex || '';
  return hex.slice(0, 8) + '…' + hex.slice(-8);
}
function renderSparklineSvg(arr, color) {
  if (!arr || arr.length === 0) return '';
  const max = Math.max(...arr, 1.0);
  const w = 280, h = 40;
  const pts = arr.map((v, i) => {
    const x = (i / (arr.length - 1 || 1)) * w;
    const y = h - ((v / max) * (h - 6)) - 3;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });
  const polyline = pts.join(' ');
  return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" style="width:100%;height:40px;display:block;"><polygon points="0,${h} ${polyline} ${w},${h}" fill="${color}" fill-opacity="0.15" /><polyline points="${polyline}" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" /></svg>`;
}
function renderNodeRow(n) {
  const roleBadge = n.is_local ? badge('purple', 'LOCAL') : (n.is_f2f ? badge('blue', 'F2F Friend') : badge('cyan', 'Shard'));
  const statusBadge = n.is_local
    ? badge('green', 'Lokal (Self)')
    : (n.connection_status.includes('Connected')
        ? (n.missing_count === 0 ? badge('green', 'Connected (0)') : badge('amber', n.connection_status))
        : (n.connection_status.includes('Suspended') ? badge('red', n.connection_status) : badge('amber', n.connection_status)));
  const rttText = n.rtt_ms != null ? escapeHtml(n.rtt_ms) + ' ms' : '<span style="color:var(--text-muted);">-</span>';
  const routeText = `${escapeHtml(n.min_hops)} Hop${n.min_hops === 1 ? '' : 's'}${n.best_ingress_peer ? ' via ' + escapeHtml(truncateHash(n.best_ingress_peer)) : (n.is_local ? ' (Self)' : (n.is_f2f ? ' (Direkt)' : ''))}`;
  const incubText = n.is_immature ? badge('amber', `24h (${escapeHtml(n.incubation_remaining_sec || 0)}s)`) : badge('green', 'Aktiv');
  const safePubkey = escapeHtml(n.public_key || '');
  return `<tr><td>${cTrunc(n.public_key)}</td><td>${escapeHtml(n.address)}</td><td>${roleBadge}</td><td>${statusBadge}</td><td>${rttText}</td><td>${routeText}</td><td>${cTrunc(n.hrw_routing_id)}</td><td>${incubText}</td><td><button class="btn btn-secondary" style="padding:0.2rem 0.5rem;" data-pubkey="${safePubkey}" onclick="openNodeInspector(this.getAttribute('data-pubkey'))">🔍 Info</button></td></tr>`;
}
function openNodeInspector(pubkey) {
  if (!currentDashboardData?.network_nodes) return;
  const node = currentDashboardData.network_nodes.find(n => n.public_key === pubkey || n.node_id === pubkey);
  if (!node) { showToast('Knoten nicht gefunden: ' + escapeHtml(pubkey), 'warning'); return; }
  setText('node-modal-title', '🔍 Knoten-Diagnose: ' + truncateHash(node.public_key));
  const statusBadge = node.connection_status.includes('Connected')
    ? (node.missing_count === 0 ? badge('green', 'Connected (0 Ausfälle)') : badge('amber', node.connection_status))
    : (node.connection_status.includes('Suspended') ? badge('red', node.connection_status) : badge('amber', node.connection_status));
  const rttText = node.rtt_ms != null ? escapeHtml(node.rtt_ms) + ' ms' : '<span style="color:var(--text-muted);">-</span>';
  const failText = node.last_failure_sec != null ? `vor ${escapeHtml(node.last_failure_sec)}s` : '<span style="color:var(--green);">Kein Ausfall</span>';
  const ingressText = node.best_ingress_peer ? 'via ' + escapeHtml(node.best_ingress_peer) : (node.is_local ? 'Lokal (Self)' : (node.is_f2f ? 'F2F Direkt' : 'Direkt / Standby'));
  const incubText = node.is_immature ? badge('amber', `24h (${escapeHtml(node.incubation_remaining_sec || 0)}s)`) : badge('green', 'Aktiv');
  const html = `<div style="line-height:1.5;font-size:0.875rem;">
    <div class="inspect-box">
      <h4 style="margin:0 0 0.4rem 0;font-size:0.85rem;color:var(--purple);">🔑 Identität &amp; Kryptographie</h4>
      <div><strong>NodePubKey:</strong> <span class="code" id="node-modal-pubkey">${escapeHtml(node.public_key)}</span> <button class="btn btn-secondary" style="padding:0.15rem 0.4rem;font-size:0.75rem;" onclick="copyNodePubkey()">Kopieren</button></div>
      <div><strong>Adresse:</strong> <span class="code">${escapeHtml(node.address)}</span></div>
      <div><strong>Shard-Ticket:</strong> <span class="code">${escapeHtml(node.hrw_routing_id)}</span> (Score: <strong>${escapeHtml(node.work_score)}</strong>)</div>
    </div>
    <div class="inspect-box">
      <h4 style="margin:0 0 0.4rem 0;font-size:0.85rem;color:var(--green);">💓 Verbindungs-Gesundheit</h4>
      <div><strong>Status:</strong> ${statusBadge}</div>
      <div><strong>Ausfälle:</strong> <strong>${escapeHtml(node.missing_count)}</strong> / 3 (Tit-for-Tat; heilt -1/h)</div>
      <div><strong>RTT:</strong> ${rttText} &bull; <strong>Letzter Fehler:</strong> ${failText}</div>
    </div>
    <div class="inspect-box" style="margin-bottom:0;">
      <h4 style="margin:0 0 0.4rem 0;font-size:0.85rem;color:var(--blue);">📡 Topologie &amp; Routing</h4>
      <div><strong>Distanz:</strong> ${escapeHtml(node.min_hops)} Hops &bull; <strong>Pfad:</strong> ${ingressText} &bull; <strong>Inkubation:</strong> ${incubText}</div>
    </div></div>`;
  setHtml('node-modal-details', html);
  $('node-modal').classList.add('active');
}
function copyNodePubkey() {
  const el = $('node-modal-pubkey');
  if (el) copyTextToClipboard(el.innerText).then(() => showToast('NodePubKey in Zwischenablage kopiert', 'success')).catch(() => showToast('Fehler beim Kopieren', 'error'));
}
let currentPeerFilter = 'ALL';
function setPeerFilter(filter) {
  currentPeerFilter = filter;
  document.querySelectorAll('.filter-chips .chip').forEach(c => c.classList.remove('active'));
  $('chip-' + filter.toLowerCase())?.classList.add('active');
  filterNodesTable();
}
function filterNodesTable() {
  const term = $('node-search-input')?.value.trim().toLowerCase();
  const nodesTbody = $('nodes-tbody');
  if (!currentDashboardData?.network_nodes || !nodesTbody) return;
  let html = '';
  for (const n of currentDashboardData.network_nodes) {
    if (currentPeerFilter === 'F2F' && !n.is_f2f) continue;
    if (currentPeerFilter === 'SHARD' && (n.is_local || n.is_f2f)) continue;
    if (currentPeerFilter === 'INCUBATING' && !n.is_immature) continue;
    if (term) {
      const m = n.public_key.toLowerCase().includes(term) || n.address.toLowerCase().includes(term) || n.connection_status.toLowerCase().includes(term) || n.hrw_routing_id.toLowerCase().includes(term);
      if (!m) continue;
    }
    html += renderNodeRow(n);
  }
  nodesTbody.innerHTML = html || '<tr><td colspan="9" class="empty-cell">Keine Knoten gefunden</td></tr>';
}
let currentFriendFilter = 'ALL';
function setFriendFilter(filter) {
  currentFriendFilter = filter;
  ['all', 'problem', 'connected'].forEach(f => {
    const chip = $('chip-friend-' + f);
    if (chip) chip.classList.toggle('active', f === filter.toLowerCase());
  });
  renderFriendsTable();
}
function renderFriendsTable() {
  const d = currentDashboardData;
  const friendsTbody = $('friends-tbody');
  if (!friendsTbody || !d?.f2f) return;
  if (d.f2f.friends?.length > 0) {
    const filtered = d.f2f.friends.filter(f => {
      const isProblem = !f.is_connected || (f.missing_count != null && f.missing_count > 0);
      if (currentFriendFilter === 'PROBLEM') return isProblem;
      if (currentFriendFilter === 'CONNECTED') return f.is_connected && (!f.missing_count || f.missing_count === 0);
      return true;
    });
    if (filtered.length > 0) {
      let html = '';
      for (const f of filtered) {
        const isProblem = !f.is_connected || (f.missing_count != null && f.missing_count > 0);
        let sBadge = badge('green', 'Verbunden (0 Ausfälle)');
        if (!f.is_connected) sBadge = badge('amber', 'Getrennt');
        else if (f.missing_count >= 3) sBadge = badge('red', 'Suspended (3/3)');
        else if (f.missing_count > 0) sBadge = badge('amber', `Degrading (${escapeHtml(f.missing_count)}/3)`);
        const rttText = f.rtt_ms != null ? escapeHtml(f.rtt_ms) + ' ms' : '<span style="color:var(--text-muted);">-</span>';
        const safeKey = escapeHtml(f.public_key || '');
        let actionBtn = `<button class="btn btn-secondary" style="padding:0.2rem 0.5rem;" data-pubkey="${safeKey}" onclick="openNodeInspector(this.getAttribute('data-pubkey'))">🔍 Info</button>`;
        if (adminToken) actionBtn += ` <button class="btn btn-danger" style="padding:0.2rem 0.5rem;margin-left:0.25rem;" data-pubkey="${safeKey}" onclick="adminRemoveFriend(this.getAttribute('data-pubkey'))">🗑️</button>`;
        const rowStyle = isProblem ? ' style="background: rgba(239, 68, 68, 0.08);"' : '';
        html += `<tr${rowStyle}><td>${cTrunc(f.public_key)}</td><td>${escapeHtml(f.address)}</td><td>${sBadge}</td><td>${rttText}</td><td>${actionBtn}</td></tr>`;
      }
      friendsTbody.innerHTML = html;
    } else {
      friendsTbody.innerHTML = '<tr><td colspan="5" class="empty-cell">Keine P2P-Peers für diesen Filter</td></tr>';
    }
  } else {
    friendsTbody.innerHTML = '<tr><td colspan="5" class="empty-cell">Keine F2F Freunde konfiguriert</td></tr>';
  }
}

let currentLockFilter = 'ALL';
function setLockFilter(filter) {
  currentLockFilter = filter;
  ['all', '409', 'vip', 'free'].forEach(f => {
    const chip = $('chip-lock-' + f);
    if (chip) chip.classList.toggle('active', f === filter.toLowerCase());
  });
  filterLocksTable();
}
function filterLocksTable() {
  const d = currentDashboardData;
  const locksTbody = $('locks-tbody');
  if (!locksTbody || !d?.recent_locks) return;
  if (d.recent_locks.length > 0) {
    const filtered = d.recent_locks.filter(l => {
      if (currentLockFilter === '409') return l.status === 'Conflict' || l.status === '409';
      if (currentLockFilter === 'VIP') return l.tier === 'VIP';
      if (currentLockFilter === 'FREE') return l.tier === 'Free';
      return true;
    });
    if (filtered.length > 0) {
      let html = '';
      for (const l of filtered) {
        const b = l.status === 'Verified' ? badge('green', 'Verified') : (l.status === 'Provisional' ? badge('amber', 'Provisional') : badge('red', 'Conflict'));
        const pShort = truncateHash(l.parent_lock_hex);
        const cShort = truncateHash(l.child_lock_hex);
        let tierBadge = badge('cyan', 'P2P Sync');
        if (l.tier === 'VIP') tierBadge = badge('purple', `VIP (${escapeHtml(l.byte_years || 0)} BY)`);
        else if (l.tier === 'F2F') tierBadge = badge('blue', `F2F (${escapeHtml(l.byte_years || 0)} BY)`);
        else if (l.tier === 'Free') tierBadge = badge('green', 'Free (PoW)');
        else if (l.tier) tierBadge = badge('cyan', l.tier);
        const safeVoucherId = l.voucher_id ? escapeHtml(l.voucher_id) : '';
        const safeParentHex = escapeHtml(l.parent_lock_hex || '');
        const vLink = l.voucher_id ? `<button class="btn btn-secondary" style="padding:0.15rem 0.4rem;font-size:0.75rem;" data-voucher="${safeVoucherId}" onclick="openVoucherInspector(this.getAttribute('data-voucher'))">🎟️ ${escapeHtml(truncateHash(l.voucher_id))}</button>` : '<span style="color:var(--text-muted);">-</span>';
        html += `<tr><td>${escapeHtml(l.timestamp_ms)}</td><td>${codeTag(pShort, l.parent_lock_hex)}</td><td>${codeTag(cShort, l.child_lock_hex)}</td><td>${tierBadge}</td><td>${vLink}</td><td>${b}</td><td><button class="btn btn-secondary" style="padding:0.2rem 0.5rem;" data-parent="${safeParentHex}" onclick="openLockInspector(this.getAttribute('data-parent'))">📄 JSON</button></td></tr>`;
      }
      locksTbody.innerHTML = html;
    } else {
      locksTbody.innerHTML = '<tr><td colspan="7" class="empty-cell">Keine Sperren für diesen Filter</td></tr>';
    }
  } else {
    locksTbody.innerHTML = '<tr><td colspan="7" class="empty-cell">Keine Sperren im Ringbuffer</td></tr>';
  }
}

async function openLockInspector(lookupTag) {
  try {
    const res = await fetchWithTimeout('/dashboard/lock/' + encodeURIComponent(lookupTag), {}, 6000);
    if (!res.ok) return;
    const json = await res.json();
    setText('modal-title', '🔒 Sperr-Rohdaten: ' + truncateHash(lookupTag));
    setHtml('modal-details', `<strong>Lookup Tag:</strong> <span class="code">${escapeHtml(lookupTag)}</span>`);
    setText('modal-json', JSON.stringify(json, null, 2));
    $('json-modal').classList.add('active');
  } catch (e) {
    showToast('Laden der Sperr-Rohdaten fehlgeschlagen: ' + e.message, 'error');
  }
}
async function openVoucherInspector(voucherId) {
  const input = $('voucher-search-input');
  if (input) input.value = voucherId;
  searchVoucher();
}
async function searchVoucher() {
  const term = $('voucher-search-input')?.value.trim();
  if (!term) return;
  try {
    const res = await fetchWithTimeout('/dashboard/voucher/' + encodeURIComponent(term), {}, 6000);
    if (res.ok) {
      const detail = await res.json();
      currentVoucherDetail = detail;
      setText('voucher-modal-title', '🎟️ Gutschein-Lineage: ' + truncateHash(detail.voucher_id));
      const html = `<div style="margin-bottom:0.6rem;line-height:1.5;">
        <div><strong>Gutschein-ID:</strong> <span class="code">${escapeHtml(detail.voucher_id)}</span> &bull; <strong>Wurzel-Gültigkeit:</strong> ${escapeHtml(detail.root_valid_until_formatted)}</div>
        <div><strong>Genesis Tag:</strong> <span class="code">${escapeHtml(detail.genesis_tag || 'N/A')}</span> &bull; <strong>Sperren in Kette:</strong> ${escapeHtml(detail.locks.length)} (${escapeHtml(detail.total_byte_years)} BY)</div></div>`;
      let tableHtml = '<h4 style="margin:0.5rem 0 0.2rem 0;font-size:0.85rem;">Ketten-Historie:</h4><div style="overflow-x:auto;"><table><thead><tr><th>Typ</th><th>Lookup Tag</th><th>Child Lock (t_id)</th><th>Sender PubKey</th></tr></thead><tbody>';
      for (const h of detail.locks) {
        const typeBadge = h.is_genesis ? badge('amber', 'GENESIS') : badge('blue', 'SPEND');
        tableHtml += `<tr><td>${typeBadge}</td><td>${cTrunc(h.lookup_tag)}</td><td class="code">${escapeHtml(truncateHash(h.t_id_hex))}</td><td class="code">${escapeHtml(truncateHash(h.sender_pub_hex))}</td></tr>`;
      }
      tableHtml += '</tbody></table></div>';
      setHtml('voucher-modal-details', html);
      setHtml('voucher-modal-table-container', tableHtml);
      setText('voucher-modal-json', JSON.stringify(detail, null, 2));
      $('voucher-modal').classList.add('active');
    } else {
      showToast(`Gutschein oder Lookup-Tag "${escapeHtml(term)}" nicht gefunden.`, 'warning');
    }
  } catch (e) {
    showToast('Fehler bei der Suche: ' + e.message, 'error');
  }
}
function updateTabBadge(id, count) {
  const el = $(id);
  if (!el) return;
  if (count > 0) {
    el.innerText = count;
    el.style.display = 'inline-flex';
  } else {
    el.style.display = 'none';
  }
}

function updateHeader(data) {
  if (data.network_time_ms) {
    const dt = new Date(data.network_time_ms);
    const pad = n => String(n).padStart(2, '0');
    setText('hdr-net-time', `${pad(dt.getDate())}.${pad(dt.getMonth() + 1)}.${dt.getFullYear()}, ${pad(dt.getHours())}:${pad(dt.getMinutes())}:${pad(dt.getSeconds())}`);
  }
  const simBadge = $('hdr-sim-badge');
  if (simBadge) simBadge.style.display = data.is_simulation ? 'inline-block' : 'none';
  if (data.clock_drift_ms != null) {
    const driftEl = $('net-clock-drift');
    if (driftEl) {
      const sign = data.clock_drift_ms > 0 ? '+' : '';
      driftEl.innerText = `${sign}${data.clock_drift_ms} ms`;
      driftEl.style.color = Math.abs(data.clock_drift_ms) > 2000 ? 'var(--red)' : (Math.abs(data.clock_drift_ms) > 500 ? 'var(--amber)' : 'var(--text)');
    }
  }
  const heroText = $('net-hero-text');
  if (heroText) {
    const isWeltnetz = (data.active_nodes_count || 0) + 1 >= 20 || data.shard_mode === 'WELTNETZ' || data.status === 'WELTNETZ';
    heroText.innerHTML = isWeltnetz
      ? '🌐 <strong>Netzwerk-Phase:</strong> Weltnetz (N &ge; 20): HRW Top-20 Sharding aktiv. BFT-Quorum 14/20.'
      : '🌐 <strong>Netzwerk-Phase:</strong> Community-Mesh (Inselnetz): Alle Knoten validieren alle 65.536 Shards. BFT-Quorum erfüllt.';
  }
  const qEl = $('hdr-lat-quorum');
  if (qEl && data.quorum_latency) {
    const qP95 = data.quorum_latency.p95_ms != null ? ` (p95: ${data.quorum_latency.p95_ms.toFixed(1)} ms)` : '';
    qEl.innerText = data.quorum_latency.avg_ms.toFixed(2) + ' ms' + qP95;
    qEl.style.color = data.quorum_latency.avg_ms >= 500.0 ? 'var(--red)' : 'var(--text)';
  }
  const localVal = data.local_latency ? (data.local_latency.avg_ms != null ? data.local_latency.avg_ms.toFixed(2) : '--') : '--';
  const e2eVal = data.e2e_latency ? (data.e2e_latency.avg_ms != null ? data.e2e_latency.avg_ms.toFixed(2) : '--') : '--';
  setText('hdr-lat-local', localVal !== '--' ? localVal + ' ms' : '--');
  setText('hdr-lat-e2e', e2eVal !== '--' ? e2eVal + ' ms' : '--');
  if (data.uptime_formatted) setText('hdr-uptime', data.uptime_formatted);
  const netPill = $('hdr-net-pill');
  if (netPill) {
    const n = (data.active_nodes_count || 0) + 1;
    netPill.innerHTML = `🌐 N=${n} &bull; ${escapeHtml(data.quorum_display || 'Quorum OK')}`;
  }
  setText('hdr-peers', `${data.connected_peers}/${data.configured_peers}`);
}

async function refreshDashboard() {
  if (isPollPaused) {
    if (pollTimer) clearTimeout(pollTimer);
    pollTimer = setTimeout(refreshDashboard, pollIntervalMs);
    return;
  }
  if (isFetchInProgress) {
    console.warn('Dashboard fetch already in progress, skipping interval');
    if (pollTimer) clearTimeout(pollTimer);
    pollTimer = setTimeout(refreshDashboard, pollIntervalMs);
    return;
  }
  isFetchInProgress = true;
  try {
    const res = await fetchWithTimeout('/dashboard/data', {}, 6000);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const d = await res.json();
    currentDashboardData = d;
    lastSuccessfulFetchTime = new Date();
    if (adminToken) {
      refreshAdminSessionTimestamp();
    }
    if (consecutiveFailures >= 3) showToast('Verbindung zum Knoten wiederhergestellt', 'success');
    consecutiveFailures = 0;
    pollIntervalMs = 2000;
    const banner = $('conn-banner');
    if (banner) banner.style.display = 'none';
    const badgeEl = $('status-badge');
    if (badgeEl) {
      const status = d.status || '';
      const badgeText = d.status_badge || status;
      if (status === 'ONLINE' || status === 'WELTNETZ') {
        const lvl = d.health?.level || 'Ok';
        if (lvl === 'Crit') {
          badgeEl.innerText = badgeText + ' (KRITISCH)';
          badgeEl.className = 'badge badge-red';
        } else if (lvl === 'Warn') {
          badgeEl.innerText = badgeText + ' (WARNUNG)';
          badgeEl.className = 'badge badge-amber';
        } else {
          badgeEl.innerText = badgeText;
          badgeEl.className = 'badge badge-green';
        }
      } else if (status === 'COMMUNITY MESH' || status === 'STANDALONE' || status === 'STABILIZING' || status === 'VILLAGE MODE') {
        badgeEl.innerText = badgeText;
        badgeEl.className = 'badge badge-amber';
      } else if (status === 'DEGRADED') {
        badgeEl.innerText = badgeText;
        badgeEl.className = 'badge badge-red';
      } else {
        badgeEl.innerText = badgeText;
        badgeEl.className = 'badge badge-red';
      }
    }
    updateHeader(d);
    setText('shard-status-sub', d.shard_mode);
    const respRatio = d.shard_responsibility_ratio || 0;
    const totalShards = d.total_shards || 65536;
    const respCount = Math.round(respRatio * totalShards);
    const respPct = (respRatio * 100).toFixed(1);
    setText('shard-resp-summary', `Aktive Zuständigkeit: ca. ${respCount.toLocaleString()} von ${totalShards.toLocaleString()} Shards (${respPct}%)`);
    const cv = d.config_view;
    if (cv) {
      setText('hdr-ports', `${cv.api_port}/${cv.p2p_port}`);
      setText('tier-free-port', cv.api_port);
      setText('f2f-client-port', cv.api_port);
      setText('cfg-footprint-bytes', cv.footprint_bytes);
      if (cv.tier_shares) {
        setText('tier-free-badge', `${cv.tier_shares.free}% Kontingent`);
        setText('tier-friends-badge', `${cv.tier_shares.f2f}% Reserviert`);
        setText('tier-vip-badge', `${cv.tier_shares.vip}% Reserviert`);
      }
    }
    if (d.health) {
      const hBadge = $('health-badge');
      const hIcon = $('health-icon');
      const hCard = $('health-card');
      const level = d.health.level || 'Ok';
      if (level === 'Crit') {
        if (hBadge) { hBadge.innerText = 'KRITISCH'; hBadge.className = 'badge badge-red'; }
        if (hIcon) hIcon.innerText = '🚨';
        if (hCard) hCard.style.borderColor = 'rgba(239, 68, 68, 0.5)';
      } else if (level === 'Warn') {
        if (hBadge) { hBadge.innerText = 'WARNUNG'; hBadge.className = 'badge badge-amber'; }
        if (hIcon) hIcon.innerText = '⚠️';
        if (hCard) hCard.style.borderColor = 'rgba(245, 158, 11, 0.5)';
      } else {
        if (hBadge) { hBadge.innerText = 'OK (GESUND)'; hBadge.className = 'badge badge-green'; }
        if (hIcon) hIcon.innerText = '🟢';
        if (hCard) hCard.style.borderColor = 'var(--border)';
      }
      updateDocumentHealthIndicator(level);
      const topBanner = $('health-banner-top');
      if (topBanner) {
        if (level !== 'Ok') {
          const isCrit = level === 'Crit';
          topBanner.className = 'health-banner-top ' + (isCrit ? 'crit' : 'warn');
          setText('health-banner-icon', isCrit ? '🚨' : '⚠️');
          const warnMsgs = (d.health.items || []).filter(i => i.severity !== 'Ok').map(i => i.message_de);
          const msg = warnMsgs.length > 0 ? warnMsgs.join(' • ') : (isCrit ? 'Kritischer Systemzustand erkannt!' : 'Systemwarnung vorhanden.');
          setText('health-banner-msg', msg);
          topBanner.style.display = 'flex';
        } else {
          topBanner.style.display = 'none';
        }
      }
      let cockpitWarns = 0, networkWarns = 0, tiersWarns = 0;
      if (d.health.items) {
        for (const item of d.health.items) {
          if (item.severity === 'Warn' || item.severity === 'Crit') {
            if (['QUEUE_HIGH', 'SLA_VIOLATED', 'CLOCK_DRIFT', 'DASHBOARD_EXPOSED'].includes(item.code)) {
              cockpitWarns++;
            } else if (['NO_PEERS', 'LOW_PEERS', 'SUBNET_DOM'].includes(item.code)) {
              networkWarns++;
            } else if (['BROOM', 'GATEWAY_CONC'].includes(item.code)) {
              tiersWarns++;
            } else {
              cockpitWarns++;
            }
          }
        }
      }
      updateTabBadge('tab-badge-cockpit', cockpitWarns);
      updateTabBadge('tab-badge-network', networkWarns);
      updateTabBadge('tab-badge-tiers', tiersWarns);

      const itemsContainer = $('health-items-container');
      if (itemsContainer) {
        if (d.health.items?.length > 0) {
          let itemsHtml = '';
          for (const item of d.health.items) {
            const isCrit = item.severity === 'Crit';
            itemsHtml += `<div class="health-item ${isCrit ? 'crit' : 'warn'}"><div class="health-item-header"><span class="badge ${isCrit ? 'badge-red' : 'badge-amber'}">${isCrit ? 'KRITISCH' : 'WARNUNG'}</span><strong style="color:var(--text);">${escapeHtml(item.message_de)}</strong><span class="code" style="font-size:0.75rem;margin-left:auto;">${escapeHtml(item.code)}</span></div>${item.hint_de ? `<div class="health-item-hint">💡 ${escapeHtml(item.hint_de)}</div>` : ''}</div>`;
          }
          itemsContainer.innerHTML = itemsHtml;
        } else {
          itemsContainer.innerHTML = '<div style="font-size:0.85rem;color:var(--green);display:flex;align-items:center;gap:0.5rem;padding:0.25rem 0;"><span>✅</span><span>Alle Systeme nominal. Keine Auffälligkeiten erkannt.</span></div>';
        }
      }
    }
    const sp = d.sparklines;
    const latestWrite = sp?.writes?.length ? sp.writes[sp.writes.length - 1] : 0;
    const latestRead = sp?.reads?.length ? sp.reads[sp.reads.length - 1] : 0;
    setText('writes-rate', latestWrite.toFixed(1));
    setText('writes-today', d.total_writes);
    setText('reads-rate', latestRead.toFixed(1));
    setText('reads-today', d.total_reads);
    if (sp) {
      setHtml('writes-sparkline', renderSparklineSvg(sp.writes, '#10b981'));
      setHtml('reads-sparkline', renderSparklineSvg(sp.reads, '#3b82f6'));
    }
    const pers = d.persistence;
    if (pers) {
      setText('persist-queue-val', (pers.flush_queue_depth || 0).toLocaleString());
      const qBar = $('persist-queue-bar');
      if (qBar) {
        const qPct = Math.min(100, ((pers.flush_queue_depth || 0) / 10000) * 100);
        qBar.style.width = qPct + '%';
        if (pers.flush_queue_depth >= 9000) qBar.className = 'progress-fill fill-red';
        else if (pers.flush_queue_depth >= 1000) qBar.className = 'progress-fill fill-amber';
        else qBar.className = 'progress-fill fill-green';
      }
      const sBadge = $('persist-status-badge');
      if (sBadge) {
        if (pers.flush_errors_total > 0) {
          sBadge.innerText = 'Fehler!';
          sBadge.className = 'badge badge-red';
        } else if (pers.flush_queue_depth >= 1000) {
          sBadge.innerText = 'Stau';
          sBadge.className = 'badge badge-amber';
        } else {
          sBadge.innerText = 'Nominal';
          sBadge.className = 'badge badge-green';
        }
      }
      let lastFlushStr = 'Nie';
      if (pers.last_successful_flush_ms > 0) {
        if (pers.last_flush_ago_sec != null) {
          lastFlushStr = `vor ${pers.last_flush_ago_sec}s`;
        } else {
          const dt = new Date(pers.last_successful_flush_ms);
          lastFlushStr = formatHHMMSS(dt);
        }
      }
      setText('persist-last-flush', lastFlushStr);
      setText('persist-batches-val', (pers.flush_batches_total || 0).toLocaleString());
      setText('persist-ops-val', (pers.flush_ops_total || 0).toLocaleString());
      const errEl = $('persist-errors-val');
      if (errEl) {
        errEl.innerText = (pers.flush_errors_total || 0).toLocaleString();
        errEl.style.color = pers.flush_errors_total > 0 ? 'var(--red)' : 'var(--green)';
      }
      setText('persist-redb-val', Math.round((pers.redb_file_bytes || 0) / 1024).toLocaleString() + ' KB');
    }
    const rej = d.rejections;
    if (rej) {
      setText('rej-total-val', (rej.total_rejected || 0).toLocaleString());
      setText('rej-409-val', (rej.conflict_409 || 0).toLocaleString());
      setText('rej-cap-val', (rej.capacity_429 || 0).toLocaleString());
      setText('rej-quota-val', (rej.quota_429 || 0).toLocaleString());
      setText('rej-pow-val', (rej.bad_pow_400 || 0).toLocaleString());
      if (rej.last_rejection_ago_sec != null) {
        setText('rej-last-ago', `vor ${rej.last_rejection_ago_sec}s`);
      } else {
        setText('rej-last-ago', 'Nie');
      }
      const rBadge = $('rej-badge');
      if (rBadge) {
        rBadge.innerText = `${(rej.total_rejected || 0).toLocaleString()} Gesamt`;
        rBadge.className = 'badge ' + ((rej.total_rejected || 0) > 0 ? 'badge-amber' : 'badge-cyan');
      }
    }
    const sys = d.system;
    if (sys) {
      setText('sys-cpu-val', sys.cpu_percent.toFixed(1) + '%');
      const cpuBar = $('sys-cpu-bar');
      if (cpuBar) {
        const pct = Math.min(100, Math.max(0, sys.cpu_percent));
        cpuBar.style.width = pct + '%';
        if (pct >= 85) cpuBar.className = 'progress-fill fill-red';
        else if (pct >= 70) cpuBar.className = 'progress-fill fill-amber';
        else cpuBar.className = 'progress-fill fill-green';
      }
      if (d.disk_free_gb != null) {
        setText('sys-disk-val', `${d.disk_free_gb.toFixed(1)} GB frei`);
        const diskBar = $('sys-disk-bar');
        if (diskBar) {
          const totalGb = sys ? ((sys.redb_bytes || 0) / (1024 * 1024 * 1024)) + d.disk_free_gb : d.disk_free_gb;
          const fillPct = totalGb > 0 ? Math.min(100, Math.max(5, (d.disk_free_gb / totalGb) * 100)) : Math.min(100, Math.max(5, (d.disk_free_gb / 20.0) * 100));
          diskBar.style.width = fillPct.toFixed(1) + '%';
          if (d.disk_free_gb < 2.0) diskBar.className = 'progress-fill fill-red';
          else if (d.disk_free_gb < 5.0) diskBar.className = 'progress-fill fill-amber';
          else diskBar.className = 'progress-fill fill-green';
        }
      }
      setText('sys-rss-val', sys.rss_mb.toFixed(1) + ' MB');
      setText('sys-netto-val', sys.netto_locks_bytes + ' B');
      setText('sys-purged-val', sys.ttl_purged_count);
    }
    const th = d.thermometer;
    if (th) {
      setText('thermo-write-load', th.gossip_write_load.toFixed(2));
      setText('thermo-read-load', th.gossip_read_load.toFixed(2));
      setText('thermo-ncb-eff', Math.round(th.ncb_eff));
      setText('thermo-ncb-read-eff', Math.round(th.ncb_read_eff));
      setText('thermo-rolling-avg', th.gossip_write_load.toFixed(2));
      setText('quota-used-val', (th.today_write_used || 0).toLocaleString());
      setText('quota-limit-val', (th.daily_write_quota || 0).toLocaleString());
    }
    setText('conc-val', (d.gateway_concentration_ratio * 100).toFixed(1) + '%');
    setText('subnet-dom-sub', (d.shard_subnet_dominance_max * 100).toFixed(1) + '%');
    renderFriendsTable();
    const searchInput = $('node-search-input');
    if (searchInput?.value.trim()) {
      filterNodesTable();
    } else {
      const nodesTbody = $('nodes-tbody');
      if (nodesTbody && d.network_nodes?.length > 0) {
        let html = '';
        for (const n of d.network_nodes) html += renderNodeRow(n);
        nodesTbody.innerHTML = html;
        setText('network-count-sub', `${d.network_nodes.length} Knoten registriert`);
      }
    }
    const shardsTbody = $('shards-tbody');
    if (shardsTbody) {
      if (d.sample_shard_scores?.length > 0) {
        const totalActive = (d.active_nodes_count || 0) + 1;
        let html = '';
        for (const s of d.sample_shard_scores) {
          const rankText = `Rang ${s.rank || 1} von ${totalActive}`;
          const sBadge = s.is_responsible
            ? badge('green', 'Validator (Signer)')
            : badge('cyan', 'Gateway (Relay)');
          html += `<tr><td><strong class="code">${escapeHtml(s.shard_id)}</strong></td><td class="code">${s.score.toFixed(4)}</td><td>${escapeHtml(rankText)}</td><td>${sBadge}</td></tr>`;
        }
        shardsTbody.innerHTML = html;
      } else {
        shardsTbody.innerHTML = '<tr><td colspan="4" class="empty-cell">Keine Shard-Daten vorhanden</td></tr>';
      }
    }
    const ti = d.tiers;
    if (ti) {
      setText('tier-free-used-val', (ti.free_used_pct || 0).toFixed(1) + '%');
      setText('tier-free-writes-val', ti.free_writes_today || 0);
      const freeBar = $('tier-free-bar');
      if (freeBar) freeBar.style.width = Math.min(100, Math.max(0, ti.free_used_pct || 0)) + '%';
      setText('tier-free-pow-val', ti.free_pow_diff);
      setText('tier-free-hashes-val', (ti.free_pow_hashes || 1).toLocaleString());
      setText('tier-free-time-val', ti.free_pow_time_est || '< 0.1 ms');
      setText('tier-free-req-val', (ti.free_req_sec || 0).toFixed(1));
      setText('tier-friends-used-val', (ti.friends_used_pct || 0).toFixed(1) + '%');
      setText('tier-friends-writes-val', ti.friends_writes_today || 0);
      const friendsBar = $('tier-friends-bar');
      if (friendsBar) friendsBar.style.width = Math.min(100, Math.max(0, ti.friends_used_pct || 0)) + '%';
      setText('tier-friends-count-val', ti.active_friends_count || 0);
      setText('tier-vip-used-val', (ti.vip_used_pct || 0).toFixed(1) + '%');
      setText('tier-vip-writes-val', ti.vip_writes_today || 0);
      const vipBar = $('tier-vip-bar');
      if (vipBar) vipBar.style.width = Math.min(100, Math.max(0, ti.vip_used_pct || 0)) + '%';
      setText('tier-vip-accounts-val', ti.vip_accounts_count || 0);
      setText('tier-vip-balance-val', (ti.vip_total_balance || 0).toLocaleString());
      setText('quota-locks-val', ti.total_writes_today || 0);
      setText('quota-pct-text', (ti.total_quota_used_pct || 0).toFixed(1) + '%');
      const quotaBar = $('quota-bar');
      if (quotaBar) quotaBar.style.width = Math.min(100, Math.max(0, ti.total_quota_used_pct || 0)) + '%';
      const vipTbody = $('vip-accounts-tbody');
      if (vipTbody) {
        if (ti.vip_accounts?.length > 0) {
          let html = '';
          for (const a of ti.vip_accounts) {
            const safeTag = escapeHtml(a.account_tag);
            const topupBtn = `<button class="btn btn-secondary admin-only" style="${adminToken ? 'display:inline-flex;' : 'display:none;'}padding:0.2rem 0.5rem;font-size:0.75rem;" data-tag="${safeTag}" onclick="prefillVipTopup(this.getAttribute('data-tag'))">+ Aufladen</button>`;
            html += `<tr><td>${codeTag(a.account_tag, a.account_tag)}</td><td><strong style="color:var(--purple);">${a.balance_byte_years.toLocaleString()}</strong> Byte-Jahre</td><td>${topupBtn}</td></tr>`;
          }
          vipTbody.innerHTML = html;
        } else {
          vipTbody.innerHTML = '<tr><td colspan="3" class="empty-cell">Keine VIP Accounts hinterlegt</td></tr>';
        }
      }
    }
    const f2fClientsTbody = $('f2f-clients-tbody');
    if (f2fClientsTbody) {
      if (d.f2f_clients?.length > 0) {
        let html = '';
        for (const c of d.f2f_clients) {
          const whaleBadge = c.whale_brake_active ? badge('amber', 'Aktiv (5x)') : badge('green', 'Inaktiv');
          const lastActive = c.last_active_sec != null ? `vor ${escapeHtml(c.last_active_sec)}s` : '<span style="color:var(--text-muted);">-</span>';
          const tok = c.token || '';
          const safeLabel = escapeHtml(c.label || 'Client');
          const safeTok = escapeHtml(tok);
          const safeHash = escapeHtml(c.token_hash || '');
          const qrBtn = `<button class="btn btn-secondary" style="padding:0.2rem 0.5rem;font-size:0.75rem;margin-right:0.35rem;" data-label="${safeLabel}" data-tok="${safeTok}" data-hash="${safeHash}" onclick="showClientQrModal(this.getAttribute('data-label'), this.getAttribute('data-tok'), this.getAttribute('data-hash'))">QR-Code</button>`;
          const revokeBtn = `<button class="btn btn-danger admin-only" style="${adminToken ? 'display:inline-flex;' : 'display:none;'}padding:0.2rem 0.5rem;font-size:0.75rem;" data-hash="${safeHash}" data-label="${safeLabel}" onclick="adminRemoveClientFriend(this.getAttribute('data-hash'), this.getAttribute('data-label'))">Widerrufen</button>`;
          html += `<tr><td><strong>${safeLabel}</strong></td><td>${cTrunc(c.token_hash)}</td><td>${(c.writes_today || 0).toLocaleString()} / ${(c.daily_limit || 0).toLocaleString()}</td><td>${whaleBadge}</td><td>${lastActive}</td><td>${qrBtn}${revokeBtn}</td></tr>`;
        }
        f2fClientsTbody.innerHTML = html;
        const sub = $('f2f-clients-count-sub');
        if (sub && cv) sub.innerHTML = `${d.f2f_clients.length} Wallets registriert &bull; REST Port <strong>${cv.api_port}</strong>`;
      } else {
        f2fClientsTbody.innerHTML = '<tr><td colspan="6" class="empty-cell">Keine Ingress-Client-Freunde registriert (Locks im Free Tier nutzen BLAKE3 PoW).</td></tr>';
      }
    }
    setText('vouchers-count-sub', `${d.total_active_vouchers_count || 0} Gutscheine aktiv (Top 15 angezeigt)`);
    const vouchersTbody = $('vouchers-tbody');
    if (vouchersTbody) {
      if (d.active_vouchers?.length > 0) {
        let html = '';
        for (const v of d.active_vouchers) {
          const genShort = v.genesis_tag ? truncateHash(v.genesis_tag) : 'N/A';
          const sBadge = v.status === 'Active' ? badge('green', 'Aktiv') : badge('amber', v.status);
          const safeVoucherId = escapeHtml(v.voucher_id || '');
          html += `<tr><td><strong>${safeVoucherId}</strong></td><td>${escapeHtml(v.root_valid_until_formatted)}</td><td class="code">${escapeHtml(genShort)}</td><td>${escapeHtml(v.locks_count)} Sperren</td><td>${sBadge}</td><td><button class="btn btn-secondary" data-voucher="${safeVoucherId}" onclick="openVoucherInspector(this.getAttribute('data-voucher'))">🔍 Wurzel-Inspektor</button></td></tr>`;
        }
        vouchersTbody.innerHTML = html;
      } else {
        vouchersTbody.innerHTML = '<tr><td colspan="6" class="empty-cell">Keine aktiven Gutscheine im Speicher</td></tr>';
      }
    }
    filterLocksTable();
  } catch (e) {
    consecutiveFailures++;
    if (consecutiveFailures >= 3) {
      const banner = $('conn-banner');
      if (banner) {
        setText('conn-banner-time', lastSuccessfulFetchTime ? formatHHMMSS(lastSuccessfulFetchTime) : '--:--:--');
        banner.style.display = 'flex';
      }
      if (pollIntervalMs < 16000) pollIntervalMs = Math.min(16000, pollIntervalMs * 2);
    }
  } finally {
    isFetchInProgress = false;
    if (pollTimer) clearTimeout(pollTimer);
    pollTimer = setTimeout(refreshDashboard, pollIntervalMs);
  }
}

const pollData = refreshDashboard;
const fetchDashboardData = refreshDashboard;

// --- Tab 4: History & Security Event Log (Phase 2) ---
let currentHistoryWindow = '24h';
let cachedHistoryPoints = [];
let cachedAuditEvents = [];
let cachedFilteredAuditEvents = null;
let eventsPollTimer = null;
let historyPollTimer = null;

async function loadHistoryWindow(windowStr) {
  currentHistoryWindow = windowStr;
  await fetchHistoryData();
}

async function fetchHistoryData() {
  try {
    const res = await fetchWithTimeout(`/dashboard/history?window=${currentHistoryWindow}`, {}, 6000);
    if (!res.ok) return;
    const data = await res.json();
    cachedHistoryPoints = data.points || [];
    renderHistoryChart(cachedHistoryPoints);
  } catch (e) {
    console.debug('Failed to fetch history:', e);
  }
}

function renderHistoryChart(points) {
  const container = $('history-chart');
  const summary = $('history-summary-sub');
  if (!container) return;

  if (!points || points.length === 0) {
    container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:var(--text-muted);font-size:0.875rem;">Noch keine Verlaufsdaten gesammelt (Sampler läuft im 60s Takt).</div>';
    if (summary) summary.innerText = '0 Datenpunkte vorhanden';
    return;
  }

  const w = 900, h = 150;
  const len = points.length;
  if (summary) {
    const last = points[len - 1];
    summary.innerText = `${len} Datenpunkte (${currentHistoryWindow}) &bull; Zuletzt: Free=${last.free_writes}, F2F=${last.f2f_writes}, VIP=${last.vip_writes}, Reads=${last.read_count}, Peers=${last.connected_peers}`;
  }

  const maxVal = Math.max(
    ...points.map(p => Math.max(p.free_writes || 0, p.f2f_writes || 0, p.vip_writes || 0, (p.read_count || 0) / 5)),
    1.0
  );

  const getPointsStr = (valFn) => {
    return points.map((p, i) => {
      const x = len > 1 ? (i / (len - 1)) * (w - 20) + 10 : w / 2;
      const v = valFn(p);
      const y = h - 20 - ((v / maxVal) * (h - 40));
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(' ');
  };

  const freePts = getPointsStr(p => p.free_writes || 0);
  const f2fPts = getPointsStr(p => p.f2f_writes || 0);
  const vipPts = getPointsStr(p => p.vip_writes || 0);
  const readPts = getPointsStr(p => (p.read_count || 0) / 5);
  const tStart = points[0].timestamp_sec ? formatHHMMSS(new Date(points[0].timestamp_sec * 1000)) : '';
  const tEnd = points[len - 1].timestamp_sec ? formatHHMMSS(new Date(points[len - 1].timestamp_sec * 1000)) : '';

  let hoverDots = '';
  for (let i = 0; i < len; i++) {
    const p = points[i];
    const x = len > 1 ? (i / (len - 1)) * (w - 20) + 10 : w / 2;
    const yFree = h - 20 - (((p.free_writes || 0) / maxVal) * (h - 40));
    const timeStr = p.timestamp_sec ? new Date(p.timestamp_sec * 1000).toLocaleTimeString() : '';
    hoverDots += `<circle cx="${x.toFixed(1)}" cy="${yFree.toFixed(1)}" r="3" fill="var(--green)" opacity="0.6"><title>${timeStr} - Free: ${p.free_writes || 0}, F2F: ${p.f2f_writes || 0}, VIP: ${p.vip_writes || 0}, Reads: ${p.read_count || 0}</title></circle>`;
  }

  container.innerHTML = `
    <svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" style="width:100%;height:100%;display:block;">
      <!-- Grid lines -->
      <line x1="10" y1="${h-20}" x2="${w-10}" y2="${h-20}" stroke="var(--border)" stroke-width="1" />
      <line x1="10" y1="${(h-20)/2}" x2="${w-10}" y2="${(h-20)/2}" stroke="var(--border)" stroke-width="1" stroke-dasharray="3,3" />
      <!-- Labels -->
      <text x="14" y="16" fill="var(--text-muted)" font-size="10" font-family="sans-serif">Max: ${Math.round(maxVal)} Writes/min</text>
      <text x="14" y="${h-6}" fill="var(--text-muted)" font-size="10" font-family="sans-serif">0</text>
      <text x="50" y="${h-6}" fill="var(--text-muted)" font-size="10" font-family="sans-serif">${tStart}</text>
      <text x="${w-70}" y="${h-6}" fill="var(--text-muted)" font-size="10" font-family="sans-serif">${tEnd}</text>
      <!-- Reads line (Cyan) -->
      <polyline points="${readPts}" fill="none" stroke="var(--cyan)" stroke-width="2" stroke-dasharray="2,2" />
      <!-- VIP line (Purple) -->
      <polyline points="${vipPts}" fill="none" stroke="var(--purple)" stroke-width="2" />
      <!-- Friends line (Blue) -->
      <polyline points="${f2fPts}" fill="none" stroke="var(--blue)" stroke-width="2" />
      <!-- Free line (Green) -->
      <polyline points="${freePts}" fill="none" stroke="var(--green)" stroke-width="2" />
      <!-- Hover data points -->
      ${hoverDots}
    </svg>
  `;
}

async function fetchAuditEvents() {
  try {
    const res = await fetchWithTimeout('/dashboard/events?limit=200', {}, 6000);
    if (!res.ok) return;
    const data = await res.json();
    cachedAuditEvents = data.events || [];
    filterEventsTable();
  } catch (e) {
    console.debug('Failed to fetch events:', e);
  }
}

function filterEventsTable() {
  const tbody = $('events-tbody');
  const countSub = $('events-count-sub');
  if (!tbody) return;

  const search = $('event-search-input')?.value.trim().toLowerCase() || '';
  const severityFilter = $('event-severity-filter')?.value || 'ALL';
  const isFiltered = Boolean(search || severityFilter !== 'ALL');

  const filtered = cachedAuditEvents.filter(ev => {
    if (severityFilter !== 'ALL' && ev.severity !== severityFilter) return false;
    if (search) {
      const matchMsg = ev.message && ev.message.toLowerCase().includes(search);
      const matchKind = ev.kind && String(ev.kind).toLowerCase().includes(search);
      if (!matchMsg && !matchKind) return false;
    }
    return true;
  });

  cachedFilteredAuditEvents = isFiltered ? filtered : null;

  if (countSub) {
    if (isFiltered) {
      countSub.innerText = `${filtered.length} von ${cachedAuditEvents.length} Ereignissen gefiltert (Ringbuffer max 1000)`;
    } else {
      countSub.innerText = `${cachedAuditEvents.length} Ereignisse geloggt (Ringbuffer max 1000)`;
    }
  }

  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-cell">Keine passenden Audit-Ereignisse gefunden.</td></tr>';
    return;
  }

  // Show most recent events first
  const displayItems = [...filtered].reverse();
  let html = '';
  for (const item of displayItems) {
    const d = new Date(item.timestamp_sec * 1000);
    const timeStr = `${d.toLocaleDateString()} ${d.toLocaleTimeString()}`;
    const sevBadge = item.severity === 'Crit'
      ? badge('red', 'CRIT')
      : (item.severity === 'Warn' ? badge('amber', 'WARN') : badge('green', 'OK'));

    let kindBadge = badge('cyan', item.kind);
    if (item.kind === 'EquivocationFraud' || item.kind === 'PeerBan') kindBadge = badge('red', item.kind);
    else if (item.kind === 'PeerConnect') kindBadge = badge('green', item.kind);
    else if (item.kind === 'QuotaTopup') kindBadge = badge('purple', item.kind);

    html += `<tr class="event-row"><td>#${item.id}</td><td>${timeStr}</td><td>${kindBadge}</td><td>${sevBadge}</td><td>${escapeHtml(item.message)}</td></tr>`;
  }
  tbody.innerHTML = html;
}

function exportAuditLogJson() {
  const list = cachedFilteredAuditEvents || cachedAuditEvents;
  if (!list || list.length === 0) {
    showToast('Keine Ereignisse zum Exportieren vorhanden', 'warning');
    return;
  }
  const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(list, null, 2));
  const a = document.createElement('a');
  a.setAttribute('href', dataStr);
  a.setAttribute('download', `humoco-audit-log-${new Date().toISOString().slice(0, 10)}.json`);
  document.body.appendChild(a);
  a.click();
  a.remove();
  showToast('JSON-Audit-Log heruntergeladen', 'success');
}

function exportAuditLogCsv() {
  const list = cachedFilteredAuditEvents || cachedAuditEvents;
  if (!list || list.length === 0) {
    showToast('Keine Ereignisse zum Exportieren vorhanden', 'warning');
    return;
  }
  const header = ['ID', 'Timestamp_Sec', 'Date_Time', 'Kind', 'Severity', 'Message'];
  const rows = list.map(e => [
    e.id,
    e.timestamp_sec,
    new Date(e.timestamp_sec * 1000).toISOString(),
    `"${(e.kind || '').replace(/"/g, '""')}"`,
    `"${(e.severity || '').replace(/"/g, '""')}"`,
    `"${(e.message || '').replace(/"/g, '""')}"`
  ]);
  const csvContent = [header.join(','), ...rows.map(r => r.join(','))].join('\r\n');
  const dataStr = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csvContent);
  const a = document.createElement('a');
  a.setAttribute('href', dataStr);
  a.setAttribute('download', `humoco-audit-log-${new Date().toISOString().slice(0, 10)}.csv`);
  document.body.appendChild(a);
  a.click();
  a.remove();
  showToast('CSV-Audit-Log heruntergeladen', 'success');
}

// Background tab throttling (Page Visibility API)
document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    pollIntervalMs = 10000;
  } else {
    pollIntervalMs = 2000;
    if (pollTimer) clearTimeout(pollTimer);
    refreshDashboard();
  }
});

// Offline air-gap QR Code Generator (ISO/IEC 18004 Byte Mode, Level L, zero CDN)
function generateQrSvg(text) {
  const bytes = new TextEncoder().encode(text);
  const len = bytes.length;
  let ver, size, alignCenter, totalCW, dataCW, ecCW, numBlocks, remBits;
  if (len <= 53) {
    ver = 3; size = 29; alignCenter = 22; totalCW = 70; dataCW = 55; ecCW = 15; numBlocks = 1; remBits = 0;
  } else if (len <= 78) {
    ver = 4; size = 33; alignCenter = 26; totalCW = 100; dataCW = 80; ecCW = 20; numBlocks = 1; remBits = 0;
  } else if (len <= 106) {
    ver = 5; size = 37; alignCenter = 30; totalCW = 134; dataCW = 108; ecCW = 26; numBlocks = 1; remBits = 0;
  } else {
    ver = 6; size = 41; alignCenter = 34; totalCW = 172; dataCW = 136; ecCW = 18; numBlocks = 2; remBits = 7;
  }

  const bitBuf = [];
  function pushBits(val, count) {
    for (let i = count - 1; i >= 0; i--) bitBuf.push(((val >> i) & 1) === 1);
  }
  pushBits(0b0100, 4);
  pushBits(len, 8);
  for (let i = 0; i < len; i++) pushBits(bytes[i], 8);

  const totalDataBits = dataCW * 8;
  const termLen = Math.min(4, Math.max(0, totalDataBits - bitBuf.length));
  pushBits(0, termLen);
  while (bitBuf.length % 8 !== 0) bitBuf.push(false);

  const dataCodewords = [];
  for (let i = 0; i < bitBuf.length; i += 8) {
    let b = 0;
    for (let j = 0; j < 8; j++) b = (b << 1) | (bitBuf[i + j] ? 1 : 0);
    dataCodewords.push(b);
  }
  const pad = [0xEC, 0x11];
  let padIdx = 0;
  while (dataCodewords.length < dataCW) {
    dataCodewords.push(pad[padIdx]);
    padIdx = 1 - padIdx;
  }

  const exp = new Uint8Array(512), log = new Uint8Array(256);
  let x = 1;
  for (let i = 0; i < 255; i++) {
    exp[i] = x; exp[i + 255] = x; log[x] = i;
    x <<= 1; if (x >= 256) x ^= 0x11D;
  }
  const gfMul = (a, b) => (!a || !b ? 0 : exp[(log[a] + log[b]) % 255]);

  let gen = [1];
  for (let i = 0; i < ecCW; i++) {
    const alpha = exp[i];
    const next = new Array(gen.length + 1).fill(0);
    for (let j = 0; j < gen.length; j++) {
      next[j] ^= gen[j];
      next[j + 1] ^= gfMul(gen[j], alpha);
    }
    gen = next;
  }

  function rsEncode(data, ecCount) {
    const rem = new Array(ecCount).fill(0);
    for (let i = 0; i < data.length; i++) {
      const factor = data[i] ^ rem[0];
      rem.copyWithin(0, 1, ecCount);
      rem[ecCount - 1] = 0;
      if (factor !== 0) {
        for (let j = 0; j < ecCount; j++) rem[j] ^= gfMul(gen[j + 1], factor);
      }
    }
    return rem;
  }

  const dataPerBlock = Math.floor(dataCW / numBlocks);
  const dataBlocks = [], ecBlocks = [];
  for (let b = 0; b < numBlocks; b++) {
    const slice = dataCodewords.slice(b * dataPerBlock, (b + 1) * dataPerBlock);
    dataBlocks.push(slice);
    ecBlocks.push(rsEncode(slice, ecCW));
  }

  const interleaved = [];
  for (let i = 0; i < dataPerBlock; i++) {
    for (let b = 0; b < numBlocks; b++) interleaved.push(dataBlocks[b][i]);
  }
  for (let i = 0; i < ecCW; i++) {
    for (let b = 0; b < numBlocks; b++) interleaved.push(ecBlocks[b][i]);
  }

  const allBits = [];
  for (let i = 0; i < interleaved.length; i++) {
    for (let j = 7; j >= 0; j--) allBits.push(((interleaved[i] >> j) & 1) === 1);
  }
  while (allBits.length < totalCW * 8 + remBits) allBits.push(false);

  const modules = Array.from({ length: size }, () => Array(size).fill(false));
  const isFunc = Array.from({ length: size }, () => Array(size).fill(false));

  function markFunc(r, c) { if (r >= 0 && r < size && c >= 0 && c < size) isFunc[r][c] = true; }
  function placeFinder(top, left) {
    for (let r = 0; r < 7; r++) {
      for (let c = 0; c < 7; c++) {
        const isBorder = r === 0 || r === 6 || c === 0 || c === 6;
        const isCenter = r >= 2 && r <= 4 && c >= 2 && c <= 4;
        modules[top + r][left + c] = isBorder || isCenter;
        isFunc[top + r][left + c] = true;
      }
    }
  }

  placeFinder(0, 0);
  placeFinder(0, size - 7);
  placeFinder(size - 7, 0);

  for (let i = 0; i < 8; i++) {
    markFunc(7, i); markFunc(i, 7);
    markFunc(7, size - 1 - i); markFunc(i, size - 8);
    markFunc(size - 8, i); markFunc(size - 1 - i, 7);
  }

  if (alignCenter > 0) {
    for (let r = -2; r <= 2; r++) {
      for (let c = -2; c <= 2; c++) {
        const isBorder = Math.abs(r) === 2 || Math.abs(c) === 2;
        const isCenter = r === 0 && c === 0;
        modules[alignCenter + r][alignCenter + c] = isBorder || isCenter;
        isFunc[alignCenter + r][alignCenter + c] = true;
      }
    }
  }

  for (let i = 8; i < size - 8; i++) {
    const isBlack = i % 2 === 0;
    modules[6][i] = isBlack; isFunc[6][i] = true;
    modules[i][6] = isBlack; isFunc[i][6] = true;
  }

  modules[size - 8][8] = true; isFunc[size - 8][8] = true;
  for (let i = 0; i < 9; i++) { isFunc[8][i] = true; isFunc[i][8] = true; }
  for (let i = 0; i < 8; i++) { isFunc[8][size - 1 - i] = true; isFunc[size - 1 - i][8] = true; }

  let bitIdx = 0, col = size - 1, upward = true;
  while (col > 0) {
    if (col === 6) col -= 1;
    const rows = upward ? Array.from({ length: size }, (_, i) => size - 1 - i) : Array.from({ length: size }, (_, i) => i);
    for (const r of rows) {
      for (const c of [col, col - 1]) {
        if (!isFunc[r][c]) {
          const bit = bitIdx < allBits.length ? allBits[bitIdx] : false;
          bitIdx++;
          const mask = (r + c) % 2 === 0;
          modules[r][c] = bit !== mask;
        }
      }
    }
    upward = !upward;
    col -= 2;
  }

  const formatVal = 0x77C4;
  for (let i = 0; i < 15; i++) {
    const bit = ((formatVal >> i) & 1) === 1;
    let r1, c1;
    if (i <= 5) { r1 = 8; c1 = i; }
    else if (i === 6) { r1 = 8; c1 = 7; }
    else if (i === 7) { r1 = 8; c1 = 8; }
    else if (i === 8) { r1 = 7; c1 = 8; }
    else { r1 = 14 - i; c1 = 8; }
    modules[r1][c1] = bit;
    const r2 = i < 7 ? size - 1 - i : 8;
    const c2 = i < 7 ? 8 : size - 8 + (i - 7);
    modules[r2][c2] = bit;
  }

  const quiet = 4, total = size + quiet * 2;
  let d = '';
  for (let r = 0; r < size; r++) {
    let c = 0;
    while (c < size) {
      if (modules[r][c]) {
        const startC = c;
        while (c < size && modules[r][c]) c++;
        const w = c - startC, x = startC + quiet, y = r + quiet;
        d += w === 1 ? `M${x} ${y}h1v1h-1z ` : `M${x} ${y}h${w}v1h-${w}z `;
      } else {
        c++;
      }
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${total} ${total}" shape-rendering="crispEdges" class="qr-svg"><rect width="${total}" height="${total}" fill="#ffffff"/><path fill="#111827" d="${d.trim()}"/></svg>`;
}

function startPhase2Pollers() {
  fetchHistoryData();
  fetchAuditEvents();
  if (historyPollTimer) clearInterval(historyPollTimer);
  historyPollTimer = setInterval(fetchHistoryData, 30000);
  if (eventsPollTimer) clearInterval(eventsPollTimer);
  eventsPollTimer = setInterval(fetchAuditEvents, 10000);
}

checkInactivityOnLoad();
updateAdminUI();
handleHashRouting();
refreshDashboard();
startPhase2Pollers();