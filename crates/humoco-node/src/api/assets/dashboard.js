const $ = id => document.getElementById(id);
const setText = (id, v) => { const el = $(id); if (el && v != null) el.innerText = v; };
const setHtml = (id, h) => { const el = $(id); if (el && h != null) el.innerHTML = h; };
const badge = (c, t) => `<span class="badge badge-${c}">${t}</span>`;
const codeTag = (t, title) => `<span class="code"${title ? ` title="${title}"` : ''}>${t}</span>`;
const cTrunc = (h, title) => codeTag(truncateHash(h), title || h);
let currentDashboardData = null;
let currentVoucherDetail = null;
let adminToken = localStorage.getItem('humoco_admin_token') || '';
let consecutiveFailures = 0;
let pollIntervalMs = 2000;
let pollTimer = null;
let lastSuccessfulFetchTime = null;
let pendingConfirmCallback = null;
function escapeHtml(s) {
  if (!s) return '';
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
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
function handleAdminBtnClick() {
  if (adminToken) {
    localStorage.removeItem('humoco_admin_token');
    adminToken = '';
    updateAdminUI();
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
      localStorage.setItem('humoco_admin_token', val);
      closeModal('admin-modal');
      updateAdminUI();
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
  const dInput = $('friend-dual-role-input');
  const raw = pInput?.value.trim() || '';
  const label = lInput?.value.trim() || '';
  const dualRole = !!dInput?.checked;
  if (!raw) return;
  const pubkey = raw.includes('@') ? raw.split('@')[0].trim() : raw;
  try {
    const res = await fetchWithTimeout('/dashboard/admin/mesh/peers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + adminToken },
      body: JSON.stringify({ pubkey, label: label || null, dual_role_ingress: dualRole })
    }, 6000);
    if (res.ok) {
      if (pInput) pInput.value = '';
      if (lInput) lInput.value = '';
      if (dInput) dInput.checked = false;
      showToast('Nachbarknoten verbunden' + (dualRole ? ' (auch als Ingress-Client)' : ''), 'success');
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
  let walletUri = '';
  if (tokenHashOrUri && tokenHashOrUri.startsWith('humoco://')) {
    walletUri = tokenHashOrUri;
  } else {
    const apiPort = currentDashboardData?.config_view?.api_port || 8080;
    const host = window.location.hostname || '127.0.0.1';
    const tok = token || tokenHashOrUri;
    walletUri = `humoco://${host}:${apiPort}?token=${tok}`;
  }
  setText('client-qr-label', label || 'Client');
  setText('client-qr-token', token || tokenHashOrUri);
  setText('client-qr-uri', walletUri);
  const svg = generateQrSvg(walletUri);
  setHtml('client-qr-box', svg);
  $('client-qr-modal')?.classList.add('active');
}
function copyClientUri() {
  const uri = $('client-qr-uri')?.innerText?.trim();
  if (!uri) return;
  navigator.clipboard.writeText(uri).then(
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
function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  const btn = document.querySelector(`[onclick="switchTab('${tabId}')"]`);
  if (btn) btn.classList.add('active');
  const target = $(tabId);
  if (target) target.classList.add('active');
}
function copyPeering() {
  const text = $('peering-text')?.innerText || '';
  navigator.clipboard.writeText(text).then(() => {
    const btn = $('copy-btn');
    if (btn) { const o = btn.innerText; btn.innerText = 'Kopiert!'; setTimeout(() => { btn.innerText = o; }, 1500); }
    showToast('Peering-String kopiert', 'success');
  }).catch(() => {});
}
function copyMyPubkey() {
  const text = $('my-pubkey-text')?.innerText || '';
  navigator.clipboard.writeText(text).then(() => showToast('NodePubKey kopiert', 'success')).catch(() => {});
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
  navigator.clipboard.writeText(text).then(() => showToast('JSON kopiert', 'success')).catch(() => {});
}
function copyVoucherJson() {
  if (!currentVoucherDetail) return;
  navigator.clipboard.writeText(JSON.stringify(currentVoucherDetail, null, 2)).then(() => showToast('JSON kopiert', 'success')).catch(() => {});
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
  const statusBadge = n.connection_status.includes('Connected')
    ? (n.missing_count === 0 ? badge('green', 'Connected (0)') : badge('amber', n.connection_status))
    : (n.connection_status.includes('Suspended') ? badge('red', n.connection_status) : badge('amber', n.connection_status));
  const rttText = n.rtt_ms != null ? n.rtt_ms + ' ms' : '<span style="color:var(--text-muted);">-</span>';
  const routeText = `${n.min_hops} Hop${n.min_hops === 1 ? '' : 's'}${n.best_ingress_peer ? ' via ' + truncateHash(n.best_ingress_peer) : (n.is_local ? ' (Self)' : (n.is_f2f ? ' (Direkt)' : ''))}`;
  const incubText = n.is_immature ? badge('amber', `24h (${n.incubation_remaining_sec || 0}s)`) : badge('green', 'Aktiv');
  return `<tr><td>${cTrunc(n.public_key)}</td><td>${n.address}</td><td>${roleBadge}</td><td>${statusBadge}</td><td>${rttText}</td><td>${routeText}</td><td>${cTrunc(n.hrw_routing_id)}</td><td>${incubText}</td><td><button class="btn btn-secondary" style="padding:0.2rem 0.5rem;" onclick="openNodeInspector('${n.public_key}')">🔍 Info</button></td></tr>`;
}
function openNodeInspector(pubkey) {
  if (!currentDashboardData?.network_nodes) return;
  const node = currentDashboardData.network_nodes.find(n => n.public_key === pubkey || n.node_id === pubkey);
  if (!node) { showToast('Knoten nicht gefunden: ' + pubkey, 'warning'); return; }
  setText('node-modal-title', '🔍 Knoten-Diagnose: ' + truncateHash(node.public_key));
  const statusBadge = node.connection_status.includes('Connected')
    ? (node.missing_count === 0 ? badge('green', 'Connected (0 Ausfälle)') : badge('amber', node.connection_status))
    : (node.connection_status.includes('Suspended') ? badge('red', node.connection_status) : badge('amber', node.connection_status));
  const rttText = node.rtt_ms != null ? node.rtt_ms + ' ms' : '<span style="color:var(--text-muted);">-</span>';
  const failText = node.last_failure_sec != null ? `vor ${node.last_failure_sec}s` : '<span style="color:var(--green);">Kein Ausfall</span>';
  const ingressText = node.best_ingress_peer ? 'via ' + node.best_ingress_peer : (node.is_local ? 'Lokal (Self)' : (node.is_f2f ? 'F2F Direkt' : 'Direkt / Standby'));
  const incubText = node.is_immature ? badge('amber', `24h (${node.incubation_remaining_sec || 0}s)`) : badge('green', 'Aktiv');
  const html = `<div style="line-height:1.5;font-size:0.875rem;">
    <div class="inspect-box">
      <h4 style="margin:0 0 0.4rem 0;font-size:0.85rem;color:var(--purple);">🔑 Identität &amp; Kryptographie</h4>
      <div><strong>NodePubKey:</strong> <span class="code" id="node-modal-pubkey">${node.public_key}</span> <button class="btn btn-secondary" style="padding:0.15rem 0.4rem;font-size:0.75rem;" onclick="copyNodePubkey()">Kopieren</button></div>
      <div><strong>Adresse:</strong> <span class="code">${node.address}</span></div>
      <div><strong>Shard-Ticket:</strong> <span class="code">${node.hrw_routing_id}</span> (Score: <strong>${node.work_score}</strong>)</div>
    </div>
    <div class="inspect-box">
      <h4 style="margin:0 0 0.4rem 0;font-size:0.85rem;color:var(--green);">💓 Verbindungs-Gesundheit</h4>
      <div><strong>Status:</strong> ${statusBadge}</div>
      <div><strong>Ausfälle:</strong> <strong>${node.missing_count}</strong> / 3 (Tit-for-Tat; heilt -1/h)</div>
      <div><strong>RTT:</strong> ${rttText} &bull; <strong>Letzter Fehler:</strong> ${failText}</div>
    </div>
    <div class="inspect-box" style="margin-bottom:0;">
      <h4 style="margin:0 0 0.4rem 0;font-size:0.85rem;color:var(--blue);">📡 Topologie &amp; Routing</h4>
      <div><strong>Distanz:</strong> ${node.min_hops} Hops &bull; <strong>Pfad:</strong> ${ingressText} &bull; <strong>Inkubation:</strong> ${incubText}</div>
    </div></div>`;
  setHtml('node-modal-details', html);
  $('node-modal').classList.add('active');
}
function copyNodePubkey() {
  const el = $('node-modal-pubkey');
  if (el) navigator.clipboard.writeText(el.innerText).then(() => showToast('NodePubKey in Zwischenablage kopiert', 'success')).catch(() => {});
}
function filterNodesTable() {
  const term = $('node-search-input')?.value.trim().toLowerCase();
  const nodesTbody = $('nodes-tbody');
  if (!currentDashboardData?.network_nodes || !nodesTbody) return;
  let html = '';
  for (const n of currentDashboardData.network_nodes) {
    if (term) {
      const m = n.public_key.toLowerCase().includes(term) || n.address.toLowerCase().includes(term) || n.connection_status.toLowerCase().includes(term) || n.hrw_routing_id.toLowerCase().includes(term);
      if (!m) continue;
    }
    html += renderNodeRow(n);
  }
  nodesTbody.innerHTML = html || '<tr><td colspan="9" class="empty-cell">Keine Knoten gefunden</td></tr>';
}
async function openLockInspector(lookupTag) {
  try {
    const res = await fetchWithTimeout('/dashboard/lock/' + encodeURIComponent(lookupTag), {}, 6000);
    if (!res.ok) return;
    const json = await res.json();
    setText('modal-title', '🔒 Sperr-Rohdaten: ' + truncateHash(lookupTag));
    setHtml('modal-details', `<strong>Lookup Tag:</strong> <span class="code">${lookupTag}</span>`);
    setText('modal-json', JSON.stringify(json, null, 2));
    $('json-modal').classList.add('active');
  } catch (e) {}
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
      setText('voucher-modal-title', '🎟️ Gutschein-Lineage: ' + detail.voucher_id);
      const html = `<div style="margin-bottom:0.6rem;line-height:1.5;">
        <div><strong>Gutschein-ID:</strong> <span class="code">${detail.voucher_id}</span> &bull; <strong>Wurzel-Gültigkeit:</strong> ${detail.root_valid_until_formatted}</div>
        <div><strong>Genesis Tag:</strong> <span class="code">${detail.genesis_tag || 'N/A'}</span> &bull; <strong>Sperren in Kette:</strong> ${detail.locks.length} (${detail.total_byte_years} BY)</div></div>`;
      let tableHtml = '<h4 style="margin:0.5rem 0 0.2rem 0;font-size:0.85rem;">Ketten-Historie:</h4><div style="overflow-x:auto;"><table><thead><tr><th>Typ</th><th>Lookup Tag</th><th>Child Lock (t_id)</th><th>Sender PubKey</th></tr></thead><tbody>';
      for (const h of detail.locks) {
        const typeBadge = h.is_genesis ? badge('amber', 'GENESIS') : badge('blue', 'SPEND');
        tableHtml += `<tr><td>${typeBadge}</td><td>${cTrunc(h.lookup_tag)}</td><td class="code">${truncateHash(h.t_id_hex)}</td><td class="code">${truncateHash(h.sender_pub_hex)}</td></tr>`;
      }
      tableHtml += '</tbody></table></div>';
      setHtml('voucher-modal-details', html);
      setHtml('voucher-modal-table-container', tableHtml);
      setText('voucher-modal-json', JSON.stringify(detail, null, 2));
      $('voucher-modal').classList.add('active');
    } else {
      showToast(`Gutschein oder Lookup-Tag "${term}" nicht gefunden.`, 'warning');
    }
  } catch (e) {
    showToast('Fehler bei der Suche: ' + e.message, 'error');
  }
}
async function refreshDashboard() {
  try {
    const res = await fetchWithTimeout('/dashboard/data', {}, 6000);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const d = await res.json();
    currentDashboardData = d;
    lastSuccessfulFetchTime = new Date();
    if (consecutiveFailures >= 3) showToast('Verbindung zum Knoten wiederhergestellt', 'success');
    consecutiveFailures = 0;
    pollIntervalMs = 2000;
    const banner = $('conn-banner');
    if (banner) banner.style.display = 'none';
    const badgeEl = $('status-badge');
    if (badgeEl) {
      badgeEl.innerText = d.status_badge;
      badgeEl.className = 'badge ' + (d.status === 'ONLINE' ? 'badge-green' : (d.status === 'VILLAGE MODE' ? 'badge-amber' : 'badge-red'));
    }
    if (d.network_time_ms) {
      const dt = new Date(d.network_time_ms);
      const pad = n => String(n).padStart(2, '0');
      setText('hdr-net-time', `${pad(dt.getDate())}.${pad(dt.getMonth() + 1)}.${dt.getFullYear()}, ${pad(dt.getHours())}:${pad(dt.getMinutes())}:${pad(dt.getSeconds())}`);
    }
    const simBadge = $('hdr-sim-badge');
    if (simBadge) simBadge.style.display = d.is_simulation ? 'inline-block' : 'none';
    if (d.clock_drift_ms != null) {
      const driftEl = $('hdr-clock-drift');
      if (driftEl) {
        const sign = d.clock_drift_ms > 0 ? '+' : '';
        driftEl.innerText = `${sign}${d.clock_drift_ms} ms`;
        driftEl.style.color = Math.abs(d.clock_drift_ms) > 2000 ? 'var(--red)' : (Math.abs(d.clock_drift_ms) > 500 ? 'var(--amber)' : 'var(--text)');
      }
    }
    setText('hdr-lat-local', d.local_latency.avg_ms.toFixed(2) + ' ms');
    setText('hdr-lat-quorum', d.quorum_latency.avg_ms.toFixed(2) + ' ms');
    setText('hdr-lat-e2e', d.e2e_latency.avg_ms.toFixed(2) + ' ms');
    setText('hdr-peers', `${d.connected_peers}/${d.configured_peers}`);
    setText('hdr-shard', d.shard_mode);
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
    const sys = d.system;
    if (sys) {
      setText('sys-cpu-val', sys.cpu_percent.toFixed(1) + '%');
      const cpuBar = $('sys-cpu-bar');
      if (cpuBar) cpuBar.style.width = Math.min(100, Math.max(0, sys.cpu_percent)) + '%';
      setText('sys-rss-val', sys.rss_mb.toFixed(1) + ' MB');
      setText('sys-redb-val', Math.round(sys.redb_bytes / 1024) + ' KB');
      setText('sys-netto-val', sys.netto_locks_bytes + ' B');
      setText('sys-purged-val', sys.ttl_purged_count);
      setText('cap-single-val', sys.peak_tps_single_core);
      setText('cap-multi-val', sys.peak_tps_multi_core);
      setText('cap-storage-val', sys.max_storage_locks);
      setText('cap-byte-years-val', sys.byte_years_capacity);
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
    const friendsTbody = $('friends-tbody');
    if (friendsTbody) {
      if (d.f2f?.friends?.length > 0) {
        let html = '';
        for (const f of d.f2f.friends) {
          let sBadge = badge('green', 'Verbunden (0 Ausfälle)');
          if (!f.is_connected) sBadge = badge('amber', 'Getrennt');
          else if (f.missing_count >= 3) sBadge = badge('red', 'Suspended (3/3)');
          else if (f.missing_count > 0) sBadge = badge('amber', `Degrading (${f.missing_count}/3)`);
          const rttText = f.rtt_ms != null ? f.rtt_ms + ' ms' : '<span style="color:var(--text-muted);">-</span>';
          let actionBtn = `<button class="btn btn-secondary" style="padding:0.2rem 0.5rem;" onclick="openNodeInspector('${f.public_key}')">🔍 Info</button>`;
          if (adminToken) actionBtn += ` <button class="btn btn-danger" style="padding:0.2rem 0.5rem;margin-left:0.25rem;" onclick="adminRemoveFriend('${f.public_key}')">🗑️</button>`;
          html += `<tr><td>${cTrunc(f.public_key)}</td><td>${f.address}</td><td>${sBadge}</td><td>${rttText}</td><td>${actionBtn}</td></tr>`;
        }
        friendsTbody.innerHTML = html;
      } else {
        friendsTbody.innerHTML = '<tr><td colspan="5" class="empty-cell">Keine F2F Freunde konfiguriert</td></tr>';
      }
    }
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
            html += `<tr><td>${codeTag(a.account_tag, a.account_tag)}</td><td><strong style="color:var(--purple);">${a.balance_byte_years.toLocaleString()}</strong> Byte-Jahre</td></tr>`;
          }
          vipTbody.innerHTML = html;
        } else {
          vipTbody.innerHTML = '<tr><td colspan="2" class="empty-cell">Keine VIP Accounts hinterlegt</td></tr>';
        }
      }
    }
    const f2fClientsTbody = $('f2f-clients-tbody');
    if (f2fClientsTbody) {
      if (d.f2f_clients?.length > 0) {
        let html = '';
        for (const c of d.f2f_clients) {
          const whaleBadge = c.whale_brake_active ? badge('amber', 'Aktiv (5x)') : badge('green', 'Inaktiv');
          const lastActive = c.last_active_sec != null ? `vor ${c.last_active_sec}s` : '<span style="color:var(--text-muted);">-</span>';
          const tok = c.token || '';
          const qrBtn = `<button class="btn btn-secondary" style="padding:0.2rem 0.5rem;font-size:0.75rem;margin-right:0.35rem;" onclick="showClientQrModal('${escapeHtml(c.label)}', '${escapeHtml(tok)}', '${escapeHtml(c.token_hash)}')">QR-Code</button>`;
          const revokeBtn = `<button class="btn btn-danger admin-only" style="${adminToken ? 'display:inline-flex;' : 'display:none;'}padding:0.2rem 0.5rem;font-size:0.75rem;" onclick="adminRemoveClientFriend('${escapeHtml(c.token_hash)}', '${escapeHtml(c.label)}')">Widerrufen</button>`;
          html += `<tr><td><strong>${escapeHtml(c.label || 'Client')}</strong></td><td>${cTrunc(c.token_hash)}</td><td>${(c.writes_today || 0).toLocaleString()} / ${(c.daily_limit || 0).toLocaleString()}</td><td>${whaleBadge}</td><td>${lastActive}</td><td>${qrBtn}${revokeBtn}</td></tr>`;
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
          html += `<tr><td><strong>${v.voucher_id}</strong></td><td>${v.root_valid_until_formatted}</td><td class="code">${genShort}</td><td>${v.locks_count} Sperren</td><td>${sBadge}</td><td><button class="btn btn-secondary" onclick="openVoucherInspector('${v.voucher_id}')">🔍 Wurzel-Inspektor</button></td></tr>`;
        }
        vouchersTbody.innerHTML = html;
      } else {
        vouchersTbody.innerHTML = '<tr><td colspan="6" class="empty-cell">Keine aktiven Gutscheine im Speicher</td></tr>';
      }
    }
    const locksTbody = $('locks-tbody');
    if (locksTbody) {
      if (d.recent_locks?.length > 0) {
        let html = '';
        for (const l of d.recent_locks) {
          const b = l.status === 'Verified' ? badge('green', 'Verified') : (l.status === 'Provisional' ? badge('amber', 'Provisional') : badge('red', 'Conflict'));
          const pShort = truncateHash(l.parent_lock_hex);
          const cShort = truncateHash(l.child_lock_hex);
          let tierBadge = badge('cyan', 'P2P Sync');
          if (l.tier === 'VIP') tierBadge = badge('purple', `VIP (${l.byte_years || 0} BY)`);
          else if (l.tier === 'F2F') tierBadge = badge('blue', `F2F (${l.byte_years || 0} BY)`);
          else if (l.tier === 'Free') tierBadge = badge('green', 'Free (PoW)');
          else if (l.tier) tierBadge = badge('cyan', l.tier);
          const vLink = l.voucher_id ? `<button class="btn btn-secondary" style="padding:0.15rem 0.4rem;font-size:0.75rem;" onclick="openVoucherInspector('${l.voucher_id}')">🎟️ ${truncateHash(l.voucher_id)}</button>` : '<span style="color:var(--text-muted);">-</span>';
          html += `<tr><td>${l.timestamp_ms}</td><td>${codeTag(pShort, l.parent_lock_hex)}</td><td>${codeTag(cShort, l.child_lock_hex)}</td><td>${tierBadge}</td><td>${vLink}</td><td>${b}</td><td><button class="btn btn-secondary" style="padding:0.2rem 0.5rem;" onclick="openLockInspector('${l.parent_lock_hex}')">📄 JSON</button></td></tr>`;
        }
        locksTbody.innerHTML = html;
      } else {
        locksTbody.innerHTML = '<tr><td colspan="7" class="empty-cell">Keine Sperren im Ringbuffer</td></tr>';
      }
    }
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
    if (pollTimer) clearTimeout(pollTimer);
    pollTimer = setTimeout(refreshDashboard, pollIntervalMs);
  }
}

// --- Tab 4: History & Security Event Log (Phase 2) ---
let currentHistoryWindow = '24h';
let cachedHistoryPoints = [];
let cachedAuditEvents = [];
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

  container.innerHTML = `
    <svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" style="width:100%;height:100%;display:block;">
      <!-- Grid lines -->
      <line x1="10" y1="${h-20}" x2="${w-10}" y2="${h-20}" stroke="var(--border)" stroke-width="1" />
      <line x1="10" y1="${(h-20)/2}" x2="${w-10}" y2="${(h-20)/2}" stroke="var(--border)" stroke-width="1" stroke-dasharray="3,3" />
      <!-- Reads line (Cyan) -->
      <polyline points="${readPts}" fill="none" stroke="var(--cyan)" stroke-width="2" stroke-dasharray="2,2" />
      <!-- VIP line (Purple) -->
      <polyline points="${vipPts}" fill="none" stroke="var(--purple)" stroke-width="2" />
      <!-- Friends line (Blue) -->
      <polyline points="${f2fPts}" fill="none" stroke="var(--blue)" stroke-width="2" />
      <!-- Free line (Green) -->
      <polyline points="${freePts}" fill="none" stroke="var(--green)" stroke-width="2" />
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

  const filtered = cachedAuditEvents.filter(ev => {
    if (severityFilter !== 'ALL' && ev.severity !== severityFilter) return false;
    if (search) {
      const matchMsg = ev.message && ev.message.toLowerCase().includes(search);
      const matchKind = ev.kind && String(ev.kind).toLowerCase().includes(search);
      if (!matchMsg && !matchKind) return false;
    }
    return true;
  });

  if (countSub) countSub.innerText = `${cachedAuditEvents.length} Ereignisse geloggt (Ringbuffer max 1000)`;

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

updateAdminUI();
refreshDashboard();
startPhase2Pollers();