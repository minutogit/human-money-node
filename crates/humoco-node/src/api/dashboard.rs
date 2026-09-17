use std::net::SocketAddr;
use std::time::Duration;

use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use crate::api::qr::generate_qr_svg;
use crate::api::routes::AppState;
use crate::storage::recent::{RecentLockStatus, RecentLockSummary};

#[derive(Debug, Serialize)]
pub struct RecentLockDto {
    pub parent_lock_hex: String,
    pub child_lock_hex: String,
    pub timestamp_ms: u64,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct DashboardData {
    pub status: String,
    pub status_badge: String,
    pub node_id: String,
    pub public_key: String,
    pub peering_string: String,
    pub uptime_seconds: u64,
    pub uptime_formatted: String,
    pub active_locks: usize,
    pub flush_queue_depth: usize,
    pub connected_peers: usize,
    pub configured_peers: usize,
    pub active_nodes_count: usize,
    pub pos_latency_count: u64,
    pub pos_latency_avg_ms: f64,
    pub pos_sla_compliant: bool,
    pub broom_patterns_detected: usize,
    pub recent_locks: Vec<RecentLockDto>,
}

/// Computes the node's peering string `<pubkey>@<ip>:9090`
pub fn determine_peering_string(state: &AppState) -> String {
    let pubkey = state.identity.public_key_hex();
    let addr = if let Some(ref t) = state.transport {
        t.local_addr().ok().map(|a| {
            if a.ip().is_unspecified() {
                SocketAddr::new("127.0.0.1".parse().unwrap(), a.port())
            } else {
                a
            }
        })
    } else {
        None
    };
    let addr_str = addr
        .map(|a| a.to_string())
        .unwrap_or_else(|| "127.0.0.1:9090".to_string());
    format!("{}@{}", pubkey, addr_str)
}

fn format_uptime(duration: Duration) -> String {
    let total_secs = duration.as_secs();
    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let mins = (total_secs % 3600) / 60;
    let secs = total_secs % 60;
    if days > 0 {
        format!("{}d {}h {}m {}s", days, hours, mins, secs)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, mins, secs)
    } else {
        format!("{}m {}s", mins, secs)
    }
}

pub async fn collect_dashboard_data(state: &AppState) -> DashboardData {
    let uptime = state.start_time.elapsed();
    let uptime_formatted = format_uptime(uptime);
    let peering_string = determine_peering_string(state);

    let (connected_peers, configured_peers, active_nodes_count, broom_patterns_detected) =
        if let Some(ref pm) = state.peer_manager {
            let conn = pm.connected_peer_count().await;
            let conf = pm.all_peer_addrs().await.len();
            let act = pm.active_known_nodes().await.len();
            
            let diversity_data = pm.get_ingress_diversity_data().await;
            let mut ingress_counts: std::collections::HashMap<SocketAddr, (usize, u32)> = std::collections::HashMap::new();
            for (best_ingress_peer, ingress_diversity_mask) in diversity_data {
                if let Some(peer) = best_ingress_peer {
                    let entry = ingress_counts.entry(peer).or_insert((0, ingress_diversity_mask));
                    entry.0 += 1;
                    entry.1 |= ingress_diversity_mask;
                }
            }
            let mut brooms = 0;
            for (_, (count, mask)) in ingress_counts {
                if count >= 10 && mask.count_ones() <= 1 {
                    brooms += 1;
                }
            }

            (conn, conf, act, brooms)
        } else {
            (0, 0, 0, 0)
        };

    let (status, status_badge) = if state.peer_manager.is_none() || configured_peers == 0 {
        ("VILLAGE MODE".to_string(), "VILLAGE MODE (N=1)".to_string())
    } else if connected_peers > 0 {
        ("ONLINE".to_string(), "ONLINE".to_string())
    } else {
        ("DEGRADED".to_string(), "DEGRADED (0 Peers)".to_string())
    };

    let active_locks =
        state.engine.ram.read().await.len() + state.engine.hmc_ram.read().await.locks.len();
    let flush_queue_depth = state.engine.flush_sender_len();

    let pos_latency_count = state.metrics.pos_latency_count();
    let pos_latency_avg_ms = state.metrics.pos_latency_avg_ms();
    let pos_sla_compliant = pos_latency_count == 0 || pos_latency_avg_ms < 5.0;

    let recent_raw = state.engine.get_recent_locks(10);
    let recent_locks: Vec<RecentLockDto> = recent_raw
        .into_iter()
        .map(|r: RecentLockSummary| {
            let status_str = match r.status {
                RecentLockStatus::Verified => "Verified".to_string(),
                RecentLockStatus::Provisional => "Provisional".to_string(),
                RecentLockStatus::Conflict => "Conflict".to_string(),
            };
            RecentLockDto {
                parent_lock_hex: r.parent_lock_hex,
                child_lock_hex: r.child_lock_hex,
                timestamp_ms: r.timestamp_ms,
                status: status_str,
            }
        })
        .collect();

    DashboardData {
        status,
        status_badge,
        node_id: state.identity.node_id_hex(),
        public_key: state.identity.public_key_hex(),
        peering_string,
        uptime_seconds: uptime.as_secs(),
        uptime_formatted,
        active_locks,
        flush_queue_depth,
        connected_peers,
        configured_peers,
        active_nodes_count,
        pos_latency_count,
        pos_latency_avg_ms,
        pos_sla_compliant,
        broom_patterns_detected,
        recent_locks,
    }
}

/// Handler for GET /dashboard/data
pub async fn dashboard_data(State(state): State<AppState>) -> (StatusCode, Json<DashboardData>) {
    let data = collect_dashboard_data(&state).await;
    (StatusCode::OK, Json(data))
}

fn truncate_hash(hex: &str) -> String {
    if hex.len() <= 16 {
        hex.to_string()
    } else {
        format!("{}…{}", &hex[..8], &hex[hex.len() - 8..])
    }
}

/// Handler for GET /dashboard rendering pure standalone HTML5.
pub async fn render_dashboard(State(state): State<AppState>) -> Response {
    let data = collect_dashboard_data(&state).await;
    let qr_svg = generate_qr_svg(&data.peering_string);

    let status_class = match data.status.as_str() {
        "ONLINE" => "badge-green",
        "VILLAGE MODE" => "badge-amber",
        _ => "badge-red",
    };

    let sla_badge_html = if data.pos_sla_compliant {
        r#"<span class="badge badge-green">🟢 &lt; 5ms SLA Met</span>"#
    } else {
        r#"<span class="badge badge-red">🔴 &gt; 5ms SLA Warning</span>"#
    };

    let mut table_rows = String::new();
    if data.recent_locks.is_empty() {
        table_rows.push_str(r#"<tr><td colspan="4" class="empty-cell">No locks present in ring buffer</td></tr>\"#);
    } else {
        for lock in &data.recent_locks {
            let status_badge = match lock.status.as_str() {
                "Verified" => r#"<span class="badge badge-green">Verified</span>"#,
                "Provisional" => r#"<span class="badge badge-amber">Provisional</span>"#,
                _ => r#"<span class="badge badge-red">Conflict</span>"#,
            };
            let parent_short = truncate_hash(&lock.parent_lock_hex);
            let child_short = truncate_hash(&lock.child_lock_hex);
            table_rows.push_str(&format!(
                r#"<tr><td>{}</td><td class="code" title="{}">{}</td><td class="code" title="{}">{}</td><td>{}</td></tr>"#,
                lock.timestamp_ms, lock.parent_lock_hex, parent_short, lock.child_lock_hex, child_short, status_badge
            ));
        }
    }

    let broom_html = if data.broom_patterns_detected > 0 {
        format!(r#"<div class="card-sub" id="broom-patterns-sub" style="color: var(--red); font-weight: bold; margin-top: 0.25rem;">⚠️ {} Tunnel/Broom-Muster erkannt</div>"#, data.broom_patterns_detected)
    } else {
        r#"<div class="card-sub" id="broom-patterns-sub" style="color: var(--green); margin-top: 0.25rem;">✅ Topologie gesund (Kein Tunneling)</div>"#.to_string()
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HuMoCo Layer-2 Node Dashboard</title>
<style>
:root {{
  --bg: #0b0f19;
  --surface: #111827;
  --surface-alt: #1f2937;
  --border: #374151;
  --text: #f3f4f6;
  --text-muted: #9ca3af;
  --green: #10b981;
  --green-bg: rgba(16,185,129,0.15);
  --amber: #f59e0b;
  --amber-bg: rgba(245,158,11,0.15);
  --red: #ef4444;
  --red-bg: rgba(239,68,68,0.15);
  --blue: #3b82f6;
  --blue-bg: rgba(59,130,246,0.15);
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  background: var(--bg);
  color: var(--text);
  font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  line-height: 1.5;
  padding: 1.5rem;
}}
.container {{ max-width: 1200px; margin: 0 auto; }}
header {{
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: center;
  padding-bottom: 1.5rem;
  margin-bottom: 1.5rem;
  border-bottom: 1px solid var(--border);
}}
.header-title {{ display: flex; align-items: center; gap: 0.75rem; }}
.header-title h1 {{ font-size: 1.5rem; font-weight: 700; letter-spacing: -0.025em; }}
.header-meta {{ display: flex; align-items: center; gap: 1rem; }}
.badge {{
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  padding: 0.25rem 0.75rem;
  border-radius: 9999px;
  font-size: 0.8125rem;
  font-weight: 600;
  white-space: nowrap;
}}
.badge-green {{ background: var(--green-bg); color: var(--green); border: 1px solid rgba(16,185,129,0.3); }}
.badge-amber {{ background: var(--amber-bg); color: var(--amber); border: 1px solid rgba(245,158,11,0.3); }}
.badge-red {{ background: var(--red-bg); color: var(--red); border: 1px solid rgba(239,68,68,0.3); }}
.badge-blue {{ background: var(--blue-bg); color: var(--blue); border: 1px solid rgba(59,130,246,0.3); }}
.grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(270px, 1fr));
  gap: 1.25rem;
  margin-bottom: 1.5rem;
}}
.card {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 0.75rem;
  padding: 1.25rem;
  display: flex;
  flex-direction: column;
}}
.card-header {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.75rem;
  color: var(--text-muted);
  font-size: 0.875rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}}
.card-value {{
  font-size: 1.75rem;
  font-weight: 700;
  color: var(--text);
  margin-bottom: 0.35rem;
}}
.card-sub {{ font-size: 0.8125rem; color: var(--text-muted); }}
.identity-card {{
  grid-column: 1 / -1;
  display: grid;
  grid-template-columns: 140px 1fr;
  gap: 1.5rem;
  align-items: center;
}}
@media (max-width: 640px) {{
  .identity-card {{ grid-template-columns: 1fr; }}
}}
.qr-box {{
  width: 140px;
  height: 140px;
  background: #ffffff;
  border-radius: 0.5rem;
  padding: 0.35rem;
  display: flex;
  align-items: center;
  justify-content: center;
}}
.qr-svg {{ width: 100%; height: 100%; display: block; }}
.code {{
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 0.8125rem;
  background: var(--surface-alt);
  padding: 0.4rem 0.6rem;
  border-radius: 0.375rem;
  border: 1px solid var(--border);
  word-break: break-all;
}}
.peering-row {{
  display: flex;
  gap: 0.5rem;
  align-items: center;
  margin-top: 0.5rem;
}}
.copy-btn {{
  background: var(--blue);
  color: #ffffff;
  border: none;
  border-radius: 0.375rem;
  padding: 0.4rem 0.75rem;
  font-size: 0.8125rem;
  font-weight: 600;
  cursor: pointer;
  transition: opacity 0.2s;
  white-space: nowrap;
}}
.copy-btn:hover {{ opacity: 0.9; }}
.table-card {{ grid-column: 1 / -1; }}
table {{
  width: 100%;
  border-collapse: collapse;
  margin-top: 0.5rem;
  font-size: 0.875rem;
}}
th {{
  text-align: left;
  padding: 0.75rem;
  color: var(--text-muted);
  border-bottom: 1px solid var(--border);
  font-weight: 600;
}}
td {{
  padding: 0.75rem;
  border-bottom: 1px solid var(--border);
  color: var(--text);
}}
.empty-cell {{ text-align: center; color: var(--text-muted); padding: 2rem 0; }}
footer {{
  margin-top: 2rem;
  text-align: center;
  font-size: 0.75rem;
  color: var(--text-muted);
}}
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="header-title">
      <h1>HuMoCo Layer-2 Node</h1>
      <span id="status-badge" class="badge {status_class}">{status_badge}</span>
    </div>
    <div class="header-meta">
      <span class="card-sub">Uptime: <strong id="uptime-text">{uptime}</strong></span>
      <span class="badge badge-blue">v{version}</span>
    </div>
  </header>

  <div class="grid">
    <div class="card">
      <div class="card-header">
        <span>⚡ PoS-Latenz &amp; SLA</span>
        <span id="sla-badge">{sla_badge}</span>
      </div>
      <div class="card-value" id="pos-latency-val">{avg_lat:.2} ms</div>
      <div class="card-sub" id="pos-latency-sub">Verifizierte Sperren: {pos_count} (SLA Ziel &lt; 5ms)</div>
    </div>

    <div class="card">
      <div class="card-header">
        <span>🛡️ Peering &amp; Mesh</span>
        <span class="badge badge-blue">{mesh_mode}</span>
      </div>
      <div class="card-value" id="peers-val">{connected_peers} <span style="font-size: 1rem; font-weight: normal; color: var(--text-muted);">/ {configured_peers} Peers</span></div>
      <div class="card-sub" id="active-nodes-sub">Aktive Netzwerkknoten (F2F): {active_nodes}</div>
      {broom_html}
    </div>

    <div class="card">
      <div class="card-header">
        <span>📊 Storage &amp; Locks</span>
        <span class="badge badge-green">redb ACID</span>
      </div>
      <div class="card-value" id="locks-val">{active_locks}</div>
      <div class="card-sub" id="flush-depth-sub">Flush-Queue Tiefe: {flush_depth} / 10000</div>
    </div>
  </div>

  <div class="card identity-card">
    <div class="qr-box">
      {qr_svg}
    </div>
    <div>
      <div class=\"card-header\"><span>📱 Node Identity & Peering String</span></div>
      <div style="font-size: 0.8125rem; color: var(--text-muted); margin-bottom: 0.25rem;">NodeId: <span class="code" id="node-id-text">{node_id}</span></div>
      <div class="peering-row">
        <span class="code" id="peering-text" style="flex: 1;">{peering_str}</span>
        <button class="copy-btn" id="copy-btn" onclick="copyPeering()">Copy</button>
      </div>
    </div>
  </div>

  <div class="card table-card" style="margin-top: 1.25rem;">
    <div class="card-header">
      <span>⏱️ Recent Locks Ring Buffer (Last 10 Locks)</span>
      <span class="card-sub">&lt; 1µs Zero-Contention Ringbuffer</span>
    </div>
    <div style="overflow-x: auto;">
      <table>
        <thead>
          <tr>
            <th>Timestamp (ms)</th>
            <th>Parent Lock</th>
            <th>Child Lock / t_id</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody id="locks-tbody">
          {table_rows}
        </tbody>
      </table>
    </div>
  </div>

  <footer>
    HuMoCo Layer-2 Daemon &bull; Offline Air-Gap Dashboard &bull; Auto-Refresh 5s
  </footer>
</div>

<script>
function copyPeering() {{
  const text = document.getElementById('peering-text').innerText;
  navigator.clipboard.writeText(text).then(() => {{
    const btn = document.getElementById('copy-btn');
    const orig = btn.innerText;
    btn.innerText = 'Kopiert!';
    setTimeout(() => {{ btn.innerText = orig; }}, 1500);
  }}).catch(() => {{}});
}}

async function refreshDashboard() {{
  try {{
    const res = await fetch('/dashboard/data');
    if (!res.ok) return;
    const d = await res.json();
    
    // Status
    const badge = document.getElementById('status-badge');
    badge.innerText = d.status_badge;
    badge.className = 'badge ' + (d.status === 'ONLINE' ? 'badge-green' : (d.status === 'VILLAGE MODE' ? 'badge-amber' : 'badge-red'));

    // Uptime
    document.getElementById('uptime-text').innerText = d.uptime_formatted;

    // PoS Latency
    document.getElementById('pos-latency-val').innerText = d.pos_latency_avg_ms.toFixed(2) + ' ms';
    document.getElementById('pos-latency-sub').innerText = 'Verifizierte Sperren: ' + d.pos_latency_count + ' (SLA Ziel < 5ms)';
    const slaBadge = document.getElementById('sla-badge');
    if (d.pos_sla_compliant) {{
      slaBadge.innerHTML = '<span class="badge badge-green">🟢 &lt; 5ms SLA Eingehalten</span>';
    }} else {{
      slaBadge.innerHTML = '<span class="badge badge-red">🔴 &gt; 5ms SLA Warnung</span>';
    }}

    // Peers
    document.getElementById('peers-val').innerHTML = d.connected_peers + ' <span style="font-size: 1rem; font-weight: normal; color: var(--text-muted);">/ ' + d.configured_peers + ' Peers</span>';
    document.getElementById('active-nodes-sub').innerText = 'Aktive Netzwerkknoten (F2F): ' + d.active_nodes_count;
    const broomSub = document.getElementById('broom-patterns-sub');
    if (d.broom_patterns_detected > 0) {{
      broomSub.innerHTML = '⚠️ ' + d.broom_patterns_detected + ' Tunnel/Broom-Muster erkannt';
      broomSub.style.color = 'var(--red)';
      broomSub.style.fontWeight = 'bold';
    }} else {{
      broomSub.innerHTML = '✅ Topologie gesund (Kein Tunneling)';
      broomSub.style.color = 'var(--green)';
      broomSub.style.fontWeight = 'normal';
    }}

    // Storage
    document.getElementById('locks-val').innerText = d.active_locks;
    document.getElementById('flush-depth-sub').innerText = 'Flush-Queue Tiefe: ' + d.flush_queue_depth + ' / 10000';

    // Table
    const tbody = document.getElementById('locks-tbody');
    if (d.recent_locks && d.recent_locks.length > 0) {{
      let html = '';
      for (const l of d.recent_locks) {{
        const b = l.status === 'Verified' ? '<span class="badge badge-green">Verified</span>' : (l.status === 'Provisional' ? '<span class="badge badge-amber">Provisional</span>' : '<span class="badge badge-red">Conflict</span>');
        const pShort = l.parent_lock_hex.length > 16 ? l.parent_lock_hex.slice(0, 8) + '…' + l.parent_lock_hex.slice(-8) : l.parent_lock_hex;
        const cShort = l.child_lock_hex.length > 16 ? l.child_lock_hex.slice(0, 8) + '…' + l.child_lock_hex.slice(-8) : l.child_lock_hex;
        html += '<tr><td>' + l.timestamp_ms + '</td><td class="code" title="' + l.parent_lock_hex + '">' + pShort + '</td><td class="code" title="' + l.child_lock_hex + '">' + cShort + '</td><td>' + b + '</td></tr>';
      }}
      tbody.innerHTML = html;
    }}
  }} catch (e) {{
    // Graceful fallback
  }}
}}

setInterval(refreshDashboard, 5000);
</script>
</body>
</html>"#,
        status_class = status_class,
        status_badge = data.status_badge,
        uptime = data.uptime_formatted,
        version = env!("CARGO_PKG_VERSION"),
        sla_badge = sla_badge_html,
        avg_lat = data.pos_latency_avg_ms,
        pos_count = data.pos_latency_count,
        mesh_mode = if data.configured_peers == 0 { "Village" } else { "Cluster" },
        connected_peers = data.connected_peers,
        configured_peers = data.configured_peers,
        active_nodes = data.active_nodes_count,
        broom_html = broom_html,
        active_locks = data.active_locks,
        flush_depth = data.flush_queue_depth,
        qr_svg = qr_svg,
        node_id = data.node_id,
        peering_str = data.peering_string,
        table_rows = table_rows
    );

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response()
}
