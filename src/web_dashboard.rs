use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use log::{info, error};

use crate::appstate::AppStateManager;

const HTML_PAGE: &str = r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Carescanner Dashboard</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: monospace; background: #1a1a2e; color: #e0e0e0; margin: 0; padding: 2em; }
  h1 { color: #00d2ff; margin-top: 0; }
  .stats { display: flex; gap: 2em; margin: 1em 0; flex-wrap: wrap; }
  .stat-card { background: #16213e; padding: 1em 1.5em; border-radius: 8px; min-width: 140px; }
  .stat-card .value { font-size: 2em; font-weight: bold; }
  .stat-card .label { color: #888; font-size: 0.85em; margin-top: 4px; }
  .stat-card.open .value { color: #00ff88; }
  .stat-card.hosts .value { color: #00d2ff; }
  .stat-card.closed .value { color: #ff4444; }
  .stat-card.scanned .value { color: #ffaa00; }
  .stat-card.progress .value { color: #cc88ff; }
  .controls { margin: 1em 0; display: flex; gap: 1em; align-items: center; flex-wrap: wrap; }
  .controls label { color: #888; }
  .controls input, .controls select {
    background: #16213e; color: #e0e0e0; border: 1px solid #333;
    padding: 6px 10px; font-family: monospace; border-radius: 4px;
  }
  table { border-collapse: collapse; width: 100%; margin-top: 1em; }
  th, td { text-align: left; padding: 6px 12px; border-bottom: 1px solid #333; }
  th { color: #00d2ff; cursor: pointer; user-select: none; }
  th:hover { color: #fff; }
  .open { color: #00ff88; }
  .closed { color: #ff4444; }
  .banner { color: #cc88ff; max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .refresh-info { color: #555; font-size: 0.8em; }
  #no-results { color: #666; margin-top: 2em; }
</style>
</head>
<body>
<h1>Carescanner Dashboard</h1>

<div class="stats" id="stats"></div>

<div class="controls">
  <label>Filter:</label>
  <select id="state-filter">
    <option value="open">Open only</option>
    <option value="all">All</option>
    <option value="closed">Closed only</option>
  </select>
  <input type="text" id="search" placeholder="Search host/port/service...">
  <span class="refresh-info">Auto-refresh 3s</span>
</div>

<div id="results"></div>

<script>
let allData = null;
let sortCol = 'host';
let sortAsc = true;

async function fetchData() {
  try {
    const r = await fetch('/api/status');
    allData = await r.json();
    render();
  } catch(e) {
    document.getElementById('stats').textContent = 'Error: ' + e;
  }
}

function render() {
  if (!allData) return;
  const d = allData;

  // Stats
  document.getElementById('stats').innerHTML = `
    <div class="stat-card scanned"><div class="value">${d.scanned}</div><div class="label">Scanned</div></div>
    <div class="stat-card open"><div class="value">${d.open_count}</div><div class="label">Open Ports</div></div>
    <div class="stat-card closed"><div class="value">${d.closed_count}</div><div class="label">Closed Ports</div></div>
    <div class="stat-card hosts"><div class="value">${d.host_count}</div><div class="label">Hosts</div></div>
    <div class="stat-card progress"><div class="value">${d.progress_pct}%</div><div class="label">Progress</div></div>
  `;

  // Filter + search
  const stateFilter = document.getElementById('state-filter').value;
  const search = document.getElementById('search').value.toLowerCase();

  let rows = [];
  for (const [host, ports] of Object.entries(d.results)) {
    for (const p of ports) {
      if (stateFilter === 'open' && p.state !== 'open') continue;
      if (stateFilter === 'closed' && p.state !== 'closed') continue;
      const svc = p.banner || '';
      const portStr = p.number + '/' + p.protocol;
      if (search && !host.includes(search) && !portStr.includes(search) && !svc.toLowerCase().includes(search)) continue;
      rows.push({ host, port: p.number, portStr, state: p.state, svc });
    }
  }

  // Sort
  rows.sort((a, b) => {
    let va = a[sortCol], vb = b[sortCol];
    if (typeof va === 'string') { va = va.toLowerCase(); vb = vb.toLowerCase(); }
    if (va < vb) return sortAsc ? -1 : 1;
    if (va > vb) return sortAsc ? 1 : -1;
    return 0;
  });

  if (rows.length === 0) {
    document.getElementById('results').innerHTML = '<div id="no-results">No matching results</div>';
    return;
  }

  const arrow = col => sortCol === col ? (sortAsc ? ' ▲' : ' ▼') : '';
  let html = `<table><tr>
    <th onclick="setSort('host')">Host${arrow('host')}</th>
    <th onclick="setSort('port')">Port${arrow('port')}</th>
    <th onclick="setSort('state')">State${arrow('state')}</th>
    <th onclick="setSort('svc')">Service${arrow('svc')}</th>
  </tr>`;
  for (const r of rows) {
    const cls = r.state === 'open' ? 'open' : 'closed';
    html += `<tr><td>${r.host}</td><td>${r.portStr}</td><td class="${cls}">${r.state}</td><td class="banner">${r.svc}</td></tr>`;
  }
  html += '</table>';
  document.getElementById('results').innerHTML = html;
}

function setSort(col) {
  if (sortCol === col) { sortAsc = !sortAsc; } else { sortCol = col; sortAsc = true; }
  render();
}

document.getElementById('state-filter').addEventListener('change', render);
document.getElementById('search').addEventListener('input', render);

fetchData();
setInterval(fetchData, 3000);
</script>
</body>
</html>"#;

/// Start the web dashboard on the given port. Runs in the background.
pub fn spawn_dashboard(
    host: &str,
    port: u16,
    total_targets: u64,
    app_state_manager: Arc<AppStateManager>,
) {
    let addr = format!("{}:{}", host, port);
    tokio::spawn(async move {
        let listener = match TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                error!("Failed to start web dashboard on {}: {}", addr, e);
                return;
            }
        };
        info!("Web dashboard running at http://{}", addr);

        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => continue,
            };

            let asm = Arc::clone(&app_state_manager);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = match tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await {
                    Ok(n) => n,
                    Err(_) => return,
                };
                let request = String::from_utf8_lossy(&buf[..n]);

                let (status, content_type, body) = if request.starts_with("GET /api/status") {
                    let state = asm.get_current_state().await;
                    let results = state.get_results();
                    let open_count: usize = results.values()
                        .flat_map(|ports| ports.iter())
                        .filter(|p| p.state == crate::appstate::PortState::Open)
                        .count();
                    let closed_count: usize = results.values()
                        .flat_map(|ports| ports.iter())
                        .filter(|p| p.state == crate::appstate::PortState::Closed)
                        .count();
                    let scanned = open_count + closed_count;
                    let progress_pct = if total_targets > 0 {
                        format!("{:.1}", scanned as f64 / total_targets as f64 * 100.0)
                    } else {
                        "0.0".to_string()
                    };
                    let json = format!(
                        r#"{{"scanned":{},"open_count":{},"closed_count":{},"host_count":{},"progress_pct":{},"results":{}}}"#,
                        scanned,
                        open_count,
                        closed_count,
                        results.len(),
                        progress_pct,
                        serde_json::to_string(&results).unwrap_or_else(|_| "{}".to_string()),
                    );
                    ("200 OK", "application/json", json)
                } else if request.starts_with("GET /") {
                    ("200 OK", "text/html; charset=utf-8", HTML_PAGE.to_string())
                } else {
                    ("404 Not Found", "text/plain", "Not Found".to_string())
                };

                let response = format!(
                    "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n{}",
                    status,
                    content_type,
                    body.len(),
                    body,
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
}
