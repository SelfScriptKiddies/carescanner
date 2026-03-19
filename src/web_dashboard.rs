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
  body { font-family: monospace; background: #1a1a2e; color: #e0e0e0; margin: 2em; }
  h1 { color: #0f3460; }
  h1 { color: #00d2ff; }
  table { border-collapse: collapse; width: 100%; margin-top: 1em; }
  th, td { text-align: left; padding: 6px 12px; border-bottom: 1px solid #333; }
  th { color: #00d2ff; }
  .open { color: #00ff88; }
  .closed { color: #ff4444; }
  #status { color: #888; margin-top: 1em; }
  .refresh-btn { background: #0f3460; color: #fff; border: none; padding: 8px 16px; cursor: pointer; margin-top: 1em; }
</style>
</head>
<body>
<h1>Carescanner Dashboard</h1>
<div id="status">Loading...</div>
<div id="results"></div>
<script>
async function refresh() {
  try {
    const r = await fetch('/api/status');
    const data = await r.json();
    document.getElementById('status').innerHTML =
      `Scanned: <b>${data.scanned}</b> | Open: <b>${data.open_count}</b> | Hosts: <b>${data.host_count}</b>` +
      ` | <span style="color:#666">Auto-refresh 3s</span>`;
    let html = '<table><tr><th>Host</th><th>Port</th><th>State</th><th>Service</th></tr>';
    for (const [host, ports] of Object.entries(data.results)) {
      for (const p of ports) {
        const cls = p.state === 'open' ? 'open' : 'closed';
        html += `<tr><td>${host}</td><td>${p.number}/${p.protocol}</td>` +
                `<td class="${cls}">${p.state}</td><td>${p.banner || ''}</td></tr>`;
      }
    }
    html += '</table>';
    document.getElementById('results').innerHTML = html;
  } catch(e) {
    document.getElementById('status').textContent = 'Error: ' + e;
  }
}
refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>"#;

/// Start the web dashboard on the given port. Runs in the background.
pub fn spawn_dashboard(
    host: &str,
    port: u16,
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
                    let json = format!(
                        r#"{{"scanned":{},"open_count":{},"host_count":{},"results":{}}}"#,
                        results.values().flat_map(|p| p.iter()).count(),
                        open_count,
                        results.len(),
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
