use std::collections::HashMap;
use std::sync::Arc;
use std::io::Write;
use tokio::sync::Mutex;
use tokio::sync::mpsc::UnboundedSender;
use crate::modes::{Target, ScanResult};
use crate::configuration::{Config, FormatScan};
use tokio::task::JoinHandle;
use log::{info, error};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    pub number: u16,
    pub protocol: String,
    pub state: PortState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AppState {
    results: HashMap<String, Vec<Port>>,
    port_scanned: u64,
    start_time: std::time::SystemTime,
    args: String,
}

/// Manager for the app state (mpsc channel)
pub struct AppStateManager {
    app_state: Arc<Mutex<AppState>>,
    results_sender: UnboundedSender<(Target, ScanResult, String)>,
    _processor_handle: JoinHandle<()>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            results: HashMap::new(),
            port_scanned: 0,
            start_time: std::time::SystemTime::now(),
            args: std::env::args().collect::<Vec<_>>().join(" "),
        }
    }

    /// Add result to the state (only called from the manager task)
    pub fn add_result(&mut self, target: Target, result: ScanResult, protocol: String) {
        use crate::modes::PortStatus;
        self.port_scanned += 1;

        let state = match result.status {
            PortStatus::Open => PortState::Open,
            PortStatus::Closed => PortState::Closed,
            PortStatus::Filtered => return,
        };

        let port = Port {
            number: target.port,
            protocol,
            state,
            banner: result.banner,
        };

        self.results.entry(target.ip).or_default().push(port);
    }

    pub fn get_results(&self) -> &HashMap<String, Vec<Port>> {
        &self.results
    }

    /// Print a summary table to stdout with ANSI colors.
    pub fn print_summary(&self, show_closed: bool) {
        const BOLD: &str = "\x1b[1m";
        const GREEN: &str = "\x1b[32m";
        const RED: &str = "\x1b[31m";
        const CYAN: &str = "\x1b[36m";
        const RESET: &str = "\x1b[0m";

        let mut has_results = false;

        let mut hosts: Vec<&String> = self.results.keys().collect();
        hosts.sort();

        for host in hosts {
            let ports = &self.results[host];
            let open: Vec<&Port> = ports.iter().filter(|p| p.state == PortState::Open).collect();
            let closed: Vec<&Port> = ports.iter().filter(|p| p.state == PortState::Closed).collect();

            if open.is_empty() && (!show_closed || closed.is_empty()) {
                continue;
            }

            has_results = true;
            println!("\n{BOLD}{}{RESET}", host);
            println!("{:<10} {:<8} {}", "PORT", "STATE", "SERVICE");

            for port in &open {
                let svc = port.banner.as_deref().unwrap_or("");
                println!("{:<10} {GREEN}{:<8}{RESET} {CYAN}{}{RESET}",
                    format!("{}/{}", port.number, port.protocol), "open", svc);
            }
            if show_closed {
                for port in &closed {
                    println!("{:<10} {RED}{:<8}{RESET}",
                        format!("{}/{}", port.number, port.protocol), "closed");
                }
            }
        }

        if !has_results {
            println!("\nNo open ports found.");
        }
        println!();
    }

    /// Get the list of hosts that have any results (used for resume).
    pub fn hosts_with_results(&self) -> Vec<String> {
        self.results.keys().cloned().collect()
    }

    /// Save resume file: one completed host IP per line (plain text).
    pub fn save_resume_file(&self, path: &str) -> Result<(), String> {
        let hosts = self.hosts_with_results();
        let content = hosts.join("\n");
        let mut file = std::fs::File::create(path)
            .map_err(|e| format!("Failed to create resume file '{}': {}", path, e))?;
        file.write_all(content.as_bytes())
            .map_err(|e| format!("Failed to write resume file: {}", e))?;
        info!("Resume state saved to {} ({} hosts)", path, hosts.len());
        Ok(())
    }

    /// Load resume file: returns list of host IPs to skip.
    pub fn load_resume_file(path: &str) -> Result<Vec<String>, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read resume file '{}': {}", path, e))?;
        let hosts: Vec<String> = content
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        Ok(hosts)
    }

    /// Save current results to file based on config format
    pub fn save_to_file(&self, config: &Config) -> Result<String, String> {
        match config.format {
            FormatScan::Json => {
                let path = config.output.clone().unwrap_or_else(|| "carescanner_results.json".to_string());
                self.write_file(&path, &self.format_json())?;
                Ok(path)
            }
            FormatScan::Text => {
                let path = config.output.clone().unwrap_or_else(|| "carescanner_results.txt".to_string());
                self.write_file(&path, &self.format_text(config.show_closed_ports))?;
                Ok(path)
            }
            FormatScan::NmapXml => {
                let path = config.output.clone().unwrap_or_else(|| "carescanner_results.xml".to_string());
                self.write_file(&path, &self.format_nmap_xml())?;
                Ok(path)
            }
            FormatScan::All => {
                let base = config.output.clone().unwrap_or_else(|| "carescanner_results".to_string());
                let base = base
                    .trim_end_matches(".json")
                    .trim_end_matches(".txt")
                    .trim_end_matches(".xml");

                self.write_file(&format!("{}.json", base), &self.format_json())?;
                self.write_file(&format!("{}.txt", base), &self.format_text(config.show_closed_ports))?;
                self.write_file(&format!("{}.xml", base), &self.format_nmap_xml())?;

                Ok(format!("{}.json, {}.txt, {}.xml", base, base, base))
            }
        }
    }

    fn write_file(&self, path: &str, content: &str) -> Result<(), String> {
        let mut file = std::fs::File::create(path)
            .map_err(|e| format!("Failed to create file '{}': {}", path, e))?;
        file.write_all(content.as_bytes())
            .map_err(|e| format!("Failed to write to '{}': {}", path, e))?;
        info!("Results saved to {}", path);
        Ok(())
    }

    fn format_text(&self, show_closed: bool) -> String {
        let mut output = String::new();
        for (host, ports) in &self.results {
            output.push_str(&format!("Host: {}\n", host));
            for port in ports {
                match port.state {
                    PortState::Open => {
                        if let Some(banner) = &port.banner {
                            output.push_str(&format!("  {}/{}  open  {}\n", port.number, port.protocol, banner));
                        } else {
                            output.push_str(&format!("  {}/{}  open\n", port.number, port.protocol));
                        }
                    }
                    PortState::Closed if show_closed => {
                        output.push_str(&format!("  {}/{}  closed\n", port.number, port.protocol));
                    }
                    _ => {}
                }
            }
            output.push('\n');
        }
        output
    }

    fn format_json(&self) -> String {
        serde_json::to_string_pretty(&self.results).unwrap_or_else(|e| {
            error!("Failed to serialize results to JSON: {}", e);
            "{}".to_string()
        })
    }

    fn format_nmap_xml(&self) -> String {
        let version = env!("CARGO_PKG_VERSION");
        let start_ts = self.start_time
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let elapsed = now_ts.saturating_sub(start_ts);

        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str(&format!(
            "<nmaprun scanner=\"carescanner\" args=\"{}\" start=\"{}\" version=\"{}\">\n",
            xml_escape(&self.args),
            start_ts,
            version,
        ));

        let mut hosts_up = 0u64;
        for (host, ports) in &self.results {
            if ports.iter().any(|p| p.state == PortState::Open) {
                hosts_up += 1;
            }

            xml.push_str("  <host>\n");
            let addrtype = if host.contains(':') { "ipv6" } else { "ipv4" };
            xml.push_str(&format!(
                "    <address addr=\"{}\" addrtype=\"{}\"/>\n",
                xml_escape(host),
                addrtype,
            ));
            xml.push_str("    <ports>\n");

            for port in ports {
                let state_str = match port.state {
                    PortState::Open => "open",
                    PortState::Closed => "closed",
                };
                xml.push_str(&format!(
                    "      <port protocol=\"{}\" portid=\"{}\">\n        <state state=\"{}\"/>\n      </port>\n",
                    xml_escape(&port.protocol),
                    port.number,
                    state_str,
                ));
            }

            xml.push_str("    </ports>\n");
            xml.push_str("  </host>\n");
        }

        xml.push_str("  <runstats>\n");
        xml.push_str(&format!(
            "    <finished time=\"{}\" elapsed=\"{}\"/>\n",
            now_ts, elapsed,
        ));
        xml.push_str(&format!(
            "    <hosts up=\"{}\" total=\"{}\"/>\n",
            hosts_up,
            self.results.len(),
        ));
        xml.push_str("  </runstats>\n");
        xml.push_str("</nmaprun>\n");

        xml
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

impl AppStateManager {
    pub fn new() -> Self {
        Self::with_state(AppState::new())
    }

    /// Create a manager pre-loaded with state from a previous scan.
    pub fn with_state(initial_state: AppState) -> Self {
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        let app_state = Arc::new(Mutex::new(initial_state));
        let app_state_clone = Arc::clone(&app_state);

        let processor_handle = tokio::spawn(async move {
            while let Some((target, scan_result, protocol)) = receiver.recv().await {
                let mut state = app_state_clone.lock().await;
                state.add_result(target, scan_result, protocol);
            }
        });

        Self {
            app_state,
            results_sender: sender,
            _processor_handle: processor_handle,
        }
    }

    pub fn get_results_sender(&self) -> UnboundedSender<(Target, ScanResult, String)> {
        self.results_sender.clone()
    }

    pub async fn get_current_state(&self) -> AppState {
        self.app_state.lock().await.clone()
    }

    // Synchronous access for signal handler menu (requires multi-threaded tokio runtime)
    pub fn get_current_state_sync(&self) -> AppState {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.get_current_state())
        })
    }
}
