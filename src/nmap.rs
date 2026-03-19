use std::process::Command;
use log::info;

use crate::appstate::{AppState, PortState};

const MAX_PARALLEL_NMAP: usize = 4;

/// Run nmap on discovered open ports for service/script detection.
/// Spawns up to MAX_PARALLEL_NMAP processes concurrently.
pub fn run_on_results(state: &AppState, nmap_args: &[String], nmap_path: &str) {
    let results = state.get_results();

    // Collect hosts with open ports
    let tasks: Vec<(String, String)> = results
        .iter()
        .filter_map(|(host, ports)| {
            let open_ports: Vec<String> = ports
                .iter()
                .filter(|p| p.state == PortState::Open)
                .map(|p| p.number.to_string())
                .collect();
            if open_ports.is_empty() {
                None
            } else {
                Some((host.clone(), open_ports.join(",")))
            }
        })
        .collect();

    if tasks.is_empty() {
        return;
    }

    println!("\n--- Running nmap on {} hosts (up to {} parallel) ---\n", tasks.len(), MAX_PARALLEL_NMAP);

    // Process in chunks for parallel execution
    for chunk in tasks.chunks(MAX_PARALLEL_NMAP) {
        let mut children: Vec<(String, std::process::Child)> = Vec::new();

        // Spawn all in chunk
        for (host, port_arg) in chunk {
            println!("Starting: {} {} -p {} {}", nmap_path, nmap_args.join(" "), port_arg, host);

            match Command::new(nmap_path)
                .args(nmap_args)
                .arg("-p")
                .arg(port_arg)
                .arg(host)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
            {
                Ok(child) => children.push((host.clone(), child)),
                Err(e) => eprintln!("Failed to spawn '{}' for {}: {}", nmap_path, host, e),
            }
        }

        // Wait for all in chunk and print output
        for (host, child) in children {
            match child.wait_with_output() {
                Ok(output) => {
                    println!("\n--- nmap results for {} ---", host);
                    if !output.stdout.is_empty() {
                        print!("{}", String::from_utf8_lossy(&output.stdout));
                    }
                    if !output.stderr.is_empty() {
                        eprint!("{}", String::from_utf8_lossy(&output.stderr));
                    }
                    info!("nmap finished for {}", host);
                }
                Err(e) => eprintln!("nmap error for {}: {}", host, e),
            }
        }
    }
}
