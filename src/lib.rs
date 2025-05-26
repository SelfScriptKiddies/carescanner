pub mod configuration;
pub mod modes;
use crate::configuration::{Config, ScanType};
use crate::modes::{Target, Mode};
use std::sync::Arc;
use futures::stream::{self, StreamExt};
use governor::{Quota, RateLimiter};
use std::num::NonZeroU32;   
use crate::modes::fulltcp::TcpScan;
use tokio::sync::Mutex;
use crate::modes::PortStatus;

pub async fn run(config: Config) {
    let mode = match config.scan_type {
        ScanType::Tcp => modes::fulltcp::TcpScan::new(&config),
        _ => panic!("Unsupported scan type"),
    };

    // for port in config.ports {
    //     for target in config.targets.clone() {
    //         let results = mode.scan(&Target { ip: target, port: port }).await;
    //         println!("{:?}", results);
    //     }
    // }
    start_mass_scan(Arc::new(config), 1000, 1000).await;
}


pub async fn start_mass_scan(
    config: Arc<Config>,
    max_concurrent_scans: usize,
    scans_per_second: u32,
) {
    let hosts = config.targets.clone();
    let ports = config.ports.clone().vec();
    let targets: Vec<Target> = hosts
        .iter()
        .flat_map(|host_ip| {
            ports.iter().map(move |port_num| Target {
                ip: host_ip.clone(),
                port: *port_num,
            })
        })
        .collect();

    let scanner = Arc::new(TcpScan::new(&config));

    let rate_limiter_quota = NonZeroU32::new(scans_per_second).unwrap_or_else(|| NonZeroU32::new(1).unwrap());
    let limiter = Arc::new(RateLimiter::direct(Quota::per_second(rate_limiter_quota)));

    println!(
        "Starting scan for {} targets with {} concurrent scans and {} scans/sec limit.",
        targets.len(),
        max_concurrent_scans,
        scans_per_second
    );

    let results = Arc::new(Mutex::new(Vec::new())); // Simple way to collect results

    stream::iter(targets)
        .for_each_concurrent(max_concurrent_scans, |target_to_scan| {
            let scanner_clone = Arc::clone(&scanner);
            let limiter_clone = Arc::clone(&limiter);
            let results_clone = results.clone(); // Clone target for the async block

            async move {
                // Wait for the rate limiter
                limiter_clone.until_ready().await;

                let status = scanner_clone.scan(&target_to_scan).await;
                
                // Process the result
                // For a real application, you might send this to another task
                // via an mpsc channel for aggregation or immediate reporting.
                match status {
                    PortStatus::Open => println!("Host: {}, Port: {}, Status: {:?}", target_to_scan.ip, target_to_scan.port, status),
                    _ => (),
                }
                let mut results_guard = results_clone.lock().await;
                results_guard.push((target_to_scan, status));
            }
        })
        .await;

    // Note: The `results.push` above is not thread-safe if `results` is a shared Vec across true OS threads.
    // `for_each_concurrent` runs tasks on Tokio's executor, which might be multi-threaded.
    // For robust result collection, consider using `tokio::sync::mpsc` channel
    // to send results from each task to a single collector task, or a `Mutex<Vec<...>>`.

    println!("Scanning complete. Processed {} results.", results.lock().await.len());
    // Further process `results` here
}