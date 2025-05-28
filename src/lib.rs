pub mod ui;
pub mod modes;
pub mod strategy;
pub mod configuration;

use crate::configuration::{Config, ScanType};
use crate::modes::Mode;
use std::sync::Arc;
use futures::stream::{self, StreamExt};
use governor::{Quota, RateLimiter};
use log::{info, error};
use std::num::NonZeroU32;   
use tokio::sync::Mutex;
use crate::modes::PortStatus;
use rand::seq::SliceRandom;
use rand::rng;
use crate::strategy::ScanStrategyTrait;
use crate::ui::Ui;
use std::unimplemented;

pub async fn run(mut config: Config) {
    let mode = match config.scan_type {
        ScanType::Tcp => modes::fulltcp::TcpScan::new(&config),
        _ => unimplemented!("Unimplemented scan type"),
    };

    if config.shuffle_ports {
        config.ports.ports.shuffle(&mut rng());
    }
    
    start_mass_scan(Arc::new(config), Arc::new(mode)).await;
}


pub async fn start_mass_scan(
    config: Arc<Config>,
    mode: Arc<dyn Mode>
) {
    let mut ui = Ui::new(&config);
    ui.print_banner();

    let hosts = config.targets.clone();
    let ports = config.ports.clone();    
    let number_of_targets = hosts.len() * ports.len();
    let targets = config.scan_strategy.create_targets(&config.targets, &config.ports);

    let scanner = mode;
    // Default value
    let mut ratelimit: u64 = 1000;

    if let Some(config_ratelimit) = config.ratelimit {
        ratelimit = config_ratelimit;
    } else if let Some(ratelimit_per_host) = config.ratelimit_per_host {
        // TODO: we must think about ratelimit per any host
        ratelimit = ratelimit_per_host * hosts.len() as u64;
    } else if let Some(maximum_scan_time) = &config.maximum_scan_time {
        match parse_duration::parse(maximum_scan_time) {
            Ok(duration) => {
                ratelimit = (number_of_targets as f64 / duration.as_secs() as f64).ceil() as u64;
            }
            Err(e) => {
                error!("Invalid maximum scan time: {}", e);
                return;
            }
        }
    }

    let limiter = Arc::new(RateLimiter::direct(Quota::per_second(NonZeroU32::new(ratelimit as u32).unwrap())));

    info!(
        "Starting scan for {} targets with {} concurrent scans and {} scans/sec limit.",
        number_of_targets,
        config.max_concurrent_ports,
        ratelimit
    );

    let results = Arc::new(Mutex::new(Vec::new())); // Simple way to collect results

    ui.init_progress_bar(number_of_targets as u64);
    stream::iter(targets)
        .for_each_concurrent(config.max_concurrent_ports as usize, |target_to_scan| {
            let scanner_clone = Arc::clone(&scanner);
            let limiter_clone = Arc::clone(&limiter);
            let results_clone = results.clone(); // Clone target for the async block
            let mut ui_clone = ui.clone();
            async move {
                limiter_clone.until_ready().await;

                let status = scanner_clone.scan(&target_to_scan).await;
                
                match status {
                    PortStatus::Open => {
                        ui_clone.print_progress_bar(format!("Host: {}, Port: {}, Status: {:?}", target_to_scan.ip, target_to_scan.port, status));
                        let mut results_guard = results_clone.lock().await;
                        results_guard.push((target_to_scan, status));
                    }
                    _ => (),
                }
                
                ui_clone.increment_progress_bar(1);
                
            }
        })
        .await;

    ui.finish_progress_bar();

    info!("Scanning complete. Processed {} results.", results.lock().await.len());
}