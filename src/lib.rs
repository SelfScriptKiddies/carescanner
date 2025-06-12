pub mod ui;
pub mod modes;
pub mod strategy;
pub mod configuration;

use crate::configuration::Config;
use crate::modes::{ScanType, ScanTypeTrait};
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

pub async fn run(mut config: Config) {
    let modes: Vec<ScanType> = config.scan_type.iter().cloned().map(|scan_type| ScanType::build(scan_type, &config)).collect::<Vec<_>>();

    if config.shuffle_ports {
        config.ports.ports.shuffle(&mut rng());
    }

    // Additional limit for ulimit (x1.5 for safety)
    config.max_concurrent_ports = increase_ulimit((config.max_concurrent_ports as f64 * 1.5).ceil() as u64) / 1.5 as u64;
    
    start_mass_scan(Arc::new(config), Arc::new(modes)).await;
}


pub async fn start_mass_scan(
    config: Arc<Config>,
    modes: Arc<Vec<ScanType>>
) {
    let mut ui = Ui::new(&config);
    ui.print_banner();

    let hosts = config.targets.clone();
    let ports = config.ports.clone();    
    let number_of_targets = hosts.len() * ports.len() * modes.len();
    let targets = config.scan_strategy.create_targets(&config.targets, &config.ports);

    let scanner: Arc<Vec<ScanType>> = modes;
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
    // Needs to make progress bar visible from the start
    ui.update_progress_bar(0);
    stream::iter(targets)
        .for_each_concurrent(config.max_concurrent_ports as usize, |target_to_scan| {
            let scanner_clone: Arc<Vec<ScanType>> = Arc::clone(&scanner);
            let limiter_clone = Arc::clone(&limiter);
            let results_clone = results.clone(); // Clone target for the async block
            let mut ui_clone = ui.clone();
            async move {
                for scan_type in scanner_clone.iter() {
                    limiter_clone.until_ready().await;

                    let status = ScanTypeTrait::scan(scan_type, &target_to_scan).await;
                    
                    match status {
                        PortStatus::Open => {
                            ui_clone.print_progress_bar(format!("Host: {}, Port: {}/{}, Status: {:?}", &target_to_scan.ip, &target_to_scan.port, scan_type.protocol(), status));
                            let mut results_guard = results_clone.lock().await;
                            results_guard.push((target_to_scan.clone(), status));
                        }
                        _ => (),
                    }
                    
                    ui_clone.increment_progress_bar(1);
                }
            }
        })
        .await;

    ui.finish_progress_bar();

    info!("Scanning complete. Processed {} results.", results.lock().await.len());
}

/// Cross-platform function to increase ulimit (file descriptor limit)
/// Returns the actual ulimit value after attempting to increase it
#[cfg(unix)]
pub fn increase_ulimit(new_size: u64) -> u64 {
    use rlimit::Resource;

    
    match Resource::NOFILE.set(new_size, new_size) {
        Ok(_) => {
            info!("Automatically increasing ulimit value to {new_size}.");
        }
        Err(e) => {
            error!("Failed to set ulimit value. {}", e);
        }
    }

    let (soft, _) = Resource::NOFILE.get().unwrap();
    soft
}

#[cfg(windows)]
pub fn increase_ulimit(new_size: u64) -> u64 {
    
    // On Windows, there's no direct ulimit equivalent
    // The closest thing is the number of handles a process can have
    // Windows typically allows 16M handles per process by default
    
    const WINDOWS_DEFAULT_HANDLE_LIMIT: u64 = 16_777_216; // 16M handles
    const WINDOWS_PRACTICAL_LIMIT: u64 = 65536; // Practical limit for most apps
    
    info!("Windows detected - ulimit concept doesn't exist");
    info!("Requested size: {}, Windows default handle limit: {}", new_size, WINDOWS_DEFAULT_HANDLE_LIMIT);
    
    // For network operations, Windows socket limit is typically around 64K
    if new_size <= WINDOWS_PRACTICAL_LIMIT {
        info!("Requested size {} is within Windows practical limits", new_size);
        new_size
    } else {
        info!("Requested size {} exceeds practical Windows limits, returning {}", new_size, WINDOWS_PRACTICAL_LIMIT);
        WINDOWS_PRACTICAL_LIMIT
    }
}

#[cfg(not(any(unix, windows)))]
pub fn increase_ulimit(new_size: u64) -> u64 {
    error!("Ulimit adjustment not supported on this platform");
    1024 // Conservative fallback
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_increase_ulimit() {
        let result = increase_ulimit(4096);
        
        #[cfg(windows)]
        {
            assert!(result <= 65536);
            println!("Windows ulimit result: {}", result);
        }
        
        #[cfg(unix)]
        {
            assert!(result >= 1024);
            println!("Unix ulimit result: {}", result);
        }
        
        let large_result = increase_ulimit(100000);
        
        #[cfg(windows)]
        {
            assert_eq!(large_result, 65536);
        }
        
        #[cfg(unix)]
        {
            assert!(large_result >= 1024);
        }
    }
}

