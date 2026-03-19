pub mod ui;
pub mod modes;
pub mod strategy;
pub mod configuration;
pub mod appstate;
pub mod signal_handler;
pub mod nmap;

use crate::configuration::Config;
use crate::configuration::top_ports::TOP_PORTS;
use crate::configuration::PortList;
use crate::modes::{ScanType, ScanTypeTrait};
use crate::modes::ping;
use std::sync::Arc;
use futures::stream::{self, StreamExt};
use governor::{Quota, RateLimiter};
use log::{info, error};
use std::num::NonZeroU32;
use crate::appstate::{AppState, AppStateManager};
use crate::configuration::TargetList;
use crate::modes::PortStatus;
use rand::seq::SliceRandom;
use rand::rng;
use crate::strategy::ScanStrategyTrait;
use crate::ui::Ui;
use crate::signal_handler::{PauseController, spawn_signal_handler};

pub async fn run(mut config: Config) {
    let modes: Vec<ScanType> = config.scan_type.iter().cloned().map(|scan_type| ScanType::build(scan_type, &config)).collect::<Vec<_>>();

    // Override ports with top-N if --top-ports is specified
    if let Some(n) = config.top_ports {
        let n = n.min(TOP_PORTS.len());
        config.ports = PortList { ports: TOP_PORTS[..n].to_vec() };
        info!("Using top {} ports", n);
    }

    // Ping scan: filter out dead hosts before main scan
    if config.ping {
        let alive = ping::discover_hosts(&config).await;
        if alive.is_empty() {
            info!("No alive hosts found during ping scan. Exiting.");
            return;
        }
        config.targets = TargetList { targets: alive };
    }

    // Resume from previous scan: exclude already-scanned hosts
    if let Some(resume_path) = &config.resume_from {
        match AppState::load_resume_file(resume_path) {
            Ok(completed_hosts) => {
                let before = config.targets.len();
                let completed_set: std::collections::HashSet<&str> =
                    completed_hosts.iter().map(|s| s.as_str()).collect();
                config.targets.targets.retain(|h| !completed_set.contains(h.as_str()));
                let skipped = before - config.targets.len();
                info!("Resuming scan from {}: skipping {} already-scanned hosts ({} remaining)",
                    resume_path, skipped, config.targets.len());
                if config.targets.targets.is_empty() {
                    info!("All hosts already scanned. Nothing to do.");
                    return;
                }
            }
            Err(e) => {
                error!("Failed to load resume file: {}. Starting fresh.", e);
            }
        }
    }

    if config.shuffle_ports {
        config.ports.ports.shuffle(&mut rng());
    }

    // Additional limit for ulimit (x1.5 for safety)
    config.max_concurrent_ports = increase_ulimit((config.max_concurrent_ports as f64 * 1.5).ceil() as u64) / 1.5 as u64;

    start_mass_scan(Arc::new(config), Arc::new(modes)).await;
}


pub async fn start_mass_scan(
    config: Arc<Config>,
    modes: Arc<Vec<ScanType>>,
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

    // Using mpsc channel to collect results
    let app_state_manager = Arc::new(AppStateManager::new());
    let results_sender = app_state_manager.get_results_sender();

    // Setup pause controller and CTRL+C handler
    let pause_controller = PauseController::new();
    let (exit_tx, exit_rx) = tokio::sync::oneshot::channel::<()>();
    spawn_signal_handler(
        pause_controller.clone(),
        Arc::clone(&app_state_manager),
        Arc::clone(&config),
        ui.clone(),
        Some(exit_tx),
    );

    ui.init_progress_bar(number_of_targets as u64);
    // Needs to make progress bar visible from the start
    ui.update_progress_bar(0);

    let scan_future = stream::iter(targets)
        .for_each_concurrent(config.max_concurrent_ports as usize, |target_to_scan| {
            let scanner_clone: Arc<Vec<ScanType>> = Arc::clone(&scanner);
            let limiter_clone = Arc::clone(&limiter);
            let results_sender_clone = results_sender.clone();
            let mut ui_clone = ui.clone();
            let pause = pause_controller.clone();
            async move {
                for scan_type in scanner_clone.iter() {
                    pause.wait_if_paused().await;
                    if pause.should_exit() {
                        return;
                    }

                    limiter_clone.until_ready().await;

                    let result = ScanTypeTrait::scan(scan_type, &target_to_scan).await;
                    let is_open = matches!(result.status, PortStatus::Open);
                    let banner_display = result.banner.clone();
                    results_sender_clone.send((target_to_scan.clone(), result, scan_type.protocol().to_string())).unwrap();

                    if is_open {
                        let msg = match &banner_display {
                            Some(b) => format!("Host: {}, Port: {}/{}, Status: Open, Banner: {}", &target_to_scan.ip, &target_to_scan.port, scan_type.protocol(), b),
                            None => format!("Host: {}, Port: {}/{}, Status: Open", &target_to_scan.ip, &target_to_scan.port, scan_type.protocol()),
                        };
                        ui_clone.print_progress_bar(msg);
                    }

                    ui_clone.increment_progress_bar(1);
                }
            }
        });

    // Race the scan against exit signal
    let exited_early = tokio::select! {
        _ = scan_future => {
            if pause_controller.should_exit() {
                ui.clear_progress_bar();
                true
            } else {
                ui.finish_progress_bar();
                info!("Scanning complete.");
                false
            }
        }
        _ = exit_rx => {
            ui.clear_progress_bar();
            true
        }
    };

    // Give the result processor a moment to drain the channel
    tokio::task::yield_now().await;

    let state = app_state_manager.get_current_state().await;

    // Auto-save results if --output is specified and we didn't exit via menu (menu already saves)
    if !exited_early {
        if config.output.is_some() {
            match state.save_to_file(&config) {
                Ok(path) => info!("Results saved to: {}", path),
                Err(e) => error!("Error saving results: {}", e),
            }
        }

        // Run nmap on found open ports if requested
        let run_nmap = config.nmap || !config.nmap_args.is_empty();
        if run_nmap {
            let nmap_args = if config.nmap_args.is_empty() {
                vec!["-sV".to_string(), "-sC".to_string()]
            } else {
                config.nmap_args.clone()
            };
            nmap::run_on_results(&state, &nmap_args);
        }
    }
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

