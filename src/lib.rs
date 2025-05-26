pub mod configuration;
pub mod modes;
use crate::configuration::{Config, ScanType};
use crate::modes::{Target, Mode};
use std::sync::Arc;

pub async fn run(config: Config) {
    let mode = match config.scan_type {
        ScanType::Tcp => modes::fulltcp::TcpScan::new(&config),
        _ => panic!("Unsupported scan type"),
    };

    for port in config.ports {
        for target in config.targets.clone() {
            let results = mode.scan(&Target { ip: target, port: port }).await;
            println!("{:?}", results);
        }
    }
}