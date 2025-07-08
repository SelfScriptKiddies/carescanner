// module for the different modes of the scan
pub mod fulltcp;
pub mod sockstcp;
pub mod udp;

use async_trait::async_trait;
use crate::configuration::Config;
use enum_dispatch::enum_dispatch;

#[derive(Debug, Clone)]
pub struct Target {
    pub ip: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub enum PortStatus {
    Open,
    Filtered,
    Closed
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum ScanTypeName { 
    Syn,
    Tcp,
    Fin,
    Ping,
    Udp,
    Socks5Tcp,
}

#[async_trait]
#[enum_dispatch]
pub trait ScanTypeTrait: Send + Sync + Sized {
    fn name(&self) -> &str;
    fn protocol(&self) -> &str;
    async fn scan(&self, target: &Target) -> PortStatus;
}

#[enum_dispatch(ScanTypeTrait)]
pub enum ScanType {
    Tcp(fulltcp::TcpScan),
    Sockstcp(sockstcp::Socks5TcpScan),
    Udp(udp::UdpScan),
}

impl ScanType {
    pub fn build(scan_type: ScanTypeName, config: &Config) -> Self {
        match scan_type {
            ScanTypeName::Tcp => ScanType::Tcp(fulltcp::TcpScan::new(&config)),
            ScanTypeName::Udp => ScanType::Udp(udp::UdpScan::new(&config)),
            ScanTypeName::Socks5Tcp => ScanType::Sockstcp(sockstcp::Socks5TcpScan::new(&config)),
            _ => unimplemented!("Unimplemented scan type"),
        }
    }
}
