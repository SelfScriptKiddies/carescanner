// module for the different modes of the scan
pub mod fulltcp;

use async_trait::async_trait;

#[derive(Debug, Clone)]
pub struct Target {
    pub ip: String,
    pub port: u16,
}

#[derive(Debug)]
pub enum PortStatus {
    Open,
    Filtered,
    Closed
}

#[async_trait]
pub trait Mode: Send + Sync {
    fn name(&self) -> &str;
    async fn scan(&self, target: &Target) -> PortStatus;
}