// module for the different modes of the scan
pub mod fulltcp;

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

pub trait Mode {
    fn name(&self) -> &str;
    fn scan(&self, target: &Target) -> impl std::future::Future<Output = PortStatus> + Send;
}