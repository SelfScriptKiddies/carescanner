// Default 3-step handshake
use tokio::net::TcpStream;
use tokio::time::Duration;
use crate::modes::{Mode, Target, PortStatus};
use crate::configuration::Config;

pub struct TcpScan {
    pub name: String,
    pub timeout: u64
}

impl TcpScan {
    pub fn new(config: &Config) -> Self { 
        Self { 
            name: "Full TCP connection".to_string(), 
            timeout: config.timeout
        }
    }
}

impl Mode for TcpScan {
    fn name(&self) -> &str {
        &self.name
    }

    async fn scan(&self, target: &Target) -> PortStatus {
        let stream = tokio::time::timeout(
            Duration::from_secs(self.timeout), 
            TcpStream::connect(format!("{}:{}", target.ip, target.port))
        ).await;

        // Timeout error
        if let Err(_) = stream {
            return PortStatus::Filtered;
        }

        // Non-timeout error, so connection failed
        if let Err(_) = stream.unwrap() {
            return PortStatus::Closed;
        }  

        // Successfully opened connection
        PortStatus::Open
    }
}