use tokio::io::AsyncWriteExt;
// Default 3-step handshake
use tokio::net::TcpStream;
use tokio::time::Duration;
use crate::modes::{ScanTypeTrait, Target, PortStatus};
use crate::configuration::Config;
use async_trait::async_trait;

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

#[async_trait]
impl ScanTypeTrait for TcpScan {
    fn name(&self) -> &str {
        &self.name
    }

    async fn scan(&self, target: &Target) -> PortStatus {
        let stream = tokio::time::timeout(
            Duration::from_secs(self.timeout), 
            TcpStream::connect(format!("{}:{}", target.ip, target.port))
        ).await;

        match stream {
            Ok(Ok(mut stream)) => {
                let _ = stream.shutdown().await;
                drop(stream);
                PortStatus::Open
            }
            Ok(Err(_closed_error)) => PortStatus::Closed,
            Err(_timeout_error) => PortStatus::Filtered,
        }
    }
}