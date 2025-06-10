use tokio::net::UdpSocket;
use tokio::time::Duration;
use crate::modes::{ScanTypeTrait, Target, PortStatus};
use crate::configuration::Config;
use async_trait::async_trait;

#[derive(Debug, Clone)]
pub struct UdpScan {
    pub name: String,
    pub timeout: u64
}

impl UdpScan {
    pub fn new(config: &Config) -> Self {
        Self { 
            name: "UDP scan".to_string(), 
            timeout: config.timeout
        }
    }
}

#[async_trait]
impl ScanTypeTrait for UdpScan {
    fn name(&self) -> &str {
        &self.name
    }

    fn protocol(&self) -> &str {
        "udp"
    }

    async fn scan(&self, target: &Target) -> PortStatus {
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(socket) => socket,
            Err(_) => return PortStatus::Filtered,
        };

        let target_addr = format!("{}:{}", target.ip, target.port);
        
        // Send empty UDP packet
        let send_result = socket.send_to(&[], &target_addr).await;
        if send_result.is_err() {
            return PortStatus::Filtered;
        }

        // Wait for response with timeout
        let mut buf = [0; 1024];
        let response = tokio::time::timeout(
            Duration::from_secs(self.timeout),
            socket.recv_from(&mut buf)
        ).await;

        match response {
            Ok(Ok(_)) => PortStatus::Open,
            Ok(Err(_)) => PortStatus::Closed,
            Err(_) => PortStatus::Filtered,
        }
    }
}