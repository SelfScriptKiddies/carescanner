use tokio::net::UdpSocket;
use tokio::time::Duration;
use crate::modes::{ScanTypeTrait, Target, ScanResult};
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

    async fn scan(&self, target: &Target) -> ScanResult {
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(socket) => socket,
            Err(_) => return ScanResult::filtered(),
        };

        let target_addr = format!("{}:{}", target.ip, target.port);

        if socket.send_to(&[], &target_addr).await.is_err() {
            return ScanResult::filtered();
        }

        let mut buf = [0; 1024];
        let response = tokio::time::timeout(
            Duration::from_secs(self.timeout),
            socket.recv_from(&mut buf),
        )
        .await;

        match response {
            Ok(Ok(_)) => ScanResult::open(None),
            Ok(Err(_)) => ScanResult::closed(),
            Err(_) => ScanResult::filtered(),
        }
    }
}