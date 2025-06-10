use crate::configuration::Config;
use crate::modes::{PortStatus, ScanTypeTrait, Target};
use async_trait::async_trait;

pub struct Socks5TcpScan {
    pub name: String,
    pub timeout: u64,
    pub socks5_proxies: Vec<String>
}

impl Socks5TcpScan {
    pub fn new(config: &Config) -> Self { 
        let socks5_proxies = config.proxy_chain.clone();

        Self { 
            name: "socks5 TCP connection".to_string(), 
            timeout: config.timeout,
            socks5_proxies: vec![]
        }
    }
}

#[async_trait]
impl ScanTypeTrait for Socks5TcpScan {
    fn name(&self) -> &str {
        &self.name
    }

    async fn scan(&self, target: &Target) -> PortStatus {
        unimplemented!("Socks5 TCP scan is not implemented yet")
    }
}

