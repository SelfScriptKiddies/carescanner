use crate::configuration::{Config, ProxyStrategy};
use crate::modes::{PortStatus, ScanTypeTrait, Target};
use tokio_socks::{tcp::socks5::Socks5Stream};
use async_trait::async_trait;
use tokio::sync::Mutex;
use crate::configuration::ProxyList;

pub struct Socks5TcpScan {
    pub name: String,
    pub timeout: u64,
    pub socks5_proxies: ProxyList,
    pub proxy_strategy: ProxyStrategy,
    pub offset: Mutex<usize>
}

impl Socks5TcpScan {
    pub fn new(config: &Config) -> Self { 
        let socks5_proxies = config.proxies.clone().unwrap_or(ProxyList { proxies: vec![] });

        Self { 
            name: "socks5 TCP connection".to_string(), 
            timeout: config.timeout,
            socks5_proxies: socks5_proxies,
            proxy_strategy: config.proxy_strategy.clone().unwrap_or(ProxyStrategy::Sequential),
            offset: Mutex::new(0)
        }
    }

    async fn scan_with_proxy(&self, target: &Target, proxy: &str) -> PortStatus {
        let _ = Socks5Stream::connect(proxy, format!("{}:{}", target.ip, target.port)).await;
        PortStatus::Open
    }
}

#[async_trait]
impl ScanTypeTrait for Socks5TcpScan {
    fn protocol(&self) -> &str {
        "tcp"
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn scan(&self, target: &Target) -> PortStatus {
        match self.proxy_strategy {
            ProxyStrategy::Sequential => {
                let mut offset = self.offset.lock().await;
                let proxy = &self.socks5_proxies.vec()[*offset];
                *offset = *offset + 1;
                self.scan_with_proxy(target, &proxy).await
            }
            _ => unimplemented!("Socks5 TCP scan is not implemented yet")
        }
    }

}

