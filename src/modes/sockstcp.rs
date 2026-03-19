use crate::configuration::{Config, ProxyStrategy, ProxyList};
use crate::modes::{ScanResult, ScanTypeTrait, Target};
use tokio_socks::tcp::socks5::Socks5Stream;
use async_trait::async_trait;
use tokio::sync::Mutex;
use tokio::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use log::debug;
use rand::prelude::IndexedRandom;

/// Helper trait for type-erased async streams (needed for proxy chaining).
trait BoxableStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> BoxableStream for T {}

pub struct Socks5TcpScan {
    pub name: String,
    pub timeout: u64,
    pub socks5_proxies: ProxyList,
    pub proxy_strategy: ProxyStrategy,
    offset: Mutex<usize>,
}

impl Socks5TcpScan {
    pub fn new(config: &Config) -> Self {
        let socks5_proxies = config.proxies.clone().unwrap_or(ProxyList { proxies: vec![] });

        Self {
            name: "SOCKS5 TCP connection".to_string(),
            timeout: config.timeout,
            socks5_proxies,
            proxy_strategy: config.proxy_strategy.clone().unwrap_or(ProxyStrategy::Sequential),
            offset: Mutex::new(0),
        }
    }

    /// Scan a target through a single SOCKS5 proxy.
    async fn scan_single_proxy(&self, target: &Target, proxy: &str) -> ScanResult {
        let target_addr = target.socket_addr();

        let result = tokio::time::timeout(
            Duration::from_secs(self.timeout),
            Socks5Stream::connect(proxy, target_addr.as_str()),
        )
        .await;

        match result {
            Ok(Ok(_)) => ScanResult::open(None),
            Ok(Err(e)) => {
                debug!("SOCKS5 connection error for {}:{} via {}: {}", target.ip, target.port, proxy, e);
                ScanResult::closed()
            }
            Err(_) => ScanResult::filtered(),
        }
    }

    /// Scan a target by chaining through ALL configured SOCKS5 proxies in order.
    /// Proxy1 → Proxy2 → ... → ProxyN → Target
    async fn scan_chain(&self, target: &Target) -> ScanResult {
        let proxies = &self.socks5_proxies.proxies;
        if proxies.is_empty() {
            return ScanResult::filtered();
        }

        let target_addr = target.socket_addr();
        // Scale timeout with chain length
        let timeout = Duration::from_secs(self.timeout * proxies.len() as u64);

        let result = tokio::time::timeout(timeout, async {
            chain_connect(proxies, &target_addr).await
        })
        .await;

        match result {
            Ok(Ok(())) => ScanResult::open(None),
            Ok(Err(e)) => {
                debug!("SOCKS5 chain error for {}:{}: {}", target.ip, target.port, e);
                ScanResult::closed()
            }
            Err(_) => ScanResult::filtered(),
        }
    }
}

/// Connect to target through a chain of SOCKS5 proxies.
async fn chain_connect(proxies: &[String], target_addr: &str) -> Result<(), tokio_socks::Error> {
    if proxies.len() == 1 {
        Socks5Stream::connect(proxies[0].as_str(), target_addr).await?;
        return Ok(());
    }

    // First hop: connect through proxy[0] to proxy[1]
    let stream = Socks5Stream::connect(proxies[0].as_str(), proxies[1].as_str()).await?;
    let mut boxed: Box<dyn BoxableStream> = Box::new(stream);

    // Chain through remaining proxies (proxy[2], proxy[3], ...)
    for proxy in &proxies[2..] {
        boxed = Box::new(
            Socks5Stream::connect_with_socket(boxed, proxy.as_str()).await?,
        );
    }

    // Final hop: through the last proxy to the actual target
    Socks5Stream::connect_with_socket(boxed, target_addr).await?;
    Ok(())
}

#[async_trait]
impl ScanTypeTrait for Socks5TcpScan {
    fn protocol(&self) -> &str {
        "tcp"
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn scan(&self, target: &Target) -> ScanResult {
        if self.socks5_proxies.proxies.is_empty() {
            debug!("No proxies configured for SOCKS5 scan");
            return ScanResult::filtered();
        }

        match self.proxy_strategy {
            ProxyStrategy::Sequential => {
                let mut offset = self.offset.lock().await;
                let proxy = &self.socks5_proxies.proxies[*offset];
                *offset = (*offset + 1) % self.socks5_proxies.len();
                self.scan_single_proxy(target, proxy).await
            }
            ProxyStrategy::Random => {
                let proxy = self.socks5_proxies.proxies
                    .choose(&mut rand::rng())
                    .unwrap();
                self.scan_single_proxy(target, proxy).await
            }
            ProxyStrategy::Chain => {
                self.scan_chain(target).await
            }
        }
    }
}
