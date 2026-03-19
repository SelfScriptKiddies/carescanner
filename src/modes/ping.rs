use std::sync::Arc;
use futures::stream::{self, StreamExt};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::Duration;
use tokio_socks::tcp::socks5::Socks5Stream;
use log::{info, debug};

use crate::configuration::{Config, ProxyStrategy};
use crate::configuration::top_ports::TOP_PORTS;

const DEFAULT_PING_PORTS: usize = 10;

/// Discover alive hosts by attempting TCP connections to top ports.
/// A host is "alive" if any port responds (open or connection-refused/RST).
/// Timeouts on all ports = host is considered down.
pub async fn discover_hosts(config: &Config) -> Vec<String> {
    let hosts = &config.targets.targets;
    let ping_ports: Vec<u16> = TOP_PORTS.iter().take(DEFAULT_PING_PORTS).copied().collect();
    let timeout = Duration::from_secs(config.timeout);
    let concurrency = config.max_concurrent_ports as usize;

    let use_proxy = config.proxies.is_some();
    let config = Arc::new(config.clone());

    info!("Ping scan: checking {} hosts via {} top ports", hosts.len(), ping_ports.len());

    let results: Vec<(String, bool)> = stream::iter(hosts.iter().cloned())
        .map(|host| {
            let ping_ports = ping_ports.clone();
            let timeout = timeout;
            let config = Arc::clone(&config);
            async move {
                let alive = if use_proxy {
                    ping_host_proxy(&host, &ping_ports, timeout, &config).await
                } else {
                    ping_host_direct(&host, &ping_ports, timeout).await
                };
                (host, alive)
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    let alive: Vec<String> = results
        .into_iter()
        .filter(|(_, alive)| *alive)
        .map(|(host, _)| host)
        .collect();

    info!("Ping scan complete: {}/{} hosts alive", alive.len(), hosts.len());
    alive
}

/// Ping a host directly (no proxy). Returns true if host is alive.
async fn ping_host_direct(host: &str, ports: &[u16], timeout: Duration) -> bool {
    for port in ports {
        let addr = if host.contains(':') {
            format!("[{}]:{}", host, port)
        } else {
            format!("{}:{}", host, port)
        };
        match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
            Ok(Ok(mut stream)) => {
                let _ = stream.shutdown().await;
                debug!("Ping: {} is alive (port {} open)", host, port);
                return true;
            }
            Ok(Err(_)) => {
                // Connection refused = host is alive (RST received)
                debug!("Ping: {} is alive (port {} refused)", host, port);
                return true;
            }
            Err(_) => continue, // Timeout, try next port
        }
    }
    debug!("Ping: {} appears down (all ports timed out)", host);
    false
}

/// Ping a host through SOCKS5 proxy. Returns true if host is alive.
async fn ping_host_proxy(host: &str, ports: &[u16], timeout: Duration, config: &Config) -> bool {
    let proxies = match &config.proxies {
        Some(pl) => &pl.proxies,
        None => return ping_host_direct(host, ports, timeout).await,
    };

    if proxies.is_empty() {
        return ping_host_direct(host, ports, timeout).await;
    }

    let proxy = match config.proxy_strategy.as_ref().unwrap_or(&ProxyStrategy::Sequential) {
        ProxyStrategy::Sequential | ProxyStrategy::Random => &proxies[0],
        ProxyStrategy::Chain => &proxies[0], // For ping, just use first proxy
    };

    for port in ports {
        let target_addr = if host.contains(':') {
            format!("[{}]:{}", host, port)
        } else {
            format!("{}:{}", host, port)
        };
        match tokio::time::timeout(
            timeout,
            Socks5Stream::connect(proxy.as_str(), target_addr.as_str()),
        )
        .await
        {
            Ok(Ok(_)) => {
                debug!("Ping (proxy): {} is alive (port {} open)", host, port);
                return true;
            }
            Ok(Err(_)) => {
                debug!("Ping (proxy): {} is alive (port {} refused)", host, port);
                return true;
            }
            Err(_) => continue,
        }
    }
    debug!("Ping (proxy): {} appears down", host);
    false
}
