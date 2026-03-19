use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::net::TcpStream;
use tokio::time::Duration;
use crate::modes::{ScanTypeTrait, Target, ScanResult};
use crate::configuration::Config;
use async_trait::async_trait;

const HTTP_PORTS: &[u16] = &[80, 443, 8080, 8443, 8000, 8888, 8081, 3000];
const BANNER_TIMEOUT_MS: u64 = 2000;
const MAX_BANNER_LEN: usize = 256;

pub struct TcpScan {
    pub name: String,
    pub timeout: u64,
    pub grab_banner: bool,
}

impl TcpScan {
    pub fn new(config: &Config) -> Self {
        Self {
            name: "Full TCP connection".to_string(),
            timeout: config.timeout,
            grab_banner: config.banner,
        }
    }
}

#[async_trait]
impl ScanTypeTrait for TcpScan {
    fn name(&self) -> &str {
        &self.name
    }

    fn protocol(&self) -> &str {
        "tcp"
    }

    async fn scan(&self, target: &Target) -> ScanResult {
        let stream = tokio::time::timeout(
            Duration::from_secs(self.timeout),
            TcpStream::connect(format!("{}:{}", target.ip, target.port)),
        )
        .await;

        match stream {
            Ok(Ok(mut stream)) => {
                let banner = if self.grab_banner {
                    grab_banner(&mut stream, target).await
                } else {
                    None
                };
                let _ = stream.shutdown().await;
                ScanResult::open(banner)
            }
            Ok(Err(_)) => ScanResult::closed(),
            Err(_) => ScanResult::filtered(),
        }
    }
}

async fn grab_banner(stream: &mut TcpStream, target: &Target) -> Option<String> {
    // For HTTP ports, send a minimal request to trigger a response.
    if HTTP_PORTS.contains(&target.port) {
        let request = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", target.ip);
        if stream.write_all(request.as_bytes()).await.is_err() {
            return None;
        }
    }

    let mut buf = vec![0u8; MAX_BANNER_LEN];
    let result = tokio::time::timeout(
        Duration::from_millis(BANNER_TIMEOUT_MS),
        stream.read(&mut buf),
    )
    .await;

    match result {
        Ok(Ok(n)) if n > 0 => {
            let raw = String::from_utf8_lossy(&buf[..n]);
            let first_line = raw.lines().next().unwrap_or("").trim().to_string();
            if first_line.is_empty() { None } else { Some(first_line) }
        }
        _ => None,
    }
}
