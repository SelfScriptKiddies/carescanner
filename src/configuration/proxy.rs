use crate::configuration::target_parsing::read_addresses_from_file;

#[derive(Debug, Clone)]
pub struct ProxyList {
    pub proxies: Vec<String>,
}

impl std::str::FromStr for ProxyList {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_proxy_input(s)
    }
}

impl Into<Vec<String>> for ProxyList {
    fn into(self) -> Vec<String> {
        self.proxies
    }
}

impl IntoIterator for ProxyList {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;

    fn into_iter(self) -> Self::IntoIter {
        self.proxies.into_iter()
    }
}

impl ProxyList {
    pub fn len(&self) -> usize {
        self.proxies.len()
    }

    pub fn vec(&self) -> Vec<String> {
        self.proxies.clone()
    }
}

pub fn parse_proxy_input(s: &str) -> Result<ProxyList, String> {
    let input = s.trim();
    let addresses: Vec<String> = match input.strip_prefix("file:") {
        Some(filepath) => read_addresses_from_file(filepath)?,
        None => {
            if input.is_empty() {
                return Err("No target specified".into());
            } else {
                input.split(',').map(|s| s.trim().to_string()).collect()
            }
        }
    };
    
    Ok(ProxyList { proxies: addresses })
} 

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum ProxyStrategy {
    Sequential,
    Random,
    Chain
}