use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use ipnetwork::IpNetwork;
use dns_lookup::lookup_host;

#[derive(Debug, Clone)]
pub struct TargetList {
    pub targets: Vec<String>,
}

impl std::str::FromStr for TargetList {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_target_input(s)
    }
}

impl Into<Vec<String>> for TargetList {
    fn into(self) -> Vec<String> {
        self.targets
    }
}

impl IntoIterator for TargetList {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;
    fn into_iter(self) -> Self::IntoIter {
        self.targets.into_iter()
    }
}

impl TargetList {
    pub fn len(&self) -> usize {
        self.targets.len()
    }

    pub fn vec(&self) -> Vec<String> {
        self.targets.clone()
    }
}

pub fn read_addresses_from_file(filepath: &str) -> Result<Vec<String>, String> {
    let filepath = filepath.trim();
    if filepath.is_empty() {
        return Err("Empty file path for targets specified with 'file:' prefix.".into());
    }
    let path = Path::new(filepath);
    let file = File::open(path).map_err(|e| format!("Failed to open file '{}': {}", filepath, e))?;
    let reader = BufReader::new(file);
    let lines = reader.lines().collect::<Result<Vec<String>, std::io::Error>>().map_err(|e| format!("Failed to read lines from file '{}': {}", filepath, e))?;
    Ok(lines.into_iter().filter(|line| !line.trim().is_empty()).collect())
}

pub fn parse_target_input(s: &str) -> Result<TargetList, String> {
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

    // Expand CIDR notation to individual IP addresses
    let mut expanded_addresses = Vec::new();
    for addr in addresses {
        expanded_addresses.extend(expand_target(&addr)?);
    }
    
    Ok(TargetList { targets: expanded_addresses })
} 

fn expand_target(target: &str) -> Result<Vec<String>, String> {
    let mut expanded_addresses = Vec::new();
    // CIDR notation
    if target.contains('/') {
        let cidr = target.parse::<IpNetwork>().map_err(|e| format!("Invalid CIDR notation '{}': {}", target, e))?;
        for ip in cidr.iter() {
            expanded_addresses.push(ip.to_string());
        }
    } else {
        // Lookup host
        let hosts = lookup_host(target).map_err(|e| format!("Failed to lookup host '{}': {}", target, e))?;
        expanded_addresses.extend(hosts.iter().map(|host| host.to_string()));
    }

    Ok(expanded_addresses)
}