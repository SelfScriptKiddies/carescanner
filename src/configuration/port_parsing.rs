use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use log::error;

fn get_ports_from_file(filename: &str) -> Result<Vec<String>, String> {
    let actual_file_path = filename.trim();
    if actual_file_path.is_empty() {
        return Err("Empty file path for ports specified with \'file:\' prefix.".to_string());
    }

    let path = Path::new(filename);
    let file = File::open(path).map_err(|e| format!("Failed to open file '{}': {}", actual_file_path, e))?;
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader.lines().collect::<Result<_, std::io::Error>>().map_err(|e| e.to_string())?;

    let mut ports = Vec::new();
    
    for part in lines.iter() {
        let trimmed_part = part.trim();
        if !trimmed_part.is_empty() {
            ports.push(trimmed_part.parse().map_err(|e| format!("Failed to parse port \'{}\': {}", trimmed_part, e))?);
        }
    }

    Ok(ports)
}

pub fn parse_ports_string_to_vec(s: &str) -> Result<Vec<u16>, String> {
    let mut ports_flat_vec = Vec::with_capacity(65535);

    let parts_to_process = match s.trim().strip_prefix("file:") {
        Some(file_path) => get_ports_from_file(file_path)?,
        None => s.split(',').map(|part| part.trim().to_string()).collect(),
    };


    for part in parts_to_process {
        if part.contains('-') {
            let mut iter = part.splitn(2, '-'); 
            let start_str = iter.next().ok_or_else(|| format!("Invalid range format: {}", part))?;
            let end_str = iter.next().ok_or_else(|| format!("Invalid range format: {}", part))?;
            
            let start: u16 = start_str.trim().parse().map_err(|e| format!("Failed to parse start of range '{}': {}", start_str, e))?;
            let end: u16 = end_str.trim().parse().map_err(|e| format!("Failed to parse end of range '{}': {}", end_str, e))?;

            if start > end {
                return Err(format!("Invalid range: start ({}) > end ({}) in {}", start, end, part));
            }

            for port in start..=end {
                ports_flat_vec.push(port);
            }
        } else {
            let port: u16 = part.trim().parse().map_err(|e| format!("Failed to parse port '{}': {}", part, e))?;
            ports_flat_vec.push(port);
        }
    }
    
    // Deduplicate ports
    let mut seen = [false; 65_536];
    let mut out = Vec::with_capacity(ports_flat_vec.len());

    for port in ports_flat_vec {
        if !seen[port as usize] {
            seen[port as usize] = true;
            out.push(port);
        }
    }

    out.shrink_to_fit();

    Ok(out)
}

#[derive(Debug, Clone)]
pub struct PortList {
    pub ports: Vec<u16>
}

impl std::str::FromStr for PortList {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ports = parse_ports_string_to_vec(s)?;
        Ok(PortList { ports })
    }
}

impl Into<Vec<u16>> for PortList {
    fn into(self) -> Vec<u16> {
        self.ports
    }
}

impl IntoIterator for PortList {
    type Item = u16;
    type IntoIter = std::vec::IntoIter<u16>;
    fn into_iter(self) -> Self::IntoIter {
        self.ports.into_iter()
    }
}

impl PortList {
    pub fn len(&self) -> usize {
        self.ports.len()
    }

    pub fn vec(&self) -> Vec<u16> {
        self.ports.clone()
    }
}