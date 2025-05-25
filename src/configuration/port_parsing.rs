pub fn parse_ports_string_to_vec(s: &str) -> Result<Vec<u16>, String> { 
    let mut ports_flat_vec = Vec::new();
    for part in s.split(',') {
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
    ports_flat_vec.dedup();
    Ok(ports_flat_vec)
}

#[derive(Debug, Clone)]
pub struct PortList(pub Vec<u16>);

impl std::str::FromStr for PortList {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ports = parse_ports_string_to_vec(s)?;
        Ok(PortList(ports))
    }
}

impl Into<Vec<u16>> for PortList {
    fn into(self) -> Vec<u16> {
        self.0
    }
}

impl IntoIterator for PortList {
    type Item = u16;
    type IntoIter = std::vec::IntoIter<u16>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl PortList {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn vec(&self) -> Vec<u16> {
        self.0.clone()
    }
}