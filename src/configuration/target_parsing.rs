use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

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

fn read_lines_from_file(filename: &str) -> std::io::Result<Vec<String>> {
    let path = Path::new(filename);
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    reader.lines().collect()
}

pub fn parse_target_input(s: &str) -> Result<TargetList, String> {
    let input = s.trim();
    if let Some(file_path) = input.strip_prefix("file:") {
        let file_path = file_path.trim();
        if file_path.is_empty() {
            return Err("Empty file path for targets specified with 'file:' prefix.".into());
        }
        match read_lines_from_file(file_path) {
            Ok(lines) => Ok(TargetList { targets: lines.into_iter().filter(|line| !line.trim().is_empty()).collect() }),
            Err(e) => Err(format!("Failed to read targets from file '{}': {}", file_path, e).into()),
        }
    } else {
        if input.is_empty() {
            Ok(TargetList { targets: Vec::new() })
        } else {
            Ok(TargetList { targets: vec![input.to_string()] })
        }
    }
} 