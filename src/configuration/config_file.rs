use serde::Deserialize;
use log::info;

const CONFIG_PATHS: &[&str] = &[
    "carescanner.toml",
    "~/.config/carescanner/config.toml",
];

#[derive(Debug, Deserialize, Default)]
pub struct FileConfig {
    pub ratelimit: Option<u64>,
    pub timeout: Option<u64>,
    pub max_concurrent_ports: Option<u64>,
    pub format: Option<String>,
    pub output: Option<String>,
    pub banner: Option<bool>,
    pub adaptive: Option<bool>,
    pub shuffle_ports: Option<bool>,
    pub ping: Option<bool>,
    pub nmap_args: Option<Vec<String>>,
}

fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{}/{}", home, rest);
        }
    }
    path.to_string()
}

/// Try to load config from known paths. Returns defaults if none found.
pub fn load_config_file() -> FileConfig {
    for path in CONFIG_PATHS {
        let expanded = expand_tilde(path);
        if let Ok(content) = std::fs::read_to_string(&expanded) {
            match toml::from_str::<FileConfig>(&content) {
                Ok(cfg) => {
                    info!("Loaded config from {}", expanded);
                    return cfg;
                }
                Err(e) => {
                    eprintln!("Warning: failed to parse {}: {}", expanded, e);
                }
            }
        }
    }
    FileConfig::default()
}
