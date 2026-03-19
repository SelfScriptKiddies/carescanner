mod target_parsing;
mod port_parsing;
mod proxy;
pub mod top_ports;
pub mod config_file;


pub use target_parsing::TargetList;
pub use port_parsing::PortList;
use clap::{Parser, builder::ArgPredicate};
use crate::modes::ScanTypeName;
pub use proxy::{ProxyStrategy, ProxyList};

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum FormatScan { 
    NmapXml,
    Json,
    Text,
    All,
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum LoggingLevel {
    Off, 
    Trace,
    Debug,
    Info,
    Warning,
    Error,
}

impl Into<log::LevelFilter> for LoggingLevel {
    fn into(self) -> log::LevelFilter {
        match self {
            LoggingLevel::Off => log::LevelFilter::Off,
            LoggingLevel::Trace => log::LevelFilter::Trace,
            LoggingLevel::Debug => log::LevelFilter::Debug,
            LoggingLevel::Info => log::LevelFilter::Info,
            LoggingLevel::Warning => log::LevelFilter::Warn,
            LoggingLevel::Error => log::LevelFilter::Error,
        }
    }
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum ScanStrategy {
    HostFirst,
    RoundRobin,
}

#[derive(Debug, Clone)]
pub enum PortItem { 
    Single(u16),
    Range(u16, u16)
}

#[derive(Debug, Clone, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Config {
    #[arg(short, long, default_value = "info", help_heading = "Logging options", help = "Logging level")]
    pub logging_level: LoggingLevel,

    // Scan options
    #[arg(short, long, help_heading = "Scan options", alias = "target", help = "Targets to scan (e.g., 192.168.1.0/24, scanme.nmap.org), comma-separated, or from a file (e.g., file:targets.txt)", value_name = "TARGETS_LIST", value_parser = target_parsing::parse_target_input)]
    pub targets: TargetList,

    #[arg(short, long, help_heading = "Scan options", alias = "port", help = "Ports to scan (e.g., 80,443, 22-25, file:ports.txt), comma-separated, or from a file", value_name = "PORTS_LIST", default_value = "1-65535")]
    pub ports: PortList,

    #[arg(long, help_heading = "Scan options", help = "Scan only the top N most common ports (from nmap)", value_name = "N")]
    pub top_ports: Option<usize>,

    #[arg(long, help_heading = "Scan options", help = "Shuffle ports", value_name = "SHUFFLE_PORTS", default_value = "false")]
    pub shuffle_ports: bool,

    #[arg(long, help_heading = "Scan options", help = "Ping hosts before scanning (skip dead hosts)")]
    pub ping: bool,

    #[arg(long, help_heading = "Scan options", help = "socks5 proxies to use for the scan. Order of connecting it will be as in argument. Separate by comma (e.g., socks5://localhost:9050, socks5://192.168.1.1:9050)", value_name = "PROXY", value_parser = proxy::parse_proxy_input)]
    pub proxies: Option<ProxyList>,

    #[arg(long, help_heading = "Scan options", help = "Proxy strategy", value_name = "PROXY_STRATEGY", default_value_if("proxies", ArgPredicate::IsPresent, "sequential"))]
    pub proxy_strategy: Option<ProxyStrategy>,

    #[arg(long, help_heading = "Scan options", help = "Exclude hosts (e.g., 192.168.1.1,10.0.0.0/24), comma-separated or file:excludes.txt", value_name = "EXCLUDE_LIST", value_parser = target_parsing::parse_target_input)]
    pub exclude: Option<TargetList>,

    #[arg(short='x', long, help_heading = "Scan options", help = "Don't start a new scan, resume from a previous scan", value_name = "FILE_RESUME_FROM")]
    pub resume_from: Option<String>,

    #[arg(long, help_heading = "Scan options", help = "Grab service banners from open ports (adds latency)")]
    pub banner: bool,

    #[arg(long, help_heading = "Scan options", help = "Total number of workers for distributed scanning", value_name = "N")]
    pub total_workers: Option<usize>,

    #[arg(long, help_heading = "Scan options", help = "This worker's ID (0-based) for distributed scanning", value_name = "ID")]
    pub worker_id: Option<usize>,

    #[arg(long, help_heading = "Scan options", help = "Scan strategy", value_name = "SCAN_STRATEGY", default_value = "round-robin")]
    pub scan_strategy: ScanStrategy,

    #[arg(short, long, help_heading = "Scan options", help = "Scan options", default_value = "tcp", value_delimiter = ',')]
    pub scan_type: Vec<ScanTypeName>,

    // Speed options
    #[arg(short, long, help_heading = "Speed options", help = "Overall packet rate limit", conflicts_with_all = ["ratelimit_per_host", "maximum_scan_time"])]
    pub ratelimit: Option<u64>,

    #[arg(long, help_heading = "Speed options", help = "Packet rate limit per host", conflicts_with_all = ["ratelimit", "maximum_scan_time"])]
    pub ratelimit_per_host: Option<u64>,

    #[arg(short='M', long, help_heading = "Speed options", help = "Maximum scan time", conflicts_with_all = ["ratelimit", "ratelimit_per_host"])]
    pub maximum_scan_time: Option<String>,

    #[arg(long, help_heading = "Speed options", help = "Adaptive rate limiting: auto-adjusts speed based on timeout ratio")]
    pub adaptive: bool,

    #[arg(long, help_heading = "Speed options", help = "Maximum ports scanning at a time", default_value = "1000")]
    pub max_concurrent_ports: u64,

    #[arg(long, help_heading = "Speed options", help = "Timeout for the scan", default_value = "3")]
    pub timeout: u64,

    // TUI options
    #[arg(short='q', long, help_heading = "TUI options", help = "Quiet mode: no banner, no progress bar, no live output. Only final results.")]
    pub quiet: bool,

    #[arg(long, help_heading = "TUI options", help = "Disable all TUI elements")]
    pub disable_all: bool,

    #[arg(long, help_heading = "TUI options", help = "Disable progress bar")]
    pub disable_progress_bar: bool,

    #[arg(long, help_heading = "TUI options", help = "Disable banner")]
    pub disable_banner: bool,

    // Output options
    #[arg(short, long, help_heading = "Output options")]
    pub output: Option<String>,

    #[arg(short, long, help_heading = "Output options", default_value = "text")]
    pub format: FormatScan,

    #[arg(short='c', long, help_heading = "Output options", help = "Show closed ports")]
    pub show_closed_ports: bool,

    #[arg(long, help_heading = "Output options", help = "Start web dashboard on given port (e.g. --dashboard 8899)", value_name = "PORT")]
    pub dashboard: Option<u16>,

    // Nmap integration
    #[arg(long, help_heading = "Nmap options", help = "Run nmap on discovered open ports for service detection")]
    pub nmap: bool,

    #[arg(long, help_heading = "Nmap options", help = "Path to nmap binary", default_value = "nmap")]
    pub nmap_path: String,

    #[arg(last = true, help_heading = "Nmap options", help = "Arguments passed to nmap (separated by --). Implies --nmap. Default: -sV -sC")]
    pub nmap_args: Vec<String>,
}