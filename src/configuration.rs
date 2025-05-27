mod target_parsing;
mod port_parsing;


pub use target_parsing::TargetList;
pub use port_parsing::PortList;
use clap::Parser;

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum ScanType { 
    Syn,
    Tcp,
    Fin,
    Ping,
}

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

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Config {
    #[arg(short, long, default_value = "info", help_heading = "Logging options", help = "Logging level")]
    pub logging_level: LoggingLevel,

    // Scan options
    #[arg(long, help_heading = "Scan options", alias = "target", help = "Targets to scan (e.g., 192.168.1.0/24, scanme.nmap.org), comma-separated, or from a file (e.g., file:targets.txt)", value_name = "TARGETS_LIST", value_parser = target_parsing::parse_target_input)]
    pub targets: TargetList,

    #[arg(long, help_heading = "Scan options", alias = "port", help = "Ports to scan (e.g., 80,443, 22-25, file:ports.txt), comma-separated, or from a file", value_name = "PORTS_LIST", default_value = "1-65535")]
    pub ports: PortList,

    #[arg(long, help_heading = "Scan options", help = "Shuffle ports", value_name = "SHUFFLE_PORTS", default_value = "false")]
    pub shuffle_ports: bool,

    #[arg(long, help_heading = "Scan options", help = "Proxies to use for the scan (e.g., socks5://localhost:9050, http://user:pass@host:port), comma-separated, or from a file (e.g., file:proxies.txt)", value_name = "PROXIES_LIST")]
    pub proxies: Option<Vec<String>>,

    #[arg(short='x', long, help_heading = "Scan options", help = "Don't start a new scan, resume from a previous scan", value_name = "FILE_RESUME_FROM")]
    pub resume_from: Option<String>,

    #[arg(long, help_heading = "Scan options", help = "Scan strategy", value_name = "SCAN_STRATEGY", default_value = "round-robin")]
    pub scan_strategy: ScanStrategy,

    #[arg(short, long, help_heading = "Scan options", help = "Scan options", default_value = "tcp")]
    pub scan_type: ScanType,

    // Speed options
    #[arg(short, long, help_heading = "Speed options", help = "Overall packet rate limit")]
    pub ratelimit: Option<u32>,

    #[arg(long, help_heading = "Speed options", help = "Packet rate limit per host")]
    pub ratelimit_per_host: Option<u32>,

    #[arg(short='M', long, help_heading = "Speed options", help = "Maximum scan time", conflicts_with_all = ["ratelimit", "ratelimit_per_host"])]
    pub maximum_scan_time: Option<u32>,

    #[arg(long, help_heading = "Speed options", help = "Maximum ports scanning at a time")]
    pub max_concurrent_ports: Option<u32>,

    #[arg(long, help_heading = "Speed options", help = "Timeout for the scan", default_value = "1")]
    pub timeout: u64,

    // TUI options
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
}