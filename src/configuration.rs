mod port_parsing;

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
    Trace,
    Debug,
    Info,
    Warning,
    Error,
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
    #[arg(long, help_heading = "Scan options", help = "Targets to scan, ranges and single ips separated by comma", value_name = "TARGETS_LIST")]
    pub targets: Vec<String>,

    #[arg(long, help_heading = "Scan options", help = "Ports to scan, ranges and single ports separated by comma", value_name = "PORTS_LIST", default_value = "1-65535")]
    pub ports: PortList,

    #[arg(long, help_heading = "Scan options", help = "Proxies to use for the scan", value_name = "PROXIES_LIST")]
    pub proxies: Option<Vec<String>>,

    #[arg(short='x', long, help_heading = "Scan options", help = "Don't start a new scan, resume from a previous scan", value_name = "FILE_RESUME_FROM")]
    pub resume_from: Option<String>,

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

    // Output options
    #[arg(short, long, help_heading = "Output options")]
    pub output: Option<String>,

    #[arg(short, long, help_heading = "Output options", default_value = "text")]
    pub format: FormatScan,
}