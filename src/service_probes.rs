/// Level 2 service detection: nmap-style probe-based matching with regex patterns.
///
/// Instead of parsing nmap-service-probes at runtime, we embed the most common
/// probes and match patterns as static data. Regexes are compiled lazily on first use.

use regex::Regex;
use std::sync::LazyLock;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A probe defines what bytes to send and a list of patterns to match against
/// the response.
pub struct ServiceProbe {
    /// "tcp" or "udp"
    pub protocol: &'static str,
    /// Bytes to send. Empty slice = NULL probe (just read the banner).
    pub probe_data: &'static [u8],
    /// Ordered list of match rules; first match wins.
    pub matches: &'static [MatchDef],
}

/// Static definition of a single match rule (pattern compiled lazily).
pub struct MatchDef {
    /// Canonical service name (e.g. "ssh", "http", "mysql")
    pub service: &'static str,
    /// Human-friendly product name (e.g. "OpenSSH", "nginx")
    pub product: &'static str,
    /// Regex pattern applied to the banner. Capture group 1 is used as version
    /// when present.
    pub pattern: &'static str,
}

/// Result of a successful probe match.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub service: String,
    pub product: String,
    pub version: Option<String>,
}

impl ProbeResult {
    /// Format as a human-readable string like "OpenSSH 8.9p1" or just "ssh".
    pub fn display(&self) -> String {
        match &self.version {
            Some(v) => format!("{} {}", self.product, v),
            None if !self.product.is_empty() => self.product.to_string(),
            None => self.service.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Embedded probes
// ---------------------------------------------------------------------------

/// NULL probe: send nothing, just read whatever the server sends on connect.
static NULL_MATCHES: &[MatchDef] = &[
    MatchDef {
        service: "ssh",
        product: "OpenSSH",
        pattern: r"^SSH-[\d.]+-OpenSSH[_-](\S+)",
    },
    MatchDef {
        service: "ssh",
        product: "SSH",
        pattern: r"^SSH-([\d.]+)-",
    },
    MatchDef {
        service: "ftp",
        product: "vsFTPd",
        pattern: r"^220.*vsFTPd\s+([\d.]+)",
    },
    MatchDef {
        service: "ftp",
        product: "ProFTPD",
        pattern: r"(?i)^220.*ProFTPD\s+([\d.]+)",
    },
    MatchDef {
        service: "ftp",
        product: "Pure-FTPd",
        pattern: r"(?i)^220.*Pure-FTPd",
    },
    MatchDef {
        service: "ftp",
        product: "FileZilla ftpd",
        pattern: r"(?i)^220.*FileZilla Server\s*([\d.]+)?",
    },
    MatchDef {
        service: "ftp",
        product: "FTP",
        pattern: r"^220[\s-].*(?i)ftp",
    },
    MatchDef {
        service: "smtp",
        product: "Postfix",
        pattern: r"^220.*Postfix",
    },
    MatchDef {
        service: "smtp",
        product: "Exim",
        pattern: r"(?i)^220.*Exim\s+([\d.]+)",
    },
    MatchDef {
        service: "smtp",
        product: "Sendmail",
        pattern: r"(?i)^220.*Sendmail\s+([\d.]+)",
    },
    MatchDef {
        service: "smtp",
        product: "SMTP",
        pattern: r"^220.*(?i)(ESMTP|SMTP)",
    },
    MatchDef {
        service: "pop3",
        product: "Dovecot",
        pattern: r"(?i)^\+OK.*Dovecot",
    },
    MatchDef {
        service: "pop3",
        product: "POP3",
        pattern: r"^\+OK",
    },
    MatchDef {
        service: "imap",
        product: "Dovecot",
        pattern: r"(?i)^\* OK.*Dovecot",
    },
    MatchDef {
        service: "imap",
        product: "Cyrus IMAP",
        pattern: r"(?i)^\* OK.*Cyrus IMAP\s*([\d.]+)?",
    },
    MatchDef {
        service: "imap",
        product: "IMAP",
        pattern: r"^\* OK.*(?i)IMAP",
    },
    MatchDef {
        service: "mysql",
        product: "MariaDB",
        pattern: r"([\d.]+)-MariaDB",
    },
    MatchDef {
        service: "mysql",
        product: "MySQL",
        // MySQL greeting packet: after the initial length bytes, the version
        // string appears as readable ASCII digits.
        pattern: r"(\d+\.\d+\.\d+).*(?:mysql|MySQL|caching_sha2_password|mysql_native_password)",
    },
    MatchDef {
        service: "postgresql",
        product: "PostgreSQL",
        pattern: r"(?i)PostgreSQL",
    },
    MatchDef {
        service: "redis",
        product: "Redis",
        pattern: r"(?i)-NOAUTH|redis_version:(\S+)|\+PONG",
    },
    MatchDef {
        service: "vnc",
        product: "VNC",
        pattern: r"^RFB (\d{3}\.\d{3})",
    },
    MatchDef {
        service: "telnet",
        product: "Telnet",
        // Telnet negotiation starts with IAC (0xFF)
        pattern: r"^\xff",
    },
    MatchDef {
        service: "amqp",
        product: "AMQP",
        pattern: r"^AMQP",
    },
    MatchDef {
        service: "mongodb",
        product: "MongoDB",
        pattern: r"(?i)mongodb|mongod|ismaster",
    },
];

/// HTTP GET probe: send a basic GET request, match the response.
static HTTP_GET_MATCHES: &[MatchDef] = &[
    MatchDef {
        service: "http",
        product: "nginx",
        pattern: r"(?i)Server:\s*nginx(?:/(\S+))?",
    },
    MatchDef {
        service: "http",
        product: "Apache httpd",
        pattern: r"(?i)Server:\s*Apache(?:/(\S+))?",
    },
    MatchDef {
        service: "http",
        product: "Microsoft IIS",
        pattern: r"(?i)Server:\s*Microsoft-IIS(?:/(\S+))?",
    },
    MatchDef {
        service: "http",
        product: "LiteSpeed",
        pattern: r"(?i)Server:\s*LiteSpeed(?:/(\S+))?",
    },
    MatchDef {
        service: "http",
        product: "Caddy",
        pattern: r"(?i)Server:\s*Caddy",
    },
    MatchDef {
        service: "http",
        product: "lighttpd",
        pattern: r"(?i)Server:\s*lighttpd(?:/(\S+))?",
    },
    MatchDef {
        service: "http",
        product: "cloudflare",
        pattern: r"(?i)Server:\s*cloudflare",
    },
    MatchDef {
        service: "http",
        product: "HTTP",
        // Generic HTTP response — no Server header matched, but it's HTTP.
        pattern: r"^HTTP/[\d.]+\s+\d{3}",
    },
];

/// TLS probe: check if the response looks like a TLS handshake.
/// We don't actually send a ClientHello — we just check the banner bytes
/// from a NULL read that starts with the TLS record header.
static TLS_MATCHES: &[MatchDef] = &[
    MatchDef {
        service: "tls/ssl",
        product: "TLS",
        // TLS record: content type 0x15 (alert) or 0x16 (handshake), version 0x03 0x0X
        pattern: r"^(?:\x15\x03|\x16\x03)",
    },
];

/// All probes in priority order. The NULL probe comes first because many
/// services send a banner on connect without any prompt.
pub static PROBES: &[ServiceProbe] = &[
    ServiceProbe {
        protocol: "tcp",
        probe_data: b"",
        matches: NULL_MATCHES,
    },
    ServiceProbe {
        protocol: "tcp",
        // We don't literally embed the GET request here because fulltcp.rs
        // already sends it for HTTP ports. This probe is only used for matching.
        probe_data: b"GET / HTTP/1.0\r\n\r\n",
        matches: HTTP_GET_MATCHES,
    },
    ServiceProbe {
        protocol: "tcp",
        probe_data: b"",
        matches: TLS_MATCHES,
    },
];

// ---------------------------------------------------------------------------
// Compiled regex cache
// ---------------------------------------------------------------------------

/// Thread-safe compiled regex cache. We compile each pattern exactly once.
struct CompiledMatch {
    service: &'static str,
    product: &'static str,
    regex: Regex,
}

struct CompiledProbe {
    matches: Vec<CompiledMatch>,
}

static COMPILED_NULL: LazyLock<CompiledProbe> = LazyLock::new(|| compile_matches(NULL_MATCHES));
static COMPILED_HTTP: LazyLock<CompiledProbe> = LazyLock::new(|| compile_matches(HTTP_GET_MATCHES));
static COMPILED_TLS: LazyLock<CompiledProbe> = LazyLock::new(|| compile_matches(TLS_MATCHES));

fn compile_matches(defs: &'static [MatchDef]) -> CompiledProbe {
    let matches = defs
        .iter()
        .filter_map(|def| {
            match Regex::new(def.pattern) {
                Ok(regex) => Some(CompiledMatch {
                    service: def.service,
                    product: def.product,
                    regex,
                }),
                Err(e) => {
                    log::error!("Failed to compile service probe regex '{}': {}", def.pattern, e);
                    None
                }
            }
        })
        .collect();
    CompiledProbe { matches }
}

fn get_compiled(matches_def: &'static [MatchDef]) -> &'static CompiledProbe {
    // Determine which compiled set to use by pointer identity.
    if std::ptr::eq(matches_def, NULL_MATCHES) {
        &COMPILED_NULL
    } else if std::ptr::eq(matches_def, HTTP_GET_MATCHES) {
        &COMPILED_HTTP
    } else if std::ptr::eq(matches_def, TLS_MATCHES) {
        &COMPILED_TLS
    } else {
        // Fallback: should never happen with our static data.
        // Compile on the fly (not cached, but this path is unreachable).
        // We use a static for safety.
        &COMPILED_NULL
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Try to match a banner against a specific probe's patterns.
/// Returns the first match found, with version extracted from capture group 1.
pub fn match_banner(probe: &ServiceProbe, banner: &str) -> Option<ProbeResult> {
    let compiled = get_compiled(probe.matches);
    for m in &compiled.matches {
        if let Some(caps) = m.regex.captures(banner) {
            let version = caps.get(1).map(|v| v.as_str().to_string());
            return Some(ProbeResult {
                service: m.service.to_string(),
                product: m.product.to_string(),
                version,
            });
        }
    }
    None
}

/// Try all probes against a banner. This is the main entry point.
/// For the NULL probe, the banner is whatever the server sent on connect.
/// For the HTTP probe, the banner is the HTTP response.
///
/// `is_http_response` should be true if an HTTP GET was sent to solicit the
/// banner (so we try HTTP patterns), false for a passive/NULL read.
pub fn identify_from_probes(banner: &str, is_http_response: bool) -> Option<ProbeResult> {
    // If this looks like an HTTP response, try HTTP patterns first.
    if is_http_response || banner.starts_with("HTTP/") {
        if let Some(result) = match_banner(&PROBES[1], banner) {
            return Some(result);
        }
    }

    // Try NULL probe patterns (SSH, FTP, SMTP, etc.)
    if let Some(result) = match_banner(&PROBES[0], banner) {
        return Some(result);
    }

    // Try TLS detection
    if let Some(result) = match_banner(&PROBES[2], banner) {
        return Some(result);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_openssh() {
        let banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6";
        let result = identify_from_probes(banner, false).unwrap();
        assert_eq!(result.service, "ssh");
        assert_eq!(result.product, "OpenSSH");
        assert_eq!(result.version.as_deref(), Some("8.9p1"));
    }

    #[test]
    fn test_ssh_generic() {
        let banner = "SSH-2.0-dropbear_2022.83";
        let result = identify_from_probes(banner, false).unwrap();
        assert_eq!(result.service, "ssh");
        assert_eq!(result.version.as_deref(), Some("2.0"));
    }

    #[test]
    fn test_ftp_vsftpd() {
        let banner = "220 (vsFTPd 3.0.5)";
        let result = identify_from_probes(banner, false).unwrap();
        assert_eq!(result.service, "ftp");
        assert_eq!(result.product, "vsFTPd");
        assert_eq!(result.version.as_deref(), Some("3.0.5"));
    }

    #[test]
    fn test_http_nginx() {
        let banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html";
        let result = identify_from_probes(banner, true).unwrap();
        assert_eq!(result.service, "http");
        assert_eq!(result.product, "nginx");
        assert_eq!(result.version.as_deref(), Some("1.18.0"));
    }

    #[test]
    fn test_http_apache() {
        let banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52\r\nContent-Type: text/html";
        let result = identify_from_probes(banner, true).unwrap();
        assert_eq!(result.service, "http");
        assert_eq!(result.product, "Apache httpd");
        assert_eq!(result.version.as_deref(), Some("2.4.52"));
    }

    #[test]
    fn test_http_generic() {
        let banner = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html";
        let result = identify_from_probes(banner, true).unwrap();
        assert_eq!(result.service, "http");
        assert_eq!(result.product, "HTTP");
    }

    #[test]
    fn test_smtp_postfix() {
        let banner = "220 mail.example.com ESMTP Postfix";
        let result = identify_from_probes(banner, false).unwrap();
        assert_eq!(result.service, "smtp");
        assert_eq!(result.product, "Postfix");
    }

    #[test]
    fn test_pop3() {
        let banner = "+OK Dovecot ready.";
        let result = identify_from_probes(banner, false).unwrap();
        assert_eq!(result.service, "pop3");
        assert_eq!(result.product, "Dovecot");
    }

    #[test]
    fn test_mysql_version() {
        let banner = "J\x00\x00\x008.0.32\x00...caching_sha2_password\x00";
        let result = identify_from_probes(banner, false).unwrap();
        assert_eq!(result.service, "mysql");
        assert_eq!(result.product, "MySQL");
        assert_eq!(result.version.as_deref(), Some("8.0.32"));
    }

    #[test]
    fn test_mariadb() {
        let banner = "J\x00\x00\x0010.6.12-MariaDB\x00";
        let result = identify_from_probes(banner, false).unwrap();
        assert_eq!(result.service, "mysql");
        assert_eq!(result.product, "MariaDB");
        assert_eq!(result.version.as_deref(), Some("10.6.12"));
    }

    #[test]
    fn test_redis() {
        let banner = "-NOAUTH Authentication required.";
        let result = identify_from_probes(banner, false).unwrap();
        assert_eq!(result.service, "redis");
    }

    #[test]
    fn test_vnc() {
        let banner = "RFB 003.008\n";
        let result = identify_from_probes(banner, false).unwrap();
        assert_eq!(result.service, "vnc");
        assert_eq!(result.product, "VNC");
        assert_eq!(result.version.as_deref(), Some("003.008"));
    }

    #[test]
    fn test_no_match() {
        let banner = "some random garbage data";
        assert!(identify_from_probes(banner, false).is_none());
    }
}
