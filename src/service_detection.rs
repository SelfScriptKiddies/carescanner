/// Lightweight service identification from banner strings.
/// Covers the most common services without external dependencies.

pub struct ServiceInfo {
    pub name: &'static str,
    pub version: Option<String>,
}

/// Identify a service from a banner string and port number.
pub fn identify(banner: &str, _port: u16) -> Option<ServiceInfo> {
    // Try banner-based detection first (more accurate)
    if let Some(svc) = identify_from_banner(banner) {
        return Some(svc);
    }
    // Fall back to well-known port mapping only if we got a banner
    // (no banner = no point guessing)
    None
}

fn identify_from_banner(banner: &str) -> Option<ServiceInfo> {
    // SSH: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    if banner.starts_with("SSH-") {
        let version = banner.strip_prefix("SSH-").map(|s| s.to_string());
        return Some(ServiceInfo { name: "ssh", version });
    }

    // HTTP responses
    if banner.starts_with("HTTP/") {
        let version = extract_http_server(banner);
        return Some(ServiceInfo { name: "http", version });
    }

    // FTP: "220 (vsFTPd 3.0.5)" or "220-FileZilla Server"
    if banner.starts_with("220") && (banner.contains("FTP") || banner.contains("ftp") || banner.contains("FileZilla")) {
        let version = extract_after(banner, "220").map(|s| s.trim_start_matches([' ', '-']).to_string());
        return Some(ServiceInfo { name: "ftp", version });
    }

    // SMTP: "220 mail.example.com ESMTP Postfix"
    if banner.starts_with("220") && (banner.contains("SMTP") || banner.contains("smtp") || banner.contains("Postfix") || banner.contains("Exim") || banner.contains("Sendmail")) {
        let version = extract_after(banner, "220").map(|s| s.trim_start_matches([' ', '-']).to_string());
        return Some(ServiceInfo { name: "smtp", version });
    }

    // POP3: "+OK Dovecot ready." or "+OK POP3"
    if banner.starts_with("+OK") {
        let version = extract_after(banner, "+OK").map(|s| s.trim().to_string());
        return Some(ServiceInfo { name: "pop3", version });
    }

    // IMAP: "* OK [CAPABILITY IMAP4rev1 ..."
    if banner.starts_with("* OK") && (banner.contains("IMAP") || banner.contains("imap") || banner.contains("Dovecot") || banner.contains("Cyrus")) {
        let version = extract_after(banner, "* OK").map(|s| s.trim().to_string());
        return Some(ServiceInfo { name: "imap", version });
    }

    // MySQL: starts with a version packet, often contains "mysql" or version like "5.7.42"
    if banner.contains("mysql") || banner.contains("MariaDB") || banner.contains("caching_sha2_password") {
        let version = if banner.contains("MariaDB") {
            Some("MariaDB".to_string())
        } else {
            extract_mysql_version(banner)
        };
        return Some(ServiceInfo { name: "mysql", version });
    }

    // PostgreSQL: starts with 'R' (authentication) or contains "PostgreSQL"
    if banner.contains("PostgreSQL") || banner.contains("pgsql") {
        return Some(ServiceInfo { name: "postgresql", version: None });
    }

    // Redis: "+PONG" or "-NOAUTH" or "$..."
    if banner.starts_with("+PONG") || banner.starts_with("-NOAUTH") || banner.contains("redis") || banner.contains("Redis") {
        return Some(ServiceInfo { name: "redis", version: None });
    }

    // MongoDB: contains "mongod" or "MongoDB"
    if banner.contains("MongoDB") || banner.contains("mongod") || banner.contains("ismaster") {
        return Some(ServiceInfo { name: "mongodb", version: None });
    }

    // DNS: unlikely to get a text banner, but just in case
    if banner.contains("BIND") || banner.contains("named") {
        return Some(ServiceInfo { name: "dns", version: None });
    }

    // RDP/Microsoft Terminal Services
    if banner.contains("\x03\x00") || banner.contains("RDP") {
        return Some(ServiceInfo { name: "rdp", version: None });
    }

    // VNC: "RFB 003.008"
    if banner.starts_with("RFB ") {
        let version = Some(banner.to_string());
        return Some(ServiceInfo { name: "vnc", version });
    }

    // AMQP (RabbitMQ): starts with "AMQP"
    if banner.starts_with("AMQP") {
        return Some(ServiceInfo { name: "amqp", version: None });
    }

    // Docker API / generic JSON API
    if banner.starts_with("{\"") || banner.starts_with("[{\"") {
        return Some(ServiceInfo { name: "json-api", version: None });
    }

    // Telnet: often starts with IAC sequences (0xFF)
    if banner.as_bytes().first() == Some(&0xFF) {
        return Some(ServiceInfo { name: "telnet", version: None });
    }

    // HTTPS/TLS: starts with 0x15 or 0x16 (TLS alert or handshake)
    if banner.as_bytes().starts_with(&[0x15, 0x03]) || banner.as_bytes().starts_with(&[0x16, 0x03]) {
        return Some(ServiceInfo { name: "tls/ssl", version: None });
    }

    // Generic 220 banner (could be FTP or SMTP but unidentified)
    if banner.starts_with("220") {
        return Some(ServiceInfo { name: "banner-220", version: Some(banner.to_string()) });
    }

    None
}

fn extract_http_server(banner: &str) -> Option<String> {
    // Look for "Server: <value>" in HTTP response headers
    for part in banner.split('\n') {
        let trimmed = part.trim();
        if let Some(rest) = trimmed.strip_prefix("Server:").or_else(|| trimmed.strip_prefix("server:")) {
            return Some(rest.trim().to_string());
        }
    }
    // If no Server header, return the status line
    Some(banner.chars().take(64).collect())
}

fn extract_after<'a>(banner: &'a str, prefix: &str) -> Option<&'a str> {
    banner.strip_prefix(prefix).map(|s| s.trim())
}

fn extract_mysql_version(banner: &str) -> Option<String> {
    // MySQL banner often contains the version as the first readable ASCII string
    let ascii: String = banner
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == '.' || *c == '-')
        .collect();
    if ascii.is_empty() { None } else { Some(ascii.chars().take(32).collect()) }
}
