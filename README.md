# Carescanner

Blazingly fast async port scanner that **won't drop your scan report**. Configurable for careful scans or maximum speed, with built-in service detection, proxy support, and a live web dashboard.

## Quick Start

```bash
# Scan a host with default settings (all 65535 ports, TCP)
carescanner -t scanme.nmap.org

# Top 100 ports with banner grabbing
carescanner -t 192.168.1.0/24 --top-ports 100 --banner

# Fast scan with nmap service detection on found ports
carescanner -t 10.0.0.1 --top-ports 1000 --nmap -- -sV -sC

# Quiet mode for scripting
carescanner -t 10.0.0.1 -p 22,80,443 -q --output - -f json | jq .
```

## Features

### Scanning
- **TCP connect scan** — full 3-way handshake
- **UDP scan** — send probe, detect open/closed/filtered
- **SOCKS5 proxy scan** — scan through one or more SOCKS5 proxies
- **IPv6** — full support for IPv6 targets and CIDR notation
- **Ping discovery** (`--ping`) — skip dead hosts before port scanning
- **Scanning strategies** — round-robin (default) or host-first ordering

### Service Detection
- **Banner grabbing** (`--banner`) — reads service banners from open ports
- **Built-in service identification** — recognizes ~35 services (SSH, HTTP, FTP, SMTP, MySQL, Redis, etc.) via regex-based probes, no external tools needed
- **nmap integration** (`--nmap`) — pipe discovered ports to nmap for deep analysis
- **Custom nmap binary** (`--nmap-path ./nmap-static`) — use your own nmap build

### Speed Control
- **Rate limiting** — global (`-r`), per-host (`--ratelimit-per-host`), or time-based (`-M 5min`)
- **Adaptive rate** (`--adaptive`) — auto-adjusts speed based on timeout ratio
- **Concurrency** — up to 65535 concurrent connections (`--max-concurrent-ports`)
- **Auto ulimit** — automatically increases file descriptor limits

### Output
- **Formats** — Text, JSON, Nmap XML, or all at once (`-f all`)
- **Live progress** — colored progress bar with real-time open port discoveries
- **Summary table** — nmap-style colored table after scan completion
- **Stdout pipe** (`--output -`) — pipe results directly to other tools
- **Quiet mode** (`-q`) — no UI, only results. Perfect for scripts.
- **Web dashboard** (`--dashboard 8899`) — live monitoring with filters and sorting

### Reliability
- **Ctrl+C pause menu** — pause scan, save results, resume, or exit at any time
- **Resume** (`--resume-from`) — continue interrupted scans from where you left off
- **Config file** (`carescanner.toml`) — set default options

### Advanced
- **SOCKS5 proxy chains** — route scans through multiple proxies (`--proxy-strategy chain`)
- **Distributed scanning** (`--total-workers 4 --worker-id 0`) — split work across machines
- **Exclude hosts** (`--exclude 10.0.0.0/8`) — skip ranges, supports CIDR and file input
- **Top ports** (`--top-ports 100`) — nmap's top-1000 ports list built in

## Installation

### Pre-built binaries

Download from [Releases](https://github.com/SelfScriptKiddies/carescanner/releases):

| Platform | Binary |
|---|---|
| Linux x86_64 | `carescanner-VERSION-linux-amd64.tar.gz` |
| Linux aarch64 | `carescanner-VERSION-linux-arm64.tar.gz` |
| Windows x86_64 | `carescanner-VERSION-windows-amd64.zip` |

### Build from source

```bash
# Requires Rust 1.80+
cargo install --path .

# Or build a static binary
make linux-amd64
```

### Cross-compilation

```bash
make setup-cross    # install cross (requires Docker)
make all            # Linux amd64 + arm64 + Windows
make release        # + tar.gz/zip archives
make checksums      # SHA256SUMS
```

## Usage Examples

### Basic scans

```bash
# Single host, all ports
carescanner -t 192.168.1.1

# Multiple targets with CIDR
carescanner -t 192.168.1.0/24,10.0.0.0/24

# Specific ports
carescanner -t example.com -p 22,80,443,8080-8090

# From file
carescanner -t file:targets.txt -p file:ports.txt
```

### Service detection

```bash
# Built-in banner detection
carescanner -t 192.168.1.1 --top-ports 100 --banner

# With nmap for deeper analysis
carescanner -t 192.168.1.1 --top-ports 100 --nmap -- -sV -sC -A

# Custom nmap path
carescanner -t host --nmap --nmap-path /opt/nmap/bin/nmap
```

### Speed tuning

```bash
# Fast (10000 scans/sec, 5000 concurrent)
carescanner -t 10.0.0.0/16 -r 10000 --max-concurrent-ports 5000

# Careful (100 scans/sec, adaptive)
carescanner -t target --adaptive -r 100

# Time-boxed
carescanner -t 192.168.1.0/24 -M 5min
```

### Proxy scanning

```bash
# Through Tor
carescanner -t target -s socks5-tcp --proxies socks5://127.0.0.1:9050

# Proxy chain (traffic goes: you -> proxy1 -> proxy2 -> target)
carescanner -t target -s socks5-tcp \
  --proxies "socks5://proxy1:1080,socks5://proxy2:1080" \
  --proxy-strategy chain
```

### Distributed scanning

```bash
# Split across 4 machines (run one per machine with different IDs)
carescanner -t 10.0.0.0/16 --total-workers 4 --worker-id 0 -o results-0.json -f json
carescanner -t 10.0.0.0/16 --total-workers 4 --worker-id 1 -o results-1.json -f json
carescanner -t 10.0.0.0/16 --total-workers 4 --worker-id 2 -o results-2.json -f json
carescanner -t 10.0.0.0/16 --total-workers 4 --worker-id 3 -o results-3.json -f json
```

### Web dashboard

```bash
# Start scan with live dashboard
carescanner -t 192.168.1.0/24 --top-ports 100 --banner --dashboard 8899

# Accessible remotely
carescanner -t targets --dashboard 8899 --dashboard-host 0.0.0.0
```

Open `http://localhost:8899` in your browser for live scan monitoring with filtering and sorting.

### Scripting

```bash
# JSON to stdout, quiet mode
carescanner -t 192.168.1.1 --top-ports 100 -q --output - -f json | jq '.[] | .[].number'

# Save results + resume file on Ctrl+C
# (choose "Exit (save results)" from pause menu)
carescanner -t 192.168.1.0/24 -o results.txt

# Resume interrupted scan
carescanner -t 192.168.1.0/24 -o results.txt --resume-from carescanner.resume
```

## Config File

Create `carescanner.toml` in the current directory or `~/.config/carescanner/config.toml`:

```toml
ratelimit = 5000
timeout = 5
max_concurrent_ports = 2000
banner = true
adaptive = true
nmap_path = "/usr/local/bin/nmap"
nmap_args = ["-sV", "-sC"]
```

CLI flags always override config file values.

## Output Formats

### Text (default)
```
Host: 192.168.1.1
  22/tcp  open  ssh (OpenSSH 8.9p1)
  80/tcp  open  http (nginx/1.18.0)
```

### JSON (`-f json`)
```json
{
  "192.168.1.1": [
    {"number": 22, "protocol": "tcp", "state": "open", "banner": "SSH-2.0-OpenSSH_8.9p1"},
    {"number": 80, "protocol": "tcp", "state": "open", "banner": "HTTP/1.1 200 OK\nServer: nginx/1.18.0"}
  ]
}
```

### Nmap XML (`-f nmap-xml`)
Compatible with tools that parse nmap XML output.

## License

MIT
