# Routeglass - High speed Router & Network Appliance Fingerprinting Tool

Routeglass is a fast, multi-threaded router fingerprinting tool written in Go.

The goal of the project is simple: identify web-exposed routers, firewalls, gateways, and embedded network devices by fingerprinting HTTP responses instead of relying solely on open ports.

Routeglass currently includes hundreds of fingerprint rules covering consumer, enterprise, ISP, and industrial networking equipment.

---

## Features

- Fast concurrent scanning
- HTTP & HTTPS support
- Single IP scanning
- CIDR support
- IPv4 range support
- Target list file support
- Random browser User-Agent rotation
- Custom User-Agent support
- Multi-port scanning
- Output to file
- Progress bar
- Graceful shutdown (Ctrl+C)
- Vendor & product fingerprinting
- Rule-based detection engine
- Lightweight Go binary
- Cross-platform

---

## Installation

Clone the repository:

```bash
git clone https://github.com/K3ysTr0K3R/Routeglass.git

cd Routeglass
```

Install dependencies:

```bash
go mod tidy
```

Build:

```bash
go build
```

Or specify an output binary:

```bash
go build -o routeglass
```

---

## Usage

### Scan a Single IP

```bash
./routeglass -ip 192.168.1.1
```

### Scan a CIDR

```bash
./routeglass -ip 192.168.1.0/24
```

### Scan an IP Range

```bash
./routeglass -ip 192.168.1.10-192.168.1.100
```

### Scan Targets from a File

```bash
./routeglass -f targets.txt
```

Example `targets.txt`

```text
192.168.1.1
192.168.1.0/24
10.0.0.5-10.0.0.50
```

### Specify Multiple Ports

```bash
./routeglass -ip 192.168.1.0/24 -ports 80,443,8080,8443
```

### Increase Worker Threads

```bash
./routeglass -ip 192.168.1.0/24 -t 250
```

### Save Results

```bash
./routeglass -ip 192.168.1.0/24 -o results.txt
```

### Append Results

```bash
./routeglass -ip 192.168.1.0/24 -o results.txt -append
```

### Custom User-Agent

```bash
./routeglass -ip 192.168.1.1 -user-agent "Mozilla/5.0"
```

### Full Example

```bash
./routeglass \
-ip 10.0.0.0/16 \
-ports 80,443,8080,8443 \
-t 500 \
-o results.txt
```

---

## Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `-ip` | Single IP, CIDR or IP Range | - |
| `-f` | Read targets from file | - |
| `-t` | Number of worker threads | `50` |
| `-ports` | Comma-separated ports | `80` |
| `-o` | Output file | - |
| `-append` | Append instead of overwrite | `false` |
| `-user-agent` | Custom User-Agent | Random Browser |

---

## Example Output

```text
Routeglass - Coded By: K3ysTr0K3R

192.168.1.1:80 [FOUND] MikroTik RouterOS
10.0.0.1:443 [FOUND] Cisco IOS Router
172.16.10.5:8443 [FOUND] Fortinet FortiGate
192.168.10.254:80 [FOUND] TP-Link Archer AX55
10.20.1.15:80 [FOUND] ASUS RT-AX86U

Scan complete.
500 targets scanned.
37 device(s) found.
```

---

## Detection Engine

Routeglass performs fingerprinting using multiple detection methods.

### HTML Title Matching

Detects products based on webpage titles.

Example:

```html
<title>MikroTik RouterOS</title>
```

---

### HTTP Header Matching

Inspects response headers.

Example:

```http
Server: cisco-IOS
```

---

### Body Signature Matching

Searches HTML content for known vendor strings.

Example:

```html
Powered by RouterOS
```

---

### Regular Expression Matching

Supports regex fingerprints for identifying model families.

Example:

```
(?i)tp-link\s+[a-z0-9-]+
```

---

### MD5 Favicon Matching

Calculates the MD5 hash of a favicon and compares it against known fingerprints.

This allows Routeglass to identify devices even when login pages have been customized.

---

## Supported Vendors

Routeglass contains fingerprints for hundreds of networking products including:

- Cisco
- MikroTik
- Ubiquiti
- Fortinet
- Juniper
- TP-Link
- ASUS
- NETGEAR
- D-Link
- Linksys
- Huawei
- ZyXEL
- Tenda
- Nokia
- Palo Alto
- SonicWall
- WatchGuard
- OpenWrt
- DD-WRT
- pfSense
- OPNsense
- VyOS
- Google
- Amazon eero
- GL.iNet
- Teltonika
- Cradlepoint
- Aruba
- Ruckus
- Cambium
- Peplink

...and many more

---

## Performance

Routeglass is designed to efficiently fingerprint large address ranges while maintaining a lightweight memory footprint.

Features include:

- Concurrent worker pool
- Connection reuse
- HTTP response caching
- Fast rule evaluation
- Graceful interrupt handling
- Configurable worker count

---

## Why Routeglass?

Traditional port scanners tell you **what ports are open**.

Routeglass tells you **what device is actually running behind those ports.**

Instead of simply reporting that TCP/80 is open, Routeglass attempts to identify the vendor and exact product using multiple fingerprinting techniques.

This makes it useful during:

- Asset discovery
- Network inventory
- Security assessments
- Red team engagements
- Penetration testing
- Exposure monitoring
- Research projects

---

## Requirements

- Go 1.24+
- Internet connectivity (or local network access)
- Windows, Linux or macOS

---

## Roadmap

Planned improvements include:

- IPv6 support
- Custom fingerprint rule loading
- JSON output
- YAML output
- CSV export
- HTTP/2 fingerprinting
- Screenshot collection
- Web interface
- Automatic rule updates
- Plugin system

---

## Disclaimer

This project was created for security research, defensive security assessments, asset inventory, and authorized penetration testing.

Only scan systems that you own or have explicit permission to assess.

The author assumes no responsibility for misuse or damage caused by this software.
