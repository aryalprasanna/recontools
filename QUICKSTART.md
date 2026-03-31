# Quick Start Guide

## Installation

```bash
# Install dependencies
pip install --break-system-packages dnspython

# Or use a virtual environment
python -m venv venv
source venv/bin/activate
pip install dnspython
```

## Basic Usage

```bash
# Full reconnaissance (all modules)
python recon_tool.py example.com

# Individual modules
python recon_tool.py example.com --dns          # DNS records
python recon_tool.py example.com --ip-intel     # Geolocation & ISP
python recon_tool.py example.com --ports        # Port scan
python recon_tool.py example.com --ssl          # Certificate info

# Combine modules
python recon_tool.py example.com --dns --ports
```

## Common Scenarios

### Scenario 1: Full Domain Analysis
```bash
python recon_tool.py google.com
```
**What it does**: DNS lookup, IP geolocation, port scanning, SSL analysis

### Scenario 2: Quick DNS Check
```bash
python recon_tool.py example.com --dns
```
**What it does**: Shows A records, MX records, nameservers, TXT records

### Scenario 3: Identify Open Services
```bash
python recon_tool.py 192.168.1.1 --ports
```
**What it does**: Scans 9 common ports and identifies running services

### Scenario 4: GeoIP Lookup
```bash
python recon_tool.py 8.8.8.8 --ip-intel
```
**What it does**: Shows country, city, ISP, coordinates

### Scenario 5: Certificate Audit
```bash
python recon_tool.py company.com --ssl
```
**What it does**: Checks certificate validity, expiry, SANs

## Module Overview

| Module | Command | Purpose |
|--------|---------|---------|
| DNS | `--dns` | Resolve domain, fetch A/MX/TXT/CNAME/NS records |
| IP Intel | `--ip-intel` | Geolocation, ISP, ASN lookup |
| Port Scanner | `--ports` | Scan common ports, grab banners |
| SSL | `--ssl` | Certificate info, expiry, SANs |

## Ports Scanned

```
21   - FTP
22   - SSH
23   - Telnet
25   - SMTP
53   - DNS
80   - HTTP
443  - HTTPS
8080 - HTTP (Alt)
3389 - RDP
```

## Output Interpretation

### Port Status Meanings
- **OPEN**: Service is listening
- **CLOSED**: Port rejects connections (host is up)
- **FILTERED**: No response (likely firewall)

### Certificate Status
- **[VALID]**: Certificate is current
- **[EXPIRED]**: Certificate has expired

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `No module named 'dns'` | Run: `pip install dnspython` |
| `Connection timeout` | Target may be offline or blocking ICMP |
| `SSL Certificate Error` | Normal for self-signed certs; script continues |
| `Permission denied` | May need elevated privileges for raw socket operations |

## Performance Tips

- Single module is 5-15 seconds faster than all modules
- Port scanning takes ~30 seconds (3 sec/port × 9 ports)
- Use `--ports` on IPs directly to skip DNS resolution
- Combine modules if analyzing multiple domains

## Educational Resources

The code demonstrates:
- Python socket programming
- DNS protocol and queries
- SSL/TLS certificate handling
- API integration (ip-api.com)
- Error handling and timeouts
- CLI design with argparse
- Data structures and dataclasses

## Next Steps

- Modify port list in `SocketScannerModule.DEFAULT_PORTS`
- Add custom timeout values
- Extend with additional DNS record types
- Implement WHOIS lookup
- Add export formats (JSON, CSV)

## Security Reminders

✅ **Use for**:
- Your own infrastructure
- Authorized pentesting
- Educational exercises
- CTF competitions

❌ **Don't use for**:
- Unauthorized scanning
- Targeting third-party systems
- DoS attacks
- Illegal activities

**Always get written permission before testing any system.**
