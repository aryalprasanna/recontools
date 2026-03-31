
ReconTools

A modular, Python-based tool for comprehensive IP and website analysis. Designed for educational purposes and authorized security testing.

## Features

- **DNS Reconnaissance**: Fetch A, MX, TXT, CNAME, and NS records
- **IP Intelligence**: Geolocation, ISP, and ASN data using ip-api.com
- **Port Scanning**: Scan common ports (21, 22, 23, 25, 53, 80, 443, 8080, 3389) with banner grabbing
- **SSL/TLS Analysis**: Extract certificate details, expiry dates, and Subject Alternative Names (SANs)
- **Clean CLI Interface**: Argument parsing with flexible module selection
- **Comprehensive Error Handling**: Timeout protection and informative error messages

## Installation

### Prerequisites
- Python 3.7+
- pip

### Setup

```bash
# Download the repository
git clone https://github.com/aryalprasanna/recontools.git

# Clone/navigate to the repository
cd /path/to/recon_tool

# Install dependencies
pip install -r requirements.txt
```

**Note**: The tool uses only standard library modules except for `dnspython`. The IP intelligence API (ip-api.com) requires no authentication.

## Usage

### Basic Usage

```bash
# Full reconnaissance (all modules)
python recon_tool.py example.com

# Specific module only
python recon_tool.py example.com --dns
python recon_tool.py example.com --ip-intel
python recon_tool.py example.com --ports
python recon_tool.py example.com --ssl
```

### Advanced Examples

```bash
# Run all modules explicitly
python recon_tool.py example.com --all

# Combine specific modules
python recon_tool.py example.com --dns --ports --ssl

# Analyze an IP address
python recon_tool.py 8.8.8.8 --ip-intel --ports

# Help
python recon_tool.py --help
```

## Module Documentation

### DNS Module (`DNSModule`)
Queries DNS records using dnspython with a 5-second timeout.

**Records fetched**:
- **A Records**: IPv4 addresses
- **MX Records**: Mail exchange servers
- **TXT Records**: Text records (SPF, DKIM, DMARC)
- **CNAME Records**: Canonical name aliases
- **NS Records**: Nameservers

**Error Handling**:
- NXDOMAIN (domain doesn't exist)
- No Answer (record type doesn't exist)
- Connection timeouts

### IP Intelligence Module (`IPIntelModule`)
Retrieves geolocation and ISP data from ip-api.com (free API, no authentication required).

**Data Retrieved**:
- Country, Region, City
- ISP Name
- ASN (Autonomous System Number)
- GPS Coordinates (Latitude/Longitude)

**Limitations**:
- Rate limited to ~45 requests/minute on free tier
- Requires internet connectivity

**Error Handling**:
- HTTP errors
- Connection timeouts
- Invalid JSON responses

### Socket Scanner Module (`SocketScannerModule`)
Lightweight port scanner using raw sockets with banner grabbing.

**Default Ports**:
- 21 (FTP)
- 22 (SSH)
- 23 (Telnet)
- 25 (SMTP)
- 53 (DNS)
- 80 (HTTP)
- 443 (HTTPS)
- 8080 (HTTP-Alt)
- 3389 (RDP)

**Port States**:
- **OPEN**: Successfully connected
- **CLOSED**: Connection refused
- **FILTERED**: Timeout (likely firewalled)
- **ERROR**: Connection error

**Banner Grabbing**:
- Attempts to read service banners from open ports
- Special handling for HTTP/HTTPS (sends HEAD request)
- Limits banner size to 100 characters in output

### SSL Module (`SSLModule`)
Extracts SSL/TLS certificate information using Python's ssl library.

**Data Extracted**:
- Certificate Subject
- Issuer information
- Valid From / Valid Until dates
- Expiration status
- Subject Alternative Names (SANs)

**Error Handling**:
- SSL errors (self-signed, expired, etc.)
- Connection timeouts
- DNS resolution failures
- Port connectivity issues

## Output Example

```
======================================================================
  RECONNAISSANCE: example.com
======================================================================

[*] Resolving example.com...
    Resolved to: 93.184.216.34

======================================================================
  DNS Records
------================================================================

  A Records:
    → 93.184.216.34

  MX Records:
    → 0 .

  TXT Records:
    → "v=spf1 -all"

[*] IP Intelligence
----------------------------------------------------------------------

  IP Address:     93.184.216.34
  Country:        United States
  Region:         California
  City:           Los Angeles
  ISP:            IANA Reserved
  ASN:            AS15169 Google LLC
  Coordinates:    34.0522, -118.2437

[*] Port Scan Results
----------------------------------------------------------------------

  Port     Service              Status     Banner
  ------------------------------------------------------------------
  80       HTTP                 OPEN       HTTP/1.1 200 OK...
  443      HTTPS                OPEN       HTTP/1.1 200 OK...

  Summary: 2 open, 7 closed, 0 filtered

[*] SSL/TLS Certificate
----------------------------------------------------------------------

  Subject:        example.com
  Issuer:         Let's Encrypt Authority X3
  Valid From:     Jan 1 00:00:00 2023 GMT
  Valid Until:    Dec 31 23:59:59 2025 GMT [VALID]

  Subject Alternative Names:
    → example.com
    → www.example.com

======================================================================
[+] Reconnaissance completed
======================================================================
```

## Code Structure

```
recon_tool.py
├── Data Structures (Dataclasses)
│   ├── DNSRecord
│   ├── IPIntel
│   ├── PortStatus
│   └── SSLInfo
├── DNS Module
│   └── DNSModule class
├── IP Intelligence Module
│   └── IPIntelModule class
├── Socket Scanner Module
│   └── SocketScannerModule class
├── SSL Certificate Module
│   └── SSLModule class
├── Formatter & CLI
│   ├── ResultFormatter class
│   └── main() function
└── Entry point
```

## Educational Notes

This tool demonstrates several cybersecurity and networking concepts:

1. **DNS Resolution**: Understanding domain-to-IP mapping
2. **Network Reconnaissance**: Enumeration of services and configurations
3. **Socket Programming**: Low-level network communication
4. **SSL/TLS Security**: Certificate validation and analysis
5. **Error Handling**: Robust timeout and exception handling
6. **API Integration**: Consuming third-party JSON APIs
7. **CLI Design**: Argument parsing and user interface patterns
8. **Code Modularity**: Separating concerns into distinct modules

## Security & Ethical Considerations

⚠️ **Important**: This tool is for:
- ✅ Educational purposes
- ✅ Authorized security testing and penetration testing
- ✅ Network administrators managing their own infrastructure
- ✅ CTF (Capture The Flag) competitions

⚠️ **Do NOT use for**:
- ❌ Unauthorized network scanning
- ❌ Targeting systems you don't own or have permission to test
- ❌ DoS/DDoS attacks
- ❌ Illegal reconnaissance

**Always obtain proper authorization before testing any systems.**

## Timeouts & Performance

- DNS queries: 5 seconds
- Port scanning: 3 seconds per port (total ~27 seconds for 9 ports)
- Banner grabbing: 2 seconds per connection
- SSL certificate retrieval: 10 seconds
- IP intelligence API: 10 seconds

Total execution time typically ranges from 30-60 seconds depending on network conditions.

## Troubleshooting

### ModuleNotFoundError: No module named 'dns'
```bash
pip install dnspython
```

### Network Error: Connection refused
- Ensure target is reachable
- Check firewall rules
- Verify DNS resolution is working

### SSL Certificate Error: CERTIFICATE_VERIFY_FAILED
- Normal for self-signed certificates
- Tool marks certificate as invalid but continues

### Timeout Errors
- Check network connectivity
- Verify target domain/IP is valid
- Try increasing timeout values in source code if network is slow
