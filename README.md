ReconTools

A modular, Python-based tool for comprehensive IP and website analysis. Designed for educational purposes and authorized security testing.

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
**Note**: The tool uses only standard library modules except for `dnspython`. 

**To use the tool:**
```bash
python main.py example.com
python main.py example.com --all --export json
python main.py example.com --help
```

## 📁 Project Structure

```
recontools/
├── main.py                    # Entry point
├── core/
│   ├── __init__.py
│   └── dataclasses.py        # 8 data structures
├── modules/                   # 10 independent modules
│   ├── dns_recon.py          # DNS lookups
│   ├── ip_intel.py           # IP geolocation
│   ├── port_scanner.py       # Port scanning
│   ├── ssl_check.py          # SSL analysis
│   ├── whois_lookup.py       # WHOIS lookups
│   ├── subdomain_enum.py     # Subdomain enumeration
│   ├── header_analysis.py    # HTTP headers
│   ├── fingerprinting.py     # Tech fingerprinting
│   ├── async_port_scan.py    # Async port scanning
│   └── geoip_map.py          # GeoIP mapping
├── utils/                     # Utilities
    ├── formatter.py          # Output formatting
    └── exporter.py           # JSON/CSV/GeoJSON export
```

## 🚀 Usage Examples

```bash
# Basic reconnaissance (default modules: DNS, IP Intel, Ports, SSL)
python main.py example.com

# Specific modules
python main.py example.com --dns --ssl --headers

# All modules
python main.py example.com --all

# With export
python main.py example.com --all --export json --output results

# Async port scanning (3x faster)
python main.py example.com --async-ports

# Help
python main.py --help
```

##Troubleshooting

**Import errors?**
- Ensure you're in the project root directory
- Verify all `__init__.py` files exist
- Check Python path includes project root

**Missing dependencies?**
```bash
pip install -r requirements.txt
```

## 🤝 Contributing

When adding new features:
1. Create module in `modules/` if it's a new reconnaissance type
2. Add dataclasses to `core/dataclasses.py` if needed
3. Update `modules/__init__.py` to export new module
4. Add CLI logic to `main.py`
5. Update documentation

