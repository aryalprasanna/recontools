# Project Structure

This project has been refactored from a monolithic `recon_tool.py` into a modular package architecture for better maintainability, testability, and code organization.

## Directory Layout

```
recontools/
├── main.py                    # Entry point with CLI orchestration
├── core/
│   ├── __init__.py
│   └── dataclasses.py         # All data structures (DNSRecord, IPIntel, etc.)
├── modules/
│   ├── __init__.py
│   ├── dns_recon.py          # DNS reconnaissance module
│   ├── ip_intel.py            # IP intelligence lookup module
│   ├── port_scanner.py        # Synchronous port scanning
│   ├── ssl_check.py           # SSL/TLS certificate analysis
│   ├── whois_lookup.py        # WHOIS information retrieval
│   ├── subdomain_enum.py      # Subdomain enumeration
│   ├── header_analysis.py     # HTTP header analysis
│   ├── fingerprinting.py      # Web service fingerprinting
│   ├── async_port_scan.py     # Asynchronous port scanning
│   └── geoip_map.py           # GeoIP data mapping
├── utils/
│   ├── __init__.py
│   ├── formatter.py           # Result formatting and display
│   └── exporter.py            # JSON/CSV/GeoJSON export functionality
└── requirements.txt           # Python dependencies
```

## Module Descriptions

### Core Package (`core/`)

**dataclasses.py** - Contains all data structures:
- `DNSRecord` - DNS query results
- `IPIntel` - IP geolocation and ASN data
- `PortStatus` - Port scan results
- `SSLInfo` - SSL/TLS certificate information
- `WHOISInfo` - WHOIS lookup results
- `HeaderInfo` - HTTP response headers
- `Fingerprint` - Technology fingerprinting results
- `GeoIPData` - Geographic IP mapping data

### Modules Package (`modules/`)

Each module is self-contained with its own logic:

**dns_recon.py** - `DNSModule`
- Fetches DNS records (A, MX, TXT, CNAME, NS)
- Uses dnspython library for queries
- Methods: `fetch_records()`, `lookup_all()`

**ip_intel.py** - `IPIntelModule`
- IP geolocation via ip-api.com
- Includes ISP and ASN detection
- Methods: `get_ip_intel()`, `resolve_domain_to_ip()`

**port_scanner.py** - `SocketScannerModule`
- Synchronous port scanning using sockets
- Banner grabbing capability
- Methods: `scan_port()`, `scan_common_ports()`

**ssl_check.py** - `SSLModule`
- SSL/TLS certificate retrieval and analysis
- Expiry checking and SAN extraction
- Methods: `get_certificate()`

**whois_lookup.py** - `WHOISModule`
- WHOIS information retrieval
- Falls back to socket-based lookup if library unavailable
- Methods: `lookup()`

**subdomain_enum.py** - `SubdomainModule`
- Subdomain discovery via DNS resolution
- Built-in wordlist of 150+ common subdomains
- Methods: `enumerate()`

**header_analysis.py** - `HeaderAnalysisModule`
- HTTP header extraction and analysis
- Security header detection
- Methods: `analyze()`

**fingerprinting.py** - `FingerprintModule`
- Technology stack detection via header patterns
- Identifies web servers, CMSes, frameworks
- Methods: `fingerprint()`

**async_port_scan.py** - `AsyncPortScannerModule`
- Concurrent async port scanning (3x faster)
- Falls back to sync scanner if aiohttp unavailable
- Methods: `scan_common_ports()` (wraps async implementation)

**geoip_map.py** - `GeoIPModule`
- GeoIP data transformation and mapping
- Creates GeoJSON-compatible output
- Methods: `create_from_ip_intel()`

### Utilities Package (`utils/`)

**formatter.py** - `ResultFormatter`
- Formats and displays results in CLI
- Methods for each module type:
  - `print_dns_results()`
  - `print_ip_intel()`
  - `print_port_scan_results()`
  - etc.

**exporter.py** - `ExportModule`
- Export results to multiple formats
- Methods: `export_json()`, `export_csv()`, `export_geojson()`

## Import Structure

All imports use absolute paths from the project root:
```python
# In any module file
from core.dataclasses import DNSRecord, IPIntel
from modules.dns_recon import DNSModule
from utils.formatter import ResultFormatter
```

This approach ensures:
- No circular import issues
- Consistent import paths across the project
- Easy to run from different directories
- Simple to extend with new modules

## Running the Tool

```bash
# Basic usage
python main.py example.com

# With specific modules
python main.py example.com --dns --ssl --headers

# All modules
python main.py example.com --all

# With export
python main.py example.com --all --export json --output results
```

## Adding New Modules

1. Create new file in `modules/` directory
2. Import necessary dataclasses from `core.dataclasses`
3. Implement module class with static methods
4. Update `modules/__init__.py` to export the class
5. Import and use in `main.py`
6. (Optional) Add formatter method to `utils.formatter.ResultFormatter`

Example:

```python
# modules/new_module.py
from core.dataclasses import SomeDataclass

class NewModule:
    @staticmethod
    def do_something(target: str):
        # Implementation
        return result

# modules/__init__.py
from .new_module import NewModule

# main.py
from modules.new_module import NewModule
```

## Testing

Each module can be tested independently:

```python
# Test a specific module
from modules.dns_recon import DNSModule
results = DNSModule.lookup_all("google.com")
```

## Benefits of Modular Architecture

1. **Maintainability** - Changes to one module don't affect others
2. **Testability** - Each module can be unit tested independently
3. **Scalability** - Easy to add new reconnaissance modules
4. **Readability** - Clear separation of concerns
5. **Reusability** - Modules can be imported and used independently
6. **Debugging** - Easier to identify and fix issues in specific modules

## Dependencies

See `requirements.txt` for a complete list:
- `dnspython` - DNS queries
- `python-whois` - WHOIS lookups (optional with fallback)
- `aiohttp` - Async HTTP (optional with sync fallback)
- `requests` - HTTP requests

All optional dependencies have fallback implementations for graceful degradation.
