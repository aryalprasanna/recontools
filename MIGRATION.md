# Migration Guide: Monolithic to Modular Architecture

## Overview

The `recon_tool.py` codebase has been successfully refactored from a 1,400+ line monolithic script into a well-organized modular package structure. This guide explains what changed and how to use the new structure.

## What Changed

### Before: Monolithic Structure
```
recon_tool.py  (1,400+ lines with everything in one file)
```

### After: Modular Structure
```
main.py                           # Entry point
core/dataclasses.py              # All data structures
modules/
  ├── dns_recon.py
  ├── ip_intel.py
  ├── port_scanner.py
  ├── ssl_check.py
  ├── whois_lookup.py
  ├── subdomain_enum.py
  ├── header_analysis.py
  ├── fingerprinting.py
  ├── async_port_scan.py
  └── geoip_map.py
utils/
  ├── formatter.py
  └── exporter.py
```

## Key Benefits

1. **Easier Maintenance** - Changes to one module don't affect others
2. **Better Testing** - Each module can be tested independently
3. **Code Reusability** - Import specific modules into other projects
4. **Clearer Organization** - Related functionality grouped logically
5. **Simpler Debugging** - Easier to trace issues to specific modules
6. **Scalability** - Simple to add new reconnaissance modules

## How to Use

### Run the Tool

The command-line interface remains **unchanged**:

```bash
# Basic usage (runs default modules: DNS, IP Intel, Ports, SSL)
python main.py example.com

# Specific modules
python main.py example.com --dns --ssl --headers

# All modules
python main.py example.com --all

# With export
python main.py example.com --all --export json --output results

# Async port scanning
python main.py example.com --async-ports
```

### Import Individual Modules (New!)

You can now import and use specific modules:

```python
from modules.dns_recon import DNSModule
from modules.whois_lookup import WHOISModule

# Use them independently
dns_results = DNSModule.lookup_all("example.com")
whois_info = WHOISModule.lookup("example.com")
```

## File Mapping Reference

| Old Location | New Location | Class |
|---|---|---|
| recon_tool.py (lines 149-206) | modules/dns_recon.py | DNSModule |
| recon_tool.py (lines 212-295) | modules/ip_intel.py | IPIntelModule |
| recon_tool.py (lines 301-433) | modules/port_scanner.py | SocketScannerModule |
| recon_tool.py (lines 439-553) | modules/ssl_check.py | SSLModule |
| recon_tool.py (lines 739-790) | modules/whois_lookup.py | WHOISModule |
| recon_tool.py (lines 796-843) | modules/subdomain_enum.py | SubdomainModule |
| recon_tool.py (lines 849-909) | modules/header_analysis.py | HeaderAnalysisModule |
| recon_tool.py (lines 915-967) | modules/fingerprinting.py | FingerprintModule |
| recon_tool.py (lines 973-1056) | modules/async_port_scan.py | AsyncPortScannerModule |
| recon_tool.py (lines 49-143) | core/dataclasses.py | All dataclasses |
| recon_tool.py (lines 559-733) | utils/formatter.py | ResultFormatter |
| recon_tool.py (lines 1062-1159) | utils/exporter.py | ExportModule |

## Backward Compatibility

- **Command-line interface**: 100% compatible - all flags work as before
- **Functionality**: All features work identically
- **Output format**: Results display the same way
- **Export formats**: JSON, CSV, GeoJSON export unchanged

The old `recon_tool.py` file is still present for reference but **should not be used** going forward.

## Adding New Features

### Add a New Reconnaissance Module

1. Create `modules/my_module.py`:
```python
from core.dataclasses import MyDataClass  # or create one in core/dataclasses.py

class MyModule:
    @staticmethod
    def do_reconnaissance(target: str):
        # Implementation here
        return MyDataClass(...)
```

2. Update `modules/__init__.py`:
```python
from modules.my_module import MyModule

__all__ = [
    # ... existing exports
    'MyModule',
]
```

3. Use in `main.py`:
```python
from modules.my_module import MyModule

# In main() function
my_results = MyModule.do_reconnaissance(target)
```

### Add a New Data Structure

Just add it to `core/dataclasses.py`:

```python
from dataclasses import dataclass
from typing import Optional, List

@dataclass
class MyData:
    field1: str
    field2: Optional[int] = None
```

## Troubleshooting

### Import Errors
If you see import errors, make sure:
- You're running from the root directory: `cd /path/to/recontools`
- All `__init__.py` files exist in each package
- Python path includes the project root

### Missing Dependencies
Install requirements:
```bash
pip install -r requirements.txt
```

## Testing

Test individual modules:

```python
# In Python REPL or test script
from modules.dns_recon import DNSModule
from modules.ip_intel import IPIntelModule

# Test DNS
results = DNSModule.lookup_all("google.com")
print(results)

# Test IP Intel
ip_results = IPIntelModule.get_ip_intel("8.8.8.8")
print(ip_results)
```

## Migration Checklist

- [x] Extracted all dataclasses into `core/dataclasses.py`
- [x] Created 10 independent module files in `modules/`
- [x] Separated formatter logic into `utils/formatter.py`
- [x] Separated export logic into `utils/exporter.py`
- [x] Updated all imports to use absolute paths
- [x] Created `main.py` entry point with unchanged CLI
- [x] Added `__init__.py` files for all packages
- [x] Validated all modules compile successfully
- [x] Tested CLI with various flag combinations
- [x] Tested export to JSON and CSV
- [x] Created documentation of new structure

## Next Steps

- Consider adding unit tests for each module
- Add integration tests for common workflows
- Document API of each module for external use
- Create example scripts showing module usage
