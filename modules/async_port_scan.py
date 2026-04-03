"""Async port scanning module."""

import asyncio
import sys
from typing import List, Optional

try:
    import aiohttp
except ImportError:
    aiohttp = None

from core.dataclasses import PortStatus
from modules.port_scanner import SocketScannerModule


class AsyncPortScannerModule:
    """Async port scanner for concurrent port scanning."""
    
    COMMON_PORTS = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        443: 'HTTPS',
        8080: 'HTTP-Alt',
        3389: 'RDP'
    }

    @staticmethod
    def scan_common_ports(target_ip: str, target_ports: Optional[List[int]] = None) -> List[PortStatus]:
        """Scan common ports asynchronously."""
        if aiohttp:
            return asyncio.run(AsyncPortScannerModule._async_scan(target_ip, target_ports))
        else:
            # Fallback to original socket scanner
            return SocketScannerModule.scan_common_ports(target_ip, target_ports)

    @staticmethod
    async def _async_scan(target_ip: str, target_ports: Optional[List[int]] = None) -> List[PortStatus]:
        """Async scan implementation."""
        tasks = []
        ports_to_scan = target_ports if target_ports else list(AsyncPortScannerModule.COMMON_PORTS.keys())
        for port in ports_to_scan:
            service = AsyncPortScannerModule.COMMON_PORTS.get(port, f"Port {port}")
            task = AsyncPortScannerModule._scan_port(target_ip, port, service)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        return [r for r in results if r]

    @staticmethod
    async def _scan_port(target_ip: str, port: int, service: str) -> Optional[PortStatus]:
        """Scan a single port asynchronously."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, port),
                timeout=3
            )
            writer.close()
            await writer.wait_closed()
            
            banner = await AsyncPortScannerModule._grab_banner(target_ip, port)
            return PortStatus(port=port, status='OPEN', service=service, banner=banner)
        except asyncio.TimeoutError:
            return PortStatus(port=port, status='FILTERED', service=service)
        except ConnectionRefusedError:
            return PortStatus(port=port, status='CLOSED', service=service)
        except Exception:
            return PortStatus(port=port, status='ERROR', service=service)

    @staticmethod
    async def _grab_banner(target_ip: str, port: int) -> Optional[str]:
        """Grab service banner asynchronously."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, port),
                timeout=2
            )
            
            # Special handling for HTTP/HTTPS
            if port in [80, 8080, 8443]:
                writer.write(b'HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n')
            else:
                writer.write(b'\r\n')
            
            await writer.drain()
            
            try:
                data = await asyncio.wait_for(reader.read(500), timeout=1)
                banner = data.decode('utf-8', errors='ignore').strip()
                return banner[:100] if banner else None
            except Exception:
                return None
            finally:
                writer.close()
                await writer.wait_closed()
        except Exception:
            return None
