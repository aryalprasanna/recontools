"""Port scanning module."""

import socket
import sys
import time
from typing import List, Optional

from core.dataclasses import PortStatus


class SocketScannerModule:
    """
    Lightweight port scanner using socket library.
    Includes basic banner grabbing capability.
    """

    DEFAULT_PORTS = {
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

    TIMEOUT = 3
    BANNER_TIMEOUT = 2

    @staticmethod
    def scan_port(host: str, port: int, service_name: str = '') -> PortStatus:
        """
        Scan a single port and attempt banner grab.

        Args:
            host: Target hostname or IP
            port: Port number to scan
            service_name: Name of the service (optional)

        Returns:
            PortStatus object with scan results
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SocketScannerModule.TIMEOUT)

        try:
            # Attempt connection
            result = sock.connect_ex((host, port))

            if result == 0:
                # Port is open, attempt banner grab
                banner = SocketScannerModule._grab_banner(sock, host, port)
                return PortStatus(
                    port=port,
                    status='OPEN',
                    service=service_name or f'Port {port}',
                    banner=banner
                )
            else:
                return PortStatus(
                    port=port,
                    status='CLOSED',
                    service=service_name or f'Port {port}'
                )

        except socket.timeout:
            return PortStatus(
                port=port,
                status='FILTERED',
                service=service_name or f'Port {port}'
            )
        except Exception as e:
            return PortStatus(
                port=port,
                status='ERROR',
                service=service_name or f'Port {port}',
                banner=str(e)
            )
        finally:
            sock.close()

    @staticmethod
    def _grab_banner(sock: socket.socket, host: str, port: int) -> Optional[str]:
        """
        Attempt to grab service banner from open port.

        Args:
            sock: Connected socket
            host: Target host
            port: Target port

        Returns:
            Banner string or None if unable to grab
        """
        try:
            sock.settimeout(SocketScannerModule.BANNER_TIMEOUT)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner if banner else None
        except:
            # Some services require a request before responding
            # For HTTP/HTTPS, try a basic HEAD request
            if port in [80, 443, 8080]:
                try:
                    import ssl
                    if port == 443:
                        sock_ssl = ssl.wrap_socket(sock)
                        sock_ssl.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock_ssl.recv(1024).decode('utf-8', errors='ignore').strip()
                        return banner[:100] if banner else None
                    else:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                        return banner[:100] if banner else None
                except:
                    return None
            return None

    @staticmethod
    def scan_common_ports(host: str, target_ports: Optional[List[int]] = None) -> List[PortStatus]:
        """
        Scan common or specific ports on a target host.

        Args:
            host: Target hostname or IP
            target_ports: Optional list of specific ports to scan

        Returns:
            List of PortStatus objects
        """
        results = []
        print(f"\n[*] Scanning {host} for open ports...")

        ports_to_scan = target_ports if target_ports else list(SocketScannerModule.DEFAULT_PORTS.keys())

        for port in ports_to_scan:
            service = SocketScannerModule.DEFAULT_PORTS.get(port, f"Port {port}")
            sys.stdout.write(f"\r    Scanning port {port}... ")
            sys.stdout.flush()

            result = SocketScannerModule.scan_port(host, port, service)
            results.append(result)
            time.sleep(0.1)  # Small delay to avoid overwhelming the network

        print("\r" + " " * 50 + "\r", end="")  # Clear the progress line
        return results
