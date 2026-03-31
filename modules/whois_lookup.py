"""WHOIS lookup module."""

import socket
from typing import Optional

try:
    from whois import whois as whois_lookup
except ImportError:
    whois_lookup = None

from core.dataclasses import WHOISInfo


class WHOISModule:
    """WHOIS lookup module for domain and IP ownership information."""

    @staticmethod
    def lookup(target: str) -> Optional[WHOISInfo]:
        """Lookup WHOIS information for domain or IP."""
        try:
            if whois_lookup:
                result = whois_lookup(target)
                whois_info = WHOISInfo(domain=target)
                
                # Extract common fields
                if hasattr(result, 'registrar'):
                    whois_info.registrar = result.registrar
                if hasattr(result, 'creation_date'):
                    whois_info.created_date = str(result.creation_date)
                if hasattr(result, 'updated_date'):
                    whois_info.updated_date = str(result.updated_date)
                if hasattr(result, 'expiration_date'):
                    whois_info.expires_date = str(result.expiration_date)
                if hasattr(result, 'registrant_name'):
                    whois_info.registrant = result.registrant_name
                
                whois_info.raw_data = str(result)
                return whois_info
            else:
                return WHOISModule._socket_whois_lookup(target)
        except Exception as e:
            return None

    @staticmethod
    def _socket_whois_lookup(target: str) -> Optional[WHOISInfo]:
        """Fallback WHOIS lookup using socket connection."""
        try:
            socket_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_conn.settimeout(5)
            socket_conn.connect(("whois.iana.org", 43))
            socket_conn.send(f"{target}\r\n".encode())
            
            data = b""
            while True:
                chunk = socket_conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            socket_conn.close()
            
            raw_data = data.decode('utf-8', errors='ignore')
            return WHOISInfo(domain=target, raw_data=raw_data)
        except Exception:
            return None
