"""Subdomain enumeration module."""

import socket
from typing import List

from core.dataclasses import DNSRecord


class SubdomainModule:
    """Subdomain enumeration module for discovering subdomains."""
    
    # Common subdomains wordlist
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
        'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
        'portal', 'admin', 'admin', 'api', 'blog', 'cdn', 'dev', 'dev', 'git',
        'staging', 'stage', 'prod', 'production', 'qa', 'quality', 'search', 'secure',
        'shop', 'support', 'vpn', 'wiki', 'apps', 'assets', 'backup', 'calendar',
        'chat', 'crm', 'dashboard', 'db', 'dns', 'docs', 'download', 'email',
        'erp', 'files', 'gw', 'help', 'home', 'images', 'info', 'internal',
        'intranet', 'it', 'knowledge', 'lab', 'legacy', 'library', 'live', 'logs',
        'manager', 'media', 'mobile', 'monitor', 'mx', 'mysql', 'net', 'network',
        'news', 'ota', 'pay', 'payment', 'people', 'photo', 'photos', 'platform',
        'plesk', 'promo', 'proxy', 'public', 'rep', 'report', 'resource', 'rs',
        'rtc', 's3', 'sandbox', 'sap', 'secure', 'server', 'services', 'share',
        'sms', 'soap', 'social', 'software', 'source', 'sql', 'ssh', 'ssl',
        'status', 'storage', 'store', 'stream', 'sys', 'sysadmin', 'system', 'tech',
        'test', 'testing', 'ticketing', 'tmp', 'tools', 'tracker', 'training',
        'transfer', 'traveler', 'tunnel', 'tv', 'twitter', 'upload', 'uptime',
        'us', 'user', 'users', 'video', 'voip', 'vpn', 'wap', 'ware',
        'warehouse', 'weather', 'webcam', 'webdev', 'webhook', 'webserver', 'website',
        'whois', 'widget', 'windows', 'wireless', 'wpad', 'ww', 'www2', 'www3',
        'www4', 'www5', 'www6', 'www7', 'www8', 'www9', 'wwwdev', 'wwwtest',
        'xs', 'xss', 'yard', 'yardım', 'yara', 'yb', 'yc', 'yellow',
        'yes', 'yld', 'yml', 'you', 'young', 'yours', 'youth', 'yp', 'yr',
        'z', 'zabbix', 'zapier', 'zd', 'zendesk', 'zero', 'zeronet', 'zeus',
        'zip', 'zl', 'zn', 'zo', 'zone', 'zonefile', 'zoo', 'zoom', 'zoneminder'
    ]

    @staticmethod
    def enumerate(domain: str) -> List[str]:
        """Enumerate common subdomains for a domain."""
        discovered = []
        
        for subdomain in SubdomainModule.COMMON_SUBDOMAINS:
            full_domain = f"{subdomain}.{domain}"
            try:
                socket.gethostbyname(full_domain)
                discovered.append(full_domain)
            except (socket.gaierror, socket.timeout):
                pass
            except Exception:
                pass
        
        return discovered
