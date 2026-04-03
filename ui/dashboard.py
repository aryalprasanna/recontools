"""Textual TUI for ReconTools."""

import asyncio
from typing import Dict, Any

from textual.app import App, ComposeResult
from textual.containers import Grid, Vertical, Horizontal
from textual.widgets import Header, Footer, Static, RichLog, ProgressBar, OptionList
from textual import work

from core.dataclasses import GeoIPData
from modules.dns_recon import DNSModule
from modules.ip_intel import IPIntelModule
from modules.port_scanner import SocketScannerModule
from modules.async_port_scan import AsyncPortScannerModule
from modules.ssl_check import SSLModule
from modules.whois_lookup import WHOISModule
from modules.subdomain_enum import SubdomainModule
from modules.header_analysis import HeaderAnalysisModule
from modules.fingerprinting import FingerprintModule
from modules.cve_mapping import CVEModule
from modules.web_screenshot import WebScreenshotModule
from modules.intel_aggregator import IntelAggregatorModule
from utils.exporter import ExportModule

CSS = """
Grid {
    grid-size: 3 3;
    grid-rows: 3 1fr 1fr;
    grid-columns: 25 1fr 1fr;
}

#top-bar {
    column-span: 3;
    height: 100%;
    min-width: 10;
    layout: horizontal;
    background: $panel;
    border: round $primary;
}

#sidebar {
    background: $surface;
    border: round $warning;
    min-width: 10;
    height: 100%;
}

#left-col {
    background: $surface;
    border: round $accent;
    min-width: 10;
    height: 100%;
}

#right-col {
    background: $surface;
    border: round $secondary;
    min-width: 10;
    height: 100%;
}

#log-box {
    column-span: 3;
    background: $boost;
    border: round $success;
    min-width: 10;
    height: 100%;
}

.box-title {
    background: $primary;
    color: $text;
    text-align: center;
    text-style: bold;
}

#top-bar > * {
    min-width: 5;
}

#target-info {
    min-width: 5;
}

#progress {
    margin: 1;
    width: 30%;
    min-width: 15;
}

#process-monitor {
    width: 1fr;
    min-width: 1;
    content-align: right middle;
}

RichLog {
}

OptionList {
    height: 100%;
}

* {
    min-width: 1;
}
"""

class ReconDashboard(App):
    """Modern TUI for ReconTools."""
    
    CSS = CSS
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("s", "toggle_export", "Export Results")
    ]

    def __init__(self, target: str, options: dict, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.target = target
        self.options = options
        self.results: Dict[str, Any] = {}
        self.target_ip: str = ""
        self.active_processes: Dict[str, str] = {}
        self.subdomains_list = []

    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Header()
        
        with Grid():
            # Top Bar & Process Monitor
            with Horizontal(id="top-bar"):
                yield Static(f" Target: {self.target} ", id="target-info", classes="box-title")
                yield ProgressBar(total=100, show_eta=False, id="progress")
                yield Static("Initializing...", id="process-monitor")
                
            # Sidebar (Discovery)
            with Vertical(id="sidebar"):
                yield Static("The Discovery", classes="box-title")
                yield OptionList(id="discovery-list")
                
            # Left Column (General Intel)
            with Vertical(id="left-col"):
                yield Static("General Intel", classes="box-title")
                yield Static("", id="general-content")
                yield Static("", id="visual-indicators-left")
                
            # Right Column (Network & Risk)
            with Vertical(id="right-col"):
                yield Static("Network & Risk", classes="box-title")
                yield Static("", id="network-content")
                yield Static("", id="visual-indicators-right")
                
            # Bottom Log
            with Vertical(id="log-box"):
                yield Static("Live Log", classes="box-title")
                yield RichLog(id="activity-log", markup=True)
                
        yield Footer()

    def on_mount(self) -> None:
        """Called when app starts."""
        options_list = self.query_one("#discovery-list", OptionList)
        options_list.add_option(self.target)

        self.log_msg(f"[bold green]Starting reconnaissance on {self.target}...[/bold green]")
        self.run_recon(self.target, is_main=True)

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        """Handle tree node selection to show specific intel."""
        selected = str(event.option.prompt)
        
        if selected == self.target:
            # Root node
            self.log_msg("[*] Returning to primary domain view.")
            return

        self.log_msg(f"[*] Focused on subdomain: {selected}")
        
        # We update the UI to indicate focus
        self.query_one("#target-info", Static).update(f" Target: {selected} ")
        self.query_one("#general-content", Static).update(f"Running mini-scan for [bold]{selected}[/bold]...")
        self.query_one("#network-content", Static).update("Awaiting data...")
        self.query_one("#visual-indicators-left", Static).update("")
        self.query_one("#visual-indicators-right", Static).update("")
        
        # Fire off a mini-scan for the subdomain
        self.run_mini_scan(selected)

    def update_process_monitor(self) -> None:
        """Update the process monitor UI."""
        status = " ".join([f"[{k}: {v}]" for k, v in self.active_processes.items()])
        try:
            self.query_one("#process-monitor", Static).update(status)
        except Exception:
            pass

    def log_msg(self, message: str) -> None:
        """Write to the rich log."""
        try:
            log_widget = self.query_one("#activity-log", RichLog)
            log_widget.write(message)
        except Exception:
            pass

    def set_process_state(self, proc: str, state: str) -> None:
        color = "yellow" if state == "Running" else "green" if state == "Done" else "white"
        self.active_processes[proc] = f"[{color}]{state}[/{color}]"
        self.call_from_thread(self.update_process_monitor)

    def append_general_intel(self, append_text: str) -> None:
        """Update the left column."""
        widget = self.query_one("#general-content", Static)
        current = widget.renderable
        widget.update(f"{current}\n{append_text}")

    def append_network(self, append_text: str) -> None:
        """Update the right column."""
        widget = self.query_one("#network-content", Static)
        current = widget.renderable
        widget.update(f"{current}\n{append_text}")
        
    def add_visual_indicator(self, side: str, indicator: str) -> None:
        if side == "left":
            widget = self.query_one("#visual-indicators-left", Static)
        else:
            widget = self.query_one("#visual-indicators-right", Static)
        current = widget.renderable
        widget.update(f"{current}\n{indicator}")

    def add_subdomain_to_tree(self, subdomain: str) -> None:
        options_list = self.query_one("#discovery-list", OptionList)
        options_list.add_option(subdomain)

    @work(exclusive=False, thread=True)
    def run_mini_scan(self, target: str) -> None:
        """Run a fast sync scan on a selected subdomain from the tree."""
        self.set_process_state(f"MiniScan:{target}", "Running")
        self.log_msg(f"[*] Starting mini-scan against {target}...")
        
        # IP Lookup
        resolved_ip = IPIntelModule.resolve_domain_to_ip(target)
        if resolved_ip:
            self.call_from_thread(self.append_general_intel, f"IP: [cyan]{resolved_ip}[/cyan]")
            
            # GeoIP lookup
            intel = IPIntelModule.get_ip_intel(resolved_ip)
            if intel:
                self.call_from_thread(self.append_general_intel, f"Location: {intel.city}, {intel.country}")
            
            # Fast DNS
            try:
                dns = DNSModule.lookup_all(target)
                a_records = []
                
                # Gracefully iterate since data may be dict keys (strings) or mixed lists
                items = dns.values() if isinstance(dns, dict) else dns
                for r in items:
                    if r is None or isinstance(r, str):
                        continue
                    if hasattr(r, 'record_type') and getattr(r, 'record_type') == 'A':
                        a_records = getattr(r, 'values', [])
                        break
                        
                self.call_from_thread(self.append_network, f"DNS A Records: {a_records}")
            except Exception as e:
                self.log_msg(f"[red][!] Error parsing mini-scan DNS data: {str(e)}[/red]")
        else:
            self.call_from_thread(self.append_general_intel, f"[-] Could not resolve {target}")

        self.set_process_state(f"MiniScan:{target}", "Done")

    @work(exclusive=True, thread=True)
    def run_recon(self, target: str, is_main: bool = True) -> None:
        """Run all recon modules asynchronously in a worker thread."""
        pb = self.query_one("#progress", ProgressBar)
        self.active_processes.clear()
        
        # Subdomain Enumeration
        if self.options.get("subdomains"):
            self.set_process_state("Subdomains", "Running")
            self.log_msg("[*] Enumerating Subdomains...")
            subdomains = SubdomainModule.enumerate(target)
            if subdomains:
                self.subdomains_list = subdomains
                self.call_from_thread(self.add_visual_indicator, 'left', f"[yellow]🟡 {len(subdomains)} Subdomains Found[/yellow]")
                for sub in subdomains:
                    self.call_from_thread(self.add_subdomain_to_tree, sub)
                self.log_msg(f"[+] Found {len(subdomains)} subdomains.")
            self.set_process_state("Subdomains", "Done")
            
        pb.advance(10)
        
        # IP Resolution
        self.set_process_state("IP Lookup", "Running")
        self.log_msg("[*] Resolving domain to IP...")
        if self.options.get("ip_intel") or self.options.get("ports"):
            self.target_ip = IPIntelModule.resolve_domain_to_ip(target)
            if self.target_ip:
                self.log_msg(f"[+] Resolved {target} to [bold cyan]{self.target_ip}[/bold cyan]")
                self.call_from_thread(self.append_general_intel, f"IP: {self.target_ip}")
            else:
                self.log_msg(f"[-] Could not resolve {target}")
                self.target_ip = target
        self.set_process_state("IP Lookup", "Done")
        pb.advance(10)
        
        if self.options.get("whois"):
            self.set_process_state("WHOIS", "Running")
            self.log_msg("[*] Running WHOIS lookup...")
            whois_info = WHOISModule.lookup(target)
            self.results['whois'] = whois_info
            if whois_info:
                reg = whois_info.registrar or 'Unknown'
                self.call_from_thread(self.append_general_intel, f"WHOIS Registrar: {reg}")
            self.set_process_state("WHOIS", "Done")
        pb.advance(10)
        
        if self.options.get("ip_intel") and self.target_ip and self.target_ip != target:
            self.set_process_state("GeoIP", "Running")
            self.log_msg("[*] Running IP Intel...")
            ip_intel = IPIntelModule.get_ip_intel(self.target_ip)
            self.results['ip_intelligence'] = ip_intel
            if ip_intel:
                self.call_from_thread(self.append_general_intel, f"Location: {ip_intel.city}, {ip_intel.country}")
            self.set_process_state("GeoIP", "Done")
        pb.advance(5)
        
        if self.options.get("ssl"):
            self.set_process_state("SSL", "Running")
            self.log_msg("[*] Running SSL check...")
            ssl_info = SSLModule.get_certificate(target)
            self.results['ssl'] = ssl_info
            if ssl_info:
                self.call_from_thread(self.append_general_intel, f"SSL Issuer: {ssl_info.issuer}\nExpires: {ssl_info.valid_until}")
                if not ssl_info.is_expired:
                    self.call_from_thread(self.add_visual_indicator, 'left', "[green]🟢 SSL Valid[/green]")
                else:
                    self.call_from_thread(self.add_visual_indicator, 'left', "[red]🔴 SSL Expired/Invalid[/red]")
            self.set_process_state("SSL", "Done")
        pb.advance(15)
        
        if self.options.get("dns"):
            self.set_process_state("DNS", "Running")
            self.log_msg("[*] Running DNS recon...")
            try:
                dns_results = DNSModule.lookup_all(target)
                self.results['dns'] = dns_results
                if dns_results:
                    a_records = []
                    
                    # Ensure safe iteration against strings
                    items = dns_results.values() if isinstance(dns_results, dict) else dns_results
                    for r in items:
                        if r is None or isinstance(r, str):
                            continue
                        if hasattr(r, 'record_type') and getattr(r, 'record_type') == 'A':
                            a_records = getattr(r, 'values', [])
                            break
                            
                    self.call_from_thread(self.append_network, f"DNS A Records: {len(a_records)}")
            except Exception as e:
                self.log_msg(f"[red][!] DNS Parsing Error: {str(e)}[/red]")
                
            self.set_process_state("DNS", "Done")
        pb.advance(10)

        # Port scanning
        if self.options.get("ports") and self.target_ip and self.target_ip != target:
            self.set_process_state("Ports", "Running")
            self.log_msg("[*] Running Port Scan...")
            if self.options.get("async_ports"):
                loop = asyncio.new_event_loop()
                port_results = loop.run_until_complete(AsyncPortScannerModule.scan_common_ports(self.target_ip, self.options.get("ports_list")))
                loop.close()
            else:
                port_results = SocketScannerModule.scan_common_ports(self.target_ip, self.options.get("ports_list"))
                
            self.results['ports'] = port_results
            open_ports = [p.port for p in port_results if p.status == 'open']
            self.call_from_thread(self.append_network, f"Open Ports: {open_ports}")
            
            if 80 in open_ports:
                self.call_from_thread(self.add_visual_indicator, 'right', "[red]🔴 Port 80 Open (Unencrypted)[/red]")
            
            self.set_process_state("Ports", "Done")
        pb.advance(15)

        # Headers and Fingerprinting
        headers_info = None
        if self.options.get("headers") or self.options.get("fingerprint"):
            self.set_process_state("Headers", "Running")
            self.log_msg("[*] Analyzing HTTP Headers...")
            headers_info = HeaderAnalysisModule.analyze(target)
            self.results['headers'] = headers_info
            self.set_process_state("Headers", "Done")
            
        if self.options.get("fingerprint"):
            self.set_process_state("Fingerprint", "Running")
            fingerprint = FingerprintModule.fingerprint(target, headers_info)
            self.results['fingerprint'] = fingerprint
            if fingerprint:
                techs = ", ".join(fingerprint.technologies)
                self.call_from_thread(self.append_network, f"Technologies: {techs}")
                
            self.log_msg("[*] Mapping CVEs...")
            cves = CVEModule.lookup(fingerprint)
            self.results['cves'] = cves
            if cves:
                self.call_from_thread(self.append_network, f"CVE/Risks: {len(cves)}")
            self.set_process_state("Fingerprint", "Done")
        pb.advance(15)

        # Web Screenshot 
        self.set_process_state("Screenshot", "Running")
        self.log_msg("[*] Taking Web Screenshot...")
        loop = asyncio.new_event_loop()
        screenshot = loop.run_until_complete(WebScreenshotModule.capture(target))
        loop.close()
        self.results['screenshot'] = screenshot
        if screenshot:
            self.call_from_thread(self.append_network, f"Page Title: {screenshot.title}")
        self.set_process_state("Screenshot", "Done")
        pb.advance(5)

        # Risk Score
        self.set_process_state("Risk Eval", "Running")
        risk = IntelAggregatorModule.calculate_risk(self.results)
        self.results['risk'] = risk
        
        color = "green"
        if risk.level == "Critical": color = "red"
        elif risk.level == "High": color = "orange1"
        elif risk.level == "Medium": color = "yellow"
        
        self.call_from_thread(self.append_network, f"[{color}]Risk Level: {risk.level}[/{color}]")
        self.set_process_state("Risk Eval", "Done")

        pb.update(total=100, progress=100)
        self.active_processes.clear()
        self.call_from_thread(self.update_process_monitor)
        
        self.log_msg("\n[bold green]=== Reconnaissance Complete ===[/bold green]")
        self.log_msg("Select nodes on the left sidebar to view subdomain intel.")

    def action_toggle_export(self) -> None:
        """Export results when user presses 's'."""
        export_format = self.options.get("export", "json")
        out_file = self.options.get("output", "recon_results") + "." + export_format
        
        if export_format == "json":
            ExportModule.export_json(self.results, out_file)
            self.log_msg(f"[green]Results exported to {out_file}[/green]")
        elif export_format == "csv":
            ExportModule.export_csv(self.results, out_file)
            self.log_msg(f"[green]Results exported to {out_file}[/green]")
        elif export_format == "geojson":
            if 'ip_intelligence' in self.results and self.results['ip_intelligence']:
                ExportModule.export_geojson([self.results['ip_intelligence']], out_file)
                self.log_msg(f"[green]GeoJSON exported to {out_file}[/green]")
