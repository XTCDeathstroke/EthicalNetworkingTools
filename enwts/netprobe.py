#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures as cf
import ipaddress
import socket
import ssl
import subprocess
import threading
import time
import urllib.request
from dataclasses import dataclass
from queue import Queue, Empty
from typing import Dict, List, Optional, Tuple

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from .common import Tooltip, deadline_seconds, is_windows, run_cmd


@dataclass(frozen=True)
class ScanResult:
    port: int
    state: str
    service: str = ""
    banner: str = ""


def resolve_target(target: str) -> Tuple[str, str]:
    target = (target or "").strip()
    if not target:
        raise ValueError("Target is required (e.g., 127.0.0.1, 192.168.1.10, example.com).")
    try:
        ip = socket.gethostbyname(target)
        return target, ip
    except socket.gaierror as e:
        raise ValueError(f"Could not resolve target '{target}': {e}") from e


def safe_get_service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


def grab_banner(host_for_tls: str, ip: str, port: int, timeout: float) -> str:
    max_bytes = 256
    if port == 443:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host_for_tls) as ssock:
                    ssock.settimeout(timeout)
                    try:
                        data = ssock.recv(max_bytes)
                        return data.decode(errors="replace").strip()
                    except socket.timeout:
                        return ""
        except Exception:
            return ""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                data = sock.recv(max_bytes)
                return data.decode(errors="replace").strip()
            except socket.timeout:
                return ""
    except Exception:
        return ""


def scan_tcp_one(ip: str, display_host_for_tls: str, port: int, timeout: float, do_banner: bool) -> ScanResult:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            service = safe_get_service_name(port)
            banner = grab_banner(display_host_for_tls, ip, port, timeout) if do_banner else ""
            return ScanResult(port=port, state="open", service=service, banner=banner)
    except ConnectionRefusedError:
        return ScanResult(port=port, state="closed")
    except socket.timeout:
        return ScanResult(port=port, state="filtered")
    except OSError:
        return ScanResult(port=port, state="closed")


def scan_udp_one(ip: str, port: int, timeout: float) -> ScanResult:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            try:
                s.send(b"")
            except OSError:
                pass
            try:
                _ = s.recv(1024)
                return ScanResult(port=port, state="open")
            except socket.timeout:
                return ScanResult(port=port, state="open|filtered")
            except ConnectionRefusedError:
                return ScanResult(port=port, state="closed")
            except OSError:
                return ScanResult(port=port, state="open|filtered")
    except Exception:
        return ScanResult(port=port, state="open|filtered")


def ping_icmp(host: str, timeout_ms: int) -> Tuple[bool, str]:
    """Best-effort ping; uses OS ping with a hard subprocess timeout."""
    timeout_ms = max(250, int(timeout_ms))

    if is_windows():
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
        r = run_cmd(cmd, timeout=max(2.0, timeout_ms / 1000.0 + 2.0))
        ok = (r.rc == 0)
        return ok, ("ICMP ping: reachable" if ok else "ICMP ping: no reply (blocked or down)")

    timeout_s = max(1, int((timeout_ms + 999) / 1000))
    candidates = [
        (["ping", "-n", "-c", "1", "-W", str(timeout_s), host], max(2.0, timeout_s + 2.0)),
        (["ping", "-n", "-c", "1", "-W", str(timeout_ms), host], max(2.0, timeout_s + 2.0)),
        (["ping", "-n", "-c", "1", "-w", str(timeout_s), host], max(2.0, timeout_s + 2.0)),
    ]
    for cmd, to in candidates:
        r = run_cmd(cmd, timeout=to)
        if r.rc in (0, 1):
            ok = (r.rc == 0)
            return ok, ("ICMP ping: reachable" if ok else "ICMP ping: no reply (blocked or down)")
    return False, "ICMP ping: unavailable"


def get_lan_ipv4() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        return "Unavailable"


def get_public_ip() -> str:
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=2.5) as r:
            ip = r.read().decode().strip()
            ipaddress.ip_address(ip)
            return ip
    except Exception:
        return "Unavailable"


def is_private_ipv4(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        return obj.version == 4 and obj.is_private
    except Exception:
        return False


def arp_lookup(target_ip: str) -> str:
    try:
        if is_windows():
            r = run_cmd(["arp", "-a"], timeout=8.0)
        else:
            r = run_cmd(["arp", "-a"], timeout=8.0)
        text = (r.out + ("\n" + r.err if r.err else "")).strip()
        if r.rc != 0:
            return "ARP: unavailable (arp command failed)"
        for line in text.splitlines():
            if target_ip in line:
                parts = line.split()
                if len(parts) >= 2:
                    return f"ARP: {target_ip} -> {parts[1]}"
        return f"ARP: no cache entry for {target_ip} (try pinging it first; must be on LAN)"
    except Exception as e:
        return f"ARP: error ({e})"


def parse_port_range(start_s: str, end_s: str) -> List[int]:
    start_s = (start_s or "").strip()
    end_s = (end_s or "").strip()
    if not start_s or not end_s:
        raise ValueError("Port range is required (Start and End).")
    start = int(start_s)
    end = int(end_s)
    if start < 1 or end > 65535 or start > end:
        raise ValueError("Port range must be between 1 and 65535, and Start must be <= End.")
    return list(range(start, end + 1))


PRESETS: Dict[str, Dict[str, object]] = {
    "Quick TCP (Common)": {
        "port_start": "1",
        "port_end": "1024",
        "timeout": "0.8",
        "workers": "150",
        "max_runtime": "10",
        "tcp": True,
        "udp": False,
        "icmp": True,
        "arp": False,
        "banner": False,
        "show_udp_inconclusive": False,
        "description": "Fast baseline scan of well-known TCP ports plus a single ping.",
    },
    "Home PC (Localhost)": {
        "port_start": "1",
        "port_end": "9024",
        "timeout": "1.0",
        "workers": "150",
        "max_runtime": "10",
        "tcp": True,
        "udp": False,
        "icmp": False,
        "arp": False,
        "banner": False,
        "show_udp_inconclusive": False,
        "description": "Checks common Windows/local services on your own PC (target often 127.0.0.1).",
    },
    "LAN Exposure Check": {
        "port_start": "1",
        "port_end": "1024",
        "timeout": "1.0",
        "workers": "120",
        "max_runtime": "10",
        "tcp": True,
        "udp": False,
        "icmp": True,
        "arp": True,
        "banner": False,
        "show_udp_inconclusive": False,
        "description": "Use a LAN IP target; includes ARP lookup to confirm neighbor mapping.",
    },
    "UDP Essentials (Focused)": {
        "port_start": "1",
        "port_end": "1024",
        "timeout": "1.2",
        "workers": "100",
        "max_runtime": "10",
        "tcp": False,
        "udp": True,
        "icmp": True,
        "arp": False,
        "banner": False,
        "show_udp_inconclusive": False,
        "description": "UDP-only scan; by default shows only ports that actually respond.",
    },
    "Thorough TCP (Wider)": {
        "port_start": "1",
        "port_end": "65535",
        "timeout": "1.0",
        "workers": "120",
        "max_runtime": "25",
        "tcp": True,
        "udp": False,
        "icmp": True,
        "arp": False,
        "banner": False,
        "show_udp_inconclusive": False,
        "description": "Comprehensive TCP scan across all ports (use only with permission; can take a while).",
    },
}


class NetProbeTab:
    """Port scanning tab."""

    def __init__(self, parent: tk.Widget):
        self.parent = parent

        self._stop_event = threading.Event()
        self._scan_thread: Optional[threading.Thread] = None
        self._ui_queue: Queue = Queue()

        self._total_work = 0
        self._done_work = 0
        self._resolved_ip = ""
        self._resolved_name = ""

        self.loopback_ip = "127.0.0.1"
        self.lan_ip_var = tk.StringVar(value=get_lan_ipv4())
        self.public_ip_var = tk.StringVar(value=get_public_ip())

        self._build_ui()
        self._poll_queue()

    def _build_ui(self):
        self.parent.columnconfigure(0, weight=1)
        self.parent.rowconfigure(0, weight=1)

        self.nb = ttk.Notebook(self.parent)
        self.nb.grid(row=0, column=0, sticky="nsew")

        self.scan_tab = ttk.Frame(self.nb, padding=12)
        self.help_tab = ttk.Frame(self.nb, padding=12)
        self.nb.add(self.scan_tab, text="Scan")
        self.nb.add(self.help_tab, text="Help")

        self.scan_tab.columnconfigure(0, weight=1)
        self.scan_tab.rowconfigure(3, weight=1)

        banner = ttk.Label(
            self.scan_tab,
            text="Authorized use only: scan systems you own or have explicit permission to test.",
            foreground="#444",
        )
        banner.grid(row=0, column=0, sticky="w")

        inputs = ttk.LabelFrame(self.scan_tab, text="Scan Settings", padding=10)
        inputs.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        inputs.columnconfigure(1, weight=1)

        preset_row = ttk.Frame(inputs)
        preset_row.grid(row=0, column=0, columnspan=4, sticky="ew", pady=(0, 8))
        preset_row.columnconfigure(1, weight=1)

        ttk.Label(preset_row, text="Preset:").grid(row=0, column=0, sticky="w", padx=(0, 8))
        self.preset_var = tk.StringVar(value="Quick TCP (Common)")
        self.preset_combo = ttk.Combobox(
            preset_row,
            textvariable=self.preset_var,
            values=list(PRESETS.keys()),
            state="readonly",
            width=30,
        )
        self.preset_combo.grid(row=0, column=1, sticky="w")
        self.preset_combo.bind("<<ComboboxSelected>>", self._on_preset_selected)
        Tooltip(self.preset_combo, "Choose a preset to auto-fill scan settings.")

        self.preset_desc_var = tk.StringVar(value=str(PRESETS[self.preset_var.get()]["description"]))  # type: ignore[index]
        ttk.Label(preset_row, textvariable=self.preset_desc_var, foreground="#444").grid(
            row=1, column=0, columnspan=3, sticky="w", pady=(6, 0)
        )

        ttk.Label(inputs, text="Loopback (localhost):").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Label(inputs, text=self.loopback_ip).grid(row=1, column=1, sticky="w", pady=4)
        self.use_loopback_btn = ttk.Button(inputs, text="Use Loopback", width=14, command=self._use_loopback)
        self.use_loopback_btn.grid(row=1, column=2, sticky="e", padx=(8, 0), pady=4)
        Tooltip(self.use_loopback_btn, "Sets the target to 127.0.0.1 (this computer only).")

        ttk.Label(inputs, text="LAN IPv4:").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Label(inputs, textvariable=self.lan_ip_var).grid(row=2, column=1, sticky="w", pady=4)
        self.use_lan_btn = ttk.Button(inputs, text="Use LAN IP", width=14, command=self._use_lan)
        self.use_lan_btn.grid(row=2, column=2, sticky="e", padx=(8, 0), pady=4)
        self.refresh_lan_btn = ttk.Button(inputs, text="Refresh", width=10, command=self._refresh_lan)
        self.refresh_lan_btn.grid(row=2, column=3, sticky="e", padx=(8, 0), pady=4)
        Tooltip(self.use_lan_btn, "Sets the target to your local network IP (reachable from devices on your Wi-Fi/LAN).")
        Tooltip(self.refresh_lan_btn, "Re-detects your LAN IP.")

        ttk.Label(inputs, text="Public IPv4:").grid(row=3, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Label(inputs, textvariable=self.public_ip_var).grid(row=3, column=1, sticky="w", pady=4)
        self.use_public_btn = ttk.Button(inputs, text="Use Public IP", width=14, command=self._use_public)
        self.use_public_btn.grid(row=3, column=2, sticky="e", padx=(8, 0), pady=4)
        self.refresh_public_btn = ttk.Button(inputs, text="Refresh", width=10, command=self._refresh_public)
        self.refresh_public_btn.grid(row=3, column=3, sticky="e", padx=(8, 0), pady=4)
        Tooltip(self.use_public_btn, "Sets the target to your public internet IP.")
        Tooltip(self.refresh_public_btn, "Re-detects your public IP.")

        ttk.Label(inputs, text="Target (hostname or IP):").grid(row=4, column=0, sticky="w", padx=(0, 8), pady=4)
        self.target_var = tk.StringVar(value="127.0.0.1")
        self.target_entry = ttk.Entry(inputs, textvariable=self.target_var)
        self.target_entry.grid(row=4, column=1, columnspan=3, sticky="ew", pady=4)
        Tooltip(self.target_entry, "The host you are scanning (only scan systems you own or have permission to test).")

        ports_row = ttk.Frame(inputs)
        ports_row.grid(row=5, column=0, columnspan=4, sticky="ew", pady=(6, 0))
        ports_row.columnconfigure(3, weight=1)

        ttk.Label(ports_row, text="Ports:").grid(row=0, column=0, sticky="w", padx=(0, 8))
        self.port_start_var = tk.StringVar(value="1")
        self.port_end_var = tk.StringVar(value="1024")
        self.port_start_entry = ttk.Entry(ports_row, textvariable=self.port_start_var, width=10)
        self.port_end_entry = ttk.Entry(ports_row, textvariable=self.port_end_var, width=10)
        self.port_start_entry.grid(row=0, column=1, sticky="w")
        ttk.Label(ports_row, text=" - ").grid(row=0, column=2, sticky="w", padx=(6, 6))
        self.port_end_entry.grid(row=0, column=3, sticky="w")
        Tooltip(self.port_start_entry, "First port number to scan (1–65535).")
        Tooltip(self.port_end_entry, "Last port number to scan (1–65535).")

        proto_frame = ttk.LabelFrame(inputs, text="Protocols", padding=8)
        proto_frame.grid(row=6, column=0, columnspan=4, sticky="ew", pady=(10, 0))
        for c in range(6):
            proto_frame.columnconfigure(c, weight=1)

        self.tcp_var = tk.BooleanVar(value=True)
        self.udp_var = tk.BooleanVar(value=False)
        self.icmp_var = tk.BooleanVar(value=True)
        self.arp_var = tk.BooleanVar(value=False)
        self.show_udp_inconclusive_var = tk.BooleanVar(value=False)

        self.tcp_cb = ttk.Checkbutton(proto_frame, text="TCP", variable=self.tcp_var)
        self.udp_cb = ttk.Checkbutton(proto_frame, text="UDP", variable=self.udp_var)
        self.icmp_cb = ttk.Checkbutton(proto_frame, text="ICMP (ping)", variable=self.icmp_var)
        self.arp_cb = ttk.Checkbutton(proto_frame, text="ARP (LAN)", variable=self.arp_var)
        self.udp_inconclusive_cb = ttk.Checkbutton(proto_frame, text="Show UDP open|filtered", variable=self.show_udp_inconclusive_var)

        self.tcp_cb.grid(row=0, column=0, sticky="w")
        self.udp_cb.grid(row=0, column=1, sticky="w")
        self.icmp_cb.grid(row=0, column=2, sticky="w")
        self.arp_cb.grid(row=0, column=3, sticky="w")
        self.udp_inconclusive_cb.grid(row=0, column=4, sticky="w")

        Tooltip(self.tcp_cb, "TCP connect scan (reliable open/closed for most targets).")
        Tooltip(self.udp_cb, "UDP scan is often inconclusive unless a service responds.")
        Tooltip(self.icmp_cb, "Sends one ping to see if the host replies.")
        Tooltip(self.arp_cb, "Looks up the target in the ARP cache (LAN only).")
        Tooltip(self.udp_inconclusive_cb, "If enabled, shows UDP ports that did not respond (could be open OR blocked).")

        opts = ttk.Frame(inputs)
        opts.grid(row=7, column=0, columnspan=4, sticky="ew", pady=(10, 0))
        opts.columnconfigure(1, weight=1)
        opts.columnconfigure(3, weight=1)

        ttk.Label(opts, text="Timeout (s):").grid(row=0, column=0, sticky="w", padx=(0, 8))
        self.timeout_var = tk.StringVar(value="1.0")
        self.timeout_entry = ttk.Entry(opts, textvariable=self.timeout_var, width=8)
        self.timeout_entry.grid(row=0, column=1, sticky="w")
        Tooltip(self.timeout_entry, "How long to wait for a response before marking it filtered/inconclusive.")

        ttk.Label(opts, text="Workers:").grid(row=0, column=2, sticky="w", padx=(16, 8))
        self.workers_var = tk.StringVar(value="150")
        self.workers_entry = ttk.Entry(opts, textvariable=self.workers_var, width=8)
        self.workers_entry.grid(row=0, column=3, sticky="w")
        Tooltip(self.workers_entry, "Parallel checks. Higher is faster but can overwhelm networks or your PC.")

        ttk.Label(opts, text="Max runtime (min):").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=(8, 0))
        self.max_runtime_var = tk.StringVar(value="10")
        self.max_runtime_entry = ttk.Entry(opts, textvariable=self.max_runtime_var, width=8)
        self.max_runtime_entry.grid(row=1, column=1, sticky="w", pady=(8, 0))
        Tooltip(self.max_runtime_entry, "Hard stop if the scan runs longer than this.")

        self.banner_var = tk.BooleanVar(value=False)
        self.banner_check = ttk.Checkbutton(inputs, text="TCP banner (best-effort)", variable=self.banner_var)
        self.banner_check.grid(row=8, column=0, columnspan=4, sticky="w", pady=(8, 0))
        Tooltip(self.banner_check, "Attempts to read a small service greeting after connecting (TCP only).")

        controls = ttk.Frame(self.scan_tab)
        controls.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        controls.columnconfigure(4, weight=1)

        self.scan_btn = ttk.Button(controls, text="Start Scan", command=self.start_scan)
        self.scan_btn.grid(row=0, column=0, sticky="w")
        Tooltip(self.scan_btn, "Starts the scan using the selected settings.")

        self.stop_btn = ttk.Button(controls, text="Stop", command=self.stop_scan, state="disabled")
        self.stop_btn.grid(row=0, column=1, sticky="w", padx=(8, 0))
        Tooltip(self.stop_btn, "Stops submitting new checks and finishes in-flight checks.")

        self.save_btn = ttk.Button(controls, text="Save Results", command=self.save_results)
        self.save_btn.grid(row=0, column=2, sticky="w", padx=(8, 0))
        Tooltip(self.save_btn, "Saves the output area to a .txt file.")

        self.clear_btn = ttk.Button(controls, text="Clear", command=self._clear_results)
        self.clear_btn.grid(row=0, column=3, sticky="w", padx=(8, 0))

        self.progress = ttk.Progressbar(controls, mode="determinate")
        self.progress.grid(row=0, column=4, sticky="ew", padx=(12, 0))

        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(self.scan_tab, textvariable=self.status_var).grid(row=3, column=0, sticky="w", pady=(8, 0))

        results_frame = ttk.LabelFrame(self.scan_tab, text="Results", padding=10)
        results_frame.grid(row=4, column=0, sticky="nsew", pady=(10, 0))
        self.scan_tab.rowconfigure(4, weight=1)
        results_frame.rowconfigure(0, weight=1)
        results_frame.columnconfigure(0, weight=1)

        self.results_text = tk.Text(results_frame, height=16, wrap="none")
        self.results_text.grid(row=0, column=0, sticky="nsew")

        yscroll = ttk.Scrollbar(results_frame, orient="vertical", command=self.results_text.yview)
        yscroll.grid(row=0, column=1, sticky="ns")
        self.results_text.configure(yscrollcommand=yscroll.set)

        xscroll = ttk.Scrollbar(results_frame, orient="horizontal", command=self.results_text.xview)
        xscroll.grid(row=1, column=0, sticky="ew")
        self.results_text.configure(xscrollcommand=xscroll.set)

        self._build_help()
        self._apply_preset(self.preset_var.get())

    def _build_help(self):
        self.help_tab.columnconfigure(0, weight=1)
        self.help_tab.rowconfigure(0, weight=1)

        box = ttk.LabelFrame(self.help_tab, text="Terms & Notes", padding=10)
        box.grid(row=0, column=0, sticky="nsew")
        box.columnconfigure(0, weight=1)
        box.rowconfigure(0, weight=1)

        txt = tk.Text(box, wrap="word")
        txt.grid(row=0, column=0, sticky="nsew")

        y = ttk.Scrollbar(box, orient="vertical", command=txt.yview)
        y.grid(row=0, column=1, sticky="ns")
        txt.configure(yscrollcommand=y.set)

        content = (
            "Target\n"
            "  The host you are testing (IP or hostname). Only scan systems you own or have permission to test.\n\n"
            "TCP\n"
            "  Connection-oriented protocol. This scanner uses a TCP connect test.\n\n"
            "UDP\n"
            "  Connectionless protocol. 'open|filtered' means inconclusive (no reply).\n\n"
            "ICMP (Ping)\n"
            "  A reachability check. Some networks block ping.\n\n"
            "ARP\n"
            "  LAN-only protocol that maps IP addresses to MAC addresses (best effort).\n\n"
            "TCP Banner\n"
            "  A small greeting some services send after a TCP connection. Best-effort and may be empty.\n\n"
            "Max runtime\n"
            "  ENWTS will stop a scan if it exceeds the configured maximum runtime.\n"
        )
        txt.insert("1.0", content)
        txt.configure(state="disabled")

    def _on_preset_selected(self, _evt=None):
        self._apply_preset(self.preset_var.get())

    def _apply_preset(self, name: str):
        p = PRESETS.get(name)
        if not p:
            return
        self.port_start_var.set(str(p["port_start"]))
        self.port_end_var.set(str(p["port_end"]))
        self.timeout_var.set(str(p["timeout"]))
        self.workers_var.set(str(p["workers"]))
        self.max_runtime_var.set(str(p.get("max_runtime", "10")))
        self.tcp_var.set(bool(p["tcp"]))
        self.udp_var.set(bool(p["udp"]))
        self.icmp_var.set(bool(p["icmp"]))
        self.arp_var.set(bool(p["arp"]))
        self.banner_var.set(bool(p["banner"]))
        self.show_udp_inconclusive_var.set(bool(p["show_udp_inconclusive"]))
        self.preset_desc_var.set(str(p.get("description", "")))

    def _refresh_lan(self):
        self.lan_ip_var.set(get_lan_ipv4())

    def _refresh_public(self):
        self.public_ip_var.set(get_public_ip())

    def _use_loopback(self):
        self.target_var.set(self.loopback_ip)

    def _use_lan(self):
        ip = self.lan_ip_var.get().strip()
        if not ip or ip.lower() == "unavailable":
            messagebox.showwarning("LAN IP unavailable", "Could not determine LAN IPv4. Click Refresh or use ipconfig/ifconfig.")
            return
        self.target_var.set(ip)

    def _use_public(self):
        ip = self.public_ip_var.get().strip()
        if not ip or ip.lower() == "unavailable":
            messagebox.showwarning("Public IP unavailable", "Could not determine public IP (offline/blocked). Click Refresh.")
            return
        self.target_var.set(ip)

    def _set_running(self, running: bool):
        state_edit = "disabled" if running else "normal"
        self.scan_btn.configure(state="disabled" if running else "normal")
        self.stop_btn.configure(state="normal" if running else "disabled")

        for w in (
            self.preset_combo,
            self.target_entry,
            self.port_start_entry,
            self.port_end_entry,
            self.timeout_entry,
            self.workers_entry,
            self.max_runtime_entry,
            self.banner_check,
            self.use_loopback_btn,
            self.use_lan_btn,
            self.refresh_lan_btn,
            self.use_public_btn,
            self.refresh_public_btn,
            self.tcp_cb,
            self.udp_cb,
            self.icmp_cb,
            self.arp_cb,
            self.udp_inconclusive_cb,
            self.save_btn,
            self.clear_btn,
        ):
            w.configure(state=state_edit)

    def _append_line(self, line: str):
        self.results_text.insert("end", line + "\n")
        self.results_text.see("end")

    def _clear_results(self):
        self.results_text.delete("1.0", "end")

    def save_results(self):
        text = self.results_text.get("1.0", "end").strip()
        if not text:
            messagebox.showinfo("Save", "No results to save.")
            return
        path = filedialog.asksaveasfilename(
            title="Save Scan Results",
            defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("All files", "*")],
            initialfile=f"enwts_netprobe_{time.strftime('%Y%m%d_%H%M%S')}.txt",
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text + "\n")
            messagebox.showinfo("Save", f"Saved: {path}")
        except Exception as e:
            messagebox.showerror("Save failed", str(e))

    def start_scan(self):
        if self._scan_thread and self._scan_thread.is_alive():
            return

        try:
            target = self.target_var.get().strip()
            ports = parse_port_range(self.port_start_var.get(), self.port_end_var.get())
            timeout = float(self.timeout_var.get())
            workers = int(self.workers_var.get())
            max_rt_min = float(self.max_runtime_var.get())
            do_banner = bool(self.banner_var.get())

            do_tcp = bool(self.tcp_var.get())
            do_udp = bool(self.udp_var.get())
            do_icmp = bool(self.icmp_var.get())
            do_arp = bool(self.arp_var.get())
            show_udp_inconclusive = bool(self.show_udp_inconclusive_var.get())

            if timeout <= 0:
                raise ValueError("Timeout must be > 0.")
            if workers < 1 or workers > 2000:
                raise ValueError("Workers must be between 1 and 2000.")
            if not any([do_tcp, do_udp, do_icmp, do_arp]):
                raise ValueError("Select at least one protocol.")

            _ = deadline_seconds(max_rt_min, default_minutes=10.0)

            name, ip = resolve_target(target)

        except Exception as e:
            messagebox.showerror("Invalid input", str(e))
            return

        work = 0
        if do_tcp:
            work += len(ports)
        if do_udp:
            work += len(ports)
        if do_icmp:
            work += 1
        if do_arp:
            work += 1

        self._stop_event.clear()
        self._clear_results()
        self._total_work = max(1, work)
        self._done_work = 0
        self._resolved_ip = ip
        self._resolved_name = name

        self.progress.configure(maximum=self._total_work, value=0)
        self.status_var.set(f"Target: {name} ({ip}) | Starting...")
        self._set_running(True)

        self._scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(name, ip, ports, timeout, workers, max_rt_min, do_banner, do_tcp, do_udp, do_icmp, do_arp, show_udp_inconclusive),
            daemon=True,
        )
        self._scan_thread.start()

    def stop_scan(self):
        self._stop_event.set()
        self.status_var.set("Stopping...")

    def _scan_worker(
        self,
        display_host: str,
        ip: str,
        ports: List[int],
        timeout: float,
        workers: int,
        max_rt_min: float,
        do_banner: bool,
        do_tcp: bool,
        do_udp: bool,
        do_icmp: bool,
        do_arp: bool,
        show_udp_inconclusive: bool,
    ):
        deadline = time.time() + deadline_seconds(max_rt_min, default_minutes=10.0)

        self._ui_queue.put(("line", f"Target: {display_host} ({ip})"))
        self._ui_queue.put(("line", f"Ports: {ports[0]}-{ports[-1]} ({len(ports)} total)"))
        self._ui_queue.put(("line", f"Timeout: {timeout}s | Workers: {workers} | TCP banner: {do_banner} | Max runtime: {max_rt_min} min"))
        self._ui_queue.put(("line", ""))

        if not is_private_ipv4(ip) and ip == self.public_ip_var.get().strip():
            self._ui_queue.put(("line", "Note: Scanning your own public IP from inside your network may not reflect internet exposure (NAT/loopback)."))
            self._ui_queue.put(("line", ""))

        try:
            if do_icmp and not self._stop_event.is_set() and time.time() < deadline:
                _, line = ping_icmp(ip, timeout_ms=int(max(250, timeout * 1000)))
                self._ui_queue.put(("line", line))
                self._ui_queue.put(("progress", 1))

            if do_arp and not self._stop_event.is_set() and time.time() < deadline:
                if not is_private_ipv4(ip):
                    self._ui_queue.put(("line", "ARP: skipped (target is not a LAN/private IPv4)."))
                else:
                    _ = ping_icmp(ip, timeout_ms=int(max(250, timeout * 1000)))
                    self._ui_queue.put(("line", arp_lookup(ip)))
                self._ui_queue.put(("progress", 1))

            if do_tcp and not self._stop_event.is_set() and time.time() < deadline:
                self._ui_queue.put(("line", "TCP results:"))
                self._ui_queue.put(("line", "PORT     STATE      SERVICE        BANNER"))
                self._ui_queue.put(("line", "-----    --------   -----------    ------"))

                def fmt_tcp(r: ScanResult) -> str:
                    svc = r.service or "unknown"
                    if r.banner:
                        banner = " ".join(r.banner.split())
                        return f"{r.port:>5}/tcp  {r.state:<8}  {svc:<12}  {banner}"
                    return f"{r.port:>5}/tcp  {r.state:<8}  {svc}"

                with cf.ThreadPoolExecutor(max_workers=workers) as ex:
                    futures: List[cf.Future] = []
                    for p in ports:
                        if self._stop_event.is_set() or time.time() >= deadline:
                            break
                        futures.append(ex.submit(scan_tcp_one, ip, display_host, p, timeout, do_banner))

                    # Drain results until stop/deadline.
                    for fut in cf.as_completed(futures):
                        if self._stop_event.is_set() or time.time() >= deadline:
                            break
                        try:
                            r = fut.result()
                        except Exception:
                            r = ScanResult(port=-1, state="error")
                        self._ui_queue.put(("progress", 1))
                        if r.state == "open":
                            self._ui_queue.put(("line", fmt_tcp(r)))

                    # If stopping early, cancel pending work.
                    try:
                        ex.shutdown(wait=False, cancel_futures=True)
                    except TypeError:
                        ex.shutdown(wait=False)

                self._ui_queue.put(("line", ""))

            if do_udp and not self._stop_event.is_set() and time.time() < deadline:
                self._ui_queue.put(("line", "UDP results:"))
                self._ui_queue.put(("line", "PORT     STATE"))
                self._ui_queue.put(("line", "-----    -----------"))

                def fmt_udp(r: ScanResult) -> str:
                    return f"{r.port:>5}/udp  {r.state}"

                with cf.ThreadPoolExecutor(max_workers=workers) as ex:
                    futures = []
                    for p in ports:
                        if self._stop_event.is_set() or time.time() >= deadline:
                            break
                        futures.append(ex.submit(scan_udp_one, ip, p, timeout))

                    for fut in cf.as_completed(futures):
                        if self._stop_event.is_set() or time.time() >= deadline:
                            break
                        try:
                            r = fut.result()
                        except Exception:
                            r = ScanResult(port=-1, state="error")
                        self._ui_queue.put(("progress", 1))
                        if r.state == "open" or (show_udp_inconclusive and r.state == "open|filtered"):
                            self._ui_queue.put(("line", fmt_udp(r)))

                    try:
                        ex.shutdown(wait=False, cancel_futures=True)
                    except TypeError:
                        ex.shutdown(wait=False)

                self._ui_queue.put(("line", ""))

            if time.time() >= deadline and not self._stop_event.is_set():
                self._stop_event.set()
                self._ui_queue.put(("done", "timed_out"))
            else:
                self._ui_queue.put(("done", "stopped" if self._stop_event.is_set() else "finished"))

        except Exception as e:
            self._ui_queue.put(("error", str(e)))

    def _poll_queue(self):
        try:
            while True:
                msg = self._ui_queue.get_nowait()
                kind = msg[0]

                if kind == "line":
                    self._append_line(msg[1])

                elif kind == "progress":
                    self._done_work += int(msg[1])
                    self.progress.configure(value=min(self._done_work, self._total_work))
                    self.status_var.set(
                        f"Target: {self._resolved_name} ({self._resolved_ip}) | "
                        f"Progress: {min(self._done_work, self._total_work)}/{self._total_work}"
                    )

                elif kind == "done":
                    mode = msg[1]
                    if mode == "stopped":
                        self.status_var.set(f"Stopped. Progress: {min(self._done_work, self._total_work)}/{self._total_work}")
                    elif mode == "timed_out":
                        self.status_var.set("Stopped: max runtime reached.")
                    else:
                        self.status_var.set("Finished.")
                    self._set_running(False)

                elif kind == "error":
                    self._set_running(False)
                    messagebox.showerror("Scan error", msg[1])
                    self.status_var.set("Error.")

        except Empty:
            pass

        self.parent.after(75, self._poll_queue)
