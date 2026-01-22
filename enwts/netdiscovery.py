#!/usr/bin/env python3
from __future__ import annotations

import csv
import ipaddress
import os
import re
import socket
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from queue import Queue, Empty
from typing import Dict, List, Optional, Tuple

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from .common import Tooltip, deadline_seconds, is_windows, now_str, run_cmd


@dataclass(frozen=True)
class DeviceRow:
    ip: str
    mac: str
    vendor: str
    hostname: str
    reachable: str


HELP_TEXT = (
    "Range Scan\n"
    "  Start IP + End Host scans sequentially.\n"
    "  Example: Start 192.168.1.0 and End Host 60 scans 192.168.1.0–192.168.1.60.\n\n"
    "Detection\n"
    "  Uses a small UDP send (to trigger ARP), ping, and ARP lookups.\n"
    "  Many devices block ping, so ARP is often the best signal on LANs.\n\n"
    "Details\n"
    "  Click the 'Open' cell on a device row (or double-click the row) to open a details window.\n\n"
    "Tip\n"
    "  Vendor lookup uses a public API; disable it if you do not want any web lookups.\n"
)


def udp_touch(ip: str, timeout_ms: int) -> None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.settimeout(max(0.05, timeout_ms / 1000.0))
            s.connect((ip, 1))
            try:
                s.send(b"\x00")
            except Exception:
                pass
        finally:
            s.close()
    except Exception:
        pass


_MAC_RE = re.compile(r"\b((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})\b")


def parse_mac_from_arp_text(ip: str, text: str) -> str:
    """Best-effort ARP parsing across common OS formats."""
    ip = ip.strip()
    if not ip or not text:
        return ""

    # Windows-style: "192.168.1.1  aa-bb-cc-dd-ee-ff  dynamic"
    win_re = re.compile(r"^\s*([0-9.]+)\s+([0-9a-fA-F:-]{11,17})\s+\w+", re.IGNORECASE)
    for line in text.splitlines():
        m = win_re.match(line)
        if m and m.group(1) == ip:
            return m.group(2).replace(":", "-").lower()

    # Unix/BSD style: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff ..."
    for line in text.splitlines():
        if ip not in line:
            continue
        mm = _MAC_RE.search(line)
        if mm:
            return mm.group(1).replace(":", "-").lower()

    return ""


def arp_lookup_ip(ip: str) -> str:
    try:
        if is_windows():
            r = run_cmd(["arp", "-a", ip], timeout=5.0)
            text = (r.out + ("\n" + r.err if r.err else "")).strip()
            return parse_mac_from_arp_text(ip, text)

        # Non-Windows: try a couple of common forms.
        for cmd in (["arp", "-n", ip], ["arp", "-a", ip], ["arp", "-a"]):
            r = run_cmd(cmd, timeout=5.0)
            text = (r.out + ("\n" + r.err if r.err else "")).strip()
            mac = parse_mac_from_arp_text(ip, text)
            if mac:
                return mac
        return ""
    except Exception:
        return ""


def reverse_dns(ip: str) -> str:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return ""


def mac_to_oui(mac: str) -> str:
    s = re.sub(r"[^0-9a-fA-F]", "", mac).upper()
    return s[:6] if len(s) >= 6 else ""


def lookup_vendor_online(mac: str, timeout: float = 1.5) -> str:
    mac = mac.strip()
    if not mac:
        return ""
    try:
        url = "https://api.macvendors.com/" + urllib.parse.quote(mac)
        req = urllib.request.Request(url, headers={"User-Agent": "ENWTS/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            txt = r.read().decode(errors="replace").strip()
        if not txt or "error" in txt.lower():
            return ""
        return txt
    except Exception:
        return ""


def ping_raw(ip: str, timeout_ms: int, count: int = 1) -> Tuple[bool, str]:
    """Cross-platform-ish ping wrapper (best effort)."""
    timeout_ms = max(100, int(timeout_ms))
    count = max(1, int(count))

    if is_windows():
        cmd = ["ping", "-n", str(count), "-w", str(timeout_ms), ip]
        r = run_cmd(cmd, timeout=max(2.0, (timeout_ms / 1000.0) * (count + 2)))
        text = (r.out + ("\n" + r.err if r.err else "")).strip()
        return r.rc == 0, text

    # Linux: -W is per-packet timeout in seconds.
    timeout_s = max(1, int((timeout_ms + 999) / 1000))
    candidates = [
        (["ping", "-n", "-c", str(count), "-W", str(timeout_s), ip], max(2.0, timeout_s * (count + 2))),
        # macOS/BSD: -W is timeout in ms on some variants
        (["ping", "-n", "-c", str(count), "-W", str(timeout_ms), ip], max(2.0, timeout_s * (count + 2))),
        # Linux: -w is total deadline in seconds
        (["ping", "-n", "-c", str(count), "-w", str(timeout_s * (count + 1)), ip], max(2.0, timeout_s * (count + 2))),
    ]
    last_text = ""
    for cmd, to in candidates:
        r = run_cmd(cmd, timeout=to)
        text = (r.out + ("\n" + r.err if r.err else "")).strip()
        last_text = text
        if r.rc in (0, 1):  # 0 reachable, 1 unreachable; both mean the ping command worked.
            return r.rc == 0, text
    return False, last_text or "Ping unavailable."


def ping_brief(ip: str, timeout_ms: int) -> bool:
    ok, _ = ping_raw(ip, timeout_ms, count=1)
    return ok


class DeviceDetailsWindow:
    def __init__(
        self,
        parent: tk.Widget,
        ip: str,
        timeout_ms: int,
        do_dns: bool,
        do_vendor: bool,
        vendor_cache: Dict[str, str],
        stop_event: threading.Event,
    ):
        self.parent = parent
        self.ip = ip
        self.timeout_ms = timeout_ms
        self.do_dns = do_dns
        self.do_vendor = do_vendor
        self.vendor_cache = vendor_cache
        self.stop_event = stop_event

        self._q: Queue = Queue()
        self.win = tk.Toplevel(parent)
        self.win.title(f"ENWTS - Device Details - {ip}")
        self.win.geometry("900x650")
        self.win.minsize(780, 520)

        self.win.columnconfigure(0, weight=1)
        self.win.rowconfigure(2, weight=1)

        top = ttk.Frame(self.win, padding=10)
        top.grid(row=0, column=0, sticky="ew")
        top.columnconfigure(1, weight=1)

        ttk.Label(top, text="IP:").grid(row=0, column=0, sticky="w", padx=(0, 8))
        ttk.Label(top, text=ip).grid(row=0, column=1, sticky="w")

        btns = ttk.Frame(self.win, padding=(10, 0, 10, 10))
        btns.grid(row=1, column=0, sticky="ew")
        btns.columnconfigure(1, weight=1)

        self.refresh_btn = ttk.Button(btns, text="Refresh", command=self.refresh)
        self.refresh_btn.grid(row=0, column=0, sticky="w")
        Tooltip(self.refresh_btn, "Re-collects details for this device.")

        self.progress = ttk.Progressbar(btns, mode="indeterminate")
        self.progress.grid(row=0, column=1, sticky="ew", padx=(10, 0))

        box = ttk.LabelFrame(self.win, text="Details", padding=10)
        box.grid(row=2, column=0, sticky="nsew", padx=10, pady=(0, 10))
        box.columnconfigure(0, weight=1)
        box.rowconfigure(0, weight=1)

        self.text = tk.Text(box, wrap="word")
        self.text.grid(row=0, column=0, sticky="nsew")
        sy = ttk.Scrollbar(box, orient="vertical", command=self.text.yview)
        sy.grid(row=0, column=1, sticky="ns")
        self.text.configure(yscrollcommand=sy.set)

        self.text.insert("1.0", "Collecting details...\n")
        self.text.configure(state="disabled")

        self.refresh()

    def refresh(self):
        self.progress.start(10)
        self.refresh_btn.configure(state="disabled")
        threading.Thread(target=self._worker, daemon=True).start()
        self._poll()

    def _set_text(self, s: str):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", s)
        self.text.configure(state="disabled")

    def _worker(self):
        ip = self.ip
        timeout_ms = self.timeout_ms

        sections: List[str] = []
        sections.append(f"IP: {ip}")
        sections.append(f"Local time: {now_str()}")

        if self.stop_event.is_set():
            self._q.put(("done", "Stopped."))
            return

        ok_ping, ping_out = ping_raw(ip, timeout_ms, count=2)
        sections.append("\nPing (2x)\n" + (ping_out or "(no output)"))

        if self.stop_event.is_set():
            self._q.put(("done", "Stopped."))
            return

        # ARP lookup
        if is_windows():
            arp = run_cmd(["arp", "-a", ip], timeout=6.0)
        else:
            arp = run_cmd(["arp", "-a"], timeout=6.0)
        arp_text = (arp.out + ("\n" + arp.err if arp.err else "")).strip()
        mac = parse_mac_from_arp_text(ip, arp_text)
        sections.append("\nARP\n" + (arp_text if arp_text else "(no ARP output)"))

        hostname = reverse_dns(ip) if self.do_dns else ""
        if self.do_dns:
            sections.append("\nReverse DNS\n" + (hostname if hostname else "(no hostname)"))

        vendor = ""
        if self.do_vendor and mac:
            oui = mac_to_oui(mac)
            if oui and oui in self.vendor_cache:
                vendor = self.vendor_cache[oui]
            else:
                v = lookup_vendor_online(mac)
                if oui and v:
                    self.vendor_cache[oui] = v
                vendor = v

        if mac:
            sections.append("\nMAC\n" + mac)
        if vendor:
            sections.append("\nVendor\n" + vendor)

        if is_windows():
            ps_cmd = f"Get-NetNeighbor -IPAddress {ip} | Format-List *"
            ps = run_cmd(["powershell", "-NoProfile", "-Command", ps_cmd], timeout=8.0)
            ps_text = (ps.out + ("\n" + ps.err if ps.err else "")).strip()
            sections.append("\nGet-NetNeighbor (PowerShell)\n" + (ps_text if ps_text else "(no output)"))

            nbt = run_cmd(["nbtstat", "-A", ip], timeout=10.0)
            nbt_text = (nbt.out + ("\n" + nbt.err if nbt.err else "")).strip()
            sections.append("\nNetBIOS (nbtstat -A)\n" + (nbt_text if nbt_text else "(no output)"))

        ns = run_cmd(["nslookup", ip], timeout=8.0)
        ns_text = (ns.out + ("\n" + ns.err if ns.err else "")).strip()
        sections.append("\nnslookup\n" + (ns_text if ns_text else "(no output)"))

        summary_lines: List[str] = []
        summary_lines.append("Summary")
        summary_lines.append("-------")
        summary_lines.append(f"IP: {ip}")
        summary_lines.append(f"Reachable (ping): {'Yes' if ok_ping else 'No'}")
        if hostname:
            summary_lines.append(f"Hostname: {hostname}")
        if mac:
            summary_lines.append(f"MAC: {mac}")
        if vendor:
            summary_lines.append(f"Vendor: {vendor}")

        final = "\n".join(summary_lines) + "\n\n" + "\n\n".join(sections)
        self._q.put(("done", final))

    def _poll(self):
        try:
            while True:
                msg = self._q.get_nowait()
                if msg[0] == "done":
                    self.progress.stop()
                    self.refresh_btn.configure(state="normal")
                    self._set_text(msg[1])
        except Empty:
            pass
        if self.refresh_btn.cget("state") == "disabled":
            self.win.after(100, self._poll)


class NetDiscoveryTab:
    """LAN range scan tab (device discovery)."""

    def __init__(self, parent: tk.Widget):
        self.parent = parent

        self._uiq: Queue = Queue()
        self._worker: Optional[threading.Thread] = None
        self._stop = threading.Event()

        self.vendor_cache: Dict[str, str] = {}
        self.row_by_ip: Dict[str, str] = {}

        self._build_ui()
        self._poll()

    def _build_ui(self):
        self.parent.columnconfigure(0, weight=1)
        self.parent.rowconfigure(0, weight=1)

        nb = ttk.Notebook(self.parent)
        nb.grid(row=0, column=0, sticky="nsew")

        tab_scan = ttk.Frame(nb, padding=12)
        tab_help = ttk.Frame(nb, padding=12)
        nb.add(tab_scan, text="Scan")
        nb.add(tab_help, text="Help")

        tab_scan.columnconfigure(0, weight=1)
        tab_scan.rowconfigure(4, weight=1)

        banner = ttk.Label(
            tab_scan,
            text="Authorized use only: scan networks you own or have explicit permission to assess.",
            foreground="#444",
        )
        banner.grid(row=0, column=0, sticky="w")

        settings = ttk.LabelFrame(tab_scan, text="Scan Settings", padding=10)
        settings.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        settings.columnconfigure(1, weight=1)
        settings.columnconfigure(3, weight=1)

        ttk.Label(settings, text="Start IP:").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=4)
        self.start_ip_var = tk.StringVar(value="192.168.1.0")
        self.start_ip_entry = ttk.Entry(settings, textvariable=self.start_ip_var)
        self.start_ip_entry.grid(row=0, column=1, sticky="ew", pady=4)
        Tooltip(self.start_ip_entry, "The first IP to check (e.g., 192.168.1.0).")

        ttk.Label(settings, text="End Host (0–255):").grid(row=0, column=2, sticky="w", padx=(16, 8), pady=4)
        self.last_host_var = tk.StringVar(value="60")
        self.last_host_entry = ttk.Entry(settings, textvariable=self.last_host_var, width=8)
        self.last_host_entry.grid(row=0, column=3, sticky="w", pady=4)
        Tooltip(self.last_host_entry, "If Start IP is 192.168.1.0 and End Host is 60, scan 192.168.1.0–192.168.1.60.")

        ttk.Label(settings, text="Timeout (ms):").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=4)
        self.timeout_var = tk.StringVar(value="700")
        self.timeout_entry = ttk.Entry(settings, textvariable=self.timeout_var, width=10)
        self.timeout_entry.grid(row=1, column=1, sticky="w", pady=4)
        Tooltip(self.timeout_entry, "Per-IP timeout for ping/ARP attempts.")

        ttk.Label(settings, text="Max runtime (min):").grid(row=1, column=2, sticky="w", padx=(16, 8), pady=4)
        self.max_runtime_var = tk.StringVar(value="5")
        self.max_runtime_entry = ttk.Entry(settings, textvariable=self.max_runtime_var, width=8)
        self.max_runtime_entry.grid(row=1, column=3, sticky="w", pady=4)
        Tooltip(self.max_runtime_entry, "Hard stop if a scan runs longer than this.")

        self.reverse_dns_var = tk.BooleanVar(value=True)
        self.dns_cb = ttk.Checkbutton(settings, text="Try hostname (reverse DNS)", variable=self.reverse_dns_var)
        self.dns_cb.grid(row=2, column=0, columnspan=2, sticky="w", pady=4)
        Tooltip(self.dns_cb, "Optional hostname lookup; often blank on home networks.")

        self.vendor_lookup_var = tk.BooleanVar(value=True)
        self.vendor_cb = ttk.Checkbutton(settings, text="Vendor lookup (online)", variable=self.vendor_lookup_var)
        self.vendor_cb.grid(row=2, column=2, columnspan=2, sticky="w", pady=4)
        Tooltip(self.vendor_cb, "Uses a public MAC vendor lookup service. Leave off if you want no web lookups.")

        controls = ttk.Frame(tab_scan)
        controls.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        controls.columnconfigure(5, weight=1)

        self.scan_btn = ttk.Button(controls, text="Scan", command=self.start_scan)
        self.scan_btn.grid(row=0, column=0, sticky="w")

        self.stop_btn = ttk.Button(controls, text="Stop", command=self.stop_scan, state="disabled")
        self.stop_btn.grid(row=0, column=1, sticky="w", padx=(8, 0))

        self.view_btn = ttk.Button(controls, text="View Selected", command=self.view_selected)
        self.view_btn.grid(row=0, column=2, sticky="w", padx=(8, 0))
        Tooltip(self.view_btn, "Opens the details window for the selected row.")

        self.export_btn = ttk.Button(controls, text="Export CSV", command=self.export_csv)
        self.export_btn.grid(row=0, column=3, sticky="w", padx=(8, 0))
        Tooltip(self.export_btn, "Exports the current table to a CSV file.")

        self.progress = ttk.Progressbar(controls, mode="determinate")
        self.progress.grid(row=0, column=5, sticky="ew", padx=(12, 0))

        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(tab_scan, textvariable=self.status_var).grid(row=3, column=0, sticky="w", pady=(8, 0))

        table = ttk.LabelFrame(tab_scan, text="Devices", padding=10)
        table.grid(row=4, column=0, sticky="nsew", pady=(10, 0))
        table.columnconfigure(0, weight=1)
        table.rowconfigure(0, weight=1)

        cols = ("ip", "mac", "vendor", "host", "reach", "details")
        self.tree = ttk.Treeview(table, columns=cols, show="headings", height=14)
        headings = [
            ("ip", "IP", 140),
            ("mac", "MAC", 160),
            ("vendor", "Vendor", 240),
            ("host", "Hostname", 280),
            ("reach", "Reachable", 110),
            ("details", "Details", 80),
        ]
        for c, h, w in headings:
            self.tree.heading(c, text=h)
            self.tree.column(c, width=w, anchor="w", stretch=(c in ("vendor", "host")))
        self.tree.grid(row=0, column=0, sticky="nsew")

        y = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        y.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=y.set)

        x = ttk.Scrollbar(table, orient="horizontal", command=self.tree.xview)
        x.grid(row=1, column=0, sticky="ew")
        self.tree.configure(xscrollcommand=x.set)

        self.tree.bind("<Button-1>", self._on_tree_click, add=True)
        self.tree.bind("<Double-1>", self._on_tree_double_click, add=True)

        # Help
        tab_help.columnconfigure(0, weight=1)
        tab_help.rowconfigure(0, weight=1)
        box = ttk.LabelFrame(tab_help, text="Help", padding=10)
        box.grid(row=0, column=0, sticky="nsew")
        box.columnconfigure(0, weight=1)
        box.rowconfigure(0, weight=1)

        txt = tk.Text(box, wrap="word")
        txt.grid(row=0, column=0, sticky="nsew")
        sy = ttk.Scrollbar(box, orient="vertical", command=txt.yview)
        sy.grid(row=0, column=1, sticky="ns")
        txt.configure(yscrollcommand=sy.set)
        txt.insert("1.0", HELP_TEXT)
        txt.configure(state="disabled")

        if not is_windows():
            note = (
                "Note: This module is Windows-focused (ARP/NetBIOS/PowerShell helpers).\n"
                "It may still partially work on other OSes, depending on available commands."
            )
            ttk.Label(tab_help, text=note, foreground="#444").grid(row=1, column=0, sticky="w", pady=(10, 0))

    def _set_running(self, running: bool):
        self.scan_btn.configure(state="disabled" if running else "normal")
        self.stop_btn.configure(state="normal" if running else "disabled")
        state = "disabled" if running else "normal"
        for w in (
            self.start_ip_entry,
            self.last_host_entry,
            self.timeout_entry,
            self.max_runtime_entry,
            self.dns_cb,
            self.vendor_cb,
            self.view_btn,
            self.export_btn,
        ):
            w.configure(state=state)

    def _clear_table(self):
        self.row_by_ip.clear()
        for i in self.tree.get_children():
            self.tree.delete(i)

    def start_scan(self):
        if self._worker and self._worker.is_alive():
            return
        try:
            start_ip_s = self.start_ip_var.get().strip()
            end_host = int(self.last_host_var.get().strip())
            timeout_ms = int(self.timeout_var.get().strip())
            max_rt_min = float(self.max_runtime_var.get().strip())

            ip_obj = ipaddress.ip_address(start_ip_s)
            if ip_obj.version != 4:
                raise ValueError("Start IP must be IPv4.")
            if not (0 <= end_host <= 255):
                raise ValueError("End Host must be 0–255.")
            if timeout_ms < 100 or timeout_ms > 10000:
                raise ValueError("Timeout should be 100–10000 ms.")

            # We allow large runtime, but clamp.
            _ = deadline_seconds(max_rt_min, default_minutes=5.0)

        except Exception as e:
            messagebox.showerror("Invalid settings", str(e))
            return

        a, b, c, start_last = [int(x) for x in start_ip_s.split(".")]
        if end_host < start_last:
            messagebox.showerror(
                "Invalid range",
                f"End Host ({end_host}) must be >= the last octet of Start IP ({start_last}).",
            )
            return

        total = (end_host - start_last) + 1
        self.progress.configure(maximum=max(1, total), value=0)

        self._stop.clear()
        self._clear_table()
        self.status_var.set("Scanning...")
        self._set_running(True)

        self._worker = threading.Thread(
            target=self._scan_worker,
            args=(a, b, c, start_last, end_host, timeout_ms, float(self.max_runtime_var.get().strip() or "5")),
            daemon=True,
        )
        self._worker.start()

    def stop_scan(self):
        self._stop.set()
        self.status_var.set("Stopping...")

    def _scan_worker(self, a: int, b: int, c: int, start_last: int, end_host: int, timeout_ms: int, max_rt_min: float):
        try:
            do_dns = bool(self.reverse_dns_var.get())
            do_vendor = bool(self.vendor_lookup_var.get())

            deadline = time.time() + deadline_seconds(max_rt_min, default_minutes=5.0)

            seen: set[str] = set()
            found_count = 0
            done = 0
            total = (end_host - start_last) + 1

            for last in range(start_last, end_host + 1):
                if self._stop.is_set():
                    self._uiq.put(("done", "stopped"))
                    return
                if time.time() >= deadline:
                    self._uiq.put(("done", "timed_out"))
                    return

                ip = f"{a}.{b}.{c}.{last}"

                udp_touch(ip, timeout_ms)
                ok = ping_brief(ip, timeout_ms)
                mac = arp_lookup_ip(ip)

                if ok or mac:
                    if ip not in seen:
                        seen.add(ip)
                        hostname = reverse_dns(ip) if do_dns else ""
                        vendor = ""
                        if do_vendor and mac:
                            oui = mac_to_oui(mac)
                            if oui and oui in self.vendor_cache:
                                vendor = self.vendor_cache[oui]
                            else:
                                vendor = ""
                                self._uiq.put(("vendor_fetch", ip, mac))
                        reach = "Yes" if ok else "No"
                        row = DeviceRow(ip=ip, mac=mac, vendor=vendor, hostname=hostname, reachable=reach)
                        found_count += 1
                        self._uiq.put(("row", row, found_count))

                done += 1
                self._uiq.put(("progress", done, total))

            self._uiq.put(("done", "finished"))
        except Exception as e:
            self._uiq.put(("error", str(e)))

    def _on_tree_click(self, event):
        region = self.tree.identify("region", event.x, event.y)
        if region != "cell":
            return
        row_id = self.tree.identify_row(event.y)
        col = self.tree.identify_column(event.x)
        if not row_id:
            return
        details_col_index = "#6"
        if col == details_col_index:
            ip = self.tree.set(row_id, "ip")
            if ip:
                self.open_details(ip)

    def _on_tree_double_click(self, event):
        row_id = self.tree.identify_row(event.y)
        if not row_id:
            return
        ip = self.tree.set(row_id, "ip")
        if ip:
            self.open_details(ip)

    def view_selected(self):
        sel = self.tree.selection()
        if not sel:
            return
        row_id = sel[0]
        ip = self.tree.set(row_id, "ip")
        if ip:
            self.open_details(ip)

    def open_details(self, ip: str):
        try:
            timeout_ms = int(self.timeout_var.get().strip())
        except Exception:
            timeout_ms = 700
        DeviceDetailsWindow(
            parent=self.parent,
            ip=ip,
            timeout_ms=timeout_ms,
            do_dns=bool(self.reverse_dns_var.get()),
            do_vendor=bool(self.vendor_lookup_var.get()),
            vendor_cache=self.vendor_cache,
            stop_event=self._stop,
        )

    def _vendor_worker(self, ip: str, mac: str):
        oui = mac_to_oui(mac)
        if not oui:
            return
        if oui in self.vendor_cache:
            self._uiq.put(("vendor_update", ip, self.vendor_cache[oui]))
            return
        v = lookup_vendor_online(mac)
        if v:
            self.vendor_cache[oui] = v
            self._uiq.put(("vendor_update", ip, v))

    def export_csv(self):
        rows = []
        for item_id in self.tree.get_children():
            rows.append({
                "ip": self.tree.set(item_id, "ip"),
                "mac": self.tree.set(item_id, "mac"),
                "vendor": self.tree.set(item_id, "vendor"),
                "hostname": self.tree.set(item_id, "host"),
                "reachable": self.tree.set(item_id, "reach"),
            })

        if not rows:
            messagebox.showinfo("Export", "No rows to export.")
            return

        path = filedialog.asksaveasfilename(
            title="Export Devices to CSV",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All files", "*")],
            initialfile=f"enwts_devices_{time.strftime('%Y%m%d_%H%M%S')}.csv",
        )
        if not path:
            return

        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=["ip", "mac", "vendor", "hostname", "reachable"])
                w.writeheader()
                w.writerows(rows)
            messagebox.showinfo("Export", f"Saved: {path}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def _poll(self):
        try:
            while True:
                msg = self._uiq.get_nowait()
                kind = msg[0]

                if kind == "progress":
                    done, total = int(msg[1]), int(msg[2])
                    self.progress.configure(value=done)
                    self.status_var.set(f"Scanning... {done}/{total}")

                elif kind == "row":
                    row: DeviceRow = msg[1]
                    found = int(msg[2])
                    row_id = self.tree.insert("", "end", values=(row.ip, row.mac, row.vendor, row.hostname, row.reachable, "Open"))
                    self.row_by_ip[row.ip] = row_id
                    self.status_var.set(f"Found {found} devices...")

                elif kind == "vendor_fetch":
                    ip, mac = str(msg[1]), str(msg[2])
                    # Limit vendor lookups by letting the OS/network timeouts do their job.
                    threading.Thread(target=self._vendor_worker, args=(ip, mac), daemon=True).start()

                elif kind == "vendor_update":
                    ip, vendor = str(msg[1]), str(msg[2])
                    row_id = self.row_by_ip.get(ip)
                    if row_id:
                        self.tree.set(row_id, "vendor", vendor)

                elif kind == "done":
                    self._set_running(False)
                    mode = msg[1]
                    if mode == "stopped":
                        self.status_var.set("Stopped.")
                    elif mode == "timed_out":
                        self.status_var.set("Stopped: max runtime reached.")
                        self._stop.set()
                    else:
                        self.status_var.set("Finished.")

                elif kind == "error":
                    self._set_running(False)
                    self.status_var.set("Error.")
                    messagebox.showerror("Scan error", msg[1])

        except Empty:
            pass

        self.parent.after(80, self._poll)
