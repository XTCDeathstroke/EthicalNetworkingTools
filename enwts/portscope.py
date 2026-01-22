#!/usr/bin/env python3
from __future__ import annotations

import csv
import ipaddress
import re
import threading
import time
from dataclasses import dataclass
from queue import Queue, Empty
from typing import Dict, List, Optional, Set, Tuple

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from .common import Tooltip, deadline_seconds, is_windows, run_cmd


@dataclass(frozen=True)
class ListenerRow:
    proto: str
    local_ip: str
    port: int
    pid: int
    process: str
    exposure: str
    firewall_allow: str


def _run(cmd: List[str], timeout: float = 10.0) -> str:
    r = run_cmd(cmd, timeout=timeout)
    return (r.out or "") + (("\n" + r.err) if r.err else "")


def get_lan_ipv4() -> str:
    try:
        import socket

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
        import urllib.request

        with urllib.request.urlopen("https://api.ipify.org", timeout=2.5) as r:
            ip = r.read().decode().strip()
        ipaddress.ip_address(ip)
        return ip
    except Exception:
        return "Unavailable"


def parse_netstat_listeners(include_tcp: bool, include_udp: bool) -> List[Tuple[str, str, int, int]]:
    lines: List[str] = []
    if include_tcp:
        out = _run(["netstat", "-ano", "-p", "tcp"], timeout=15.0)
        lines.extend(out.splitlines())
    if include_udp:
        out = _run(["netstat", "-ano", "-p", "udp"], timeout=15.0)
        lines.extend(out.splitlines())

    rows: List[Tuple[str, str, int, int]] = []

    tcp_re = re.compile(r"^\s*TCP\s+(\S+):(\d+)\s+\S+:\S+\s+LISTENING\s+(\d+)\s*$", re.IGNORECASE)
    udp_re = re.compile(r"^\s*UDP\s+(\S+):(\d+)\s+\S+\s+(\d+)\s*$", re.IGNORECASE)

    for line in lines:
        m = tcp_re.match(line)
        if m:
            ip_s, port_s, pid_s = m.group(1), m.group(2), m.group(3)
            rows.append(("TCP", ip_s, int(port_s), int(pid_s)))
            continue
        m = udp_re.match(line)
        if m:
            ip_s, port_s, pid_s = m.group(1), m.group(2), m.group(3)
            rows.append(("UDP", ip_s, int(port_s), int(pid_s)))
            continue

    uniq = list({(p, ip, port, pid) for (p, ip, port, pid) in rows})
    uniq.sort(key=lambda x: (x[0], x[2], x[1], x[3]))
    return uniq


def pid_to_process_name(pid: int) -> str:
    try:
        out = _run(["tasklist", "/fi", f"PID eq {pid}", "/fo", "csv", "/nh"], timeout=10.0).strip()
        if not out or out.lower().startswith("info:"):
            return "Unknown"
        parts = [p.strip().strip('"') for p in out.split(",")]
        if parts and parts[0]:
            return parts[0]
        return "Unknown"
    except Exception:
        return "Unknown"


def classify_exposure(local_ip: str) -> str:
    ip = local_ip.strip().lower()
    if ip in ("127.0.0.1", "::1"):
        return "Local-only"
    if ip in ("0.0.0.0", "::"):
        return "All interfaces"
    try:
        obj = ipaddress.ip_address(ip)
        if obj.is_private:
            return "LAN interface"
        if obj.is_loopback:
            return "Local-only"
        return "Non-private interface"
    except Exception:
        return "Unknown"


def get_allowed_inbound_ports() -> Dict[str, Set[int]]:
    ps = (
        "Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow | "
        "Get-NetFirewallPortFilter | "
        "Select-Object Protocol,LocalPort | "
        "ConvertTo-Csv -NoTypeInformation"
    )
    try:
        out = _run(["powershell", "-NoProfile", "-Command", ps], timeout=25.0)
        allow_tcp: Set[int] = set()
        allow_udp: Set[int] = set()
        for line in out.splitlines():
            line = line.strip()
            if not line or line.lower().startswith('"protocol"'):
                continue
            parts = [p.strip().strip('"') for p in line.split(",")]
            if len(parts) < 2:
                continue
            proto_s, port_s = parts[0].upper(), parts[1]
            if not port_s or port_s in ("Any", "*"):
                continue
            if "-" in port_s:
                a, b = port_s.split("-", 1)
                try:
                    start = int(a)
                    end = int(b)
                    if 1 <= start <= end <= 65535:
                        rng = range(start, end + 1)
                        if proto_s == "TCP":
                            allow_tcp.update(rng)
                        elif proto_s == "UDP":
                            allow_udp.update(rng)
                except Exception:
                    continue
            else:
                try:
                    p = int(port_s)
                    if 1 <= p <= 65535:
                        if proto_s == "TCP":
                            allow_tcp.add(p)
                        elif proto_s == "UDP":
                            allow_udp.add(p)
                except Exception:
                    continue
        return {"TCP": allow_tcp, "UDP": allow_udp}
    except Exception:
        return {"TCP": set(), "UDP": set()}


HELP_TEXT = (
    "What this tool does\n"
    "  Shows which programs are listening on your PC and whether they look local-only or network-reachable.\n\n"
    "Listening port\n"
    "  A service is waiting for connections on a port number. Open ports are part of your 'attack surface'.\n\n"
    "Exposure (this app)\n"
    "  Local-only: reachable only from this machine.\n"
    "  LAN interface: reachable from other devices on your local network (if firewall allows).\n"
    "  All interfaces: reachable on any interface (LAN/Wi-Fi/VPN), firewall still applies.\n\n"
    "Firewall Allow\n"
    "  Best-effort check of Windows inbound allow rules for that protocol/port.\n"
    "  Even if a program listens, the firewall can block inbound connections.\n\n"
    "Max runtime\n"
    "  ENWTS will stop analysis if it exceeds the configured maximum runtime.\n"
)


class PortScopeTab:
    """Local listener audit tab."""

    def __init__(self, parent: tk.Widget):
        self.parent = parent

        self._uiq: Queue = Queue()
        self._worker: Optional[threading.Thread] = None
        self._stop = threading.Event()

        self.loopback_ip = "127.0.0.1"
        self.lan_ip_var = tk.StringVar(value=get_lan_ipv4())
        self.public_ip_var = tk.StringVar(value=get_public_ip())

        self.include_tcp_var = tk.BooleanVar(value=True)
        self.include_udp_var = tk.BooleanVar(value=True)
        self.include_ephemeral_var = tk.BooleanVar(value=False)

        self.status_var = tk.StringVar(value="Ready.")
        self._build_ui()
        self._poll()

    def _build_ui(self):
        self.parent.columnconfigure(0, weight=1)
        self.parent.rowconfigure(0, weight=1)

        nb = ttk.Notebook(self.parent)
        nb.grid(row=0, column=0, sticky="nsew")

        scan_tab = ttk.Frame(nb, padding=12)
        help_tab = ttk.Frame(nb, padding=12)
        nb.add(scan_tab, text="Audit")
        nb.add(help_tab, text="Help")

        scan_tab.columnconfigure(0, weight=1)
        scan_tab.rowconfigure(4, weight=1)

        banner = ttk.Label(
            scan_tab,
            text="Authorized use only: audit systems you own or have explicit permission to test.",
            foreground="#444",
        )
        banner.grid(row=0, column=0, sticky="w")

        top = ttk.LabelFrame(scan_tab, text="This Computer", padding=10)
        top.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        top.columnconfigure(1, weight=1)

        ttk.Label(top, text="Loopback (localhost):").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Label(top, text=self.loopback_ip).grid(row=0, column=1, sticky="w", pady=4)

        ttk.Label(top, text="LAN IPv4:").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Label(top, textvariable=self.lan_ip_var).grid(row=1, column=1, sticky="w", pady=4)
        btn_lan = ttk.Button(top, text="Refresh", width=10, command=lambda: self.lan_ip_var.set(get_lan_ipv4()))
        btn_lan.grid(row=1, column=2, sticky="e", padx=(8, 0), pady=4)
        Tooltip(btn_lan, "Re-detects your LAN IP.")

        ttk.Label(top, text="Public IPv4:").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Label(top, textvariable=self.public_ip_var).grid(row=2, column=1, sticky="w", pady=4)
        btn_pub = ttk.Button(top, text="Refresh", width=10, command=lambda: self.public_ip_var.set(get_public_ip()))
        btn_pub.grid(row=2, column=2, sticky="e", padx=(8, 0), pady=4)
        Tooltip(btn_pub, "Re-detects your public IP.")

        settings = ttk.LabelFrame(scan_tab, text="Audit Settings", padding=10)
        settings.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        for c in range(6):
            settings.columnconfigure(c, weight=1)

        cb_tcp = ttk.Checkbutton(settings, text="TCP listeners", variable=self.include_tcp_var)
        cb_udp = ttk.Checkbutton(settings, text="UDP listeners", variable=self.include_udp_var)
        cb_eph = ttk.Checkbutton(settings, text="Include ephemeral ports (>= 49152)", variable=self.include_ephemeral_var)

        cb_tcp.grid(row=0, column=0, sticky="w")
        cb_udp.grid(row=0, column=1, sticky="w")
        cb_eph.grid(row=0, column=2, sticky="w")

        Tooltip(cb_tcp, "Shows TCP ports in LISTENING state.")
        Tooltip(cb_udp, "Shows UDP endpoints (best-effort representation of listeners).")
        Tooltip(cb_eph, "Shows high-numbered ports often used temporarily by apps; can be noisy.")

        ttk.Label(settings, text="Max runtime (min):").grid(row=0, column=3, sticky="w", padx=(16, 8))
        self.max_runtime_var = tk.StringVar(value="2")
        self.max_runtime_entry = ttk.Entry(settings, textvariable=self.max_runtime_var, width=8)
        self.max_runtime_entry.grid(row=0, column=4, sticky="w")
        Tooltip(self.max_runtime_entry, "Hard stop if analysis runs longer than this.")

        controls = ttk.Frame(scan_tab)
        controls.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        controls.columnconfigure(3, weight=1)

        self.btn_run = ttk.Button(controls, text="Analyze", command=self.start_audit)
        self.btn_run.grid(row=0, column=0, sticky="w")
        Tooltip(self.btn_run, "Collects listening ports, owner processes, and firewall allow status.")

        self.btn_stop = ttk.Button(controls, text="Stop", command=self.stop_audit, state="disabled")
        self.btn_stop.grid(row=0, column=1, sticky="w", padx=(8, 0))
        Tooltip(self.btn_stop, "Stops analysis after current steps finish.")

        self.export_btn = ttk.Button(controls, text="Export CSV", command=self.export_csv)
        self.export_btn.grid(row=0, column=2, sticky="w", padx=(8, 0))

        self.progress = ttk.Progressbar(controls, mode="indeterminate")
        self.progress.grid(row=0, column=3, sticky="ew", padx=(12, 0))

        ttk.Label(scan_tab, textvariable=self.status_var).grid(row=4, column=0, sticky="w", pady=(8, 0))

        table_frame = ttk.LabelFrame(scan_tab, text="Findings", padding=10)
        table_frame.grid(row=5, column=0, sticky="nsew", pady=(10, 0))
        scan_tab.rowconfigure(5, weight=1)
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)

        cols = ("proto", "local", "port", "pid", "proc", "exposure", "fw")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", height=14)
        for c, h, w in [
            ("proto", "Proto", 70),
            ("local", "Local Address", 170),
            ("port", "Port", 70),
            ("pid", "PID", 70),
            ("proc", "Process", 220),
            ("exposure", "Exposure", 140),
            ("fw", "Firewall Allow", 120),
        ]:
            self.tree.heading(c, text=h)
            self.tree.column(c, width=w, anchor="w", stretch=(c in ("proc", "local")))
        self.tree.grid(row=0, column=0, sticky="nsew")

        y = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        y.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=y.set)

        x = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        x.grid(row=1, column=0, sticky="ew")
        self.tree.configure(xscrollcommand=x.set)

        # Help
        help_tab.columnconfigure(0, weight=1)
        help_tab.rowconfigure(0, weight=1)
        help_box = ttk.LabelFrame(help_tab, text="Terms & Definitions", padding=10)
        help_box.grid(row=0, column=0, sticky="nsew")
        help_box.columnconfigure(0, weight=1)
        help_box.rowconfigure(0, weight=1)

        txt = tk.Text(help_box, wrap="word")
        txt.grid(row=0, column=0, sticky="nsew")
        sy = ttk.Scrollbar(help_box, orient="vertical", command=txt.yview)
        sy.grid(row=0, column=1, sticky="ns")
        txt.configure(yscrollcommand=sy.set)
        txt.insert("1.0", HELP_TEXT)
        txt.configure(state="disabled")

        if not is_windows():
            ttk.Label(
                help_tab,
                text=(
                    "Note: PortScope uses Windows netstat/tasklist/PowerShell to map ports to processes and firewall rules.\n"
                    "On non-Windows OSes this module is disabled."
                ),
                foreground="#444",
            ).grid(row=1, column=0, sticky="w", pady=(10, 0))

            # Disable actions on non-Windows.
            self.btn_run.configure(state="disabled")

    def _set_running(self, running: bool):
        self.btn_run.configure(state="disabled" if running else ("normal" if is_windows() else "disabled"))
        self.btn_stop.configure(state="normal" if running else "disabled")
        self.export_btn.configure(state="disabled" if running else "normal")
        self.max_runtime_entry.configure(state="disabled" if running else "normal")
        if running:
            self.progress.start(10)
        else:
            self.progress.stop()

    def _clear(self):
        for i in self.tree.get_children():
            self.tree.delete(i)

    def start_audit(self):
        if not is_windows():
            messagebox.showinfo("PortScope", "PortScope is Windows-only in this release.")
            return
        if self._worker and self._worker.is_alive():
            return
        if not (self.include_tcp_var.get() or self.include_udp_var.get()):
            messagebox.showerror("Invalid settings", "Select at least one of TCP listeners or UDP listeners.")
            return

        try:
            max_rt_min = float(self.max_runtime_var.get())
            _ = deadline_seconds(max_rt_min, default_minutes=2.0)
        except Exception as e:
            messagebox.showerror("Invalid settings", str(e))
            return

        self._stop.clear()
        self._clear()
        self.status_var.set("Analyzing...")
        self._set_running(True)
        self._worker = threading.Thread(target=self._audit_worker, args=(max_rt_min,), daemon=True)
        self._worker.start()

    def stop_audit(self):
        self._stop.set()
        self.status_var.set("Stopping...")

    def _audit_worker(self, max_rt_min: float):
        try:
            deadline = time.time() + deadline_seconds(max_rt_min, default_minutes=2.0)

            include_tcp = bool(self.include_tcp_var.get())
            include_udp = bool(self.include_udp_var.get())
            include_eph = bool(self.include_ephemeral_var.get())

            if time.time() >= deadline:
                self._uiq.put(("done", "timed_out"))
                return

            listeners = parse_netstat_listeners(include_tcp, include_udp)

            if not include_eph:
                listeners = [r for r in listeners if r[2] < 49152]

            if self._stop.is_set() or time.time() >= deadline:
                self._uiq.put(("done", "timed_out" if time.time() >= deadline else "stopped"))
                return

            allow = get_allowed_inbound_ports()

            pid_cache: Dict[int, str] = {}

            out_rows: List[ListenerRow] = []
            for proto, ip_s, port, pid in listeners:
                if self._stop.is_set() or time.time() >= deadline:
                    self._uiq.put(("done", "timed_out" if time.time() >= deadline else "stopped"))
                    return
                if pid not in pid_cache:
                    pid_cache[pid] = pid_to_process_name(pid)
                proc = pid_cache[pid]
                exposure = classify_exposure(ip_s)
                fw_allow = "Unknown"
                if allow["TCP"] or allow["UDP"]:
                    fw_allow = "Allow" if port in allow.get(proto, set()) else "No rule"
                out_rows.append(
                    ListenerRow(
                        proto=proto,
                        local_ip=ip_s,
                        port=port,
                        pid=pid,
                        process=proc,
                        exposure=exposure,
                        firewall_allow=fw_allow,
                    )
                )

            out_rows.sort(key=lambda r: (r.proto, r.port, r.local_ip, r.pid))
            self._uiq.put(("rows", out_rows))
            self._uiq.put(("done", "finished"))
        except Exception as e:
            self._uiq.put(("error", str(e)))

    def export_csv(self):
        rows = []
        for item_id in self.tree.get_children():
            rows.append(
                {
                    "proto": self.tree.set(item_id, "proto"),
                    "local_ip": self.tree.set(item_id, "local"),
                    "port": self.tree.set(item_id, "port"),
                    "pid": self.tree.set(item_id, "pid"),
                    "process": self.tree.set(item_id, "proc"),
                    "exposure": self.tree.set(item_id, "exposure"),
                    "firewall_allow": self.tree.set(item_id, "fw"),
                }
            )

        if not rows:
            messagebox.showinfo("Export", "No rows to export.")
            return

        path = filedialog.asksaveasfilename(
            title="Export Findings to CSV",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All files", "*")],
            initialfile=f"enwts_portscope_{time.strftime('%Y%m%d_%H%M%S')}.csv",
        )
        if not path:
            return

        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(
                    f,
                    fieldnames=["proto", "local_ip", "port", "pid", "process", "exposure", "firewall_allow"],
                )
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
                if kind == "rows":
                    rows: List[ListenerRow] = msg[1]
                    for r in rows:
                        self.tree.insert("", "end", values=(r.proto, r.local_ip, r.port, r.pid, r.process, r.exposure, r.firewall_allow))
                    self.status_var.set(f"Found {len(rows)} listeners.")
                elif kind == "done":
                    mode = msg[1]
                    self._set_running(False)
                    if mode == "stopped":
                        self.status_var.set("Stopped.")
                    elif mode == "timed_out":
                        self.status_var.set("Stopped: max runtime reached.")
                    else:
                        # keep the count message
                        pass
                elif kind == "error":
                    self._set_running(False)
                    self.status_var.set("Error.")
                    messagebox.showerror("Audit error", msg[1])
        except Empty:
            pass
        self.parent.after(80, self._poll)
