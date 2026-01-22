#!/usr/bin/env python3
from __future__ import annotations

import os
import tkinter as tk
from tkinter import ttk, messagebox

from .common import APP_FULL_NAME, APP_VERSION, is_windows
from .netdiscovery import NetDiscoveryTab
from .netprobe import NetProbeTab
from .portscope import PortScopeTab


ETHICAL_USE_TEXT = (
    "ENWTS is intended for authorized network testing and education.\n\n"
    "Only use ENWTS on systems and networks you own or have explicit written permission to assess.\n\n"
    "Malicious use is not authorized and is not what this software was developed for."
)


def _apply_theme(root: tk.Tk) -> None:
    try:
        root.tk.call("tk", "scaling", 1.0)
    except Exception:
        pass

    style = ttk.Style(root)
    # Prefer a Windows-native look when available.
    for theme in ("vista", "xpnative", "clam", "default"):
        try:
            style.theme_use(theme)
            break
        except Exception:
            continue


def _show_ethics_prompt(root: tk.Tk) -> bool:
    # Keep it simple and explicit.
    return messagebox.askyesno(
        title="Ethical use notice",
        message=ETHICAL_USE_TEXT + "\n\nDo you agree to use this tool responsibly?",
        parent=root,
    )


def _build_about_tab(parent: tk.Widget) -> None:
    parent.columnconfigure(0, weight=1)
    parent.rowconfigure(0, weight=1)

    box = ttk.LabelFrame(parent, text="About ENWTS", padding=12)
    box.grid(row=0, column=0, sticky="nsew", padx=12, pady=12)
    box.columnconfigure(0, weight=1)
    box.rowconfigure(0, weight=1)

    txt = tk.Text(box, wrap="word", height=18)
    txt.grid(row=0, column=0, sticky="nsew")
    sy = ttk.Scrollbar(box, orient="vertical", command=txt.yview)
    sy.grid(row=0, column=1, sticky="ns")
    txt.configure(yscrollcommand=sy.set)

    content = (
        f"{APP_FULL_NAME} v{APP_VERSION}\n\n"
        "Purpose\n"
        "  ENWTS bundles several small utilities to help you understand and assess networks ethically.\n\n"
        "Included tools\n"
        "  • LAN Discovery: scan a LAN range to identify likely devices (best effort).\n"
        "  • Net Probe: TCP/UDP port scanning and basic reachability checks (best effort).\n"
        "  • Port Scope: audit local listening ports and (Windows) firewall allow status.\n\n"
        "Ethical use\n"
        "  Only test systems you own or have explicit permission to test.\n\n"
        "Platform\n"
        "  Net Probe is mostly cross-platform. LAN Discovery and Port Scope are Windows-focused.\n\n"
        "Copyright\n"
        "  Copyright (c) 2026 Christian Huttunen\n"
    )

    txt.insert("1.0", content)
    txt.configure(state="disabled")

    foot = ttk.Label(
        parent,
        text=(
            "Tip: For packaging into a single Windows .exe, see README.md (PyInstaller)."
        ),
        foreground="#444",
    )
    foot.grid(row=1, column=0, sticky="w", padx=12, pady=(0, 12))


def run() -> None:
    root = tk.Tk()
    root.title(f"{APP_FULL_NAME} v{APP_VERSION}")
    root.minsize(1100, 760)

    _apply_theme(root)

    if not _show_ethics_prompt(root):
        root.destroy()
        return

    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)

    nb = ttk.Notebook(root)
    nb.grid(row=0, column=0, sticky="nsew")

    tab_discovery = ttk.Frame(nb, padding=0)
    tab_probe = ttk.Frame(nb, padding=0)
    tab_scope = ttk.Frame(nb, padding=0)
    tab_about = ttk.Frame(nb, padding=0)

    nb.add(tab_discovery, text="LAN Discovery")
    nb.add(tab_probe, text="Net Probe")
    nb.add(tab_scope, text="Port Scope")
    nb.add(tab_about, text="About")

    # Instantiate tools.
    NetDiscoveryTab(tab_discovery)
    NetProbeTab(tab_probe)
    PortScopeTab(tab_scope)
    _build_about_tab(tab_about)

    # If non-Windows, give a small hint up front.
    if not is_windows():
        try:
            messagebox.showinfo(
                "Platform note",
                "Some ENWTS modules are Windows-focused. If you see disabled buttons, that is expected on this OS.",
                parent=root,
            )
        except Exception:
            pass

    root.mainloop()


if __name__ == "__main__":
    run()
