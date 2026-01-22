"""Common helpers for ENWTS (Ethical Networking Tools).

ENWTS is intended for *authorized* network testing and education.
"""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass
from typing import Optional, Sequence, Tuple

import tkinter as tk
from tkinter import ttk


APP_NAME = "ENWTS"
APP_FULL_NAME = "ENWTS (Ethical Networking Tools)"
APP_VERSION = "1.0.0"

# Hide console windows spawned by subprocess on Windows.
CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def is_windows() -> bool:
    return os.name == "nt"


@dataclass(frozen=True)
class CmdResult:
    rc: int
    out: str
    err: str
    timed_out: bool = False
    not_found: bool = False


def run_cmd(cmd: Sequence[str], timeout: float = 10.0) -> CmdResult:
    """Run a command with a hard timeout, capturing stdout/stderr.

    Returns a CmdResult. Never raises.
    """
    try:
        cp = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            creationflags=CREATE_NO_WINDOW,
        )
        return CmdResult(cp.returncode, cp.stdout or "", cp.stderr or "")
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode(errors="replace") if isinstance(e.stdout, (bytes, bytearray)) else (e.stdout or "")
        err = e.stderr.decode(errors="replace") if isinstance(e.stderr, (bytes, bytearray)) else (e.stderr or "")
        if not err:
            err = f"Command timed out after {timeout}s: {list(cmd)!r}"
        return CmdResult(124, out or "", err, timed_out=True)
    except FileNotFoundError:
        return CmdResult(127, "", f"Command not found: {cmd[0]}", not_found=True)
    except Exception as e:
        return CmdResult(1, "", f"Command error: {e}")


def deadline_seconds(max_minutes: float, default_minutes: float) -> float:
    """Convert a UI minutes value to seconds, with sane bounds."""
    try:
        m = float(max_minutes)
    except Exception:
        m = float(default_minutes)
    # 0 means "no limit" but we don't allow that by default; clamp at 0.5..240 minutes.
    if m <= 0:
        m = float(default_minutes)
    m = max(0.5, min(240.0, m))
    return m * 60.0


def now_str() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


class Tooltip:
    """Tiny Tk tooltip (hover for ~450ms)."""

    def __init__(self, widget: tk.Widget, text: str):
        self.widget = widget
        self.text = text
        self.tip: Optional[tk.Toplevel] = None
        self._after_id: Optional[str] = None
        widget.bind("<Enter>", self._schedule, add=True)
        widget.bind("<Leave>", self._hide, add=True)
        widget.bind("<ButtonPress>", self._hide, add=True)

    def _schedule(self, _evt=None):
        self._cancel()
        self._after_id = self.widget.after(450, self._show)

    def _cancel(self):
        if self._after_id:
            try:
                self.widget.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None

    def _show(self):
        if self.tip is not None:
            return
        try:
            x = self.widget.winfo_rootx() + 10
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 8
        except Exception:
            return
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f"+{x}+{y}")
        frm = ttk.Frame(self.tip, padding=8)
        frm.grid(row=0, column=0, sticky="nsew")
        ttk.Label(frm, text=self.text, justify="left").grid(row=0, column=0, sticky="w")

    def _hide(self, _evt=None):
        self._cancel()
        if self.tip is not None:
            try:
                self.tip.destroy()
            except Exception:
                pass
            self.tip = None
