# ENWTS (Ethical Networking Tools)

ENWTS is a small, GUI-based toolkit for **authorized** network testing and education.

It bundles three utilities into one application:

- **LAN Discovery** – scan a LAN IPv4 range and list likely devices (best effort; ping/ARP + optional reverse DNS + optional MAC vendor lookup).
- **Net Probe** – TCP/UDP port scanning and basic reachability checks (ping + optional ARP).
- **Port Scope** – audit local listening ports and (Windows) firewall allow status (best effort).

## Ethical use

Only use ENWTS on systems and networks you **own** or where you have **explicit written permission** to assess.

Malicious use is **not authorized** and is **not what this software was developed for**.

## Requirements

- Python **3.11+** recommended
- Tkinter (usually included with standard Python installs on Windows/macOS; may require an extra package on some Linux distros)

No third-party Python packages are required.

## Run

From the project folder:

```bash
python ENWTS.py
```

Or:

```bash
python -m enwts
```

## Exporting results

- LAN Discovery: **Export CSV** exports the current device table.
- Net Probe: **Save Results** saves the output window to a `.txt` file.
- Port Scope: **Export CSV** exports the current findings.

## Platform notes

- **Net Probe** is mostly cross-platform.
- **LAN Discovery** and **Port Scope** are **Windows-focused** because they use Windows utilities (e.g., `arp`, `netstat -ano`, `tasklist`, PowerShell firewall cmdlets). They may be partially disabled or limited on non-Windows systems.

## Network services used (optional)

ENWTS can make optional requests to public services:

- **Public IP detection** uses `https://api.ipify.org`
- **MAC vendor lookup** (LAN Discovery) uses `https://api.macvendors.com/`

You can disable vendor lookup in LAN Discovery if you do not want any web lookups.

## Packaging (Windows .exe)

If you want a single-file Windows executable, PyInstaller is a common choice.

Example:

```bash
pip install pyinstaller
pyinstaller --noconsole --onefile --name ENWTS ENWTS.py
```

The executable will be created under `dist/`.

## Disclaimer

This software is provided for educational and authorized testing purposes. The author(s) and contributors assume no responsibility for misuse.
