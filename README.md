# ENWTS (Ethical Networking Tools)

ENWTS is a small, GUI-based toolkit designed for **authorized network testing and education**.
It focuses on transparency, safety, and ease of use rather than offensive exploitation.

The application bundles three related utilities into a single interface:

- **LAN Discovery** – Scan a local IPv4 range and list likely devices (best-effort using ping/ARP, optional reverse DNS, and optional MAC vendor lookup).
- **Net Probe** – Perform TCP/UDP port scans and basic reachability checks (ping with optional ARP).
- **Port Scope** – Audit local listening ports and, on Windows, display firewall allow status (best-effort).

## Ethical use

Only use ENWTS on systems and networks that you **own** or where you have **explicit written authorization** to perform testing.

Malicious use is **not authorized** and is **not the purpose for which this software was developed**.

## Requirements

- Python **3.11+** (recommended)
- Tkinter  
  - Included with standard Python installs on Windows and macOS  
  - May require an additional package on some Linux distributions

No third-party Python packages are required.

## Running ENWTS

From the project directory:

```bash
python ENWTS.py
```

Or:

```bash
python -m enwts
```

## Exporting results

- **LAN Discovery**: Export CSV saves the current device table.
- **Net Probe**: Save Results writes the output window to a `.txt` file.
- **Port Scope**: Export CSV saves the current findings.

## Platform notes

- **Net Probe** is mostly cross-platform.
- **LAN Discovery** and **Port Scope** are **Windows-focused**, as they rely on Windows utilities such as:
  - `arp`
  - `netstat -ano`
  - `tasklist`
  - PowerShell firewall cmdlets

On non-Windows systems, some features may be limited or disabled.

## Network services used (optional)

ENWTS can optionally access public services:

- **Public IP detection**: https://api.ipify.org
- **MAC vendor lookup** (LAN Discovery): https://api.macvendors.com/

MAC vendor lookup can be disabled if you prefer not to make any external web requests.

## Packaging (Windows executable)

To build a Windows executable, PyInstaller can be used.

Example:

```bash
pip install pyinstaller
pyinstaller --noconsole --onefile --name ENWTS ENWTS.py
```

The executable will be created in the `dist/` directory.

## Disclaimer

This software is provided for educational and authorized testing purposes only.
The author(s) and contributors assume no responsibility for misuse or unauthorized deployment.
