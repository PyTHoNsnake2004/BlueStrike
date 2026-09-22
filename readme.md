# 🔵 BlueStrike

> **Advanced Network Scanner & Vulnerability Analysis Framework**  
> Educational cybersecurity tool built with Python (Flask) + Vanilla JS

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0+-black?style=flat-square&logo=flask)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=flat-square&logo=linux)
![License](https://img.shields.io/badge/License-Educational-orange?style=flat-square)

---

## ⚠️ Legal Disclaimer

> BlueStrike is strictly for **authorized security testing and educational purposes only.**  
> Never scan or attack systems you do not own or have explicit written permission to test.  
> Unauthorized use may violate the Computer Fraud and Abuse Act (CFAA) or local laws.  
> The developers are not responsible for any misuse of this tool.

---

## 📸 Overview

BlueStrike is a web-based network security dashboard that combines:
- Real **Nmap** port scanning with vulnerability detection
- **Host discovery** via netdiscover / ARP sweep
- **CVE-matched vulnerability** reporting
- **Exploit simulation engine** (educational — no real payloads)
- **Live system monitor** (CPU, RAM, GPU, Disk, Network, Services, Security Logs)
- Interactive **network topology map**

---

## 🗂️ Project Structure

```
BlueStrike/
├── app.py              # Flask backend — all API routes & scan logic
├── index.html          # Single-page frontend UI
├── style.css           # Dark theme styling
├── script.js           # Frontend logic (fetch, render, SSE streaming)
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

---

## 🚀 Installation

### Prerequisites

Install system packages (Kali Linux / Debian):

```bash
sudo apt update
sudo apt install nmap netdiscover python3 python3-pip python3-venv -y
```

### Setup

```bash
# 1. Clone or copy the project
cd ~/BlueStrike

# 2. Create a virtual environment
python3 -m venv env
source env/bin/activate       # Linux/macOS
# env\Scripts\activate        # Windows (limited support)

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Run the backend
python3 app.py
```

### Open in Browser

```
http://localhost:5000
```

---

## 🧰 Features

### 🔍 Port Scanner
- Real Nmap scans via subprocess — results streamed live to the UI
- Multiple scan profiles:

| Profile | Nmap Flags | Description |
|---------|-----------|-------------|
| Quick Scan | `-T4 -F` | Fast scan of top 100 ports |
| Service Version | `-sV -T4` | Detect service versions |
| OS Detection | `-O -T4` | Identify operating system |
| Full Scan | `-p- -T4` | All 65535 ports |
| Stealth SYN | `-sS -T4` | SYN scan (requires root) |
| UDP Scan | `-sU -T4` | UDP port scan (requires root) |
| Vulnerability | `--script vuln` | NSE vulnerability scripts |
| Aggressive | `-A -T4` | OS + version + scripts |

- Live streaming terminal output (SSE)
- Stop scan mid-way
- Auto CVE matching on detected services

---

### 🖥️ Host Discovery
- Network sweep using `netdiscover` or `nmap -sn`
- Detects: IP, MAC address, vendor, hostname, status
- Discovered hosts auto-populate scan target field

---

### 🐛 Vulnerability Detection

Automatic CVE matching against detected services:

| Service | CVE | Severity |
|---------|-----|----------|
| SMB (Port 445) | CVE-2017-0143 (EternalBlue) | CRITICAL |
| RDP (Port 3389) | CVE-2019-0708 (BlueKeep) | CRITICAL |
| MySQL (Port 3306) | CVE-2016-6662 | CRITICAL |
| Redis (Port 6379) | CVE-2015-8080 | CRITICAL |
| MongoDB (Port 27017) | CVE-2013-4650 | CRITICAL |
| SSH (Port 22) | CVE-2018-15473 | MEDIUM |
| FTP (Port 21) | CVE-2010-2075 | HIGH |
| Telnet (Port 23) | CVE-2018-1234 | HIGH |
| VNC (Port 5900) | CVE-2006-2450 | HIGH |
| OpenSSH versions | Multiple CVEs | MEDIUM |
| Apache / nginx | Multiple CVEs | MEDIUM–HIGH |

---

### ⚡ Exploit Simulation Engine

> **SIMULATED ONLY — no real payloads are executed.**

Demonstrates how exploits work step-by-step for educational purposes:
- EternalBlue / MS17-010 (SMB)
- BlueKeep / CVE-2019-0708 (RDP)
- SSH Username Enumeration
- vsftpd 2.3.4 Backdoor
- ProFTPD Remote Code Execution
- MySQL Root Code Execution
- VNC Authentication Bypass

Each exploit shows a realistic terminal walkthrough ending with `[!] SIMULATED EXPLOIT — educational purposes only`.

---

### 🗺️ Network Map

Interactive canvas-based topology visualizer:
- Nodes for each discovered host
- Zoom, pan, drag
- Click a node to inspect host details
- Color-coded by host role (router, workstation, server)

---

### 💻 My System (Live Monitor)

Real-time system dashboard — auto-refreshes every 5 seconds.

#### OS & Hardware Tab

| Panel | Metrics |
|-------|---------|
| **CPU** | Frequency (MHz), usage %, temperature °C, core count, model |
| **GPU** | Name, usage %, VRAM used/total, power draw, temperature (via nvidia-smi) |
| **Network** | Hostname, local IP, per-interface RX/TX traffic |
| **Memory** | RAM used/total GB, usage %, free — Disk used/total GB, usage % |

Also shows: Distro name, kernel version, hostname, live uptime.

#### Running Services Tab
- Lists all active systemd services (falls back to `ps` if no systemd)
- Filter/search by service name or description
- Shows: service name, active state, sub-state, description

#### Security Logs Tab
- Ring buffer of up to 500 security events (in-memory)
- Auto-captures:
  - Every **scan start** → `WARNING / NETWORK`
  - Every **exploit click** → `CRITICAL / ATTACK`
  - Every **host discovery** → `WARNING / NETWORK`
  - App startup & session events → `INFO / SYSTEM`
- Filter by **Level** (INFO / WARNING / CRITICAL) and **Category** (AUTH / NETWORK / SYSTEM / ATTACK)
- Auto-refreshes every 3 seconds while the tab is open

---

## 🔌 API Reference

All endpoints are served at `http://localhost:5000/api/`

### Scanner

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/info` | Backend info, nmap version, privileges |
| `POST` | `/api/scan` | Start a port scan (streaming SSE) |
| `POST` | `/api/scan/stop` | Stop active scan |
| `GET` | `/api/hosts` | Get all discovered hosts |

**POST `/api/scan` body:**
```json
{
  "target": "192.168.0.1",
  "scan_type": "service_version",
  "ports": "1-1000",
  "extra_args": ""
}
```

### Host Discovery

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/discover` | Start host discovery (streaming SSE) |
| `POST` | `/api/discover/stop` | Stop active discovery |

### Exploit Engine

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/exploit` | Simulate single exploit (streaming SSE) |
| `POST` | `/api/exploit/all` | Run all detected exploits |

**POST `/api/exploit` body:**
```json
{
  "target": "192.168.0.102",
  "port": 445,
  "cve": "CVE-2017-0143"
}
```

### My System

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/system/stats` | CPU, RAM, GPU, Disk, Network, OS |
| `GET` | `/api/system/services` | Running services list |
| `GET` | `/api/system/logs` | Security event log |
| `POST` | `/api/system/log` | Add a custom log event |

**GET `/api/system/logs` query params:**
```
?limit=100&level=WARNING&category=ATTACK
```

**POST `/api/system/log` body:**
```json
{
  "level": "CRITICAL",
  "category": "ATTACK",
  "message": "Custom event",
  "detail": "Additional detail"
}
```

---

## 🐧 Running on Kali Linux (Recommended)

```bash
# Activate venv as regular user
source ~/BlueStrike/env/bin/activate
python3 app.py

# If you need raw socket scans (SYN/UDP), run as root:
sudo ~/BlueStrike/env/bin/python3 app.py
```

> **Tip:** Don't use `sudo su` before activating the venv — root won't see the venv's packages. Instead pass the venv's Python directly to sudo as shown above.

---

## 🪟 Windows Support

BlueStrike runs on Windows with some limitations:

| Feature | Windows | Linux |
|---------|---------|-------|
| Port Scanner | ✅ (nmap for Windows) | ✅ |
| Host Discovery | ⚠️ Limited | ✅ netdiscover |
| Stealth/SYN Scan | ⚠️ Requires WinPcap | ✅ |
| GPU Stats | ✅ nvidia-smi | ✅ |
| CPU Temp | ❌ | ✅ /sys/class/thermal |
| Running Services | ⚠️ ps fallback | ✅ systemctl |
| System Logs | ✅ | ✅ |

---

## 🛠️ Troubleshooting

### `ModuleNotFoundError: No module named 'flask_cors'`
You ran `python3 app.py` outside the virtual environment, or as root without the venv path.
```bash
# Fix: use the venv python directly
sudo /home/youruser/BlueStrike/env/bin/python3 app.py
```

### Nmap not found
```bash
sudo apt install nmap -y       # Kali/Debian
sudo yum install nmap -y       # RHEL/CentOS
```

### Port scan returns no results
- Ensure the target is reachable (`ping <target>`)
- Some scan types (SYN, UDP) require root privileges
- Try `Quick Scan` first to verify connectivity

### GPU shows "Unknown / Integrated"
nvidia-smi is not installed or no NVIDIA GPU is present. AMD/Intel GPU stats require additional drivers and are not yet supported.

---

## 📦 Dependencies

### Python (pip)
```
flask>=3.0.0
flask-cors>=4.0.0
```

### System
```
nmap
netdiscover
python3
python3-venv
```

### Optional
```
nvidia-smi    (NVIDIA GPU stats in My System)
systemd       (Running Services tab)
```

---

## 🗺️ Roadmap

- [ ] CVE live lookup via NVD API
- [ ] Export scan results to PDF / JSON
- [ ] Scheduled / automated scans
- [ ] Authentication (login page)
- [ ] Dark / light theme toggle
- [ ] Multi-target batch scanning
- [ ] Persistent log storage (SQLite)
- [ ] Plugin system for custom exploits

---

## 👨‍💻 Built With

- **Backend:** Python 3, Flask, subprocess (nmap/netdiscover), threading, SSE streaming
- **Frontend:** Vanilla HTML5 / CSS3 / JavaScript (no frameworks)
- **Visualisation:** HTML5 Canvas (network map)
- **Styling:** Custom dark theme with CSS variables

---

## 📄 License

This project is intended for **educational and authorized penetration testing use only.**  
Do not use against systems without explicit permission.

---

*BlueStrike — Know your network before the attacker does.*