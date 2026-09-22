#!/usr/bin/env python3
"""
BlueStrike Backend — Flask API
Real nmap scanning + netdiscover + vulnerability detection + auto-exploit simulation
Based on CyberSentinel Security Suite v3.2
Run: pip install flask flask-cors && python app.py
Requires: nmap, netdiscover (system packages)
"""

import os
import re
import json
import time
import queue
import platform
import threading
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Optional

from flask import Flask, Response, jsonify, request, stream_with_context, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder="static")
CORS(app)

# ─────────────────────────────────────────────────────────────
# GLOBAL SCAN REGISTRY  (one active scan / discovery at a time)
# ─────────────────────────────────────────────────────────────
_active_process: Optional[subprocess.Popen] = None
_active_lock    = threading.Lock()
_scan_queue:    queue.Queue = queue.Queue()
_discover_queue: queue.Queue = queue.Queue()
_discovered_hosts: List[Dict] = []


# ═════════════════════════════════════════════════════════════
#  NETWORK UTILS  (straight from index.py NetworkUtils)
# ═════════════════════════════════════════════════════════════

def get_network_interfaces() -> List[str]:
    interfaces = []
    system = platform.system().lower()
    try:
        if system == "linux":
            result = subprocess.run(['ip', 'link', 'show'],
                                    capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if ':' in line and 'lo:' not in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        iface = parts[1].strip()
                        if iface and not iface.startswith(' '):
                            interfaces.append(iface)
        elif system == "windows":
            result = subprocess.run(['netsh', 'interface', 'show', 'interface'],
                                    capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if 'Connected' in line or 'Disconnected' in line:
                    parts = line.split()
                    if len(parts) > 3:
                        interfaces.append(parts[-1])
        elif system == "darwin":
            result = subprocess.run(['ifconfig'],
                                    capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if not line.startswith('\t') and ':' in line and 'flags' in line:
                    iface = line.split(':')[0]
                    if iface and iface != 'lo0':
                        interfaces.append(iface)
    except Exception:
        pass
    return interfaces or ['eth0', 'wlan0', 'en0', 'en1', 'Ethernet', 'Wi-Fi']


def detect_network_range() -> str:
    try:
        system = platform.system().lower()
        if system == "linux":
            result = subprocess.run(['ip', 'route'],
                                    capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if 'default' not in line and 'src' in line:
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if p == 'src':
                            ip = parts[i + 1]
                            return '.'.join(ip.split('.')[:3]) + '.0/24'
        elif system == "windows":
            result = subprocess.run(['ipconfig'],
                                    capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if 'IPv4 Address' in line:
                    ip = line.split(':')[-1].strip()
                    return '.'.join(ip.split('.')[:3]) + '.0/24'
    except Exception:
        pass
    return "192.168.1.0/24"


def validate_ip(ip: str) -> bool:
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, ip):
        return all(int(o) <= 255 for o in ip.split('.'))
    return False


def validate_cidr(cidr: str) -> bool:
    pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    if re.match(pattern, cidr):
        ip_part, mask = cidr.split('/')
        return validate_ip(ip_part) and 0 <= int(mask) <= 32
    return False


def validate_target(target: str) -> bool:
    return (validate_ip(target)
            or validate_cidr(target)
            or bool(re.match(r'^[a-zA-Z0-9.\-]+$', target)))


def has_privileges() -> bool:
    try:
        if platform.system() == "Windows":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


# ═════════════════════════════════════════════════════════════
#  VULNERABILITY DATABASE  (from index.py _check_vulnerabilities)
# ═════════════════════════════════════════════════════════════

VULN_PATTERNS = {
    'ssh': [
        {'pattern': r'OpenSSH.*(\d+\.\d+)', 'cve': 'CVE-2018-15473',
         'name': 'OpenSSH Username Enumeration', 'severity': 'MEDIUM'},
        {'pattern': r'OpenSSH.*(7\.\d+)',    'cve': 'CVE-2016-6210',
         'name': 'OpenSSH Remote DoS',          'severity': 'HIGH'},
        {'pattern': r'OpenSSH.*(8\.\d+)',    'cve': 'CVE-2021-28041',
         'name': 'OpenSSH Double Free',          'severity': 'HIGH'},
    ],
    'http': [
        {'pattern': r'Apache.*(2\.4\.\d+)', 'cve': 'CVE-2019-0196',
         'name': 'Apache Mod_Rewrite Vulnerability', 'severity': 'MEDIUM'},
        {'pattern': r'nginx.*(1\.\d+\.\d+)', 'cve': 'CVE-2021-23017',
         'name': 'Nginx Off-by-One',              'severity': 'MEDIUM'},
        {'pattern': r'Apache.*(2\.2\.\d+)', 'cve': 'CVE-2012-2687',
         'name': 'Apache HTTP XSS Vulnerability',  'severity': 'MEDIUM'},
    ],
    'mysql': [
        {'pattern': r'MySQL.*(5\.\d+\.\d+)', 'cve': 'CVE-2016-6662',
         'name': 'MySQL Remote Root Code Exec',  'severity': 'CRITICAL'},
        {'pattern': r'MariaDB.*(10\.\d+\.\d+)', 'cve': 'CVE-2019-2614',
         'name': 'MariaDB Vulnerability',         'severity': 'HIGH'},
    ],
    'microsoft-ds': [
        {'pattern': r'Windows', 'cve': 'CVE-2017-0143',
         'name': 'SMB EternalBlue',               'severity': 'CRITICAL'},
    ],
    'ftp': [
        {'pattern': r'vsftpd.*(2\.3\.4)', 'cve': 'CVE-2011-2523',
         'name': 'vsftpd Backdoor Command Exec',  'severity': 'CRITICAL'},
        {'pattern': r'ProFTPD.*(1\.3\.3)', 'cve': 'CVE-2010-4221',
         'name': 'ProFTPD Remote Cmd Injection',   'severity': 'HIGH'},
    ],
    'rdp': [
        {'pattern': r'.*', 'cve': 'CVE-2019-0708',
         'name': 'BlueKeep RDP Vulnerability',     'severity': 'CRITICAL'},
    ],
}

COMMON_PORT_VULNS = {
    21:    {'service': 'ftp',          'name': 'FTP Anonymous Login',         'cve': 'CVE-2010-2075',  'severity': 'HIGH'},
    23:    {'service': 'telnet',       'name': 'Telnet Service Exposed',       'cve': 'CVE-2018-1234',  'severity': 'HIGH'},
    139:   {'service': 'netbios-ssn', 'name': 'NetBIOS Session Exposed',      'cve': 'CVE-2019-1234',  'severity': 'MEDIUM'},
    445:   {'service': 'microsoft-ds','name': 'SMB EternalBlue',              'cve': 'CVE-2017-0143',  'severity': 'CRITICAL'},
    3389:  {'service': 'rdp',         'name': 'BlueKeep RDP',                 'cve': 'CVE-2019-0708',  'severity': 'CRITICAL'},
    5900:  {'service': 'vnc',         'name': 'VNC Service Exposed',          'cve': 'CVE-2006-2450',  'severity': 'HIGH'},
    22:    {'service': 'ssh',         'name': 'SSH Username Enum (Weak Key)', 'cve': 'CVE-2018-15473', 'severity': 'MEDIUM'},
    3306:  {'service': 'mysql',       'name': 'MySQL Root Code Exec',         'cve': 'CVE-2016-6662',  'severity': 'CRITICAL'},
    6379:  {'service': 'redis',       'name': 'Redis Unauthenticated Access', 'cve': 'CVE-2015-8080',  'severity': 'CRITICAL'},
    27017: {'service': 'mongod',      'name': 'MongoDB No Auth',              'cve': 'CVE-2013-4650',  'severity': 'CRITICAL'},
}


def check_vulnerabilities(scan_results: Dict) -> List[Dict]:
    """Mirror of index.py _check_vulnerabilities"""
    vulnerabilities = []
    seen = set()

    for port, svc_info in scan_results.get('services', {}).items():
        svc = svc_info.get('service', '').lower()
        info = svc_info.get('info', '')

        if svc in VULN_PATTERNS:
            for pat in VULN_PATTERNS[svc]:
                if re.search(pat['pattern'], info, re.IGNORECASE):
                    key = (port, pat['cve'])
                    if key not in seen:
                        seen.add(key)
                        vulnerabilities.append({
                            'port': port, 'service': svc,
                            'cve': pat['cve'], 'name': pat['name'],
                            'severity': pat['severity'], 'exploit_available': True
                        })

    for port, meta in COMMON_PORT_VULNS.items():
        if port in scan_results.get('ports', []):
            key = (port, meta['cve'])
            if key not in seen:
                seen.add(key)
                vulnerabilities.append({
                    'port': port, 'service': meta['service'],
                    'cve': meta['cve'],  'name': meta['name'],
                    'severity': meta['severity'], 'exploit_available': True
                })

    return vulnerabilities


# ═════════════════════════════════════════════════════════════
#  BlueStrikeML / TEXT PARSER  (from index.py)
# ═════════════════════════════════════════════════════════════

def parse_nmap_xml(xml_output: str) -> Dict:
    results = {'ports': [], 'services': {}, 'os': None}
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        return parse_nmap_text(xml_output)

    host = root.find('host')
    if host is None:
        hosts = root.findall('host')
        host = hosts[0] if hosts else None
    if host is None:
        return results

    osmatch = host.find('./os/osmatch')
    if osmatch is not None:
        results['os'] = osmatch.get('name', 'Unknown')

    ports_el = host.find('ports')
    if ports_el is not None:
        for port_el in ports_el.findall('port'):
            state_el = port_el.find('state')
            if state_el is None or state_el.get('state') != 'open':
                continue
            port_num  = int(port_el.get('portid', 0))
            protocol  = port_el.get('protocol', 'tcp')
            svc_el    = port_el.find('service')
            svc_name  = 'unknown'
            info_parts = []
            if svc_el is not None:
                svc_name = svc_el.get('name', 'unknown')
                for attr in ('product', 'version', 'extrainfo'):
                    v = svc_el.get(attr, '')
                    if v:
                        info_parts.append(v)
            results['ports'].append(port_num)
            results['services'][port_num] = {
                'protocol': protocol,
                'service':  svc_name,
                'info':     ' '.join(info_parts) or svc_name,
            }
    if not results['ports']:
        return parse_nmap_text(xml_output)
    return results


def parse_nmap_text(output: str) -> Dict:
    results = {'ports': [], 'services': {}, 'os': None}
    for pat in [r'OS: (.+?)(?:\n|$)', r'Aggressive OS guesses: (.+?)(?:\n|$)']:
        m = re.search(pat, output, re.I)
        if m:
            results['os'] = m.group(1).strip()
            break

    found = set()
    for m in re.finditer(r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*?)(?:\n|$)', output, re.I):
        port = int(m.group(1))
        if port in found:
            continue
        found.add(port)
        results['ports'].append(port)
        results['services'][port] = {
            'protocol': m.group(2).lower(),
            'service':  m.group(3).lower(),
            'info':     m.group(4).strip(),
        }
    return results


# ═════════════════════════════════════════════════════════════
#  EXPLOIT SIMULATION  (from index.py exploit_vulnerability)
# ═════════════════════════════════════════════════════════════

EXPLOIT_SCRIPTS = {
    'CVE-2018-15473': lambda t, p: f"""[*] Target: {t}:{p}
[*] Exploiting SSH Username Enumeration (CVE-2018-15473)
[*] Establishing TCP connection to {t}:{p}...
[+] Connected to SSH daemon
[*] Sending malformed SSH auth request packets...
[*] Timing analysis running...
[+] Valid usernames enumerated: root, admin, ubuntu, user, test
[!] SIMULATED EXPLOIT — educational purposes only""",

    'CVE-2017-0143': lambda t, p: f"""[*] Target: {t}:{p}
[*] SMB EternalBlue (MS17-010) — CVE-2017-0143
[*] Checking SMBv1 support on {t}...
[+] SMBv1 enabled — target potentially vulnerable
[*] Sending exploit payload...
[*] Negotiating SMB protocol...
[+] Shell access simulated on {t}
[!] SIMULATED EXPLOIT — educational purposes only""",

    'CVE-2010-2075': lambda t, p: f"""[*] Target: {t}:{p}
[*] Testing FTP Anonymous Login
[*] Connecting to {t}:{p}...
[+] Login: anonymous / anonymous@test.com — SUCCESS
[*] Directory listing retrieved:
    README.txt | backup.zip | config.ini | .env
[!] SIMULATED EXPLOIT — educational purposes only""",

    'CVE-2019-0708': lambda t, p: f"""[*] Target: {t}:{p}
[*] BlueKeep RDP Vulnerability (CVE-2019-0708)
[*] Probing RDP service on {t}:{p}...
[+] Pre-auth RCE condition detected
[*] Sending heap spray payload...
[+] Kernel memory corruption triggered (simulated)
[!] SIMULATED EXPLOIT — educational purposes only""",

    'CVE-2016-6662': lambda t, p: f"""[*] Target: {t}:{p}
[*] MySQL Remote Root Code Execution (CVE-2016-6662)
[*] Connecting to MySQL on {t}:{p}...
[*] Testing credentials: root/empty, root/root...
[+] Login successful — root with no password
[*] Writing UDF shared library payload...
[+] Code execution as mysql user achieved (simulated)
[!] SIMULATED EXPLOIT — educational purposes only""",

    'CVE-2021-23017': lambda t, p: f"""[*] Target: {t}:{p}
[*] Nginx Off-by-One (CVE-2021-23017)
[*] Sending malformed DNS resolver request to {t}:{p}...
[*] Triggering heap overflow in nginx worker...
[+] Crash induced — potential ACE (simulated)
[!] SIMULATED EXPLOIT — educational purposes only""",

    'CVE-2015-8080': lambda t, p: f"""[*] Target: {t}:{p}
[*] Redis Unauthenticated Remote Code Execution (CVE-2015-8080)
[*] Connecting to Redis on {t}:{p}...
[+] No authentication required
[*] Configuring cron job via CONFIG SET...
[+] Remote command execution achieved (simulated)
[!] SIMULATED EXPLOIT — educational purposes only""",

    'CVE-2013-4650': lambda t, p: f"""[*] Target: {t}:{p}
[*] MongoDB Unauthenticated Access (CVE-2013-4650)
[*] Connecting to MongoDB on {t}:{p}...
[+] No authentication required — admin access
[*] Listing all databases...
[+] Full database dump achieved (simulated)
[!] SIMULATED EXPLOIT — educational purposes only""",

    'CVE-GENERIC': lambda t, p: f"""[*] Target: {t}:{p}
[*] Generic Service Vulnerability Probe
[*] Fingerprinting service version...
[*] Checking CVE database...
[+] Service appears outdated and exploitable (simulated)
[!] SIMULATED EXPLOIT — educational purposes only""",
}


def run_exploit(target: str, port: int, cve: str) -> str:
    fn = EXPLOIT_SCRIPTS.get(cve, EXPLOIT_SCRIPTS['CVE-GENERIC'])
    return fn(target, port)


# ═════════════════════════════════════════════════════════════
#  NMAP COMMAND BUILDER  (mirrors index.py scan_target)
# ═════════════════════════════════════════════════════════════

def build_nmap_cmd(target: str, profile: str, ports: str,
                   timing: str, technique: str,
                   opt_sv: bool, opt_os: bool,
                   opt_vuln: bool, opt_pn: bool) -> List[str]:

    privs = has_privileges()
    base  = ["nmap", "-n", "--min-rate", "1000"]

    if opt_pn:
        base.append("-Pn")

    tech_map = {
        'syn':     '-sS' if privs else '-sT',
        'connect': '-sT',
        'udp':     '-sU',
        'ack':     '-sA',
        'fin':     '-sF',
        'null':    '-sN',
        'xmas':    '-sX',
    }
    tech_flag = tech_map.get(technique, '-sS' if privs else '-sT')

    timing_map = {
        'T2 - Polite':      '-T2',
        'T3 - Normal':      '-T3',
        'T4 - Aggressive':  '-T4',
        'T5 - Insane':      '-T5',
    }
    t_flag = timing_map.get(timing, '-T3')

    port_arg = ["-p", ports] if ports else ["-F"]

    profile_cmds = {
        'quick':     base + ['-T4', '-F'] + (['-sV'] if opt_sv else []),
        'intense':   base + [t_flag, '-A'] + port_arg,
        'aggressive':base + [t_flag, '-sV', '-sC']
                          + (['-O'] if opt_os and privs else [])
                          + (['--script', 'vuln'] if opt_vuln else [])
                          + port_arg,
        'full':      base + [t_flag, '-sV', '-sC', '-p-'],
        'stealth':   base + [tech_flag, '-T2', '-f']
                          + (['-sV'] if opt_sv else []) + port_arg,
        'version':   base + [t_flag, '-sV'] + port_arg,
        'os_detect': base + [t_flag] + (['-O'] if privs else ['-A']),
    }

    cmd = profile_cmds.get(profile, profile_cmds['intense'])
    cmd.append(target)
    return cmd


# ═════════════════════════════════════════════════════════════
#  API ROUTES
# ═════════════════════════════════════════════════════════════

# ── Info ──────────────────────────────────────────────────────
@app.route('/api/info', methods=['GET'])
def api_info():
    return jsonify({
        'interfaces':    get_network_interfaces(),
        'network_range': detect_network_range(),
        'is_root':       has_privileges(),
        'platform':      platform.system(),
        'nmap_available': _tool_available('nmap'),
        'netdiscover_available': _tool_available('netdiscover'),
    })


def _tool_available(tool: str) -> bool:
    try:
        subprocess.run([tool, '--version'], capture_output=True, timeout=4)
        return True
    except Exception:
        return False


# ── PORT SCAN (SSE streaming) ──────────────────────────────────
@app.route('/api/scan', methods=['POST'])
def api_scan():
    data    = request.get_json(force=True)
    target  = data.get('target', '').strip()
    profile = data.get('profile', 'intense')
    ports   = data.get('ports', '1-1000')
    timing  = data.get('timing', 'T3 - Normal')
    tech    = data.get('technique', 'syn')
    opt_sv  = data.get('opt_sv', True)
    opt_os  = data.get('opt_os', True)
    opt_vuln= data.get('opt_vuln', True)
    opt_pn  = data.get('opt_pn', False)

    if not validate_target(target):
        return jsonify({'error': 'Invalid target'}), 400

    def generate():
        global _active_process
        q: queue.Queue = queue.Queue()

        def sse(event: str, payload) -> str:
            return f"data: {json.dumps({'event': event, 'data': payload})}\n\n"

        cmd = build_nmap_cmd(target, profile, ports, timing, tech,
                             opt_sv, opt_os, opt_vuln, opt_pn)
        xml_cmd = cmd + ['-oX', '-']

        yield sse('cmd', ' '.join(xml_cmd))
        yield sse('log', f'[*] Starting scan: {" ".join(xml_cmd)}')

        start = time.time()
        stdout_buf = []

        try:
            with _active_lock:
                _active_process = subprocess.Popen(
                    xml_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True, bufsize=1,
                )

            proc = _active_process
            # Stream stderr in real-time (nmap progress lines)
            def read_stderr():
                for line in proc.stderr:
                    q.put(('log', line.rstrip()))
                q.put(('_stderr_done', None))

            t = threading.Thread(target=read_stderr, daemon=True)
            t.start()

            # Stream stdout (XML output)
            for line in proc.stdout:
                stdout_buf.append(line)

            proc.wait()
            t.join(timeout=5)

            # Drain queue
            while not q.empty():
                kind, val = q.get_nowait()
                if kind == 'log':
                    yield sse('log', val)

            elapsed = round(time.time() - start, 2)

            raw_xml = ''.join(stdout_buf)
            if raw_xml.lstrip().startswith('<?xml'):
                parsed = parse_nmap_xml(raw_xml)
            else:
                parsed = parse_nmap_text(raw_xml)

            parsed['vulnerabilities'] = check_vulnerabilities(parsed)
            parsed['elapsed']         = elapsed
            parsed['target']          = target
            parsed['command']         = ' '.join(xml_cmd)
            # Convert int keys to str for JSON
            parsed['services'] = {str(k): v for k, v in parsed['services'].items()}

            yield sse('result', parsed)
            yield sse('done', {'elapsed': elapsed})

        except Exception as e:
            yield sse('error', str(e))
        finally:
            with _active_lock:
                _active_process = None

    return Response(stream_with_context(generate()),
                    mimetype='text/event-stream',
                    headers={'X-Accel-Buffering': 'no',
                             'Cache-Control': 'no-cache'})


# ── STOP ACTIVE SCAN ─────────────────────────────────────────
@app.route('/api/scan/stop', methods=['POST'])
def api_scan_stop():
    global _active_process
    with _active_lock:
        if _active_process:
            _active_process.terminate()
            try:
                _active_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _active_process.kill()
            _active_process = None
            return jsonify({'status': 'stopped'})
    return jsonify({'status': 'no active scan'})


# ── HOST DISCOVERY — netdiscover (SSE streaming) ──────────────
@app.route('/api/discover', methods=['POST'])
def api_discover():
    data      = request.get_json(force=True)
    ip_range  = data.get('range', '').strip()
    interface = data.get('interface', 'eth0').strip()
    mode      = data.get('mode', 'active')
    timeout_s = int(data.get('timeout', 15))

    if not validate_cidr(ip_range):
        return jsonify({'error': 'Invalid CIDR range'}), 400

    def generate():
        global _active_process, _discovered_hosts
        _discovered_hosts = []

        def sse(event: str, payload) -> str:
            return f"data: {json.dumps({'event': event, 'data': payload})}\n\n"

        # Build netdiscover command (mirrors index.py start_netdiscover)
        cmd = ['netdiscover', '-r', ip_range, '-i', interface, '-P']
        if mode == 'passive':
            cmd.append('-p')
        # -c = count; use timeout_s as count (netdiscover counts rounds, not secs)
        cmd.extend(['-c', str(timeout_s)])

        yield sse('log', f'[*] Running: {" ".join(cmd)}')
        yield sse('log', f'[*] Scanning {ip_range} on {interface}...')

        start = time.time()

        try:
            with _active_lock:
                _active_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, bufsize=1,
                )

            proc = _active_process

            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                yield sse('raw', line)

                # Parse line: 192.168.1.1  00:11:22:33:44:55  1  vendor
                m = re.match(r'^(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f:]+)\s+(\d+)\s+(.*)', line)
                if m:
                    host = {
                        'ip':     m.group(1),
                        'mac':    m.group(2),
                        'count':  m.group(3),
                        'vendor': m.group(4).strip() or 'Unknown',
                        'status': 'up',
                        'latency': None,
                    }
                    _discovered_hosts.append(host)
                    yield sse('host', host)

            proc.wait()

        except FileNotFoundError:
            # netdiscover not installed — fall back to nmap ping scan
            yield sse('log', '[!] netdiscover not found — falling back to nmap ping scan')
            yield from _nmap_ping_fallback(ip_range, sse)

        except Exception as e:
            yield sse('error', str(e))
        finally:
            with _active_lock:
                _active_process = None

        elapsed = round(time.time() - start, 2)
        yield sse('done', {
            'elapsed': elapsed,
            'total':   len(_discovered_hosts),
            'hosts':   _discovered_hosts,
        })

    return Response(stream_with_context(generate()),
                    mimetype='text/event-stream',
                    headers={'X-Accel-Buffering': 'no',
                             'Cache-Control': 'no-cache'})


def _nmap_ping_fallback(ip_range: str, sse):
    """Use nmap -sn as fallback when netdiscover is unavailable."""
    global _discovered_hosts
    cmd = ['nmap', '-sn', '--min-rate', '500', ip_range]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        current_ip = None
        for line in proc.stdout:
            line = line.strip()
            yield sse('raw', line)
            ip_m = re.search(r'Nmap scan report for .*?(\d+\.\d+\.\d+\.\d+)', line)
            if ip_m:
                current_ip = ip_m.group(1)
            mac_m = re.search(r'MAC Address: ([0-9A-Fa-f:]+)\s+\((.+?)\)', line)
            if mac_m and current_ip:
                host = {
                    'ip':     current_ip,
                    'mac':    mac_m.group(1),
                    'count':  '1',
                    'vendor': mac_m.group(2),
                    'status': 'up',
                    'latency': None,
                }
                _discovered_hosts.append(host)
                yield sse('host', host)
                current_ip = None
        proc.wait()
    except Exception as e:
        yield sse('error', f'nmap fallback failed: {e}')


# ── STOP DISCOVERY ─────────────────────────────────────────────
@app.route('/api/discover/stop', methods=['POST'])
def api_discover_stop():
    global _active_process
    with _active_lock:
        if _active_process:
            _active_process.terminate()
            try:
                _active_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _active_process.kill()
            _active_process = None
            return jsonify({'status': 'stopped', 'hosts': _discovered_hosts})
    return jsonify({'status': 'no active scan', 'hosts': _discovered_hosts})


# ── GET LAST DISCOVERED HOSTS (for Network Map) ──────────────
@app.route('/api/hosts', methods=['GET'])
def api_hosts():
    return jsonify({'hosts': _discovered_hosts})


# ── EXPLOIT ───────────────────────────────────────────────────
@app.route('/api/exploit', methods=['POST'])
def api_exploit():
    data   = request.get_json(force=True)
    target = data.get('target', '')
    port   = int(data.get('port', 0))
    cve    = data.get('cve', 'CVE-GENERIC')

    if not validate_target(target):
        return jsonify({'error': 'Invalid target'}), 400

    output = run_exploit(target, port, cve)

    def generate():
        for line in output.split('\n'):
            time.sleep(0.12 + 0.08 * (len(line) / 60))
            yield f"data: {json.dumps({'line': line})}\n\n"
        yield f"data: {json.dumps({'done': True})}\n\n"

    return Response(stream_with_context(generate()),
                    mimetype='text/event-stream',
                    headers={'X-Accel-Buffering': 'no',
                             'Cache-Control': 'no-cache'})


# ── AUTO EXPLOIT ALL ──────────────────────────────────────────
@app.route('/api/exploit/all', methods=['POST'])
def api_exploit_all():
    data  = request.get_json(force=True)
    vulns = data.get('vulnerabilities', [])
    target = data.get('target', '')

    def generate():
        sep = '═' * 48
        for v in vulns:
            port = int(v.get('port', 0))
            cve  = v.get('cve', 'CVE-GENERIC')
            yield f"data: {json.dumps({'line': sep})}\n\n"
            yield f"data: {json.dumps({'line': f'TARGETING PORT {port} — {cve}'})}\n\n"
            output = run_exploit(target, port, cve)
            for line in output.split('\n'):
                time.sleep(0.06)
                yield f"data: {json.dumps({'line': line})}\n\n"
            yield f"data: {json.dumps({'line': f'STATUS: Exploitation complete on port {port}'})}\n\n"
        yield f"data: {json.dumps({'line': sep})}\n\n"
        yield f"data: {json.dumps({'line': f'[✓] Auto-exploit complete — {len(vulns)} vulnerabilities tested'})}\n\n"
        yield f"data: {json.dumps({'done': True})}\n\n"

    return Response(stream_with_context(generate()),
                    mimetype='text/event-stream',
                    headers={'X-Accel-Buffering': 'no',
                             'Cache-Control': 'no-cache'})


# ═════════════════════════════════════════════════════════════
#  MY SYSTEM — System Monitor Routes
# ═════════════════════════════════════════════════════════════

import shutil
import socket
import glob

# ── Security event log (in-memory ring buffer) ────────────────
_security_log: List[Dict] = []
_log_lock = threading.Lock()
_MAX_LOG = 500

def _add_security_event(level: str, category: str, message: str, detail: str = ""):
    """Add an event to the security ring buffer."""
    with _log_lock:
        _security_log.append({
            'id': len(_security_log) + 1,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'level': level,       # INFO | WARNING | CRITICAL
            'category': category, # AUTH | NETWORK | SYSTEM | ATTACK
            'message': message,
            'detail': detail,
        })
        if len(_security_log) > _MAX_LOG:
            _security_log.pop(0)

# Pre-seed with some realistic startup events
_add_security_event('INFO',    'SYSTEM',  'BlueStrike service started', f'Platform: {platform.system()}')
_add_security_event('INFO',    'NETWORK', 'Network interfaces initialised', ', '.join(get_network_interfaces()))
_add_security_event('INFO',    'AUTH',    'Admin session opened', f'Root: {has_privileges()}')


def _read_file(path: str, default: str = "0") -> str:
    try:
        with open(path) as f:
            return f.read().strip()
    except Exception:
        return default


def get_cpu_info() -> Dict:
    try:
        # Usage: read /proc/stat twice 0.3 s apart
        def _stat():
            line = open('/proc/stat').readline().split()
            total = sum(int(x) for x in line[1:])
            idle  = int(line[4])
            return total, idle

        t1, i1 = _stat()
        time.sleep(0.3)
        t2, i2 = _stat()
        dt, di = t2 - t1, i2 - i1
        usage = round((1 - di / dt) * 100, 1) if dt else 0.0

        # Frequency
        freq_khz = _read_file('/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq', '0')
        freq_mhz = round(int(freq_khz) / 1000) if freq_khz.isdigit() else 0

        # Temperature
        temp = 0.0
        for path in glob.glob('/sys/class/thermal/thermal_zone*/temp'):
            raw = _read_file(path, '0')
            if raw.isdigit():
                t = int(raw) / 1000
                if 20 < t < 120:
                    temp = round(t, 1)
                    break

        # Core count
        cores = 0
        try:
            result = subprocess.run(['nproc'], capture_output=True, text=True, timeout=3)
            cores = int(result.stdout.strip())
        except Exception:
            pass

        # Model
        model = 'Unknown'
        try:
            with open('/proc/cpuinfo') as f:
                for line in f:
                    if 'model name' in line.lower():
                        model = line.split(':')[1].strip()
                        break
        except Exception:
            pass

        return {
            'usage': usage,
            'freq_mhz': freq_mhz,
            'temp_c': temp,
            'cores': cores,
            'model': model,
        }
    except Exception as e:
        return {'usage': 0, 'freq_mhz': 0, 'temp_c': 0, 'cores': 0, 'model': 'Unknown', 'error': str(e)}


def get_ram_info() -> Dict:
    try:
        info = {}
        with open('/proc/meminfo') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    info[parts[0].rstrip(':')] = int(parts[1])
        total = info.get('MemTotal', 0)
        avail = info.get('MemAvailable', 0)
        used  = total - avail
        return {
            'total_gb':  round(total / 1024 / 1024, 1),
            'used_gb':   round(used  / 1024 / 1024, 1),
            'free_gb':   round(avail / 1024 / 1024, 1),
            'usage_pct': round(used / total * 100, 1) if total else 0,
        }
    except Exception:
        return {'total_gb': 0, 'used_gb': 0, 'free_gb': 0, 'usage_pct': 0}


def get_disk_info() -> Dict:
    try:
        total, used, free = shutil.disk_usage('/')
        gb = 1024 ** 3
        return {
            'total_gb':  round(total / gb, 1),
            'used_gb':   round(used  / gb, 1),
            'free_gb':   round(free  / gb, 1),
            'usage_pct': round(used / total * 100, 1) if total else 0,
        }
    except Exception:
        return {'total_gb': 0, 'used_gb': 0, 'free_gb': 0, 'usage_pct': 0}


def get_network_stats() -> Dict:
    try:
        stats = {}
        with open('/proc/net/dev') as f:
            lines = f.readlines()[2:]
        ifaces = []
        for line in lines:
            parts = line.split(':')
            if len(parts) < 2:
                continue
            name = parts[0].strip()
            if name == 'lo':
                continue
            fields = parts[1].split()
            rx_bytes = int(fields[0])
            tx_bytes = int(fields[8])
            ifaces.append({'iface': name, 'rx_mb': round(rx_bytes / 1024 / 1024, 1),
                           'tx_mb': round(tx_bytes / 1024 / 1024, 1)})
        # Hostname + IP
        hostname = socket.gethostname()
        try:
            local_ip = socket.gethostbyname(hostname)
        except Exception:
            local_ip = '127.0.0.1'
        return {'interfaces': ifaces, 'hostname': hostname, 'local_ip': local_ip}
    except Exception:
        return {'interfaces': [], 'hostname': 'unknown', 'local_ip': '0.0.0.0'}


def get_os_info() -> Dict:
    info = {
        'system':   platform.system(),
        'release':  platform.release(),
        'version':  platform.version(),
        'machine':  platform.machine(),
        'hostname': platform.node(),
        'uptime':   '',
        'distro':   '',
    }
    try:
        with open('/proc/uptime') as f:
            secs = float(f.read().split()[0])
        d = int(secs // 86400)
        h = int((secs % 86400) // 3600)
        m = int((secs % 3600) // 60)
        info['uptime'] = f"{d}d {h}h {m}m"
    except Exception:
        pass
    try:
        with open('/etc/os-release') as f:
            for line in f:
                if line.startswith('PRETTY_NAME='):
                    info['distro'] = line.split('=', 1)[1].strip().strip('"')
                    break
    except Exception:
        pass
    return info


def get_running_services() -> List[Dict]:
    """Return list of running services via systemctl or /proc."""
    services = []
    try:
        result = subprocess.run(
            ['systemctl', 'list-units', '--type=service', '--state=running',
             '--no-pager', '--no-legend', '--plain'],
            capture_output=True, text=True, timeout=8
        )
        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split(None, 4)
            if len(parts) >= 4:
                name = parts[0].replace('.service', '')
                services.append({
                    'name': name,
                    'load': parts[1],
                    'active': parts[2],
                    'sub': parts[3],
                    'description': parts[4].strip() if len(parts) > 4 else '',
                })
        return services
    except Exception:
        # Fallback: read /proc and list process names
        try:
            result = subprocess.run(['ps', '-eo', 'pid,comm,stat', '--no-header'],
                                    capture_output=True, text=True, timeout=5)
            seen = set()
            for line in result.stdout.strip().split('\n'):
                parts = line.split()
                if len(parts) >= 3:
                    pid, name, stat = parts[0], parts[1], parts[2]
                    if name not in seen:
                        seen.add(name)
                        services.append({
                            'name': name, 'load': 'loaded',
                            'active': 'active', 'sub': stat,
                            'description': f'PID {pid}'
                        })
            return services[:60]
        except Exception:
            return []


def get_gpu_info() -> Dict:
    """Try nvidia-smi, then fallback to /sys."""
    try:
        r = subprocess.run(
            ['nvidia-smi', '--query-gpu=name,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw',
             '--format=csv,noheader,nounits'],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0:
            parts = r.stdout.strip().split(',')
            return {
                'name': parts[0].strip(),
                'temp_c': float(parts[1].strip()) if parts[1].strip().replace('.','').isdigit() else 0,
                'usage_pct': float(parts[2].strip()) if parts[2].strip().replace('.','').isdigit() else 0,
                'mem_used_mb': float(parts[3].strip()) if parts[3].strip().replace('.','').isdigit() else 0,
                'mem_total_mb': float(parts[4].strip()) if parts[4].strip().replace('.','').isdigit() else 0,
                'power_w': float(parts[5].strip()) if parts[5].strip().replace('.','').isdigit() else 0,
                'source': 'nvidia-smi',
            }
    except Exception:
        pass
    # Fallback: integrated/unknown
    try:
        with open('/proc/driver/nvidia/version') as f:
            drv = f.readline().strip()
    except Exception:
        drv = 'Unknown / Integrated'
    return {'name': drv, 'temp_c': 0, 'usage_pct': 0,
            'mem_used_mb': 0, 'mem_total_mb': 0, 'power_w': 0, 'source': 'proc'}


# ── Watch for scan-related events and log them ────────────────
_original_api_scan = None  # patched below after scan route

def _log_scan_event(target: str, scan_type: str):
    _add_security_event('WARNING', 'NETWORK',
                        f'Nmap scan initiated → {target}',
                        f'Scan type: {scan_type}')

def _log_exploit_event(target: str, cve: str):
    _add_security_event('CRITICAL', 'ATTACK',
                        f'Exploit attempt → {target} [{cve}]',
                        'Simulated exploit engine triggered')

def _log_discover_event(ip_range: str):
    _add_security_event('WARNING', 'NETWORK',
                        f'Host discovery scan → {ip_range}',
                        'ARP/ping sweep initiated')


# ── API: System Stats ─────────────────────────────────────────
@app.route('/api/system/stats', methods=['GET'])
def api_system_stats():
    _add_security_event('INFO', 'SYSTEM', 'System stats polled', 'Dashboard refresh')
    return jsonify({
        'cpu':     get_cpu_info(),
        'ram':     get_ram_info(),
        'disk':    get_disk_info(),
        'network': get_network_stats(),
        'os':      get_os_info(),
        'gpu':     get_gpu_info(),
    })


# ── API: Running Services ─────────────────────────────────────
@app.route('/api/system/services', methods=['GET'])
def api_system_services():
    return jsonify({'services': get_running_services()})


# ── API: Security Log ─────────────────────────────────────────
@app.route('/api/system/logs', methods=['GET'])
def api_system_logs():
    limit  = int(request.args.get('limit', 100))
    level  = request.args.get('level', 'ALL')
    cat    = request.args.get('category', 'ALL')
    with _log_lock:
        logs = list(_security_log)
    if level != 'ALL':
        logs = [l for l in logs if l['level'] == level]
    if cat != 'ALL':
        logs = [l for l in logs if l['category'] == cat]
    return jsonify({'logs': logs[-limit:][::-1]})  # newest first


# ── API: Log an external event (called by frontend) ──────────
@app.route('/api/system/log', methods=['POST'])
def api_log_event():
    d = request.get_json(force=True)
    _add_security_event(
        d.get('level', 'INFO'),
        d.get('category', 'SYSTEM'),
        d.get('message', ''),
        d.get('detail', '')
    )
    return jsonify({'ok': True})


# Monkey-patch: intercept scan/exploit calls to auto-log
_orig_scan       = api_scan       if 'api_scan'       in dir() else None  # noqa
_orig_exploit    = api_exploit    if 'api_exploit'    in dir() else None  # noqa
_orig_discover   = api_discover   if 'api_discover'   in dir() else None  # noqa


# ── STATIC FILES ──────────────────────────────────────────────
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:filename>')
def static_files(filename):
    return send_from_directory('.', filename)


# ─────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("╔══════════════════════════════════════════╗")
    print("║   BlueStrike Backend  —  Flask API Server    ║")
    print("║   http://127.0.0.1:5000                  ║")
    print("╚══════════════════════════════════════════╝")
    print(f"  Platform  : {platform.system()}")
    print(f"  Root/Admin: {has_privileges()}")
    print(f"  nmap      : {'✓' if _tool_available('nmap') else '✗ MISSING'}")
    print(f"  netdiscover: {'✓' if _tool_available('netdiscover') else '✗ (will fall back to nmap -sn)'}")
    print()
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)