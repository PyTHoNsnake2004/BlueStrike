/* ═══════════════════════════════════════════════════════════════
   BlueStrike — script.js
   All frontend logic: navigation, API calls via SSE,
   port scanner, host discovery, network map, exploit modal.
   Backend: Flask app.py on http://localhost:5000
═══════════════════════════════════════════════════════════════ */

'use strict';

const API = 'http://localhost:5000/api';

/* ─────────────────────────────────────────────────────────────
   STATE
───────────────────────────────────────────────────────────── */
let scanning     = false;
let discovering  = false;
let scanResults  = [];          // [{port, state, service, info, cve, severity}]
let allVulns     = [];          // [{port, service, cve, name, severity}]
let discoveredHosts = [];       // from backend /api/hosts
let mapZoom      = 1.0;
let mapOffX      = 0, mapOffY = 0;
let mapNodes     = [];
let mapDragging  = false;
let mapDragStart = { x: 0, y: 0 };
let mapOffStart  = { x: 0, y: 0 };
let selectedNse  = new Set();

/* ─────────────────────────────────────────────────────────────
   DOM SHORTCUTS
───────────────────────────────────────────────────────────── */
const $  = id => document.getElementById(id);
const $$ = sel => document.querySelectorAll(sel);

/* ─────────────────────────────────────────────────────────────
   NAVIGATION
───────────────────────────────────────────────────────────── */
const PAGE_META = {
  'port-scanner':  ['Port Scanner',   'Nmap-based vulnerability scanning with auto-exploitation'],
  'host-discovery':['Host Discovery', 'NetDiscover ARP-based scanning — MAC & vendor identification'],
  'network-map':   ['Network Map',    'Visual topology of discovered network hosts'],
};

function showPage(pageId) {
  $$('.page').forEach(p => p.classList.remove('active'));
  $$('.menu-item').forEach(m => m.classList.remove('active'));

  const page = $(`page-${pageId}`);
  if (page) page.classList.add('active');

  const nav = document.querySelector(`[data-page="${pageId}"]`);
  if (nav) nav.classList.add('active');

  const meta = PAGE_META[pageId];
  if (meta) {
    $('pageTitle').textContent    = meta[0];
    $('pageSubtitle').textContent = meta[1];
  }

  if (pageId === 'network-map') drawNetworkMap();
}

$$('.menu-item').forEach(item => {
  item.addEventListener('click', () => showPage(item.dataset.page));
});

$('goDiscoverBtn').addEventListener('click', () => showPage('host-discovery'));
$('viewMapBtn').addEventListener('click', () => showPage('network-map'));

/* ─────────────────────────────────────────────────────────────
   BACKEND INFO — populate interfaces & network range on load
───────────────────────────────────────────────────────────── */
async function loadBackendInfo() {
  try {
    const res  = await fetch(`${API}/info`);
    const data = await res.json();

    // Populate interfaces
    const sel = $('ndInterface');
    if (data.interfaces && data.interfaces.length) {
      sel.innerHTML = data.interfaces
        .map(i => `<option>${i}</option>`)
        .join('');
    }

    // Populate network range
    if (data.network_range) {
      $('ndRange').value = data.network_range;
    }

    $('sysStatusText').textContent = data.is_root
      ? 'Root — full scan capabilities'
      : 'Non-root — limited scans';

    if (!data.nmap_available) {
      termLog('[!] nmap not found — install nmap for real scanning', 'c-orange');
    }
    if (!data.netdiscover_available) {
      ndLog('[!] netdiscover not found — will use nmap -sn fallback', 'nd-warn');
    }
  } catch {
    termLog('[!] Backend not reachable — run: python app.py', 'c-orange');
    $('sysStatusText').textContent = 'Backend offline';
    $('sysStatusDot').style.background = '#ff4455';
  }
}

/* ─────────────────────────────────────────────────────────────
   TECHNIQUE SELECTION
───────────────────────────────────────────────────────────── */
$$('input[name="scanTechnique"]').forEach(radio => {
  radio.addEventListener('change', function () {
    $$('.technique').forEach(t => t.classList.remove('active'));
    this.closest('.technique').classList.add('active');
  });
});

/* ─────────────────────────────────────────────────────────────
   TERMINAL HELPERS
───────────────────────────────────────────────────────────── */
function termLog(msg, cls = '') {
  const t   = $('terminal');
  const div = document.createElement('div');
  div.textContent = msg;
  if (cls) div.className = cls;
  t.appendChild(div);
  t.scrollTop = t.scrollHeight;
}

function termClear() {
  $('terminal').innerHTML = '';
}

/* ─────────────────────────────────────────────────────────────
   PROGRESS
───────────────────────────────────────────────────────────── */
function setProgress(pct, status) {
  $('progressFill').style.width = pct + '%';
  $('progressPct').textContent  = pct + '%';
  $('progressStatus').textContent = status;
}

/* ─────────────────────────────────────────────────────────────
   SCAN COMMAND BUILDER  (mirrors app.py build_nmap_cmd)
───────────────────────────────────────────────────────────── */
function buildScanPayload() {
  const tech = document.querySelector('input[name="scanTechnique"]:checked')?.value || 'syn';
  return {
    target:    $('targetInput').value.trim(),
    ports:     $('portInput').value.trim()  || '1-1000',
    profile:   $('profileInput').value,
    timing:    $('timingInput').value,
    technique: tech,
    opt_sv:    $('optSV').checked,
    opt_os:    $('optOS').checked,
    opt_vuln:  $('optVuln').checked,
    opt_pn:    $('optPn').checked,
  };
}

/* ─────────────────────────────────────────────────────────────
   PORT SCANNER
───────────────────────────────────────────────────────────── */
function validateTarget(t) {
  if (!t) return false;
  return /^[\d.\/]+$|^[a-zA-Z0-9.\-]+$/.test(t);
}

function startPortScan() {
  if (scanning) return;
  const payload = buildScanPayload();
  if (!validateTarget(payload.target)) {
    alert('Enter a valid IP, hostname or CIDR target.');
    return;
  }

  scanning    = true;
  scanResults = [];
  allVulns    = [];

  $('startBtn').disabled      = true;
  $('stopBtn').disabled       = false;
  $('exploitAllBtn').disabled = true;
  $('progressWrap').style.display = '';
  $('vulnSection').style.display  = 'none';
  $('statHosts').textContent    = '0';
  $('statOpen').textContent     = '0';
  $('statVulns').textContent    = '0';
  $('statDuration').textContent = '--';
  $('portResults').innerHTML    = '<tr><td colspan="7" class="tbl-empty">Scanning in progress...</td></tr>';
  $('scanBadge').className = 'badge-scanning';
  $('scanBadge').innerHTML = '<span></span> SCANNING';

  termClear();
  setProgress(5, 'Connecting to backend...');

  const es = new EventSource(`${API}/scan?` + new URLSearchParams({ _: Date.now() }));

  /* We actually POST and stream via fetch + ReadableStream */
  es.close();
  streamPost(`${API}/scan`, payload, handleScanEvent, () => finishPortScan());
}

function handleScanEvent(ev) {
  const { event, data } = ev;

  if (event === 'cmd') {
    $('termCmd').textContent = data;
    $('progressCmd').textContent = data;
    termLog('$ ' + data, 'c-green');
    setProgress(10, 'Scan started');
  }
  else if (event === 'log') {
    termLog(data, guessLogClass(data));
    // Bump progress based on nmap status lines
    if (data.includes('host discovery')) setProgress(20, 'Host discovery...');
    else if (data.includes('SYN Stealth') || data.includes('TCP')) setProgress(40, 'Port enumeration...');
    else if (data.includes('service')) setProgress(60, 'Service detection...');
    else if (data.includes('script')) setProgress(75, 'Running NSE scripts...');
    else if (data.includes('OS')) setProgress(85, 'OS fingerprinting...');
  }
  else if (event === 'result') {
    setProgress(98, 'Parsing results...');
    renderScanResult(data);
  }
  else if (event === 'error') {
    termLog('[ERROR] ' + data, 'c-red');
    setProgress(0, 'Error');
  }
}

function guessLogClass(line) {
  if (line.includes('open'))   return 'c-green';
  if (line.includes('ERROR') || line.includes('error')) return 'c-red';
  if (line.includes('warn') || line.includes('WARN'))   return 'c-orange';
  return 'c-gray';
}

function renderScanResult(data) {
  const ports    = data.ports    || [];
  const services = data.services || {};
  const vulns    = data.vulnerabilities || [];
  const elapsed  = data.elapsed || 0;

  allVulns = vulns;
  $('portResults').innerHTML = '';

  if (!ports.length) {
    $('portResults').innerHTML = '<tr><td colspan="7" class="tbl-empty">No open ports found</td></tr>';
  } else {
    ports.forEach(port => {
      const svc  = services[String(port)] || {};
      const vuln = vulns.find(v => v.port == port);
      appendPortRow(port, 'open', svc.service || '—', svc.info || '—',
                    vuln?.cve || '—', vuln?.severity || '—', data.target);
      scanResults.push({ port, state: 'open', service: svc.service, info: svc.info });
    });
  }

  // Stats
  $('statHosts').textContent    = '1';
  $('statOpen').textContent     = ports.length;
  $('statVulns').textContent    = vulns.length;
  $('statDuration').textContent = elapsed + 's';

  // Terminal summary
  termLog('');
  termLog('PORT      STATE   SERVICE', 'c-green');
  ports.forEach(p => {
    const s = services[String(p)] || {};
    termLog(`${String(p).padEnd(9)} open    ${s.service || '?'}   ${s.info || ''}`);
  });
  termLog('');
  termLog(`${ports.length} open port(s) — ${vulns.length} vulnerability/ies detected.`, 'c-green');
  termLog(`Scan duration: ${elapsed}s`);

  // Vulnerabilities panel
  if (vulns.length) {
    $('vulnSection').style.display = '';
    $('vulnCountLabel').textContent = vulns.length + ' found';
    $('vulnList').innerHTML = '';
    vulns.forEach(v => {
      const di = document.createElement('div');
      di.className = 'vuln-item';
      di.innerHTML = `
        <div class="vuln-info">
          <div class="vuln-name">${v.name}</div>
          <div class="vuln-meta">
            <span class="vuln-cve">${v.cve}</span>
            <span>Port: ${v.port} / ${v.service}</span>
            <span class="state-badge ${sevClass(v.severity)}">${v.severity}</span>
          </div>
        </div>
        <div>
          <button class="btn-attack" onclick="openExploit('${data.target}',${v.port},'${v.cve}','${v.name}')">⚡ Exploit</button>
        </div>`;
      $('vulnList').appendChild(di);
    });
    $('exploitAllBtn').disabled = false;
  }
}

function appendPortRow(port, state, service, info, cve, severity, target) {
  const tb  = $('portResults');
  if (tb.querySelector('.tbl-empty')) tb.innerHTML = '';
  const vuln = allVulns.find(v => v.port == port);
  const attackBtn = (vuln && state === 'open')
    ? `<button class="btn-attack" onclick="openExploit('${target}',${port},'${vuln.cve}','${vuln.name}')">⚡ Attack</button>`
    : '—';
  const tr = document.createElement('tr');
  tr.innerHTML = `
    <td class="td-port">${port}/tcp</td>
    <td><span class="state-badge state-${state}">${state.toUpperCase()}</span></td>
    <td><strong>${service}</strong></td>
    <td style="color:var(--muted);font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${info}">${info}</td>
    <td style="font-size:11px;">${cve !== '—' ? `<span style="color:var(--orange)">${cve}</span>` : '—'}</td>
    <td>${severity !== '—' ? `<span class="state-badge ${sevClass(severity)}">${severity}</span>` : '—'}</td>
    <td>${attackBtn}</td>`;
  tb.appendChild(tr);
}

function sevClass(s) {
  const m = { CRITICAL: 'sev-critical', HIGH: 'sev-high', MEDIUM: 'sev-medium', LOW: 'sev-low' };
  return m[s] || '';
}

function finishPortScan() {
  scanning = false;
  $('startBtn').disabled = false;
  $('stopBtn').disabled  = true;
  $('scanBadge').className = 'badge-ready';
  $('scanBadge').innerHTML = '<span></span> DONE';
  setProgress(100, 'Scan complete');
  $('sysStatusText').textContent = 'Scan complete';
}

function stopScan() {
  fetch(`${API}/scan/stop`, { method: 'POST' });
  termLog('[!] Scan stop requested', 'c-orange');
  finishPortScan();
}

function resetScan() {
  stopScan();
  scanResults = []; allVulns = [];
  termClear();
  termLog('$ nmap --interactive', 'c-green');
  termLog('BlueStrike ready.', 'c-gray');
  $('portResults').innerHTML = '<tr><td colspan="7" class="tbl-empty">Run a scan to see results</td></tr>';
  $('vulnSection').style.display = 'none';
  $('statHosts').textContent = $('statOpen').textContent = $('statVulns').textContent = '0';
  $('statDuration').textContent = '--';
  setProgress(0, 'Ready');
  $('progressWrap').style.display = 'none';
  $('scanBadge').className = 'badge-ready';
  $('scanBadge').innerHTML = '<span></span> READY';
  $('exploitAllBtn').disabled = true;
}

/* Port result search/filter */
$('portSearch').addEventListener('input', function () {
  const q = this.value.toLowerCase();
  $$('#portResults tr').forEach(tr => {
    tr.style.display = tr.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
});

/* Buttons */
$('startBtn').addEventListener('click', startPortScan);
$('stopBtn').addEventListener('click', stopScan);
$('resetBtn').addEventListener('click', resetScan);
$('btnRefresh').addEventListener('click', resetScan);
$('exploitAllBtn').addEventListener('click', openExploitAll);

/* ─────────────────────────────────────────────────────────────
   HOST DISCOVERY
───────────────────────────────────────────────────────────── */
function ndLog(msg, cls = 'c-cyan') {
  const log = $('ndLog');
  const br  = document.createElement('br');
  const sp  = document.createElement('span');
  sp.className   = cls;
  sp.textContent = msg;
  log.appendChild(br);
  log.appendChild(sp);
  log.scrollTop = log.scrollHeight;
}

function startDiscovery() {
  if (discovering) return;
  const range   = $('ndRange').value.trim();
  const iface   = $('ndInterface').value;
  const mode    = $('ndMode').value;
  const timeout = $('ndTimeout').value || '15';

  if (!range) { alert('Enter a CIDR range'); return; }

  discovering     = true;
  discoveredHosts = [];

  $('discoverBtn').disabled    = true;
  $('stopDiscoverBtn').disabled = false;
  $('viewMapBtn').disabled     = true;
  $('discoverBadge').className = 'badge-scanning';
  $('discoverBadge').innerHTML = '<span></span> SCANNING';
  $('hdDiscovered').textContent = $('hdOnline').textContent =
  $('hdOffline').textContent   = '0';
  $('hdLatency').textContent   = '-- ms';
  $('ndLog').innerHTML = '';
  renderHostGrid([]);   // clear

  const payload = { range, interface: iface, mode, timeout: parseInt(timeout) };

  ndLog(`$ netdiscover -r ${range} -i ${iface}${mode === 'passive' ? ' -p' : ''}`, 'c-cyan');

  streamPost(`${API}/discover`, payload, handleDiscoverEvent, finishDiscovery);
}

function handleDiscoverEvent(ev) {
  const { event, data } = ev;
  if (event === 'log') {
    ndLog(data, data.startsWith('[!]') ? 'nd-warn' : 'c-cyan');
  }
  else if (event === 'raw') {
    ndLog(data, 'c-gray');
  }
  else if (event === 'host') {
    discoveredHosts.push(data);
    ndLog(`[FOUND] ${data.ip.padEnd(16)} ${data.mac}  ${data.vendor}`, 'nd-found');
    updateDiscoveryStats();
    renderHostGrid(discoveredHosts);
  }
  else if (event === 'error') {
    ndLog('[ERROR] ' + data, 'nd-warn');
  }
  else if (event === 'done') {
    if (data.hosts && data.hosts.length) {
      discoveredHosts = data.hosts;
      renderHostGrid(discoveredHosts);
      updateDiscoveryStats();
    }
  }
}

function updateDiscoveryStats() {
  const online  = discoveredHosts.filter(h => h.status === 'up');
  const offline = discoveredHosts.filter(h => h.status !== 'up');
  $('hdDiscovered').textContent = discoveredHosts.length;
  $('hdOnline').textContent     = online.length;
  $('hdOffline').textContent    = offline.length;
  $('hdLatency').textContent    = '—';
}

function renderHostGrid(hosts) {
  const grid = $('hostGrid');

  // Apply search/filter
  const q      = $('hostSearch').value.toLowerCase();
  const filter = $('hostFilter').value;

  const filtered = hosts.filter(h => {
    const matchQ = !q || [h.ip, h.mac, h.vendor].some(v => (v || '').toLowerCase().includes(q));
    const matchF = filter === 'all' || (filter === 'up' && h.status === 'up') || (filter === 'down' && h.status !== 'up');
    return matchQ && matchF;
  });

  if (!filtered.length) {
    grid.className = 'empty-state';
    grid.innerHTML = `
      <div class="host-empty">
        <div class="host-empty-icon">◎</div>
        <strong>${hosts.length ? 'No matching hosts' : 'No hosts discovered yet'}</strong>
        <small>${hosts.length ? 'Try another search or filter' : 'Start host discovery to scan the local network'}</small>
      </div>`;
    return;
  }

  grid.className = '';
  grid.style.display = 'grid';
  grid.style.gridTemplateColumns = 'repeat(3,1fr)';
  grid.style.gap = '12px';
  grid.innerHTML = '';

  filtered.forEach(h => {
    const online  = h.status === 'up';
    const card    = document.createElement('div');
    card.className = `host-card ${online ? 'online' : 'offline'}`;
    card.innerHTML = `
      <div class="host-card-top">
        <span class="host-icon">${online ? '◉' : '○'}</span>
        <span class="${online ? 'host-badge-online' : 'host-badge-offline'}">${online ? '● ONLINE' : '○ OFFLINE'}</span>
      </div>
      <div class="host-ip">${h.ip}</div>
      <div class="host-name">${h.mac || '—'}</div>
      <div class="host-detail-row">
        <div class="host-detail"><span>VENDOR</span><strong>${h.vendor || '—'}</strong></div>
        <div class="host-detail"><span>COUNT</span><strong>${h.count || '—'}</strong></div>
      </div>
      <button class="btn-host-scan" onclick="scanHostFromDiscovery('${h.ip}')">⌕ Port Scan this Host</button>`;
    grid.appendChild(card);
  });
}

function finishDiscovery() {
  discovering = false;
  $('discoverBtn').disabled     = false;
  $('stopDiscoverBtn').disabled = true;
  $('discoverBadge').className  = 'badge-ready';
  $('discoverBadge').innerHTML  = '<span></span> DONE';
  if (discoveredHosts.length) {
    $('viewMapBtn').disabled = false;
    ndLog(`[✓] Discovery complete — ${discoveredHosts.length} host(s) found`, 'nd-found');
  } else {
    ndLog('[!] No hosts found', 'nd-warn');
  }
}

function stopDiscovery() {
  fetch(`${API}/discover/stop`, { method: 'POST' })
    .then(r => r.json())
    .then(d => {
      if (d.hosts) {
        discoveredHosts = d.hosts;
        renderHostGrid(discoveredHosts);
        updateDiscoveryStats();
      }
    });
  ndLog('[!] Discovery stopped by user', 'nd-warn');
  finishDiscovery();
}

function clearDiscovery() {
  stopDiscovery();
  discoveredHosts = [];
  renderHostGrid([]);
  $('hdDiscovered').textContent = $('hdOnline').textContent = $('hdOffline').textContent = '0';
  $('hdLatency').textContent    = '-- ms';
  $('ndLog').innerHTML = '<span class="c-cyan">$ netdiscover — cleared.</span>';
  $('viewMapBtn').disabled = true;
}

function scanHostFromDiscovery(ip) {
  $('targetInput').value = ip;
  showPage('port-scanner');
  setTimeout(startPortScan, 200);
}

/* Host search / filter */
$('hostSearch').addEventListener('input', () => renderHostGrid(discoveredHosts));
$('hostFilter').addEventListener('change', () => renderHostGrid(discoveredHosts));

$('discoverBtn').addEventListener('click', startDiscovery);
$('stopDiscoverBtn').addEventListener('click', stopDiscovery);
$('clearDiscoverBtn').addEventListener('click', clearDiscovery);

/* ─────────────────────────────────────────────────────────────
   NSE SCRIPT ENGINE
───────────────────────────────────────────────────────────── */
const NSE_SCRIPTS = [
  { name:'http-title',              category:'discovery', severity:'info', description:'Obtains the title of HTTP services.' },
  { name:'http-headers',            category:'discovery', severity:'safe', description:'Displays HTTP response headers.' },
  { name:'http-methods',            category:'discovery', severity:'safe', description:'Enumerates supported HTTP methods.' },
  { name:'http-server-header',      category:'version',   severity:'info', description:'Retrieves the HTTP server header.' },
  { name:'ssh-hostkey',             category:'discovery', severity:'safe', description:'Displays SSH host key information.' },
  { name:'ssh-auth-methods',        category:'auth',      severity:'auth', description:'Reports supported SSH authentication methods.' },
  { name:'ssl-cert',                category:'version',   severity:'info', description:'Retrieves SSL certificate information.' },
  { name:'ssl-enum-ciphers',        category:'version',   severity:'info', description:'Enumerates supported TLS cipher suites.' },
  { name:'dns-service-discovery',   category:'discovery', severity:'safe', description:'Collects DNS service information.' },
  { name:'smb-os-discovery',        category:'discovery', severity:'safe', description:'Attempts to identify SMB host info.' },
  { name:'ftp-anon',                category:'auth',      severity:'auth', description:'Checks for anonymous FTP access.' },
  { name:'http-vuln-cve2021-41773', category:'vuln',      severity:'vuln', description:'Checks for Apache HTTP Server path traversal.' },
  { name:'http-security-headers',   category:'safe',      severity:'safe', description:'Checks common HTTP security headers.' },
  { name:'banner',                  category:'version',   severity:'info', description:'Attempts to retrieve service banners.' },
  { name:'vuln',                    category:'vuln',      severity:'vuln', description:'Runs all vulnerability detection scripts.' },
  { name:'smb-vuln-ms17-010',       category:'vuln',      severity:'vuln', description:'Detects EternalBlue (MS17-010) vulnerability.' },
];

function renderNseScripts() {
  const q    = $('nseSearch').value.toLowerCase();
  const cat  = $('nseCategory').value;
  const list = $('nseList');
  list.innerHTML = '';

  const filtered = NSE_SCRIPTS.filter(s =>
    (cat === 'all' || s.category === cat) &&
    (s.name.includes(q) || s.description.toLowerCase().includes(q))
  );

  if (!filtered.length) {
    list.innerHTML = '<div style="padding:20px;text-align:center;color:var(--muted);font-size:12px;">No scripts found</div>';
    return;
  }

  filtered.forEach(s => {
    const lbl = document.createElement('label');
    lbl.className = 'nse-script' + (selectedNse.has(s.name) ? ' selected' : '');
    lbl.innerHTML = `
      <input type="checkbox" value="${s.name}" ${selectedNse.has(s.name) ? 'checked' : ''}>
      <span class="nse-check"></span>
      <div>
        <div class="nse-name"><strong>${s.name}</strong>
          <span class="nse-badge badge-${s.severity}">${s.severity.toUpperCase()}</span>
        </div>
        <div class="nse-desc">${s.description}</div>
      </div>`;
    lbl.querySelector('input').addEventListener('change', function () {
      if (this.checked) { selectedNse.add(this.value); lbl.classList.add('selected'); }
      else              { selectedNse.delete(this.value); lbl.classList.remove('selected'); }
      $('nseCount').textContent = selectedNse.size;
    });
    list.appendChild(lbl);
  });
  $('nseCount').textContent = selectedNse.size;
}

$('nseSearch').addEventListener('input', renderNseScripts);
$('nseCategory').addEventListener('change', renderNseScripts);
$('selectAllNse').addEventListener('click', () => {
  NSE_SCRIPTS.forEach(s => selectedNse.add(s.name));
  renderNseScripts();
});
$('clearNse').addEventListener('click', () => {
  selectedNse.clear();
  renderNseScripts();
});

/* ─────────────────────────────────────────────────────────────
   EXPLOIT MODAL
───────────────────────────────────────────────────────────── */
function openExploit(target, port, cve, name) {
  $('exploitTitle').textContent = name || 'Exploit';
  $('exploitMeta').textContent  = `Target: ${target}:${port}  |  CVE: ${cve}`;
  $('exploitLog').innerHTML     = '';
  $('exploitModal').classList.add('open');

  streamExploit(`${API}/exploit`, { target, port, cve });
}

function openExploitAll() {
  if (!allVulns.length) return;
  const target = $('targetInput').value.trim();
  $('exploitTitle').textContent = `Auto-Exploit All (${allVulns.length} vulns)`;
  $('exploitMeta').textContent  = `Target: ${target}`;
  $('exploitLog').innerHTML     = '';
  $('exploitModal').classList.add('open');

  streamExploit(`${API}/exploit/all`, { target, vulnerabilities: allVulns });
}

function streamExploit(url, payload) {
  const log = $('exploitLog');
  streamPost(url, payload, ev => {
    if (ev.line !== undefined) {
      const d = document.createElement('div');
      d.textContent = ev.line;
      d.className =
        ev.line.startsWith('[+]') || ev.line.startsWith('[✓]') ? 'log-ok'   :
        ev.line.startsWith('[*]')                              ? 'log-info' :
        ev.line.startsWith('[!]')                              ? 'log-warn' :
        ev.line.startsWith('═')                               ? 'log-sep'  : '';
      log.appendChild(d);
      log.scrollTop = log.scrollHeight;
    }
  }, () => {});
}

function closeExploit() {
  $('exploitModal').classList.remove('open');
}
$('closeExploit').addEventListener('click', closeExploit);
$('closeExploitBtn').addEventListener('click', closeExploit);
$('exploitModal').addEventListener('click', e => {
  if (e.target === $('exploitModal')) closeExploit();
});

/* ─────────────────────────────────────────────────────────────
   NETWORK MAP
───────────────────────────────────────────────────────────── */
function drawNetworkMap() {
  const wrap   = $('mapWrap');
  const canvas = $('topoCanvas');
  const empty  = $('mapEmpty');

  if (!discoveredHosts.length) {
    canvas.style.display = 'none';
    empty.style.display  = 'flex';
    return;
  }

  empty.style.display  = 'none';
  canvas.style.display = 'block';
  canvas.width  = wrap.clientWidth  || 900;
  canvas.height = wrap.clientHeight || 520;

  buildMapNodes(canvas.width, canvas.height);
  renderCanvas(canvas);
}

function buildMapNodes(W, H) {
  mapNodes = [];

  // Internet at top
  mapNodes.push({
    id: 'internet', label: 'INTERNET', sub: 'External Network',
    x: W / 2, y: 80, type: 'internet', online: true,
  });

  // Gateway (first host)
  const gw = discoveredHosts[0];
  mapNodes.push({
    id: gw.ip, label: 'GATEWAY', sub: gw.ip, extra: 'ONLINE',
    x: W / 2, y: 220, type: 'gateway', online: true, host: gw,
  });

  // Rest spread in arc
  const others = discoveredHosts.slice(1);
  const cx = W / 2;
  const cy = 390;
  const radius = Math.min(W / 2.6, 260);

  others.forEach((h, i) => {
    const angle = (Math.PI / (others.length + 1)) * (i + 1);
    const x = cx + radius * Math.cos(Math.PI - angle);
    const y = cy + Math.abs(Math.sin(angle)) * 60;
    const typeMap = ['desktop', 'server', 'printer', 'router', 'desktop', 'server'];
    mapNodes.push({
      id: h.ip, label: (h.vendor || 'HOST').split(' ')[0].toUpperCase(),
      sub: h.ip, extra: h.status === 'up' ? 'ONLINE' : 'OFFLINE',
      x, y, type: typeMap[i % typeMap.length],
      online: h.status === 'up', host: h,
    });
  });
}

function renderCanvas(canvas) {
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;

  ctx.clearRect(0, 0, W, H);
  ctx.save();
  ctx.translate(mapOffX, mapOffY);
  ctx.scale(mapZoom, mapZoom);

  // Draw links
  const intNode = mapNodes.find(n => n.type === 'internet');
  const gwNode  = mapNodes.find(n => n.type === 'gateway');

  if (intNode && gwNode) drawLink(ctx, intNode, gwNode, true);
  mapNodes.forEach(n => {
    if (n.type !== 'internet' && n.type !== 'gateway' && gwNode) {
      drawLink(ctx, gwNode, n, false);
    }
  });

  mapNodes.forEach(n => drawNode(ctx, n));
  ctx.restore();
}

function drawLink(ctx, a, b, solid) {
  ctx.beginPath();
  ctx.setLineDash(solid ? [] : [8, 6]);
  ctx.strokeStyle = solid ? 'rgba(0,229,255,0.3)' : 'rgba(0,229,255,0.15)';
  ctx.lineWidth   = 1.5;
  ctx.moveTo(a.x, a.y);
  ctx.lineTo(b.x, b.y);
  ctx.stroke();
  ctx.setLineDash([]);
}

function drawNode(ctx, n) {
  const cx = n.x, cy = n.y;
  const big  = n.type === 'internet' || n.type === 'gateway';
  const sz   = big ? 58 : 48;
  const bx = cx - sz / 2 - 8, by = cy - sz / 2 - 8;
  const bw = sz + 16, bh = sz + 16;

  ctx.fillStyle   = big ? '#0c1825' : '#0a1520';
  ctx.strokeStyle = big
    ? 'rgba(0,229,255,0.45)'
    : n.online
      ? 'rgba(0,230,118,0.25)'
      : 'rgba(68,85,102,0.35)';
  ctx.lineWidth = 1.5;
  roundRect(ctx, bx, by, bw, bh, 10);
  ctx.fill();
  ctx.stroke();

  // Icon
  const icons = { internet: '◎', gateway: '●', desktop: '▪', server: '▪', printer: '▪', router: '◇' };
  ctx.fillStyle    = '#00e5ff';
  ctx.font         = `${big ? 18 : 14}px Arial`;
  ctx.textAlign    = 'center';
  ctx.textBaseline = 'middle';
  ctx.shadowColor  = '#00e5ff';
  ctx.shadowBlur   = 10;
  ctx.fillText(icons[n.type] || '▪', cx, cy - 4);
  ctx.shadowBlur   = 0;

  // Labels
  ctx.fillStyle    = '#e5edf6';
  ctx.font         = `bold ${big ? 12 : 11}px Arial`;
  ctx.textBaseline = 'top';
  ctx.fillText(n.label, cx, cy + sz / 2 - 8);

  ctx.fillStyle = big ? 'rgba(0,229,255,0.85)' : '#6f7e91';
  ctx.font      = '10px monospace';
  ctx.fillText(n.sub, cx, cy + sz / 2 + 4);

  if (n.extra) {
    ctx.fillStyle = n.extra === 'ONLINE' ? '#00e676' : '#445566';
    ctx.font      = 'bold 9px Arial';
    ctx.fillText(n.extra, cx, cy + sz / 2 + 16);
  }

  ctx.textAlign    = 'left';
  ctx.textBaseline = 'alphabetic';
}

function roundRect(ctx, x, y, w, h, r) {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.lineTo(x + w - r, y); ctx.arcTo(x + w, y,     x + w, y + r,     r);
  ctx.lineTo(x + w, y + h - r); ctx.arcTo(x + w, y + h, x + w - r, y + h, r);
  ctx.lineTo(x + r, y + h); ctx.arcTo(x,     y + h, x,     y + h - r, r);
  ctx.lineTo(x,     y + r); ctx.arcTo(x,     y,     x + r, y,         r);
  ctx.closePath();
}

/* Zoom */
function zoomMap(delta) {
  mapZoom = Math.max(0.4, Math.min(2.5, mapZoom + delta));
  $('zoomLabel').textContent = Math.round(mapZoom * 100) + '%';
  const c = $('topoCanvas');
  if (c.style.display !== 'none') renderCanvas(c);
}
function resetMapView() {
  mapZoom = 1; mapOffX = 0; mapOffY = 0;
  $('zoomLabel').textContent = '100%';
  const c = $('topoCanvas');
  if (c.style.display !== 'none') renderCanvas(c);
}
$('zoomIn').addEventListener('click', () => zoomMap(0.15));
$('zoomOut').addEventListener('click', () => zoomMap(-0.15));
$('zoomReset').addEventListener('click', resetMapView);

/* Drag-to-pan */
const canvas = $('topoCanvas');
canvas.addEventListener('mousedown', e => {
  mapDragging  = true;
  mapDragStart = { x: e.clientX, y: e.clientY };
  mapOffStart  = { x: mapOffX, y: mapOffY };
});
window.addEventListener('mousemove', e => {
  if (!mapDragging) return;
  mapOffX = mapOffStart.x + (e.clientX - mapDragStart.x);
  mapOffY = mapOffStart.y + (e.clientY - mapDragStart.y);
  if (canvas.style.display !== 'none') renderCanvas(canvas);
});
window.addEventListener('mouseup', () => (mapDragging = false));

/* Tooltip on hover */
canvas.addEventListener('mousemove', e => {
  if (mapDragging) return;
  const rect = canvas.getBoundingClientRect();
  const mx = (e.clientX - rect.left  - mapOffX) / mapZoom;
  const my = (e.clientY - rect.top   - mapOffY) / mapZoom;
  const tip = $('nodeTooltip');
  let hit = null;
  mapNodes.forEach(n => {
    if (Math.abs(mx - n.x) < 40 && Math.abs(my - n.y) < 40) hit = n;
  });
  if (hit) {
    $('ttIp').textContent  = hit.sub;
    $('ttInfo').innerHTML  = hit.host
      ? `Vendor: ${hit.host.vendor || '—'}<br>MAC: ${hit.host.mac || '—'}<br>Status: ${hit.host.status || '—'}`
      : hit.label;
    tip.style.display = 'block';
    tip.style.left    = (e.clientX - rect.left + 14) + 'px';
    tip.style.top     = (e.clientY - rect.top  - 10) + 'px';
  } else {
    tip.style.display = 'none';
  }
});

/* Resize observer */
new ResizeObserver(() => {
  const c = $('topoCanvas');
  const w = $('mapWrap');
  if (c.style.display !== 'none') {
    c.width  = w.clientWidth  || 900;
    c.height = w.clientHeight || 520;
    renderCanvas(c);
  }
}).observe($('mapWrap'));

/* ─────────────────────────────────────────────────────────────
   SSE STREAMING via fetch (POST + ReadableStream)
   Handles text/event-stream from Flask.
───────────────────────────────────────────────────────────── */
async function streamPost(url, payload, onEvent, onDone) {
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!res.body) {
      onDone();
      return;
    }

    const reader  = res.body.getReader();
    const decoder = new TextDecoder();
    let   buf     = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buf += decoder.decode(value, { stream: true });
      const lines = buf.split('\n');
      buf = lines.pop(); // keep incomplete line

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        try {
          const parsed = JSON.parse(line.slice(6));
          // Exploit streams send {line, done} directly; scan sends {event, data}
          if (parsed.event !== undefined) {
            onEvent(parsed);
            if (parsed.event === 'done') { onDone(); return; }
          } else {
            onEvent(parsed);
            if (parsed.done) { onDone(); return; }
          }
        } catch { /* skip malformed */ }
      }
    }
    onDone();
  } catch (err) {
    termLog('[ERROR] ' + err.message, 'c-red');
    onDone();
  }
}

/* ─────────────────────────────────────────────────────────────
   INIT
───────────────────────────────────────────────────────────── */
renderNseScripts();
loadBackendInfo();
console.log('BlueStrike frontend initialized.');
/* ═════════════════════════════════════════════════════════════
   MY SYSTEM — Frontend Logic
═════════════════════════════════════════════════════════════ */

// ── Extend PAGE_META ─────────────────────────────────────────
PAGE_META['my-system'] = ['My System', 'Live system monitor — OS, CPU, RAM, GPU, Network & Security Logs'];

// ── State ────────────────────────────────────────────────────
let _sysRefreshTimer = null;
let _logRefreshTimer = null;
let _currentSysSubtab = 'os';
let _sysDisplayedLogs = [];   // currently shown logs (for clear-view)

// ── Extend showPage to handle my-system ──────────────────────
const _origShowPage = showPage;
showPage = function(pageId, subtab) {
  _origShowPage(pageId);
  if (pageId === 'my-system') {
    const tab = subtab || _currentSysSubtab || 'os';
    switchSysTab(tab);
    fetchSystemStats();
    startSysAutoRefresh();
    startLogAutoRefresh();
  } else {
    stopSysAutoRefresh();
    stopLogAutoRefresh();
  }
};

// ── Navigation patch: handle subtab data attrs ───────────────
document.querySelectorAll('[data-page]').forEach(el => {
  el.addEventListener('click', () => {
    const page   = el.dataset.page;
    const subtab = el.dataset.subtab;
    showPage(page, subtab);
  });
});

// ── Sub-tab switching ─────────────────────────────────────────
function switchSysTab(tab) {
  _currentSysSubtab = tab;
  document.querySelectorAll('.sys-tab').forEach(b => {
    b.classList.toggle('active', b.dataset.subtab === tab);
  });
  document.querySelectorAll('.systab').forEach(d => {
    d.classList.toggle('active', d.id === `systab-${tab}`);
  });
  if (tab === 'services') fetchServices();
  if (tab === 'logs')     fetchLogs();
}

document.querySelectorAll('.sys-tab').forEach(btn => {
  btn.addEventListener('click', () => switchSysTab(btn.dataset.subtab));
});

// ── Refresh button ────────────────────────────────────────────
$('sysRefreshBtn').addEventListener('click', () => {
  fetchSystemStats();
  if (_currentSysSubtab === 'services') fetchServices();
  if (_currentSysSubtab === 'logs')     fetchLogs();
});

// ── Auto-refresh timers ───────────────────────────────────────
function startSysAutoRefresh() {
  stopSysAutoRefresh();
  _sysRefreshTimer = setInterval(fetchSystemStats, 5000);
}
function stopSysAutoRefresh() {
  if (_sysRefreshTimer) { clearInterval(_sysRefreshTimer); _sysRefreshTimer = null; }
}
function startLogAutoRefresh() {
  stopLogAutoRefresh();
  _logRefreshTimer = setInterval(() => {
    if (_currentSysSubtab === 'logs') fetchLogs();
  }, 3000);
}
function stopLogAutoRefresh() {
  if (_logRefreshTimer) { clearInterval(_logRefreshTimer); _logRefreshTimer = null; }
}

// ── Fetch system stats ────────────────────────────────────────
async function fetchSystemStats() {
  try {
    const res  = await fetch(`${API}/system/stats`);
    const data = await res.json();
    renderSystemStats(data);
    $('sysLastUpdate').textContent = 'Updated ' + new Date().toLocaleTimeString();
  } catch (e) {
    $('sysLastUpdate').textContent = '⚠ Backend offline';
  }
}

function renderSystemStats(d) {
  const cpu  = d.cpu  || {};
  const ram  = d.ram  || {};
  const disk = d.disk || {};
  const net  = d.network || {};
  const os   = d.os  || {};
  const gpu  = d.gpu  || {};

  // OS Banner
  $('sysOsName').textContent  = os.distro || os.system || 'Unknown OS';
  $('sysOsMeta').textContent  = `${os.machine || ''} | ${os.release || ''} | ${os.hostname || ''}`;
  $('sysUptime').textContent  = os.uptime || '--';

  // CPU
  $('cpuFreq').textContent    = cpu.freq_mhz ? `${cpu.freq_mhz} MHz` : '-- MHz';
  $('cpuUsage').textContent   = `${cpu.usage ?? '--'} %`;
  $('cpuTemp').textContent    = cpu.temp_c  ? `${cpu.temp_c} °C` : '-- °C';
  $('cpuCores').textContent   = cpu.cores || '--';
  $('cpuModel').textContent   = cpu.model  || '--';
  setBar('cpuFreqBar',  (cpu.freq_mhz || 0) / 5000 * 100);
  setBar('cpuUsageBar', cpu.usage || 0);

  // GPU
  $('gpuName').textContent    = gpu.name   || 'Unknown / Integrated';
  $('gpuUsage').textContent   = `${gpu.usage_pct ?? '--'} %`;
  $('gpuTemp').textContent    = gpu.temp_c ? `${gpu.temp_c} °C` : '-- °C';
  $('gpuMem').textContent     = gpu.mem_used_mb  ? `${gpu.mem_used_mb} MB / ${gpu.mem_total_mb} MB` : '-- MB';
  $('gpuPower').textContent   = gpu.power_w ? `${gpu.power_w} W` : '-- W';
  setBar('gpuUsageBar', gpu.usage_pct || 0);

  // Network
  $('netHostname').textContent = net.hostname || '--';
  $('netIp').textContent       = net.local_ip  || '--';
  const ifaceList = $('netIfaceList');
  ifaceList.innerHTML = (net.interfaces || []).map(i =>
    `<div class="sys-iface-row">
       <span class="sys-iface-name">${i.iface}</span>
       <span class="sys-iface-stat">↓ ${i.rx_mb} MB &nbsp; ↑ ${i.tx_mb} MB</span>
     </div>`
  ).join('') || '<div class="sys-iface-stat">No interfaces detected</div>';

  // RAM
  $('ramUsed').textContent = `${ram.used_gb ?? '--'} / ${ram.total_gb ?? '--'} GB`;
  $('ramPct').textContent  = `${ram.usage_pct ?? '--'} %`;
  $('ramFree').textContent = `${ram.free_gb ?? '--'} GB`;
  setBar('ramBar', ram.usage_pct || 0);

  // Disk
  $('diskUsed').textContent = `${disk.used_gb ?? '--'} / ${disk.total_gb ?? '--'} GB`;
  $('diskPct').textContent  = `${disk.usage_pct ?? '--'} %`;
  setBar('diskBar', disk.usage_pct || 0);
}

function setBar(id, pct) {
  const el = $(id);
  if (el) el.style.width = Math.min(100, Math.max(0, pct)) + '%';
}

// ── Fetch running services ────────────────────────────────────
async function fetchServices() {
  try {
    const res  = await fetch(`${API}/system/services`);
    const data = await res.json();
    renderServices(data.services || []);
  } catch (e) {
    $('svcTableBody').innerHTML = `<tr><td colspan="4" class="tbl-empty" style="color:var(--red)">⚠ Backend offline</td></tr>`;
  }
}

function renderServices(svcs) {
  $('svcCount').textContent = `${svcs.length} services`;
  const query = ($('svcSearch').value || '').toLowerCase();
  const filtered = svcs.filter(s =>
    s.name.toLowerCase().includes(query) ||
    (s.description || '').toLowerCase().includes(query)
  );
  if (!filtered.length) {
    $('svcTableBody').innerHTML = `<tr><td colspan="4" class="tbl-empty">No services found</td></tr>`;
    return;
  }
  $('svcTableBody').innerHTML = filtered.map(s => {
    const activeClass = s.active === 'active' ? 'svc-active' : 'svc-inactive';
    return `<tr>
      <td style="color:var(--cyan);font-weight:600">${escHtml(s.name)}</td>
      <td class="${activeClass}">${escHtml(s.active)}</td>
      <td style="color:var(--muted)">${escHtml(s.sub)}</td>
      <td style="color:var(--muted);font-size:11px">${escHtml(s.description)}</td>
    </tr>`;
  }).join('');
}

$('svcSearch').addEventListener('input', () => {
  // re-render with filter — refetch to get latest list
  fetchServices();
});

// ── Fetch security logs ───────────────────────────────────────
async function fetchLogs() {
  const level = $('logLevelFilter').value;
  const cat   = $('logCatFilter').value;
  try {
    const res  = await fetch(`${API}/system/logs?limit=200&level=${level}&category=${cat}`);
    const data = await res.json();
    renderLogs(data.logs || []);
  } catch (e) {
    $('logStream').innerHTML = `<div style="color:var(--red)">⚠ Backend offline</div>`;
  }
}

function renderLogs(logs) {
  if (!logs.length) {
    $('logStream').innerHTML = `<div class="sys-log-empty">No events match the current filter.</div>`;
    return;
  }
  $('logStream').innerHTML = logs.map(l => `
    <div class="sys-log-row">
      <span class="sys-log-ts">${escHtml(l.timestamp)}</span>
      <span class="sys-log-level level-${l.level}">${l.level}</span>
      <span class="sys-log-cat">[${l.category}]</span>
      <span class="sys-log-msg">${escHtml(l.message)}
        ${l.detail ? `<span class="sys-log-detail"> — ${escHtml(l.detail)}</span>` : ''}
      </span>
    </div>`).join('');
}

function escHtml(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// Filter change listeners
$('logLevelFilter').addEventListener('change', fetchLogs);
$('logCatFilter').addEventListener('change',   fetchLogs);
$('clearLogsBtn').addEventListener('click', () => {
  $('logStream').innerHTML = `<div class="sys-log-empty">Log view cleared. New events will appear on next refresh.</div>`;
});

// ── Intercept scan/exploit starts → log to backend ───────────
// Wrap the scan button to also log security events
const _origScanBtn = $('scanBtn');
if (_origScanBtn) {
  _origScanBtn.addEventListener('click', () => {
    const target = $('targetInput') ? $('targetInput').value : '';
    fetch(`${API}/system/log`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        level: 'WARNING', category: 'NETWORK',
        message: `Nmap scan started → ${target}`,
        detail:  `Profile: ${$('profileInput') ? $('profileInput').value : 'unknown'}`
      })
    }).catch(() => {});
  }, { capture: true });
}

// Log exploit modal opens
document.addEventListener('click', e => {
  const btn = e.target.closest('[data-cve]');
  if (btn) {
    const cve    = btn.dataset.cve    || 'unknown';
    const target = btn.dataset.target || 'unknown';
    fetch(`${API}/system/log`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        level: 'CRITICAL', category: 'ATTACK',
        message: `Exploit launched → ${target} [${cve}]`,
        detail: 'Simulated exploit engine'
      })
    }).catch(() => {});
  }
}, { capture: true });

console.log('MY SYSTEM module loaded.');