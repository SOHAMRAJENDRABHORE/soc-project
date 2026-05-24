/* =====================================================
   AGENTIC SOC — DASHBOARD APPLICATION
   ===================================================== */

// ── Config & State ──────────────────────────────────
const CFG = {
  apiBase:     localStorage.getItem('soc_api') || 'http://localhost:8080',
  authToken:   localStorage.getItem('soc_token') || '',
  demoMode:    localStorage.getItem('soc_demo') !== 'false',
  autoRefresh: localStorage.getItem('soc_refresh') !== 'false',
};

const STATE = {
  tab: 'overview',
  alerts: [],
  agents: [],
  runs: [],
  stats: {},
  iocs: [],
  mitreCounts: {},        // { 'T1059.001': 3, ... } built from real pipeline verdicts
  killChainCounts: {},    // { 'C2': 5, 'Exploitation': 3, ... } from verdict.kill_chain_phase
  threatIntelCleared: false,  // true after user explicitly clears — suppresses auto-reload
  chartData: null,        // real data from /dashboard/chart-data
  selectedAlerts: new Set(),
  isConnected: false,
  botRunning: false,
  currentDetailAlert: null,
  charts: {},
  refreshTimer: null,
};

// ── Demo Data ────────────────────────────────────────
const DEMO = {
  stats: {
    pipeline_runs: {
      total_runs: 247, last_24h: 18, avg_duration_seconds: 42.3,
      by_status: { done: 218, failed: 12, running: 2, requires_approval: 15 },
      by_severity: { critical: 34, high: 78, medium: 91, low: 44 },
      vip_count: 8,
    },
    agents: { total: 14 },
    tenants: { total: 4, enabled: 3 },
    pending_alerts: { new: 23 },
    enrichers: { virustotal: true, abuseipdb: true, otx: true, urlhaus: true, threatfox: true, malwarebazaar: true, greynoise: false, shodan: false },
    vip_list: ['ceo', 'cfo', 'alice@acme.com'],
  },
  alerts: [
    { pending_id:'pa-001', tenant_id:'t1', tenant_name:'ACME Corp', status:'new', ingested_at: ago(5),
      alert:{ alert_id:'ACME-2024-0091', severity:'critical', title:'Ransomware Activity — Mass File Encryption', description:'vssadmin delete shadows /for=C: detected. bcdedit /set recoveryenabled No. 847 files modified in 60 seconds with .locked extension. READ_ME_TO_DECRYPT.txt dropped on Desktop.', source:'graph', endpoint_id:'ws-alice-laptop', timestamp: ago(5) } },
    { pending_id:'pa-002', tenant_id:'t1', tenant_name:'ACME Corp', status:'new', ingested_at: ago(15),
      alert:{ alert_id:'ACME-2024-0090', severity:'high', title:'Suspicious PowerShell Encoded Command', description:'powershell.exe -EncodedCommand JABzAD0ATgBlAHcA... spawned by winword.exe. Dropped svchost32.exe in C:\\Users\\AppData\\Local\\Temp\\', source:'edr', endpoint_id:'ws-bob-desktop', timestamp: ago(15) } },
    { pending_id:'pa-003', tenant_id:'t2', tenant_name:'Globex Inc', status:'new', ingested_at: ago(32),
      alert:{ alert_id:'GLOBEX-2024-0044', severity:'high', title:'C2 Beacon to Known Malicious IP', description:'Outbound TCP connection to 185.220.101.45:443 every 60 seconds. Process: svchost32.exe (PID 4892). VirusTotal 67/72 engines flagged.', source:'webhook', endpoint_id:'srv-globex-dc01', timestamp: ago(32) } },
    { pending_id:'pa-004', tenant_id:'t1', tenant_name:'ACME Corp', status:'triaged', ingested_at: ago(55),
      alert:{ alert_id:'ACME-2024-0089', severity:'medium', title:'Unusual Registry Persistence Key', description:'New Run key added: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate = C:\\Users\\Public\\update.exe. Parent process: cmd.exe.', source:'edr', endpoint_id:'ws-charlie-laptop', timestamp: ago(55) } },
    { pending_id:'pa-005', tenant_id:'t2', tenant_name:'Globex Inc', status:'new', ingested_at: ago(78),
      alert:{ alert_id:'GLOBEX-2024-0043', severity:'medium', title:'YARA Match: Mimikatz Variant', description:'YARA rule Mimikatz_v2 matched file C:\\Windows\\Temp\\m64.exe (SHA256: 44d88612fea8a8f36de82e1278abb02f). File created 4 minutes ago.', source:'edr', endpoint_id:'srv-globex-dc01', timestamp: ago(78) } },
    { pending_id:'pa-006', tenant_id:'t3', tenant_name:'Initech LLC', status:'auto_processed', ingested_at: ago(110),
      alert:{ alert_id:'INIT-2024-0021', severity:'low', title:'Potential Phishing Email Link Clicked', description:'User clicked link to hxxp://secure-login-portal[.]ru/microsoft from Outlook. Chromium launched with URL. No file download detected.', source:'graph', endpoint_id:'ws-dave-laptop', timestamp: ago(110) } },
    { pending_id:'pa-007', tenant_id:'t1', tenant_name:'ACME Corp', status:'new', ingested_at: ago(130),
      alert:{ alert_id:'ACME-2024-0088', severity:'critical', title:'Lateral Movement — Pass-the-Hash', description:'Successful NTLM authentication from ws-bob-desktop to srv-fileserver-01 using hash. No interactive logon. WMI process creation on remote host. User: ACME\\bob.', source:'edr', endpoint_id:'ws-bob-desktop', timestamp: ago(130) } },
    { pending_id:'pa-008', tenant_id:'t2', tenant_name:'Globex Inc', status:'new', ingested_at: ago(145),
      alert:{ alert_id:'GLOBEX-2024-0042', severity:'high', title:'Suspicious WMI Subscription Created', description:'New permanent WMI event subscription: __EventFilter + CommandLineEventConsumer. Executes cmd.exe /c powershell.exe -w hidden -c ... on system start.', source:'graph', endpoint_id:'srv-globex-web01', timestamp: ago(145) } },
  ],
  agents: [
    { agent_id:'agt-alice-01', hostname:'ws-alice-laptop', os:'Windows', os_version:'11 Pro 22H2', agent_version:'0.1.0', capabilities:['processes','network','persistence','auth_logs','file_inspect','yara_scan','memory_dump','binary_re','isolate_endpoint','block_ip','quarantine_file','disable_user'], last_seen_at: ago(2), online:true },
    { agent_id:'agt-bob-02', hostname:'ws-bob-desktop', os:'Windows', os_version:'10 Pro 21H2', agent_version:'0.1.0', capabilities:['processes','network','persistence','auth_logs','file_inspect','yara_scan','block_ip','quarantine_file','disable_user'], last_seen_at: ago(1), online:true },
    { agent_id:'agt-charlie-03', hostname:'ws-charlie-laptop', os:'Windows', os_version:'11 Pro 23H2', agent_version:'0.1.0', capabilities:['processes','network','persistence','file_inspect','block_ip'], last_seen_at: ago(3), online:true },
    { agent_id:'agt-dc01-04', hostname:'srv-globex-dc01', os:'Windows', os_version:'Server 2022', agent_version:'0.1.0', capabilities:['processes','network','persistence','auth_logs','yara_scan','memory_dump','block_ip','isolate_endpoint'], last_seen_at: ago(4), online:true },
    { agent_id:'agt-web01-05', hostname:'srv-globex-web01', os:'Linux', os_version:'Ubuntu 22.04', agent_version:'0.1.0', capabilities:['processes','network','persistence','auth_logs','file_inspect','yara_scan','block_ip'], last_seen_at: ago(8), online:true },
    { agent_id:'agt-dave-06', hostname:'ws-dave-laptop', os:'Windows', os_version:'11 Home 23H2', agent_version:'0.1.0', capabilities:['processes','network','block_ip','quarantine_file'], last_seen_at: ago(9), online:true },
    { agent_id:'agt-fs01-07', hostname:'srv-fileserver-01', os:'Windows', os_version:'Server 2019', agent_version:'0.1.0', capabilities:['processes','network','persistence','auth_logs','isolate_endpoint','block_ip'], last_seen_at: ago(900), online:false },
    { agent_id:'agt-sql01-08', hostname:'srv-sql-01', os:'Windows', os_version:'Server 2022', agent_version:'0.1.0', capabilities:['processes','network','persistence','auth_logs'], last_seen_at: ago(1800), online:false },
  ],
  runs: [
    { run_id:'run-a1b2c3', alert_id:'ACME-2024-0087', agent_id:'agt-alice-01', final_status:'done', is_vip:false, requires_approval:false, duration_seconds:38.4, started_at: ago(3600), finished_at: ago(3562), pdf_path:'/reports/run-a1b2c3.pdf', _severity:'critical' },
    { run_id:'run-d4e5f6', alert_id:'GLOBEX-2024-0041', agent_id:'agt-dc01-04', final_status:'done', is_vip:false, requires_approval:false, duration_seconds:52.1, started_at: ago(7200), finished_at: ago(7148), pdf_path:'/reports/run-d4e5f6.pdf', _severity:'high' },
    { run_id:'run-g7h8i9', alert_id:'ACME-2024-0086', agent_id:'agt-bob-02', final_status:'requires_approval', is_vip:true, requires_approval:true, duration_seconds:29.7, started_at: ago(9000), finished_at: ago(8970), pdf_path:null, _severity:'high' },
    { run_id:'run-j0k1l2', alert_id:'INIT-2024-0020', agent_id:'agt-dave-06', final_status:'done', is_vip:false, requires_approval:false, duration_seconds:21.3, started_at: ago(14400), finished_at: ago(14379), pdf_path:'/reports/run-j0k1l2.pdf', _severity:'medium' },
    { run_id:'run-m3n4o5', alert_id:'GLOBEX-2024-0040', agent_id:'agt-web01-05', final_status:'failed', is_vip:false, requires_approval:false, duration_seconds:0, started_at: ago(18000), finished_at: ago(18000), pdf_path:null, _severity:'high' },
    { run_id:'run-p6q7r8', alert_id:'ACME-2024-0085', agent_id:'agt-alice-01', final_status:'done', is_vip:false, requires_approval:false, duration_seconds:61.8, started_at: ago(21600), finished_at: ago(21538), pdf_path:'/reports/run-p6q7r8.pdf', _severity:'critical' },
  ],
  iocs: [
    { type:'ip', value:'185.220.101.45', sources:['virustotal','abuseipdb','otx'], malicious_score:94, tags:['c2','tor-exit','known-bad'], first_seen: ago(3600) },
    { type:'ip', value:'91.219.236.222', sources:['virustotal','abuseipdb'], malicious_score:87, tags:['c2','ransomware'], first_seen: ago(7200) },
    { type:'sha256', value:'44d88612fea8a8f36de82e1278abb02f...', sources:['virustotal','malwarebazaar'], malicious_score:100, tags:['mimikatz','credential-theft'], first_seen: ago(78*60) },
    { type:'domain', value:'secure-login-portal.ru', sources:['urlhaus','threatfox'], malicious_score:76, tags:['phishing','credential-harvesting'], first_seen: ago(110*60) },
    { type:'url', value:'hxxp://secure-login-portal[.]ru/microsoft', sources:['urlhaus','virustotal'], malicious_score:82, tags:['phishing','microsoft-lure'], first_seen: ago(110*60) },
    { type:'file_path', value:'C:\\Users\\AppData\\Local\\Temp\\svchost32.exe', sources:['virustotal'], malicious_score:71, tags:['trojan','dropper'], first_seen: ago(15*60) },
    { type:'md5', value:'5f4dcc3b5aa765d61d8327deb882cf99', sources:['malwarebazaar','virustotal'], malicious_score:89, tags:['ransomware','encryptor'], first_seen: ago(5*60) },
    { type:'ip', value:'45.142.212.100', sources:['abuseipdb','greynoise'], malicious_score:63, tags:['scanner','suspicious'], first_seen: ago(180*60) },
  ],
  chartVolume: {
    labels: last7Days(),
    critical: [3,1,4,6,2,5,8],
    high:     [8,5,9,11,7,13,15],
    medium:   [14,11,18,16,12,19,22],
    low:      [20,17,23,19,22,25,28],
  },
};

function ago(seconds) {
  return new Date(Date.now() - seconds * 1000).toISOString();
}
function last7Days() {
  const d = [], now = new Date();
  for (let i = 6; i >= 0; i--) {
    const dt = new Date(now); dt.setDate(dt.getDate() - i);
    d.push(dt.toLocaleDateString('en-US',{month:'short',day:'numeric'}));
  }
  return d;
}

// ── API Client ───────────────────────────────────────
const API = {
  async request(method, path, body) {
    const url = `${CFG.apiBase}${path}`;
    const opts = {
      method,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${CFG.authToken}`,
      },
    };
    if (body) opts.body = JSON.stringify(body);
    const resp = await fetch(url, opts);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
    return resp.json();
  },
  get: (p) => API.request('GET', p),
  post: (p, b) => API.request('POST', p, b),
};

// ── Utilities ────────────────────────────────────────
function fmtTime(iso) {
  if (!iso) return '--';
  const d = new Date(iso);
  const now = Date.now(), diff = Math.floor((now - d.getTime()) / 1000);
  if (diff < 60)  return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
  return d.toLocaleDateString('en-US',{month:'short',day:'numeric'});
}
function fmtDuration(secs) {
  if (!secs || secs <= 0) return '--';
  if (secs < 60) return `${secs.toFixed(1)}s`;
  return `${Math.floor(secs/60)}m ${Math.round(secs%60)}s`;
}
function nowStr() {
  return new Date().toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false});
}
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function rand(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function randFrom(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

function escapeHtml(s) {
  const d = document.createElement('div');
  d.textContent = s ?? '';
  return d.innerHTML;
}

function openModal(id) {
  document.getElementById(id).classList.add('open');
}
function closeModal(id) {
  document.getElementById(id).classList.remove('open');
}

function showToast(type, title, msg = '', duration = 4000) {
  const icons = { success:'fa-circle-check', error:'fa-circle-xmark', info:'fa-circle-info', warn:'fa-triangle-exclamation' };
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `<i class="fas ${icons[type]||icons.info} toast-icon"></i><div class="toast-body"><div class="toast-title">${escapeHtml(title)}</div>${msg?`<div class="toast-msg">${escapeHtml(msg)}</div>`:''}</div>`;
  const container = document.getElementById('toast-container');
  container.appendChild(el);
  setTimeout(() => { el.classList.add('fade-out'); setTimeout(() => el.remove(), 300); }, duration);
}

function animateCounter(el, target, duration = 800) {
  const start = parseInt(el.textContent.replace(/\D/g,'')) || 0;
  const step = (target - start) / (duration / 16);
  let cur = start;
  const timer = setInterval(() => {
    cur += step;
    if ((step > 0 && cur >= target) || (step < 0 && cur <= target)) {
      el.textContent = target;
      clearInterval(timer);
    } else {
      el.textContent = Math.round(cur);
    }
  }, 16);
}

// ── Tab Navigation ───────────────────────────────────
function switchTab(name) {
  STATE.tab = name;
  document.querySelectorAll('.tab-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.tab === name);
  });
  document.querySelectorAll('.tab-panel').forEach(p => {
    p.classList.toggle('active', p.id === `panel-${name}`);
  });
  if (name === 'bots') initBotConsoleIdle();
  if (name === 'threats') {
    // Re-fetch if we have runs but no IOCs yet and user hasn't explicitly cleared
    if (!CFG.demoMode && STATE.iocs.length === 0 && STATE.runs.length > 0 && !STATE.threatIntelCleared) {
      loadRealThreatIntel().then(() => renderThreatIntel()).catch(() => renderThreatIntel());
    } else {
      renderThreatIntel();
    }
  }
}

document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => switchTab(btn.dataset.tab));
});

// ── Connection Status ────────────────────────────────
function setConnStatus(status, label) {
  const dot = document.getElementById('conn-dot');
  const lbl = document.getElementById('conn-label');
  dot.className = `conn-dot ${status}`;
  lbl.textContent = label;
}

// ── Data Loading ─────────────────────────────────────
async function loadAll() {
  if (CFG.demoMode) {
    STATE.stats     = DEMO.stats;
    STATE.alerts    = DEMO.alerts;
    STATE.agents    = DEMO.agents;
    STATE.runs      = DEMO.runs;
    STATE.iocs      = DEMO.iocs;
    STATE.chartData = null;
    setConnStatus('demo', 'Demo Mode');
    STATE.isConnected = true;
    return;
  }
  try {
    const [stats, alerts, agents, runs, chartData] = await Promise.all([
      API.get('/dashboard/stats'),
      API.get('/alerts/pending?limit=100'),
      API.get('/agents'),
      API.get('/workflow/runs?limit=50'),
      API.get('/dashboard/chart-data'),
    ]);
    STATE.stats     = stats;
    STATE.alerts    = alerts;
    STATE.agents    = agents;
    STATE.runs      = runs;
    STATE.chartData = chartData;
    STATE.isConnected = true;
    setConnStatus('online', 'Connected');
    // Back-fill IOCs + MITRE from stored runs — awaited so data is ready before first render
    await loadRealThreatIntel();
  } catch (e) {
    STATE.isConnected = false;
    setConnStatus('offline', 'Offline');
    console.error('API error:', e.message);
    showToast('error', 'Connection Failed', e.message, 8000);
    // Keep whatever state we already had — do NOT silently flip to demo data
  }
}

async function refreshAlerts() {
  if (CFG.demoMode) {
    STATE.alerts = DEMO.alerts;
  } else {
    try {
      STATE.alerts = await API.get('/alerts/pending?limit=100');
      setConnStatus('online', 'Connected');
      STATE.isConnected = true;
    } catch(e) {
      showToast('error', 'Refresh Failed', e.message);
      return;
    }
  }
  renderAlertTable();
  showToast('info', 'Refreshed', `${STATE.alerts.length} alerts loaded`);
}

async function refreshEndpoints() {
  if (CFG.demoMode) {
    STATE.agents = DEMO.agents;
  } else {
    try { STATE.agents = await API.get('/agents'); } catch(e) {
      showToast('error', 'Refresh Failed', e.message); return;
    }
  }
  renderEndpoints();
}

async function refreshIncidents() {
  if (CFG.demoMode) {
    STATE.runs = DEMO.runs;
  } else {
    try { STATE.runs = await API.get('/workflow/runs?limit=50'); } catch(e) {
      showToast('error', 'Refresh Failed', e.message); return;
    }
  }
  renderIncidents();
}

// ── Overview Tab ─────────────────────────────────────
function renderOverview() {
  const s = STATE.stats;
  const pr = s.pipeline_runs || {};
  // Prefer pipeline severity breakdown; fall back to pending-alert severity from chart-data
  const bySev = (Object.keys(pr.by_severity || {}).length > 0)
    ? pr.by_severity
    : (STATE.chartData?.severity_dist || {});

  // Stat cards
  const total24h = pr.last_24h || 0;
  const totalAll = pr.total_runs || 0;
  const pendingNew = s.pending_alerts?.new || 0;

  const svAlerts = document.getElementById('sv-alerts');
  const svThreats = document.getElementById('sv-threats');
  const svRuns = document.getElementById('sv-runs');
  const svEp = document.getElementById('sv-endpoints');

  animateCounter(svAlerts, total24h);
  animateCounter(svThreats, (bySev.critical || 0) + (bySev.high || 0));
  animateCounter(svRuns, totalAll);

  const online = (STATE.agents || []).filter(a => a.online).length;
  animateCounter(svEp, online);

  document.getElementById('ss-alerts').textContent = `${pendingNew} pending in inbox`;
  document.getElementById('ss-threats').textContent = `${bySev.critical || 0} critical`;
  document.getElementById('ss-runs').textContent = `${pr.last_24h || 0} today`;
  document.getElementById('ss-endpoints').textContent = `${(STATE.agents||[]).length} registered`;

  // Charts
  renderVolumeChart();
  renderSeverityDonut(bySev);
  renderMitreChart();
  renderEnrichmentRadar(s.enrichers || {});
  renderKillChainChart();
  renderGeoChart();
  renderActivityFeed();

  // update volume meta
  let total7d = 0;
  if (!CFG.demoMode && STATE.chartData?.volume_7d?.length) {
    total7d = STATE.chartData.volume_7d.reduce((s, r) =>
      s + (r.critical||0) + (r.high||0) + (r.medium||0) + (r.low||0), 0);
  } else {
    total7d = DEMO.chartVolume.critical.reduce((a,b)=>a+b,0)
            + DEMO.chartVolume.high.reduce((a,b)=>a+b,0)
            + DEMO.chartVolume.medium.reduce((a,b)=>a+b,0)
            + DEMO.chartVolume.low.reduce((a,b)=>a+b,0);
  }
  document.getElementById('vol-meta').textContent = `${total7d} total · 7-day view`;
}

function makeChart(id, config) {
  if (STATE.charts[id]) { STATE.charts[id].destroy(); }
  const ctx = document.getElementById(id);
  if (!ctx) return null;
  STATE.charts[id] = new Chart(ctx, config);
  return STATE.charts[id];
}

const CHART_DEFAULTS = {
  color: '#7a8db0',
  font: { family: "'Inter', sans-serif", size: 11 },
};

function renderVolumeChart() {
  // Use real API data when connected, demo data otherwise
  let v;
  if (!CFG.demoMode && STATE.chartData && STATE.chartData.volume_7d?.length) {
    const cd = STATE.chartData.volume_7d;
    v = {
      labels:   cd.map(r => r.date),
      critical: cd.map(r => r.critical || 0),
      high:     cd.map(r => r.high     || 0),
      medium:   cd.map(r => r.medium   || 0),
      low:      cd.map(r => r.low      || 0),
    };
  } else {
    v = DEMO.chartVolume;
  }
  makeChart('chart-volume', {
    type: 'line',
    data: {
      labels: v.labels,
      datasets: [
        { label:'Critical', data: v.critical, borderColor:'#ff3355', backgroundColor:'rgba(255,51,85,0.08)', fill:true, tension:0.4, borderWidth:2, pointRadius:3, pointBackgroundColor:'#ff3355' },
        { label:'High',     data: v.high,     borderColor:'#ff8800', backgroundColor:'rgba(255,136,0,0.08)', fill:true, tension:0.4, borderWidth:2, pointRadius:3, pointBackgroundColor:'#ff8800' },
        { label:'Medium',   data: v.medium,   borderColor:'#ffd600', backgroundColor:'rgba(255,214,0,0.06)', fill:true, tension:0.4, borderWidth:2, pointRadius:3, pointBackgroundColor:'#ffd600' },
        { label:'Low',      data: v.low,      borderColor:'#00ff88', backgroundColor:'rgba(0,255,136,0.06)', fill:true, tension:0.4, borderWidth:2, pointRadius:3, pointBackgroundColor:'#00ff88' },
      ]
    },
    options: {
      responsive:true, maintainAspectRatio:false,
      interaction:{ mode:'index', intersect:false },
      plugins:{ legend:{ position:'top', labels:{ color:'#7a8db0', font:CHART_DEFAULTS.font, boxWidth:10, usePointStyle:true } },
                tooltip:{ backgroundColor:'#111829', borderColor:'rgba(0,212,255,0.2)', borderWidth:1, titleColor:'#e8eef8', bodyColor:'#7a8db0', padding:10 } },
      scales:{
        x:{ grid:{ color:'rgba(255,255,255,0.04)' }, ticks:{ color:'#3d5080', font:CHART_DEFAULTS.font } },
        y:{ grid:{ color:'rgba(255,255,255,0.04)' }, ticks:{ color:'#3d5080', font:CHART_DEFAULTS.font }, beginAtZero:true },
      },
    }
  });
}

function renderSeverityDonut(bySev) {
  const c = bySev.critical || 0, h = bySev.high || 0, m = bySev.medium || 0, l = bySev.low || 0;
  const total = c + h + m + l;
  document.getElementById('donut-total').innerHTML = `<span class="donut-num">${total}</span><span class="donut-lbl">total</span>`;

  makeChart('chart-severity', {
    type: 'doughnut',
    data: {
      labels: ['Critical','High','Medium','Low'],
      datasets:[{ data: total > 0 ? [c, h, m, l] : [1, 1, 1, 1],
        backgroundColor:['rgba(255,51,85,0.85)','rgba(255,136,0,0.85)','rgba(255,214,0,0.85)','rgba(0,255,136,0.85)'],
        borderColor:['#ff3355','#ff8800','#ffd600','#00ff88'],
        borderWidth: total > 0 ? 1 : 0, hoverOffset: total > 0 ? 6 : 0 }]
    },
    options:{
      responsive:true, maintainAspectRatio:false, cutout:'68%',
      plugins:{ legend:{ display:false },
        tooltip:{ enabled: total > 0, backgroundColor:'#111829', borderColor:'rgba(0,212,255,0.2)', borderWidth:1, titleColor:'#e8eef8', bodyColor:'#7a8db0' } },
      animation:{ animateRotate:true, duration:800 },
    }
  });

  // Legend
  const leg = document.getElementById('severity-legend');
  const data = [['Critical',c,'#ff3355'],['High',h,'#ff8800'],['Medium',m,'#ffd600'],['Low',l,'#00ff88']];
  leg.innerHTML = data.map(([lbl,v,col]) => `<div class="sev-leg-item"><div class="sev-leg-dot" style="background:${col}"></div><span class="sev-leg-label">${lbl}</span><span class="sev-leg-count" style="color:${col}">${v}</span></div>`).join('');
}

function renderMitreChart() {
  const useReal = !CFG.demoMode && Object.keys(STATE.mitreCounts).length > 0;
  let techniques;
  if (useReal) {
    techniques = Object.entries(STATE.mitreCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([id, count]) => ({ id, name: MITRE_NAMES[id] || id, count }));
  } else if (CFG.demoMode) {
    techniques = [
      { id:'T1059.001', name:'PowerShell', count:47 },
      { id:'T1055',    name:'Process Inject', count:34 },
      { id:'T1027',    name:'Obfuscation', count:29 },
      { id:'T1003',    name:'Credential Dump', count:24 },
      { id:'T1547',    name:'Boot/Logon Persist', count:21 },
      { id:'T1071.001',name:'Web Protocol C2', count:19 },
      { id:'T1486',    name:'Data Encrypted', count:16 },
      { id:'T1021',    name:'Remote Services', count:14 },
    ];
  } else {
    // Real mode but no MITRE data yet
    const el = document.getElementById('chart-mitre');
    if (el) { el.style.display = 'none'; }
    const wrap = el?.closest('.chart-wrap') || el?.parentElement;
    if (wrap && !wrap.querySelector('.no-data-msg')) {
      const msg = document.createElement('div');
      msg.className = 'no-data-msg';
      msg.style.cssText = 'display:flex;align-items:center;justify-content:center;height:100%;color:#3d5080;font-size:12px;flex-direction:column;gap:8px';
      msg.innerHTML = '<i class="fas fa-shield-halved" style="font-size:24px;opacity:0.3"></i><span>No MITRE data yet — run pipeline alerts to populate</span>';
      wrap.appendChild(msg);
    }
    return;
  }
  const el = document.getElementById('chart-mitre');
  if (el) { el.style.display = ''; }
  const wrap = el?.closest('.chart-wrap') || el?.parentElement;
  wrap?.querySelector('.no-data-msg')?.remove();

  makeChart('chart-mitre', {
    type: 'bar',
    data:{
      labels: techniques.map(t => t.id),
      datasets:[{ label:'Occurrences', data: techniques.map(t=>t.count),
        backgroundColor: techniques.map((_,i) => `rgba(0,212,255,${0.9 - i*0.08})`),
        borderColor: '#00d4ff', borderWidth:0, borderRadius:3 }]
    },
    options:{
      indexAxis:'y', responsive:true, maintainAspectRatio:false,
      plugins:{ legend:{ display:false },
                tooltip:{ backgroundColor:'#111829', borderColor:'rgba(0,212,255,0.2)', borderWidth:1, titleColor:'#e8eef8', bodyColor:'#7a8db0',
                  callbacks:{ title: (items) => {
                    const t = techniques[items[0].dataIndex];
                    return `${t.id}: ${t.name}`;
                  }}
                }
      },
      scales:{
        x:{ grid:{ color:'rgba(255,255,255,0.04)' }, ticks:{ color:'#3d5080', font:CHART_DEFAULTS.font }, beginAtZero:true },
        y:{ grid:{ display:false }, ticks:{ color:'#7a8db0', font:{ family:"'JetBrains Mono',monospace", size:10 } } },
      },
    }
  });
}

function renderEnrichmentRadar(enrichers) {
  const sources =    ['VirusTotal','AbuseIPDB','OTX','URLhaus','ThreatFox','MalwareBazaar'];
  const configKeys = ['virustotal','abuseipdb','otx','urlhaus','threatfox','malwarebazaar'];
  let values, tooltipLabel;

  if (!CFG.demoMode && STATE.iocs.length > 0) {
    // Count how many IOCs each source contributed to
    const hitCounts = {};
    STATE.iocs.forEach(ioc => {
      (ioc.sources || []).forEach(src => {
        const key = src.toLowerCase().replace(/[^a-z]/g, '');
        hitCounts[key] = (hitCounts[key] || 0) + 1;
      });
    });
    const maxHits = Math.max(1, ...Object.values(hitCounts));
    values = configKeys.map(k => {
      const count = hitCounts[k] || 0;
      return { pct: Math.round((count / maxHits) * 100), count };
    });
    tooltipLabel = (ctx) => {
      const v = values[ctx.dataIndex];
      return `${v.count} IOC${v.count !== 1 ? 's' : ''} flagged`;
    };
  } else {
    // Demo: static plausible values for configured enrichers
    const demoPcts = [95, 88, 82, 100, 100, 78];
    values = configKeys.map((k, i) => ({ pct: enrichers[k] ? demoPcts[i] : 0, count: null }));
    tooltipLabel = (ctx) => `${values[ctx.dataIndex].pct}% coverage`;
  }

  makeChart('chart-enrichment', {
    type:'radar',
    data:{
      labels: sources,
      datasets:[{ label:'Coverage', data: values.map(v => v.pct),
        backgroundColor:'rgba(0,212,255,0.12)', borderColor:'#00d4ff',
        pointBackgroundColor:'#00d4ff', pointBorderColor:'#00d4ff',
        borderWidth:2, pointRadius:4 }]
    },
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{ legend:{ display:false },
        tooltip:{ backgroundColor:'#111829', borderColor:'rgba(0,212,255,0.2)', borderWidth:1, titleColor:'#e8eef8', bodyColor:'#7a8db0',
          callbacks:{ label: tooltipLabel } } },
      scales:{ r:{ grid:{ color:'rgba(255,255,255,0.06)' }, pointLabels:{ color:'#7a8db0', font:{ size:10 } }, ticks:{ display:false }, angleLines:{ color:'rgba(255,255,255,0.06)' }, min:0, max:100 } },
    }
  });
}

function normalizeKillChainPhase(phase) {
  if (!phase) return null;
  const p = phase.toLowerCase().replace(/[\s_&-]+/g, '');
  if (/recon/.test(p)) return 'Reconnaissance';
  if (/weapon/.test(p)) return 'Weaponization';
  if (/deliv/.test(p)) return 'Delivery';
  if (/exploit/.test(p)) return 'Exploitation';
  if (/install/.test(p)) return 'Installation';
  if (/c2|command|control/.test(p)) return 'C2';
  if (/exfil/.test(p)) return 'Exfiltration';
  return null;
}

function renderKillChainChart() {
  const phases = ['Reconnaissance','Weaponization','Delivery','Exploitation','Installation','C2','Exfiltration'];
  const colors = ['#9b59ff','#7c3aed','#6d28d9','#5b21b6','#4c1d95','#3730a3','#312e81'];
  let vals;

  if (!CFG.demoMode) {
    vals = phases.map(p => STATE.killChainCounts[p] || 0);
  } else {
    vals = [12, 8, 23, 31, 19, 28, 9];
  }

  makeChart('chart-killchain', {
    type:'bar',
    data:{
      labels: phases,
      datasets:[{ label:'Events', data: vals,
        backgroundColor: colors.map(c => c+'cc'),
        borderColor: colors, borderWidth:1, borderRadius:4 }]
    },
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{ legend:{ display:false }, tooltip:{ backgroundColor:'#111829', borderColor:'rgba(0,212,255,0.2)', borderWidth:1, titleColor:'#e8eef8', bodyColor:'#7a8db0' } },
      scales:{
        x:{ grid:{ display:false }, ticks:{ color:'#3d5080', font:{ size:9 }, maxRotation:45 } },
        y:{ grid:{ color:'rgba(255,255,255,0.04)' }, ticks:{ color:'#3d5080', font:CHART_DEFAULTS.font }, beginAtZero:true },
      },
    }
  });
}

function renderGeoChart() {
  // In real mode: show top malicious IPs by score from enriched IOCs
  // In demo mode: show representative country-origin data
  let labels, vals, colors, tooltipTitle, chartTitle;

  if (!CFG.demoMode) {
    const ipIOCs = (STATE.iocs || [])
      .filter(i => (i.type || '').toLowerCase() === 'ip' && i.malicious_score > 0)
      .sort((a, b) => b.malicious_score - a.malicious_score)
      .slice(0, 8);

    if (ipIOCs.length === 0) {
      // No enriched IPs yet — show placeholder
      const el = document.getElementById('chart-geo');
      if (el) el.style.display = 'none';
      const wrap = el?.closest('.chart-wrap') || el?.parentElement;
      if (wrap && !wrap.querySelector('.no-data-msg-geo')) {
        const msg = document.createElement('div');
        msg.className = 'no-data-msg-geo';
        msg.style.cssText = 'display:flex;align-items:center;justify-content:center;height:100%;color:#3d5080;font-size:12px;flex-direction:column;gap:8px';
        msg.innerHTML = '<i class="fas fa-globe" style="font-size:24px;opacity:0.3"></i><span>No malicious IPs detected yet</span>';
        wrap.appendChild(msg);
      }
      return;
    }

    // Clear any placeholder
    const el = document.getElementById('chart-geo');
    if (el) el.style.display = '';
    el?.closest('.chart-wrap')?.querySelector('.no-data-msg-geo')?.remove();
    el?.parentElement?.querySelector('.no-data-msg-geo')?.remove();

    labels = ipIOCs.map(i => i.value);
    vals   = ipIOCs.map(i => i.malicious_score);
    colors = vals.map(v => v >= 90 ? 'rgba(255,51,85,0.8)' : v >= 70 ? 'rgba(255,136,0,0.8)' : 'rgba(255,214,0,0.8)');
    tooltipTitle = (items) => `Score: ${items[0].raw}/100`;
    chartTitle = 'label';
  } else {
    const countries = ['Russia','China','Netherlands','United States','Ukraine','Romania','Brazil','Germany'];
    const demoVals  = [34,28,21,19,15,12,9,7];
    labels = countries;
    vals   = demoVals;
    colors = demoVals.map(v => `rgba(255,${Math.round(255-v*5)},${Math.round(100-v*2)},0.8)`);
    tooltipTitle = null;
    chartTitle = 'label';
    const titleEl = document.getElementById('geo-chart-title');
    if (titleEl) titleEl.innerHTML = '<i class="fas fa-globe"></i> Threat Origin Distribution';
  }

  makeChart('chart-geo', {
    type:'bar',
    data:{
      labels,
      datasets:[{ label: CFG.demoMode ? 'Threat Events' : 'Malicious Score', data: vals,
        backgroundColor: colors, borderColor: colors.map(c=>c.replace('0.8','1')),
        borderWidth:1, borderRadius:4 }]
    },
    options:{
      indexAxis:'y', responsive:true, maintainAspectRatio:false,
      plugins:{ legend:{ display:false },
        tooltip:{ backgroundColor:'#111829', borderColor:'rgba(0,212,255,0.2)', borderWidth:1, titleColor:'#e8eef8', bodyColor:'#7a8db0',
          callbacks: tooltipTitle ? { title: tooltipTitle } : {} } },
      scales:{
        x:{ grid:{ color:'rgba(255,255,255,0.04)' }, ticks:{ color:'#3d5080', font:CHART_DEFAULTS.font }, beginAtZero:true, max: CFG.demoMode ? undefined : 100 },
        y:{ grid:{ display:false }, ticks:{ color:'#7a8db0', font:{ family:"'JetBrains Mono',monospace", size:9 } } },
      },
    }
  });
}

function renderActivityFeed() {
  const feed = document.getElementById('activity-feed');
  const sevIcons = { critical:'🚨', high:'⚠️', medium:'🔍', low:'📋', info:'ℹ️' };
  let items;

  if (!CFG.demoMode && STATE.alerts && STATE.alerts.length > 0) {
    // Build from real pending alerts
    items = STATE.alerts.slice(0, 8).map(a => {
      const alert = a.alert || {};
      const sev = (alert.severity || 'info').toLowerCase();
      return {
        sev,
        icon: sevIcons[sev] || '📋',
        title: alert.title || alert.alert_id || 'Unknown Alert',
        time: a.ingested_at || alert.timestamp,
      };
    });
  } else {
    // Demo fallback
    items = [
      { sev:'critical', icon:'🚨', title:'Ransomware detected on ws-alice-laptop',       time: ago(5) },
      { sev:'high',     icon:'⚠️', title:'PowerShell C2 beacon blocked',                 time: ago(15) },
      { sev:'info',     icon:'🤖', title:'Decision Bot: verdict MALICIOUS (94%)',         time: ago(18) },
      { sev:'high',     icon:'⚠️', title:'Mimikatz variant found on srv-globex-dc01',    time: ago(78*60) },
      { sev:'info',     icon:'✅', title:'Action Bot: isolated ws-alice-laptop',          time: ago(22) },
      { sev:'medium',   icon:'🔍', title:'Suspicious registry key — ws-charlie',         time: ago(55*60) },
      { sev:'info',     icon:'📋', title:'Analysis Bot: 5 findings (2 critical)',        time: ago(28) },
      { sev:'low',      icon:'📧', title:'Phishing link detected — ws-dave',             time: ago(110*60) },
    ];
  }

  feed.innerHTML = items.length
    ? items.map(it => `
        <div class="activity-item ${it.sev}">
          <span class="activity-icon">${it.icon}</span>
          <div class="activity-text">
            <div class="activity-title">${escapeHtml(it.title)}</div>
            <div class="activity-time">${fmtTime(it.time)}</div>
          </div>
        </div>`).join('')
    : '<div class="activity-placeholder"><i class="fas fa-inbox"></i> No recent alerts</div>';
}

// ── Alert Inbox ──────────────────────────────────────
function renderAlertTable() {
  const search = (document.getElementById('alert-search')?.value || '').toLowerCase();
  const sevFilter = document.getElementById('filter-severity')?.value || '';
  const statusFilter = document.getElementById('filter-status')?.value || '';

  let alerts = STATE.alerts || [];
  if (search)      alerts = alerts.filter(a => JSON.stringify(a).toLowerCase().includes(search));
  if (sevFilter)   alerts = alerts.filter(a => a.alert?.severity === sevFilter);
  if (statusFilter) alerts = alerts.filter(a => a.status === statusFilter);

  const newCount = (STATE.alerts || []).filter(a => a.status === 'new').length;
  const badge = document.getElementById('badge-alerts');
  if (newCount > 0) { badge.textContent = newCount; badge.style.display = ''; }
  else { badge.style.display = 'none'; }

  const runBadge = document.getElementById('run-badge');
  const selCount = STATE.selectedAlerts.size || newCount;
  runBadge.textContent = STATE.selectedAlerts.size > 0 ? STATE.selectedAlerts.size : newCount;

  const tbody = document.getElementById('alerts-tbody');
  if (!alerts.length) {
    tbody.innerHTML = `<tr><td colspan="9"><div class="empty-state"><i class="fas fa-inbox"></i><p>No alerts match your filters</p></div></td></tr>`;
    return;
  }

  tbody.innerHTML = alerts.map(a => {
    const alert = a.alert || {};
    const sev = (alert.severity || 'unknown').toLowerCase();
    const st = a.status || 'new';
    const checked = STATE.selectedAlerts.has(a.pending_id) ? 'checked' : '';
    return `
    <tr class="${STATE.selectedAlerts.has(a.pending_id) ? 'selected' : ''}" data-id="${escapeHtml(a.pending_id)}">
      <td class="th-check"><input type="checkbox" ${checked} onchange="toggleAlert('${escapeHtml(a.pending_id)}',this)"></td>
      <td><span class="sev-badge sev-${sev}">${sev}</span></td>
      <td>
        <div style="font-weight:600;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeHtml(alert.title||'')}">${escapeHtml(alert.title||'Unknown Alert')}</div>
        <div style="font-size:10px;color:var(--text-3);font-family:var(--mono)">${escapeHtml(alert.alert_id||'')}</div>
      </td>
      <td><span class="mono" style="color:var(--text-2)">${escapeHtml(alert.source||'--')}</span></td>
      <td><span class="mono" style="color:var(--c-cyan)">${escapeHtml(alert.endpoint_id||'--')}</span></td>
      <td>${escapeHtml(a.tenant_name||'--')}</td>
      <td><span class="status-chip status-${st}">${st.replace('_',' ')}</span></td>
      <td style="color:var(--text-3);font-size:12px;white-space:nowrap">${fmtTime(a.ingested_at)}</td>
      <td>
        <div class="tbl-actions">
          <button class="tbl-btn" onclick="showAlertDetail('${escapeHtml(a.pending_id)}')"><i class="fas fa-eye"></i></button>
          <button class="tbl-btn run" onclick="runSingleAlert('${escapeHtml(a.pending_id)}')"><i class="fas fa-play"></i></button>
          <button class="tbl-btn danger" onclick="dismissAlert('${escapeHtml(a.pending_id)}')"><i class="fas fa-xmark"></i></button>
        </div>
      </td>
    </tr>`;
  }).join('');

  updateSelectionUI();
}

function toggleAlert(id, chk) {
  if (chk.checked) STATE.selectedAlerts.add(id);
  else STATE.selectedAlerts.delete(id);
  const row = chk.closest('tr');
  if (row) row.classList.toggle('selected', chk.checked);
  updateSelectionUI();
}

function toggleSelectAll(chk) {
  document.querySelectorAll('#alerts-tbody input[type=checkbox]').forEach(c => {
    const id = c.closest('tr')?.dataset.id;
    if (id) {
      c.checked = chk.checked;
      if (chk.checked) STATE.selectedAlerts.add(id);
      else STATE.selectedAlerts.delete(id);
      c.closest('tr')?.classList.toggle('selected', chk.checked);
    }
  });
  updateSelectionUI();
}

function updateSelectionUI() {
  const count = STATE.selectedAlerts.size;
  const lbl = document.getElementById('sel-label');
  const cnt = document.getElementById('sel-count');
  if (count > 0) { lbl.style.display = ''; cnt.textContent = count; }
  else { lbl.style.display = 'none'; }
  const newCount = (STATE.alerts || []).filter(a => a.status === 'new').length;
  document.getElementById('run-badge').textContent = count > 0 ? count : newCount;
}

function showAlertDetail(pendingId) {
  const a = (STATE.alerts || []).find(x => x.pending_id === pendingId);
  if (!a) return;
  STATE.currentDetailAlert = a;
  const alert = a.alert || {};
  const sev = (alert.severity || 'unknown').toLowerCase();
  const body = document.getElementById('alert-detail-body');
  body.innerHTML = `
    <div class="detail-grid">
      <div class="detail-item"><div class="detail-label">Alert ID</div><div class="detail-value mono">${escapeHtml(alert.alert_id||'--')}</div></div>
      <div class="detail-item"><div class="detail-label">Severity</div><div class="detail-value"><span class="sev-badge sev-${sev}">${sev}</span></div></div>
      <div class="detail-item"><div class="detail-label">Source</div><div class="detail-value">${escapeHtml(alert.source||'--')}</div></div>
      <div class="detail-item"><div class="detail-label">Endpoint</div><div class="detail-value mono" style="color:var(--c-cyan)">${escapeHtml(alert.endpoint_id||'--')}</div></div>
      <div class="detail-item"><div class="detail-label">Tenant</div><div class="detail-value">${escapeHtml(a.tenant_name||'--')}</div></div>
      <div class="detail-item"><div class="detail-label">Status</div><div class="detail-value"><span class="status-chip status-${a.status}">${(a.status||'').replace('_',' ')}</span></div></div>
      <div class="detail-item"><div class="detail-label">Ingested</div><div class="detail-value">${fmtTime(a.ingested_at)}</div></div>
      <div class="detail-item"><div class="detail-label">Timestamp</div><div class="detail-value">${fmtTime(alert.timestamp)}</div></div>
    </div>
    <div class="detail-description"><strong>Description:</strong><br>${escapeHtml(alert.description||'No description available.')}</div>
    ${Object.keys(alert.raw||{}).length ? `<div class="detail-raw">${escapeHtml(JSON.stringify(alert.raw, null, 2))}</div>` : ''}
  `;
  openModal('modal-alert');
}

function runSingleFromDetail() {
  if (!STATE.currentDetailAlert) return;
  closeModal('modal-alert');
  STATE.selectedAlerts.clear();
  STATE.selectedAlerts.add(STATE.currentDetailAlert.pending_id);
  openRunModal();
}

function runSingleAlert(pendingId) {
  STATE.selectedAlerts.clear();
  STATE.selectedAlerts.add(pendingId);
  openRunModal();
}

function dismissAlert(pendingId) {
  STATE.alerts = STATE.alerts.map(a => a.pending_id === pendingId ? {...a, status:'dismissed'} : a);
  renderAlertTable();
  showToast('info','Alert Dismissed','Alert marked as dismissed');
}

// ── Run All Bots Modal ───────────────────────────────
function openRunModal() {
  const count = STATE.selectedAlerts.size || (STATE.alerts||[]).filter(a=>a.status==='new').length;
  document.getElementById('run-alert-count').textContent = count;

  // Populate agents
  const sel = document.getElementById('run-agent');
  const agents = STATE.agents || [];
  sel.innerHTML = agents.length
    ? agents.map(a => `<option value="${escapeHtml(a.agent_id)}" ${!a.online?'disabled':''}>
        ${escapeHtml(a.hostname)} · ${escapeHtml(a.os)} ${!a.online?'(offline)':'🟢'}
      </option>`).join('')
    : '<option value="demo-agent-01">demo-agent-01 (ws-alice-laptop)</option>';

  openModal('modal-run');
}

async function confirmRunAllBots() {
  const agentId = document.getElementById('run-agent').value;
  const mode = document.querySelector('input[name="run-mode"]:checked')?.value || 'auto';

  const toRun = STATE.selectedAlerts.size > 0
    ? [...STATE.selectedAlerts].map(id => (STATE.alerts||[]).find(a=>a.pending_id===id)).filter(Boolean)
    : (STATE.alerts||[]).filter(a => a.status==='new');

  if (!toRun.length) {
    showToast('warn','No Alerts','No alerts selected or available in inbox');
    return;
  }

  closeModal('modal-run');
  STATE.selectedAlerts.clear();
  updateSelectionUI();

  // Switch to bot console
  switchTab('bots');
  document.getElementById('badge-bots').style.display = '';

  // Run pipeline
  if (CFG.demoMode || !STATE.isConnected) {
    await simulatePipeline(toRun, agentId, mode);
  } else {
    await runRealPipeline(toRun, agentId, mode);
  }
}

// ── Bot Console ──────────────────────────────────────
function initBotConsoleIdle() {
  if (STATE.botRunning) return;
  document.getElementById('pb-icon').className = 'pb-icon idle';
  document.getElementById('pb-title').textContent = 'Pipeline Idle';
  document.getElementById('pb-sub').textContent = 'No active executions. Use Alert Inbox → Run All 3 Bots to start.';
  document.getElementById('pb-progress-wrap').style.display = 'none';
  document.getElementById('pb-alert-info').style.display = 'none';
}

function setBotStatus(bot, status, pct, stepText) {
  const badge = document.getElementById(`b-${bot}-badge`);
  const prog  = document.getElementById(`prog-${bot}`);
  const pctEl = document.getElementById(`pct-${bot}`);
  const stepEl = document.getElementById(`step-${bot}-txt`);
  const card  = document.getElementById(`bot-${bot}`);

  const labels = { idle:'Idle', running:'Running', done:'Done', error:'Error' };
  badge.className = `bot-badge ${status}`;
  badge.innerHTML = `<span class="bdot"></span> ${labels[status]||status}`;

  prog.style.width = `${pct}%`;
  pctEl.textContent = `${pct}%`;
  if (stepText !== undefined && stepEl) stepEl.textContent = stepText;

  card.className = `bot-card ${status !== 'idle' ? status : ''}`;
}

function setPipelineStatus(status, title, sub, pct) {
  const icon = document.getElementById('pb-icon');
  icon.className = `pb-icon ${status}`;
  const icons = { idle:'fa-circle-pause', running:'fa-circle-play', done:'fa-circle-check', error:'fa-circle-xmark' };
  icon.innerHTML = `<i class="fas ${icons[status]||'fa-circle-pause'}"></i>`;
  document.getElementById('pb-title').textContent = title;
  document.getElementById('pb-sub').textContent = sub;

  const pw = document.getElementById('pb-progress-wrap');
  if (pct !== undefined) {
    pw.style.display = '';
    document.getElementById('pb-prog-fill').style.width = `${pct}%`;
    document.getElementById('pb-prog-pct').textContent = `${pct}%`;
  } else {
    pw.style.display = 'none';
  }
}

function setCurrentAlert(title, idx, total) {
  const info = document.getElementById('pb-alert-info');
  info.style.display = '';
  document.getElementById('pb-alert-idx').textContent = idx;
  document.getElementById('pb-alert-total').textContent = total;
  document.getElementById('pb-alert-title').textContent = title;
}

function activateConnector(num) {
  document.getElementById(`pc-line-${num}`).classList.add('active');
  document.getElementById(`pc-line-${num}`).nextElementSibling?.classList.add('active');
}

function resetBotMetrics() {
  ['d','a','x'].forEach(k => {
    ['dur','ioc','verdict','findings','sev','actions','vip'].forEach(m => {
      const el = document.getElementById(`bm-${k}-${m}`);
      if (el) el.textContent = '--';
    });
  });
}

function addLog(level, msg) {
  const log = document.getElementById('exec-log');
  const entry = document.createElement('div');
  entry.className = `log-entry log-${level}`;
  entry.innerHTML = `<span class="log-ts">${nowStr()}</span><span class="log-tag ${level}">${level.toUpperCase()}</span><span class="log-msg">${escapeHtml(msg)}</span>`;
  log.appendChild(entry);
  if (document.getElementById('autoscroll')?.checked) {
    log.scrollTop = log.scrollHeight;
  }
}

function clearLog() {
  document.getElementById('exec-log').innerHTML = '';
}

async function simulatePipeline(alerts, agentId, mode) {
  STATE.botRunning = true;
  const total = alerts.length;

  setPipelineStatus('running', 'Pipeline Running', `Processing ${total} alert${total>1?'s':''} through 3-bot pipeline`, 0);
  addLog('info', `Pipeline started: ${total} alert(s) queued | Agent: ${agentId} | Mode: ${mode}`);

  for (let i = 0; i < alerts.length; i++) {
    const alert = alerts[i].alert || {};
    const sev = alert.severity || 'high';
    setCurrentAlert(alert.title || alert.alert_id || 'Unknown', i + 1, total);

    // Reset for this alert
    ['decision','analysis','action'].forEach(b => setBotStatus(b, 'idle', 0, 'Waiting...'));
    document.getElementById('pc-line-1').classList.remove('active');
    document.getElementById('pc-line-2').classList.remove('active');
    resetBotMetrics();

    const overallPct = Math.round((i / total) * 100);
    setPipelineStatus('running', 'Pipeline Running', `Alert ${i+1} of ${total}: ${alert.title||alert.alert_id}`, overallPct);

    // ═══════ DECISION BOT ═══════
    addLog('info', `[Decision Bot] ▶ Starting — Alert: ${alert.alert_id||'unknown'} (${sev})`);
    setBotStatus('decision', 'running', 0, 'Extracting indicators of compromise...');
    await sleep(600);

    setBotStatus('decision', 'running', 18, 'IOC extraction complete');
    const iocCount = rand(2, 7);
    addLog('info', `[Decision Bot] IOC extraction: ${iocCount} indicators found (IPs, hashes, domains)`);
    await sleep(500);

    setBotStatus('decision', 'running', 35, 'Running parallel enrichment (8 sources)...');
    addLog('info', '[Decision Bot] Enrichment started: VirusTotal, AbuseIPDB, OTX, URLhaus, ThreatFox, MalwareBazaar...');
    await sleep(300);
    addLog('info', `[Decision Bot] VirusTotal: malicious (score ${rand(72,96)}/100)`);
    await sleep(200);
    addLog('info', `[Decision Bot] AbuseIPDB: high-confidence abuse (confidence ${rand(80,97)}%)`);
    await sleep(200);
    addLog('info', `[Decision Bot] OTX: ${rand(0,1)?'3 pulses found':'timeout — skipped'}`);
    await sleep(200);
    addLog('info', '[Decision Bot] URLhaus: malicious URL confirmed');
    await sleep(200);
    addLog('info', '[Decision Bot] ThreatFox: C2 indicator match found');
    await sleep(300);

    setBotStatus('decision', 'running', 65, 'Enrichment complete. Generating LLM verdict...');
    addLog('info', '[Decision Bot] Sending to LLM for verdict generation...');
    await sleep(1200);

    const verdictLabel = sev === 'critical' ? 'MALICIOUS' : sev === 'high' ? 'MALICIOUS' : 'SUSPICIOUS';
    const confidence = rand(82, 97);
    const mitre = randFrom(['T1059.001, T1055, T1027','T1486, T1490, T1041','T1003, T1547, T1021']);
    const killChain = randFrom(['Actions on Objectives','Command & Control','Exploitation']);

    setBotStatus('decision', 'running', 90, `Verdict: ${verdictLabel} (${confidence}% confidence)`);
    addLog('info', `[Decision Bot] Verdict: ${verdictLabel} | Confidence: ${confidence}% | Kill Chain: ${killChain}`);
    addLog('info', `[Decision Bot] MITRE ATT&CK: ${mitre}`);
    await sleep(400);

    setBotStatus('decision', 'done', 100, `Done — ${verdictLabel}`);
    document.getElementById('bm-d-dur').textContent = `${(rand(30,55)/10).toFixed(1)}s`;
    document.getElementById('bm-d-ioc').textContent = iocCount;
    document.getElementById('bm-d-verdict').textContent = verdictLabel;
    addLog('success', `[Decision Bot] ✓ Complete in ${(rand(30,55)/10).toFixed(1)}s`);
    await sleep(400);

    activateConnector(1);
    await sleep(300);

    // ═══════ ANALYSIS BOT ═══════
    addLog('info', `[Analysis Bot] ▶ Starting forensic investigation on ${alert.endpoint_id||agentId}`);
    setBotStatus('analysis', 'running', 0, 'Planning forensic actions...');
    await sleep(500);

    const forensicActions = sev === 'critical'
      ? ['processes','network','persistence','auth_logs','file_inspect','yara_scan','memory_dump','binary_re','deep_memory']
      : ['processes','network','persistence','auth_logs','file_inspect','yara_scan'];
    addLog('info', `[Analysis Bot] Action plan (${sev} severity): ${forensicActions.join(', ')}`);
    setBotStatus('analysis', 'running', 15, `${forensicActions.length} forensic actions planned`);
    await sleep(400);

    setBotStatus('analysis', 'running', 28, `Dispatching job to ${agentId}...`);
    const jobId = `job-${Math.random().toString(36).slice(2,10)}`;
    addLog('info', `[Analysis Bot] Job dispatched — ID: ${jobId} | Agent: ${agentId}`);
    await sleep(600);

    setBotStatus('analysis', 'running', 42, 'Executing forensic collection on endpoint...');
    addLog('info', `[Analysis Bot] processes.run() → ${rand(130,200)} processes, ${rand(2,5)} flagged suspicious`);
    await sleep(500);
    addLog('info', `[Analysis Bot] network.run() → ${rand(8,20)} connections, ${rand(1,3)} to malicious IPs`);
    await sleep(400);
    addLog('info', `[Analysis Bot] persistence.run() → ${rand(0,2)} suspicious startup entries`);
    await sleep(400);
    addLog('info', '[Analysis Bot] yara_scan.run() → 1 match: ' + randFrom(['Ransom.WannaCry','Mimikatz.v2','CobaltStrike.Beacon','Generic.Trojan']));
    await sleep(400);

    if (sev === 'critical') {
      setBotStatus('analysis', 'running', 62, 'Running memory dump analysis...');
      addLog('warn', '[Analysis Bot] memory_dump.run() → Volatility 3 running (may take 60-120s in production)');
      await sleep(800);
      addLog('info', '[Analysis Bot] memory_dump.run() → Injected shellcode found at 0x7ffe1234, process hollowing detected');
    }

    setBotStatus('analysis', 'running', 80, 'Synthesizing findings with LLM...');
    addLog('info', '[Analysis Bot] Sending telemetry to LLM for synthesis...');
    await sleep(1200);

    const findingCount = rand(3, 7);
    const critCount = rand(1, 2);
    const overallSev = sev === 'critical' ? 'CRITICAL' : 'HIGH';
    const recActions = ['isolate_endpoint', 'block_ip', 'quarantine_file', 'disable_user'].slice(0, rand(2,4));
    addLog('info', `[Analysis Bot] ${findingCount} findings (${critCount} critical) | Overall: ${overallSev}`);
    addLog('info', `[Analysis Bot] Recommended actions: ${recActions.join(', ')}`);
    await sleep(400);

    setBotStatus('analysis', 'done', 100, `Done — ${findingCount} findings`);
    document.getElementById('bm-a-dur').textContent = `${(rand(55,110)/10).toFixed(1)}s`;
    document.getElementById('bm-a-findings').textContent = findingCount;
    document.getElementById('bm-a-sev').textContent = overallSev;
    addLog('success', `[Analysis Bot] ✓ Complete in ${(rand(55,110)/10).toFixed(1)}s`);
    await sleep(400);

    activateConnector(2);
    await sleep(300);

    // ═══════ ACTION BOT ═══════
    addLog('info', '[Action Bot] ▶ Starting remediation mapping...');
    setBotStatus('action', 'running', 0, 'Mapping recommendations to executable actions...');
    await sleep(500);

    const mappedActions = recActions.map(a => {
      const params = {
        block_ip: '185.220.101.45',
        quarantine_file: 'C:\\Users\\AppData\\Local\\Temp\\svchost32.exe',
        disable_user: alert.endpoint_id?.replace('ws-','') || 'alice',
      };
      return { name: a, param: params[a] || '' };
    });

    mappedActions.forEach(a => {
      const matched = Math.random() > 0.15;
      addLog('info', `[Action Bot] → ${a.name}(${a.param}) [${matched?'rules match':'LLM fallback'}]`);
    });

    setBotStatus('action', 'running', 30, 'Checking VIP gating...');
    await sleep(500);

    const isVip = Math.random() < 0.1;
    const vipStatus = isVip ? 'VIP — manual approval required' : 'Not VIP — proceeding';
    addLog(isVip ? 'warn' : 'info', `[Action Bot] VIP check: ${vipStatus}`);
    await sleep(300);

    if (mode === 'manual' || isVip) {
      setBotStatus('action', 'running', 45, 'Awaiting analyst approval...');
      addLog('warn', '[Action Bot] Manual mode — paused for analyst approval');
      await sleep(800);
      addLog('info', '[Action Bot] Approval received (simulated)');
    }

    setBotStatus('action', 'running', 60, 'Executing remediation on endpoint...');
    for (const a of mappedActions) {
      await sleep(rand(300, 600));
      addLog('success', `[Action Bot] ✓ ${a.name}${a.param?' ('+a.param+')':''} — executed successfully`);
    }

    setBotStatus('action', 'done', 100, `Done — ${mappedActions.length}/${mappedActions.length} actions`);
    document.getElementById('bm-x-dur').textContent = `${(rand(20,45)/10).toFixed(1)}s`;
    document.getElementById('bm-x-actions').textContent = `${mappedActions.length}/${mappedActions.length}`;
    document.getElementById('bm-x-vip').textContent = isVip ? 'YES' : 'N/A';
    addLog('success', `[Action Bot] ✓ Complete in ${(rand(20,45)/10).toFixed(1)}s`);

    addLog('success', `━━━ Pipeline complete for alert: ${alert.alert_id||'unknown'} ━━━`);

    if (i < alerts.length - 1) {
      await sleep(800);
      addLog('info', `Next alert in queue (${i+2}/${total})...`);
      await sleep(400);
    }
  }

  const pct100 = 100;
  setPipelineStatus('done', 'Pipeline Complete', `${total} alert${total>1?'s':''} processed successfully`, pct100);
  STATE.botRunning = false;
  document.getElementById('badge-bots').style.display = 'none';
  showToast('success', 'Pipeline Complete', `${total} alert${total>1?'s':''} processed through all 3 bots`);

  // Refresh runs
  STATE.runs = [
    { run_id:`run-${Date.now().toString(36)}`, alert_id: alerts[0]?.alert?.alert_id, agent_id:agentId, final_status:'done', is_vip:false, requires_approval:false, duration_seconds: rand(30,70), started_at: new Date(Date.now()-60000).toISOString(), finished_at: new Date().toISOString(), _severity: alerts[0]?.alert?.severity || 'high' },
    ...STATE.runs,
  ].slice(0, 20);
}

function _bm(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val ?? '--';
}

async function runRealPipeline(alerts, agentId, mode) {
  STATE.botRunning = true;
  setPipelineStatus('running', 'Pipeline Running', 'Sending requests to server...', 0);
  addLog('info', `Running ${alerts.length} alert(s) through server pipeline | Agent: ${agentId} | Mode: ${mode}`);

  // Reset all metrics
  ['bm-d-dur','bm-d-ioc','bm-d-verdict','bm-a-dur','bm-a-findings','bm-a-sev',
   'bm-x-dur','bm-x-actions','bm-x-vip'].forEach(id => _bm(id, '--'));

  let done = 0;
  for (const a of alerts) {
    const alertId = a.alert?.alert_id || '(unknown)';
    try {
      addLog('info', `[Pipeline] Starting alert: ${alertId} | Severity: ${a.alert?.severity || '?'}`);
      setBotStatus('decision', 'running', 10, 'Awaiting Gemini verdict...');
      setBotStatus('analysis', 'idle',    0,  'Waiting for verdict...');
      setBotStatus('action',   'idle',    0,  'Waiting for analysis...');

      const result = await API.post('/workflow/run', {
        alert: a.alert,
        agent_id: agentId,
        mode,
      });

      done++;

      // Index stages by name
      const stageMap = Object.fromEntries((result.stages || []).map(s => [s.name, s]));
      const decS = stageMap['decision']         || {};
      const anaS = stageMap['analysis']         || {};
      const apS  = stageMap['action_planning']  || {};
      const aeS  = stageMap['action_execution'] || {};

      // ── Decision Bot ─────────────────────────────────────────
      // Verdict schema: { label, confidence, reasoning, mitre_techniques,
      //                   kill_chain_phase, iocs, recommended_next_step }
      const v       = result.verdict || {};
      const vLabel  = v.label || '--';                     // field is "label", not "verdict"
      const vConf   = v.confidence ?? '--';
      const iocList = v.iocs || [];
      const decDur  = decS.duration_seconds != null ? `${decS.duration_seconds.toFixed(1)}s` : '--';

      if (decS.status === 'failed') {
        setBotStatus('decision', 'error', 100, decS.error || 'Error');
        addLog('error', `[Decision Bot] FAILED: ${decS.error}`);
      } else {
        setBotStatus('decision', 'done', 100, `${vLabel} (${vConf}%)`);
        addLog('info',  `[Decision Bot] Verdict: ${vLabel.toUpperCase()} | Confidence: ${vConf}% | IOCs found: ${iocList.length}`);
        if (v.kill_chain_phase) addLog('info', `[Decision Bot] Kill chain: ${v.kill_chain_phase}`);
        if (v.mitre_techniques?.length) addLog('info', `[Decision Bot] MITRE ATT&CK: ${v.mitre_techniques.join(', ')}`);
        if (v.reasoning) addLog('info', `[Decision Bot] Reasoning: ${v.reasoning}`);
        if (iocList.length) addLog('warn', `[Decision Bot] IOCs: ${iocList.map(i => `${i.type}:${i.value}`).join(' | ')}`);
      }
      _bm('bm-d-dur',     decDur);
      _bm('bm-d-ioc',     iocList.length || (decS.status === 'done' ? 0 : '--'));
      _bm('bm-d-verdict', v.label ? `${vLabel} ${vConf}%` : '--');

      // ── Analysis Bot ─────────────────────────────────────────
      // Report schema: { findings, overall_severity, summary, recommended_actions }
      const rep      = result.report || {};
      const findings = rep.findings  || [];
      const severity = rep.overall_severity || '--';
      const anaDur   = anaS.duration_seconds != null ? `${anaS.duration_seconds.toFixed(1)}s` : '--';

      if (anaS.status === 'failed') {
        setBotStatus('analysis', 'error', 100, anaS.error || 'Error');
        addLog('error', `[Analysis Bot] FAILED: ${anaS.error}`);
      } else if (anaS.status === 'done') {
        setBotStatus('analysis', 'done', 100, `${findings.length} findings — ${severity}`);
        addLog('info',  `[Analysis Bot] ${findings.length} finding(s) | Overall severity: ${severity.toUpperCase()}`);
        if (rep.summary) addLog('info', `[Analysis Bot] ${rep.summary}`);
        findings.forEach((f, i) => {
          const lvl = (f.severity === 'critical' || f.severity === 'high') ? 'error' : 'warn';
          addLog(lvl, `[Finding ${i+1}] [${f.severity?.toUpperCase()}] ${f.title} — ${(f.evidence || '').slice(0, 120)}`);
          if (f.mitre_techniques?.length) addLog('info', `  └ MITRE: ${f.mitre_techniques.join(', ')}`);
        });
        if (rep.recommended_actions?.length) {
          addLog('info', `[Analysis Bot] ${rep.recommended_actions.length} recommended action(s):`);
          rep.recommended_actions.forEach(ra => addLog('info', `  → ${ra}`));
        } else {
          addLog('warn', '[Analysis Bot] No recommended actions produced — Action Bot will skip execution');
        }
      }
      _bm('bm-a-dur',      anaDur);
      _bm('bm-a-findings', findings.length ?? '--');
      _bm('bm-a-sev',      severity);

      // ── Action Bot ───────────────────────────────────────────
      const requiresApproval = result.requires_approval || false;
      const isVip            = result.is_vip || false;
      const actionPlan       = result.action_plan || [];
      const actionResult     = result.action_result || {};
      const executed         = actionResult.executed || [];
      const actResults       = actionResult.results  || [];
      const actDur           = aeS.duration_seconds != null ? `${aeS.duration_seconds.toFixed(1)}s`
                             : apS.duration_seconds != null ? `${apS.duration_seconds.toFixed(1)}s` : '--';
      const vipGate          = requiresApproval ? 'PENDING' : (isVip ? 'VIP / OK' : 'N/A');

      if (requiresApproval) {
        setBotStatus('action', 'idle', 50, 'Awaiting approval (VIP endpoint)');
        addLog('warn', `[Action Bot] VIP gate triggered — ${result.approval_reason || 'manual approval required'}`);
        addLog('warn', `[Action Bot] ${actionPlan.length} action(s) planned but NOT executed — requires analyst approval`);
        actionPlan.forEach(ap => addLog('info', `  → ${ap.name}(${JSON.stringify(ap.params)}) — ${ap.reason}`));
        _bm('bm-x-actions', `${actionPlan.length} planned`);
      } else if (aeS.status === 'skipped' || (!executed.length && !actionPlan.length)) {
        setBotStatus('action', 'idle', 100, 'No actions to execute');
        addLog('warn', `[Action Bot] Skipped — no mapped actions from analysis recommendations`);
        _bm('bm-x-actions', '0');
      } else if (aeS.status === 'failed') {
        setBotStatus('action', 'error', 100, aeS.error || 'Error');
        addLog('error', `[Action Bot] FAILED: ${aeS.error}`);
        _bm('bm-x-actions', '--');
      } else {
        setBotStatus('action', 'done', 100, `${executed.length} action(s) executed`);
        addLog('info', `[Action Bot] Executed ${executed.length} action(s):`);
        actResults.forEach(r => {
          const lvl = r.success ? 'success' : 'error';
          addLog(lvl, `  [${r.success ? 'OK' : 'FAIL'}] ${r.action}(${JSON.stringify(executed.find(e=>e.name===r.action)?.params||{})}) — ${r.duration_seconds}s`);
          if (!r.success && r.error) addLog('error', `    Error: ${r.error}`);
        });
        _bm('bm-x-actions', executed.length);
      }
      _bm('bm-x-dur', actDur);
      _bm('bm-x-vip', vipGate);

      // Extract IOCs + MITRE + kill chain into Threat Intel state
      const newIOCs = extractIOCsFromResult(result);
      const mitreHits = harvestMitreFromResult(result);
      const kcPhase = normalizeKillChainPhase(result.verdict?.kill_chain_phase);
      if (newIOCs.length || Object.keys(mitreHits).length || kcPhase) {
        const existingVals = new Set(STATE.iocs.map(i => i.value));
        newIOCs.forEach(ioc => {
          if (!existingVals.has(ioc.value)) { STATE.iocs.push(ioc); existingVals.add(ioc.value); }
        });
        Object.entries(mitreHits).forEach(([t, c]) => {
          STATE.mitreCounts[t] = (STATE.mitreCounts[t] || 0) + c;
        });
        if (kcPhase) STATE.killChainCounts[kcPhase] = (STATE.killChainCounts[kcPhase] || 0) + 1;
        if (newIOCs.length) addLog('info', `[Threat Intel] ${newIOCs.length} IOC(s) added — ${STATE.iocs.length} total`);
        if (Object.keys(mitreHits).length) addLog('info', `[Threat Intel] MITRE techniques: ${Object.keys(mitreHits).join(', ')}`);
        if (STATE.tab === 'threats') renderThreatIntel();
      }

      const overallPct = Math.round((done / alerts.length) * 100);
      setPipelineStatus('running', 'Pipeline Running', `${done}/${alerts.length} complete`, overallPct);
      addLog('success', `[Pipeline] Done: ${result.run_id} | Status: ${result.final_status} | Duration: ${result.duration_seconds?.toFixed(1)}s`);

    } catch (e) {
      addLog('error', `[Pipeline] FAILED for ${alertId}: ${e.message}`);
      ['decision','analysis','action'].forEach(b => setBotStatus(b, 'error', 0, 'Error'));
    }
  }

  STATE.botRunning = false;
  setPipelineStatus('done', 'Pipeline Complete', `${done} of ${alerts.length} alerts processed`, 100);
  showToast('success', 'Pipeline Complete', `${done}/${alerts.length} processed`);
  refreshIncidents();
}

// ── PDF Download ─────────────────────────────────────
async function downloadPDF(runId) {
  try {
    showToast('info', 'Downloading PDF...', runId);
    const resp = await fetch(`${CFG.apiBase}/workflow/runs/${encodeURIComponent(runId)}/report.pdf`, {
      headers: { 'Authorization': `Bearer ${CFG.authToken}` },
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${runId}.pdf`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch (e) {
    showToast('error', 'PDF Download Failed', e.message);
  }
}

// ── Action Approval Modal ─────────────────────────────
async function approveRun(runId) {
  try {
    const r = await API.get(`/workflow/runs/${encodeURIComponent(runId)}`);
    const result = r.result || {};
    const actionPlan = result.action_plan || [];

    document.getElementById('approve-run-info').innerHTML = `
      <div class="approve-meta">
        <span class="approve-meta-item"><i class="fas fa-hashtag"></i> ${escapeHtml(runId)}</span>
        <span class="approve-meta-item"><i class="fas fa-bell"></i> ${escapeHtml(result.alert_id || '--')}</span>
        <span class="approve-meta-item"><i class="fas fa-server"></i> ${escapeHtml(r.agent_id || result.original_agent_id || '--')}</span>
      </div>
      <div class="approve-warning"><i class="fas fa-triangle-exclamation"></i> Review each action carefully. Destructive actions cannot be undone.</div>`;

    if (!actionPlan.length) {
      document.getElementById('approve-actions-list').innerHTML =
        `<div class="empty-state"><i class="fas fa-info-circle"></i><p>No planned actions found for this run.</p></div>`;
    } else {
      document.getElementById('approve-actions-list').innerHTML = actionPlan.map((a, i) => {
        const isDestructive = !!a.destructive;
        const paramsStr = JSON.stringify(a.params || {}, null, 2);
        return `
        <div class="approve-action-item${isDestructive ? ' destructive' : ''}">
          <label class="approve-action-check">
            <input type="checkbox" class="approve-chk" data-idx="${i}" checked>
            <span class="approve-action-name">
              <i class="fas fa-${isDestructive ? 'triangle-exclamation' : 'cog'}"></i>
              ${escapeHtml(a.name)}
              ${isDestructive ? '<span class="destructive-badge">DESTRUCTIVE</span>' : ''}
            </span>
          </label>
          <div class="approve-action-reason">${escapeHtml(a.reason || '')}</div>
          <div class="approve-action-params">
            <label class="approve-param-label">Parameters (JSON — edit before executing):</label>
            <textarea class="approve-param-input" data-idx="${i}" rows="2">${escapeHtml(paramsStr)}</textarea>
          </div>
        </div>`;
      }).join('');
    }

    STATE._approveRunId = runId;
    STATE._approveRunData = r;
    openModal('modal-approve');
  } catch (e) {
    showToast('error', 'Failed to load run', e.message);
  }
}

async function submitApproval() {
  const runId = STATE._approveRunId;
  const result = STATE._approveRunData?.result || {};
  const actionPlan = result.action_plan || [];

  const approved = [];
  document.querySelectorAll('.approve-chk').forEach(chk => {
    if (!chk.checked) return;
    const idx = parseInt(chk.dataset.idx);
    const action = { ...actionPlan[idx] };
    const paramInput = document.querySelector(`.approve-param-input[data-idx="${idx}"]`);
    if (paramInput) {
      try { action.params = JSON.parse(paramInput.value); } catch { /* keep original */ }
    }
    approved.push(action);
  });

  if (!approved.length) {
    showToast('warn', 'No Actions Selected', 'Check at least one action to execute');
    return;
  }

  closeModal('modal-approve');
  showToast('info', 'Executing Actions...', `${approved.length} action(s) approved`);
  addLog('info', `[Approval] Submitting ${approved.length} approved action(s) for ${runId}`);
  approved.forEach(a => addLog('info', `  → ${a.name}(${JSON.stringify(a.params || {})}) — ${a.reason || ''}`));

  try {
    const res = await API.post(`/workflow/runs/${encodeURIComponent(runId)}/approve`, {
      approved_actions: approved,
    });
    const execResult = res.exec_result || {};
    const results = execResult.results || [];
    const ok   = results.filter(r => r.success).length;
    const fail = results.length - ok;

    addLog('success', `[Approval] Execution complete — ${ok} succeeded, ${fail} failed`);
    results.forEach(r => {
      addLog(r.success ? 'success' : 'error',
        `  [${r.success ? 'OK' : 'FAIL'}] ${r.action} — ${r.duration_seconds?.toFixed(1) ?? '?'}s${r.error ? ': ' + r.error : ''}`);
    });
    showToast('success', 'Actions Executed', `${ok} succeeded${fail ? `, ${fail} failed` : ''}`);
    refreshIncidents();
  } catch (e) {
    showToast('error', 'Execution Failed', e.message);
    addLog('error', `[Approval] Execution failed: ${e.message}`);
  }
}

// ── IOC + MITRE Extraction from Pipeline Results ─────
function extractIOCsFromResult(result) {
  const iocs = [];
  const rawIocs = result.verdict?.iocs || [];
  const now = new Date().toISOString();

  // Build enrichment lookup keyed by ioc_value.
  // verdict.enrichment is list[EnrichmentResult]: {source, ioc_value, ioc_type,
  //   success, malicious_score, reputation, tags, summary}
  // IOC objects only have {type, value, context} — no score/source embedded.
  const enrichMap = {};
  (result.verdict?.enrichment || []).forEach(e => {
    if (!e.ioc_value || !e.success) return;
    if (!enrichMap[e.ioc_value]) enrichMap[e.ioc_value] = { scores: [], sources: [], tags: [], reputation: null };
    if (typeof e.malicious_score === 'number') enrichMap[e.ioc_value].scores.push(e.malicious_score);
    if (e.source) enrichMap[e.ioc_value].sources.push(e.source);
    if (e.tags?.length) enrichMap[e.ioc_value].tags.push(...e.tags);
    if (e.reputation && !enrichMap[e.ioc_value].reputation) enrichMap[e.ioc_value].reputation = e.reputation;
  });

  rawIocs.forEach(ioc => {
    const iocValue = ioc.value || ioc.ioc_value;
    const iocType  = ioc.type  || ioc.ioc_type;
    if (!iocValue) return;

    const ed      = enrichMap[iocValue] || {};
    const scores  = ed.scores || [];
    const score   = scores.length ? Math.round(Math.max(...scores)) : 0;
    const sources = [...new Set(ed.sources || [])];
    const tags    = [...new Set(ed.tags || [])];
    if (score > 90 && !tags.includes('critical'))  tags.unshift('critical');
    if (score > 70 && !tags.includes('high-risk')) tags.unshift('high-risk');

    iocs.push({
      type:            iocType || 'unknown',
      value:           iocValue,
      sources:         sources.length ? sources : ['pipeline'],
      malicious_score: score,
      reputation:      ed.reputation || null,
      tags,
      context:         ioc.context || null,
      first_seen:      now,
    });
  });
  return iocs;
}

function harvestMitreFromResult(result) {
  const hits = {};
  const addTech = (t) => { if (t) hits[t] = (hits[t] || 0) + 1; };
  (result.verdict?.mitre_techniques || []).forEach(addTech);
  (result.report?.findings || []).forEach(f => (f.mitre_techniques || []).forEach(addTech));
  return hits;
}

async function loadRealThreatIntel(forceReload = false) {
  if (CFG.demoMode || !STATE.runs.length) return;
  if (forceReload) {
    STATE.iocs = [];
    STATE.mitreCounts = {};
    STATE.killChainCounts = {};
    STATE.threatIntelCleared = false;
  }
  if (STATE.threatIntelCleared) return;
  const toFetch = STATE.runs.slice(0, 25);
  const details = await Promise.all(
    toFetch.map(r => API.get(`/workflow/runs/${encodeURIComponent(r.run_id)}`).catch(() => null))
  );
  const existingVals = new Set(STATE.iocs.map(i => i.value));
  let newCount = 0;
  details.forEach(d => {
    if (!d) return;
    const res = d.result || {};
    extractIOCsFromResult(res).forEach(ioc => {
      if (!existingVals.has(ioc.value)) {
        STATE.iocs.push(ioc);
        existingVals.add(ioc.value);
        newCount++;
      }
    });
    const hits = harvestMitreFromResult(res);
    Object.entries(hits).forEach(([t, c]) => {
      STATE.mitreCounts[t] = (STATE.mitreCounts[t] || 0) + c;
    });
    // Harvest kill chain phase
    const phase = normalizeKillChainPhase(res.verdict?.kill_chain_phase);
    if (phase) STATE.killChainCounts[phase] = (STATE.killChainCounts[phase] || 0) + 1;
  });
  if (newCount > 0) addLog('info', `[Threat Intel] Loaded ${STATE.iocs.length} IOC(s) from ${details.filter(Boolean).length} run(s)`);
  if (STATE.tab === 'threats') renderThreatIntel();
}

function clearThreatIntel() {
  STATE.iocs = [];
  STATE.mitreCounts = {};
  STATE.killChainCounts = {};
  STATE.threatIntelCleared = true;
  renderThreatIntel();
  addLog('info', '[Threat Intel] Data cleared from view');
  showToast('info', 'Cleared', 'Threat intel data cleared. Use Refresh to reload.');
}

// ── Threat Intel Tab ─────────────────────────────────
function renderThreatIntel() {
  renderIOCSummary();
  renderEnrichmentSources();
  renderMitreHeatmap();
  renderIOCTable();
  renderIOCTypesChart();
}

function renderIOCSummary() {
  const types = [
    { type:'ip',         icon:'🌐', label:'IP Addresses',  color:'#00d4ff' },
    { type:'domain',     icon:'🔗', label:'Domains',       color:'#9b59ff' },
    { type:'sha256',     icon:'#️⃣', label:'File Hashes',   color:'#ff8800' },
    { type:'url',        icon:'📎', label:'URLs',          color:'#ff3355' },
    { type:'file_path',  icon:'📄', label:'File Paths',    color:'#ffd600' },
    { type:'md5',        icon:'🔒', label:'MD5 Hashes',    color:'#00ff88' },
  ];
  const iocs = CFG.demoMode ? DEMO.iocs : STATE.iocs;
  const grid = document.getElementById('ioc-summary-grid');
  grid.innerHTML = types.map(t => {
    const matching = iocs.filter(i => i.type === t.type);
    const count = matching.length;
    const avgScore = count > 0
      ? Math.round(matching.reduce((s, i) => s + (i.malicious_score || 0), 0) / count)
      : 0;
    const scoreColor = avgScore > 70 ? '#ff3355' : avgScore > 50 ? '#ff8800' : '#00ff88';
    const scoreLabel = count > 0 ? `${avgScore}% malicious` : 'no data';
    return `
    <div class="ioc-type-card">
      <div class="ioc-type-icon">${t.icon}</div>
      <div class="ioc-type-count" style="color:${t.color}">${count}</div>
      <div class="ioc-type-label">${t.label}</div>
      <div class="ioc-type-score" style="color:${count > 0 ? scoreColor : 'var(--text-3)'}">${scoreLabel}</div>
    </div>`;
  }).join('');
}

function renderEnrichmentSources() {
  const sourceDefs = [
    { name:'VirusTotal',     key:'virustotal',    icon:'🦠', color:'#ff3355' },
    { name:'AbuseIPDB',      key:'abuseipdb',     icon:'🛡', color:'#ff8800' },
    { name:'OTX AlienVault', key:'otx',           icon:'👽', color:'#9b59ff' },
    { name:'URLhaus',        key:'urlhaus',        icon:'🔗', color:'#00d4ff' },
    { name:'ThreatFox',      key:'threatfox',      icon:'🦊', color:'#ffd600' },
    { name:'MalwareBazaar',  key:'malwarebazaar',  icon:'💀', color:'#ff3355' },
    { name:'GreyNoise',      key:'greynoise',      icon:'🔊', color:'#00ff88' },
    { name:'Shodan',         key:'shodan',         icon:'📡', color:'#00d4ff' },
  ];
  const enrichers = STATE.stats?.enrichers || DEMO.stats.enrichers;

  // Count IOCs that list each source (real data). In demo mode use DEMO.iocs for counts.
  const iocs = CFG.demoMode ? DEMO.iocs : STATE.iocs;
  const srcCounts = {};
  iocs.forEach(ioc => (ioc.sources || []).forEach(s => { srcCounts[s] = (srcCounts[s] || 0) + 1; }));

  // In demo mode fall back to plausible demo query counts when IOC source counts are very low
  const demoCounts = { virustotal:612, abuseipdb:431, otx:374, urlhaus:284, threatfox:252, malwarebazaar:198 };

  const sources = sourceDefs.map(s => ({
    ...s,
    queries: CFG.demoMode
      ? (srcCounts[s.key] || demoCounts[s.key] || 0)
      : (srcCounts[s.key] || 0),
  }));

  const maxQ = Math.max(...sources.map(s => s.queries), 1);
  const grid = document.getElementById('enrichment-source-grid');
  grid.innerHTML = sources.map(s => {
    const active = enrichers[s.key] !== false;
    const pct = active && s.queries ? Math.round((s.queries / maxQ) * 100) : 0;
    const countLabel = s.queries ? s.queries : (active ? '0 IOCs' : '--');
    return `
    <div class="enrich-src-card">
      <div class="enrich-src-header">
        <div class="enrich-src-icon" style="background:${s.color}22;color:${s.color}">${s.icon}</div>
        <div class="enrich-src-name">${escapeHtml(s.name)}</div>
        <div class="enrich-src-status"><span class="status-chip ${active?'status-done':'status-dismissed'}">${active?'Active':'Off'}</span></div>
      </div>
      <div class="enrich-src-bar-wrap">
        <div class="enrich-src-bar"><div class="enrich-src-fill" style="width:${pct}%;background:${s.color}"></div></div>
        <span class="enrich-src-pct">${countLabel}</span>
      </div>
    </div>`;
  }).join('');
}

const MITRE_NAMES = {
  'T1059':'Cmd & Scripting','T1059.001':'PowerShell','T1059.003':'Windows Cmd','T1059.007':'JavaScript',
  'T1055':'Proc Inject','T1027':'Obfuscation','T1003':'Cred Dump',
  'T1547':'Boot Persist','T1547.001':'Registry Run','T1071':'App Layer Protocol','T1071.001':'Web C2',
  'T1486':'Encryption','T1021':'Remote Svc','T1021.001':'RDP',
  'T1190':'Exploit PubApp','T1078':'Valid Accts','T1098':'Account Manip',
  'T1562':'Disable Def','T1562.001':'Disable AV','T1112':'Mod Registry','T1041':'Exfil C2',
  'T1566':'Phishing','T1566.001':'Spearphish','T1136':'Create Acct',
  'T1070':'Ind Removal','T1543':'Create/Modify Svc','T1053':'Sched Task',
  'T1218':'Signed Bin Proxy','T1036':'Masquerading','T1105':'Ingress Tool',
  'T1082':'System Info Disc','T1057':'Process Disc',
};

const DEMO_MITRE = [
  { id:'T1059.001', name:'PowerShell', count:47 }, { id:'T1055', name:'Proc Inject', count:34 },
  { id:'T1027', name:'Obfuscation', count:29 }, { id:'T1003', name:'Cred Dump', count:24 },
  { id:'T1547', name:'Boot Persist', count:21 }, { id:'T1071.001', name:'Web C2', count:19 },
  { id:'T1486', name:'Encryption', count:16 }, { id:'T1021', name:'Remote Svc', count:14 },
  { id:'T1190', name:'Exploit PubApp', count:12 }, { id:'T1078', name:'Valid Accts', count:11 },
  { id:'T1562', name:'Disable Def', count:10 }, { id:'T1112', name:'Mod Registry', count:9 },
  { id:'T1041', name:'Exfil C2', count:8 }, { id:'T1566', name:'Phishing', count:8 },
  { id:'T1136', name:'Create Acct', count:7 }, { id:'T1070', name:'Ind Removal', count:6 },
];

function renderMitreHeatmap() {
  const heatmap = document.getElementById('mitre-heatmap');
  const realCounts = STATE.mitreCounts || {};
  const hasReal = !CFG.demoMode && Object.keys(realCounts).length > 0;

  let techniques;
  if (hasReal) {
    techniques = Object.entries(realCounts)
      .map(([id, count]) => ({ id, name: MITRE_NAMES[id] || id, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 16);
  } else if (CFG.demoMode) {
    techniques = DEMO_MITRE;
  } else {
    heatmap.innerHTML = `<div class="empty-state" style="padding:20px"><i class="fas fa-crosshairs" style="font-size:24px;color:var(--text-3)"></i><p style="color:var(--text-3);font-size:12px;margin-top:8px">No MITRE data yet — run a pipeline to populate</p></div>`;
    return;
  }

  const maxCount = Math.max(...techniques.map(t => t.count), 1);
  heatmap.innerHTML = techniques.map(t => {
    const intensity = t.count / maxCount;
    const r = Math.round(255 * intensity);
    const g = Math.round(51 + 80 * (1 - intensity));
    const color = `rgba(${r},${g},85,${0.3 + intensity * 0.5})`;
    return `
    <div class="mitre-cell" style="border-color:rgba(${r},${g},85,0.4)" title="${t.id}: ${t.name} — ${t.count} hit${t.count !== 1 ? 's' : ''}">
      <div class="mitre-cell-id" style="color:rgba(${r},${g},85,1)">${escapeHtml(t.id)}</div>
      <div class="mitre-cell-name">${escapeHtml(t.name)}</div>
    </div>`;
  }).join('');
}

function renderIOCTable() {
  const typeFilter = document.getElementById('ioc-filter')?.value || '';
  let iocs = CFG.demoMode ? DEMO.iocs : STATE.iocs;
  if (typeFilter) iocs = iocs.filter(i => i.type === typeFilter);

  const typeColors = { ip:'#00d4ff', domain:'#9b59ff', sha256:'#ff8800', url:'#ff3355', md5:'#ffd600', file_path:'#00ff88', email:'#ff8800' };

  const tbody = document.getElementById('ioc-tbody');
  if (!iocs.length) {
    const msg = typeFilter
      ? 'No IOCs of this type found'
      : CFG.demoMode ? 'No IOCs found' : 'No IOCs yet — run a pipeline to populate threat intel';
    tbody.innerHTML = `<tr><td colspan="6"><div class="empty-state"><i class="fas fa-shield-halved"></i><p>${msg}</p></div></td></tr>`;
    return;
  }
  tbody.innerHTML = iocs.map(i => {
    const color = typeColors[i.type] || '#7a8db0';
    const score = i.malicious_score || 0;
    const scoreColor = score > 70 ? '#ff3355' : score > 50 ? '#ff8800' : '#00ff88';
    return `
    <tr>
      <td><span class="ioc-type-badge" style="background:${color}22;color:${color};border:1px solid ${color}44">${escapeHtml(i.type)}</span></td>
      <td><span class="mono" style="font-size:11px;color:var(--text-1)">${escapeHtml(i.value.length > 50 ? i.value.slice(0,50)+'…' : i.value)}</span></td>
      <td><div style="display:flex;flex-wrap:wrap;gap:3px">${(i.sources||[]).map(s=>`<span class="tag-pill">${escapeHtml(s)}</span>`).join('')}</div></td>
      <td>
        <div class="score-bar-wrap">
          <div class="score-bar"><div class="score-fill" style="width:${score}%;background:${scoreColor}"></div></div>
          <span class="score-num" style="color:${scoreColor}">${score}</span>
        </div>
      </td>
      <td><div style="display:flex;flex-wrap:wrap;gap:3px">${(i.tags||[]).map(t=>`<span class="tag-pill">${escapeHtml(t)}</span>`).join('')}</div></td>
      <td style="color:var(--text-3);font-size:11px;white-space:nowrap">${fmtTime(i.first_seen)}</td>
    </tr>`;
  }).join('');
}

function renderIOCTypesChart() {
  const iocs = CFG.demoMode ? DEMO.iocs : STATE.iocs;
  const types = ['ip','domain','sha256','md5','url','file_path'];
  const labels = ['IP Address','Domain','SHA-256','MD5','URL','File Path'];
  const counts = types.map(t => iocs.filter(i => i.type === t).length);
  const colors = ['#00d4ff','#9b59ff','#ff8800','#ffd600','#ff3355','#00ff88'];
  makeChart('chart-ioc-types', {
    type:'doughnut',
    data:{ labels, datasets:[{ data:counts, backgroundColor:colors.map(c=>c+'cc'), borderColor:colors, borderWidth:1, hoverOffset:4 }] },
    options:{
      responsive:true, maintainAspectRatio:false, cutout:'60%',
      plugins:{ legend:{ position:'right', labels:{ color:'#7a8db0', font:{size:10}, boxWidth:10 } },
                tooltip:{ backgroundColor:'#111829', borderColor:'rgba(0,212,255,0.2)', borderWidth:1, titleColor:'#e8eef8', bodyColor:'#7a8db0' } },
    }
  });
}

// ── Endpoints Tab ────────────────────────────────────
function renderEndpoints() {
  const agents = STATE.agents || DEMO.agents;
  const online = agents.filter(a=>a.online).length;
  const offline = agents.length - online;
  document.getElementById('ep-total').textContent = agents.length;
  document.getElementById('ep-online').textContent = online;
  document.getElementById('ep-offline').textContent = offline;

  const grid = document.getElementById('agents-grid');
  if (!agents.length) {
    grid.innerHTML = `<div class="empty-state"><i class="fas fa-server"></i><p>No agents registered</p></div>`;
    return;
  }
  grid.innerHTML = agents.map(a => {
    const caps = (a.capabilities || []).slice(0, 6);
    const moreCaps = Math.max(0, (a.capabilities||[]).length - 6);
    const osIcon = a.os === 'Windows' ? '🪟' : a.os === 'Linux' ? '🐧' : '🍎';
    return `
    <div class="agent-card ${a.online?'online':'offline'}">
      <div class="agent-header">
        <div class="agent-status-dot ${a.online?'online':'offline'}"></div>
        <div style="flex:1">
          <div class="agent-hostname">${escapeHtml(a.hostname)}</div>
          <div class="agent-id-text">${escapeHtml(a.agent_id)}</div>
        </div>
        <span class="status-chip ${a.online?'status-done':'status-dismissed'}">${a.online?'Online':'Offline'}</span>
      </div>
      <div class="agent-meta">
        <span class="agent-meta-tag">${osIcon} ${escapeHtml(a.os)} ${escapeHtml(a.os_version||'')}</span>
        <span class="agent-meta-tag">v${escapeHtml(a.agent_version||'0.1.0')}</span>
      </div>
      <div class="agent-caps">
        ${caps.map(c=>`<span class="cap-badge">${escapeHtml(c)}</span>`).join('')}
        ${moreCaps > 0 ? `<span class="cap-badge">+${moreCaps} more</span>` : ''}
      </div>
      <div class="agent-footer">
        <span class="agent-last-seen">Last seen: ${fmtTime(a.last_seen_at)}</span>
        <button class="tbl-btn run" onclick="runSingleAlert('_'); document.getElementById('run-agent').value='${escapeHtml(a.agent_id)}'"><i class="fas fa-play"></i> Run</button>
      </div>
    </div>`;
  }).join('');
}

// ── Incidents Tab ────────────────────────────────────
function renderIncidents() {
  const statusFilter = document.getElementById('filter-run-status')?.value || '';
  let runs = STATE.runs || DEMO.runs;
  if (statusFilter) runs = runs.filter(r => r.final_status === statusFilter);

  const tbody = document.getElementById('incidents-tbody');
  if (!runs.length) {
    tbody.innerHTML = `<tr><td colspan="9"><div class="empty-state"><i class="fas fa-file-contract"></i><p>No pipeline runs found</p></div></td></tr>`;
    return;
  }
  tbody.innerHTML = runs.map(r => {
    const sev = r._severity || r.sev || 'unknown';
    const statusCls = { done:'status-done', failed:'status-failed', running:'status-running', requires_approval:'status-new' }[r.final_status] || 'status-new';
    return `
    <tr>
      <td><span class="mono" style="font-size:11px;color:var(--c-cyan)">${escapeHtml((r.run_id||'').slice(0,14))}</span></td>
      <td><span class="mono" style="font-size:11px">${escapeHtml((r.alert_id||'--').slice(0,22))}</span></td>
      <td><span class="mono" style="font-size:11px;color:var(--text-2)">${escapeHtml(r.agent_id||'--')}</span></td>
      <td><span class="status-chip ${statusCls}">${(r.final_status||'unknown').replace('_',' ')}</span></td>
      <td><span class="sev-badge sev-${sev}">${sev}</span></td>
      <td style="color:var(--text-2);font-family:var(--mono);font-size:12px">${fmtDuration(r.duration_seconds)}</td>
      <td style="color:var(--text-3);font-size:12px;white-space:nowrap">${fmtTime(r.started_at)}</td>
      <td>${r.is_vip ? '<span class="vip-badge"><i class="fas fa-user-shield"></i> VIP</span>' : '<span style="color:var(--text-3);font-size:11px">—</span>'}</td>
      <td>
        <div class="tbl-actions">
          ${r.pdf_path ? `<button class="tbl-btn" title="Download PDF" onclick="downloadPDF('${r.run_id}')"><i class="fas fa-file-pdf"></i></button>` : ''}
          ${r.requires_approval ? `<button class="tbl-btn run" title="Approve &amp; Execute" onclick="approveRun('${r.run_id}')"><i class="fas fa-check"></i> Approve</button>` : ''}
        </div>
      </td>
    </tr>`;
  }).join('');
}

// ── Settings ─────────────────────────────────────────
function loadSettingsUI() {
  document.getElementById('cfg-api').value   = CFG.apiBase;
  document.getElementById('cfg-token').value = CFG.authToken;
  document.getElementById('cfg-demo').checked    = CFG.demoMode;
  document.getElementById('cfg-refresh').checked = CFG.autoRefresh;
}

function saveSettings() {
  CFG.apiBase     = document.getElementById('cfg-api').value.trim();
  CFG.authToken   = document.getElementById('cfg-token').value.trim();
  CFG.demoMode    = document.getElementById('cfg-demo').checked;
  CFG.autoRefresh = document.getElementById('cfg-refresh').checked;
  localStorage.setItem('soc_api', CFG.apiBase);
  localStorage.setItem('soc_token', CFG.authToken);
  localStorage.setItem('soc_demo', CFG.demoMode);
  localStorage.setItem('soc_refresh', CFG.autoRefresh);
  closeModal('modal-settings');
  showToast('success','Settings Saved','Reconnecting...');
  initialize();
}

// ── Auto Refresh ─────────────────────────────────────
function startAutoRefresh() {
  if (STATE.refreshTimer) clearInterval(STATE.refreshTimer);
  if (!CFG.autoRefresh) return;
  STATE.refreshTimer = setInterval(() => {
    if (!STATE.botRunning) {
      loadAll().then(() => {
        renderOverview();
        renderAlertTable();
        renderEndpoints();
        renderIncidents();
      });
    }
  }, 5000);
}

// ── Background Canvas ────────────────────────────────
function initBackground() {
  const canvas = document.getElementById('bg-canvas');
  const ctx = canvas.getContext('2d');
  canvas.width = window.innerWidth;
  canvas.height = window.innerHeight;
  window.addEventListener('resize', () => {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  });

  const dots = Array.from({length: 80}, () => ({
    x: Math.random() * canvas.width,
    y: Math.random() * canvas.height,
    r: Math.random() * 1.5 + 0.3,
    vx: (Math.random() - 0.5) * 0.3,
    vy: (Math.random() - 0.5) * 0.3,
    opacity: Math.random() * 0.4 + 0.1,
  }));

  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    dots.forEach(d => {
      d.x += d.vx; d.y += d.vy;
      if (d.x < 0 || d.x > canvas.width) d.vx *= -1;
      if (d.y < 0 || d.y > canvas.height) d.vy *= -1;
      ctx.beginPath();
      ctx.arc(d.x, d.y, d.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(0,212,255,${d.opacity})`;
      ctx.fill();
    });
    // Draw lines between nearby dots
    for (let i = 0; i < dots.length; i++) {
      for (let j = i+1; j < dots.length; j++) {
        const dx = dots[i].x - dots[j].x;
        const dy = dots[i].y - dots[j].y;
        const dist = Math.sqrt(dx*dx+dy*dy);
        if (dist < 120) {
          ctx.beginPath();
          ctx.moveTo(dots[i].x, dots[i].y);
          ctx.lineTo(dots[j].x, dots[j].y);
          ctx.strokeStyle = `rgba(0,212,255,${0.06*(1-dist/120)})`;
          ctx.lineWidth = 0.5;
          ctx.stroke();
        }
      }
    }
    requestAnimationFrame(draw);
  }
  draw();
}

// ── Clock ────────────────────────────────────────────
function startClock() {
  const el = document.getElementById('header-clock');
  setInterval(() => {
    el.textContent = new Date().toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false});
  }, 1000);
  el.textContent = new Date().toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false});
}

// ── Event Listeners ───────────────────────────────────
document.getElementById('alert-search')?.addEventListener('input', renderAlertTable);
document.getElementById('filter-severity')?.addEventListener('change', renderAlertTable);
document.getElementById('filter-status')?.addEventListener('change', renderAlertTable);
document.getElementById('ioc-filter')?.addEventListener('change', renderIOCTable);

// ── Initialize ────────────────────────────────────────
async function initialize() {
  initBackground();
  startClock();
  loadSettingsUI();

  // Loading progress simulation
  const bar = document.getElementById('loading-bar');
  const status = document.getElementById('loading-status');
  const steps = [
    [15, 'Initializing components...'],
    [35, 'Loading configuration...'],
    [55, CFG.demoMode ? 'Loading demo data...' : 'Connecting to server...'],
    [80, 'Rendering dashboard...'],
    [100, 'Ready!'],
  ];

  for (const [pct, msg] of steps) {
    await sleep(180);
    bar.style.width = `${pct}%`;
    status.textContent = msg;
  }

  await loadAll();

  renderOverview();
  renderAlertTable();
  renderEndpoints();
  renderIncidents();
  renderThreatIntel();

  // Hide loading overlay
  await sleep(300);
  document.getElementById('loading-overlay').classList.add('hidden');

  startAutoRefresh();

  if (CFG.demoMode) {
    showToast('info', 'Demo Mode Active', 'Showing sample data. Configure server in Settings ⚙️', 6000);
  }
}

document.addEventListener('DOMContentLoaded', initialize);
