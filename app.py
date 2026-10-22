from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
import json, random, time, socket, threading

# Attempt to import psutil for real-time connection tracking
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

HOST, PORT = '127.0.0.1', 8000
EVENTS = []

# --- 1. DYNAMICALLY DETECT LAPTOP IP ---
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

MY_IP = get_local_ip()

# --- 2. BEHAVIOR ANALYSIS ENGINE FOR REAL CONNECTIONS ---
def analyze_connection(process_name, remote_port):
    proc_lower = process_name.lower().replace('.exe', '')
    
    # Rule 1: Known Web Browsers
    browsers = ['chrome', 'brave', 'firefox', 'msedge', 'safari', 'opera']
    if any(b in proc_lower for b in browsers):
        if remote_port in [80, 443, 8080]:
            return "Safe", "Standard web browsing traffic."
        else:
            return "Warning", f"Browser using unusual port ({remote_port})."
            
    # Rule 2: Known Safe Applications
    good_apps = ['discord', 'spotify', 'slack', 'zoom', 'teams', 'whatsapp', 'telegram', 'onedrive', 'dropbox']
    if any(a in proc_lower for a in good_apps):
        return "Safe", "Verified communication/media application."
        
    # Rule 3: Core System Processes
    sys_apps = ['svchost', 'system', 'kernel', 'lsass', 'spoolsv', 'services']
    if any(s in proc_lower for s in sys_apps):
        return "Safe", "Standard background system process."
        
    # Rule 4: Suspicious / High-Risk Ports
    # 21=FTP, 23=Telnet, 3389=RDP, 4444=Metasploit, 6667=IRC (often botnets)
    suspicious_ports = [21, 23, 3389, 4444, 6667]
    if remote_port in suspicious_ports:
        return "Suspicious", f"High-risk port ({remote_port}) accessed by unknown process."
        
    # Rule 5: Default Unknown Process
    if process_name == "System/Unknown":
        return "Warning", "OS restricted access to process name."
        
    return "Warning", "Uncategorized background process making external connection."

# --- 3. GET REAL ACTIVE CONNECTIONS ---
def get_real_connections():
    if not PSUTIL_AVAILABLE:
        return []
    
    active_conns = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            # Only care about active (ESTABLISHED) outbound connections
            if conn.status == 'ESTABLISHED' and conn.raddr:
                try:
                    proc = psutil.Process(conn.pid)
                    proc_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                    proc_name = "System/Unknown"
                
                # Run the behavior analysis
                verdict, explanation = analyze_connection(proc_name, conn.raddr.port)
                
                active_conns.append({
                    'process': proc_name,
                    'remote': f"{conn.raddr.ip}",
                    'port': conn.raddr.port,
                    'verdict': verdict,
                    'explanation': explanation
                })
    except psutil.AccessDenied:
        pass 
        
    # Sort alphabetically by process name
    return sorted(active_conns, key=lambda x: x['process'])

# --- 4. TRAFFIC DEFINITIONS (DYNAMIC GENERATORS) ---
NORMAL_DOMAINS = [
    "google.com", "github.com", "aws.amazon.com", "wikipedia.org", "microsoft.com", 
    "apple.com", "netflix.com", "reddit.com", "discord.com", "spotify.com", 
    "zoom.us", "slack.com", "cloudflare.com", "yahoo.com", "bing.com", "linkedin.com"
]
NORMAL_PREFIXES = ["www", "api", "cdn", "mail", "app", "auth", "static", "dev", "telemetry"]

SCAM_KEYWORDS = ["urgent", "verify", "secure", "free", "win", "claim", "update", "alert", "login", "reset"]
SCAM_BRANDS = ["paypal", "apple", "amazon", "netflix", "chase", "crypto", "wallet", "support", "meta"]
SCAM_TLDS = [".xyz", ".club", ".info", ".net", ".ru", ".tk", ".cc", ".biz", ".online"]

def get_dynamic_normal_site():
    domain = random.choice(NORMAL_DOMAINS)
    if random.random() < 0.40:
        prefix = random.choice(NORMAL_PREFIXES)
        if random.random() < 0.5:
            prefix += f"-{random.randint(1, 99)}"
        return f"{prefix}.{domain}"
    return domain

def get_dynamic_scam_site():
    kw = random.choice(SCAM_KEYWORDS)
    brand = random.choice(SCAM_BRANDS)
    tld = random.choice(SCAM_TLDS)
    patterns = [
        f"{kw}-{brand}{tld}",
        f"{brand}-{kw}-now{tld}",
        f"{kw}-account-{brand}{tld}",
        f"my-{brand}-security{tld}",
        f"support-ticket-{random.randint(1000,9999)}{tld}"
    ]
    return random.choice(patterns)

live_traffic_active = False

def generate_live_traffic():
    global EVENTS, live_traffic_active
    while True:
        if live_traffic_active:
            now = time.strftime('%H:%M:%S')
            # 10% chance to hit a scam site, 90% normal traffic
            if random.random() < 0.10:
                dest = get_dynamic_scam_site()
                EVENTS.append({'time': now, 'ip': MY_IP, 'dest_ip': dest, 'event': 'Outbound Request', 'protocol': 'TCP', 'port': 443, 'suspicious': True, 'explanation': 'User attempted to access a known malicious domain.'})
                for i in range(1, 6):
                    time.sleep(0.2)
                    EVENTS.append({'time': time.strftime('%H:%M:%S'), 'ip': MY_IP, 'dest_ip': dest, 'event': f'Connection Blocked (Attempt {i}/5)', 'protocol': 'TCP', 'port': 443, 'suspicious': True, 'explanation': 'Firewall auto-blocked connection to malicious site.'})
            else:
                dest = get_dynamic_normal_site()
                EVENTS.append({'time': now, 'ip': MY_IP, 'dest_ip': dest, 'event': 'Outbound Web Traffic', 'protocol': 'TCP', 'port': random.choice([443, 80]), 'suspicious': False, 'explanation': 'Standard outbound HTTP/HTTPS request.'})
            EVENTS = EVENTS[-100:]
        time.sleep(random.uniform(1.5, 3.5))

threading.Thread(target=generate_live_traffic, daemon=True).start()

HTML = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NETSENTRY</title>
<style>
:root{{font-family:Segoe UI,Arial,sans-serif;color:#e8eef8;background:#0b1220}}*{{box-sizing:border-box}}body{{margin:0}}.wrap{{max-width:1150px;margin:auto;padding:28px 18px}}.top{{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:22px}}.brand{{display:flex;gap:12px;align-items:center}}.logo{{display:grid;place-items:center;width:48px;height:48px;border-radius:14px;background:#193452;font-size:25px}}.muted{{color:#96a8bf}}.pill{{border:1px solid #28654f;color:#7ce4b1;background:#103326;border-radius:999px;padding:7px 12px;font-size:13px}}.panel{{background:#111c2d;border:1px solid #26364b;border-radius:16px;padding:20px;margin-bottom:18px}}
.stats{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}}.stat{{background:#162338;border:1px solid #293d56;border-radius:13px;padding:16px}}.label{{font-size:13px;color:#9fb0c6}}.num{{font-size:29px;font-weight:700;margin-top:8px}}.actions{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:14px}}.btn{{border:1px solid #3b5878;border-radius:11px;padding:14px 12px;background:#19304a;color:#f1f6ff;font-weight:600;cursor:pointer;transition:0.2s}}.btn:hover{{background:#234467}}.btn:disabled{{opacity:.5;cursor:wait}}.btn-live{{background:#103326;border-color:#28654f;color:#7ce4b1}}.btn-live.active{{background:#3b2029;border-color:#ff9c9c;color:#ff9c9c}}
.result{{display:none;margin-top:16px;padding:15px;border-radius:12px;background:#172a40;border:1px solid #385472}}.result.show{{display:block}}.good{{color:#7ce4b1}}.bad{{color:#ff9c9c}}.tablewrap{{overflow:auto}}table{{width:100%;border-collapse:collapse;margin-top:10px;min-width:700px}}th,td{{text-align:left;padding:12px 10px;border-bottom:1px solid #27384d;font-size:14px}}th{{color:#9fb0c6;font-weight:600}}
.status{{font-size:12px;border-radius:999px;padding:5px 8px;display:inline-block;font-weight:600;}}
.safe{{background:#103326;color:#7ce4b1;border:1px solid #28654f;}}
.alert{{background:#3b2029;color:#ff9c9c;border:1px solid #753b49;}}
.warning{{background:#3b3620;color:#ffd166;border:1px solid #75623b;}}
.rowhead{{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}}.smallbtn{{background:transparent;color:#b7c8dc;border:1px solid #40536a;border-radius:8px;padding:7px 10px;cursor:pointer}}
/* TABS CSS */
.tabs {{ display: flex; gap: 10px; margin-bottom: 20px; border-bottom: 1px solid #26364b; padding-bottom: 15px; }}
.tab {{ background: transparent; color: #9fb0c6; border: none; font-size: 16px; cursor: pointer; padding: 10px 15px; border-radius: 8px; transition: 0.2s; }}
.tab:hover {{ background: #162338; }}
.tab.active {{ background: #19304a; color: #f1f6ff; font-weight: 600; border: 1px solid #3b5878; }}
.tab-content {{ display: none; }}
.tab-content.active {{ display: block; }}
</style></head><body><main class="wrap">
<header class="top"><div class="brand"><div class="logo">🛡️</div><div><h1 style="margin:0;font-size:25px">NETSENTRY</h1><div class="muted" style="margin-top:5px">Monitoring IP: <strong style="color:#7ce4b1">{MY_IP}</strong></div></div></div></header>

<div class="tabs">
    <button class="tab active" onclick="switchTab('sim-tab', this)">Simulated Events & Alerts</button>
    <button class="tab" onclick="switchTab('real-tab', this)">Real-Time Device Behavior</button>
</div>

<!-- SIMULATION TAB -->
<div id="sim-tab" class="tab-content active">
    <section class="panel"><div class="rowhead"><div><h2 style="margin:0 0 5px">Network monitor</h2><div class="muted">Trigger anomalies or let background traffic flow.</div></div><button class="smallbtn" onclick="resetDemo()">Reset Data</button></div>
    <div class="stats" style="margin-top:18px"><div class="stat"><div class="label">Events logged</div><div class="num" id="total">0</div></div><div class="stat"><div class="label">Suspicious / Blocked</div><div class="num bad" id="suspicious">0</div></div><div class="stat"><div class="label">Normal events</div><div class="num good" id="normal">0</div></div></div>
    <div class="actions">
        <button class="btn btn-live" id="liveBtn" onclick="toggleLiveTraffic(this)">▶ &nbsp; Start Live Traffic</button>
        <button class="btn" onclick="runScenario('port_scan',this)">⌕ &nbsp; Inbound Port Scan</button>
        <button class="btn" onclick="runScenario('login_failures',this)">⚠ &nbsp; SSH Brute Force</button>
        <button class="btn" onclick="runScenario('behavior_anomaly',this)">⚲ &nbsp; Data Exfiltration</button>
    </div>
    <div class="result" id="result"></div></section>
    <section class="panel"><div class="rowhead"><div><h2 style="margin:0 0 5px">Live Traffic Stream</h2></div></div><div class="tablewrap"><table><thead><tr><th>Time</th><th>Source IP</th><th>Target (URL/IP)</th><th>Event</th><th>Protocol / Port</th><th>Result</th></tr></thead><tbody id="rows"><tr><td colspan="6" class="muted">No events yet. Start live traffic or trigger a scenario.</td></tr></tbody></table></div></section>
</div>

<!-- REAL CONNECTIONS TAB -->
<div id="real-tab" class="tab-content">
    <section class="panel">
        <div class="rowhead">
            <div><h2 style="margin:0 0 5px">Behavioral Analysis (Live)</h2>
            <div class="muted">Analyzing your machine's actual outbound connections in real-time.</div></div>
        </div>
        <div class="tablewrap" style="margin-top: 15px;">
            <table>
                <thead><tr>
                    <th>Process</th>
                    <th>Remote IP</th>
                    <th>Port</th>
                    <th>Verdict</th>
                    <th>Analysis Details</th>
                </tr></thead>
                <tbody id="real-rows"><tr><td colspan="5" class="muted">Fetching real connections...</td></tr></tbody>
            </table>
        </div>
    </section>
</div>

</main><script>
let events=[]; let pollInterval = null; let realPollInterval = null; const $=id=>document.getElementById(id);

// Tab switching logic
function switchTab(tabId, btn) {{
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
    $(tabId).classList.add('active'); btn.classList.add('active');
}}

// Simulation logic
async function fetchEvents() {{ let r = await fetch('/api/events'); let data = await r.json(); events = data.events; render(null); }}
async function toggleLiveTraffic(btn) {{
    let r = await fetch('/api/toggle_live', {{method:'POST'}}); let data = await r.json();
    if(data.active) {{ btn.innerHTML = '⏸ &nbsp; Pause Traffic'; btn.classList.add('active'); pollInterval = setInterval(fetchEvents, 1000);
    }} else {{ btn.innerHTML = '▶ &nbsp; Start Live Traffic'; btn.classList.remove('active'); clearInterval(pollInterval); }}
}}
async function runScenario(type,btn){{
    btn.disabled=true;
    try{{ let r=await fetch('/api/simulate',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{scenario:type}})}}); let data=await r.json(); events=data.events; render(data.latest);
    }}catch(e){{ $('result').className='result show';$('result').innerHTML='<b class="bad">Server connection lost.</b>' }}finally{{btn.disabled=false;}}
}}
async function resetDemo(){{ await fetch('/api/reset',{{method:'POST'}}); events=[]; render(null); $('result').className='result';$('result').innerHTML=''; }}
function render(latest){{
    $('total').textContent=events.length; $('suspicious').textContent=events.filter(e=>e.suspicious).length; $('normal').textContent=events.filter(e=>!e.suspicious).length;
    let rows=$('rows');
    if(!events.length){{ rows.innerHTML='<tr><td colspan="6" class="muted">No events yet.</td></tr>' }}else{{
        rows.innerHTML=events.slice().reverse().map(e=>`<tr><td>${{e.time}}</td><td>${{e.ip}}</td><td>${{e.dest_ip}}</td><td>${{e.event}}</td><td>${{e.protocol}} / ${{e.port}}</td><td><span class="status ${{e.suspicious?'alert':'safe'}}">${{e.suspicious?'Blocked/Sus':'Normal'}}</span></td></tr>`).join('');
    }}
    if(latest){{ $('result').className='result show';$('result').innerHTML=`<b class="${{latest.suspicious?'bad':'good'}}">${{latest.suspicious?'⚠ Suspicious activity detected':'✓ Normal traffic'}}</b><div style="margin-top:7px">${{latest.explanation}}</div>` }}
}}

// Real Connections Logic
function getVerdictClass(verdict) {{
    if(verdict === "Safe") return "safe";
    if(verdict === "Warning") return "warning";
    return "alert";
}}

async function fetchRealConnections() {{
    if(!$('real-tab').classList.contains('active')) return;
    try {{
        let r = await fetch('/api/real_connections'); let data = await r.json(); let rows = $('real-rows');
        if(data.error) {{ rows.innerHTML = `<tr><td colspan="5" class="bad" style="padding:20px; text-align:center;">${{data.error}}</td></tr>`; return; }}
        if(data.connections.length === 0) {{ rows.innerHTML = '<tr><td colspan="5" class="muted">No active outbound connections found.</td></tr>'; return; }}
        
        rows.innerHTML = data.connections.map(c => `<tr>
            <td><strong style="color: #f1f6ff">${{c.process}}</strong></td>
            <td style="color: #9fb0c6">${{c.remote}}</td>
            <td style="color: #9fb0c6">${{c.port}}</td>
            <td><span class="status ${{getVerdictClass(c.verdict)}}">${{c.verdict}}</span></td>
            <td class="muted">${{c.explanation}}</td>
        </tr>`).join('');
    }} catch(e) {{ }}
}}
setInterval(fetchRealConnections, 2500); fetchRealConnections();
</script></body></html>'''

class Handler(BaseHTTPRequestHandler):
    def _send(self, code, content, content_type='application/json; charset=utf-8'):
        raw = content.encode('utf-8')
        self.send_response(code); self.send_header('Content-Type', content_type); self.send_header('Content-Length', str(len(raw))); self.send_header('Cache-Control','no-store'); self.end_headers(); self.wfile.write(raw)
    
    def do_GET(self):
        if urlparse(self.path).path == '/': self._send(200, HTML, 'text/html; charset=utf-8')
        elif urlparse(self.path).path == '/api/events': self._send(200, json.dumps({'events': EVENTS}))
        
        elif urlparse(self.path).path == '/api/real_connections':
            if not PSUTIL_AVAILABLE:
                self._send(200, json.dumps({'error': '<strong>Library Missing:</strong> To view real connections, run:<br><br><code>pip install psutil</code>'}))
            else:
                conns = get_real_connections()
                self._send(200, json.dumps({'connections': conns}))
                
        else: self._send(404, json.dumps({'error':'Not found'}))
        
    def do_POST(self):
        global EVENTS, live_traffic_active
        path = urlparse(self.path).path
        if path == '/api/reset': EVENTS = []; self._send(200, json.dumps({'ok': True})); return
        if path == '/api/toggle_live': live_traffic_active = not live_traffic_active; self._send(200, json.dumps({'active': live_traffic_active})); return
        if path != '/api/simulate': self._send(404, json.dumps({'error':'Not found'})); return
        
        try: body = json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))).decode('utf-8'))
        except Exception: self._send(400, json.dumps({'error':'Invalid JSON'})); return
        
        scenario = body.get('scenario')
        now = time.strftime('%H:%M:%S')
        attacker_ip = f"{random.randint(100,200)}.{random.randint(10,50)}.x.x"
        
        if scenario == 'port_scan': generated = [{'time':now, 'ip':attacker_ip, 'dest_ip': MY_IP, 'event':'Port Probe', 'protocol':'TCP', 'port':p, 'suspicious':True, 'explanation':f'External IP mapping open ports on {MY_IP}.'} for p in [21,22,80,443,3389]]
        elif scenario == 'login_failures': generated = [{'time':now, 'ip':attacker_ip, 'dest_ip': MY_IP, 'event':'Failed SSH Login', 'protocol':'TCP', 'port':22, 'suspicious':True, 'explanation':'Repeated SSH login failures indicate a brute-force attack.'} for _ in range(5)]
        elif scenario == 'behavior_anomaly': suspect_dest = "185.15.x.x"; generated = [{'time':now, 'ip':MY_IP, 'dest_ip': suspect_dest, 'event':'Massive Data Upload (14.2 GB)', 'protocol':'TCP', 'port':443, 'suspicious':True, 'explanation':'Unexpected large data transfer indicating potential exfiltration.'}]
        else: self._send(400, json.dumps({'error':'Unknown scenario'})); return
            
        EVENTS.extend(generated); EVENTS = EVENTS[-100:]
        self._send(200, json.dumps({'events':EVENTS,'latest':generated[-1]}))

    def log_message(self, format, *args): pass 

if __name__ == '__main__':
    print(f'NETSENTRY running at http://{HOST}:{PORT}')
    if not PSUTIL_AVAILABLE: print("WARNING: 'psutil' is not installed. Real connections tab will not work.")
    try: HTTPServer((HOST, PORT), Handler).serve_forever()
    except KeyboardInterrupt: print('\nServer stopped.')