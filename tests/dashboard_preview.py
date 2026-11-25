#!/usr/bin/env python3
"""On-demand, loopback-only dashboard source preview; synthetic data only."""
import argparse
import hashlib
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs
import time

ASSETS = {
    "/dashboard/style.css": ("src/http/dashboard/style.css", "text/css; charset=utf-8"),
    "/dashboard/app.js": ("src/http/dashboard/app.js", "text/javascript; charset=utf-8"),
    "/dashboard/icon.svg": ("assets/veyl.svg", "image/svg+xml"),
    "/dashboard/api/marketplace": ("src/http/dashboard/marketplace.json", "application/json; charset=utf-8"),
}
INDEX = "src/http/dashboard/index.html"
PREVIEW_CSS = b"""
.preview-banner { display:flex; flex-wrap:wrap; justify-content:space-between; gap:.5rem; padding:.45rem 1rem; border-bottom:1px solid var(--stroke); background:var(--surface); color:var(--accent); font-size:.8rem; }
.preview-banner strong { letter-spacing:.06em; }
"""
RELOAD = b"""
(() => {
  const initial=document.querySelector('meta[name=veyl-preview-revision]').content;
  let busy=false;
  async function check() {
    if(document.hidden || busy) return;
    busy=true;
    try {
      const res=await fetch('/preview/revision',{cache:'no-store'});
      if(!res.ok) return;
      const {revision}=await res.json();
      if(revision!==initial) location.reload();
    } catch (_) { /* Keep the current preview when the server is stopped. */ }
    finally {busy=false;}
  }
  setInterval(check,1500);
  document.addEventListener('visibilitychange',check);
})();
"""

def inventory(*items):
    return {"available": True, "items": list(items), "truncated": False}

GIB = 1024**3
DIAGNOSTICS = {
    "resources": {
        "architecture": "x86_64", "cpu_model": "Example 16-thread processor",
        "logical_cpus": 16, "platform": "linux", "load_average": [0.8, 1.1, 1.4],
        "memory_total_kib": 16*1024**2, "memory_available_kib": 9*1024**2,
        "swap_total_kib": 8*1024**2, "swap_free_kib": 6*1024**2,
        "uptime_seconds": 12545,
        "pressure": {k:"some avg10=0.12 avg60=0.25 avg300=0.30 total=1000\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0" for k in ("cpu","memory","io")},
        "workspace_filesystem": {"total_bytes": 256*GIB, "available_bytes": 140*GIB},
        "thermal": inventory({"id":"thermal0","type":"CPU","temperature_millicelsius":54000}),
        "power": inventory({"name":"BAT0","type":"Battery","capacity_percent":76,"status":"Discharging"}),
    },
    "gpu": inventory({"pci_address":"0000:01:00.0","driver":"example","runtime_status":"active","busy_percent":28,"vram_total_bytes":8*GIB,"vram_used_bytes":2*GIB},
                     {"pci_address":"0000:00:02.0","driver":"example-integrated","runtime_status":"suspended","busy_percent":None,"vram_total_bytes":None,"vram_used_bytes":None}),
    "storage": {"workspace_filesystem":{"total_bytes":256*GIB,"available_bytes":140*GIB},
                "devices":inventory({"name":"nvme0n1","model":"Example SSD","size_bytes":512*GIB,"read_only":False,"rotational":False})},
    "network": inventory({"interface":"wlan0","state":"up","carrier":True,"mtu":1500,"rx_bytes":3*GIB,"tx_bytes":GIB},
                         {"interface":"eth0","state":"down","carrier":False,"mtu":1500,"rx_bytes":0,"tx_bytes":0}),
    "audio": {**inventory({"card":"card0","driver":"example","id":"PCH"}),
              "session":{"sinks":inventory({"description":"Speakers","state":"RUNNING","mute":False,"volume":{"front-left":{"value_percent":"75%"}}}),
                         "sources":inventory({"description":"Microphone","state":"SUSPENDED","mute":True})}},
    "bluetooth": {**inventory({"adapter":"hci0","driver":"btusb"}),"session":{"available":True,"connected_names":["Example headphones"]}},
    "desktop": inventory({"connector":"eDP-1","status":"connected","enabled":"enabled","supported_modes":["1920x1200","1280x800"]}),
    "sway": {"outputs":inventory({"name":"eDP-1","active":True,"scale":1.25,"current_mode":{"width":1920,"height":1200,"refresh":165000}}),
             "workspaces":inventory({"name":"1","focused":True,"visible":True,"output":"eDP-1"},{"name":"2","focused":False,"visible":False,"output":"eDP-1"})},
    "services": {"veyl":{"ActiveState":"active","SubState":"running","MainPID":"1234","MemoryCurrent":"5242880","NRestarts":"0","UnitFileState":"enabled"},
                 "user_failed":inventory(),"system_failed":inventory()},
}

def fixture(path, query):
    if path == "status":
        return {"version":"development preview","listener":"Preview only","sessions":3,"connections":1,"active_calls":0,"rss_kib":5120,"cpu_percent":0.2,"audit":"Sample",
                "csrf":"preview-only","jobs_configured":True,"skills_configured":True,
                "configuration":{"authorization":"Sample","broad_state_layout":"Sample","configured_job_profiles":True,"configured_skills_store":True},
                "protected_paths":{"state_directory":"Preview state","skills_directory":"Preview skills","default_masked":[".ssh",".gnupg"],"default_readonly":[".config/systemd",".local/bin"],"extra_masked":[],"extra_readonly":[]},
                "clients":[{"id":name,"mode":mode,"connections":1,"grants":["system_info","read_file"],"skills":[],"upstreams":[]} for name,mode in (("chatgpt","yolo"),("codex","standard"),("agy","standard"))]}
    if path == "diagnostics":
        section=query.get("section",["resources"])[0]
        if section not in DIAGNOSTICS:
            return None
        return {"schema_version":1,"read_only":True,"limitations":"Synthetic preview, not host telemetry.","sections":{section:DIAGNOSTICS[section]}}
    if path == "integrations":
        return {"service":{"ActiveState":"Sample"},"tailscale":{"state":"Preview only","mcp":"Not connected","dashboard":"Not connected"}}
    if path == "servers":
        return {"servers":[{"id":"example-provider","transport":"stdio","enabled":False}]}
    if path == "skills":
        return {"skills":[{"name":"example-skill","description":"Example development instructions","enabled":True}]}
    if path == "skills/read":
        return {"document":"# Example skill\nSynthetic preview instructions."}
    if path == "jobs":
        return {"jobs":[{"job_id":"a"*32,"client":query.get("client",["chatgpt"])[0],"state":"completed","exit_code":0,"created_at":int(time.time()),"cwd":"/example/project","profile":"test","execution_duration_ms":1245}],"next_cursor":None}
    if path == "jobs/"+"a"*32+"/logs":
        return {"stdout":"Example test output\nTests passed","stderr":""}
    if path == "activity":
        return {"active_calls":0,"events":[{"kind":"mcp_call","call_id":"preview-1","time":int(time.time()),"tool":"system_inspect","client":"chatgpt","status":"success","duration_ms":24,"target_summary":"Example subsystem inspection"},{"kind":"mcp_call","call_id":"preview-2","time":int(time.time())-3,"tool":"exec_command","client":"chatgpt","status":"success","duration_ms":1245,"target_summary":"Example command"}]}
    if path == "audit":
        return {"events":[]}
    if path == "trace":
        return {"enabled":False,"busy":False,"remaining_ms":0,"events":[]}
    return None

def source_bytes(root, path):
    file=(root/path).resolve(strict=True)
    if not file.is_relative_to(root) or not file.is_file():
        raise ValueError("Invalid source asset")
    with file.open("rb") as handle:
        data=handle.read(4*1024*1024+1)
    if len(data)>4*1024*1024:
        raise ValueError("Source asset too large")
    return data

def revision(root):
    h=hashlib.sha256()
    for path in [INDEX,*(item[0] for item in ASSETS.values())]:
        h.update(path.encode()+b"\0"+source_bytes(root,path))
    return h.hexdigest()

def handler(root, port):
    class Preview(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def send(self, code, data, content_type):
            self.send_response(code)
            self.send_header("Content-Type",content_type)
            self.send_header("Content-Length",str(len(data)))
            self.send_header("Cache-Control","no-store")
            self.send_header("X-Content-Type-Options","nosniff")
            self.send_header("Referrer-Policy","no-referrer")
            self.send_header("Content-Security-Policy","default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
            self.end_headers()
            self.wfile.write(data)
        def json(self, code, data):
            self.send(code,json.dumps(data).encode(),"application/json; charset=utf-8")
        def valid_host(self):
            # Use localhost rather than the production 127.0.0.1 origin.
            return self.headers.get("Host")==f"localhost:{port}"
        def do_POST(self):
            self.json(403,{"error":"Preview only: mutations and live gateway access are disabled."})
        def do_GET(self):
            if not self.valid_host():
                self.json(403,{"error":"Invalid preview host"})
                return
            u=urlsplit(self.path)
            try:
                if u.path in ("/","/dashboard","/dashboard/login"):
                    rev=revision(root)
                    html=source_bytes(root,INDEX)
                    if b"</head>" not in html or b"<body>" not in html:
                        raise ValueError("Dashboard markup incomplete")
                    html=html.replace(b"</head>",b'<meta name="veyl-preview-revision" content="'+rev.encode()+b'"><script src="/preview/reload.js" defer></script></head>',1)
                    html=html.replace(b"<body>",b'<body><aside class="preview-banner" role="status"><strong>DEVELOPMENT PREVIEW</strong><span>Synthetic data &middot; read-only &middot; auto-reload &middot; '+rev[:10].encode()+b'</span></aside>',1)
                    self.send(200,html,"text/html; charset=utf-8")
                elif u.path=="/preview/reload.js":
                    self.send(200,RELOAD,"text/javascript; charset=utf-8")
                elif u.path=="/preview/revision":
                    self.json(200,{"revision":revision(root)})
                elif u.path in ASSETS:
                    path,mime=ASSETS[u.path]
                    data=source_bytes(root,path)
                    self.send(200,data+PREVIEW_CSS if u.path.endswith("style.css") else data,mime)
                elif u.path.startswith("/dashboard/api/"):
                    data=fixture(u.path.removeprefix("/dashboard/api/"),parse_qs(u.query))
                    self.json(200,data) if data is not None else self.json(404,{"error":"No preview fixture"})
                else:
                    self.json(404,{"error":"Not a preview route"})
            except (OSError,ValueError):
                self.json(503,{"error":"Preview source is unavailable or incomplete. Save changes and retry."})
    return Preview

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source",type=Path,default=Path(__file__).resolve().parents[1],help="Veyl source checkout or isolated candidate")
    parser.add_argument("--port",type=int,default=7333)
    args=parser.parse_args()
    if os.geteuid()==0 or not 1024<=args.port<=65535:
        parser.error("Use an unprivileged user and port")
    root=args.source.resolve(strict=True)
    revision(root)
    server=ThreadingHTTPServer(("127.0.0.1",args.port),handler(root,args.port))
    print(f"Preview: http://localhost:{args.port}/dashboard#diagnostics",flush=True)
    print(f"Source: {root} | synthetic fixtures only | Ctrl+C to stop",flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__=="__main__":
    main()
