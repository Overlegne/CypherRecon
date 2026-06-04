# CypherRecon | AI-Powered Multi-Target Reconnaissance

CypherRecon is een enterprise-grade dashboard voor het beheren van multi-target reconnaissance. Het ondersteunt het groeperen van targets en voert parallelle scans uit via de lokale Python Engine.

## 🚀 Quickstart Guide

### 1. Vereisten
- Installeer **Nmap** en zorg dat het in je systeem-pad staat (`nmap --version`).
- Installeer **Subfinder** voor subdomain discovery.
- Installeer Python afhankelijkheden:
  ```bash
  pip install fastapi uvicorn pydantic httpx playwright beautifulsoup4 dnspython
  playwright install chromium
  ```
- **API Key**: Haal een gratis API-key op via [Google AI Studio](https://aistudio.google.com/app/apikey) en zet deze in het `.env` bestand in de hoofdmap van dit project:
  `GOOGLE_GENAI_API_KEY=jouw_sleutel_hier`

### 2. Start de Python Scanner
Sla de onderstaande code op als `main.py` op je lokale machine en start deze:
`uvicorn main:app --host 0.0.0.0 --port 5000`

```python
import uuid, time, asyncio, subprocess, json, httpx, os, shutil, base64, re, ssl, socket
from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict
from playwright.async_api import async_playwright
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import dns.resolver

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory opslag
db = {"groups": {}, "stop_flags": set()}

class Credential(BaseModel):
    id: str
    type: str
    label: str
    value: str
    headerName: Optional[str] = ""
    username: Optional[str] = ""
    password: Optional[str] = ""
    notes: Optional[str] = ""
    enabled: bool

class GroupCreate(BaseModel):
    name: str
    hosts: List[str]
    mode: str
    modules: Dict[str, bool]
    credentials: Optional[List[Credential]] = []

@app.get("/health")
def health(): 
    return {"status": "ok", "engine": "CypherRecon Multi-Core v2.0"}

@app.get("/targets")
def get_groups(): 
    return list(db["groups"].values())

@app.get("/targets/{id}")
def get_group(id: str): 
    return db["groups"].get(id)

@app.post("/targets")
def add_group(g: GroupCreate):
    group_id = str(uuid.uuid4())
    child_targets = []
    for host in g.hosts:
        child_targets.append({
            "id": str(uuid.uuid4()),
            "host": host.rstrip('/'),
            "status": "idle",
            "progress": 0,
            "results": {"logs": [], "subdomains": [], "portScanResults": [], "osintData": [], "techStack": [], "apiEndpoints": [], "screenshots": [], "webSurface": None, "tlsData": None, "urlHarvesting": None, "cors_audit": None, "cookie_audit": None, "dns_takeover": None, "js_inventory": None}
        })
    
    group = {
        "id": group_id,
        "name": g.name,
        "mode": g.mode,
        "status": "idle",
        "progress": 0,
        "createdAt": int(time.time()*1000),
        "modules": g.modules,
        "credentials": [c.dict() for c in g.credentials],
        "childTargets": child_targets
    }
    db["groups"][group_id] = group
    return group

@app.post("/targets/{id}/scan")
def run_group_scan(id: str, background_tasks: BackgroundTasks):
    if id in db["groups"]:
        if id in db["stop_flags"]: db["stop_flags"].remove(id)
        group = db["groups"][id]
        group["status"] = "running"
        group["progress"] = 0
        for child in group["childTargets"]:
            child["status"] = "running"
            child["progress"] = 0
            child["results"] = {"logs": [], "subdomains": [], "portScanResults": [], "osintData": [], "techStack": [], "apiEndpoints": [], "screenshots": [], "webSurface": None, "tlsData": None, "urlHarvesting": None, "cors_audit": None, "cookie_audit": None, "dns_takeover": None, "js_inventory": None}
        
        background_tasks.add_task(execute_group_workflow, id)
        return {"status": "started"}
    return {"error": "not found"}, 404

@app.post("/targets/{id}/stop")
def stop_group_scan(id: str):
    if id in db["groups"]:
        db["stop_flags"].add(id)
        return {"status": "stopping"}
    return {"error": "not found"}, 404

@app.post("/targets/{id}/risk")
def update_risk(id: str, payload: dict):
    if id in db["groups"]:
        group = db["groups"][id]
        child_id = payload.get("childId")
        for child in group["childTargets"]:
            if child["id"] == child_id:
                child["results"]["riskAnalysis"] = payload["riskAnalysis"]
                return {"status": "ok"}
    return {"error": "not found"}, 404

@app.delete("/targets/{id}")
def delete_group(id: str):
    if id in db["groups"]: 
        del db["groups"][id]
    return {"status": "deleted"}

async def execute_group_workflow(group_id: str):
    group = db["groups"][group_id]
    total_targets = len(group["childTargets"])
    
    for i, child in enumerate(group["childTargets"]):
        if group_id in db["stop_flags"]:
            break
        await execute_single_target(group, child, group_id)
        group["progress"] = int(((i + 1) / total_targets) * 100)
        
    if group_id in db["stop_flags"]:
        group["status"] = "failed"
    else:
        group["status"] = "completed"
        group["lastRunAt"] = int(time.time()*1000)
        group["progress"] = 100

async def execute_single_target(group, child, group_id):
    host = child["host"]
    modules = group["modules"]
    mode = group["mode"]
    creds = group.get("credentials", [])
    
    def log(msg, type="info"):
        child["results"]["logs"].append({
            "id": str(uuid.uuid4()), "timestamp": int(time.time()*1000),
            "message": msg, "type": type
        })

    def is_stopped():
        return group_id in db["stop_flags"]

    def build_http_context():
        headers = {"User-Agent": "CypherRecon/2.0"}
        cookies = []
        for c in creds:
            if not c.get("enabled"): continue
            ctype = c.get("type")
            if ctype == "api_key": headers[c.get("headerName") or "X-API-Key"] = c.get("value")
            elif ctype in ["bearer_token", "jwt"]: headers["Authorization"] = f"Bearer {c.get('value')}"
            elif ctype == "cookie": 
                cookies.append({"name": c.get("label"), "value": c.get("value"), "domain": host, "path": "/"})
            elif ctype == "custom_header": headers[c.get("headerName")] = c.get("value")
            elif ctype == "basic_auth":
                import base64
                encoded = base64.b64encode(f"{c.get('username')}:{c.get('password')}".encode()).decode()
                headers["Authorization"] = f"Basic {encoded}"
        return headers, cookies

    try:
        log(f"Initiating {mode.upper()} scan for {host}.", "info")

        # Phase 1: Subdomain Enumeration
        subdomains = []
        if modules.get("subdomain_enumeration") and not is_stopped():
            child["activeModule"] = "subdomain_enumeration"
            log("Phase 1: Subdomain Discovery...")
            binary = shutil.which('subfinder') or os.path.join(os.path.expanduser("~"), "go", "bin", "subfinder")
            if binary and os.path.exists(binary):
                cmd = [binary, '-d', host, '-silent']
                try:
                    process = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                    stdout, _ = await process.communicate()
                    subdomains = [s for s in stdout.decode().strip().split('\n') if s]
                    child["results"]["subdomains"] = subdomains
                    log(f"Found {len(subdomains)} subdomains.", "success")
                except:
                    log("Execution of subfinder failed.", "error")
            else:
                log("Subfinder binary not found, skipping subdomain discovery.", "warn")
            child["progress"] = 15

        # Phase 1.5: DNS / Subdomain Takeover
        if modules.get("dns_takeover") and not is_stopped():
            child["activeModule"] = "dns_takeover"
            log("Phase 1.5: DNS Audit...")
            dns_results = {"records": [], "summary": {"tested": 0, "cname_records": 0, "suspicious": 0, "high_risk": 0}}
            targets_to_test = list(set([host] + subdomains))
            
            cloud_providers = [".s3.amazonaws.com", ".azurewebsites.net", ".github.io", ".herokuapp.com", ".cloudfront.net", ".wpengine.com", ".zendesk.com", ".myshopify.com"]

            for sd in targets_to_test:
                dns_results["summary"]["tested"] += 1
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = 2
                    resolver.lifetime = 2
                    try:
                        answers = resolver.resolve(sd, 'CNAME')
                        for rdata in answers:
                            cname_val = str(rdata.target).rstrip('.')
                            dns_results["summary"]["cname_records"] += 1
                            status = "ok"
                            issue = None
                            try:
                                resolver.resolve(cname_val)
                            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                                status = "high"
                                issue = "Dangling CNAME: Target does not resolve"
                                dns_results["summary"]["high_risk"] += 1
                            except:
                                if any(cp in cname_val for cp in cloud_providers):
                                    status = "suspicious"
                                    issue = "Points to external cloud service"
                                    dns_results["summary"]["suspicious"] += 1
                            
                            dns_results["records"].append({"subdomain": sd, "type": "CNAME", "value": cname_val, "status": status, "issue": issue})
                    except: pass
                    try:
                        answers = resolver.resolve(sd, 'A')
                        for rdata in answers:
                            dns_results["records"].append({"subdomain": sd, "type": "A", "value": str(rdata), "status": "ok"})
                    except: pass
                except: pass
            child["results"]["dns_takeover"] = dns_results
            log(f"DNS Audit complete.", "success")
            child["progress"] = 25

        # Phase 2: Port Scanning
        web_ports = [80, 443, 8080]
        if modules.get("port_scanning") and not is_stopped():
            child["activeModule"] = "port_scanning"
            log("Phase 2: Service Discovery...")
            cmd_fast = ['nmap', '-p-', '--open', '-T4', host]
            proc = await asyncio.create_subprocess_exec(*cmd_fast, stdout=asyncio.subprocess.PIPE)
            stdout, _ = await proc.communicate()
            found_ports = []
            for line in stdout.decode().split('\n'):
                if "/tcp" in line:
                    p_val = line.split('/')[0].strip()
                    if p_val.isdigit(): found_ports.append(p_val)
            
            if found_ports:
                cmd_deep = ['nmap', '-sCV', '-p', ",".join(found_ports), host]
                proc_deep = await asyncio.create_subprocess_exec(*cmd_deep, stdout=asyncio.subprocess.PIPE)
                stdout_deep, _ = await proc_deep.communicate()
                ports_results = []
                for line in stdout_deep.decode().split('\n'):
                    if "/tcp" in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            p_val = int(parts[0].split('/')[0])
                            service = parts[2].lower()
                            ports_results.append({"port": p_val, "service": service, "state": parts[1], "version": " ".join(parts[3:])})
                            if p_val in [80, 443, 8080] or "http" in service: web_ports.append(p_val)
                child["results"]["portScanResults"] = ports_results
                log(f"Found {len(found_ports)} active ports.", "success")
            child["progress"] = 35

        # Phase 3: Web Surface & Technology Inventory
        harvested_js = []
        if modules.get("web_surface_scan") and not is_stopped():
            child["activeModule"] = "web_surface_scan"
            log("Phase 3: Web Security & Tech Audit...")
            headers, _ = build_http_context()
            surface_results = {
                "urls_tested": [], 
                "ports_used": list(set(web_ports)), 
                "headers": [], 
                "technology_inventory": {"technologies": [], "summary": {"found": 0, "up_to_date": 0, "possibly_outdated": 0, "vulnerable_hint": 0}},
                "summary": {"tested": 0, "ok": 0, "missing": 0, "weak": 0, "info": 0}
            }
            
            async with httpx.AsyncClient(headers=headers, verify=False, follow_redirects=True, timeout=10) as client:
                for p in list(set(web_ports)):
                    proto = "https" if p in [443, 8443] else "http"
                    url = f"{proto}://{host}:{p}"
                    try:
                        resp = await client.get(url)
                        final_url = str(resp.url).rstrip('/')
                        if final_url in surface_results["urls_tested"]: continue
                        surface_results["urls_tested"].append(final_url)
                        
                        soup = BeautifulSoup(resp.text, 'html.parser')
                        for s in soup.find_all('script', src=True): harvested_js.append(urljoin(final_url, s['src']))

                        # Security Headers Audit
                        header_defs = [("Content-Security-Policy", "high"), ("Strict-Transport-Security", "medium"), ("X-Frame-Options", "medium"), ("X-Content-Type-Options", "low")]
                        for h_name, h_sev in header_defs:
                            val = resp.headers.get(h_name)
                            status = "ok" if val else "missing"
                            surface_results["headers"].append({"name": h_name, "value": val, "status": status, "severity": h_sev if status == "missing" else "none", "url": final_url})
                            surface_results["summary"]["tested"] += 1
                            if status == "ok": surface_results["summary"]["ok"] += 1
                            else: surface_results["summary"]["missing"] += 1
                            
                        # Technology Fingerprinting
                        sigs = [
                            ("nginx", "webserver", r"nginx/(\d+\.\d+\.\d+)", "server"),
                            ("Apache", "webserver", r"Apache/(\d+\.\d+\.\d+)", "server"),
                            ("Cloudflare", "cdn", r"cloudflare", "server"),
                            ("WordPress", "cms", r"wp-content", "html"),
                            ("Next.js", "frontend", r"_next/static", "html"),
                            ("PHP", "backend", r"PHP/(\d+\.\d+\.\d+)", "x-powered-by")
                        ]
                        
                        for name, type_tag, pattern, source in sigs:
                            found = False
                            ver = None
                            if source == "server" and resp.headers.get("Server"):
                                match = re.search(pattern, resp.headers["Server"], re.I)
                                if match: 
                                    found = True
                                    try: ver = match.group(1)
                                    except: pass
                            elif source == "x-powered-by" and resp.headers.get("X-Powered-By"):
                                match = re.search(pattern, resp.headers["X-Powered-By"], re.I)
                                if match: 
                                    found = True
                                    try: ver = match.group(1)
                                    except: pass
                            elif source == "html":
                                if re.search(pattern, resp.text, re.I): found = True
                                
                            if found:
                                tech_item = {
                                    "name": name, "type": type_tag, "version": ver, 
                                    "confidence": 0.9, "status": "up_to_date" if ver else "unknown",
                                    "risk": "low" if ver else "info", "evidence": [source]
                                }
                                if tech_item["name"] not in [t["name"] for t in surface_results["technology_inventory"]["technologies"]]:
                                    surface_results["technology_inventory"]["technologies"].append(tech_item)
                                    surface_results["technology_inventory"]["summary"]["found"] += 1
                                    if tech_item["status"] == "up_to_date": surface_results["technology_inventory"]["summary"]["up_to_date"] += 1

                    except: pass
            child["results"]["webSurface"] = surface_results
            log("Web security & technology audit complete.", "success")
            child["progress"] = 60

        # Phase 4: JS Library Inventory
        if modules.get("js_inventory") and not is_stopped():
            child["activeModule"] = "js_inventory"
            log("Phase 4: Auditing JS Libraries...")
            js_results = {"libraries": [], "summary": {"js_files_tested": 0, "unique_libraries": 0, "possibly_outdated": 0, "high_risk": 0}}
            js_targets = list(set(harvested_js))[:10]
            
            patterns = [("jQuery", r"jQuery v?(\d+\.\d+\.\d+)", "3.6.0"), ("React", r"React\.version\s*=\s*['\"](\d+\.\d+\.\d+)['\"]", "17.0.0")]
            async with httpx.AsyncClient(verify=False, timeout=5) as client:
                for js_url in js_targets:
                    js_results["summary"]["js_files_tested"] += 1
                    try:
                        r = await client.get(js_url)
                        if r.status_code == 200:
                            for name, pat, min_v in patterns:
                                match = re.search(pat, r.text)
                                if match:
                                    ver = match.group(1)
                                    status = "ok" if ver >= min_v else "possibly_outdated"
                                    js_results["libraries"].append({"name": name, "version": ver, "file": js_url, "confidence": 0.9, "status": status})
                    except: pass
            js_results["summary"]["unique_libraries"] = len(set([l["name"] for l in js_results["libraries"]]))
            child["results"]["js_inventory"] = js_results
            log(f"JS Inventory complete.", "success")
            child["progress"] = 80

        child["status"] = "completed"
        child["progress"] = 100
        log("Target scan completed.", "success")

    except Exception as e:
        log(f"Error: {str(e)}", "error")
        child["status"] = "failed"
```

Veel succes met je scans! De Technology Inventory helpt je nu nog beter te begrijpen wat de 'onderkant' van de webapplicatie is en waar de grootste risico's liggen.