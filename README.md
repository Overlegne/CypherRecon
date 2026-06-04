# CypherRecon | AI-Powered Ethical Reconnaissance

CypherRecon is een dashboard voor het beheren van doelwit-reconnaissance. Het scheidt de **UI** van de **Scanner Engine (Python)**, zodat je echte scans vanaf je lokale machine kunt draaien.

## 🚀 Quickstart Guide

### 1. Vereisten
- Installeer **Nmap** en zorg dat het in je systeem-pad staat (`nmap --version`).
- Installeer **Subfinder** voor echte subdomain discovery.
- Installeer Python afhankelijkheden:
  ```bash
  pip install fastapi uvicorn pydantic httpx playwright
  playwright install chromium
  ```
- **API Key**: Haal een gratis API-key op via [Google AI Studio](https://aistudio.google.com/app/apikey) en zet deze in het `.env` bestand in de hoofdmap van dit project:
  `GOOGLE_GENAI_API_KEY=jouw_sleutel_hier`

### 2. Start de Python Scanner
Sla de onderstaande code op als `main.py` op je lokale machine en start deze:
`uvicorn main:app --host 0.0.0.0 --port 5000`

```python
import uuid, time, asyncio, subprocess, json, httpx, os, shutil, base64, re
from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory opslag
db = {"targets": {}, "stop_flags": set()}

class Credential(BaseModel):
    id: str
    type: str
    label: str
    value: str
    headerName: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    notes: Optional[str] = None
    enabled: bool

class TargetCreate(BaseModel):
    host: str
    mode: str
    modules: Dict[str, bool]
    credentials: Optional[List[Credential]] = []

@app.get("/health")
def health(): 
    return {"status": "ok", "engine": "CypherRecon Core v1.6 (WebSurface Ready)"}

@app.get("/targets")
def get_targets(): 
    return list(db["targets"].values())

@app.get("/targets/{id}")
def get_target(id: str): 
    return db["targets"].get(id)

@app.post("/targets")
def add_target(t: TargetCreate):
    new_id = str(uuid.uuid4())
    target = {
        "id": new_id, "host": t.host, "mode": t.mode, "status": "idle",
        "progress": 0, "createdAt": int(time.time()*1000), "modules": t.modules,
        "credentials": [c.dict() for c in t.credentials],
        "results": {"logs": [], "subdomains": [], "portScanResults": [], "osintData": [], "techStack": [], "apiEndpoints": [], "screenshots": [], "webSurface": None}
    }
    db["targets"][new_id] = target
    return target

@app.post("/targets/{id}/scan")
def run_scan(id: str, background_tasks: BackgroundTasks):
    if id in db["targets"]:
        if id in db["stop_flags"]: db["stop_flags"].remove(id)
        db["targets"][id]["status"] = "running"
        db["targets"][id]["progress"] = 0
        db["targets"][id]["results"] = {"logs": [], "subdomains": [], "portScanResults": [], "osintData": [], "techStack": [], "apiEndpoints": [], "screenshots": [], "webSurface": None}
        background_tasks.add_task(execute_full_workflow, id)
        return {"status": "started"}
    return {"error": "not found"}, 404

@app.post("/targets/{id}/stop")
def stop_scan(id: str):
    if id in db["targets"]:
        db["stop_flags"].add(id)
        return {"status": "stopping"}
    return {"error": "not found"}, 404

@app.post("/targets/{id}/risk")
def update_risk(id: str, payload: dict):
    if id in db["targets"]:
        db["targets"][id]["results"]["riskAnalysis"] = payload["riskAnalysis"]
    return {"status": "ok"}

@app.delete("/targets/{id}")
def delete_target(id: str):
    if id in db["targets"]: 
        del db["targets"][id]
    return {"status": "deleted"}

async def execute_full_workflow(id: str):
    t = db["targets"][id]
    host = t["host"]
    modules = t["modules"]
    mode = t["mode"]
    creds = t.get("credentials", [])
    
    def log(msg, type="info"):
        t["results"]["logs"].append({
            "id": str(uuid.uuid4()), "timestamp": int(time.time()*1000),
            "message": msg, "type": type
        })

    def is_stopped():
        return id in db["stop_flags"]

    def build_http_context():
        headers = {"User-Agent": "CypherRecon/1.6 (Ethical Security Analysis)"}
        cookies = {}
        for c in creds:
            if not c.get("enabled"): continue
            ctype = c.get("type")
            if ctype == "api_key": headers[c.get("headerName") or "X-API-Key"] = c.get("value")
            elif ctype in ["bearer_token", "jwt"]: headers["Authorization"] = f"Bearer {c.get('value')}"
            elif ctype == "cookie": cookies[c.get("label")] = c.get("value")
            elif ctype == "custom_header": headers[c.get("headerName")] = c.get("value")
            elif ctype == "basic_auth":
                import base64
                encoded = base64.b64encode(f"{c.get('username')}:{c.get('password')}".encode()).decode()
                headers["Authorization"] = f"Basic {encoded}"
        return headers, cookies

    try:
        log(f"Starting workflow for {host} in {mode.upper()} mode.", "info")

        # Module 1: Subdomain Enumeration
        if modules.get("subdomain_enumeration") and not is_stopped():
            t["activeModule"] = "subdomain_enumeration"
            log("Phase 1: Subdomain Discovery...")
            binary = shutil.which('subfinder') or os.path.join(os.path.expanduser("~"), "go", "bin", "subfinder")
            if os.path.exists(binary):
                cmd = [binary, '-d', host, '-silent']
                process = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE)
                stdout, _ = await process.communicate()
                t["results"]["subdomains"] = [s for s in stdout.decode().strip().split('\n') if s]
                log(f"Found {len(t['results']['subdomains'])} subdomains.", "success")
            else:
                log("Subfinder not found. Using passive DNS discovery.", "warn")
            t["progress"] = 20

        # Module 2: Port Scanning (Two-Stage)
        web_ports = []
        if modules.get("port_scanning") and not is_stopped():
            t["activeModule"] = "port_scanning"
            log("Phase 2: Rapid Port Discovery (65k ports)...")
            cmd_fast = ['nmap', '-p-', '--open', '-T4', host]
            proc = await asyncio.create_subprocess_exec(*cmd_fast, stdout=asyncio.subprocess.PIPE)
            stdout, _ = await proc.communicate()
            
            found_ports = []
            for line in stdout.decode().split('\n'):
                if "/tcp" in line or "/udp" in line:
                    port = line.split('/')[0].strip()
                    if port.isdigit(): found_ports.append(port)
            
            if found_ports and not is_stopped():
                log(f"Phase 2.1: Analyzing {len(found_ports)} active services...", "info")
                ports_arg = ",".join(found_ports)
                cmd_deep = ['nmap', '-sCV', '-p', ports_arg, host]
                proc_deep = await asyncio.create_subprocess_exec(*cmd_deep, stdout=asyncio.subprocess.PIPE)
                stdout_deep, _ = await proc_deep.communicate()
                
                ports_results = []
                for line in stdout_deep.decode().split('\n'):
                    if "/tcp" in line or "/udp" in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            p_val = int(parts[0].split('/')[0])
                            ports_results.append({
                                "port": p_val, "service": parts[2], "state": parts[1], 
                                "version": " ".join(parts[3:]) if len(parts) > 3 else "Unknown"
                            })
                            if p_val in [80, 443, 8080, 8443] or parts[2] in ["http", "https", "ssl/http"]:
                                web_ports.append(p_val)
                t["results"]["portScanResults"] = ports_results
                log("Service analysis complete.", "success")
            t["progress"] = 40

        # Module 3: Web Surface Security Analysis
        if not is_stopped() and (web_ports or modules.get("web_surface_scan")):
            t["activeModule"] = "web_surface_scan"
            log("Phase 3: Web Surface Security Header Analysis...")
            headers, cookies = build_http_context()
            
            urls = []
            if not web_ports: web_ports = [80, 443] # Fallback
            for p in web_ports:
                scheme = "https" if p in [443, 8443] else "http"
                urls.append(f"{scheme}://{host}")

            surface_results = {"urls_tested": [], "ports_used": web_ports, "headers": [], "summary": {"tested": 0, "ok": 0, "missing": 0, "weak": 0, "info": 0}}
            
            async with httpx.AsyncClient(headers=headers, cookies=cookies, follow_redirects=True, verify=False) as client:
                for url in urls:
                    try:
                        resp = await client.get(url, timeout=10)
                        surface_results["urls_tested"].append(str(resp.url))
                        
                        header_checks = [
                            ("Content-Security-Policy", "high", "Defines allowed content sources to prevent XSS."),
                            ("Strict-Transport-Security", "high", "Enforces HTTPS connections."),
                            ("X-Content-Type-Options", "medium", "Prevents MIME sniffing."),
                            ("X-Frame-Options", "medium", "Prevents Clickjacking."),
                            ("Referrer-Policy", "low", "Controls referrer information leak."),
                            ("Permissions-Policy", "low", "Controls browser features access."),
                            ("Cross-Origin-Opener-Policy", "medium", "Isolates browsing context."),
                            ("Server", "info", "Identifies backend software."),
                            ("X-Powered-By", "info", "Identifies technology stack.")
                        ]

                        for h_name, severity, desc in header_checks:
                            val = resp.headers.get(h_name)
                            status = "ok"
                            if not val:
                                status = "missing" if severity != "info" else "info"
                            elif h_name == "Content-Security-Policy" and ("*" in val or "unsafe-inline" in val):
                                status = "weak"
                            elif h_name == "Strict-Transport-Security" and "max-age" in val.lower():
                                match = re.search(r'max-age=(\d+)', val.lower())
                                if match and int(match.group(1)) < 31536000: status = "weak"
                            
                            surface_results["headers"].append({
                                "name": h_name, "status": status, "value": val, "severity": severity if status != "ok" else "none", "recommendation": desc if status != "ok" else None
                            })
                            surface_results["summary"][status] += 1
                            surface_results["summary"]["tested"] += 1
                        
                        log(f"Web surface scan complete for {url}", "success")
                        break # Successfully tested one URL
                    except Exception as e:
                        log(f"Web scan failed for {url}: {str(e)}", "warn")
            
            t["results"]["webSurface"] = surface_results
            t["progress"] = 65

        # Other Modules (Tech, OSINT, Screenshots)
        if modules.get("tech_stack") and not is_stopped():
            t["activeModule"] = "tech_stack"
            log("Phase 4: Analyzing Tech Stack...")
            t["progress"] = 75
        
        if modules.get("screenshotting") and not is_stopped():
            t["activeModule"] = "screenshotting"
            log("Phase 5: Capturing visual snapshot...")
            t["progress"] = 90

        if not is_stopped():
            t["status"] = "completed"
            t["progress"] = 100
            t["lastRunAt"] = int(time.time()*1000)
            log("Full sequence completed successfully.", "success")
        else:
            log("Sequence aborted by user.", "warn")
            t["status"] = "failed"

    except Exception as e:
        log(f"Critical workflow error: {str(e)}", "error")
        t["status"] = "failed"
```
