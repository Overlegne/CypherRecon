
# CypherRecon | AI-Powered Ethical Reconnaissance

CypherRecon is een dashboard voor het beheren van doelwit-reconnaissance. Het scheidt de **UI** van de **Scanner Engine (Python)**, zodat je echte scans vanaf je lokale machine kunt draaien.

## 🚀 Quickstart Guide

### 1. Vereisten
- Installeer **Nmap** en zorg dat het in je systeem-pad staat (`nmap --version`).
- Installeer **Subfinder** voor echte subdomain discovery:
  `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
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
import uuid, time, asyncio, subprocess, json, httpx, os, shutil, base64
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
    return {"status": "ok", "engine": "CypherRecon Core v1.5 (Greybox Ready)"}

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
        "results": {"logs": [], "subdomains": [], "portScanResults": [], "osintData": [], "techStack": [], "apiEndpoints": [], "screenshots": []}
    }
    db["targets"][new_id] = target
    return target

@app.post("/targets/{id}/scan")
def run_scan(id: str, background_tasks: BackgroundTasks):
    if id in db["targets"]:
        if id in db["stop_flags"]: db["stop_flags"].remove(id)
        db["targets"][id]["status"] = "running"
        db["targets"][id]["progress"] = 0
        db["targets"][id]["results"] = {"logs": [], "subdomains": [], "portScanResults": [], "osintData": [], "techStack": [], "apiEndpoints": [], "screenshots": []}
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

    # Helper: Build HTTP Context (Headers/Cookies/Auth)
    def build_http_context():
        headers = {"User-Agent": "CypherRecon/1.5 (Greybox)"}
        cookies = {}
        auth = None
        
        for c in creds:
            if not c.get("enabled"): continue
            ctype = c.get("type")
            if ctype == "api_key":
                headers[c.get("headerName") or "X-API-Key"] = c.get("value")
            elif ctype == "bearer_token":
                headers["Authorization"] = f"Bearer {c.get('value')}"
            elif ctype == "jwt":
                headers["Authorization"] = f"Bearer {c.get('value')}"
            elif ctype == "cookie":
                cookies[c.get("label")] = c.get("value")
            elif ctype == "custom_header":
                headers[c.get("headerName")] = c.get("value")
            elif ctype == "basic_auth":
                import base64
                encoded = base64.b64encode(f"{c.get('username')}:{c.get('password')}".encode()).decode()
                headers["Authorization"] = f"Basic {encoded}"
        return headers, cookies, auth

    try:
        if mode == "greybox":
            log(f"Initiating GREYBOX sequence with {len(creds)} active credentials.", "success")
        else:
            log("Initiating BLACKBOX sequence (Unauthenticated).", "info")

        # Module 1: Subdomain Enumeration
        if modules.get("subdomain_enumeration") and not is_stopped():
            t["activeModule"] = "subdomain_enumeration"
            log(f"Starting subdomain discovery for {host}...")
            binary = shutil.which('subfinder') or os.path.join(os.path.expanduser("~"), "go", "bin", "subfinder")
            if os.path.exists(binary):
                cmd = [binary, '-d', host, '-silent']
                process = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                stdout, _ = await process.communicate()
                if not is_stopped():
                    subs = stdout.decode().strip().split('\n')
                    t["results"]["subdomains"] = [s for s in subs if s]
                    log(f"Discovered {len(t['results']['subdomains'])} subdomains.", "success")
            else:
                log("subfinder not found. Skipping active discovery.", "warn")
            t["progress"] = 20

        # Module 2: Port Scanning
        if modules.get("port_scanning") and not is_stopped():
            t["activeModule"] = "port_scanning"
            log(f"Step 1: Rapid discovery on {host} (all ports)...")
            cmd_fast = ['nmap', '-p-', '--open', '-T4', host]
            proc = await asyncio.create_subprocess_exec(*cmd_fast, stdout=asyncio.subprocess.PIPE)
            stdout, _ = await proc.communicate()
            
            if is_stopped(): return
            
            found_ports = []
            for line in stdout.decode().split('\n'):
                if "/tcp" in line or "/udp" in line:
                    port = line.split('/')[0].strip()
                    if port.isdigit(): found_ports.append(port)
            
            if found_ports and not is_stopped():
                log(f"Found {len(found_ports)} active ports. Step 2: Running service analysis...", "success")
                ports_arg = ",".join(found_ports)
                cmd_deep = ['nmap', '-sCV', '-p', ports_arg, host]
                proc_deep = await asyncio.create_subprocess_exec(*cmd_deep, stdout=asyncio.subprocess.PIPE)
                stdout_deep, _ = await proc_deep.communicate()
                
                if not is_stopped():
                    ports_results = []
                    for line in stdout_deep.decode().split('\n'):
                        if "/tcp" in line or "/udp" in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                port_val = int(parts[0].split('/')[0])
                                ports_results.append({
                                    "port": port_val, "service": parts[2], "state": parts[1], 
                                    "version": " ".join(parts[3:]) if len(parts) > 3 else "Unknown"
                                })
                    t["results"]["portScanResults"] = ports_results
            t["progress"] = 40

        # Module 3: Tech Stack (Authenticated)
        if modules.get("tech_stack") and not is_stopped():
            t["activeModule"] = "tech_stack"
            log("Analyzing technology stack (using credentials if Greybox)...")
            headers, cookies, _ = build_http_context()
            async with httpx.AsyncClient(headers=headers, cookies=cookies, follow_redirects=True, verify=False) as client:
                try:
                    url = f"https://{host}" if "://" not in host else host
                    resp = await client.get(url, timeout=10)
                    t["results"]["techStack"] = [
                        resp.headers.get("Server", "Unknown Server"),
                        f"Status: {resp.status_code}",
                        resp.headers.get("X-Powered-By", "Hidden Stack")
                    ]
                    if "application/json" in resp.headers.get("Content-Type", ""):
                        t["results"]["techStack"].append("REST API Detected")
                    log("Web surface analysis complete.", "success")
                except Exception as e:
                    log(f"Tech stack analysis failed: {str(e)}", "warn")
            t["progress"] = 60

        # Module 4: OSINT
        if modules.get("osint") and not is_stopped():
            t["activeModule"] = "osint"
            log("Generating target OSINT profile...")
            t["results"]["osintData"] = [
                {"label": "GitHub Search", "description": f"Code patterns for {host}", "url": f"https://github.com/search?q={host}", "type": "code"},
                {"label": "Shodan", "description": "Infrastructure history", "url": f"https://www.shodan.io/search?query={host}", "type": "info"}
            ]
            t["progress"] = 75

        # Module 5: Screenshots (Authenticated)
        if modules.get("screenshotting") and not is_stopped():
            t["activeModule"] = "screenshotting"
            log(f"Visual snapshot of {host} (injecting auth for Greybox)...")
            try:
                from playwright.async_api import async_playwright
                headers, cookies, _ = build_http_context()
                async with async_playwright() as p:
                    browser = await p.chromium.launch()
                    # Apply cookies if present
                    context = await browser.new_context(extra_http_headers=headers)
                    if cookies:
                        formatted_cookies = [{"name": k, "value": v, "domain": host, "path": "/"} for k, v in cookies.items()]
                        await context.add_cookies(formatted_cookies)
                    
                    page = await context.new_page()
                    target_url = host if "://" in host else f"https://{host}"
                    try:
                        await page.goto(target_url, timeout=15000)
                    except:
                        await page.goto(target_url.replace("https", "http"), timeout=15000)
                    
                    screenshot_bytes = await page.screenshot()
                    b64_img = base64.b64encode(screenshot_bytes).decode()
                    t["results"]["screenshots"].append(f"data:image/png;base64,{b64_img}")
                    await browser.close()
                log("Authenticated snapshot captured.", "success")
            except Exception as e:
                log(f"Screenshot failed: {str(e)}", "warn")
            t["progress"] = 90

        if not is_stopped():
            t["status"] = "completed"
            t["progress"] = 100
            t["lastRunAt"] = int(time.time()*1000)
            log("All sequence modules completed.", "success")
        else:
            log("Scan aborted by user.", "warn")
            t["status"] = "failed"

    except Exception as e:
        log(f"Critical workflow error: {str(e)}", "error")
        t["status"] = "failed"
```
