
# CypherRecon | AI-Powered Ethical Reconnaissance

CypherRecon is een dashboard voor het beheren van doelwit-reconnaissance. Het scheidt de **UI** van de **Scanner Engine (Python)**, zodat je echte scans vanaf je lokale machine kunt draaien.

## 🚀 Quickstart Guide

### 1. Vereisten
- Installeer **Nmap** en zorg dat het in je systeem-pad staat (`nmap --version`).
- Installeer **Subfinder** voor echte subdomain discovery:
  ```bash
  # Go moet geïnstalleerd zijn
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  ```
  **BELANGRIJK:** Voeg de Go bin-map toe aan je PATH (voeg dit toe aan je `.bashrc` of `.zshrc`):
  `export PATH=$PATH:$(go env GOPATH)/bin`

- Installeer Python afhankelijkheden:
  ```bash
  pip install fastapi uvicorn pydantic httpx
  ```
- **API Key**: Haal een gratis API-key op via [Google AI Studio](https://aistudio.google.com/app/apikey) en zet deze in het `.env` bestand in de hoofdmap van dit project:
  `GOOGLE_GENAI_API_KEY=jouw_sleutel_hier`

### 2. Start de Python Scanner
Sla de onderstaande code op als `main.py` op je lokale machine en start deze:
`uvicorn main:app --host 0.0.0.0 --port 5000`

```python
import uuid, time, asyncio, subprocess, json, httpx, os, shutil
from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict

app = FastAPI()

# CRITICAL: CORS moet aanstaan zodat de frontend met deze lokale service kan praten
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory opslag
db = {"targets": {}}

class TargetCreate(BaseModel):
    host: str
    mode: str
    modules: Dict[str, bool]

@app.get("/health")
def health(): 
    return {"status": "ok", "engine": "CypherRecon Core v1.2"}

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
        "results": {"logs": [], "subdomains": [], "portScanResults": [], "osintData": [], "techStack": [], "apiEndpoints": [], "screenshots": []}
    }
    db["targets"][new_id] = target
    return target

@app.post("/targets/{id}/scan")
def run_scan(id: str, background_tasks: BackgroundTasks):
    if id in db["targets"]:
        db["targets"][id]["status"] = "running"
        db["targets"][id]["progress"] = 0
        db["targets"][id]["results"] = {"logs": [], "subdomains": [], "portScanResults": [], "osintData": [], "techStack": [], "apiEndpoints": [], "screenshots": []}
        background_tasks.add_task(execute_full_workflow, id)
        return {"status": "started"}
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
    
    def log(msg, type="info"):
        t["results"]["logs"].append({
            "id": str(uuid.uuid4()), "timestamp": int(time.time()*1000),
            "message": msg, "type": type
        })

    try:
        # Module 1: Subdomain Enumeration
        if modules.get("subdomain_enumeration"):
            t["activeModule"] = "subdomain_enumeration"
            log(f"Starting subdomain discovery for {host}...")
            
            # Zoek naar subfinder binary
            binary = shutil.which('subfinder')
            if not binary:
                # Probeer veelvoorkomende Go installatiepaden
                go_path = os.path.join(os.path.expanduser("~"), "go", "bin", "subfinder")
                if os.path.exists(go_path):
                    binary = go_path
            
            if binary:
                try:
                    log(f"Using subfinder binary at: {binary}")
                    cmd = [binary, '-d', host, '-silent']
                    process = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                    stdout, stderr = await process.communicate()
                    if process.returncode == 0:
                        subs = stdout.decode().strip().split('\n')
                        t["results"]["subdomains"] = [s for s in subs if s]
                        log(f"Subfinder complete. Discovered {len(t['results']['subdomains'])} subdomains.", "success")
                    else:
                        log(f"Subfinder error: {stderr.decode()}", "warn")
                except Exception as e:
                    log(f"Failed to run subfinder: {str(e)}", "error")
            else:
                log("Subfinder binary not found in PATH or ~/go/bin/. Run 'go install ...' and check instructions.", "warn")
            
            t["progress"] = 20

        # Module 2: Two-Stage Port Scanning (FAST -> DEEP)
        if modules.get("port_scanning"):
            t["activeModule"] = "port_scanning"
            log(f"Stage 1: Fast discovery of all 65,535 ports on {host}...")
            
            cmd_fast = ['nmap', '-p-', '--open', '-T4', host]
            process = await asyncio.create_subprocess_exec(*cmd_fast, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await process.communicate()
            
            found_ports = []
            if process.returncode == 0:
                output = stdout.decode()
                for line in output.split('\n'):
                    if "/tcp" in line or "/udp" in line:
                        port = line.split('/')[0].strip()
                        if port.isdigit():
                            found_ports.append(port)
            
            if not found_ports:
                log("No open ports found. The target might be down or blocking ICMP/discovery.", "warn")
                t["progress"] = 50
            else:
                log(f"Found active ports: {', '.join(found_ports)}. Starting Stage 2 (Service Analysis)...", "success")
                t["progress"] = 35
                
                ports_arg = ",".join(found_ports)
                cmd_deep = ['nmap', '-sCV', '-p', ports_arg, host]
                process = await asyncio.create_subprocess_exec(*cmd_deep, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                stdout, _ = await process.communicate()
                
                if process.returncode == 0:
                    output = stdout.decode()
                    ports_results = []
                    for line in output.split('\n'):
                        if "/tcp" in line or "/udp" in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                port_proto = parts[0].split('/')
                                port_val = int(port_proto[0])
                                state = parts[1]
                                service = parts[2]
                                version = " ".join(parts[3:]) if len(parts) > 3 else "Unknown"
                                ports_results.append({"port": port_val, "service": service, "state": state, "version": version})
                    t["results"]["portScanResults"] = ports_results
                    log(f"Deep scan complete. Identified {len(ports_results)} services.", "success")

            t["progress"] = 50

        # Module 3: OSINT Intelligence
        if modules.get("osint"):
            t["activeModule"] = "osint"
            log("Building OSINT intelligence profile...")
            t["results"]["osintData"] = [
                {"label": "GitHub Search", "description": f"Target specific code patterns for {host}", "url": f"https://github.com/search?q={host}", "type": "code"},
                {"label": "Shodan Historical", "description": "View historical IP and banner data", "url": f"https://www.shodan.io/search?query={host}", "type": "info"},
                {"label": "LinkedIn Profile", "description": "Identify associated staff and infrastructure managers", "url": f"https://www.linkedin.com/search/results/all/?keywords={host}", "type": "social"}
            ]
            t["progress"] = 70

        # Module 4: Tech Stack Analysis
        if modules.get("tech_stack"):
            t["activeModule"] = "tech_stack"
            log(f"Analyzing server headers and fingerprints for {host}...")
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    target_url = host if "://" in host else f"https://{host}"
                    resp = await client.get(target_url, follow_redirects=True)
                    server = resp.headers.get("Server", "Unknown")
                    framework = resp.headers.get("X-Powered-By", "Unknown")
                    tech = [f"Web Server: {server}"]
                    if framework != "Unknown": tech.append(f"Framework: {framework}")
                    t["results"]["techStack"] = tech
                    log(f"Tech stack detected: {', '.join(tech)}", "success")
            except Exception as e:
                log(f"Tech analysis failed (HTTPS connection error)", "warn")
                t["results"]["techStack"] = ["Web Server: Unknown"]
            t["progress"] = 90

        # Finalize
        t["status"] = "completed"
        t["progress"] = 100
        t["lastRunAt"] = int(time.time()*1000)
        log("Full reconnaissance sequence finished.", "success")

    except Exception as e:
        log(f"Fatal Workflow Exception: {str(e)}", "error")
        t["status"] = "failed"
```
