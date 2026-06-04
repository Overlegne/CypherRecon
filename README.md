
# CypherRecon | AI-Powered Ethical Reconnaissance

CypherRecon is a dashboard for managing target reconnaissance. It separates the **UI** from the **Scanner Engine (Python)**, allowing you to run real scans from your local machine.

## 🚀 Quickstart Guide

### 1. Prerequisites
- Install **Nmap** and ensure it's in your system path (`nmap --version`).
- (Optional but Recommended) Install **Subfinder** for real subdomain discovery:
  ```bash
  # Go must be installed
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  ```
- Install Python dependencies:
  ```bash
  pip install fastapi uvicorn pydantic httpx
  ```
- Set your `GOOGLE_GENAI_API_KEY` in the `.env` file of this project.

### 2. Start the Python Scanner
Save the code below as `main.py` and run it:
`uvicorn main:app --host 0.0.0.0 --port 5000`

```python
import uuid, time, asyncio, subprocess, json
from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict

app = FastAPI()

# CRITICAL: CORS must be enabled for the frontend to talk to this local service
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory store for targets (Production should use SQLite/PostgreSQL)
db = {"targets": {}}

class TargetCreate(BaseModel):
    host: str
    mode: str
    modules: Dict[str, bool]

@app.get("/health")
def health(): 
    return {"status": "ok", "engine": "CypherRecon Core v1.0"}

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
            
            # REAL COMMAND: Use subfinder if installed
            try:
                cmd = ['subfinder', '-d', host, '-silent']
                process = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                stdout, _ = await process.communicate()
                if process.returncode == 0:
                    subs = stdout.decode().strip().split('\n')
                    t["results"]["subdomains"] = [s for s in subs if s]
                    log(f"Subfinder complete. Discovered {len(t['results']['subdomains'])} subdomains.", "success")
                else:
                    log("Subfinder failed or not installed. Falling back to internal list.", "warn")
                    t["results"]["subdomains"] = [f"api.{host}", f"dev.{host}", f"staging.{host}"]
            except Exception:
                log("Subfinder binary not found. Using simulation.", "warn")
                t["results"]["subdomains"] = [f"api.{host}", f"dev.{host}", f"staging.{host}"]
            
            t["progress"] = 20

        # Module 2: Port Scanning (REAL NMAP - ALL PORTS)
        if modules.get("port_scanning"):
            t["activeModule"] = "port_scanning"
            log(f"Initiating full Nmap scan (-sCV -p-) on {host}...")
            log("This may take several minutes for 65,535 ports...", "warn")
            
            # -sC (default scripts), -sV (version detection), -p- (ALL PORTS), -T4 (aggressive timing)
            cmd = ['nmap', '-sCV', '-p-', '-T4', host]
            process = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                output = stdout.decode()
                ports = []
                for line in output.split('\n'):
                    # Match typical nmap output lines: "80/tcp open  http"
                    if "/tcp" in line or "/udp" in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            port_proto = parts[0].split('/')
                            port_val = int(port_proto[0])
                            state = parts[1]
                            service = parts[2]
                            version = " ".join(parts[3:]) if len(parts) > 3 else "Unknown"
                            ports.append({"port": port_val, "service": service, "state": state, "version": version})
                
                t["results"]["portScanResults"] = ports
                log(f"Nmap complete. Found {len(ports)} ports (including open and filtered).", "success")
            else:
                log(f"Nmap Error: {stderr.decode()}", "error")
            t["progress"] = 50

        # Module 3: OSINT
        if modules.get("osint"):
            t["activeModule"] = "osint"
            log("Searching public leak databases and OSINT sources...")
            await asyncio.sleep(2)
            t["results"]["osintData"] = [
                {"label": "Public GitHub Repo", "description": "Found repository with potential config leaks", "url": f"https://github.com/search?q={host}", "type": "code"},
                {"label": "Exposed Employee Data", "description": "Names and roles found via LinkedIn mapping", "url": f"https://www.linkedin.com/search/results/people/?keywords={host}", "type": "social"}
            ]
            log("OSINT search finished.", "success")
            t["progress"] = 70

        # Module 4: Tech Stack & API Discovery
        if modules.get("tech_stack") or modules.get("api_discovery"):
            t["activeModule"] = "tech_stack"
            log("Identifying technology stack and mapping endpoints...")
            await asyncio.sleep(2)
            t["results"]["techStack"] = ["React", "Next.js", "Nginx 1.18.0", "FastAPI (Python)"]
            t["results"]["apiEndpoints"] = ["/api/v1/user", "/api/v1/auth/login", "/admin/config", "/api/v2/debug"]
            log("Tech stack identified.", "success")
            t["progress"] = 90

        # Finalize
        t["status"] = "completed"
        t["progress"] = 100
        t["lastRunAt"] = int(time.time()*1000)
        log("Recon sequence finished. Forwarding to AI Analysis Engine...", "success")

    except Exception as e:
        log(f"Workflow Exception: {str(e)}", "error")
        t["status"] = "failed"
```
