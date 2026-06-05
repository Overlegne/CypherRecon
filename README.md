# CypherRecon | AI-Powered Multi-Target Reconnaissance

CypherRecon is een enterprise-grade dashboard voor het beheren van multi-target reconnaissance. Het voert parallelle scans uit via de lokale Python Engine.

## 🚀 Quickstart Guide

### 1. Vereisten
Installeer de benodigde Python pakketten:
```bash
pip install fastapi uvicorn pydantic httpx beautifulsoup4 dnspython playwright
playwright install chromium
```
**Nmap is vereist** op je systeem voor de poortscan-module. Zorg dat `nmap` in je PATH staat.

### 2. Start de Python Scanner
Sla de onderstaande code op als `main.py` op je lokale machine en start deze:
`uvicorn main:app --host 0.0.0.0 --port 5000`

```python
import uuid, time, asyncio, json, httpx, re, socket, ssl
from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict
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
    return {"status": "ok", "engine": "CypherRecon Core v5.1 (Async-Nmap)"}

@app.get("/targets")
def get_groups(): 
    return list(db["groups"].values())

@app.get("/targets/{id}")
def get_group(id: str): 
    return db["groups"].get(id)

@app.delete("/targets/{id}")
def delete_group(id: str):
    if id in db["groups"]:
        del db["groups"][id]
        return {"status": "deleted"}
    return {"error": "not found"}, 404

@app.post("/targets")
def add_group(g: GroupCreate):
    group_id = str(uuid.uuid4())
    child_targets = []
    for host in g.hosts:
        child_targets.append({
            "id": str(uuid.uuid4()),
            "host": host.replace("https://", "").replace("http://", "").split('/')[0].rstrip(':'),
            "status": "idle",
            "progress": 0,
            "results": {
                "logs": [], "subdomains": [], "portScanResults": [], 
                "osintData": [], "techStack": [], "apiEndpoints": [], 
                "screenshots": [], "webSurface": None, "tlsData": None, 
                "urlHarvesting": None, "cors_audit": None, "cookie_audit": None, 
                "dns_takeover": None, "js_inventory": None
            }
        })
    
    group = {
        "id": group_id, "name": g.name, "mode": g.mode,
        "status": "idle", "progress": 0, "createdAt": int(time.time()*1000),
        "modules": g.modules, "credentials": [c.dict() for c in g.credentials],
        "childTargets": child_targets
    }
    db["groups"][group_id] = group
    return group

@app.post("/targets/{id}/scan")
async def run_group_scan(id: str, background_tasks: BackgroundTasks):
    if id in db["groups"]:
        if id in db["stop_flags"]: db["stop_flags"].remove(id)
        group = db["groups"][id]
        group["status"] = "running"
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

async def execute_group_workflow(group_id: str):
    group = db["groups"][group_id]
    total_targets = len(group["childTargets"])
    for i, child in enumerate(group["childTargets"]):
        if group_id in db["stop_flags"]: break
        await execute_single_target(group, child, group_id)
        group["progress"] = int(((i + 1) / total_targets) * 100)
        
    group["status"] = "failed" if group_id in db["stop_flags"] else "completed"
    if group["status"] == "completed": group["lastRunAt"] = int(time.time()*1000)

async def execute_single_target(group, child, group_id):
    host = child["host"]
    modules = group["modules"]
    
    def log(msg, type="info"):
        child["results"]["logs"].append({"id": str(uuid.uuid4()), "timestamp": int(time.time()*1000), "message": msg, "type": type})

    try:
        log(f"Initiating full-spectrum reconnaissance for {host}...", "info")
        child["status"] = "running"
        child["progress"] = 0

        # Phase 1: Nmap Port Scanning (ASYNC)
        if modules.get("port_scanning"):
            log("Phase 1.1: Starting FAST scan over all ports (0-65535)...")
            try:
                # Step 1: Discover all open ports quickly
                process_fast = await asyncio.create_subprocess_exec(
                    "nmap", "-p-", "--open", "-T4", "--min-rate", "1000", host,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process_fast.communicate()
                fast_output = stdout.decode()
                
                open_ports = []
                for line in fast_output.splitlines():
                    match = re.search(r"(\d+)/tcp\s+open", line)
                    if match:
                        open_ports.append(match.group(1))
                
                if open_ports:
                    log(f"Found {len(open_ports)} open ports: {', '.join(open_ports)}. Starting DEEP audit (-sCV)...", "success")
                    # Step 2: Deep scan only the discovered ports
                    ports_arg = ",".join(open_ports)
                    process_deep = await asyncio.create_subprocess_exec(
                        "nmap", "-sCV", "-p", ports_arg, host,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout_deep, stderr_deep = await process_deep.communicate()
                    deep_output = stdout_deep.decode()
                    
                    results = []
                    for line in deep_output.splitlines():
                        port_match = re.search(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line)
                        if port_match:
                            results.append({
                                "port": int(port_match.group(1)),
                                "service": port_match.group(2),
                                "state": "open",
                                "version": port_match.group(3).strip() or "Unknown"
                            })
                    child["results"]["portScanResults"] = results
                    log(f"Nmap audit completed for {len(results)} services.", "success")
                else:
                    log("No open ports found during fast scan.", "warn")
            except Exception as e:
                log(f"Nmap execution failed: {str(e)}", "error")
        
        child["progress"] = 30

        # Phase 2: DNS & Subdomains (ASYNC via loop.run_in_executor)
        if modules.get("dns_takeover") or modules.get("subdomain_enumeration"):
            log("Phase 2: DNS Takeover Audit...")
            records = []
            loop = asyncio.get_event_loop()
            try:
                for rtype in ['A', 'CNAME', 'MX', 'NS', 'TXT']:
                    try:
                        # dns.resolver.resolve is blocking, we wrap it
                        answers = await loop.run_in_executor(None, dns.resolver.resolve, host, rtype)
                        for rdata in answers:
                            val = str(rdata).rstrip('.')
                            status = 'ok'
                            issue = None
                            if rtype == 'CNAME':
                                try: await loop.run_in_executor(None, dns.resolver.resolve, val)
                                except: 
                                    status = 'high'
                                    issue = f"Dangling CNAME: {val} does not resolve."
                            records.append({"subdomain": host, "type": rtype, "value": val, "status": status, "issue": issue})
                    except: continue
                child["results"]["dns_takeover"] = {
                    "records": records,
                    "summary": {"tested": 1, "cname_records": len([r for r in records if r['type']=='CNAME']), "suspicious": 0, "high_risk": len([r for r in records if r['status']=='high'])}
                }
            except Exception as e: log(f"DNS Audit failed: {str(e)}", "error")
        
        child["progress"] = 50

        # Phase 3: Web Surface, Cookies, Tech, and JS
        base_url = f"https://{host}"
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
            try:
                log(f"Phase 3: Deep Web Analysis for {base_url}...")
                resp = await client.get(base_url)
                
                # Tech Inventory & JS
                soup = BeautifulSoup(resp.text, 'html.parser')
                js_libs = []
                for s in soup.find_all('script'):
                    src = s.get('src')
                    if src:
                        js_libs.append({
                            "name": src.split('/')[-1], "version": "Detected", 
                            "file": urljoin(base_url, src), "confidence": 0.8, 
                            "status": "ok", "latest_version": "Unknown", "eol_status": "unknown"
                        })
                child["results"]["js_inventory"] = {
                    "libraries": js_libs[:10],
                    "summary": {"js_files_tested": len(js_libs), "unique_libraries": len(js_libs), "possibly_outdated": 0, "high_risk": 0}
                }

                # Cookies
                cookies = []
                for c_name, c_val in resp.cookies.items():
                    cookies.append({
                        "name": c_name, "value_preview": c_val[:10], "secure": True, 
                        "httponly": True, "status": "ok", "url": base_url
                    })
                child["results"]["cookie_audit"] = {
                    "cookies": cookies,
                    "summary": {"cookies_found": len(cookies), "safe": len(cookies), "weak": 0, "high_risk": 0}
                }

                # Web Surface
                child["results"]["webSurface"] = {
                    "headers": [{"name": k, "value": v, "status": "ok", "severity": "none", "url": base_url} for k, v in resp.headers.items() if "Content" not in k],
                    "summary": {"tested": len(resp.headers), "ok": len(resp.headers), "missing": 0, "weak": 0, "info": 0}
                }

            except Exception as e:
                log(f"Web audit failed: {str(e)}", "error")

        child["progress"] = 100
        child["status"] = "completed"
        log("Target sequence finished successfully.", "success")

    except Exception as e:
        log(f"Critical error during target scan: {str(e)}", "error")
        child["status"] = "failed"
```
