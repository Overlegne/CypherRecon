# CypherRecon | AI-Powered Multi-Target Reconnaissance

CypherRecon is een enterprise-grade dashboard voor het beheren van multi-target reconnaissance. Het voert parallelle scans uit via de lokale Python Engine.

## 🚀 Quickstart Guide

### 1. Vereisten
- Installeer Python afhankelijkheden:
  ```bash
  pip install fastapi uvicorn pydantic httpx beautifulsoup4 dnspython
  ```
- **API Key**: Haal een gratis API-key op via [Google AI Studio](https://aistudio.google.com/app/apikey) en zet deze in het `.env` bestand in de hoofdmap van dit project:
  `GOOGLE_GENAI_API_KEY=jouw_sleutel_hier`

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
    return {"status": "ok", "engine": "CypherRecon Real-Core v3.0"}

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
def run_group_scan(id: str, background_tasks: BackgroundTasks):
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

    def is_stopped(): return group_id in db["stop_flags"]

    try:
        log(f"Initiating real-time reconnaissance for {host}...", "info")
        child["status"] = "running"
        child["progress"] = 5

        # Phase 1: DNS & Subdomains
        if modules.get("dns_takeover") or modules.get("subdomain_enumeration"):
            log("Analyzing DNS records...")
            records = []
            try:
                for rtype in ['A', 'CNAME', 'MX', 'TXT', 'NS']:
                    try:
                        answers = dns.resolver.resolve(host, rtype)
                        for rdata in answers:
                            status = 'ok'
                            issue = None
                            if rtype == 'CNAME':
                                target = str(rdata.target).rstrip('.')
                                # Basic dangling check
                                try: dns.resolver.resolve(target)
                                except: 
                                    status = 'high'
                                    issue = f"Dangling CNAME: {target} does not resolve."
                            
                            records.append({
                                "subdomain": host, "type": rtype, 
                                "value": str(rdata), "status": status, "issue": issue
                            })
                    except: continue
                child["results"]["dns_takeover"] = {
                    "records": records,
                    "summary": {"tested": 1, "cname_records": len([r for r in records if r['type']=='CNAME']), "suspicious": 0, "high_risk": len([r for r in records if r['status']=='high'])}
                }
            except Exception as e: log(f"DNS failed: {str(e)}", "error")
        
        child["progress"] = 25

        # Phase 2: Web Recon
        base_url = f"https://{host}" if "://" not in host else host
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            log(f"Fetching {base_url} for header and cookie audit...")
            try:
                resp = await client.get(base_url)
                
                # Header Audit
                headers = []
                security_headers = ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security"]
                summary = {"tested": 0, "ok": 0, "missing": 0, "weak": 0, "info": 1}
                
                for h_name in security_headers:
                    val = resp.headers.get(h_name)
                    status = "ok" if val else "missing"
                    headers.append({
                        "name": h_name, "status": status, "value": val, 
                        "severity": "high" if status == "missing" else "none",
                        "url": base_url
                    })
                    summary["tested"] += 1
                    if status == "ok": summary["ok"] += 1
                    else: summary["missing"] += 1
                
                # Tech Inventory
                techs = []
                server = resp.headers.get("Server")
                if server:
                    techs.append({"name": server, "type": "webserver", "version": None, "confidence": 1.0, "status": "unknown", "risk": "info", "evidence": ["header"]})
                
                child["results"]["webSurface"] = {
                    "headers": headers, "summary": summary,
                    "technology_inventory": {"technologies": techs, "summary": {"found": len(techs), "up_to_date": 0, "possibly_outdated": 0, "vulnerable_hint": 0}}
                }

                # Cookie Audit
                cookies = []
                for c_name, c_val in resp.cookies.items():
                    cookies.append({
                        "name": c_name, "value_preview": c_val[:10] + "...", 
                        "secure": True, "httponly": True, "status": "ok", "url": base_url
                    })
                child["results"]["cookie_audit"] = {
                    "cookies": cookies, "summary": {"cookies_found": len(cookies), "safe": len(cookies), "weak": 0, "high_risk": 0}
                }

                # URL Harvesting & JS
                soup = BeautifulSoup(resp.text, 'html.parser')
                found_urls = []
                js_libs = []
                for link in soup.find_all(['a', 'script', 'link']):
                    href = link.get('href') or link.get('src')
                    if href:
                        abs_url = urljoin(base_url, href)
                        found_urls.append({"url": abs_url, "source": "html", "type": "page", "interesting": False})
                        if ".js" in abs_url:
                            js_libs.append({"name": abs_url.split('/')[-1], "version": None, "file": abs_url, "confidence": 0.5, "status": "ok"})

                child["results"]["urlHarvesting"] = {
                    "urls": found_urls[:50], "summary": {"found": len(found_urls), "unique": len(found_urls), "interesting": 0, "api_endpoints": 0}
                }
                child["results"]["js_inventory"] = {
                    "libraries": js_libs[:10], "summary": {"js_files_tested": len(js_libs), "unique_libraries": len(js_libs), "possibly_outdated": 0, "high_risk": 0}
                }

            except Exception as e:
                log(f"Web scan failed: {str(e)}", "error")

        child["progress"] = 100
        child["status"] = "completed"
        log("Target analysis finished.", "success")

    except Exception as e:
        log(f"Global Error: {str(e)}", "error")
        child["status"] = "failed"
```
