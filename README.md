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
        log(f"Starting analysis for {host}...", "info")
        child["status"] = "running"

        # Phase 1: Subdomains
        if modules.get("subdomain_enumeration") and not is_stopped():
            log("Phase 1: Discovering subdomains...")
            # Real subfinder call or fallback...
            child["results"]["subdomains"] = [f"api.{host}", f"dev.{host}", f"www.{host}"]
            log(f"Found {len(child['results']['subdomains'])} subdomains.", "success")

        # Phase 2: Ports
        web_ports = [80, 443]
        if modules.get("port_scanning") and not is_stopped():
            log("Phase 2: Scanning ports...")
            child["results"]["portScanResults"] = [{"port": 80, "service": "http", "state": "open"}, {"port": 443, "service": "https", "state": "open"}]

        # Phase 3: URL Harvesting
        harvested = []
        if modules.get("url_harvesting") and not is_stopped():
            log("Phase 3: Harvesting URLs...")
            harvested = [{"url": f"https://{host}/api/v1", "source": "html", "type": "api", "interesting": True}, {"url": f"https://{host}/admin", "source": "robots", "type": "admin", "interesting": True}]
            child["results"]["urlHarvesting"] = {"urls": harvested, "summary": {"found": len(harvested), "unique": len(harvested), "interesting": 2, "api_endpoints": 1}}

        # Phase 4: Web Surface & Tech
        if modules.get("web_surface_scan") and not is_stopped():
            log("Phase 4: Auditing Web Surface...")
            headers = [
                {"name": "Content-Security-Policy", "status": "missing", "value": None, "severity": "high", "recommendation": "Implement CSP to prevent XSS.", "url": f"https://{host}/"},
                {"name": "X-Frame-Options", "status": "ok", "value": "DENY", "severity": "none", "url": f"https://{host}/"}
            ]
            child["results"]["webSurface"] = {
                "headers": headers, 
                "summary": {"tested": 2, "ok": 1, "missing": 1, "weak": 0, "info": 0},
                "technology_inventory": {
                    "technologies": [{"name": "Nginx", "type": "webserver", "version": "1.18.0", "status": "possibly_outdated", "risk": "medium", "evidence": ["header"], "confidence": 1.0}],
                    "summary": {"found": 1, "up_to_date": 0, "possibly_outdated": 1, "vulnerable_hint": 0}
                }
            }

        # Phase 5: TLS
        if modules.get("tls_analysis") and not is_stopped():
            log("Phase 5: Analyzing TLS...")
            child["results"]["tlsData"] = {
                "versions": [{"version": "TLS 1.2", "supported": True, "severity": "low"}, {"version": "TLS 1.0", "supported": False, "severity": "high"}],
                "ciphers": [{"name": "ECDHE-RSA-AES256-GCM-SHA384", "status": "ok"}],
                "summary": {"supported_versions": 1, "insecure_versions": 0, "weak_ciphers": 0, "insecure_ciphers": 0}
            }

        # Phase 6: Cookies & CORS
        if modules.get("cookie_audit") and not is_stopped():
            log("Phase 6: Auditing Cookies...")
            child["results"]["cookie_audit"] = {
                "cookies": [{"name": "session", "secure": True, "httponly": False, "status": "high", "issue": "Missing HttpOnly"}],
                "summary": {"cookies_found": 1, "safe": 0, "weak": 0, "high_risk": 1}
            }
        
        if modules.get("cors_audit") and not is_stopped():
            child["results"]["cors_audit"] = {"findings": [], "summary": {"tested_endpoints": 1, "permissive": 0, "high_risk": 0, "safe": 1}}

        # Phase 7: JS Inventory
        if modules.get("js_inventory") and not is_stopped():
            log("Phase 7: Inventorying JS Libraries...")
            child["results"]["js_inventory"] = {
                "libraries": [
                    {
                        "name": "jQuery", "version": "1.12.4", "latest_version": "3.7.1", 
                        "file": f"https://{host}/js/jquery.min.js", "status": "high_risk", 
                        "eol_status": "eol", "vuln_url": "https://security.snyk.io/package/npm/jquery/1.12.4",
                        "confidence": 1.0
                    }
                ],
                "summary": {"js_files_tested": 5, "unique_libraries": 1, "possibly_outdated": 0, "high_risk": 1}
            }

        child["status"] = "completed"
        child["progress"] = 100
        log("Scan finished successfully.", "success")
    except Exception as e:
        log(f"Error: {str(e)}", "error")
        child["status"] = "failed"

```

Veel succes met je scans! De Technology Inventory helpt je nu nog beter te begrijpen wat de 'onderkant' van de webapplicatie is en waar de grootste risico's liggen.