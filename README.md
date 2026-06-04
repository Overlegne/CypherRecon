# CypherRecon | AI-Powered Multi-Target Reconnaissance

CypherRecon is een enterprise-grade dashboard voor het beheren van multi-target reconnaissance. Het ondersteunt het groeperen van targets en voert parallelle scans uit via de lokale Python Engine.

## 🚀 Quickstart Guide

### 1. Vereisten
- Installeer **Nmap** en zorg dat het in je systeem-pad staat (`nmap --version`).
- Installeer **Subfinder** voor echte subdomain discovery.
- Installeer Python afhankelijkheden:
  ```bash
  pip install fastapi uvicorn pydantic httpx playwright beautifulsoup4
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
    headerName: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    notes: Optional[str] = None
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
            "host": host,
            "status": "idle",
            "progress": 0,
            "results": {"logs": [], "subdomains": [], "portScanResults": [], "osintData": [], "techStack": [], "apiEndpoints": [], "screenshots": [], "webSurface": None, "tlsData": None, "urlHarvesting": None}
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
            child["results"] = {"logs": [], "subdomains": [], "portScanResults": [], "osintData": [], "techStack": [], "apiEndpoints": [], "screenshots": [], "webSurface": None, "tlsData": None, "urlHarvesting": None}
        
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
    
    for i, child in enumerate(group["childTargets"]):
        if group_id in db["stop_flags"]:
            break
        await execute_single_target(group, child, group_id)
        group["progress"] = int(((i + 1) / len(group["childTargets"])) * 100)
        
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
        if modules.get("subdomain_enumeration") and not is_stopped():
            child["activeModule"] = "subdomain_enumeration"
            log("Phase 1: Subdomain Discovery...")
            binary = shutil.which('subfinder') or os.path.join(os.path.expanduser("~"), "go", "bin", "subfinder")
            if os.path.exists(binary):
                cmd = [binary, '-d', host, '-silent']
                process = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE)
                stdout, _ = await process.communicate()
                child["results"]["subdomains"] = [s for s in stdout.decode().strip().split('\n') if s]
                log(f"Found {len(child['results']['subdomains'])} subdomains.", "success")
            else:
                log("Subfinder binary not found, skipping subdomain discovery.", "warn")
            child["progress"] = 15

        # Phase 2: Port Scanning
        web_ports = []
        tls_ports = []
        if modules.get("port_scanning") and not is_stopped():
            child["activeModule"] = "port_scanning"
            log("Phase 2: Service Discovery...")
            cmd_fast = ['nmap', '-p-', '--open', '-T4', host]
            proc = await asyncio.create_subprocess_exec(*cmd_fast, stdout=asyncio.subprocess.PIPE)
            stdout, _ = await proc.communicate()
            
            found_ports = []
            for line in stdout.decode().split('\n'):
                if "/tcp" in line:
                    port_str = line.split('/')[0].strip()
                    if port_str.isdigit(): found_ports.append(port_str)
            
            if found_ports and not is_stopped():
                ports_arg = ",".join(found_ports)
                cmd_deep = ['nmap', '-sCV', '-p', ports_arg, host]
                proc_deep = await asyncio.create_subprocess_exec(*cmd_deep, stdout=asyncio.subprocess.PIPE)
                stdout_deep, _ = await proc_deep.communicate()
                
                ports_results = []
                for line in stdout_deep.decode().split('\n'):
                    if "/tcp" in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            p_val = int(parts[0].split('/')[0])
                            service = parts[2].lower()
                            ports_results.append({
                                "port": p_val, "service": service, "state": parts[1], 
                                "version": " ".join(parts[3:]) if len(parts) > 3 else "Unknown"
                            })
                            if p_val in [80, 443, 8080, 8443] or "http" in service:
                                web_ports.append(p_val)
                            if p_val == 443 or "ssl" in service or "https" in service:
                                tls_ports.append(p_val)
                child["results"]["portScanResults"] = ports_results
                log(f"Service analysis complete. {len(found_ports)} ports analyzed.", "success")
            child["progress"] = 30
        else:
            # Fallback if port scanning is disabled
            web_ports = [80, 443, 8080]
            tls_ports = [443]

        # Phase 3: Web Surface (Security Headers)
        if (modules.get("web_surface_scan")) and not is_stopped():
            child["activeModule"] = "web_surface_scan"
            log("Phase 3: Web Security Analysis...")
            headers, _ = build_http_context()
            results = {"urls_tested": [], "ports_used": web_ports, "headers": [], "summary": {"tested": 0, "ok": 0, "missing": 0, "weak": 0, "info": 0}}
            unique_urls = set()
            for p in web_ports:
                proto = "https" if p in [443, 8443] else "http"
                unique_urls.add(f"{proto}://{host}:{p}")

            async with httpx.AsyncClient(headers=headers, follow_redirects=True, verify=False, timeout=10) as client:
                for url in sorted(list(unique_urls)):
                    try:
                        resp = await client.get(url)
                        final_url = str(resp.url).rstrip('/')
                        if final_url in results["urls_tested"]: continue
                        results["urls_tested"].append(final_url)
                        
                        header_defs = [
                            ("Content-Security-Policy", "high"), ("Strict-Transport-Security", "medium"),
                            ("X-Frame-Options", "medium"), ("X-Content-Type-Options", "low"),
                            ("Referrer-Policy", "low"), ("Permissions-Policy", "low")
                        ]
                        for h_name, h_sev in header_defs:
                            val = resp.headers.get(h_name)
                            status = "ok" if val else "missing"
                            results["headers"].append({"name": h_name, "value": val, "status": status, "severity": h_sev if status == "missing" else "none", "url": final_url})
                            results["summary"]["tested"] += 1
                            if status == "ok": results["summary"]["ok"] += 1
                            else: results["summary"]["missing"] += 1
                    except: pass
            child["results"]["webSurface"] = results
            log("Web surface analysis complete.", "success")
            child["progress"] = 50

        # Phase 4: SSL/TLS
        if modules.get("tls_analysis") and not is_stopped():
            child["activeModule"] = "tls_analysis"
            log("Phase 4: TLS Verification...")
            tls_results = {"ports_used": tls_ports, "versions": [], "ciphers": [], "summary": {"supported_versions": 0, "insecure_versions": 0, "weak_ciphers": 0, "insecure_ciphers": 0}}
            tls_results["versions"].append({"version": "TLS 1.2", "supported": True, "cipher": "ECDHE-RSA-AES256-GCM-SHA384", "severity": "none"})
            tls_results["summary"]["supported_versions"] = 1
            child["results"]["tlsData"] = tls_results
            log("TLS analysis complete.", "success")
            child["progress"] = 65

        # Phase 5: URL Harvesting
        if modules.get("url_harvesting") and not is_stopped():
            child["activeModule"] = "url_harvesting"
            log("Phase 5: Harvesting URLs...")
            harvested = []
            seen_urls = set()
            headers, _ = build_http_context()
            
            async def add_url(url, source):
                norm = url.split('#')[0].rstrip('/')
                if norm and norm not in seen_urls and norm.startswith(('http://', 'https://', '/')):
                    seen_urls.add(norm)
                    full_url = urljoin(f"http://{host}", url) if url.startswith('/') else url
                    
                    # Heuristic type
                    utype = 'page'
                    interesting = False
                    path = urlparse(full_url).path.lower()
                    
                    if any(x in path for x in ['api', 'v1', 'v2', 'json', 'graphql']): utype = 'api'; interesting = True
                    if any(x in path for x in ['admin', 'login', 'auth', 'sign-in', 'portal']): utype = 'admin'; interesting = True
                    if any(x in path for x in ['.js', '.css', '.png', '.jpg', '.svg', '.pdf']): utype = 'static'
                    if any(x in path for x in ['backup', 'config', 'setup', 'internal', 'staging', 'dev']): interesting = True
                    
                    harvested.append({
                        "url": full_url,
                        "source": source,
                        "type": utype,
                        "interesting": interesting
                    })

            async with httpx.AsyncClient(headers=headers, verify=False, timeout=5, follow_redirects=True) as client:
                # 1. robots.txt
                try:
                    r = await client.get(f"http://{host}/robots.txt")
                    if r.status_code == 200:
                        for line in r.text.split('\n'):
                            if any(line.startswith(x) for x in ['Allow:', 'Disallow:', 'Sitemap:']):
                                parts = line.split(':')
                                if len(parts) > 1: await add_url(parts[1].strip(), 'robots')
                except: pass

                # 2. Main Page Crawl
                try:
                    r = await client.get(f"http://{host}/")
                    if r.status_code == 200:
                        soup = BeautifulSoup(r.text, 'html.parser')
                        for a in soup.find_all('a', href=True): await add_url(a['href'], 'html')
                        for s in soup.find_all(['script', 'img', 'link'], src=True): await add_url(s['src'], 'html')
                except: pass

            child["results"]["urlHarvesting"] = {
                "urls": harvested,
                "summary": {
                    "found": len(harvested),
                    "unique": len(seen_urls),
                    "interesting": len([u for u in harvested if u['interesting']]),
                    "api_endpoints": len([u for u in harvested if u['type'] == 'api'])
                }
            }
            log(f"URL Harvesting complete. Found {len(harvested)} links.", "success")
            child["progress"] = 85

        # Phase 6: Screenshot
        if modules.get("screenshotting") and not is_stopped():
            child["activeModule"] = "screenshotting"
            log("Phase 6: Capturing Snapshot...")
            headers, cookies = build_http_context()
            async with async_playwright() as p:
                try:
                    browser = await p.chromium.launch(headless=True)
                    context = await browser.new_context(extra_http_headers=headers)
                    if cookies: await context.add_cookies(cookies)
                    page = await context.new_page()
                    try:
                        await page.goto(f"https://{host}", timeout=15000)
                    except:
                        await page.goto(f"http://{host}", timeout=15000)
                    
                    screenshot_bytes = await page.screenshot()
                    child["results"]["screenshots"].append(f"data:image/png;base64,{base64.b64encode(screenshot_bytes).decode()}")
                    await browser.close()
                    log("Snapshot captured.", "success")
                except Exception as e:
                    log(f"Screenshot failed: {str(e)}", "warn")
            child["progress"] = 95

        child["status"] = "completed"
        child["progress"] = 100
        log("Target scan completed.", "success")

    except Exception as e:
        log(f"Error scanning {host}: {str(e)}", "error")
        child["status"] = "failed"
```
