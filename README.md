
# CypherRecon | AI-Powered Ethical Reconnaissance

CypherRecon is een dashboard voor het beheren van target reconnaissance. Het scheidt de **UI** van de **Scanner Engine (Python)**, waardoor je echte scans kunt uitvoeren vanaf je lokale machine.

## 🚀 Snelstartgids (Testen)

### 1. Voorbereiding
- Installeer **Nmap** en zorg dat het in je systeem-pad staat (`nmap --version` moet werken in je terminal).
- Installeer Python dependencies:
  ```bash
  pip install fastapi uvicorn pydantic
  ```

### 2. Start de Python Scanner
Sla de onderstaande code op als `main.py` en start deze met:
`uvicorn main:app --host 0.0.0.0 --port 5000`

```python
import uuid, time, asyncio, subprocess, json
from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict

app = FastAPI()

# CRITICAL: Sta verbindingen toe vanuit de browser (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In productie vervangen door specifiek adres
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
        "results": {"logs": [], "subdomains": [], "portScanResults": []}
    }
    db["targets"][new_id] = target
    return target

@app.post("/targets/{id}/scan")
def run_scan(id: str, background_tasks: BackgroundTasks):
    if id in db["targets"]:
        db["targets"][id]["status"] = "running"
        db["targets"][id]["progress"] = 0
        db["targets"][id]["results"] = {"logs": [], "subdomains": [], "portScanResults": []}
        background_tasks.add_task(execute_real_nmap, id)
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

async def execute_real_nmap(id: str):
    t = db["targets"][id]
    host = t["host"]
    
    def log(msg, type="info"):
        t["results"]["logs"].append({
            "id": str(uuid.uuid4()), "timestamp": int(time.time()*1000),
            "message": msg, "type": type
        })

    try:
        log(f"Initiating deep scan sequence on {host}...", "info")
        t["progress"] = 10
        
        # ECHTE NMAP CALL: -sV (service detection) -p- (alle poorten)
        # Voor testen gebruiken we vaak een kleinere range voor snelheid: 1-1000
        cmd = ['nmap', '-sV', '-p', '1-1000', host]
        log(f"Executing: {' '.join(cmd)}", "info")
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        t["progress"] = 40
        stdout, stderr = await process.communicate()
        
        if process.returncode == 0:
            output = stdout.decode()
            log("Nmap scan completed successfully.", "success")
            ports = []
            for line in output.split('\n'):
                if "/tcp" in line and "open" in line:
                    parts = line.split()
                    port_val = int(parts[0].split('/')[0])
                    service = parts[2]
                    version = " ".join(parts[3:]) if len(parts) > 3 else "Unknown"
                    ports.append({"port": port_val, "service": service, "state": "open", "version": version})
            
            t["results"]["portScanResults"] = ports
            t["progress"] = 100
            t["status"] = "completed"
            t["lastRunAt"] = int(time.time()*1000)
        else:
            log(f"Nmap error: {stderr.decode()}", "error")
            t["status"] = "failed"

    except Exception as e:
        log(f"Engine Exception: {str(e)}", "error")
        t["status"] = "failed"
```

### 3. Troubleshooting
- Zie je "Engine Offline"? Open de browser console (F12) om te zien of er CORS-fouten zijn.
- Controleer of je in de CypherRecon Settings de URL op `http://localhost:5000` hebt gezet.
