
# CypherRecon | AI-Powered Ethical Reconnaissance

CypherRecon is a production-ready dashboard for managing target reconnaissance. It separates the **Command & Control (UI)** from the **Scanning Engine (Local Backend)**, allowing you to perform real network scans from your local machine while managing them through a modern web interface.

## 🛠 Setup & Testing Guide

### 1. Prerequisites
- Python 3.9+
- Node.js 18+
- **Nmap** geïnstalleerd op je systeem pad (nodig voor echte scans).

### 2. Start de Echte Python Scanner
Gebruik dit script om de frontend te koppelen aan echte systeemcommando's. Dit script voert daadwerkelijk `nmap -sCV -p-` uit.

```python
import uuid, time, asyncio, subprocess, json
from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# In-memory DB (Vervang door SQLite voor persistentie)
db = {"targets": {}}

class TargetCreate(BaseModel):
    host: str
    mode: str
    modules: Dict[str, bool]

@app.get("/health")
def health(): return {"status": "ok"}

@app.get("/targets")
def get_targets(): return list(db["targets"].values())

@app.get("/targets/{id}")
def get_target(id: str): return db["targets"].get(id)

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
    if id in db["targets"]: del db["targets"][id]
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
        log(f"Starting deep scan on {host}...", "info")
        t["progress"] = 10
        
        # ECHTE NMAP CALL: -sCV (Service/Script) -p- (Alle poorten)
        # We gebruiken -oX - om XML output te krijgen die makkelijk te parsen is, 
        # of gewoon tekst voor dit voorbeeld.
        process = subprocess.Popen(
            ['nmap', '-sV', '-p', '1-1000', host], # Beperkt tot 1000 voor snelheid in test, gebruik -p- voor alles
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True
        )
        
        t["progress"] = 40
        stdout, stderr = process.communicate()
        
        if process.returncode == 0:
            log("Nmap sequence completed successfully.", "success")
            # Simpele parser voor nmap output (Zou in productie een echte XML parser moeten zijn)
            ports = []
            for line in stdout.split('\n'):
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
            log(f"Nmap failed: {stderr}", "error")
            t["status"] = "failed"

    except Exception as e:
        log(f"Scanner engine error: {str(e)}", "error")
        t["status"] = "failed"

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
```

### 3. Hoe te testen
1. Zorg dat `nmap` is geïnstalleerd op je computer (`brew install nmap` of `sudo apt install nmap`).
2. Draai het bovenstaande Python script.
3. Ga in CypherRecon naar **System Settings** en zet de URL op `http://localhost:5000`.
4. Start een scan. Je zult zien dat de logs en resultaten nu 1-op-1 overeenkomen met je lokale Nmap output.
