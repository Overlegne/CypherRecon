
# CypherRecon | AI-Powered Ethical Reconnaissance

CypherRecon is a production-ready dashboard for managing target reconnaissance. It separates the **Command & Control (UI)** from the **Scanning Engine (Local Backend)**, allowing you to perform real network scans from your local machine while managing them through a modern web interface.

## 🛠 Setup & Testing Guide

### 1. Prerequisites
- Python 3.9+
- Node.js 18+
- [Optional] Nmap installed on your system path.

### 2. Start the Python Scanner (Mock/Real Backend)
To test the integration immediately, use this FastAPI boilerplate. It simulates real scan progress and data structures.

```python
import uuid, time, asyncio
from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# In-memory DB
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
        db["targets"][id]["results"]["logs"] = []
        background_tasks.add_task(simulate_scan, id)
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

async def simulate_scan(id: str):
    t = db["targets"][id]
    steps = [
        (10, "Initializing workflow engine..."),
        (30, "Enumerating subdomains via Passive DNS..."),
        (50, "Running Nmap -sCV -p- across all interfaces..."),
        (80, "Identifying technology stack and API surface..."),
        (100, "Sequence complete. Data ready for AI analysis.")
    ]
    
    for prog, msg in steps:
        await asyncio.sleep(2)
        t["progress"] = prog
        t["results"]["logs"].append({
            "id": str(uuid.uuid4()), "timestamp": int(time.time()*1000),
            "message": msg, "type": "info" if prog < 100 else "success"
        })
        if prog == 50:
            t["results"]["portScanResults"] = [
                {"port": 80, "service": "http", "state": "open", "version": "nginx 1.18.0"},
                {"port": 443, "service": "https", "state": "open", "version": "nginx (SSL)"}
            ]
        if prog == 100:
            t["status"] = "completed"
            t["lastRunAt"] = int(time.time()*1000)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
```

### 3. Connect the Frontend
1. Open CypherRecon.
2. Go to **System Settings**.
3. Set **Local Backend API URL** to `http://localhost:5000`.
4. Ensure the sidebar status turns green.
5. Create a target and click **Start Sequence**.

## 🚀 Production Deployment
For production, swap the `simulate_scan` function for real subprocess calls:
```python
import subprocess
def run_nmap(host):
    result = subprocess.run(['nmap', '-sCV', host], capture_output=True, text=True)
    return result.stdout
```
