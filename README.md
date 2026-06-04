
# CypherRecon

CypherRecon is a modern, AI-powered ethical hacking reconnaissance dashboard. It provides a visual interface for managing target sequences, monitoring real-time scan telemetry, and performing automated risk assessments using Google Gemini.

## 🚀 Production Deployment Strategy

To run CypherRecon in production, you need two components:
1. **Frontend**: This Next.js application (can be hosted on Firebase, Vercel, or lokaal).
2. **Scanner Service (Python)**: A local service that performs the actual network scans (Nmap, DNS, etc.).

### 1. Start the Python Backend
Create a file named `scanner_backend.py` and install dependencies:
```bash
pip install fastapi uvicorn
```

**Minimal Backend Boilerplate:**
```python
from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uuid, time

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

db = {"targets": []}

class Target(BaseModel):
    host: str
    mode: str
    modules: dict

@app.get("/health")
def health(): return {"status": "ok"}

@app.get("/targets")
def get_targets(): return db["targets"]

@app.post("/targets")
def add_target(target: Target):
    new_t = {
        "id": str(uuid.uuid4()), "host": target.host, "mode": target.mode,
        "status": "idle", "progress": 0, "createdAt": int(time.time()*1000),
        "modules": target.modules, "results": {"logs": []}
    }
    db["targets"].append(new_t)
    return new_t

@app.post("/targets/{id}/scan")
def run_scan(id: str, background_tasks: BackgroundTasks):
    # Hier implementeer je je echte Nmap/Subdomain scripts
    background_tasks.add_task(dummy_scan_logic, id)
    return {"status": "started"}

async def dummy_scan_logic(id: str):
    # Zoek target in db en update resultaten real-time
    pass

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
```

### 2. Configure Frontend
1. Open CypherRecon.
2. Ga naar **System Settings**.
3. Stel de **Local Backend API URL** in op `http://localhost:5000`.
4. De status indicator in de sidebar wordt groen zodra de Python service draait.

## Technical Stack
- **Frontend**: Next.js 15, Tailwind CSS, ShadCN UI
- **AI Logic**: Genkit v1.x (Gemini 2.5 Flash)
- **Scanning**: External local service (Python/Go/Rust)
