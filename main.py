import os
import sys
import json
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(ROOT_DIR, "config.env"))
sys.path.insert(0, ROOT_DIR)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

from backend.database import get_connection

app = FastAPI(title="CVIP Backend API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

def sev_score(sev): return {"CRITICAL":95,"HIGH":75,"MEDIUM":50,"LOW":20}.get(str(sev).upper(),5)
def os_icon(fam):
    f = str(fam).lower()
    if "windows" in f: return "🪟"
    if "linux" in f or "ubuntu" in f or "debian" in f: return "🐧"
    if "mac" in f or "apple" in f: return "🍎"
    return "💻"

@app.get("/api/dashboard")
def dashboard():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) as c FROM hosts")
    total_hosts = c.fetchone()["c"]
    
    c.execute("SELECT COUNT(*) as c FROM vulnerabilities WHERE severity='CRITICAL'")
    crit = c.fetchone()["c"]
    
    c.execute("SELECT COUNT(DISTINCT host_id) as c FROM vulnerabilities WHERE severity IN ('CRITICAL', 'HIGH')")
    hi_ips = c.fetchone()["c"]
    
    c.execute("SELECT AVG(cvss_score) as avg_score FROM vulnerabilities WHERE cvss_score IS NOT NULL")
    avg_score = c.fetchone()["avg_score"] or 0
    risk = int(avg_score * 10)
    
    c.execute("""
        SELECT v.severity, v.cve_id, h.ip, s.port, v.description, v.published 
        FROM vulnerabilities v
        JOIN hosts h ON v.host_id = h.id
        JOIN services s ON v.service_id = s.id
        ORDER BY v.cvss_score DESC LIMIT 5
    """)
    alerts = [{
        "type": row["severity"].lower(), "title": row["cve_id"],
        "detail": f"{row['ip']}:{row['port']} — {row['description'][:80]}",
        "time": row["published"]
    } for row in c.fetchall()]
    
    c.execute("SELECT target, start_time, scan_time_seconds, status FROM scans ORDER BY id DESC LIMIT 5")
    recent_scans = [{
        "subnet": row["target"], "date": row["start_time"][:10],
        "time": row["scan_time_seconds"], "status": row["status"]
    } for row in c.fetchall()]
    
    conn.close()
    return {
        "stats": {"total_hosts": total_hosts, "critical_cves": crit, "high_risk_hosts": hi_ips, "risk_score": risk},
        "security_notifications": alerts,
        "recent_scans": recent_scans,
    }

@app.get("/api/scans")
def get_scans():
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT h.ip, h.hostname, h.os, h.os_family, h.state,
               (SELECT COUNT(*) FROM vulnerabilities WHERE host_id = h.id) as cve_count,
               (SELECT severity FROM vulnerabilities WHERE host_id = h.id ORDER BY cvss_score DESC LIMIT 1) as max_severity
        FROM hosts h
        ORDER BY h.id DESC
    """)
    results = []
    for row in c.fetchall():
        sev = (row["max_severity"] or "LOW").upper()
        results.append({
            "ip": row["ip"], "hostname": row["hostname"] or "Unknown",
            "os": row["os"] or "Unknown OS", "os_family": row["os_family"] or "Unknown",
            "os_icon": os_icon(row["os_family"] or ""), "severity": sev,
            "risk_score": sev_score(sev), "cve_count": row["cve_count"], "state": row["state"]
        })
    conn.close()
    return results

@app.get("/api/vulnerabilities")
def get_vulnerabilities():
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT v.cve_id, v.severity, v.cvss_score, v.published, v.description,
               h.ip as affected_ip, s.port as affected_port, s.service as affected_service, s.product as affected_product
        FROM vulnerabilities v
        JOIN hosts h ON v.host_id = h.id
        JOIN services s ON v.service_id = s.id
        ORDER BY v.cvss_score DESC
    """)
    res = [dict(row) for row in c.fetchall()]
    conn.close()
    return res

@app.get("/api/hosts")
def get_hosts():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT ip, hostname, os, os_family, state, mac FROM hosts")
    res = [dict(row) for row in c.fetchall()]
    conn.close()
    return res

@app.get("/api/services")
def get_services():
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT s.port, s.protocol, s.service, s.product, s.version, s.version_string, s.cpe, h.ip
        FROM services s JOIN hosts h ON s.host_id = h.id
    """)
    res = [dict(row) for row in c.fetchall()]
    conn.close()
    return res

@app.get("/api/remediation")
def get_remediation():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT r.advisory, h.ip FROM remediations r JOIN hosts h ON r.host_id = h.id")
    res = [dict(row) for row in c.fetchall()]
    conn.close()
    return res

class ScanRequest(BaseModel):
    target: str
    intensity: str = "standard"

def _run_pipeline(target: str, intensity: str):
    from scanner.pipeline import run_pipeline
    run_pipeline(target, intensity, GEMINI_API_KEY, NVD_API_KEY or None)

@app.post("/api/scans/start")
def start_scan(req: ScanRequest, bg: BackgroundTasks):
    import re
    target = req.target.strip()
    valid_ip = re.match(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$', target)
    valid_host = re.match(r'^[a-zA-Z0-9._-]+$', target)
    if not target or (not valid_ip and not valid_host):
        raise HTTPException(400, f"Invalid target: '{target}'. Enter a valid IP address (e.g. 192.168.1.1) or hostname.")
    if not GEMINI_API_KEY or GEMINI_API_KEY == "YOUR_GEMINI_API_KEY_HERE":
        raise HTTPException(400, "Gemini API key not configured. Edit config.env and restart the backend.")
    
    status_file = os.path.join(ROOT_DIR, "scanner", "results", "pipeline_status.json")
    if os.path.exists(status_file):
        with open(status_file) as f:
            status = json.load(f)
            if status.get("is_running"):
                raise HTTPException(400, "A scan is already in progress.")
                
    bg.add_task(_run_pipeline, target, req.intensity)
    return {"message": "Pipeline started", "target": target, "intensity": req.intensity}

@app.get("/api/scans/status")
def scan_status():
    status_file = os.path.join(ROOT_DIR, "scanner", "results", "pipeline_status.json")
    if os.path.exists(status_file):
        with open(status_file) as f: return json.load(f)
    return {"is_running": False, "phase": 0, "progress": 0, "message": "No scan has been run yet.", "target": ""}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
