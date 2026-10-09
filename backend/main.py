from datetime import datetime
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles
from backend import detector as d

ROOT = Path(__file__).resolve().parent.parent
app = FastAPI(title="UPI Shield (simulation only)")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.mount("/static", StaticFiles(directory=ROOT / "frontend"), name="static")
HISTORY = []

class Msg(BaseModel): text: str; sender: str = ""
class Url(BaseModel): url: str
class Qr(BaseModel): payload: str
class Snd(BaseModel): sender: str; text: str = ""
class Pay(BaseModel): risk_score: int; method: str

def log(kind, r):
    HISTORY.append({"time": datetime.now().strftime("%H:%M:%S"), "type": kind, "risk": r["risk_level"], "score": r["risk_score"],
                    "action": {"ALLOW": "Allowed", "WARN": "Warned", "BLOCK": "Blocked"}[r["decision"]]})
    return r

@app.post("/api/analyze/message")
def a_msg(b: Msg): return log("Message", d.analyze_message(b.text, b.sender))
@app.post("/api/analyze/url")
def a_url(b: Url): return log("Link", d.analyze_url(b.url))
@app.post("/api/analyze/qr")
def a_qr(b: Qr): return log("QR", d.analyze_upi(b.payload))
@app.post("/api/verify/sender")
def v_snd(b: Snd): return d.verify_sender(b.sender, b.text)
@app.post("/api/payment/verify")
def v_pay(b: Pay): return d.verify_payment(b.risk_score, b.method)
@app.get("/api/test-cases")
def cases(): return d.run_cases(ROOT / "sample_data" / "cases.json")
@app.get("/api/dashboard")
def dash():
    n = len(HISTORY); sc = [h["score"] for h in HISTORY]
    dist = {k: sum(1 for h in HISTORY if h["risk"] == k) for k in ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]}
    return {"total": n, "suspicious": sum(1 for h in HISTORY if h["score"] >= 30), "high_risk": dist["HIGH"] + dist["CRITICAL"],
            "legitimate": sum(1 for h in HISTORY if h["score"] < 30), "average_score": round(sum(sc) / n, 1) if n else 0,
            "distribution": dist, "recent": HISTORY[-10:][::-1]}
@app.get("/")
def index(): return FileResponse(ROOT / "frontend" / "index.html")
