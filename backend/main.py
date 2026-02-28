from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
import joblib
import pandas as pd

# Local imports
from services.url_analyzer import analyze_url
from services.url_features_urlonly import extract_url_only_features

app = FastAPI()

API_KEY = "TEST-DEV-KEY-12345"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------
# DEFINE BatchScanRequest BEFORE USING IT
# ------------------------
class BatchScanRequest(BaseModel):
    urls: List[str]


# ------------------------
# NOW the route can use BatchScanRequest
# ------------------------
@app.post("/scan_batch")
def scan_batch(req: BatchScanRequest, x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

    urls = req.urls
    if not urls or len(urls) == 0:
        raise HTTPException(status_code=400, detail="No URLs provided")

    if len(urls) > 200:
        raise HTTPException(status_code=413, detail="Too many URLs (max 200)")

    model = joblib.load("url_model.pkl")

    rows = []
    for u in urls:
        feats = extract_url_only_features(u)
        rows.append(feats)

    df = pd.DataFrame(rows).fillna(0)

    if "domain" in df.columns:
        df = df.drop(columns=["domain"])

    X = df

    probs = model.predict_proba(X)[:, 1]
    preds = model.predict(X)

    results = []
    for i, url in enumerate(urls):
        results.append({
            "url": url,
            "ai_prediction": int(preds[i]),
            "ai_probability": float(probs[i]),
            "heuristic_score": 0,  # you can enhance this later
            "combined_risk_score": round(float(probs[i]) * 100, 2)
        })

    return { "count": len(results), "results": results }

