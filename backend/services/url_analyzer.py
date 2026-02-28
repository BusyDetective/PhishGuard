from services.features import extract_features
from services.model_loader import load_model
import pandas as pd

def analyze_url(url: str):
    try:
        features = extract_features(url)

        # Load ML model
        model = load_model()

        # Prepare features for ML
        df = pd.DataFrame([features])
        if "domain" in df.columns:
            df = df.drop(columns=["domain"])  # ML only needs numeric features

        ml_prob = model.predict_proba(df)[0][1]   # probability phishing
        ml_prediction = int(model.predict(df)[0]) # 0 = safe, 1 = phish

        # Start heuristic scoring
        heuristic_score = 0
        reasons = []

        # Trusted safe domains
        trusted_domains = [
            "google.com",
            "youtube.com",
            "microsoft.com",
            "github.com",
            "facebook.com",
            "wikipedia.org",
            "apple.com",
            "amazon.com",
            "openai.com"
        ]

        # Heuristic rules
        if features["bad_tld"]:
            heuristic_score += 25
            reasons.append("Suspicious TLD detected")

        if features["has_ip"]:
            heuristic_score += 20
            reasons.append("URL uses raw IP address")

        if features["entropy"] > 4.2:
            heuristic_score += 20
            reasons.append("High entropy (random-looking URL)")

        if features["password_fields"] > 0:
            heuristic_score += 20
            reasons.append("Password input field detected")

        if features["keyword_hits"] > 0 and features["domain"] not in trusted_domains:
            heuristic_score += 15
            reasons.append("Phishing-like phrases detected")

        # Combine ML + heuristic (Hybrid score)
        combined = (heuristic_score / 100) * 0.4 + ml_prob * 0.6

        return {
            "url": url,
            "ai_prediction": ml_prediction,
            "ai_probability": float(ml_prob),
            "heuristic_score": heuristic_score,
            "combined_risk_score": round(combined * 100, 2),
            "reasons": reasons,
            "features": features
        }

    except Exception as e:
        return {"error": str(e)}

