import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../backend")))

import pandas as pd
import joblib
import requests
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from services.features import extract_features

# ------------------------------------------
# Download clean dataset
# ------------------------------------------

def get_safe_urls():
    return [
        "https://google.com",
        "https://youtube.com",
        "https://wikipedia.org",
        "https://microsoft.com",
        "https://github.com",
        "https://amazon.com",
        "https://netflix.com",
        "https://cloudflare.com",
        "https://twitter.com",
        "https://instagram.com",
        "https://openai.com",
        "https://spotify.com",
        "https://apple.com",
        "https://paypal.com",
        "https://bbc.com",
        "https://nytimes.com",
        "https://dropbox.com",
        "https://zoom.us",
        "https://coursera.org",
        "https://udemy.com",
    ]


def get_phishing_urls():
    return [
        "http://login-verification-secure.com",
        "http://account-update-security-alert.net",
        "http://paypal-login-authenticate.xyz",
        "http://secure-verify-amazon.tk",
        "http://banking-verification-center.ml",
        "http://google-security-check.ga",
        "http://instagram-login-alert.cf",
        "http://facebook-reset-password.gq",
        "http://secure-mail-verification.click",
        "http://login-office365-support.xyz",
        "http://verifybilling-stripe.top",
        "http://webemail-authenticate-reset.pw",
        "http://secureaccess-auth-login.work",
        "http://cloudflare-security-update.rest",
        "http://apple-id-verify-billing.ml",
        "http://microsoft-auth-reset.ga",
        "http://netflix-security-update.gq",
    ]



# ------------------------------------------
# Extract features for ML
# ------------------------------------------

def build_dataset():
    safe = get_safe_urls()
    phish = get_phishing_urls()

    print(f"[+] Safe URLs: {len(safe)}")
    print(f"[+] Phishing URLs: {len(phish)}")

    rows = []

    for u in safe:
        try:
            feats = extract_features(u)
            feats["label"] = 0
            rows.append(feats)
        except:
            pass

    for u in phish:
        try:
            feats = extract_features(u)
            feats["label"] = 1
            rows.append(feats)
        except:
            pass

    df = pd.DataFrame(rows)
    df = df.fillna(0)
    return df


# ------------------------------------------
# Train model
# ------------------------------------------

def train():
    df = build_dataset()

    X = df.drop(columns=["label", "domain"])
    y = df["label"]

    # split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1
    )

    print("[+] Training model...")
    model.fit(X_train, y_train)

    print("[+] Accuracy:", model.score(X_test, y_test))

    joblib.dump(model, "../phishing_model.pkl")
    print("[+] Model saved as phishing_model.pkl")


if __name__ == "__main__":
    train()

