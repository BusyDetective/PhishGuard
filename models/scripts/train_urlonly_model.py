import os
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from backend.services.url_features_urlonly import extract_url_only_features

# Absolute paths to ensure correct file loading
BASE_DIR = "/home/detective/phishguard/models/scripts"
SAFE_FILE = os.path.join(BASE_DIR, "safe_urls.txt")
PHISH_FILE = os.path.join(BASE_DIR, "phishing_urls.txt")

def load_urls(path):
    if not os.path.exists(path):
        print(f"File not found: {path}")
        return []
    with open(path, "r") as f:
        return [line.strip() for line in f.readlines() if line.strip()]

def build_dataset():
    safe = load_urls(SAFE_FILE)
    phish = load_urls(PHISH_FILE)

    print(f"Loaded {len(safe)} safe URLs")
    print(f"Loaded {len(phish)} phishing URLs")

    rows = []
    labels = []

    for u in safe:
        rows.append(extract_url_only_features(u))
        labels.append(0)

    for u in phish:
        rows.append(extract_url_only_features(u))
        labels.append(1)

    df = pd.DataFrame(rows)
    df["label"] = labels
    return df

def train():
    df = build_dataset()

    print(f"Training samples: {len(df)}")
    if len(df) == 0:
        raise ValueError("Dataset is empty. Cannot train model.")

    # Drop string columns
    drop_cols = []
    if "domain" in df.columns:
        drop_cols.append("domain")

    X = df.drop(columns=drop_cols + ["label"])
    y = df["label"]

    print(f"Training on columns: {list(X.columns)}")

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        random_state=42
    )

    model.fit(X, y)

    output_path = os.path.join(BASE_DIR, "url_model.pkl")
    joblib.dump(model, output_path)
    print(f"Saved URL-only model as: {output_path}")
    print("Training complete.")

if __name__ == "__main__":
    train()

