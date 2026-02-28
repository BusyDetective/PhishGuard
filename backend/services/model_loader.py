import joblib
import os

MODEL_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../models/phishing_model.pkl"))

model = None

def load_model():
    global model
    if model is None:
        model = joblib.load(MODEL_PATH)
    return model

