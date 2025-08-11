from sklearn.ensemble import IsolationForest
import pandas as pd
import joblib
import os

MODEL_PATH = "model.pkl"

def train_model(data_path="data.csv", model_path=MODEL_PATH):
    df = pd.read_csv(data_path)
    features = df[["packet_size", "geo_distance", "threat_score", "time_delta"]]
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(features)
    joblib.dump(model, model_path)
    print("✅ Model wytrenowany i zapisany.")

def predict_anomaly(packet_features, model_path=MODEL_PATH):
    if not os.path.exists(model_path):
        print("⚠️ Brak wytrenowanego modelu. Użyj train_model().")
        return False
    model = joblib.load(model_path)
    prediction = model.predict([packet_features])
    return prediction[0] == -1  # True = anomalia
