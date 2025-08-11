# ai.py

import joblib

model = None

def load_model(path="model.pkl"):
    global model
    try:
        model = joblib.load(path)
        print("[✅] Model AI załadowany.")
    except Exception as e:
        print(f"[❌] Błąd ładowania modelu: {e}")

def extract_features(packet):
    size = len(packet)
    proto = packet["IP"].proto if packet.haslayer("IP") else 0
    sport = packet["TCP"].sport if packet.haslayer("TCP") else 0
    dport = packet["TCP"].dport if packet.haslayer("TCP") else 0
    return [size, proto, sport, dport]

def predict_packet_features(features):
    if model:
        try:
            return model.predict([features])[0]
        except Exception as e:
            print(f"[❌] Błąd predykcji: {e}")
            return 0
    return 0
