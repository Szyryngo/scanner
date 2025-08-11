# ai.py

def extract_features(packet):
    size = len(packet)
    threat_score = 1 if packet.haslayer("TCP") and packet["TCP"].dport == 23 else 0
    time_delta = 0.05  # przykładowa wartość
    return [size, threat_score, time_delta]

def predict_packet_features(features):
    return features[1] == 1  # jeśli threat_score == 1, uznajemy za zagrożenie
