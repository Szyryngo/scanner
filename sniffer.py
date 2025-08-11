from scapy.all import sniff, IP
from geo import get_geo_info
from oui import get_vendor
from threat_intel import check_ip_threat
from ai import predict_anomaly, update_model
from tkinter import messagebox
import threading
import logging
import time

class SnifferThread(threading.Thread):
    def __init__(self, stats):
        super().__init__()
        self.running = True
        self.stats = stats
        self.last_packet_time = time.time()

    def run(self):
        sniff(prn=self.packet_callback, store=False)

    def packet_callback(self, packet):
        if not self.running:
            return

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            self.stats["packets"] += 1

            geo = get_geo_info(src_ip)
            vendor = get_vendor(packet.src)
            threat = check_ip_threat(src_ip)

            packet_size = len(packet)
            geo_distance = 0.0  # Można rozbudować o obliczenia geograficzne
            threat_score = 1 if threat.get("malicious") else 0
            current_time = time.time()
            time_delta = current_time - self.last_packet_time
            self.last_packet_time = current_time

            features = [packet_size, geo_distance, threat_score, time_delta]

            if predict_anomaly(features):
                logging.warning(f"🧠 Wykryto anomalię: {src_ip} → {dst_ip}")
                self.stats["alerts"] += 1

                # 🔁 Uczenie online
                new_data = {
                    "packet_size": packet_size,
                    "geo_distance": geo_distance,
                    "threat_score": threat_score,
                    "time_delta": time_delta
                }
                update_model(new_data)

            if threat.get("malicious"):
                self.stats["threats"] += 1
                alert = f"Zagrożenie: {src_ip} oznaczone jako złośliwe!"
                logging.warning(alert)
                messagebox.showwarning("Threat Intelligence", alert)
