from scapy.all import sniff, IP
from geo import get_geo_info
from oui import get_vendor
from threat_intel import check_ip_threat
from tkinter import messagebox
import threading
import logging

class SnifferThread(threading.Thread):
    def __init__(self, stats):
        super().__init__()
        self.running = True
        self.stats = stats

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
            if threat.get("malicious"):
                self.stats["threats"] += 1
                alert = f"Zagrożenie: {src_ip} oznaczone jako złośliwe!"
                logging.warning(alert)
                messagebox.showwarning("Threat Intelligence", alert)
