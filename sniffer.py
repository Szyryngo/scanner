import threading
import time
import logging
from scapy.all import sniff, IP, TCP, UDP
from db import DatabaseManager
from datetime import datetime

logging.basicConfig(level=logging.INFO)

class SnifferThread(threading.Thread):
    def __init__(self, iface="eth0"):
        super().__init__()
        self.iface = iface
        self.running = True
        self.db = DatabaseManager()

    def packet_callback(self, pkt):
        try:
            if IP in pkt:
                ip_layer = pkt[IP]
                proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other"
                info = f"{ip_layer.src} → {ip_layer.dst} | {proto} | {len(pkt)} bytes"
                logging.info(info)
                self.db.add_packet(str(datetime.now()), info)
        except Exception as e:
            logging.exception("Error processing packet")

    def run(self):
        logging.info("Sniffer started")
        while self.running:
            try:
                sniff(iface=self.iface, prn=self.packet_callback, timeout=5)
                time.sleep(0.1)
            except Exception as e:
                logging.exception("Sniffer error")

    def stop(self):
        self.running = False
        self.db.stop()
