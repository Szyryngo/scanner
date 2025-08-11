import threading
import time
import logging
from scapy.all import ARP, sniff

logging.basicConfig(level=logging.INFO)

class ArpGuardThread(threading.Thread):
    def __init__(self):
        super().__init__()
        self.running = True
        self.known_macs = {}

    def detect_spoof(self, pkt):
        if ARP in pkt and pkt[ARP].op == 2:
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            if ip in self.known_macs and self.known_macs[ip] != mac:
                logging.warning(f"ARP Spoofing detected: {ip} changed from {self.known_macs[ip]} to {mac}")
            else:
                self.known_macs[ip] = mac

    def run(self):
        logging.info("ARP Guard started")
        while self.running:
            try:
                sniff(filter="arp", prn=self.detect_spoof, timeout=5)
                time.sleep(0.5)
            except Exception as e:
                logging.exception("ARP Guard error")

    def stop(self):
        self.running = False
