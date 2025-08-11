import threading
import time
import logging
from scapy.all import sniff

logging.basicConfig(level=logging.INFO)

class SnifferThread(threading.Thread):
    def __init__(self, iface="eth0", callback=None):
        super().__init__()
        self.iface = iface
        self.callback = callback or self.default_callback
        self.running = True

    def default_callback(self, pkt):
        logging.debug(f"Packet: {pkt.summary()}")

    def run(self):
        logging.info("Sniffer started")
        while self.running:
            try:
                sniff(iface=self.iface, prn=self.callback, timeout=5)
                time.sleep(0.1)
            except Exception as e:
                logging.exception("Sniffer error")

    def stop(self):
        self.running = False
