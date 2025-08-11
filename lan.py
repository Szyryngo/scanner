import threading
import time
import logging
import socket

logging.basicConfig(level=logging.INFO)

class LanScanner(threading.Thread):
    def __init__(self, subnet="192.168.1.0/24"):
        super().__init__()
        self.subnet = subnet
        self.running = True

    def run(self):
        logging.info("LAN Scanner started")
        while self.running:
            try:
                # Tu dodaj logikę skanowania LAN
                time.sleep(10)  # Throttling
            except Exception as e:
                logging.exception("LAN Scanner error")

    def stop(self):
        self.running = False
