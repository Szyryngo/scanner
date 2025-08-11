import threading
import time
import logging

logging.basicConfig(level=logging.INFO)

class ArpGuardThread(threading.Thread):
    def __init__(self):
        super().__init__()
        self.running = True

    def run(self):
        logging.info("ARP Guard started")
        while self.running:
            try:
                # Tu dodaj logikę wykrywania ARP spoofingu
                time.sleep(1)
            except Exception as e:
                logging.exception("ARP Guard error")

    def stop(self):
        self.running = False
