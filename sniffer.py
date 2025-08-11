import threading
import time
import logging
from scapy.all import sniff, IP, TCP, UDP
from db import DatabaseManager
from datetime import datetime
from geo import get_geo_info
from oui import get_vendor
from ui import packet_queue
from map import show_map

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
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                length = len(pkt)

                geo = get_geo_info(src_ip)
                vendor = get_vendor(pkt.src)

                info = f"{src_ip} → {dst_ip} | {proto} | {length} bytes"
                if geo.get("country_name"):
                    info += f" | {geo['country_name']}"
                if vendor != "Unknown":
                    info += f" | {vendor}"

                logging.info(info)
                self.db.add_packet(str(datetime.now()), info)
                packet_queue.put(info)

                if geo.get("latitude") and geo.get("longitude"):
                    show_map(src_ip, geo["latitude"], geo["longitude"])
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
