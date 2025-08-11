from scapy.all import sniff, IP, TCP, UDP
import threading

class SnifferThread(threading.Thread):
    def __init__(self, stats, online_mode=True, log_callback=None):
        super().__init__()
        self.stats = stats
        self.online_mode = online_mode
        self.log_callback = log_callback or (lambda msg: print(msg))
        self.running = True
        self.last_ip = None

    def run(self):
        self.log_callback(f"🔄 Tryb: {'Online' if self.online_mode else 'Offline'}")
        sniff(prn=self.process_packet, store=False, stop_filter=self.should_stop)

    def should_stop(self, packet):
        return not self.running

    def process_packet(self, packet):
        if not self.running:
            return

        self.stats["packets"] += 1

        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            proto = packet[IP].proto

            msg = f"📦 IP: {ip_src} → {ip_dst} | Proto: {proto}"
            self.log_callback(msg)

            # Prosta analiza zagrożeń
            if TCP in packet and packet[TCP].dport == 4444:
                self.stats["alerts"] += 1
                self.stats["threats"] += 1
                self.log_callback(f"☠️ Podejrzany port 4444 od {ip_src}!")

            if UDP in packet and packet[UDP].dport == 53 and self.online_mode:
                self.stats["alerts"] += 1
                self.log_callback(f"🔔 DNS zapytanie od {ip_src}")

            # Zapamiętaj IP do mapy
            if self.online_mode:
                self.last_ip = ip_src
