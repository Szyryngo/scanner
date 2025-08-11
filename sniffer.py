# sniffer.py

from scapy.all import sniff
import threading

sniffing = False
sniff_thread = None
packet_callback = None

def set_callback(callback_fn):
    global packet_callback
    packet_callback = callback_fn

def sniff_packets():
    try:
        sniff(prn=handle_packet, store=False, stop_filter=lambda x: not sniffing)
    except Exception as e:
        print(f"[❌] Błąd sniffowania: {e}")

def handle_packet(packet):
    if packet_callback:
        packet_callback(packet)

def start_sniffing():
    global sniffing, sniff_thread
    if sniffing:
        print("[ℹ️] Sniffowanie już trwa.")
        return
    sniffing = True
    sniff_thread = threading.Thread(target=sniff_packets, daemon=True)
    sniff_thread.start()
    print("[✅] Sniffowanie rozpoczęte.")

def stop_sniffing():
    global sniffing
    sniffing = False
    print("[⏹] Sniffowanie zatrzymane.")
