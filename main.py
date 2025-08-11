import threading
import logging
from sniffer import SnifferThread
from arp_guard import ArpGuardThread
from ui import start_ui

logging.basicConfig(level=logging.INFO)

def main():
    logging.info("Starting application...")

    # Uruchomienie sniffera
    sniffer = SnifferThread()
    sniffer.start()

    # Uruchomienie ARP Guard
    arp_guard = ArpGuardThread()
    arp_guard.start()

    # Uruchomienie GUI
    start_ui()

    # Zatrzymanie wątków przy zamknięciu
    sniffer.stop()
    arp_guard.stop()
    sniffer.join()
    arp_guard.join()

if __name__ == "__main__":
    main()
