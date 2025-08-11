import logging
from sniffer import SnifferThread
from arp_guard import ArpGuardThread
from lan import LanScanner
from ui import start_ui

logging.basicConfig(level=logging.INFO)

def main():
    logging.info("Starting application...")

    sniffer = SnifferThread()
    arp_guard = ArpGuardThread()
    lan_scanner = LanScanner()

    sniffer.start()
    arp_guard.start()
    lan_scanner.start()

    start_ui()

    sniffer.stop()
    arp_guard.stop()
    lan_scanner.stop()

    sniffer.join()
    arp_guard.join()
    lan_scanner.join()

if __name__ == "__main__":
    main()
