import logging
from sniffer import SnifferThread
import time

# Konfiguracja logowania
logging.basicConfig(level=logging.INFO)
logging.info("Starting application...")

def main():
    # Statystyki przekazywane do sniffera
    stats = {
        "packets": 0,
        "alerts": 0,
        "threats": 0
    }

    # Inicjalizacja i uruchomienie sniffera
    sniffer = SnifferThread(stats)
    sniffer.start()

    try:
        while True:
            time.sleep(5)
            logging.info(f"Statystyki: {stats}")
    except KeyboardInterrupt:
        sniffer.running = False
        logging.info("Sniffer zatrzymany przez użytkownika.")

if __name__ == "__main__":
    main()
