"""
🛡️ NetSentinel AI — skrypt startowy
Uruchamia interfejs GUI do monitorowania sieci, trenowania AI i wizualizacji zagrożeń.
"""

from ui import start_ui

if __name__ == "__main__":
    try:
        start_ui()
    except Exception as e:
        print(f"❌ Błąd uruchomienia: {e}")
