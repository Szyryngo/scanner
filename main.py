import os
import sys
import warnings

# Jeśli uruchamiasz ten plik bezpośrednio (python main.py) z katalogu netsentinel_ai,
# ustaw kontekst pakietu, żeby zadziałały importy względne (from .ui import MainWindow).
if __name__ == "__main__" and (not __package__ or __package__ == ""):
    pkg_dir = os.path.dirname(os.path.abspath(__file__))      # ...\netsentinel_ai
    parent_dir = os.path.dirname(pkg_dir)                     # katalog nadrzędny
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)
    __package__ = os.path.basename(pkg_dir)                   # 'netsentinel_ai'

# Wycisz ostrzeżenia o niezweryfikowanym HTTPS (używamy verify=False przy fingerprintingu w LAN)
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass
# Dodatkowy fallback dla vendora w requests (nie zawsze potrzebny, ale nie zaszkodzi):
try:
    import requests  # noqa: F401
    from requests.packages.urllib3.exceptions import InsecureRequestWarning as ReqInsecureRequestWarning  # type: ignore
    requests.packages.urllib3.disable_warnings(ReqInsecureRequestWarning)  # type: ignore
except Exception:
    pass

from PyQt5 import QtWidgets
from .ui import MainWindow

def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName("NetSentinel-AI")
    mw = MainWindow()
    mw.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()