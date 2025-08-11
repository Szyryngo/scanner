import threading
import queue
import json
import os
from PyQt5 import QtCore
from .utils import GEO_CACHE_PATH, is_private_ip

class GeoResolver(QtCore.QObject):
    resultReady = QtCore.pyqtSignal(str, dict)

    def __init__(self, cache_path=GEO_CACHE_PATH, parent=None):
        super().__init__(parent)
        self.cache_path = cache_path
        self.cache = {}
        self.queue = queue.Queue()
        self.thread = None
        self.stop_event = threading.Event()
        self.lock = threading.RLock()
        self._load()

    def _load(self):
        try:
            if os.path.isfile(self.cache_path):
                with open(self.cache_path, "r", encoding="utf-8") as f:
                    self.cache = json.load(f)
        except Exception:
            self.cache = {}

    def _save(self):
        try:
            with open(self.cache_path, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._worker, daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=1.0)

    def request(self, ip):
        if not ip or is_private_ip(ip):
            return
        with self.lock:
            if ip in self.cache:
                self.resultReady.emit(ip, self.cache[ip])
                return
        self.queue.put(ip)

    def _worker(self):
        while not self.stop_event.is_set():
            try:
                ip = self.queue.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                data = self._resolve_ip(ip)
                with self.lock:
                    if data:
                        self.cache[ip] = data
                        self._save()
                self.resultReady.emit(ip, data or {})
            except Exception:
                pass

    def _resolve_ip(self, ip):
        try:
            import requests
        except Exception:
            return {}
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,org,as,query"
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                j = r.json()
                if j.get("status") == "success":
                    return {
                        "country": j.get("country") or "",
                        "cc": (j.get("countryCode") or "").upper(),
                        "region": j.get("regionName") or "",
                        "city": j.get("city") or "",
                        "org": j.get("org") or "",
                        "asn": j.get("as") or "",
                        "ip": j.get("query") or ip
                    }
        except Exception:
            return {}
        return {}