import os
import re
import json
from .utils import OUI_CACHE_PATH, BASE_DIR

class OUIMatcher:
    def __init__(self, cache_path=OUI_CACHE_PATH):
        self.cache_path = cache_path
        self.cache = {}
        self.builtins = {
            "00:1A:79": "Cisco", "00:50:56": "VMware", "00:0C:29": "VMware",
            "00:05:69": "VMware", "00:1B:63": "Apple", "F4:5C:89": "Apple",
            "BC:92:6B": "Xiaomi", "3C:5A:B4": "Samsung", "70:66:55": "Intel",
            "D0:37:45": "HUAWEI", "E0:CB:4E": "TP-Link", "FC:FB:FB": "Ubiquiti",
        }
        self.oui_db = {}
        self._load_cache()

    def _load_cache(self):
        try:
            if os.path.isfile(self.cache_path):
                with open(self.cache_path, "r", encoding="utf-8") as f:
                    self.cache = json.load(f)
        except Exception:
            self.cache = {}

    def _save_cache(self):
        try:
            with open(self.cache_path, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def try_load_local_oui_files(self):
        loaded = 0
        candidates = ["oui.txt", "ieee oui.txt", "oui.csv", "IEEE OUI.txt", "IEEE_OUI.txt"]
        for name in candidates:
            path = os.path.join(BASE_DIR, name)
            if os.path.isfile(path):
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        txt = f.read()
                    loaded += self._parse_oui_text(path, txt)
                except Exception:
                    continue
        return loaded

    def _parse_oui_text(self, name, text):
        lines = text.splitlines()
        count = 0
        for line in lines:
            line = line.strip()
            m = re.match(r"^([0-9A-Fa-f]{2}[:-]){2}([0-9A-Fa-f]{2})\s+(.+)$", line)
            if m:
                parts = re.split(r"\s+", line, maxsplit=1)
                if len(parts) == 2:
                    prefix = parts[0].upper().replace("-", ":")
                    vendor = parts[1].strip()
                    self.oui_db[prefix] = vendor
                    count += 1
                continue
            m2 = re.match(r"^([0-9A-Fa-f]{6})\s+(.+)$", line)
            if m2:
                prefix = ":".join([m2.group(1)[i:i+2] for i in range(0, 6, 2)]).upper()
                vendor = m2.group(2).strip()
                self.oui_db[prefix] = vendor
                count += 1
        return count

    def vendor_for(self, mac):
        if not mac:
            return ""
        mac = mac.upper().replace("-", ":")
        parts = mac.split(":")
        if len(parts) < 3:
            return ""
        prefix = ":".join(parts[:3])
        if prefix in self.oui_db:
            return self.oui_db[prefix]
        if prefix in self.cache:
            return self.cache[prefix]
        if prefix in self.builtins:
            return self.builtins[prefix]
        return ""

    def cache_vendor(self, mac, vendor):
        mac = mac.upper().replace("-", ":")
        parts = mac.split(":")
        if len(parts) >= 3 and vendor:
            prefix = ":".join(parts[:3])
            self.cache[prefix] = vendor
            self._save_cache()