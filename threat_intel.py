# netsentinel_ai/threat_intel.py
import os
import re
import json
import ipaddress
import threading
from collections import deque
from .utils import CACHE_DIR

TI_DB_PATH = os.path.join(CACHE_DIR, "ti_db.json")

class ThreatIntel:
    def __init__(self, path=TI_DB_PATH):
        self.path = path
        self.lock = threading.RLock()
        self.db = {"ips": {}, "subnets": [], "domains": {}, "url_patterns": [], "http_banners": []}
        self._compiled = {"url_patterns": [], "http_banners": []}
        self.last_hits = deque(maxlen=500)
        self._load_builtin()
        self._load_file_if_exists()

    def _load_builtin(self):
        builtin = {
            "ips": {
                "45.155.205.233": {"threat": "Known botnet/C2 (example)", "source": "builtin"},
                "185.220.101.1": {"threat": "Tor Exit (example)", "source": "builtin"}
            },
            "subnets": [
                {"cidr": "45.155.205.0/24", "threat": "Malware hosting (example)", "source": "builtin"}
            ],
            "domains": {
                "example-phish.com": {"threat": "Phishing (example)", "source": "builtin"},
                "malware.test": {"threat": "Malware test (example)", "source": "builtin"}
            },
            "url_patterns": [
                {"re": r"/wp-login\.php", "threat": "WordPress brute-force (pattern)", "source": "builtin"},
                {"re": r"/xmlrpc\.php", "threat": "WordPress xmlrpc abuse (pattern)", "source": "builtin"},
                {"re": r"/cgi-bin/.*(\?|\&)(cmd|exec|query)=", "threat": "CGI cmd injection attempt", "source": "builtin"}
            ],
            "http_banners": [
                {"re": r"(?i)\bBoa/0\.", "field": "server", "threat": "Legacy Boa web server (IoT, vulnerable)", "source": "builtin"},
                {"re": r"(?i)\bGoAhead/\d", "field": "server", "threat": "GoAhead web server (check CVEs)", "source": "builtin"},
                {"re": r"(?i)\bMikroTik\b", "field": "server", "threat": "MikroTik RouterOS (check CVEs)", "source": "builtin"}
            ]
        }
        with self.lock:
            self.db = builtin
            self._compile_regexes()

    def _load_file_if_exists(self):
        if os.path.isfile(self.path):
            self.load_file(self.path)

    def _compile_regexes(self):
        self._compiled = {"url_patterns": [], "http_banners": []}
        for it in self.db.get("url_patterns", []):
            try:
                self._compiled["url_patterns"].append((re.compile(it.get("re", "")), it))
            except Exception:
                continue
        for it in self.db.get("http_banners", []):
            try:
                self._compiled["http_banners"].append((re.compile(it.get("re", "")), it))
            except Exception:
                continue

    def load_file(self, path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                j = json.load(f)
            with self.lock:
                for k in ["ips","subnets","domains","url_patterns","http_banners"]:
                    if k in j:
                        self.db[k] = j[k]
                self._compile_regexes()
            return True
        except Exception:
            return False

    def save_file(self, path=None):
        path = path or self.path
        try:
            with self.lock, open(path, "w", encoding="utf-8") as f:
                json.dump(self.db, f, ensure_ascii=False, indent=2)
            return True
        except Exception:
            return False

    @staticmethod
    def has_internet(timeout=3):
        try:
            import requests
            r = requests.get("https://clients3.google.com/generate_204", timeout=timeout)
            return r.status_code in (204, 200)
        except Exception:
            try:
                r = requests.get("https://1.1.1.1", timeout=timeout, verify=False)
                return r.status_code in (200, 301, 302)
            except Exception:
                return False

    def update_from_osint(self, urls=None, timeout=6, limit_lines_per_feed=100000):
        try:
            import requests
        except Exception:
            return {"ips": 0, "domains": 0}
        urls = urls or [
            # IP
            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/2.txt",
            "https://lists.blocklist.de/lists/all.txt",
            # Domains
            "https://phishing.army/download/phishing_army_blocklist_extended.txt",
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        ]
        ips_added = 0
        doms_added = 0
        for url in urls:
            try:
                r = requests.get(url, timeout=timeout)
                if r.status_code != 200 or not r.text:
                    continue
                lines = r.text.splitlines()
                if limit_lines_per_feed and len(lines) > limit_lines_per_feed:
                    lines = lines[:limit_lines_per_feed]
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#") or len(line) < 3:
                        continue
                    # hosts format
                    if " " in line and (line.startswith("0.0.0.0") or line.startswith("127.0.0.1")):
                        parts = line.split()
                        if len(parts) >= 2:
                            dom = parts[1].strip().lower()
                            if self._is_domain(dom):
                                with self.lock:
                                    if dom not in self.db["domains"]:
                                        self.db["domains"][dom] = {"threat": f"OSINT: {url}", "source": "osint"}
                                        doms_added += 1
                        continue
                    token = line.split()[0]
                    if self._is_ip(token):
                        with self.lock:
                            if token not in self.db["ips"]:
                                self.db["ips"][token] = {"threat": f"OSINT: {url}", "source": "osint"}
                                ips_added += 1
                        continue
                    if self._is_domain(token):
                        with self.lock:
                            if token not in self.db["domains"]:
                                self.db["domains"][token] = {"threat": f"OSINT: {url}", "source": "osint"}
                                doms_added += 1
            except Exception:
                continue
        with self.lock:
            self._compile_regexes()
        return {"ips": ips_added, "domains": doms_added}

    def _is_ip(self, s):
        try:
            ipaddress.ip_address(s)
            return True
        except Exception:
            return False

    def _is_domain(self, s):
        return bool(re.match(r"^[A-Za-z0-9\.\-]+\.[A-Za-z]{2,}$", s))

    def _domain_match(self, domain):
        dom = (domain or "").lower().strip(".")
        if not dom:
            return None
        if dom in self.db.get("domains", {}):
            info = self.db["domains"][dom]
            return {"indicator": dom, "type": "domain", "threat": info.get("threat",""), "source": info.get("source","")}
        parts = dom.split(".")
        for i in range(1, len(parts)-1):
            suf = ".".join(parts[i:])
            if suf in self.db["domains"]:
                info = self.db["domains"][suf]
                return {"indicator": dom, "matched_suffix": suf, "type": "domain", "threat": info.get("threat",""), "source": info.get("source","")}
        return None

    def _ip_match(self, ip):
        if not ip:
            return None
        if ip in self.db.get("ips", {}):
            info = self.db["ips"][ip]
            return {"indicator": ip, "type": "ip", "threat": info.get("threat",""), "source": info.get("source","")}
        try:
            ip_obj = ipaddress.ip_address(ip)
            for sn in self.db.get("subnets", []):
                try:
                    net = ipaddress.ip_network(sn.get("cidr",""), strict=False)
                    if ip_obj in net:
                        return {"indicator": ip, "matched_cidr": sn.get("cidr",""), "type": "ip", "threat": sn.get("threat",""), "source": sn.get("source","")}
                except Exception:
                    continue
        except Exception:
            pass
        return None

    def match_packet(self, pkt_info):
        hits = []
        sip = pkt_info.get("src_ip") or ""
        dip = pkt_info.get("dst_ip") or ""
        ext_ip = pkt_info.get("ext_ip") or ""
        dns_q = (pkt_info.get("dns_query") or "").lower()
        http_host = (pkt_info.get("http_host") or "").lower()
        http_path = pkt_info.get("http_path") or ""
        http_server = pkt_info.get("http_server") or ""
        user_agent = pkt_info.get("user_agent") or ""

        for ip in filter(None, [ext_ip, sip, dip]):
            m = self._ip_match(ip)
            if m:
                m["where"] = "ip"
                hits.append(m)
        if dns_q:
            m = self._domain_match(dns_q.strip("."))
            if m:
                m["where"] = "dns"
                hits.append(m)
        if http_host:
            m = self._domain_match(http_host)
            if m:
                m["where"] = "http_host"
                hits.append(m)
        if http_host or http_path:
            url = f"http://{http_host}{http_path or '/'}"
            for cre, meta in self._compiled.get("url_patterns", []):
                try:
                    if cre.search(url):
                        hits.append({"indicator": url, "type": "url", "threat": meta.get("threat",""), "source": meta.get("source",""), "where": "url"})
                except Exception:
                    continue
        if http_server:
            for cre, meta in self._compiled.get("http_banners", []):
                try:
                    if meta.get("field","server").lower() == "server" and cre.search(http_server):
                        hits.append({
                            "indicator": http_server, "type": "banner", "field": "server",
                            "threat": meta.get("threat",""), "source": meta.get("source",""), "where": "http"
                        })
                except Exception:
                    continue
        if user_agent:
            for cre, meta in self._compiled.get("http_banners", []):
                try:
                    if meta.get("field","server").lower() == "user-agent" and cre.search(user_agent):
                        hits.append({
                            "indicator": user_agent, "type": "banner", "field": "user-agent",
                            "threat": meta.get("threat",""), "source": meta.get("source",""), "where": "http"
                        })
                except Exception:
                    continue
        return hits

    def record_hit(self, hit: dict):
        self.last_hits.append({"ts": time.time(), **hit})

    def get_last_hits(self):
        return list(self.last_hits)

    def counts(self):
        with self.lock:
            return {
                "ips": len(self.db.get("ips", {})),
                "subnets": len(self.db.get("subnets", [])),
                "domains": len(self.db.get("domains", {})),
                "url_patterns": len(self.db.get("url_patterns", [])),
                "http_banners": len(self.db.get("http_banners", [])),
            }