import time
from threading import RLock

class ActiveTraffic:
    def __init__(self):
        self.lock = RLock()
        self.hosts = {}

    def observe(self, src_ip, dst_ip, length, proto, sport, dport):
        now = time.time()
        with self.lock:
            for ip in filter(None, [src_ip, dst_ip]):
                h = self.hosts.get(ip)
                if not h:
                    h = {"ip": ip, "packets": 0, "bytes": 0, "ports": set(), "last": now, "type": ""}
                    self.hosts[ip] = h
                h["packets"] += 1
                h["bytes"] += int(length or 0)
                if sport:
                    h["ports"].add(int(sport))
                if dport:
                    h["ports"].add(int(dport))
                h["last"] = now

    def get_snapshot(self):
        with self.lock:
            res = []
            for ip, h in self.hosts.items():
                res.append({
                    "ip": ip,
                    "packets": h["packets"],
                    "bytes": h["bytes"],
                    "ports": sorted(list(h["ports"])),
                    "type": h.get("type", "")
                })
            return res