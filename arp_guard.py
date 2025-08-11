# netsentinel_ai/arp_guard.py
import time
from collections import defaultdict, deque

class ArpGuard:
    def __init__(self, max_events=300):
        self.ip_macs = defaultdict(set)   # ip -> set(mac)
        self.conflicts = deque(maxlen=max_events)

    def observe(self, ip, mac):
        if not ip or not mac:
            return
        mac = mac.lower()
        s = self.ip_macs[ip]
        if s and mac not in s:
            # konflikt
            self.conflicts.append({
                "ts": time.time(),
                "ip": ip,
                "macs": list(s | {mac}),
                "new": mac
            })
        s.add(mac)

    def get_conflicts(self):
        return list(self.conflicts)