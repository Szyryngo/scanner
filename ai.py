# netsentinel_ai/ai.py
import time
import json
import os
import re
import math
from threading import RLock
from .utils import safe_decode, b64_try_decode, AI_MEMORY_PATH, extract_credentials

def _entropy(s: str):
    from collections import Counter
    if not s:
        return 0.0
    p, lns = Counter(s), float(len(s))
    return -sum((c/lns) * math.log2(c/lns) for c in p.values())

def _is_dga_like(domain: str):
    d = (domain or "").lower().strip(".")
    if not d or len(d) < 8:
        return False
    ent = _entropy(d)
    digits = sum(ch.isdigit() for ch in d)
    hyph = d.count("-")
    # prosta heurystyka
    return (ent > 3.6 and len(d) > 18) or (digits > 5 and len(d) > 15) or (hyph > 3 and len(d) > 20)

class ThreatAI:
    def __init__(self, path=AI_MEMORY_PATH, geo=None, learn_log_cb=None, threat_intel=None):
        self.path = path
        self.geo = geo
        self.learn_log_cb = learn_log_cb
        self.ti = threat_intel
        self.mem = {
            "feature_weights": {
                "plaintext_credentials": 5.0,
                "unencrypted_protocol": 1.5,
                "suspicious_country": 1.0,
                "external_unknown": 0.8,
                "port_scan": 3.5,
                "dns_amplification": 2.0,
                "syn_flood": 2.5,
                "smb": 1.2,
                "telnet": 1.8,
                "mdns_nbns_llmnr_flood": 1.0,
                "new_host": 0.6,
                "udp_1900": 1.4,
                "udp_53_unusual": 1.2,
                "threat_intel_match": 6.0,
                "dns_tunnel": 3.0,
                "dga_suspect": 2.2
            },
            "ip_reputation": {},
            "allowlist": [],
            "blocklist": []
        }
        self._load()
        self.window_events = {"ports_by_src": {}, "seen_hosts": {}, "dns_stats": {}}
        self.lock = RLock()

    def _load(self):
        try:
            if os.path.isfile(self.path):
                with open(self.path, "r", encoding="utf-8") as f:
                    self.mem = json.load(f)
        except Exception:
            pass

    def _save(self):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.mem, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def log_learn(self, msg):
        if self.learn_log_cb:
            try:
                self.learn_log_cb(msg)
            except Exception:
                pass

    def feedback_ip(self, ip, label):
        if label == "malicious":
            self.mem["ip_reputation"][ip] = min(10.0, self.mem["ip_reputation"].get(ip, 0.0) + 2.0)
            if ip not in self.mem["blocklist"]:
                self.mem["blocklist"].append(ip)
            self.log_learn(f"[AI] Zaznaczono IP jako złośliwe: {ip}.")
        else:
            self.mem["ip_reputation"][ip] = max(-10.0, self.mem["ip_reputation"].get(ip, 0.0) - 1.5)
            if ip not in self.mem["allowlist"]:
                self.mem["allowlist"].append(ip)
            self.log_learn(f"[AI] Zaznaczono IP jako zaufane: {ip}.")
        self._save()

    def score_packet(self, pkt_info):
        tags = []
        score = 0.0
        fw = self.mem["feature_weights"]

        src_ip = pkt_info.get("src_ip") or ""
        dst_ip = pkt_info.get("dst_ip") or ""
        proto = (pkt_info.get("proto") or "").upper()
        sport = pkt_info.get("src_port")
        dport = pkt_info.get("dst_port")
        raw = pkt_info.get("raw") or b""
        ext_ip = pkt_info.get("ext_ip") or ""
        dns_q = (pkt_info.get("dns_query") or "").lower()
        http_host = (pkt_info.get("http_host") or "").lower()

        cred_found = self._detect_plain_credentials(proto, sport, dport, raw)
        if cred_found:
            tags.append("plaintext_credentials")
            score += fw.get("plaintext_credentials", 5.0)

        if proto == "TCP" and dport in [21, 23, 25, 110, 143, 389, 445, 80]:
            tags.append("unencrypted_protocol")
            score += fw.get("unencrypted_protocol", 1.5)

        if (proto == "TCP") and pkt_info.get("tcp_flags_syn") and not pkt_info.get("tcp_flags_ack"):
            self._mark_port_seen(src_ip, dport)
            unique_ports = self._unique_ports(src_ip)
            if unique_ports >= 20:
                tags.append("port_scan")
                score += fw.get("port_scan", 3.5)
            if unique_ports >= 100:
                tags.append("syn_flood")
                score += fw.get("syn_flood", 2.5)

        if proto == "UDP":
            if dport == 1900:
                tags.append("udp_1900")
                score += fw.get("udp_1900", 1.4)
            if dport == 53 and len(raw) > 400:
                tags.append("dns_amplification")
                score += fw.get("dns_amplification", 2.0)
            if dport == 53 and sport not in [53, None]:
                tags.append("udp_53_unusual")
                score += fw.get("udp_53_unusual", 1.2)

        if proto == "TCP" and dport in [139, 445]:
            tags.append("smb"); score += fw.get("smb", 1.2)
        if proto == "TCP" and dport == 23:
            tags.append("telnet"); score += fw.get("telnet", 1.8)

        # DNS heurystyki (DGA / tunneling)
        if dns_q:
            if _is_dga_like(dns_q):
                tags.append("dga_suspect"); score += fw.get("dga_suspect", 2.2)
            self._update_dns_stats(src_ip, dns_q)
            if self._suspect_dns_tunnel(src_ip):
                tags.append("dns_tunnel"); score += fw.get("dns_tunnel", 3.0)

        with self.lock:
            now = time.time()
            w = self.mem.setdefault("_seen_hosts", {})
            if src_ip and src_ip not in w:
                tags.append("new_host"); score += fw.get("new_host", 0.6)
            w[src_ip] = now

        if ext_ip:
            rep = self.mem["ip_reputation"].get(ext_ip, 0.0)
            if rep > 0: score += rep; tags.append("bad_reputation")
            elif rep < 0: score += rep; tags.append("good_reputation")
            if ext_ip in self.mem["blocklist"]:
                score += 3.0; tags.append("blocklisted")
            if self.geo:
                data = self.geo.cache.get(ext_ip)
                if data:
                    code = (data.get("cc") or "").upper()
                    if code in ["RU", "CN", "IR", "KP", "BY"]:
                        tags.append("suspicious_country"); score += fw.get("suspicious_country", 1.0)
                else:
                    tags.append("external_unknown"); score += fw.get("external_unknown", 0.8)
                    self.geo.request(ext_ip)

        # Threat Intel
        if self.ti:
            try:
                hits = self.ti.match_packet(pkt_info)
                if hits:
                    score += fw.get("threat_intel_match", 6.0)
                    tags.append("threat_intel")
                    for h in hits:
                        # zapamiętaj i zaloguj
                        self.ti.record_hit(h)
                        self.log_learn(f"[TI] Match: {h.get('type')}={h.get('indicator')} threat={h.get('threat')} src={h.get('source')} where={h.get('where')}")
            except Exception:
                pass

        return max(0.0, score), ",".join(sorted(set(tags)))

    def _mark_port_seen(self, src_ip, dport):
        if not src_ip:
            return
        with self.lock:
            deq = self.window_events["ports_by_src"].get(src_ip)
            if not deq:
                from collections import deque
                deq = self.window_events["ports_by_src"][src_ip] = deque(maxlen=500)
            deq.append((time.time(), dport))

    def _unique_ports(self, src_ip, window_sec=60):
        with self.lock:
            deq = self.window_events["ports_by_src"].get(src_ip)
            if not deq:
                return 0
            t0 = time.time() - window_sec
            while deq and deq[0][0] < t0:
                deq.popleft()
            return len(set(p for _, p in deq if p is not None))

    def _detect_plain_credentials(self, proto, sport, dport, raw):
        if not raw:
            return False
        creds = extract_credentials(raw)
        if creds:
            for ctype, value in creds:
                self.log_learn(f"[AI] Credentials captured: {ctype}: {value}")
            return True
        return False

    def _update_dns_stats(self, src_ip, qname):
        with self.lock:
            st = self.window_events["dns_stats"].setdefault(src_ip, {"ts": [], "qnames": [], "long": 0, "uniq": set()})
            now = time.time()
            st["ts"].append(now)
            st["qnames"].append(qname)
            st["uniq"].add(qname)
            if len(qname) > 40:
                st["long"] += 1
            # purge >60s
            while st["ts"] and st["ts"][0] < now - 60:
                st["ts"].pop(0)

    def _suspect_dns_tunnel(self, src_ip):
        st = self.window_events["dns_stats"].get(src_ip) or {}
        if not st:
            return False
        cnt = len(st.get("ts", []))
        longq = st.get("long", 0)
        uniq = len(st.get("uniq", set()))
        # progi heurystyczne
        return (cnt > 50 and longq > 10) or uniq > 60