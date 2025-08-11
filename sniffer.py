import threading
from PyQt5 import QtCore
from .utils import now_ts, to_bytes, is_private_ip, safe_decode
from .ja3 import parse_client_hello, parse_server_hello

# Lazy import Scapy — dopiero przy starcie sniffingu
sniff = IP = IPv6 = TCP = UDP = ICMP = ARP = Raw = DNS = DNSQR = None
SCAPY_OK = None

def _import_scapy():
    global sniff, IP, IPv6, TCP, UDP, ICMP, ARP, Raw, DNS, DNSQR, SCAPY_OK
    if SCAPY_OK is not None:
        return
    try:
        from scapy.all import sniff as _sniff, IP as _IP, IPv6 as _IPv6, TCP as _TCP, UDP as _UDP, ICMP as _ICMP, ARP as _ARP, Raw as _Raw, DNS as _DNS, DNSQR as _DNSQR  # type: ignore
        sniff, IP, IPv6, TCP, UDP, ICMP, ARP, Raw, DNS, DNSQR = _sniff, _IP, _IPv6, _TCP, _UDP, _ICMP, _ARP, _Raw, _DNS, _DNSQR
        SCAPY_OK = True
    except Exception:
        SCAPY_OK = False

class SnifferWorker(QtCore.QObject):
    packetInserted = QtCore.pyqtSignal(int)
    statusMsg = QtCore.pyqtSignal(str)

    def __init__(self, db, ai, geo, active_traffic, iface=None, bpf_filter="", ja3_collector=None, arp_guard=None, parent=None):
        super().__init__(parent)
        self.db = db
        self.ai = ai
        self.geo = geo
        self.active = active_traffic
        self.iface = iface
        self.bpf_filter = bpf_filter or ""
        self._stop_ev = threading.Event()
        self._thread = None
        self.paused = False
        self.ja3c = ja3_collector
        self.arp = arp_guard

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_ev.clear()
        self.paused = False
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self.statusMsg.emit("Sniffer wystartował.")

    def stop(self):
        self._stop_ev.set()
        self.statusMsg.emit("Zatrzymywanie sniffera...")

    def pause(self):
        self.paused = True
        self.statusMsg.emit("Sniffer wstrzymany.")

    def resume(self):
        self.paused = False
        self.statusMsg.emit("Sniffer wznowiony.")

    def _run(self):
        _import_scapy()
        if not SCAPY_OK:
            self.statusMsg.emit("Brak scapy — nie mogę sniffować.")
            return
        try:
            sniff(
                iface=self.iface,
                filter=self.bpf_filter,
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda _p: self._stop_ev.is_set()
            )
        except Exception as e:
            self.statusMsg.emit(f"Błąd sniff: {e}")

    def _parse_http_fields(self, raw_bytes):
        http_host = ""
        http_path = ""
        http_server = ""
        user_agent = ""
        try:
            s = safe_decode(raw_bytes)
            if not s:
                return http_host, http_path, http_server, user_agent
            lines = s.split("\r\n")
            if not lines:
                return http_host, http_path, http_server, user_agent
            if lines[0].startswith(("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ")):
                parts = lines[0].split()
                if len(parts) >= 2:
                    http_path = parts[1]
            if lines[0].startswith("HTTP/"):
                for ln in lines[1:8]:
                    if ln.lower().startswith("server:"):
                        http_server = ln.split(":",1)[1].strip()
                        break
            for ln in lines[0:20]:
                lnl = ln.lower()
                if lnl.startswith("host:"):
                    http_host = ln.split(":",1)[1].strip().lower()
                elif lnl.startswith("user-agent:"):
                    user_agent = ln.split(":",1)[1].strip()
        except Exception:
            pass
        return http_host, http_path, http_server, user_agent

    def _handle_packet(self, pkt):
        if self.paused:
            return
        try:
            ts = now_ts()
            raw = to_bytes(bytes(pkt))
            length = len(raw)
            flags_syn = False
            flags_ack = False
            ext_ip = ""
            http_host = ""
            http_path = ""
            http_server = ""
            user_agent = ""
            dns_query = ""
            if ARP in pkt:
                proto = "ARP"
                sip = pkt[ARP].psrc
                dip = pkt[ARP].pdst
                sport = None
                dport = None
                summary = pkt.summary()
                # ARP guard
                try:
                    mac = getattr(pkt[ARP], "hwsrc", "") or ""
                    if self.arp:
                        self.arp.observe(sip, mac)
                except Exception:
                    pass
            elif IP in pkt or IPv6 in pkt:
                ip_layer = pkt[IPv6] if IPv6 in pkt else pkt[IP]
                sip = ip_layer.src
                dip = ip_layer.dst
                if not is_private_ip(sip) and is_private_ip(dip):
                    ext_ip = sip
                elif not is_private_ip(dip) and is_private_ip(sip):
                    ext_ip = dip
                if TCP in pkt:
                    proto = "TCP"
                    sport = int(pkt[TCP].sport)
                    dport = int(pkt[TCP].dport)
                    tcp_flags = pkt[TCP].flags
                    flags_syn = bool(tcp_flags & 0x02)
                    flags_ack = bool(tcp_flags & 0x10)
                    if Raw in pkt:
                        payload = pkt[Raw].load if hasattr(pkt[Raw],'load') else raw
                        http_host, http_path, http_server, user_agent = self._parse_http_fields(payload)
                        # JA3/JA3S
                        ch = parse_client_hello(payload)
                        if ch and self.ja3c:
                            self.ja3c.record("CH", sip, dip, ja3=ch, sni=ch.get("sni"))
                        sh = parse_server_hello(payload)
                        if sh and self.ja3c:
                            self.ja3c.record("SH", sip, dip, ja3s=sh)
                elif UDP in pkt:
                    proto = "UDP"
                    sport = int(pkt[UDP].sport)
                    dport = int(pkt[UDP].dport)
                    if DNS in pkt and pkt[DNS].qd is not None:
                        try:
                            q = pkt[DNS].qd
                            if isinstance(q, DNSQR):
                                dns_query = (q.qname or b"").decode("utf-8", errors="ignore").strip(".")
                        except Exception:
                            pass
                elif ICMP in pkt:
                    proto = "ICMP"
                    sport = None
                    dport = None
                else:
                    proto = "IP"
                    sport = None
                    dport = None
                summary = pkt.summary()
            else:
                proto = "OTHER"
                sip = ""
                dip = ""
                sport = None
                dport = None
                summary = pkt.summary()

            ai_info = {
                "src_ip": sip, "dst_ip": dip, "proto": proto,
                "src_port": sport, "dst_port": dport, "raw": raw,
                "summary": summary, "ext_ip": ext_ip,
                "tcp_flags_syn": flags_syn, "tcp_flags_ack": flags_ack,
                "dns_query": dns_query,
                "http_host": http_host, "http_path": http_path,
                "http_server": http_server, "user_agent": user_agent
            }
            score, tags = self.ai.score_packet(ai_info)

            rec = {
                "ts": ts, "iface": str(self.iface),
                "src_ip": sip, "dst_ip": dip,
                "src_port": sport, "dst_port": dport, "proto": proto,
                "length": length, "raw": raw, "summary": summary,
                "threat_score": float(score), "threat_tags": tags, "ext_ip": ext_ip
            }
            pid = self.db.insert_packet(rec)
            try:
                if (score or 0) >= 1.0 or (tags and tags.strip()):
                    self.ai.log_learn(f"{sip}:{sport or ''} -> {dip}:{dport or ''} {proto} len={length} score={score:.2f} tags={tags}")
            except Exception:
                pass
            try:
                self.active.observe(sip, dip, length, proto, sport, dport)
            except Exception:
                pass
            self.packetInserted.emit(pid)
        except Exception:
            pass