# netsentinel_ai/ja3.py
import hashlib
import time
from collections import deque

def _u16(b, o):
    return (b[o] << 8) | b[o+1]

def _u24(b, o):
    return (b[o] << 16) | (b[o+1] << 8) | b[o+2]

def parse_client_hello(raw: bytes):
    # TLS record(s) — szukamy handshake ClientHello
    try:
        i = 0
        while i + 5 <= len(raw):
            ct = raw[i]
            if ct != 0x16:  # Handshake
                return None
            ver = _u16(raw, i+1)
            rec_len = _u16(raw, i+3)
            if i + 5 + rec_len > len(raw):
                return None
            rec = raw[i+5:i+5+rec_len]
            # Handshake header
            if len(rec) < 4:
                return None
            hs_type = rec[0]
            if hs_type != 0x01:  # ClientHello
                return None
            hs_len = _u24(rec, 1)
            if len(rec) < 4 + hs_len:
                return None
            ch = rec[4:4+hs_len]
            p = 0
            if len(ch) < 2+32+1:
                return None
            client_version = _u16(ch, 0)
            p += 2
            p += 32  # random
            sid_len = ch[p]
            p += 1
            p += sid_len
            if p + 2 > len(ch):
                return None
            cs_len = _u16(ch, p)
            p += 2
            if p + cs_len > len(ch):
                return None
            ciphers = []
            for off in range(0, cs_len, 2):
                ciphers.append((_u16(ch, p+off)))
            p += cs_len
            if p >= len(ch):
                return None
            comp_len = ch[p]
            p += 1 + comp_len
            if p + 2 > len(ch):
                # brak rozszerzeń
                exts = []
                curves = []
                ec_pf = []
                sni = ""
            else:
                ext_total = _u16(ch, p)
                p += 2
                exts = []
                curves = []
                ec_pf = []
                sni = ""
                end = p + ext_total
                if end > len(ch):
                    end = len(ch)
                while p + 4 <= end:
                    etype = _u16(ch, p)
                    elen = _u16(ch, p+2)
                    p += 4
                    if p + elen > end:
                        break
                    ed = ch[p:p+elen]
                    p += elen
                    exts.append(etype)
                    if etype == 0:  # server_name
                        try:
                            if len(ed) >= 5:
                                l = _u16(ed, 0)
                                pos = 2
                                if pos + 3 <= len(ed):
                                    nt = ed[pos]
                                    nl = _u16(ed, pos+1)
                                    if pos+3+nl <= len(ed):
                                        sni = ed[pos+3:pos+3+nl].decode("utf-8", errors="ignore")
                        except Exception:
                            pass
                    elif etype == 10:  # supported_groups (elliptic curves)
                        try:
                            gl = _u16(ed, 0)
                            pos = 2
                            while pos + 1 < len(ed) and pos < 2 + gl:
                                curves.append(_u16(ed, pos))
                                pos += 2
                        except Exception:
                            pass
                    elif etype == 11:  # ec_point_formats
                        try:
                            l1 = ed[0]
                            for j in range(1, 1+l1):
                                if j < len(ed):
                                    ec_pf.append(ed[j])
                        except Exception:
                            pass
            ja3_str = f"{client_version},{'-'.join(map(str,ciphers))},{'-'.join(map(str,exts))},{'-'.join(map(str,curves))},{'-'.join(map(str,ec_pf))}"
            ja3 = hashlib.md5(ja3_str.encode()).hexdigest()
            return {"ja3": ja3, "ja3_str": ja3_str, "sni": sni}
    except Exception:
        return None
    return None

def parse_server_hello(raw: bytes):
    try:
        i = 0
        while i + 5 <= len(raw):
            ct = raw[i]
            if ct != 0x16:
                return None
            rec_len = _u16(raw, i+3)
            if i + 5 + rec_len > len(raw):
                return None
            rec = raw[i+5:i+5+rec_len]
            if len(rec) < 4:
                return None
            hs_type = rec[0]
            if hs_type != 0x02:  # ServerHello
                return None
            hs_len = _u24(rec, 1)
            if len(rec) < 4 + hs_len:
                return None
            sh = rec[4:4+hs_len]
            p = 0
            if len(sh) < 2+32+1+2+1:
                return None
            server_version = _u16(sh, 0)
            p += 2
            p += 32  # random
            sid_len = sh[p]
            p += 1 + sid_len
            cipher = _u16(sh, p)
            p += 2
            comp = sh[p]
            p += 1
            exts = []
            if p + 2 <= len(sh):
                ext_total = _u16(sh, p)
                p += 2
                end = p + ext_total
                if end > len(sh):
                    end = len(sh)
                while p + 4 <= end:
                    etype = _u16(sh, p)
                    elen = _u16(sh, p+2)
                    p += 4
                    if p + elen > end:
                        break
                    # ed = sh[p:p+elen]
                    p += elen
                    exts.append(etype)
            ja3s_str = f"{server_version},{cipher},{'-'.join(map(str,exts))}"
            ja3s = hashlib.md5(ja3s_str.encode()).hexdigest()
            return {"ja3s": ja3s, "ja3s_str": ja3s_str}
    except Exception:
        return None
    return None

class JA3Collector:
    def __init__(self, max_events=500):
        self.events = deque(maxlen=max_events)

    def record(self, direction, src_ip, dst_ip, ja3=None, ja3s=None, sni=None):
        self.events.append({
            "ts": time.time(),
            "dir": direction,  # "CH" lub "SH"
            "src": src_ip,
            "dst": dst_ip,
            "ja3": (ja3 or {}).get("ja3"),
            "ja3_str": (ja3 or {}).get("ja3_str"),
            "sni": sni or (ja3 or {}).get("sni") or "",
            "ja3s": (ja3s or {}).get("ja3s"),
            "ja3s_str": (ja3s or {}).get("ja3s_str"),
        })

    def get_events(self):
        return list(self.events)