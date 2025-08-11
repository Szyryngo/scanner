import socket
import ipaddress
import threading
from PyQt5 import QtCore
from .oui import OUIMatcher
from .utils import WINDOWS, run_subprocess, ip_sort_key, extract_title

try:
    import psutil
except Exception:
    psutil = None

try:
    import requests
except Exception:
    requests = None

# Lazy import Scapy w wątku skanera
Ether = ARP = srp = get_if_addr = get_if_hwaddr = None
SCAPY_OK = None

def _import_scapy():
    global Ether, ARP, srp, get_if_addr, get_if_hwaddr, SCAPY_OK
    if SCAPY_OK is not None:
        return
    try:
        from scapy.all import Ether as _Ether, ARP as _ARP, srp as _srp, get_if_addr as _get_if_addr, get_if_hwaddr as _get_if_hwaddr  # type: ignore
        Ether, ARP, srp, get_if_addr, get_if_hwaddr = _Ether, _ARP, _srp, _get_if_addr, _get_if_hwaddr
        SCAPY_OK = True
    except Exception:
        SCAPY_OK = False

class LanScanner(QtCore.QObject):
    progress = QtCore.pyqtSignal(int, int)
    result = QtCore.pyqtSignal(list)
    statusMsg = QtCore.pyqtSignal(str)

    def __init__(self, iface_capture=None, iface_psutil=None, oui_matcher=None, udp_quick=True, parent=None):
        super().__init__(parent)
        self.iface_capture = iface_capture
        self.iface_psutil = iface_psutil
        self.oui = oui_matcher or OUIMatcher()
        self.udp_quick = udp_quick
        self._stop_ev = threading.Event()
        self._thread = None
        self.MAX_HOSTS = 4096

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_ev.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_ev.set()

    def _emit_progress(self, v, total):
        self.progress.emit(v, total)

    def _emit_status(self, msg):
        self.statusMsg.emit(msg)

    def _local_net(self):
        # psutil – szybkie pozyskanie IP/maski
        try:
            addrs = psutil.net_if_addrs() if psutil else {}
            key = self.iface_psutil or self.iface_capture
            if key and key in addrs:
                ipv4 = None
                netmask = None
                mac = None
                for snic in addrs[key]:
                    if snic.family == socket.AF_INET:
                        ipv4 = snic.address
                        netmask = snic.netmask
                    elif hasattr(psutil, "AF_LINK") and snic.family == psutil.AF_LINK:
                        mac = snic.address
                if ipv4 and netmask:
                    net = ipaddress.IPv4Network((ipv4, netmask), strict=False)
                    return str(net), ipv4, mac
        except Exception:
            pass
        # Fallback – Scapy (jeśli dostępny)
        try:
            _import_scapy()
            if SCAPY_OK:
                ip = get_if_addr(self.iface_capture or self.iface_psutil)
                mac = get_if_hwaddr(self.iface_capture or self.iface_psutil)
                net = str(ipaddress.IPv4Network(ip + "/24", strict=False))
                return net, ip, mac
        except Exception:
            pass
        return None, None, None

    def _run(self):
        _import_scapy()  # na wypadek ARP
        net_cidr, my_ip, my_mac = self._local_net()
        devices = []
        if not net_cidr or not my_ip:
            self._emit_status("Brak IP/maski na interfejsie — nie mogę wyznaczyć podsieci. Uruchom jako Administrator.")
            self.result.emit(devices)
            return
        try:
            network = ipaddress.ip_network(net_cidr, strict=False)
        except Exception:
            self._emit_status(f"Błędny CIDR: {net_cidr}")
            self.result.emit(devices)
            return

        hosts_iter = list(network.hosts())
        if len(hosts_iter) > self.MAX_HOSTS:
            self._emit_status(f"Podsieć {net_cidr} ma {len(hosts_iter)} hostów — ograniczam do pierwszych {self.MAX_HOSTS}.")
            hosts_iter = hosts_iter[:self.MAX_HOSTS]

        targets = [str(ip) for ip in hosts_iter]
        total = len(targets)
        self._emit_status(f"Skanuję {net_cidr} (IP {my_ip})")

        answers = []
        found_ips = set()

        if SCAPY_OK and self.iface_capture:
            try:
                self._emit_status("ARP scan...")
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=net_cidr)
                ans, _unans = srp(pkt, timeout=2, iface=self.iface_capture, inter=0, verbose=False)
                for _snd, rcv in ans:
                    answers.append((rcv.psrc, rcv.hwsrc))
                    found_ips.add(rcv.psrc)
            except Exception:
                self._emit_status("ARP nie powiodło się — fallback ping sweep.")
        else:
            self._emit_status("Brak Scapy/iface_capture — użyję ping sweep.")

        if (not self._stop_ev.is_set()) and len(found_ips) < max(1, total * 0.2):
            self._emit_status("Ping sweep + ARP cache...")
            for i, ip in enumerate(targets, 1):
                if self._stop_ev.is_set():
                    break
                if ip == my_ip:
                    self._emit_progress(i, total)
                    continue
                alive = False
                try:
                    if WINDOWS:
                        out = run_subprocess(["ping", "-n", "1", "-w", "300", ip], timeout=1.5)
                    else:
                        out = run_subprocess(["ping", "-c", "1", "-W", "1", ip], timeout=1.5)
                    if "TTL=" in out or "ttl=" in out.lower():
                        alive = True
                except Exception:
                    pass
                if alive:
                    found_ips.add(ip)
                if i % 8 == 0 or i == total:
                    self._emit_progress(i, total)

            # ARP cache
            if not self._stop_ev.is_set():
                if WINDOWS:
                    out = run_subprocess(["arp", "-a"], timeout=2)
                    for line in out.splitlines():
                        import re
                        m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]{17})", line, re.IGNORECASE)
                        if m:
                            mac = m.group(2).replace("-", ":").lower()
                            ipx = m.group(1)
                            found_ips.add(ipx)
                            answers.append((ipx, mac))
                else:
                    out = run_subprocess(["ip", "neigh", "show"], timeout=2)
                    for line in out.splitlines():
                        import re
                        m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+([0-9a-f:]{17})", line, re.IGNORECASE)
                        if m:
                            found_ips.add(m.group(1))
                            answers.append((m.group(1), m.group(2)))

        mac_by_ip = {}
        for ip, mac in answers:
            mac_by_ip[ip] = mac

        devs = []
        ips_sorted = sorted(list(found_ips), key=ip_sort_key)
        for i, ip in enumerate(ips_sorted, 1):
            if self._stop_ev.is_set():
                break
            mac = mac_by_ip.get(ip, "")
            vendor = self.oui.vendor_for(mac)
            devs.append({
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
                "hostname": "",
                "type": "",
                "ports": [],
                "udp": [],
                "services": {}
            })
            if i % 4 == 0 or i == len(ips_sorted):
                self._emit_progress(i, max(1, len(ips_sorted)))

        if self._stop_ev.is_set():
            self._emit_status(f"Przerwano — znaleziono {len(devs)} hostów.")
            self.result.emit(devs)
            return

        self._emit_status("Reverse DNS / NBNS...")
        self._names_via_discovery(devs)

        if self._stop_ev.is_set():
            self.result.emit(devs)
            return

        self._emit_status("Skan TCP + UDP quick...")
        common_ports = [21,22,23,25,53,80,110,123,135,139,143,161,389,443,445,554,587,993,995,1900,3389,5353,8080,8443,9000,8008,8888,9100,1723,3306,5432,6379,27017]
        for idx, d in enumerate(devs, 1):
            if self._stop_ev.is_set():
                break
            d["ports"] = self._tcp_scan(d["ip"], common_ports, timeout=0.3)
            if self.udp_quick:
                d["udp"] = self._udp_quick_scan(d["ip"])
            for p in d["ports"]:
                if p in [80, 8080, 8008, 8888, 443, 8443, 9000]:
                    srv, title, xp = self._http_fingerprint(d["ip"], p, use_tls=(p in [443,8443]))
                    if srv or title or xp:
                        d["services"][f"http:{p}"] = {"server": srv, "title": title, "x": xp}
            d["type"] = self._classify_device(d)
            if idx % 2 == 0 or idx == len(devs):
                self._emit_progress(idx, len(devs))

        self._emit_status(f"Zakończono skan LAN. Znaleziono {len(devs)} hostów.")
        self.result.emit(devs)

    def _tcp_scan(self, ip, ports, timeout=0.3):
        open_ports = []
        for p in ports:
            if self._stop_ev.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                r = s.connect_ex((ip, p))
                s.close()
                if r == 0:
                    open_ports.append(p)
            except Exception:
                pass
        return open_ports

    def _udp_quick_scan(self, ip):
        res = []
        def udp_try(port, payload=b"\x00"):
            if self._stop_ev.is_set():
                return False
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(0.4)
                s.sendto(payload, (ip, port))
                try:
                    _data, _addr = s.recvfrom(1024)
                    return True
                except socket.timeout:
                    return False
                finally:
                    s.close()
            except Exception:
                return False
        dns_q = b'\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x04test\x03com\x00\x00\x01\x00\x01'
        if udp_try(53, dns_q): res.append(53)
        ntp = b'\x1b' + b'\x00'*47
        if udp_try(123, ntp): res.append(123)
        snmp = bytes.fromhex("302602010004067075626c6963a01902041f00000102010002010030100406082b060102010101000500")
        if udp_try(161, snmp): res.append(161)
        ssdp = (b"M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\n\r\n")
        if udp_try(1900, ssdp): res.append(1900)
        return res

    def _http_fingerprint(self, ip, port, use_tls=False):
        if not requests:
            return "", "", ""
        url = f"http{'s' if use_tls else ''}://{ip}:{port}/"
        try:
            r = requests.get(url, timeout=1.5, verify=False, allow_redirects=True)
            server = r.headers.get("Server", "")
            xp = r.headers.get("X-Powered-By", "")
            title = extract_title(r.text or "")
            return server, title, xp
        except Exception:
            return "", "", ""

    def _names_via_discovery(self, devs):
        for d in devs:
            if self._stop_ev.is_set():
                return
            try:
                name, _alias, _ = socket.gethostbyaddr(d["ip"])
                if name and name != d["ip"]:
                    d["hostname"] = name
            except Exception:
                pass

    def _classify_device(self, d):
        ports = set(d.get("ports", []))
        udp = set(d.get("udp", []))
        srv = d.get("services", {})
        vendor = (d.get("vendor") or "").lower()
        http_titles = " ".join([v.get("title","") for k,v in srv.items()])
        http_servers = " ".join([v.get("server","") for k,v in srv.items()])
        if 554 in ports or "camera" in http_titles.lower() or "dahua" in http_servers.lower() or "hikvision" in http_servers.lower():
            return "Kamera / Rejestrator"
        if 9100 in ports or 515 in ports or "printer" in http_servers.lower():
            return "Drukarka"
        if any(p in ports for p in [80,443,22,25,53,3306,5432,6379,27017]):
            return "Serwer"
        if 445 in ports or 139 in ports:
            if "nas" in http_titles.lower():
                return "NAS"
            return "Udostępnianie plików/SMB"
        if 1900 in udp or 161 in udp or "router" in http_titles.lower() or "router" in http_servers.lower():
            return "Router/IoT"
        if any(v in vendor for v in ["apple","samsung","huawei","xiaomi"]) and not any(p in ports for p in [80,443,22,445,139]):
            return "Telefon / Tablet"
        if 3389 in ports or 22 in ports or (135 in ports and (139 in ports or 445 in ports)):
            return "Komputer"
        return "Urządzenie"