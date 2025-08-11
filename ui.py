# netsentinel_ai/ui.py
import math
import socket
import threading
from datetime import datetime
from PyQt5 import QtCore, QtGui, QtWidgets

from .db import DBManager
from .oui import OUIMatcher
from .geo import GeoResolver
from .ai import ThreatAI
from .sniffer import SnifferWorker
from .models import PacketTableModel
from .active import ActiveTraffic
from .lan import LanScanner
from .i18n import i18n
from .threat_intel import ThreatIntel
from .anomalies import AnomalyEngine
from .ja3 import JA3Collector
from .arp_guard import ArpGuard
from .utils import (
    WINDOWS, hexdump_lines, safe_decode, ip_sort_key, extract_credentials,
    filter_virtual_ifaces, guess_if_human_friendly_name, run_subprocess
)

# Worker do enumeracji interfejsów (off-UI)
class IfaceEnumerator(QtCore.QObject):
    result = QtCore.pyqtSignal(list)  # list[(label, info_dict)]
    def run(self):
        items = []
        try:
            import psutil
        except Exception:
            psutil = None
        if WINDOWS:
            # Spróbuj Scapy w wątku (może być ciężkie)
            try:
                from scapy.arch.windows import get_windows_if_list  # type: ignore
                for d in get_windows_if_list():
                    if not filter_virtual_ifaces(d):
                        continue
                    label_type = guess_if_human_friendly_name(d)
                    friendly = d.get("friendly_name") or d.get("name") or d.get("description") or "?"
                    ip = ""
                    try:
                        ips = d.get("ips") or []
                        for a in ips:
                            if "." in a:
                                ip = a
                                break
                    except Exception:
                        pass
                    mac = d.get("mac") or ""
                    npf = d.get("win") or d.get("name") or d.get("guid") or ""
                    psname = friendly
                    label = f"{label_type} — {friendly} ({ip or '—'} / {mac or '—'})"
                    items.append((label, {"npf": npf, "psutil": psname, "ip": ip, "mac": mac}))
            except Exception:
                # Fallback: psutil (bez NPF)
                try:
                    addrs = psutil.net_if_addrs() if psutil else {}
                    for name, arr in addrs.items():
                        d = {"name": name, "description": name, "friendly_name": name}
                        if not filter_virtual_ifaces(d):
                            continue
                        ip = ""
                        mac = ""
                        for snic in arr:
                            if snic.family == socket.AF_INET:
                                ip = snic.address
                            elif hasattr(psutil, "AF_LINK") and snic.family == psutil.AF_LINK:
                                mac = snic.address
                        label_type = guess_if_human_friendly_name(d)
                        label = f"{label_type} — {name} ({ip or '—'} / {mac or '—'})"
                        items.append((label, {"npf": name, "psutil": name, "ip": ip, "mac": mac}))
                except Exception:
                    pass
        else:
            # Linux/macOS
            try:
                from scapy.all import get_if_list, get_if_addr, get_if_hwaddr  # type: ignore
                for name in get_if_list():
                    try:
                        ip = get_if_addr(name)
                        mac = get_if_hwaddr(name)
                    except Exception:
                        ip, mac = "", ""
                    d = {"name": name, "description": name, "friendly_name": name}
                    if not filter_virtual_ifaces(d):
                        continue
                    label_type = guess_if_human_friendly_name(d)
                    label = f"{label_type} — {name} ({ip or '—'} / {mac or '—'})"
                    items.append((label, {"npf": name, "psutil": name, "ip": ip, "mac": mac}))
            except Exception:
                try:
                    addrs = psutil.net_if_addrs() if psutil else {}
                    for name, arr in addrs.items():
                        d = {"name": name, "description": name, "friendly_name": name}
                        if not filter_virtual_ifaces(d):
                            continue
                        ip = ""
                        mac = ""
                        for snic in arr:
                            if snic.family == socket.AF_INET:
                                ip = snic.address
                            elif hasattr(psutil, "AF_LINK") and snic.family == psutil.AF_LINK:
                                mac = snic.address
                        label_type = guess_if_human_friendly_name(d)
                        label = f"{label_type} — {name} ({ip or '—'} / {mac or '—'})"
                        items.append((label, {"npf": name, "psutil": name, "ip": ip, "mac": mac}))
                except Exception:
                    pass
        self.result.emit(items)

class MainWindow(QtWidgets.QMainWindow):
    aiLogSig = QtCore.pyqtSignal(str)
    tiStatusSig = QtCore.pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle(i18n.t("app_title"))
        screen = QtWidgets.QApplication.primaryScreen()
        size = screen.availableGeometry()
        self.resize(int(size.width() * 0.9), int(size.height() * 0.9))

        self.iface_map = {}
        self.capture_iface = None
        self.psutil_iface = None

        self.auto_follow = True
        self.page_size = 300
        self.page_index_from_end = 0
        self.selected_packet_id = None
        self.only_threats = False

        self.db = DBManager()
        self.oui = OUIMatcher()
        self.active_tr = ActiveTraffic()
        self.geo = GeoResolver()
        self.geo.resultReady.connect(self.on_geo_result)
        self.geo.start()

        self.ti = ThreatIntel()
        self.ja3c = JA3Collector()
        self.arp_guard = ArpGuard()
        self._build_ui()

        self.aiLogSig.connect(self._on_ai_log)
        self.tiStatusSig.connect(lambda m: self.statusBar().showMessage(m, 5000))

        cnt = self.ti.counts()
        self.ai_log(f"[TI] Załadowano bazę TI: IP={cnt['ips']} subnets={cnt['subnets']} domains={cnt['domains']} url={cnt['url_patterns']} banners={cnt['http_banners']}")

        self.ai = ThreatAI(geo=self.geo, learn_log_cb=self.ai_log, threat_intel=self.ti)
        self.ai_log(f"[AI] Pamięć wczytana. Reputacje={len(self.ai.mem.get('ip_reputation',{}))}, allowlist={len(self.ai.mem.get('allowlist',[]))}, blocklist={len(self.ai.mem.get('blocklist',[]))}")

        self.anom = AnomalyEngine(self.active_tr, sensitivity=0.15)

        self.sniffer = None
        self._enumerate_ifaces_async()  # asynchronicznie

        # Timery — mniej agresywne interwały
        self.timer_stats = QtCore.QTimer(self)
        self.timer_stats.timeout.connect(self.update_sys_stats)
        self.timer_stats.start(1500)

        self.timer_refresh = QtCore.QTimer(self)
        self.timer_refresh.timeout.connect(self.refresh_packets)
        self.timer_refresh.start(1000)

        self.timer_ja3 = QtCore.QTimer(self)
        self.timer_ja3.timeout.connect(self.refresh_ja3)
        self.timer_ja3.start(3000)

        self.timer_arp = QtCore.QTimer(self)
        self.timer_arp.timeout.connect(self.refresh_arp)
        self.timer_arp.start(5000)

        self.timer_anom = QtCore.QTimer(self)
        self.timer_anom.timeout.connect(self.refresh_anomalies)
        self.timer_anom.start(5000)

        self.timer_ti = QtCore.QTimer(self)
        self.timer_ti.timeout.connect(self.refresh_ti_hits)
        self.timer_ti.start(4000)

        # Opóźnij auto-OSINT
        QtCore.QTimer.singleShot(3000, lambda: self.update_ti_osint_async(auto=True))

        self._refresh_timer()

    def closeEvent(self, event):
        try:
            if self.sniffer:
                self.sniffer.stop()
            self.geo.stop()
        except Exception:
            pass
        event.accept()

    def _build_ui(self):
        cw = QtWidgets.QWidget()
        self.setCentralWidget(cw)
        root = QtWidgets.QVBoxLayout(cw)

        top = QtWidgets.QWidget()
        top_layout = QtWidgets.QGridLayout(top)
        root.addWidget(top)

        self.lang_combo = QtWidgets.QComboBox()
        self.lang_combo.addItems(["Polski", "English"])
        self.lang_combo.currentIndexChanged.connect(self.on_lang_change)

        self.iface_combo = QtWidgets.QComboBox()
        self.iface_combo.currentIndexChanged.connect(self.on_iface_change)
        self.iface_combo.addItem("Ładowanie interfejsów...")

        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText(i18n.t("filters"))
        completer_words = ["tcp", "udp", "icmp", "arp", "port", "src", "dst", "host", "net", "portrange", "and", "or", "not", "vlan", "ether", "ip", "ip6"]
        comp = QtWidgets.QCompleter(completer_words)
        comp.setCaseSensitivity(QtCore.Qt.CaseInsensitive)
        self.filter_edit.setCompleter(comp)

        self.preset_combo = QtWidgets.QComboBox()
        self.preset_combo.addItems([
            "— Presety —",
            "HTTP only (tcp port 80)",
            "DNS only (udp port 53)",
            "TLS/HTTPS (tcp port 443)",
            "SMB (tcp port 445 or 139)",
            "DHCP/BOOTP (udp port 67 or 68)",
            "Zagrożenia (ftp/telnet/pop3) (tcp port 21 or 23 or 110 or 143)",
        ])
        self.preset_combo.currentIndexChanged.connect(self.on_preset)

        self.btn_start = QtWidgets.QPushButton(i18n.t("start"))
        self.btn_pause = QtWidgets.QPushButton(i18n.t("pause"))
        self.btn_stop = QtWidgets.QPushButton(i18n.t("stop"))
        self.btn_export = QtWidgets.QPushButton(i18n.t("export"))
        self.btn_save_filters = QtWidgets.QPushButton(i18n.t("save_filters"))
        self.btn_load_filters = QtWidgets.QPushButton(i18n.t("load_filters"))
        self.btn_load_ti = QtWidgets.QPushButton("Załaduj TI (JSON)")
        self.btn_update_ti = QtWidgets.QPushButton("Aktualizuj TI (OSINT)")

        self.btn_start.clicked.connect(self.on_start)
        self.btn_pause.clicked.connect(self.on_pause_resume)
        self.btn_stop.clicked.connect(self.on_stop)
        self.btn_export.clicked.connect(self.on_export)
        self.btn_save_filters.clicked.connect(self.on_save_filters)
        self.btn_load_filters.clicked.connect(self.on_load_filters)
        self.btn_load_ti.clicked.connect(self.on_load_ti)
        self.btn_update_ti.clicked.connect(lambda: self.update_ti_osint_async(auto=False))

        self.cpu_label = QtWidgets.QLabel(f"{i18n.t('cpu')}: —")
        self.mem_label = QtWidgets.QLabel(f"{i18n.t('mem')}: —")

        self.btn_first = QtWidgets.QPushButton(i18n.t("first"))
        self.btn_prev = QtWidgets.QPushButton(i18n.t("prev"))
        self.btn_next = QtWidgets.QPushButton(i18n.t("next"))
        self.btn_last = QtWidgets.QPushButton(i18n.t("last"))
        self.range_slider = QtWidgets.QSlider(QtCore.Qt.Horizontal)
        self.range_slider.setMinimum(0)
        self.range_slider.setMaximum(0)
        self.range_slider.valueChanged.connect(self.on_slider)
        self.auto_follow_chk = QtWidgets.QCheckBox(i18n.t("auto_follow"))
        self.auto_follow_chk.setChecked(True)
        self.auto_follow_chk.stateChanged.connect(self.on_auto_follow)
        self.only_threats_chk = QtWidgets.QCheckBox(i18n.t("only_threats"))
        self.only_threats_chk.stateChanged.connect(self.on_only_threats)
        self.colorize_chk = QtWidgets.QCheckBox(i18n.t("threats_colored"))
        self.colorize_chk.setChecked(True)

        # Podpięcie przycisków nawigacji
        self.btn_first.clicked.connect(lambda: self._nav_to("first"))
        self.btn_prev.clicked.connect(lambda: self._nav_to("prev"))
        self.btn_next.clicked.connect(lambda: self._nav_to("next"))
        self.btn_last.clicked.connect(lambda: self._nav_to("last"))

        top_layout.addWidget(QtWidgets.QLabel(i18n.t("language")+":"), 0, 0)
        top_layout.addWidget(self.lang_combo, 0, 1)
        top_layout.addWidget(QtWidgets.QLabel(i18n.t("iface")+":"), 0, 2)
        top_layout.addWidget(self.iface_combo, 0, 3, 1, 2)
        top_layout.addWidget(self.filter_edit, 0, 5, 1, 3)
        top_layout.addWidget(self.preset_combo, 0, 8)
        top_layout.addWidget(self.btn_start, 0, 9)
        top_layout.addWidget(self.btn_pause, 0, 10)
        top_layout.addWidget(self.btn_stop, 0, 11)
        top_layout.addWidget(self.btn_save_filters, 0, 12)
        top_layout.addWidget(self.btn_load_filters, 0, 13)
        top_layout.addWidget(self.btn_export, 0, 14)
        top_layout.addWidget(self.btn_load_ti, 0, 15)
        top_layout.addWidget(self.btn_update_ti, 0, 16)
        top_layout.addWidget(self.cpu_label, 0, 17)
        top_layout.addWidget(self.mem_label, 0, 18)

        top_layout.addWidget(self.btn_first, 1, 0)
        top_layout.addWidget(self.btn_prev, 1, 1)
        top_layout.addWidget(self.range_slider, 1, 2, 1, 8)
        top_layout.addWidget(self.btn_next, 1, 10)
        top_layout.addWidget(self.btn_last, 1, 11)
        top_layout.addWidget(self.auto_follow_chk, 1, 12)
        top_layout.addWidget(self.only_threats_chk, 1, 13)
        top_layout.addWidget(self.colorize_chk, 1, 14)

        tabs = QtWidgets.QTabWidget()
        self.tabs = tabs
        root.addWidget(tabs)

        # Sniffer
        self.tab_sniffer = QtWidgets.QWidget()
        tabs.addTab(self.tab_sniffer, i18n.t("sniffer"))
        sn_layout = QtWidgets.QHBoxLayout(self.tab_sniffer)

        self.table = QtWidgets.QTableView()
        self.table_model = PacketTableModel()
        self.table.setModel(self.table_model)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.table.clicked.connect(self.on_table_click)
        self.table.doubleClicked.connect(self.on_table_click)
        self.table.setSortingEnabled(False)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        sn_layout.addWidget(self.table, 2)

        right = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        sn_layout.addWidget(right, 3)

        top_right = QtWidgets.QWidget()
        tr_layout = QtWidgets.QVBoxLayout(top_right)
        self.details_text = QtWidgets.QPlainTextEdit()
        self.details_text.setReadOnly(True)
        self.geo_text = QtWidgets.QPlainTextEdit()
        self.geo_text.setReadOnly(True)
        tr_layout.addWidget(QtWidgets.QLabel(i18n.t("details")))
        tr_layout.addWidget(self.details_text, 2)
        tr_layout.addWidget(QtWidgets.QLabel(i18n.t("geo")))
        tr_layout.addWidget(self.geo_text, 1)

        mid_right = QtWidgets.QWidget()
        mr_layout = QtWidgets.QHBoxLayout(mid_right)
        self.hex_text = QtWidgets.QPlainTextEdit()
        self.hex_text.setReadOnly(True)
        self.ascii_text = QtWidgets.QPlainTextEdit()
        self.ascii_text.setReadOnly(True)
        mr_layout.addWidget(QtWidgets.QLabel(i18n.t("hex")))
        mr_layout.addWidget(self.hex_text)
        mr_layout.addWidget(QtWidgets.QLabel(i18n.t("ascii")))
        mr_layout.addWidget(self.ascii_text)

        bottom_right = QtWidgets.QWidget()
        br_layout = QtWidgets.QVBoxLayout(bottom_right)
        self.ai_log_text = QtWidgets.QPlainTextEdit()
        self.ai_log_text.setReadOnly(True)
        br_layout.addWidget(QtWidgets.QLabel(i18n.t("ai_learning")))
        br_layout.addWidget(self.ai_log_text)

        right.addWidget(top_right)
        right.addWidget(mid_right)
        right.addWidget(bottom_right)
        right.setSizes([200, 200, 150])

        # LAN
        self.tab_lan = QtWidgets.QWidget()
        tabs.addTab(self.tab_lan, i18n.t("lan_scanner"))
        lan_layout = QtWidgets.QVBoxLayout(self.tab_lan)
        lan_controls = QtWidgets.QHBoxLayout()
        self.btn_scan_lan = QtWidgets.QPushButton(i18n.t("scan_lan"))
        self.btn_scan_lan.clicked.connect(self.on_scan_lan)
        self.lan_progress = QtWidgets.QProgressBar()
        self.lan_status = QtWidgets.QLabel("—")
        self.btn_export_lan = QtWidgets.QPushButton(i18n.t("export_devices_csv"))
        self.btn_export_lan.clicked.connect(self.on_export_devices)
        self.btn_load_oui = QtWidgets.QPushButton("Załaduj OUI (lokalnie)")
        self.btn_load_oui.clicked.connect(self.on_load_oui)
        self.udp_quick_chk = QtWidgets.QCheckBox("Szybkie UDP (53/123/161/1900)")
        self.udp_quick_chk.setChecked(True)
        self.names_chk = QtWidgets.QCheckBox("nazwy hostów (NBNS/mDNS/LLMNR)")
        self.names_chk.setChecked(True)
        lan_controls.addWidget(self.btn_scan_lan)
        lan_controls.addWidget(self.lan_progress)
        lan_controls.addWidget(self.lan_status)
        lan_controls.addStretch(1)
        lan_controls.addWidget(self.btn_load_oui)
        lan_controls.addWidget(self.udp_quick_chk)
        lan_controls.addWidget(self.names_chk)
        lan_controls.addWidget(self.btn_export_lan)
        lan_layout.addLayout(lan_controls)

        self.lan_table = QtWidgets.QTableWidget(0, 7)
        self.lan_table.setHorizontalHeaderLabels(["IP", "MAC", "Vendor", "Hostname", "Typ", "TCP ports", "UDP ports"])
        self.lan_table.horizontalHeader().setStretchLastSection(True)
        self.lan_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.lan_table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.lan_table.customContextMenuRequested.connect(self.on_lan_context)
        lan_layout.addWidget(self.lan_table)

        # Aktywne (ruch)
        self.tab_active = QtWidgets.QWidget()
        tabs.addTab(self.tab_active, i18n.t("active_by_traffic"))
        act_layout = QtWidgets.QVBoxLayout(self.tab_active)
        act_controls = QtWidgets.QHBoxLayout()
        self.btn_ip_up = QtWidgets.QPushButton(i18n.t("ip_up"))
        self.btn_ip_down = QtWidgets.QPushButton(i18n.t("ip_down"))
        self.btn_ip_up.clicked.connect(lambda: self.refresh_active(sort_dir="up"))
        self.btn_ip_down.clicked.connect(lambda: self.refresh_active(sort_dir="down"))
        act_controls.addWidget(self.btn_ip_up)
        act_controls.addWidget(self.btn_ip_down)
        act_controls.addStretch(1)
        act_layout.addLayout(act_controls)

        self.active_table = QtWidgets.QTableWidget(0, 5)
        self.active_table.setHorizontalHeaderLabels(["IP", "Pakiety", "Bajty", "Porty", "Typ"])
        self.active_table.horizontalHeader().setStretchLastSection(True)
        self.active_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.active_table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.active_table.customContextMenuRequested.connect(self.on_active_context)
        act_layout.addWidget(self.active_table)

        # TLS/JA3
        self.tab_ja3 = QtWidgets.QWidget()
        tabs.addTab(self.tab_ja3, "TLS / JA3")
        ja3_layout = QtWidgets.QVBoxLayout(self.tab_ja3)
        self.ja3_table = QtWidgets.QTableWidget(0, 8)
        self.ja3_table.setHorizontalHeaderLabels(["Czas", "Kier.", "Src", "Dst", "SNI", "JA3", "JA3S", "JA3/JA3S string"])
        self.ja3_table.horizontalHeader().setStretchLastSection(True)
        ja3_layout.addWidget(self.ja3_table)

        # ARP/MITM
        self.tab_arp = QtWidgets.QWidget()
        tabs.addTab(self.tab_arp, "ARP / MITM")
        arp_layout = QtWidgets.QVBoxLayout(self.tab_arp)
        self.arp_table = QtWidgets.QTableWidget(0, 5)
        self.arp_table.setHorizontalHeaderLabels(["Czas", "IP", "MAC(e)", "Nowy MAC", "Liczba MAC"])
        self.arp_table.horizontalHeader().setStretchLastSection(True)
        arp_layout.addWidget(self.arp_table)

        # Anomalie
        self.tab_anom = QtWidgets.QWidget()
        tabs.addTab(self.tab_anom, "Anomalie (AI)")
        an_layout = QtWidgets.QVBoxLayout(self.tab_anom)
        controls = QtWidgets.QHBoxLayout()
        controls.addWidget(QtWidgets.QLabel("Czułość:"))
        self.anom_slider = QtWidgets.QSlider(QtCore.Qt.Horizontal)
        self.anom_slider.setMinimum(1); self.anom_slider.setMaximum(50); self.anom_slider.setValue(15)
        self.anom_slider.valueChanged.connect(self.on_anom_sens)
        controls.addWidget(self.anom_slider)
        controls.addStretch(1)
        an_layout.addLayout(controls)
        self.anom_table = QtWidgets.QTableWidget(0, 6)
        self.anom_table.setHorizontalHeaderLabels(["IP", "Score", "Pakiety", "Bajty", "Unikalne porty", "Ostatnie"])
        self.anom_table.horizontalHeader().setStretchLastSection(True)
        an_layout.addWidget(self.anom_table)

        # TI hits
        self.tab_ti = QtWidgets.QWidget()
        tabs.addTab(self.tab_ti, "Threat Intel")
        ti_layout = QtWidgets.QVBoxLayout(self.tab_ti)
        self.ti_table = QtWidgets.QTableWidget(0, 6)
        self.ti_table.setHorizontalHeaderLabels(["Czas", "Typ", "Wskaźnik", "Szczegół", "Źródło", "Gdzie"])
        self.ti_table.horizontalHeader().setStretchLastSection(True)
        ti_layout.addWidget(self.ti_table)

        self.statusBar().showMessage("Ready")

    def _enumerate_ifaces_async(self):
        self._iface_thread = QtCore.QThread(self)
        self._iface_worker = IfaceEnumerator()
        self._iface_worker.moveToThread(self._iface_thread)
        self._iface_thread.started.connect(self._iface_worker.run)
        self._iface_worker.result.connect(self._on_ifaces_ready)
        self._iface_thread.start()

    def _on_ifaces_ready(self, items):
        self._iface_thread.quit()
        self._iface_thread.wait(1000)
        self.iface_combo.clear()
        self.iface_map.clear()
        for label, info in items:
            self.iface_map[label] = info
            self.iface_combo.addItem(label)
        if self.iface_combo.count() > 0:
            self.iface_combo.setCurrentIndex(0)
            self.on_iface_change(0)
        else:
            self.iface_combo.addItem("Brak interfejsów (sprawdź Npcap/uprawnienia)")

    def _refresh_timer(self):
        try:
            self.refresh_packets(live=False)
            self.refresh_active()
            if self.selected_packet_id:
                self.show_packet_details(self.selected_packet_id)
        except Exception:
            pass

    def on_lang_change(self, idx):
        i18n.lang = "pl" if idx == 0 else "en"
        self.setWindowTitle(i18n.t("app_title"))
        self.btn_start.setText(i18n.t("start"))
        self.btn_pause.setText(i18n.t("pause") if not self.sniffer or not self.sniffer.paused else i18n.t("resume"))
        self.btn_stop.setText(i18n.t("stop"))
        self.btn_export.setText(i18n.t("export"))
        self.btn_save_filters.setText(i18n.t("save_filters"))
        self.btn_load_filters.setText(i18n.t("load_filters"))
        self.btn_load_ti.setText("Załaduj TI (JSON)")
        self.btn_update_ti.setText("Aktualizuj TI (OSINT)")
        self.btn_first.setText(i18n.t("first"))
        self.btn_prev.setText(i18n.t("prev"))
        self.btn_next.setText(i18n.t("next"))
        self.btn_last.setText(i18n.t("last"))
        # Tytuły zakładek zgodnie z kolejnością
        self.tabs.setTabText(0, i18n.t("sniffer"))
        self.tabs.setTabText(1, i18n.t("lan_scanner"))
        self.tabs.setTabText(2, i18n.t("active_by_traffic"))
        self.tabs.setTabText(3, "TLS / JA3")
        self.tabs.setTabText(4, "ARP / MITM")
        self.tabs.setTabText(5, "Anomalie (AI)")
        self.tabs.setTabText(6, "Threat Intel")
        self.table_model.layoutChanged.emit()

    def on_iface_change(self, idx):
        label = self.iface_combo.currentText()
        info = self.iface_map.get(label) or {}
        self.capture_iface = info.get("npf")
        self.psutil_iface = info.get("psutil")

    def on_preset(self, idx):
        if idx <= 0:
            return
        text = self.preset_combo.currentText()
        mapping = {
            "HTTP only (tcp port 80)": "tcp port 80",
            "DNS only (udp port 53)": "udp port 53",
            "TLS/HTTPS (tcp port 443)": "tcp port 443",
            "SMB (tcp port 445 or 139)": "(tcp port 445) or (tcp port 139)",
            "DHCP/BOOTP (udp port 67 or 68)": "(udp port 67) or (udp port 68)",
            "Zagrożenia (ftp/telnet/pop3) (tcp port 21 or 23 or 110 or 143)": "(tcp port 21) or (tcp port 23) or (tcp port 110) or (tcp port 143)"
        }
        self.filter_edit.setText(mapping.get(text, ""))

    def on_start(self):
        if self.sniffer:
            self.sniffer.stop()
            QtCore.QThread.msleep(100)
        if not self.capture_iface:
            self.on_status("Brak wybranego interfejsu.")
            return
        bpf = self.filter_edit.text().strip()
        self.sniffer = SnifferWorker(
            self.db, self.ai, self.geo, self.active_tr,
            iface=self.capture_iface, bpf_filter=bpf,
            ja3_collector=self.ja3c, arp_guard=self.arp_guard
        )
        self.sniffer.packetInserted.connect(self.on_packet_inserted)
        self.sniffer.statusMsg.connect(self.on_status)
        self.sniffer.start()
        self.btn_pause.setText(i18n.t("pause"))

    def on_pause_resume(self):
        if not self.sniffer:
            return
        if not self.sniffer.paused:
            self.sniffer.pause()
            self.btn_pause.setText(i18n.t("resume"))
        else:
            self.sniffer.resume()
            self.btn_pause.setText(i18n.t("pause"))

    def on_stop(self):
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None

    def on_export(self):
        menu = QtWidgets.QMenu(self)
        act_csv = menu.addAction(i18n.t("export_csv"))
        act_txt = menu.addAction(i18n.t("export_txt"))
        act_pcap = menu.addAction(i18n.t("export_pcap"))
        act = menu.exec_(QtGui.QCursor.pos())
        if not act:
            return
        if act == act_csv:
            path, _ = QtWidgets.QFileDialog.getSaveFileName(self, i18n.t("export_csv"), "", "CSV (*.csv)")
            if path:
                self.db.stream_export_csv(path)
                self.statusBar().showMessage("Zapisano CSV.")
        elif act == act_txt:
            path, _ = QtWidgets.QFileDialog.getSaveFileName(self, i18n.t("export_txt"), "", "TXT (*.txt)")
            if path:
                self.db.stream_export_txt(path)
                self.statusBar().showMessage("Zapisano TXT.")
        elif act == act_pcap:
            path, _ = QtWidgets.QFileDialog.getSaveFileName(self, i18n.t("export_pcap"), "", "PCAP (*.pcap)")
            if path:
                self.db.stream_export_pcap(path)
                self.statusBar().showMessage("Zapisano PCAP.")

    def on_save_filters(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, i18n.t("save_filters"), "", "JSON (*.json)")
        if not path:
            return
        import json
        data = {"filters": self.filter_edit.text().strip(), "ts": datetime.now().isoformat()}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        self.statusBar().showMessage("Zapisano filtry.")

    def on_load_filters(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, i18n.t("load_filters"), "", "JSON (*.json)")
        if not path:
            return
        import json
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.filter_edit.setText(data.get("filters",""))
            self.statusBar().showMessage("Wczytano filtry.")
        except Exception as e:
            self.statusBar().showMessage(f"Błąd: {e}")

    def on_load_ti(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Załaduj TI (JSON)", "", "JSON (*.json)")
        if not path:
            return
        ok = self.ti.load_file(path)
        cnt = self.ti.counts()
        if ok:
            self.ai_log(f"[TI] Wczytano {path}. IP={cnt['ips']} subnets={cnt['subnets']} domains={cnt['domains']} url={cnt['url_patterns']} banners={cnt['http_banners']}")
            self.statusBar().showMessage("Wczytano bazę TI.")
        else:
            self.statusBar().showMessage("Błąd wczytywania bazy TI.")

    def update_ti_osint_async(self, auto=False):
        def worker():
            try:
                if not self.ti.has_internet():
                    self.ai_log("[TI] Brak internetu — pomijam aktualizację OSINT.")
                    return
                self.tiStatusSig.emit("Pobieram TI (OSINT)...")
                res = self.ti.update_from_osint()
                cnt = self.ti.counts()
                self.ai_log(f"[TI] Aktualizacja OSINT: dodano IP={res['ips']} domains={res['domains']}. Teraz: IP={cnt['ips']} domains={cnt['domains']}")
                self.tiStatusSig.emit("Aktualizacja TI zakończona.")
            except Exception as e:
                self.ai_log(f"[TI] Błąd aktualizacji OSINT: {e}")
        threading.Thread(target=worker, daemon=True).start()

    def on_packet_inserted(self, pid):
        self.refresh_packets(live=True)
        self.refresh_active()

    def refresh_packets(self, live=False):
        total, rows = self.db.get_page_from_end(self.page_size, self.page_index_from_end, only_threats=self.only_threats)
        mapped = []
        for r in rows:
            pid, ts, sip, dip, sport, dport, proto, length, summary, score, tags = r
            mapped.append({
                "id": pid,
                "ts": ts,
                "src_ip": sip, "dst_ip": dip, "src_port": sport, "dst_port": dport, "proto": proto,
                "length": length, "summary": summary, "threat_score": score or 0.0, "threat_tags": tags or ""
            })
        self.table_model.setRows(mapped)
        pages = max(1, math.ceil(total / self.page_size))
        self.range_slider.setMaximum(pages-1)
        if self.auto_follow:
            self.page_index_from_end = 0
            self.range_slider.setValue(0)
        if self.selected_packet_id:
            self._restore_selection(self.selected_packet_id)

    def _restore_selection(self, pid):
        model = self.table_model
        for row_idx, r in enumerate(model.rows):
            if r["id"] == pid:
                sel = QtCore.QItemSelectionModel.Select | QtCore.QItemSelectionModel.Rows
                self.table.selectionModel().select(model.index(row_idx, 0), sel)
                self.table.scrollTo(model.index(row_idx, 0))
                return

    def on_table_click(self, index):
        self.auto_follow_chk.setChecked(False)
        self.auto_follow = False
        model = self.table_model
        row = index.row()
        if row < 0 or row >= len(model.rows):
            return
        pid = model.rows[row]["id"]
        self.selected_packet_id = pid
        self.show_packet_details(pid)

    def _parse_http_dns_for_details(self, raw):
        http_host = ""
        http_path = ""
        http_server = ""
        user_agent = ""
        dns_query = ""
        s = safe_decode(raw)
        try:
            lines = s.split("\r\n")
            if lines and lines[0]:
                if lines[0].startswith(("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ")):
                    parts = lines[0].split()
                    if len(parts) >= 2:
                        http_path = parts[1]
                if lines[0].startswith("HTTP/"):
                    for ln in lines[1:6]:
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
        return http_host, http_path, http_server, user_agent, dns_query

    def show_packet_details(self, pid):
        rec = self.db.get_packet_by_id(pid)
        if not rec:
            return
        ts = datetime.fromtimestamp(rec["ts"]).isoformat()
        sip = rec["src_ip"]; dip = rec["dst_ip"]
        sport = rec["src_port"]; dport = rec["dst_port"]
        proto = rec["proto"]
        score = rec["threat_score"] or 0.0
        tags = rec["threat_tags"] or ""
        ext_ip = rec.get("ext_ip") or ""
        raw = rec["raw"] or b""

        detail = []
        detail.append(f"ID: {rec['id']}  Time: {ts}")
        detail.append(f"Proto: {proto}")
        detail.append(f"From: {sip}{(':'+str(sport)) if sport else ''}")
        detail.append(f"To:   {dip}{(':'+str(dport)) if dport else ''}")
        detail.append(f"Len: {rec['length']}  Risk: {score:.2f}  Tags: {tags}")
        detail.append(f"Summary: {rec['summary']}")
        if ext_ip:
            detail.append(f"External IP: {ext_ip}")

        creds = extract_credentials(raw)
        if creds:
            detail.append("Credentials captured:")
            for ctype, value in creds:
                detail.append(f"- {ctype}: {value}")

        http_host, http_path, http_server, user_agent, dns_q = self._parse_http_dns_for_details(raw)
        pkt_info = {
            "src_ip": sip, "dst_ip": dip, "ext_ip": ext_ip,
            "http_host": http_host, "http_path": http_path,
            "http_server": http_server, "user_agent": user_agent,
            "dns_query": dns_q, "proto": proto, "raw": raw,
            "src_port": sport, "dst_port": dport
        }
        try:
            hits = self.ti.match_packet(pkt_info)
        except Exception:
            hits = []
        if hits:
            detail.append("Threat Intel hits:")
            for h in hits:
                ind = h.get("indicator")
                th = h.get("threat")
                src = h.get("source")
                w = h.get("where")
                if h.get("type") == "ip" and h.get("matched_cidr"):
                    ind = f"{ind} in {h.get('matched_cidr')}"
                if h.get("type") == "domain" and h.get("matched_suffix"):
                    ind = f"{ind} (suffix {h.get('matched_suffix')})"
                detail.append(f"- {h.get('type')}={ind} | {th} [{src}] where={w}")

        self.details_text.setPlainText("\n".join(detail))
        self.hex_text.setPlainText(hexdump_lines(raw))
        self.ascii_text.setPlainText(safe_decode(raw))

        geo = self.geo.cache.get(ext_ip, {}) if ext_ip else {}
        if geo:
            s = f"IP: {geo.get('ip')}\nCountry: {geo.get('country')} ({geo.get('cc')})\nRegion: {geo.get('region')}\nCity: {geo.get('city')}\nOrg: {geo.get('org')}\nASN: {geo.get('asn')}"
        else:
            s = "—"
        self.geo_text.setPlainText(s)

    def on_status(self, msg):
        self.statusBar().showMessage(msg, 3000)

    def on_geo_result(self, ip, data):
        if self.selected_packet_id:
            rec = self.db.get_packet_by_id(self.selected_packet_id)
            if rec and (rec.get("ext_ip") == ip):
                self.show_packet_details(self.selected_packet_id)

    def update_sys_stats(self):
        try:
            import psutil
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory().percent
            self.cpu_label.setText(f"{i18n.t('cpu')}: {cpu:.0f}%")
            self.mem_label.setText(f"{i18n.t('mem')}: {mem:.0f}%")
        except Exception:
            pass

    def _nav_to(self, where):
        total = self.db.count(only_threats=self.only_threats)
        pages = max(1, math.ceil(total / self.page_size))
        if where == "first":
            self.page_index_from_end = pages-1
        elif where == "prev":
            self.page_index_from_end = min(self.page_index_from_end+1, pages-1)
        elif where == "next":
            self.page_index_from_end = max(0, self.page_index_from_end-1)
        elif where == "last":
            self.page_index_from_end = 0
        self.range_slider.setValue(self.page_index_from_end)
        self.refresh_packets()

    def on_slider(self, val):
        self.page_index_from_end = val
        self.refresh_packets()

    def on_auto_follow(self, st):
        self.auto_follow = (st == QtCore.Qt.Checked)

    def on_only_threats(self, st):
        self.only_threats = (st == QtCore.Qt.Checked)
        self.refresh_packets()

    def ai_log(self, msg):
        try:
            self.aiLogSig.emit(msg)
        except Exception:
            pass

    def _on_ai_log(self, msg):
        try:
            ts = datetime.now().strftime("%H:%M:%S")
            self.ai_log_text.appendPlainText(f"[{ts}] {msg}")
            self.ai_log_text.moveCursor(QtGui.QTextCursor.End)
        except Exception:
            pass

    # LAN
    def on_scan_lan(self):
        if not self.capture_iface and not self.psutil_iface:
            self.on_status("Brak wybranego interfejsu.")
            return
        self.lan_table.setRowCount(0)
        self.lan_progress.setValue(0)
        self.lan_progress.setMaximum(100)
        self.lan_status.setText("Start...")
        self.lscanner = LanScanner(
            iface_capture=self.capture_iface,
            iface_psutil=self.psutil_iface,
            oui_matcher=self.oui,
            udp_quick=self.udp_quick_chk.isChecked()
        )
        self.lscanner.progress.connect(self.on_lan_progress)
        self.lscanner.result.connect(self.on_lan_result)
        self.lscanner.statusMsg.connect(self.on_lan_status)
        self.lscanner.start()

    def on_lan_progress(self, v, total):
        try:
            p = int((v/max(1,total)) * 100)
            self.lan_progress.setValue(p)
        except Exception:
            self.lan_progress.setValue(0)

    def on_lan_status(self, msg):
        self.lan_status.setText(msg)

    def on_lan_result(self, devices):
        self.lan_table.setRowCount(0)
        for d in devices:
            r = self.lan_table.rowCount()
            self.lan_table.insertRow(r)
            self.lan_table.setItem(r, 0, QtWidgets.QTableWidgetItem(d.get("ip","")))
            self.lan_table.setItem(r, 1, QtWidgets.QTableWidgetItem(d.get("mac","")))
            self.lan_table.setItem(r, 2, QtWidgets.QTableWidgetItem(d.get("vendor","")))
            self.lan_table.setItem(r, 3, QtWidgets.QTableWidgetItem(d.get("hostname","")))
            self.lan_table.setItem(r, 4, QtWidgets.QTableWidgetItem(d.get("type","")))
            self.lan_table.setItem(r, 5, QtWidgets.QTableWidgetItem(",".join(str(p) for p in d.get("ports",[]))))
            self.lan_table.setItem(r, 6, QtWidgets.QTableWidgetItem(",".join(str(p) for p in d.get("udp",[]))))
        self.lan_status.setText(f"Gotowe. Znaleziono: {len(devices)}")

    def on_export_devices(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, i18n.t("export_devices_csv"), "", "CSV (*.csv)")
        if not path:
            return
        import csv
        with open(path, "w", newline="", encoding="utf-8") as f:
            wr = csv.writer(f)
            wr.writerow(["IP","MAC","Vendor","Hostname","Typ","TCP ports","UDP ports"])
            for r in range(self.lan_table.rowCount()):
                row = []
                for c in range(self.lan_table.columnCount()):
                    it = self.lan_table.item(r, c)
                    row.append(it.text() if it else "")
                wr.writerow(row)
        self.statusBar().showMessage("Zapisano listę urządzeń.")

    def on_load_oui(self):
        cnt = self.oui.try_load_local_oui_files()
        if cnt > 0:
            self.statusBar().showMessage(f"Załadowano {cnt} wpisów OUI z lokalnych plików.")
        else:
            self.statusBar().showMessage("Nie znaleziono lokalnych plików OUI.")

    def on_lan_context(self, pos):
        row = self.lan_table.currentRow()
        if row < 0:
            return
        ip = self.lan_table.item(row, 0).text()
        menu = QtWidgets.QMenu(self)
        act_ping = menu.addAction(i18n.t("ping"))
        act_tr = menu.addAction(i18n.t("traceroute"))
        act_ps = menu.addAction(i18n.t("port_scan"))
        act = menu.exec_(self.lan_table.viewport().mapToGlobal(pos))
        if act == act_ping:
            self._run_ping(ip)
        elif act == act_tr:
            self._run_traceroute(ip)
        elif act == act_ps:
            self._run_port_scan(ip)

    def _run_ping(self, ip):
        out = ""
        try:
            if WINDOWS:
                out = run_subprocess(["ping", "-n", "4", ip], timeout=8)
            else:
                out = run_subprocess(["ping", "-c", "4", ip], timeout=8)
        except Exception as e:
            out = str(e)
        self._show_text_dialog("Ping", out)

    def _run_traceroute(self, ip):
        out = ""
        try:
            if WINDOWS:
                out = run_subprocess(["tracert", "-d", ip], timeout=25)
            else:
                out = run_subprocess(["traceroute", "-n", ip], timeout=25)
        except Exception as e:
            out = str(e)
        self._show_text_dialog("Traceroute", out)

    def _run_port_scan(self, ip):
        out = []
        ports = list(range(1, 1025)) + [1433,1521,2049,2483,2484,3306,3389,5432,5632,5900,6379,8080,8443,9000,9200,11211,27017]
        for p in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.15)
                r = s.connect_ex((ip, p))
                s.close()
                if r == 0:
                    out.append(p)
            except Exception:
                pass
        text = f"Otwarte TCP porty na {ip}:\n" + (", ".join(str(x) for x in out) if out else "(brak)")
        self._show_text_dialog("Port scan", text)

    def _show_text_dialog(self, title, text):
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle(title)
        lay = QtWidgets.QVBoxLayout(dlg)
        ed = QtWidgets.QPlainTextEdit()
        ed.setReadOnly(True)
        ed.setPlainText(text)
        lay.addWidget(ed)
        btn = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok)
        btn.accepted.connect(dlg.accept)
        lay.addWidget(btn)
        dlg.resize(700, 500)
        dlg.exec_()

    # Active (ruch)
    def refresh_active(self, sort_dir=None):
        snap = self.active_tr.get_snapshot()
        if sort_dir == "up":
            snap = sorted(snap, key=lambda x: ip_sort_key(x["ip"]))
        elif sort_dir == "down":
            snap = sorted(snap, key=lambda x: ip_sort_key(x["ip"]), reverse=True)
        self.active_table.setRowCount(0)
        for d in snap:
            r = self.active_table.rowCount()
            self.active_table.insertRow(r)
            self.active_table.setItem(r, 0, QtWidgets.QTableWidgetItem(d["ip"]))
            self.active_table.setItem(r, 1, QtWidgets.QTableWidgetItem(str(d["packets"])))
            self.active_table.setItem(r, 2, QtWidgets.QTableWidgetItem(str(d["bytes"])))
            self.active_table.setItem(r, 3, QtWidgets.QTableWidgetItem(",".join(str(p) for p in d["ports"])))
            self.active_table.setItem(r, 4, QtWidgets.QTableWidgetItem(d.get("type","")))

    def on_active_context(self, pos):
        row = self.active_table.currentRow()
        if row < 0:
            return
        ip = self.active_table.item(row, 0).text()
        menu = QtWidgets.QMenu(self)
        act_ping = menu.addAction(i18n.t("ping"))
        act_tr = menu.addAction(i18n.t("traceroute"))
        act_ps = menu.addAction(i18n.t("port_scan"))
        act = menu.exec_(self.active_table.viewport().mapToGlobal(pos))
        if act == act_ping:
            self._run_ping(ip)
        elif act == act_tr:
            self._run_traceroute(ip)
        elif act == act_ps:
            self._run_port_scan(ip)

    # TLS/JA3
    def refresh_ja3(self):
        evs = self.ja3c.get_events()
        self.ja3_table.setRowCount(0)
        for e in evs[-300:]:
            r = self.ja3_table.rowCount()
            self.ja3_table.insertRow(r)
            self.ja3_table.setItem(r, 0, QtWidgets.QTableWidgetItem(datetime.fromtimestamp(e["ts"]).strftime("%H:%M:%S")))
            self.ja3_table.setItem(r, 1, QtWidgets.QTableWidgetItem(e["dir"]))
            self.ja3_table.setItem(r, 2, QtWidgets.QTableWidgetItem(e["src"]))
            self.ja3_table.setItem(r, 3, QtWidgets.QTableWidgetItem(e["dst"]))
            self.ja3_table.setItem(r, 4, QtWidgets.QTableWidgetItem(e.get("sni","")))
            self.ja3_table.setItem(r, 5, QtWidgets.QTableWidgetItem(e.get("ja3") or ""))
            self.ja3_table.setItem(r, 6, QtWidgets.QTableWidgetItem(e.get("ja3s") or ""))
            s = e.get("ja3_str") or e.get("ja3s_str") or ""
            self.ja3_table.setItem(r, 7, QtWidgets.QTableWidgetItem(s))

    # ARP
    def refresh_arp(self):
        confs = self.arp_guard.get_conflicts()
        self.arp_table.setRowCount(0)
        for c in confs[-200:]:
            r = self.arp_table.rowCount()
            self.arp_table.insertRow(r)
            self.arp_table.setItem(r, 0, QtWidgets.QTableWidgetItem(datetime.fromtimestamp(c["ts"]).strftime("%H:%M:%S")))
            self.arp_table.setItem(r, 1, QtWidgets.QTableWidgetItem(c["ip"]))
            self.arp_table.setItem(r, 2, QtWidgets.QTableWidgetItem(", ".join(c["macs"])))
            self.arp_table.setItem(r, 3, QtWidgets.QTableWidgetItem(c["new"]))
            self.arp_table.setItem(r, 4, QtWidgets.QTableWidgetItem(str(len(c["macs"]))))

    # Anomalie
    def on_anom_sens(self, val):
        self.anom.set_sensitivity(float(val)/100.0 + 0.01)

    def refresh_anomalies(self):
        res = self.anom.get_results()
        self.anom_table.setRowCount(0)
        for a in res:
            r = self.anom_table.rowCount()
            self.anom_table.insertRow(r)
            self.anom_table.setItem(r, 0, QtWidgets.QTableWidgetItem(a["ip"]))
            self.anom_table.setItem(r, 1, QtWidgets.QTableWidgetItem(f"{a['score']:.2f}"))
            self.anom_table.setItem(r, 2, QtWidgets.QTableWidgetItem(str(a["packets"])))
            self.anom_table.setItem(r, 3, QtWidgets.QTableWidgetItem(str(a["bytes"])))
            self.anom_table.setItem(r, 4, QtWidgets.QTableWidgetItem(str(a["uniq_ports"])))
            self.anom_table.setItem(r, 5, QtWidgets.QTableWidgetItem("—"))

    # TI tab
    def refresh_ti_hits(self):
        hits = self.ti.get_last_hits() if hasattr(self.ti, "get_last_hits") else []
        self.ti_table.setRowCount(0)
        for h in hits[-300:]:
            r = self.ti_table.rowCount()
            self.ti_table.insertRow(r)
            self.ti_table.setItem(r, 0, QtWidgets.QTableWidgetItem(datetime.fromtimestamp(h["ts"]).strftime("%H:%M:%S")))
            self.ti_table.setItem(r, 1, QtWidgets.QTableWidgetItem(h.get("type","")))
            self.ti_table.setItem(r, 2, QtWidgets.QTableWidgetItem(h.get("indicator","")))
            detail = ""
            if h.get("matched_cidr"): detail = f"in {h.get('matched_cidr')}"
            if h.get("matched_suffix"): detail = f"(suffix {h.get('matched_suffix')})"
            self.ti_table.setItem(r, 3, QtWidgets.QTableWidgetItem(detail))
            self.ti_table.setItem(r, 4, QtWidgets.QTableWidgetItem(h.get("source","")))
            self.ti_table.setItem(r, 5, QtWidgets.QTableWidgetItem(h.get("where","")))