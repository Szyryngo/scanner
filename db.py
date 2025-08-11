import sqlite3
import threading
import math
import csv
from datetime import datetime
from .utils import DB_PATH, to_bytes
from scapy.all import Ether, Raw, PcapWriter  # type: ignore

class DBManager:
    def __init__(self, path=DB_PATH):
        self.path = path
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self._create()

    def _create(self):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL,
                iface TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                proto TEXT,
                length INTEGER,
                raw BLOB,
                summary TEXT,
                threat_score REAL,
                threat_tags TEXT,
                ext_ip TEXT
            );
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(ts);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(src_ip);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_packets_dst ON packets(dst_ip);")
            self.conn.commit()

    def insert_packet(self, rec):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("""
                INSERT INTO packets (ts, iface, src_ip, dst_ip, src_port, dst_port, proto, length, raw, summary, threat_score, threat_tags, ext_ip)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rec.get("ts"), rec.get("iface"), rec.get("src_ip"), rec.get("dst_ip"),
                rec.get("src_port"), rec.get("dst_port"), rec.get("proto"), rec.get("length"),
                sqlite3.Binary(rec.get("raw") or b""), rec.get("summary"), rec.get("threat_score"),
                rec.get("threat_tags"), rec.get("ext_ip") or ""
            ))
            self.conn.commit()
            return cur.lastrowid

    def count(self, only_threats=False):
        with self.lock:
            cur = self.conn.cursor()
            if only_threats:
                cur.execute("SELECT COUNT(*) FROM packets WHERE threat_score >= 1.0")
            else:
                cur.execute("SELECT COUNT(*) FROM packets")
            return cur.fetchone()[0]

    def get_page_from_end(self, page_size=300, page_index_from_end=0, only_threats=False):
        with self.lock:
            cur = self.conn.cursor()
            where = "WHERE 1=1"
            if only_threats:
                where += " AND threat_score >= 1.0"
            cur.execute(f"SELECT COUNT(*) FROM packets {where}")
            total = cur.fetchone()[0]
            if total <= 0:
                return total, []
            pages = max(1, math.ceil(total / page_size))
            page_index_from_end = max(0, min(page_index_from_end, pages-1))
            page = pages - 1 - page_index_from_end
            offset = page * page_size
            cur.execute(f"""
                SELECT id, ts, src_ip, dst_ip, src_port, dst_port, proto, length, summary, threat_score, threat_tags
                FROM packets
                {where}
                ORDER BY id ASC
                LIMIT ? OFFSET ?
            """, (page_size, offset))
            rows = cur.fetchall()
            return total, rows

    def get_packet_by_id(self, pid):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("""
                SELECT id, ts, iface, src_ip, dst_ip, src_port, dst_port, proto, length, raw, summary, threat_score, threat_tags, ext_ip
                FROM packets WHERE id=?
            """, (pid,))
            r = cur.fetchone()
            if not r:
                return None
            keys = ["id","ts","iface","src_ip","dst_ip","src_port","dst_port","proto","length","raw","summary","threat_score","threat_tags","ext_ip"]
            return dict(zip(keys, r))

    def stream_export_csv(self, path):
        with self.lock, open(path, "w", newline="", encoding="utf-8") as f:
            cur = self.conn.cursor()
            writer = csv.writer(f)
            writer.writerow(["id","time","iface","src_ip","src_port","dst_ip","dst_port","proto","length","summary","threat_score","threat_tags","ext_ip"])
            for row in cur.execute("SELECT id, ts, iface, src_ip, src_port, dst_ip, dst_port, proto, length, summary, threat_score, threat_tags, ext_ip FROM packets ORDER BY id ASC"):
                (pid, ts, iface, sip, sport, dip, dport, proto, length, summary, score, tags, ext_ip) = row
                tstr = datetime.fromtimestamp(ts).isoformat()
                writer.writerow([pid, tstr, iface, sip, sport or "", dip, dport or "", proto, length, summary, f"{(score or 0.0):.2f}", tags or "", ext_ip or ""])

    def stream_export_txt(self, path):
        with self.lock, open(path, "w", encoding="utf-8") as f:
            cur = self.conn.cursor()
            for row in cur.execute("SELECT id, ts, src_ip, src_port, dst_ip, dst_port, proto, length, summary, threat_score, threat_tags FROM packets ORDER BY id ASC"):
                pid, ts, sip, sport, dip, dport, proto, length, summary, score, tags = row
                tstr = datetime.fromtimestamp(ts).isoformat()
                f.write(f"[{pid}] {tstr} {sip}:{sport or ''} -> {dip}:{dport or ''} {proto} len={length} score={score} tags={tags} {summary}\n")

    def stream_export_pcap(self, path):
        with self.lock:
            cur = self.conn.cursor()
            writer = PcapWriter(path, append=False, sync=True)
            cur.execute("SELECT raw FROM packets ORDER BY id ASC")
            while True:
                rows = cur.fetchmany(5000)
                if not rows:
                    break
                for (raw,) in rows:
                    if not raw:
                        continue
                    raw_b = to_bytes(raw)
                    try:
                        pkt = Ether(raw_b)
                    except Exception:
                        pkt = Raw(raw_b)
                    writer.write(pkt)
            writer.close()