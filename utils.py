import os
import re
import sys
import time
import csv
import json
import math
import queue
import socket
import base64
import ipaddress
import platform
import subprocess
import urllib.parse
from datetime import datetime

APP_NAME = "NetSentinel-AI"
VERSION = "1.1.0"

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
CACHE_DIR = os.path.join(BASE_DIR, "cache")
os.makedirs(CACHE_DIR, exist_ok=True)

DB_PATH = os.path.join(CACHE_DIR, "packets.db")
OUI_CACHE_PATH = os.path.join(CACHE_DIR, "oui_cache.json")
GEO_CACHE_PATH = os.path.join(CACHE_DIR, "geo_cache.json")
AI_MEMORY_PATH = os.path.join(CACHE_DIR, "ai_memory.json")
TI_DB_PATH = os.path.join(CACHE_DIR, "ti_db.json")  # NOWE: baza TI (opcjonalna)

OUI_LOCAL_FILES = ["oui.txt", "ieee oui.txt", "oui.csv", "IEEE OUI.txt", "IEEE_OUI.txt"]

WINDOWS = platform.system().lower().startswith("win")

def now_ts():
    return time.time()

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True

def safe_decode(b: bytes, enc_list=("utf-8", "latin1")):
    if not isinstance(b, (bytes, bytearray)):
        return str(b)
    for enc in enc_list:
        try:
            return b.decode(enc, errors="ignore")
        except Exception:
            continue
    try:
        return b.decode("latin1", errors="ignore")
    except Exception:
        return ""

def hexdump_lines(data: bytes, width=16):
    if not isinstance(data, (bytes, bytearray)):
        data = bytes(data or b"")
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_bytes = " ".join(f"{b:02X}" for b in chunk)
        ascii_bytes = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08X}  {hex_bytes:<{width*3}}  {ascii_bytes}")
    return "\n".join(lines)

def ip_sort_key(ip):
    try:
        return tuple(int(x) for x in ip.split("."))
    except Exception:
        return (999, 999, 999, 999)

def mask_sensitive(text, keep=2):
    if not text:
        return text
    if len(text) <= keep:
        return "*" * len(text)
    return text[:keep] + "*" * (len(text)-keep)

def extract_title(html):
    try:
        m = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if m:
            t = m.group(1)
            t = re.sub(r'\s+', ' ', t).strip()
            return t[:200]
        return ""
    except Exception:
        return ""

def b64_try_decode(payload):
    try:
        s = payload.strip()
        if not s:
            return ""
        if re.match(r"^[A-Za-z0-9+/=]+$", s) and len(s) % 4 == 0:
            return base64.b64decode(s, validate=False).decode("latin1", errors="ignore")
        return ""
    except Exception:
        return ""

def guess_if_human_friendly_name(d):
    txt = (d.get("description") or "") + " " + (d.get("name") or "") + " " + (d.get("friendly_name") or "")
    txt_low = txt.lower()
    if "wi-fi" in txt_low or "wireless" in txt_low or "802.11" in txt_low or "wlan" in txt_low:
        return "Wi‑Fi"
    return "Karta sieciowa"

def filter_virtual_ifaces(d):
    txt = (d.get("description") or "") + " " + (d.get("name") or "") + " " + (d.get("friendly_name") or "")
    txt_low = txt.lower()
    bad = ["hyper-v", "vmware", "virtualbox", "npcap loopback", "loopback", "tap", "tun", "docker", "hamachi", "bluetooth", "vmbus", "vethernet"]
    if any(b in txt_low for b in bad):
        return False
    return True

def to_bytes(obj):
    if isinstance(obj, (bytes, bytearray)):
        return bytes(obj)
    try:
        return bytes(obj)
    except Exception:
        return b""

def ensure_requests():
    try:
        import requests  # noqa
    except Exception:
        raise RuntimeError("requests is required. Try: pip install requests")

def run_subprocess(cmd, timeout=10):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=False, timeout=timeout)
        return out.decode("utf-8", errors="ignore")
    except Exception as e:
        return str(e)

def extract_credentials(raw_bytes):
    """
    Zwraca listę krotek (typ, wartość) z poświadczeniami wykrytymi w pakiecie.
    Nie maskuje wartości.
    Obsługa: HTTP Basic, FTP/POP3 USER/PASS, IMAP LOGIN, telnet login/password,
    pola formularzy HTTP (application/x-www-form-urlencoded).
    """
    s = safe_decode(raw_bytes)
    creds = []

    # HTTP Basic
    for m in re.finditer(r'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)', s, re.IGNORECASE):
        b64 = m.group(1)
        cred = b64_try_decode(b64)
        if cred:
            creds.append(("HTTP Basic", cred))

    # FTP/POP3
    for m in re.finditer(r'(?mi)^(USER)\s+(.+)$', s):
        creds.append(("FTP/POP3 USER", m.group(2).strip()))
    for m in re.finditer(r'(?mi)^(PASS)\s+(.+)$', s):
        creds.append(("FTP/POP3 PASS", m.group(2).strip()))

    # IMAP LOGIN
    for m in re.finditer(r'(?i)\bLOGIN\s+(\S+)\s+(\S+)', s):
        creds.append(("IMAP LOGIN", f"{m.group(1)} {m.group(2)}"))

    # Telnet: login: / password:
    for m in re.finditer(r'(?i)login:\s*([^\r\n]+)', s):
        v = (m.group(1) or "").strip()
        if v:
            creds.append(("Telnet login", v))
    for m in re.finditer(r'(?i)password:\s*([^\r\n]+)', s):
        v = (m.group(1) or "").strip()
        if v:
            creds.append(("Telnet password", v))

    # HTTP form (urlencoded)
    body = s
    if "\r\n\r\n" in s:
        body = s.split("\r\n\r\n", 1)[1]
    if any(k in body.lower() for k in ["username=", "user=", "login=", "email="]) and any(k in body.lower() for k in ["password=", "pass=", "pwd=", "passwd="]):
        pairs = {}
        for key in ["username","user","login","email","userid","name"]:
            m = re.search(key + r'=([^&\s]+)', body, re.IGNORECASE)
            if m:
                pairs[key] = urllib.parse.unquote_plus(m.group(1))
        for key in ["password","pass","pwd","passwd"]:
            m = re.search(key + r'=([^&\s]+)', body, re.IGNORECASE)
            if m:
                pairs[key] = urllib.parse.unquote_plus(m.group(1))
        if pairs:
            parts = [f"{k}={v}" for k, v in pairs.items()]
            creds.append(("HTTP form", " ".join(parts)))

    return creds