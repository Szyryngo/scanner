import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, IP
from scapy.utils import wrpcap
from datetime import datetime
import threading
import psutil

# === AI Prediction Stub ===
def extract_features(pkt):
    return [len(pkt), pkt.time]

def predict_packet_features(features):
    return 0.7 if features[0] > 100 else 0.2

# === GUI Setup ===
root = tk.Tk()
root.title("NetSentinel AI")
root.geometry("1000x600")
root.configure(bg="#1e1e1e")

# === Top Bar ===
top_bar = tk.Frame(root, bg="#2d2d2d")
top_bar.pack(fill=tk.X)

title_label = tk.Label(top_bar, text="NetSentinel AI v1.0", bg="#2d2d2d", fg="lightblue", font=("Segoe UI", 10, "bold"))
title_label.pack(side=tk.LEFT, padx=10)

status_label = tk.Label(top_bar, text="", bg="#2d2d2d", fg="lightgreen", font=("Segoe UI", 10))
status_label.pack(side=tk.RIGHT, padx=10)

def update_status():
    cpu = psutil.cpu_percent()
    ram = psutil.virtual_memory().percent
    status_label.config(text=f"CPU: {cpu:.1f}% | RAM: {ram:.1f}%")
    root.after(1000, update_status)

update_status()

# === Main Frames ===
main_frame = tk.Frame(root, bg="#1e1e1e")
main_frame.pack(fill=tk.BOTH, expand=True)

left_frame = tk.Frame(main_frame, bg="#1e1e1e", width=200)
left_frame.pack(side=tk.LEFT, fill=tk.Y)

right_frame = tk.Frame(main_frame, bg="#1e1e1e")
right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

# === Filter Section ===
filter_frame = tk.Frame(right_frame, bg="#1e1e1e")
filter_frame.pack(fill=tk.X, padx=10, pady=5)

filter_var = tk.StringVar()
tk.Label(filter_frame, text="Filtr BPF:", bg="#1e1e1e", fg="white").pack(side=tk.LEFT)
filter_entry = tk.Entry(filter_frame, textvariable=filter_var, width=30)
filter_entry.pack(side=tk.LEFT, padx=5)
tk.Button(filter_frame, text="🔍 Zastosuj", command=lambda: apply_filter(), bg="#3a3a3a", fg="white").pack(side=tk.LEFT)

# === Packet List ===
packet_listbox = tk.Listbox(right_frame, bg="#121212", fg="white", font=("Consolas", 10))
packet_listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# === Control Buttons ===
control_frame = tk.Frame(right_frame, bg="#1e1e1e")
control_frame.pack(fill=tk.X, padx=10, pady=5)

tk.Button(control_frame, text="📦 Eksport PCAP", command=lambda: export_pcap(), bg="#3a3a3a", fg="white").pack(side=tk.LEFT, padx=5)

# === Packet Storage ===
packets = []
filtered_packets = []

# === Sniffer Thread ===
def packet_callback(pkt):
    packets.append(pkt)
    if filter_var.get():
        if pkt.haslayer(IP) and filter_var.get().lower() in pkt.summary().lower():
            filtered_packets.append(pkt)
            features = extract_features(pkt)
            weight = predict_packet_features(features)
            label = f"{len(filtered_packets)}. {pkt.summary()} | AI: {weight:.2f}"
            packet_listbox.insert(0, label)
            packet_listbox.itemconfig(0, {'fg': 'red' if weight >= 0.5 else 'white'})
    else:
        features = extract_features(pkt)
        weight = predict_packet_features(features)
        label = f"{len(packets)}. {pkt.summary()} | AI: {weight:.2f}"
        packet_listbox.insert(0, label)
        packet_listbox.itemconfig(0, {'fg': 'red' if weight >= 0.5 else 'white'})

def start_sniffing():
    sniff(prn=packet_callback, store=False)

sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
sniff_thread.start()

# === Filter Function ===
def apply_filter():
    bpf = filter_var.get()
    filtered_packets.clear()
    packet_listbox.delete(0, tk.END)
    for pkt in packets:
        if pkt.haslayer(IP) and bpf.lower() in pkt.summary().lower():
            filtered_packets.append(pkt)
            features = extract_features(pkt)
            weight = predict_packet_features(features)
            label = f"{len(filtered_packets)}. {pkt.summary()} | AI: {weight:.2f}"
            packet_listbox.insert(0, label)
            packet_listbox.itemconfig(0, {'fg': 'red' if weight >= 0.5 else 'white'})

# === Export Function ===
def export_pcap():
    filename = f"filtered_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    try:
        wrpcap(filename, filtered_packets)
        print(f"[📦] Eksport PCAP zakończony: {filename}")
    except Exception as e:
        print(f"[❌] Błąd eksportu PCAP: {e}")

# === Start GUI ===
root.mainloop()
