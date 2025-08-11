import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, IP, raw
from scapy.utils import wrpcap
from datetime import datetime
import threading
import psutil
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import time

# === AI Prediction Stub ===
def extract_features(pkt):
    return [len(pkt), pkt.time]

def predict_packet_features(features):
    return 0.7 if features[0] > 100 else 0.2

# === GUI Setup ===
root = tk.Tk()
root.title("NetSentinel AI")
root.geometry("1200x700")
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

# === Fullscreen Toggle ===
def toggle_fullscreen():
    root.attributes("-fullscreen", not root.attributes("-fullscreen"))

fullscreen_btn = tk.Button(top_bar, text="🔲", command=toggle_fullscreen, bg="#2d2d2d", fg="white")
fullscreen_btn.pack(side=tk.RIGHT, padx=5)

# === Main Frames ===
main_frame = tk.Frame(root, bg="#1e1e1e")
main_frame.pack(fill=tk.BOTH, expand=True)

left_frame = tk.Frame(main_frame, bg="#1e1e1e", width=400)
left_frame.pack(side=tk.LEFT, fill=tk.Y)

right_frame = tk.Frame(main_frame, bg="#1e1e1e")
right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

# === Tabs in Left Panel ===
tabs = ttk.Notebook(left_frame)
tabs.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

style_tab = tk.Text(tabs, bg="#1e1e1e", fg="white", font=("Consolas", 9), wrap=tk.NONE)
hex_tab = tk.Text(tabs, bg="#1e1e1e", fg="white", font=("Consolas", 9), wrap=tk.NONE)

tabs.add(style_tab, text="Struktura")
tabs.add(hex_tab, text="HEX / ASCII")

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

def on_packet_select(event):
    selection = event.widget.curselection()
    if selection:
        index = selection[0]
        show_packet_details(index)

packet_listbox.bind("<<ListboxSelect>>", on_packet_select)

# === Control Buttons ===
control_frame = tk.Frame(right_frame, bg="#1e1e1e")
control_frame.pack(fill=tk.X, padx=10, pady=5)

tk.Button(control_frame, text="▶️ Start", command=lambda: start_sniffing(), bg="#3a3a3a", fg="white").pack(side=tk.LEFT, padx=5)
tk.Button(control_frame, text="⏸️ Pauza", command=lambda: pause_sniffing(), bg="#3a3a3a", fg="white").pack(side=tk.LEFT, padx=5)
tk.Button(control_frame, text="⏹️ Stop", command=lambda: stop_sniffing(), bg="#3a3a3a", fg="white").pack(side=tk.LEFT, padx=5)
tk.Button(control_frame, text="📦 Eksport PCAP", command=lambda: export_pcap(), bg="#3a3a3a", fg="white").pack(side=tk.LEFT, padx=5)

# === Packet Storage ===
packets = []
filtered_packets = []
sniffing = False
paused = False
# === Sniffer Thread ===
def packet_callback(pkt):
    if paused:
        return
    packets.append(pkt)
    timestamp = time.time()
    traffic_data.append(timestamp)
    if filter_var.get():
        if pkt.haslayer(IP) and filter_var.get().lower() in pkt.summary().lower():
            filtered_packets.append(pkt)
            display_packet(pkt, filtered=True)
    else:
        display_packet(pkt)

def display_packet(pkt, filtered=False):
    features = extract_features(pkt)
    weight = predict_packet_features(features)
    label = f"{len(filtered_packets) if filtered else len(packets)}. {pkt.summary()} | AI: {weight:.2f}"
    packet_listbox.insert(0, label)
    packet_listbox.itemconfig(0, {'fg': 'red' if weight >= 0.5 else 'white'})

def sniff_loop():
    sniff(prn=packet_callback, store=False)

def start_sniffing():
    global sniffing, paused
    if not sniffing:
        sniffing = True
        paused = False
        threading.Thread(target=sniff_loop, daemon=True).start()

def pause_sniffing():
    global paused
    paused = True

def stop_sniffing():
    global sniffing, paused
    sniffing = False
    paused = True

# === Filter Function ===
def apply_filter():
    bpf = filter_var.get()
    filtered_packets.clear()
    packet_listbox.delete(0, tk.END)
    for pkt in packets:
        if pkt.haslayer(IP) and bpf.lower() in pkt.summary().lower():
            filtered_packets.append(pkt)
            display_packet(pkt, filtered=True)

# === Export Function ===
def export_pcap():
    filename = f"filtered_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    try:
        wrpcap(filename, filtered_packets)
        print(f"[📦] Eksport PCAP zakończony: {filename}")
    except Exception as e:
        print(f"[❌] Błąd eksportu PCAP: {e}")

# === Show Packet Details ===
def show_packet_details(index):
    pkt = None
    if filter_var.get():
        if index < len(filtered_packets):
            pkt = filtered_packets[index]
    else:
        if index < len(packets):
            pkt = packets[index]
    if pkt:
        style_tab.config(state=tk.NORMAL)
        style_tab.delete(1.0, tk.END)
        style_tab.insert(tk.END, pkt.show(dump=True))
        style_tab.config(state=tk.DISABLED)

        hex_tab.config(state=tk.NORMAL)
        hex_tab.delete(1.0, tk.END)
        raw_bytes = raw(pkt)
        hex_view = ' '.join(f"{b:02x}" for b in raw_bytes)
        ascii_view = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in raw_bytes)
        hex_tab.insert(tk.END, f"HEX:\n{hex_view}\n\nASCII:\n{ascii_view}")
        hex_tab.config(state=tk.DISABLED)

# === Traffic Graph ===
traffic_data = []

graph_frame = tk.Frame(right_frame, bg="#1e1e1e")
graph_frame.pack(fill=tk.X, padx=10, pady=5)

fig, ax = plt.subplots(figsize=(5, 2), dpi=100)
canvas = FigureCanvasTkAgg(fig, master=graph_frame)
canvas.get_tk_widget().pack()

def update_graph():
    now = time.time()
    recent = [t for t in traffic_data if now - t < 60]
    traffic_data[:] = recent
    counts = [0]*60
    for t in recent:
        sec = int(now - t)
        if 0 <= sec < 60:
            counts[59 - sec] += 1
    ax.clear()
    ax.plot(counts, color='cyan')
    ax.set_title("Pakiety / sekunda")
    ax.set_ylim(0, max(counts) + 1)
    canvas.draw()
    root.after(1000, update_graph)

update_graph()

# === Start GUI ===
root.mainloop()
