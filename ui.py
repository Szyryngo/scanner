import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, IP, TCP, UDP

# Przykładowe funkcje AI
def extract_features(packet):
    size = len(packet)
    threat_score = 1 if packet.haslayer(TCP) and packet[TCP].dport == 23 else 0  # np. Telnet
    time_delta = 0.05  # przykładowa wartość
    return [size, threat_score, time_delta]

def predict_packet_features(features):
    return features[1] == 1  # jeśli threat_score == 1, uznajemy za zagrożenie

# Globalne zmienne
packets = []
sniffing = False

# GUI
root = tk.Tk()
root.title("NetSentinel AI")
root.geometry("1200x800")
root.configure(bg="#1e1e1e")

style = ttk.Style()
style.theme_use("clam")
style.configure("TLabel", background="#1e1e1e", foreground="lightblue", font=("Segoe UI", 10, "bold"))

main_frame = tk.Frame(root, bg="#1e1e1e")
main_frame.pack(fill=tk.BOTH, expand=True)

# Lista pakietów po lewej
packet_listbox = tk.Listbox(main_frame, width=50, bg="#2d2d2d", fg="white", font=("Consolas", 10))
packet_listbox.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

# Panel szczegółów po prawej
right_frame = tk.Frame(main_frame, bg="#1e1e1e")
right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

# Panel sterowania
control_frame = tk.Frame(right_frame, bg="#1e1e1e")
control_frame.pack(fill=tk.X, padx=10, pady=5)

start_btn = tk.Button(control_frame, text="▶ Start", command=lambda: start_sniffing(), bg="#3a3a3a", fg="white")
start_btn.pack(side=tk.LEFT, padx=5)

stop_btn = tk.Button(control_frame, text="⏹ Stop", command=lambda: stop_sniffing(), bg="#3a3a3a", fg="white")
stop_btn.pack(side=tk.LEFT, padx=5)

clear_btn = tk.Button(control_frame, text="🧹 Wyczyść", command=lambda: clear_packets(), bg="#3a3a3a", fg="white")
clear_btn.pack(side=tk.LEFT, padx=5)

# Informacje o pakiecie
info_label = ttk.Label(right_frame, text="Informacje o pakiecie")
info_label.pack()
info_box = tk.Text(right_frame, height=6, bg="#2d2d2d", fg="white", font=("Segoe UI", 9))
info_box.pack(fill=tk.X, padx=10)

# Geolokalizacja
geo_label = ttk.Label(right_frame, text="Geolokalizacja")
geo_label.pack()
geo_box = tk.Text(right_frame, height=4, bg="#2d2d2d", fg="white", font=("Segoe UI", 9))
geo_box.pack(fill=tk.X, padx=10)

# HEX
hex_label = ttk.Label(right_frame, text="HEX")
hex_label.pack()
hex_box = tk.Text(right_frame, height=6, bg="#2d2d2d", fg="white", font=("Consolas", 9))
hex_box.pack(fill=tk.X, padx=10)

# ASCII
ascii_label = ttk.Label(right_frame, text="ASCII")
ascii_label.pack()
ascii_box = tk.Text(right_frame, height=6, bg="#2d2d2d", fg="white", font=("Consolas", 9))
ascii_box.pack(fill=tk.X, padx=10)

# Decyzja AI
ai_label = ttk.Label(right_frame, text="Decyzja AI")
ai_label.pack()
ai_box = tk.Text(right_frame, height=4, bg="#2d2d2d", fg="lightgreen", font=("Segoe UI", 9))
ai_box.pack(fill=tk.X, padx=10)

# Funkcje GUI
def show_packet_details(index):
    packet = packets[index]

    info_box.config(state=tk.NORMAL)
    geo_box.config(state=tk.NORMAL)
    hex_box.config(state=tk.NORMAL)
    ascii_box.config(state=tk.NORMAL)
    ai_box.config(state=tk.NORMAL)

    info_box.delete("1.0", tk.END)
    geo_box.delete("1.0", tk.END)
    hex_box.delete("1.0", tk.END)
    ascii_box.delete("1.0", tk.END)
    ai_box.delete("1.0", tk.END)

    if packet.haslayer(IP):
        ip = packet[IP]
        info_box.insert(tk.END, f"IP src: {ip.src}\n")
        info_box.insert(tk.END, f"IP dst: {ip.dst}\n")
        info_box.insert(tk.END, f"Proto: {ip.proto}\n")

        geo_box.insert(tk.END, f"Kraj: Polska\nMiasto: Warszawa\nLat: 52.2297\nLon: 21.0122\n")

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        info_box.insert(tk.END, f"TCP sport: {tcp.sport}\n")
        info_box.insert(tk.END, f"TCP dport: {tcp.dport}\n")

    if packet.haslayer(UDP):
        udp = packet[UDP]
        info_box.insert(tk.END, f"UDP sport: {udp.sport}\n")
        info_box.insert(tk.END, f"UDP dport: {udp.dport}\n")

    if packet.haslayer("Raw"):
        raw = bytes(packet["Raw"].load)
        hex_data = raw.hex(" ")
        ascii_data = "".join([chr(b) if 32 <= b <= 126 else "." for b in raw])
        hex_box.insert(tk.END, hex_data)
        ascii_box.insert(tk.END, ascii_data)

    # AI analiza
    features = extract_features(packet)
    decision = predict_packet_features(features)
    ai_box.insert(tk.END, f"Cecha 1 (rozmiar): {features[0]}\n")
    ai_box.insert(tk.END, f"Cecha 2 (zagrożenie): {features[1]}\n")
    ai_box.insert(tk.END, f"Cecha 3 (czas delta): {features[2]}\n")
    ai_box.insert(tk.END, f"Decyzja AI: {'Zagrożenie' if decision else 'Normalny'}")

    info_box.config(state=tk.DISABLED)
    geo_box.config(state=tk.DISABLED)
    hex_box.config(state=tk.DISABLED)
    ascii_box.config(state=tk.DISABLED)
    ai_box.config(state=tk.DISABLED)

def on_select(event):
    selection = event.widget.curselection()
    if selection:
        index = selection[0]
        show_packet_details(index)

packet_listbox.bind("<<ListboxSelect>>", on_select)

def packet_callback(packet):
    packets.insert(0, packet)
    packet_listbox.insert(0, f"{len(packets)}. {packet.summary()}")

def start_sniffing():
    global sniffing
    sniffing = True
    sniff(prn=packet_callback, store=False, stop_filter=lambda x: not sniffing)

def stop_sniffing():
    global sniffing
    sniffing = False

def clear_packets():
    packets.clear()
    packet_listbox.delete(0, tk.END)

# Funkcja startowa dla main.py
def start_ui():
    root.mainloop()
