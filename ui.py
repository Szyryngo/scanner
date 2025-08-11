import tkinter as tk
from tkinter import ttk
from scapy.all import IP, TCP, UDP
from sniffer import set_callback, start_sniffing, stop_sniffing
from ai import extract_features, predict_packet_features

packets = []

root = tk.Tk()
root.title("NetSentinel AI")
root.geometry("1200x800")
root.configure(bg="#1e1e1e")

style = ttk.Style()
style.theme_use("clam")
style.configure("TLabel", background="#1e1e1e", foreground="lightblue", font=("Segoe UI", 10, "bold"))

main_frame = tk.Frame(root, bg="#1e1e1e")
main_frame.pack(fill=tk.BOTH, expand=True)

packet_listbox = tk.Listbox(main_frame, width=50, bg="#2d2d2d", fg="white", font=("Consolas", 10))
packet_listbox.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

right_frame = tk.Frame(main_frame, bg="#1e1e1e")
right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

control_frame = tk.Frame(right_frame, bg="#1e1e1e")
control_frame.pack(fill=tk.X, padx=10, pady=5)

tk.Button(control_frame, text="▶ Start", command=start_sniffing, bg="#3a3a3a", fg="white").pack(side=tk.LEFT, padx=5)
tk.Button(control_frame, text="⏹ Stop", command=stop_sniffing, bg="#3a3a3a", fg="white").pack(side=tk.LEFT, padx=5)
tk.Button(control_frame, text="🧹 Wyczyść", command=lambda: clear_packets(), bg="#3a3a3a", fg="white").pack(side=tk.LEFT, padx=5)

def create_panel(label_text, height, fg="white", font=("Segoe UI", 9)):
    ttk.Label(right_frame, text=label_text).pack()
    box = tk.Text(right_frame, height=height, bg="#2d2d2d", fg=fg, font=font)
    box.pack(fill=tk.X, padx=10)
    return box

info_box = create_panel("Informacje o pakiecie", 6)
geo_box = create_panel("Geolokalizacja", 4)
hex_box = create_panel("HEX", 6, font=("Consolas", 9))
ascii_box = create_panel("ASCII", 6, font=("Consolas", 9))
ai_box = create_panel("Decyzja AI", 4, fg="lightgreen")

def show_packet_details(index):
    packet = packets[index]

    for box in [info_box, geo_box, hex_box, ascii_box, ai_box]:
        box.config(state=tk.NORMAL)
        box.delete("1.0", tk.END)

    if packet.haslayer(IP):
        ip = packet[IP]
        info_box.insert(tk.END, f"IP src: {ip.src}\nIP dst: {ip.dst}\nProto: {ip.proto}\n")
        geo_box.insert(tk.END, f"Kraj: Polska\nMiasto: Warszawa\nLat: 52.2297\nLon: 21.0122\n")

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        info_box.insert(tk.END, f"TCP sport: {tcp.sport}\nTCP dport: {tcp.dport}\n")

    if packet.haslayer(UDP):
        udp = packet[UDP]
        info_box.insert(tk.END, f"UDP sport: {udp.sport}\nUDP dport: {udp.dport}\n")

    if packet.haslayer("Raw"):
        raw = bytes(packet["Raw"].load)
        hex_data = raw.hex(" ")
        ascii_data = "".join([chr(b) if 32 <= b <= 126 else "." for b in raw])
        hex_box.insert(tk.END, hex_data)
        ascii_box.insert(tk.END, ascii_data)

    features = extract_features(packet)
    decision = predict_packet_features(features)
    ai_box.insert(tk.END, f"Cecha 1: {features[0]}\nCecha 2: {features[1]}\nCecha 3: {features[2]}\n")
    ai_box.insert(tk.END, f"Decyzja AI: {'Zagrożenie' if decision else 'Normalny'}")

    for box in [info_box, geo_box, hex_box, ascii_box, ai_box]:
        box.config(state=tk.DISABLED)

def on_select(event):
    selection = event.widget.curselection()
    if selection:
        index = selection[0]
        show_packet_details(index)

packet_listbox.bind("<<ListboxSelect>>", on_select)

def packet_callback(packet):
    packets.insert(0, packet)
    packet_listbox.insert(0, f"{len(packets)}. {packet.summary()}")

def clear_packets():
    packets.clear()
    packet_listbox.delete(0, tk.END)

def start_ui():
    set_callback(packet_callback)
    root.mainloop()
