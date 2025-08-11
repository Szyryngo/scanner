import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext, ttk
from sniffer import SnifferThread
from visualize import show_anomaly_chart
from ai import train_model
from map import show_map
import logging
from scapy.all import IP, TCP, UDP

stats = {
    "packets": 0,
    "alerts": 0,
    "threats": 0
}

sniffer_thread = None
online_mode = True
last_ip = None
captured_packets = []

def start_sniffer():
    global sniffer_thread
    sniffer_thread = SnifferThread(stats, online_mode, log_callback)
    sniffer_thread.start()
    log_callback("Sniffer uruchomiony.")

def stop_sniffer():
    global sniffer_thread
    if sniffer_thread:
        sniffer_thread.running = False
        log_callback("Sniffer zatrzymany.")

def show_stats():
    stat_text = "\n".join([f"{k}: {v}" for k, v in stats.items()])
    messagebox.showinfo("Statystyki", stat_text)

def save_stats():
    try:
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                for key, value in stats.items():
                    f.write(f"{key}: {value}\n")
            messagebox.showinfo("Zapisano", "Statystyki zapisane.")
    except Exception as e:
        logging.exception("Save stats error")
        messagebox.showerror("Błąd", "Nie udało się zapisać statystyk.")

def toggle_mode():
    global online_mode
    online_mode = not online_mode
    mode_label.config(text=f"Tryb: {'Online' if online_mode else 'Offline'}")
    log_callback(f"Przełączono tryb na {'Online' if online_mode else 'Offline'}.")

def train_ai_model():
    try:
        train_model("data.csv")
        messagebox.showinfo("AI", "Model AI został wytrenowany.")
        log_callback("Model AI wytrenowany.")
    except Exception as e:
        logging.exception("Train model error")
        messagebox.showerror("Błąd", str(e))

def show_geo_map():
    global last_ip
    if sniffer_thread and sniffer_thread.last_ip:
        show_map(sniffer_thread.last_ip, 52.2297, 21.0122)
        log_callback(f"Wyświetlono mapę dla IP: {sniffer_thread.last_ip}")
    else:
        messagebox.showinfo("Mapa", "Brak IP do wyświetlenia.")

def log_callback(msg, packet=None):
    packet_list.insert(tk.END, msg)
    if packet:
        captured_packets.append(packet)

def on_packet_select(event):
    selection = event.widget.curselection()
    if selection:
        index = selection[0]
        packet = captured_packets[index]
        show_packet_details(packet)

def show_packet_details(packet):
    detail_box.delete("1.0", tk.END)

    if packet.haslayer(IP):
        ip = packet[IP]
        detail_box.insert(tk.END, f"IP src: {ip.src}\n")
        detail_box.insert(tk.END, f"IP dst: {ip.dst}\n")
        detail_box.insert(tk.END, f"Proto: {ip.proto}\n")

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        detail_box.insert(tk.END, f"TCP sport: {tcp.sport}\n")
        detail_box.insert(tk.END, f"TCP dport: {tcp.dport}\n")

    if packet.haslayer(UDP):
        udp = packet[UDP]
        detail_box.insert(tk.END, f"UDP sport: {udp.sport}\n")
        detail_box.insert(tk.END, f"UDP dport: {udp.dport}\n")

    if packet.haslayer("Raw"):
        raw = bytes(packet["Raw"].load)
        hex_data = raw.hex(" ")
        ascii_data = "".join([chr(b) if 32 <= b <= 126 else "." for b in raw])
        detail_box.insert(tk.END, "\nHEX:\n" + hex_data + "\n")
        detail_box.insert(tk.END, "\nASCII:\n" + ascii_data + "\n")

def on_close():
    stop_sniffer()
    root.destroy()

def start_ui():
    global mode_label, log_box, root, packet_list, detail_box

    root = tk.Tk()
    root.title("NetSentinel AI")
    root.geometry("1000x600")
    root.protocol("WM_DELETE_WINDOW", on_close)

    style = ttk.Style()
    style.configure("TButton", font=("Segoe UI", 10), padding=6)
    style.configure("Start.TButton", foreground="green")
    style.configure("Stop.TButton", foreground="red")

    top_frame = tk.Frame(root)
    top_frame.pack(pady=10)

    ttk.Button(top_frame, text="Start", command=start_sniffer, style="Start.TButton").grid(row=0, column=0, padx=5)
    ttk.Button(top_frame, text="Stop", command=stop_sniffer, style="Stop.TButton").grid(row=0, column=1, padx=5)
    ttk.Button(top_frame, text="Statystyki", command=show_stats).grid(row=0, column=2, padx=5)
    ttk.Button(top_frame, text="Zapisz", command=save_stats).grid(row=0, column=3, padx=5)
    ttk.Button(top_frame, text="Wykres", command=lambda: show_anomaly_chart(stats)).grid(row=0, column=4, padx=5)
    ttk.Button(top_frame, text="Trenuj AI", command=train_ai_model).grid(row=0, column=5, padx=5)
    ttk.Button(top_frame, text="Mapa IP", command=show_geo_map).grid(row=0, column=6, padx=5)

    mode_label = tk.Label(root, text="Tryb: Online", font=("Arial", 12))
    mode_label.pack(pady=5)

    ttk.Button(root, text="Przełącz tryb", command=toggle_mode).pack(pady=5)

    main_frame = tk.Frame(root)
    main_frame.pack(fill=tk.BOTH, expand=True)

    left_frame = tk.Frame(main_frame)
    left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    right_frame = tk.Frame(main_frame)
    right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

    packet_list = tk.Listbox(left_frame, width=60, height=20)
    packet_list.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
    packet_list.bind("<<ListboxSelect>>", on_packet_select)

    detail_box = tk.Text(right_frame, width=60, height=20)
    detail_box.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    log_box = scrolledtext.ScrolledText(root, width=110, height=8)
    log_box.pack(padx=10, pady=10)

    root.mainloop()
