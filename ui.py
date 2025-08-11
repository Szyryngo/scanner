import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext
from sniffer import SnifferThread
from visualize import show_anomaly_chart
from ai import train_model
from map import show_map
import logging

stats = {
    "packets": 0,
    "alerts": 0,
    "threats": 0
}

sniffer_thread = None
online_mode = True
last_ip = None

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
            messagebox.showinfo("Statystyki", "Zapisano statystyki do pliku.")
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
        messagebox.showerror("Błąd", "Nie udało się wytrenować modelu.")

def show_geo_map():
    if last_ip:
        show_map(last_ip, 52.2297, 21.0122)  # Przykładowe współrzędne (Warszawa)
        log_callback(f"Wyświetlono mapę dla IP: {last_ip}")
    else:
        messagebox.showinfo("Mapa", "Brak IP do wyświetlenia.")

def log_callback(msg):
    log_box.insert(tk.END, msg + "\n")
    log_box.see(tk.END)

def start_ui():
    global mode_label, log_box

    root = tk.Tk()
    root.title("NetSentinel AI")
    root.geometry("800x600")

    top_frame = tk.Frame(root)
    top_frame.pack(pady=10)

    start_btn = tk.Button(top_frame, text="▶ Start", command=start_sniffer, width=12)
    start_btn.grid(row=0, column=0, padx=5)

    stop_btn = tk.Button(top_frame, text="⏹ Stop", command=stop_sniffer, width=12)
    stop_btn.grid(row=0, column=1, padx=5)

    stats_btn = tk.Button(top_frame, text="📊 Statystyki", command=show_stats, width=12)
    stats_btn.grid(row=0, column=2, padx=5)

    save_btn = tk.Button(top_frame, text="💾 Zapisz", command=save_stats, width=12)
    save_btn.grid(row=0, column=3, padx=5)

    chart_btn = tk.Button(top_frame, text="📈 Wykres", command=lambda: show_anomaly_chart(stats), width=12)
    chart_btn.grid(row=0, column=4, padx=5)

    train_btn = tk.Button(top_frame, text="🧠 Trenuj AI", command=train_ai_model, width=12)
    train_btn.grid(row=0, column=5, padx=5)

    map_btn = tk.Button(top_frame, text="🌍 Mapa IP", command=show_geo_map, width=12)
    map_btn.grid(row=0, column=6, padx=5)

    mode_label = tk.Label(root, text="Tryb: Online", font=("Arial", 12))
    mode_label.pack(pady=5)

    toggle_btn = tk.Button(root, text="🌐 Przełącz tryb", command=toggle_mode)
    toggle_btn.pack(pady=5)

    log_box = scrolledtext.ScrolledText(root, width=100, height=20)
    log_box.pack(padx=10, pady=10)

    root.mainloop()
