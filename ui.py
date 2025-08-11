import tkinter as tk
from tkinter import messagebox, filedialog
from sniffer import SnifferThread
from visualize import show_anomaly_chart
import logging

# Statystyki globalne
stats = {
    "packets": 0,
    "alerts": 0,
    "threats": 0
}

sniffer_thread = None

def start_sniffer():
    global sniffer_thread
    sniffer_thread = SnifferThread(stats)
    sniffer_thread.start()
    messagebox.showinfo("Sniffer", "Sniffer uruchomiony.")

def stop_sniffer():
    global sniffer_thread
    if sniffer_thread:
        sniffer_thread.running = False
        messagebox.showinfo("Sniffer", "Sniffer zatrzymany.")

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

def start_ui():
    root = tk.Tk()
    root.title("NetSentinel AI")

    btn_frame = tk.Frame(root)
    btn_frame.pack(pady=10)

    start_btn = tk.Button(btn_frame, text="Start", command=start_sniffer)
    start_btn.grid(row=0, column=0, padx=5)

    stop_btn = tk.Button(btn_frame, text="Stop", command=stop_sniffer)
    stop_btn.grid(row=0, column=1, padx=5)

    stats_btn = tk.Button(btn_frame, text="Statystyki", command=show_stats)
    stats_btn.grid(row=0, column=2, padx=5)

    save_stats_btn = tk.Button(btn_frame, text="Zapisz statystyki", command=save_stats)
    save_stats_btn.grid(row=0, column=3, padx=5)

    chart_btn = tk.Button(btn_frame, text="Wykres", command=lambda: show_anomaly_chart(stats))
    chart_btn.grid(row=0, column=4, padx=5)

    root.mainloop()
