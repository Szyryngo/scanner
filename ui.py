import threading
import tkinter as tk
from tkinter import filedialog, messagebox
import logging
import time
import queue
from i18n import t
from sniffer import SnifferThread

logging.basicConfig(level=logging.INFO)

packet_queue = queue.Queue()
filtered_packets = []
sniffer_thread = None
stats = {"total": 0, "TCP": 0, "UDP": 0, "Other": 0}

def update_packet_list(listbox, filter_entry, stats_label):
    def loop():
        while True:
            try:
                pkt = packet_queue.get(timeout=1)
                keyword = filter_entry.get().lower()
                if keyword in pkt.lower():
                    filtered_packets.append(pkt)
                    listbox.insert(tk.END, pkt)
                    if listbox.size() > 100:
                        listbox.delete(0)

                    # Statystyki
                    if "TCP" in pkt:
                        stats["TCP"] += 1
                    elif "UDP" in pkt:
                        stats["UDP"] += 1
                    else:
                        stats["Other"] += 1
                    stats["total"] += 1
                    stats_label.config(text=f"Pakiety: {stats['total']} | TCP: {stats['TCP']} | UDP: {stats['UDP']} | Inne: {stats['Other']}")
            except queue.Empty:
                pass
    threading.Thread(target=loop, daemon=True).start()

def export_packets():
    try:
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                for pkt in filtered_packets:
                    f.write(pkt + "\n")
            messagebox.showinfo("Eksport", "Zapisano pakiety do pliku.")
    except Exception as e:
        logging.exception("Export error")
        messagebox.showerror("Błąd", "Nie udało się zapisać pliku.")

def show_details(event, listbox):
    selection = listbox.curselection()
    if selection:
        pkt = listbox.get(selection[0])
        messagebox.showinfo("Szczegóły pakietu", pkt)

def stop_sniffing():
    global sniffer_thread
    if sniffer_thread:
        sniffer_thread.stop()
        messagebox.showinfo("Sniffer", "Sniffing zatrzymany.")

def clear_list(listbox):
    listbox.delete(0, tk.END)
    filtered_packets.clear()

def start_ui():
    global sniffer_thread
    sniffer_thread = SnifferThread()
    sniffer_thread.start()

    root = tk.Tk()
    root.title(t("app_title"))

    stats_label = tk.Label(root, text="Pakiety: 0 | TCP: 0 | UDP: 0 | Inne: 0", font=("Arial", 12))
    stats_label.pack(pady=5)

    filter_entry = tk.Entry(root, width=40)
    filter_entry.pack(pady=5)
    filter_entry.insert(0, "Filtruj po słowie kluczowym...")

    listbox = tk.Listbox(root, width=100, height=20)
    listbox.pack(padx=10, pady=10)
    listbox.bind("<Double-Button-1>", lambda e: show_details(e, listbox))

    update_packet_list(listbox, filter_entry, stats_label)

    btn_frame = tk.Frame(root)
    btn_frame.pack(pady=10)

    export_btn = tk.Button(btn_frame, text="Eksportuj", command=export_packets)
    export_btn.grid(row=0, column=0, padx=5)

    stop_btn = tk.Button(btn_frame, text="Zatrzymaj sniffing", command=stop_sniffing)
    stop_btn.grid(row=0, column=1, padx=5)

    clear_btn = tk.Button(btn_frame, text="Wyczyść listę", command=lambda: clear_list(listbox))
    clear_btn.grid(row=0, column=2, padx=5)

    root.mainloop()
