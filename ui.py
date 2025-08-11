import threading
import tkinter as tk
import logging
import time
import queue
from i18n import t

logging.basicConfig(level=logging.INFO)

packet_queue = queue.Queue()

def update_packet_list(listbox):
    def loop():
        while True:
            try:
                pkt = packet_queue.get(timeout=1)
                listbox.insert(tk.END, pkt)
                if listbox.size() > 100:
                    listbox.delete(0)
            except queue.Empty:
                pass
    threading.Thread(target=loop, daemon=True).start()

def start_ui():
    root = tk.Tk()
    root.title(t("app_title"))

    label = tk.Label(root, text=t("status_running"), font=("Arial", 14))
    label.pack(pady=10)

    listbox = tk.Listbox(root, width=100, height=20)
    listbox.pack(padx=10, pady=10)

    update_packet_list(listbox)
    root.mainloop()
