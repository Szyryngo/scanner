import threading
import tkinter as tk
import logging
from i18n import t

logging.basicConfig(level=logging.INFO)

status_text = t("status_running")

def update_status(label):
    def loop():
        global status_text
        while True:
            label.config(text=status_text)
            time.sleep(1)
    threading.Thread(target=loop, daemon=True).start()

def start_ui():
    root = tk.Tk()
    root.title(t("app_title"))
    label = tk.Label(root, text=status_text, font=("Arial", 14))
    label.pack(pady=20)

    update_status(label)
    root.mainloop()
