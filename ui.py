import threading
import tkinter as tk
import logging
from i18n import t

logging.basicConfig(level=logging.INFO)

def start_ui():
    def run():
        root = tk.Tk()
        root.title(t("app_title"))
        label = tk.Label(root, text=t("status_running"))
        label.pack()
        root.mainloop()

    ui_thread = threading.Thread(target=run)
    ui_thread.start()
