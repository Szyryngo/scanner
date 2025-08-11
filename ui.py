import threading
import tkinter as tk
import logging

logging.basicConfig(level=logging.INFO)

def start_ui():
    def run():
        root = tk.Tk()
        root.title("Scanner")
        label = tk.Label(root, text="Aplikacja działa...")
        label.pack()
        root.mainloop()

    ui_thread = threading.Thread(target=run)
    ui_thread.start()
