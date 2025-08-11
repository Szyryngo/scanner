import sqlite3
import threading
import logging
import time

logging.basicConfig(level=logging.INFO)

class DatabaseManager:
    def __init__(self, db_name="scanner.db"):
        self.db_name = db_name
        self.lock = threading.Lock()
        self.buffer = []
        self.running = True
        self.thread = threading.Thread(target=self._flush_loop)
        self.thread.start()
        self._init_db()

    def _init_db(self):
        try:
            with sqlite3.connect(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS packets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        data TEXT
                    )
                """)
                conn.commit()
        except Exception as e:
            logging.exception("Database initialization failed")

    def add_packet(self, timestamp, data):
        with self.lock:
            self.buffer.append((timestamp, data))

    def _flush_loop(self):
        while self.running:
            try:
                time.sleep(5)
                self._flush()
            except Exception as e:
                logging.exception("Database flush error")

    def _flush(self):
        with self.lock:
            if not self.buffer:
                return
            try:
                with sqlite3.connect(self.db_name) as conn:
                    cursor = conn.cursor()
                    cursor.executemany("INSERT INTO packets (timestamp, data) VALUES (?, ?)", self.buffer)
                    conn.commit()
                    logging.info(f"Flushed {len(self.buffer)} packets to DB")
                    self.buffer.clear()
            except Exception as e:
                logging.exception("Database write error")

    def stop(self):
        self.running = False
        self.thread.join()
        self._flush()
