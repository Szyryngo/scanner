from PyQt5 import QtCore, QtGui
from datetime import datetime
from .i18n import i18n

class PacketTableModel(QtCore.QAbstractTableModel):
    HEADERS = ["ID", "Time", "Source", "Destination", "Proto", "Len", "Risk", "Tags", "Summary"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows = []

    def rowCount(self, parent=None):
        return len(self.rows)

    def columnCount(self, parent=None):
        return len(self.HEADERS)

    def data(self, index, role=QtCore.Qt.DisplayRole):
        if not index.isValid():
            return None
        r = self.rows[index.row()]
        col = index.column()
        if role == QtCore.Qt.DisplayRole:
            if col == 0:
                return str(r["id"])
            elif col == 1:
                return datetime.fromtimestamp(r["ts"]).strftime("%H:%M:%S.%f")[:-3]
            elif col == 2:
                return f"{r.get('src_ip')}{(':'+str(r.get('src_port'))) if r.get('src_port') else ''}"
            elif col == 3:
                return f"{r.get('dst_ip')}{(':'+str(r.get('dst_port'))) if r.get('dst_port') else ''}"
            elif col == 4:
                return r.get("proto")
            elif col == 5:
                return str(r.get("length"))
            elif col == 6:
                return f"{(r.get('threat_score') or 0.0):.2f}"
            elif col == 7:
                return r.get("threat_tags")
            elif col == 8:
                return r.get("summary")
        if role == QtCore.Qt.BackgroundRole:
            s = r.get("threat_score") or 0.0
            if s >= 5.0:
                return QtGui.QBrush(QtGui.QColor("#ffb3b3"))
            elif s >= 2.0:
                return QtGui.QBrush(QtGui.QColor("#ffe0b3"))
            elif s >= 1.0:
                return QtGui.QBrush(QtGui.QColor("#fff7b3"))
        if role == QtCore.Qt.TextAlignmentRole:
            if col in [0,5,6]:
                return QtCore.Qt.AlignCenter
        return None

    def headerData(self, section, orientation, role=QtCore.Qt.DisplayRole):
        if role != QtCore.Qt.DisplayRole:
            return None
        if orientation == QtCore.Qt.Horizontal:
            h = self.HEADERS[section]
            map_keys = {
                "ID": "index",
                "Time": "time",
                "Source": "src",
                "Destination": "dst",
                "Proto": "proto",
                "Len": "len",
                "Risk": "risk",
                "Tags": "tags",
                "Summary": "details"
            }
            key = map_keys.get(h)
            if key:
                return i18n.t(key)
            return h
        return str(section)

    def setRows(self, rows):
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()