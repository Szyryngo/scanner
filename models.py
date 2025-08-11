from dataclasses import dataclass
from datetime import datetime

@dataclass
class PacketInfo:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    protocol: str
    length: int
    raw_data: str
