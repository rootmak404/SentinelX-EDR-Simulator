from dataclasses import dataclass
from datetime import datetime


@dataclass
class SignatureRecord:
    sha256: str
    name: str
    family: str
    severity: str
    description: str
    created_at: str


@dataclass
class ScanSessionRecord:
    scan_type: str
    target_path: str
    start_time: datetime
    end_time: datetime
    total_scanned: int
    detections: int
    duration_seconds: float
    summary: str


@dataclass
class RealtimeEventRecord:
    event_type: str
    file_path: str
    action: str
    severity: str
    created_at: str
