import sqlite3
import threading
from collections import Counter
from pathlib import Path

from config import DB_PATH, ensure_directories
from utils import now_iso


class DatabaseManager:
    def __init__(self, db_path: Path | None = None) -> None:
        ensure_directories()
        self.db_path = db_path or DB_PATH
        self._lock = threading.RLock()
        self.connection = sqlite3.connect(self.db_path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self) -> None:
        with self._lock:
            cursor = self.connection.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS signatures (
                    sha256 TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    family TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_type TEXT NOT NULL,
                    target_path TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT NOT NULL,
                    total_scanned INTEGER NOT NULL,
                    detections INTEGER NOT NULL,
                    duration_seconds REAL NOT NULL,
                    summary TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    file_path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    signature_name TEXT NOT NULL,
                    family TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    detected_at TEXT NOT NULL,
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS quarantine (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    original_path TEXT NOT NULL,
                    quarantine_path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    signature_name TEXT NOT NULL,
                    quarantined_at TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS realtime_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    action TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            self.connection.commit()

    def upsert_signature(self, sha256: str, name: str, family: str, severity: str, description: str) -> None:
        with self._lock:
            self.connection.execute(
                """
                INSERT INTO signatures (sha256, name, family, severity, description, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(sha256) DO UPDATE SET
                    name=excluded.name,
                    family=excluded.family,
                    severity=excluded.severity,
                    description=excluded.description
                """,
                (sha256, name, family, severity, description, now_iso()),
            )
            self.connection.commit()

    def get_signature_by_hash(self, sha256: str):
        with self._lock:
            cursor = self.connection.execute("SELECT * FROM signatures WHERE sha256 = ?", (sha256,))
            return cursor.fetchone()

    def get_signature_stats(self) -> dict:
        with self._lock:
            rows = self.connection.execute("SELECT family, severity FROM signatures").fetchall()
        family_counts = Counter([r["family"] for r in rows])
        severity_counts = Counter([r["severity"] for r in rows])
        return {"families": dict(family_counts), "severity": dict(severity_counts)}

    def create_scan(self, scan_type: str, target_path: str, start_time: str, end_time: str, total_scanned: int, detections: int, duration_seconds: float, summary: str) -> int:
        with self._lock:
            cursor = self.connection.execute(
                """
                INSERT INTO scans (scan_type, target_path, start_time, end_time, total_scanned, detections, duration_seconds, summary)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (scan_type, target_path, start_time, end_time, total_scanned, detections, duration_seconds, summary),
            )
            self.connection.commit()
            return int(cursor.lastrowid)

    def add_detection(self, scan_id: int, file_path: str, sha256: str, signature_name: str, family: str, severity: str) -> None:
        with self._lock:
            self.connection.execute(
                """
                INSERT INTO detections (scan_id, file_path, sha256, signature_name, family, severity, detected_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (scan_id, file_path, sha256, signature_name, family, severity, now_iso()),
            )
            self.connection.commit()

    def add_quarantine_record(self, original_path: str, quarantine_path: str, sha256: str, reason: str, severity: str, signature_name: str) -> None:
        with self._lock:
            self.connection.execute(
                """
                INSERT INTO quarantine (original_path, quarantine_path, sha256, reason, severity, signature_name, quarantined_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (original_path, quarantine_path, sha256, reason, severity, signature_name, now_iso()),
            )
            self.connection.commit()

    def delete_quarantine_record(self, record_id: int) -> None:
        with self._lock:
            self.connection.execute("DELETE FROM quarantine WHERE id = ?", (record_id,))
            self.connection.commit()

    def get_quarantine(self):
        with self._lock:
            return self.connection.execute("SELECT * FROM quarantine ORDER BY id DESC").fetchall()

    def add_realtime_event(self, event_type: str, file_path: str, action: str, severity: str) -> None:
        with self._lock:
            self.connection.execute(
                """
                INSERT INTO realtime_events (event_type, file_path, action, severity, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (event_type, file_path, action, severity, now_iso()),
            )
            self.connection.commit()

    def get_recent_events(self, limit: int = 50):
        with self._lock:
            return self.connection.execute("SELECT * FROM realtime_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def get_scan_history(self):
        with self._lock:
            return self.connection.execute("SELECT * FROM scans ORDER BY id DESC").fetchall()

    def get_recent_detections(self, limit: int = 20):
        with self._lock:
            return self.connection.execute("SELECT * FROM detections ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def close(self) -> None:
        with self._lock:
            self.connection.close()
