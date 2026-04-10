import time

from PyQt6.QtCore import QThread, pyqtSignal

from config import SCAN_BATCH_SLEEP_MS
from database import DatabaseManager
from utils import list_files_in_path, now_iso, sha256_file


class ScanWorker(QThread):
    progress = pyqtSignal(dict)
    detection = pyqtSignal(dict)
    completed = pyqtSignal(dict)
    failed = pyqtSignal(str)

    def __init__(self, db: DatabaseManager, scan_type: str, target_path: str) -> None:
        super().__init__()
        self.db = db
        self.scan_type = scan_type
        self.target_path = target_path
        self._running = True

    def stop(self) -> None:
        self._running = False

    def run(self) -> None:
        start = time.time()
        start_iso = now_iso()
        try:
            files = list_files_in_path(self.target_path)
            total = len(files)
            detections = []
            for idx, file_path in enumerate(files, start=1):
                if not self._running:
                    break
                elapsed = time.time() - start
                speed = idx / elapsed if elapsed else 0
                eta = (total - idx) / speed if speed else 0
                payload = {
                    "current_file": file_path,
                    "progress": int((idx / total) * 100) if total else 100,
                    "files_scanned": idx,
                    "threats_detected": len(detections),
                    "elapsed_time": elapsed,
                    "eta": eta,
                    "scan_speed": speed,
                    "status": "Running",
                }
                try:
                    file_hash = sha256_file(file_path)
                    signature = self.db.get_signature_by_hash(file_hash)
                    if signature:
                        detection_payload = {
                            "file_path": file_path,
                            "sha256": file_hash,
                            "signature_name": signature["name"],
                            "family": signature["family"],
                            "severity": signature["severity"],
                        }
                        detections.append(detection_payload)
                        self.detection.emit(detection_payload)
                except Exception:
                    pass
                self.progress.emit(payload)
                self.msleep(SCAN_BATCH_SLEEP_MS)

            end = time.time()
            duration = end - start
            end_iso = now_iso()
            summary = f"{len(detections)} threat(s) detected across {len(files)} scanned file(s)."
            scan_id = self.db.create_scan(
                self.scan_type,
                self.target_path,
                start_iso,
                end_iso,
                len(files),
                len(detections),
                duration,
                summary,
            )
            for item in detections:
                self.db.add_detection(scan_id, item["file_path"], item["sha256"], item["signature_name"], item["family"], item["severity"])
            self.completed.emit(
                {
                    "scan_id": scan_id,
                    "duration": duration,
                    "detections": detections,
                    "total_files": len(files),
                    "summary": summary,
                }
            )
        except Exception as exc:
            self.failed.emit(str(exc))
