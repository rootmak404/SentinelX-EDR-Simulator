import shutil
from pathlib import Path

from config import QUARANTINE_DIR, ensure_directories
from database import DatabaseManager
from utils import now_iso


class QuarantineManager:
    def __init__(self, db: DatabaseManager) -> None:
        ensure_directories()
        self.db = db

    def quarantine_file(self, file_path: str, sha256: str, reason: str, severity: str, signature_name: str) -> str:
        source = Path(file_path)
        if not source.exists():
            raise FileNotFoundError(file_path)
        quarantine_name = f"{source.name}.{sha256[:12]}.{now_iso().replace(':', '-')}.qnt"
        quarantine_path = QUARANTINE_DIR / quarantine_name
        shutil.move(str(source), str(quarantine_path))
        self.db.add_quarantine_record(str(source), str(quarantine_path), sha256, reason, severity, signature_name)
        return str(quarantine_path)

    def restore_file(self, record_id: int) -> bool:
        rows = [row for row in self.db.get_quarantine() if row["id"] == record_id]
        if not rows:
            return False
        row = rows[0]
        quarantine_path = Path(row["quarantine_path"])
        original_path = Path(row["original_path"])
        if not quarantine_path.exists():
            self.db.delete_quarantine_record(record_id)
            return False
        original_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(quarantine_path), str(original_path))
        self.db.delete_quarantine_record(record_id)
        return True

    def delete_permanently(self, record_id: int) -> bool:
        rows = [row for row in self.db.get_quarantine() if row["id"] == record_id]
        if not rows:
            return False
        path = Path(rows[0]["quarantine_path"])
        if path.exists():
            path.unlink(missing_ok=True)
        self.db.delete_quarantine_record(record_id)
        return True
