from PyQt6.QtCore import QObject, pyqtSignal
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from database import DatabaseManager
from utils import sha256_file


class RealtimeEventHandler(FileSystemEventHandler):
    def __init__(self, db: DatabaseManager, callback) -> None:
        super().__init__()
        self.db = db
        self.callback = callback

    def _process(self, event_type: str, path: str) -> None:
        action = "clean"
        severity = "info"
        if path.endswith(".tmp") or path.endswith(".bin"):
            action = "suspicious"
            severity = "medium"
        try:
            file_hash = sha256_file(path)
            sig = self.db.get_signature_by_hash(file_hash)
            if sig:
                action = "threat detected"
                severity = sig["severity"]
        except Exception:
            pass
        self.db.add_realtime_event(event_type, path, action, severity)
        self.callback({"event_type": event_type, "file_path": path, "action": action, "severity": severity})

    def on_created(self, event):
        if not event.is_directory:
            self._process("created", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._process("modified", event.src_path)


class RealtimeMonitor(QObject):
    event_signal = pyqtSignal(dict)

    def __init__(self, db: DatabaseManager) -> None:
        super().__init__()
        self.db = db
        self.observer = Observer()
        self._running = False

    def start(self, folders: list[str]) -> None:
        if self._running:
            return
        handler = RealtimeEventHandler(self.db, self.event_signal.emit)
        for folder in folders:
            self.observer.schedule(handler, folder, recursive=True)
        self.observer.start()
        self._running = True

    def stop(self) -> None:
        if not self._running:
            return
        self.observer.stop()
        self.observer.join(timeout=2)
        self._running = False
