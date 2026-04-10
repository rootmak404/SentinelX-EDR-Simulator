import hashlib
import os
from datetime import datetime
from pathlib import Path


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as file_handle:
        while True:
            chunk = file_handle.read(8192)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def list_files_in_path(target_path: str) -> list[str]:
    path = Path(target_path)
    if path.is_file():
        return [str(path)]
    if not path.exists():
        return []
    collected: list[str] = []
    for root, _, files in os.walk(path):
        for file_name in files:
            collected.append(str(Path(root) / file_name))
    return collected


def format_duration(seconds: float) -> str:
    mins = int(seconds // 60)
    secs = int(seconds % 60)
    return f"{mins:02d}:{secs:02d}"
