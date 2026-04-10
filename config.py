from pathlib import Path

APP_NAME = "SentinelX EDR Simulator"
APP_VERSION = "1.0.0"
SIGNATURE_VERSION = "2026.04"
ENDPOINT_ID = "SX-ENDPOINT-01A7"

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
ASSETS_DIR = BASE_DIR / "assets"
DOCS_DIR = BASE_DIR / "docs"
QUARANTINE_DIR = DATA_DIR / "quarantine"
REPORTS_DIR = DATA_DIR / "reports"
LOGS_DIR = DATA_DIR / "logs"
DB_PATH = DATA_DIR / "sentinelx.db"

DEFAULT_MONITORED_FOLDERS = [str(BASE_DIR)]
QUICK_SCAN_FOLDERS = [str(BASE_DIR)]

DEMO_SIGNATURE_COUNT = 220

SCAN_BATCH_SLEEP_MS = 3


def ensure_directories() -> None:
    for directory in [DATA_DIR, ASSETS_DIR, DOCS_DIR, QUARANTINE_DIR, REPORTS_DIR, LOGS_DIR]:
        directory.mkdir(parents=True, exist_ok=True)
