import hashlib
from pathlib import Path
from random import choice

from config import DEMO_SIGNATURE_COUNT
from database import DatabaseManager

FAMILIES = ["HydraLoader", "NebulaWorm", "SpecterStealer", "GhostDropper", "IonMiner"]
SEVERITIES = ["low", "medium", "high", "critical"]


def seed_signatures(db: DatabaseManager, count: int = DEMO_SIGNATURE_COUNT) -> None:
    for i in range(count):
        content = f"SENTINELX_DEMO_THREAT_{i:03d}".encode("utf-8")
        digest = hashlib.sha256(content).hexdigest()
        db.upsert_signature(
            digest,
            f"SX.Signature.{i:03d}",
            choice(FAMILIES),
            choice(SEVERITIES),
            "Demo signature for educational simulation.",
        )


def generate_demo_threat_files(target_folder: str, amount: int = 10) -> list[str]:
    target = Path(target_folder)
    target.mkdir(parents=True, exist_ok=True)
    generated = []
    for i in range(amount):
        idx = i % DEMO_SIGNATURE_COUNT
        payload = f"SENTINELX_DEMO_THREAT_{idx:03d}"
        file_path = target / f"demo_threat_{idx:03d}.txt"
        file_path.write_text(payload, encoding="utf-8")
        generated.append(str(file_path))
    return generated
