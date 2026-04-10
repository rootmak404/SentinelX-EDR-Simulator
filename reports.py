import csv
from pathlib import Path

from fpdf import FPDF

from config import REPORTS_DIR, ensure_directories
from database import DatabaseManager


class ReportManager:
    def __init__(self, db: DatabaseManager) -> None:
        ensure_directories()
        self.db = db

    def export_scan_history_csv(self, output_name: str = "scan_history.csv") -> str:
        output_path = REPORTS_DIR / output_name
        rows = self.db.get_scan_history()
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["id", "scan_type", "target_path", "start_time", "end_time", "total_scanned", "detections", "duration_seconds", "summary"])
            for row in rows:
                writer.writerow([row["id"], row["scan_type"], row["target_path"], row["start_time"], row["end_time"], row["total_scanned"], row["detections"], row["duration_seconds"], row["summary"]])
        return str(output_path)

    def export_scan_pdf(self, output_name: str = "scan_report.pdf") -> str:
        output_path = REPORTS_DIR / output_name
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "SentinelX EDR Simulator - Scan Report", ln=True)
        pdf.set_font("Arial", "", 10)
        for row in self.db.get_scan_history()[:30]:
            pdf.multi_cell(
                0,
                7,
                f"#{row['id']} | {row['scan_type']} | {row['target_path']} | Scanned: {row['total_scanned']} | Detections: {row['detections']} | {row['summary']}",
            )
        pdf.output(str(output_path))
        return str(output_path)

    def export_quarantine_pdf(self, output_name: str = "quarantine_report.pdf") -> str:
        output_path = REPORTS_DIR / output_name
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "SentinelX EDR Simulator - Quarantine Report", ln=True)
        pdf.set_font("Arial", "", 10)
        for row in self.db.get_quarantine():
            pdf.multi_cell(
                0,
                7,
                f"#{row['id']} | {row['signature_name']} | {row['severity']} | {row['original_path']} | {row['quarantined_at']}",
            )
        pdf.output(str(output_path))
        return str(output_path)
