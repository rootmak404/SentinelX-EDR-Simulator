import random
import time
from datetime import datetime
from pathlib import Path

import pyqtgraph as pg
from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QProgressBar,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

from config import APP_NAME, APP_VERSION, DEFAULT_MONITORED_FOLDERS, ENDPOINT_ID, QUICK_SCAN_FOLDERS, SIGNATURE_VERSION
from database import DatabaseManager
from quarantine import QuarantineManager
from realtime_monitor import RealtimeMonitor
from reports import ReportManager
from scanner import ScanWorker
from utils import format_duration


class MainWindow(QMainWindow):
    def __init__(self, db: DatabaseManager) -> None:
        super().__init__()
        self.db = db
        self.quarantine_manager = QuarantineManager(db)
        self.report_manager = ReportManager(db)
        self.realtime_monitor = RealtimeMonitor(db)
        self.scan_worker = None
        self.scan_started = 0.0
        self.metric_points = list(range(60))
        self.files_speed_series = [0] * 60
        self.det_series = [0] * 60
        self.cpu_series = [0] * 60
        self.mem_series = [0] * 60
        self.events_series = [0] * 60
        self._build_ui()
        self._build_tray()
        self._connect_actions()
        self._refresh_all()
        self._start_dashboard_timer()

    def _card(self, title: str) -> tuple[QFrame, QVBoxLayout]:
        frame = QFrame()
        frame.setProperty("class", "glassCard")
        layout = QVBoxLayout(frame)
        layout.addWidget(QLabel(f"<b>{title}</b>"))
        return frame, layout

    def _build_ui(self) -> None:
        self.setWindowTitle(f"{APP_NAME} {APP_VERSION}")
        self.resize(1460, 880)
        root = QWidget()
        self.setCentralWidget(root)
        layout = QHBoxLayout(root)

        self.sidebar = QWidget()
        self.sidebar.setObjectName("Sidebar")
        side_layout = QVBoxLayout(self.sidebar)
        side_layout.addWidget(QLabel("<h2>SentinelX</h2>"))
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("> search command / path / IOC")
        side_layout.addWidget(self.search_bar)

        self.page_names = ["Dashboard", "Scan Center", "Realtime Protection", "Threat Intelligence", "Quarantine", "Scan History", "Reports", "Settings", "About"]
        self.nav_buttons = []
        for idx, page in enumerate(self.page_names):
            btn = QPushButton(page)
            btn.setCheckable(True)
            if idx == 0:
                btn.setChecked(True)
            btn.clicked.connect(lambda _checked=False, i=idx: self.switch_page(i))
            self.nav_buttons.append(btn)
            side_layout.addWidget(btn)
        side_layout.addStretch(1)

        main = QVBoxLayout()
        header = QFrame()
        header.setProperty("class", "glassCard")
        header_layout = QHBoxLayout(header)
        self.header_status = QLabel("Status: Secure")
        self.header_endpoint = QLabel(f"Endpoint: {ENDPOINT_ID}")
        self.header_sig = QLabel(f"Signature DB: {SIGNATURE_VERSION}")
        self.header_update = QLabel("Last Update: --")
        self.update_sig_button = QPushButton("Update Signatures")
        header_layout.addWidget(self.header_status)
        header_layout.addWidget(self.header_endpoint)
        header_layout.addWidget(self.header_sig)
        header_layout.addWidget(self.header_update)
        header_layout.addStretch(1)
        header_layout.addWidget(self.update_sig_button)

        self.stack = QStackedWidget()
        self.dashboard_page = self._build_dashboard_page()
        self.scan_page = self._build_scan_page()
        self.realtime_page = self._build_realtime_page()
        self.intel_page = self._build_intel_page()
        self.quarantine_page = self._build_quarantine_page()
        self.history_page = self._build_history_page()
        self.reports_page = self._build_reports_page()
        self.settings_page = self._build_settings_page()
        self.about_page = self._build_about_page()
        for page in [
            self.dashboard_page,
            self.scan_page,
            self.realtime_page,
            self.intel_page,
            self.quarantine_page,
            self.history_page,
            self.reports_page,
            self.settings_page,
            self.about_page,
        ]:
            self.stack.addWidget(page)

        main.addWidget(header)
        main.addWidget(self.stack)
        layout.addWidget(self.sidebar, 1)
        layout.addLayout(main, 5)

        report_action = QAction("Refresh Data", self)
        report_action.triggered.connect(self._refresh_all)
        self.menuBar().addAction(report_action)

    def _connect_actions(self) -> None:
        self.update_sig_button.clicked.connect(self._simulate_signature_update)
        self.start_quick_btn.clicked.connect(lambda: self.start_scan("Quick Scan", QUICK_SCAN_FOLDERS[0]))
        self.start_full_btn.clicked.connect(self.select_full_scan_target)
        self.start_custom_btn.clicked.connect(self.select_custom_scan_target)
        self.realtime_toggle_btn.clicked.connect(self.toggle_realtime)
        self.realtime_filter_input.textChanged.connect(self.refresh_realtime_events_table)
        self.quarantine_refresh_btn.clicked.connect(self.refresh_quarantine_table)
        self.restore_btn.clicked.connect(self.restore_selected_quarantine)
        self.delete_btn.clicked.connect(self.delete_selected_quarantine)
        self.export_pdf_btn.clicked.connect(self.export_scan_pdf)
        self.export_csv_btn.clicked.connect(self.export_scan_csv)
        self.export_quarantine_btn.clicked.connect(self.export_quarantine_pdf)

    def _build_dashboard_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        stats_row = QHBoxLayout()
        self.metric_labels = {}
        for name in ["Files Scanned", "Threats Detected", "Quarantined", "Realtime Events"]:
            card, card_layout = self._card(name)
            value = QLabel("0")
            value.setStyleSheet("font-size:28px; color:#62e6ff;")
            card_layout.addWidget(value)
            self.metric_labels[name] = value
            stats_row.addWidget(card)
        layout.addLayout(stats_row)

        graph_row = QHBoxLayout()
        self.graph_speed = pg.PlotWidget(title="Files Scanned / sec")
        self.graph_det = pg.PlotWidget(title="Detections Over Time")
        self.curve_speed = self.graph_speed.plot(self.metric_points, self.files_speed_series, pen=pg.mkPen("#46f3ff", width=2))
        self.curve_det = self.graph_det.plot(self.metric_points, self.det_series, pen=pg.mkPen("#f25dff", width=2))
        graph_row.addWidget(self.graph_speed)
        graph_row.addWidget(self.graph_det)
        layout.addLayout(graph_row)
        return page

    def _build_scan_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        controls = QHBoxLayout()
        self.start_quick_btn = QPushButton("Quick Scan")
        self.start_full_btn = QPushButton("Full Scan")
        self.start_custom_btn = QPushButton("Custom Scan")
        controls.addWidget(self.start_quick_btn)
        controls.addWidget(self.start_full_btn)
        controls.addWidget(self.start_custom_btn)
        controls.addStretch(1)
        layout.addLayout(controls)

        self.scan_progress = QProgressBar()
        self.scan_info = QLabel("Scan status: Idle")
        layout.addWidget(self.scan_progress)
        layout.addWidget(self.scan_info)
        self.drag_drop_target = ScanDropTarget(self)
        layout.addWidget(self.drag_drop_target)

        self.scan_event_console = QTextEdit()
        self.scan_event_console.setReadOnly(True)
        self.scan_event_console.setPlaceholderText("Live event console")
        layout.addWidget(self.scan_event_console)
        return page

    def _build_realtime_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.realtime_toggle_btn = QPushButton("Enable Realtime Protection")
        self.realtime_status = QLabel("Realtime status: Disabled")
        self.realtime_filter_input = QLineEdit()
        self.realtime_filter_input.setPlaceholderText("Filter events by path, action, severity, type")
        layout.addWidget(self.realtime_toggle_btn)
        layout.addWidget(self.realtime_status)
        layout.addWidget(self.realtime_filter_input)
        self.realtime_events_table = QTableWidget(0, 5)
        self.realtime_events_table.setHorizontalHeaderLabels(["Time", "Type", "Path", "Action", "Severity"])
        layout.addWidget(self.realtime_events_table)
        return page

    def _build_tray(self) -> None:
        self.tray = QSystemTrayIcon(self)
        self.tray.setToolTip(APP_NAME)
        self.tray.setVisible(True)

    def _build_intel_page(self) -> QWidget:
        page = QWidget()
        layout = QHBoxLayout(page)
        left, left_layout = self._card("Threat Intelligence")
        self.intel_text = QTextEdit()
        self.intel_text.setReadOnly(True)
        left_layout.addWidget(self.intel_text)
        right = QVBoxLayout()
        self.graph_cpu = pg.PlotWidget(title="CPU Usage %")
        self.graph_mem = pg.PlotWidget(title="Memory Usage %")
        self.graph_events = pg.PlotWidget(title="Realtime Events Pulse")
        self.curve_cpu = self.graph_cpu.plot(self.metric_points, self.cpu_series, pen=pg.mkPen("#61ffb0", width=2))
        self.curve_mem = self.graph_mem.plot(self.metric_points, self.mem_series, pen=pg.mkPen("#ffe861", width=2))
        self.curve_events = self.graph_events.plot(self.metric_points, self.events_series, pen=pg.mkPen("#8f89ff", width=2))
        right.addWidget(self.graph_cpu)
        right.addWidget(self.graph_mem)
        right.addWidget(self.graph_events)
        layout.addWidget(left, 3)
        container = QWidget()
        container.setLayout(right)
        layout.addWidget(container, 2)
        return page

    def _build_quarantine_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        controls = QHBoxLayout()
        self.quarantine_search = QLineEdit()
        self.quarantine_search.setPlaceholderText("Search quarantine entries")
        self.quarantine_refresh_btn = QPushButton("Refresh")
        self.restore_btn = QPushButton("Restore Selected")
        self.delete_btn = QPushButton("Delete Selected")
        controls.addWidget(self.quarantine_search)
        controls.addWidget(self.quarantine_refresh_btn)
        controls.addWidget(self.restore_btn)
        controls.addWidget(self.delete_btn)
        layout.addLayout(controls)
        self.quarantine_table = QTableWidget(0, 7)
        self.quarantine_table.setHorizontalHeaderLabels(["ID", "Signature", "Severity", "Reason", "Original Path", "Quarantine Path", "Time"])
        layout.addWidget(self.quarantine_table)
        return page

    def _build_history_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.history_table = QTableWidget(0, 8)
        self.history_table.setHorizontalHeaderLabels(["ID", "Scan Type", "Target", "Start", "End", "Total", "Detections", "Summary"])
        layout.addWidget(self.history_table)
        return page

    def _build_reports_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        controls = QHBoxLayout()
        self.export_pdf_btn = QPushButton("Export Scan PDF")
        self.export_csv_btn = QPushButton("Export History CSV")
        self.export_quarantine_btn = QPushButton("Export Quarantine PDF")
        controls.addWidget(self.export_pdf_btn)
        controls.addWidget(self.export_csv_btn)
        controls.addWidget(self.export_quarantine_btn)
        layout.addLayout(controls)
        self.report_preview = QTextEdit()
        self.report_preview.setReadOnly(True)
        self.report_preview.setPlaceholderText("Report preview panel")
        layout.addWidget(self.report_preview)
        return page

    def _build_settings_page(self) -> QWidget:
        page = QWidget()
        layout = QFormLayout(page)
        self.monitor_path_input = QLineEdit(DEFAULT_MONITORED_FOLDERS[0])
        self.scan_target_input = QLineEdit(QUICK_SCAN_FOLDERS[0])
        layout.addRow("Default Monitor Folder", self.monitor_path_input)
        layout.addRow("Default Scan Target", self.scan_target_input)
        return page

    def _build_about_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        text = QTextEdit()
        text.setReadOnly(True)
        text.setPlainText(
            "SentinelX EDR Simulator\n\n"
            "A portfolio-grade endpoint protection and threat detection simulator focused on signature-based analysis.\n\n"
            "It demonstrates modular cybersecurity engineering practices, realtime monitoring, quarantine workflows, scan analytics, and reporting."
        )
        layout.addWidget(text)
        return page

    def switch_page(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        for i, button in enumerate(self.nav_buttons):
            button.setChecked(i == index)

    def _simulate_signature_update(self) -> None:
        self.header_update.setText(f"Last Update: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        QMessageBox.information(self, "Signature Update", "Signature update simulation completed.")

    def start_scan(self, scan_type: str, target_path: str) -> None:
        if self.scan_worker and self.scan_worker.isRunning():
            QMessageBox.warning(self, "Scan Running", "A scan is already in progress.")
            return
        if not Path(target_path).exists():
            QMessageBox.warning(self, "Invalid Path", "Target path does not exist.")
            return
        self.scan_progress.setValue(0)
        self.scan_started = time.time()
        self.scan_info.setText("Scan status: Running")
        self.scan_event_console.append(f"[{datetime.now().strftime('%H:%M:%S')}] {scan_type} started on {target_path}")
        self.scan_worker = ScanWorker(self.db, scan_type, target_path)
        self.scan_worker.progress.connect(self.on_scan_progress)
        self.scan_worker.detection.connect(self.on_scan_detection)
        self.scan_worker.completed.connect(self.on_scan_complete)
        self.scan_worker.failed.connect(lambda m: QMessageBox.critical(self, "Scan Error", m))
        self.scan_worker.start()

    def select_full_scan_target(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Select Full Scan Folder", self.scan_target_input.text())
        if folder:
            self.start_scan("Full Scan", folder)

    def select_custom_scan_target(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select File for Custom Scan", self.scan_target_input.text())
        if path:
            self.start_scan("Custom Scan", path)
            return
        folder = QFileDialog.getExistingDirectory(self, "Select Folder for Custom Scan", self.scan_target_input.text())
        if folder:
            self.start_scan("Custom Scan", folder)

    def on_scan_progress(self, data: dict) -> None:
        self.scan_progress.setValue(data["progress"])
        status = (
            f"File: {data['current_file']} | Scanned: {data['files_scanned']} | Threats: {data['threats_detected']} | "
            f"Elapsed: {format_duration(data['elapsed_time'])} | ETA: {format_duration(data['eta'])} | Speed: {data['scan_speed']:.2f}/s"
        )
        self.scan_info.setText(status)
        self.files_speed_series = self.files_speed_series[1:] + [data["scan_speed"]]
        self.det_series = self.det_series[1:] + [data["threats_detected"]]
        self.curve_speed.setData(self.metric_points, self.files_speed_series)
        self.curve_det.setData(self.metric_points, self.det_series)

    def on_scan_detection(self, data: dict) -> None:
        message = f"[{datetime.now().strftime('%H:%M:%S')}] THREAT {data['signature_name']} ({data['severity']}) -> {data['file_path']}"
        self.scan_event_console.append(message)
        self.db.add_realtime_event("scan", data["file_path"], "threat detected", data["severity"])
        self.tray.showMessage("SentinelX Alert", f"Threat detected: {data['signature_name']}", QSystemTrayIcon.MessageIcon.Warning)
        if Path(data["file_path"]).exists():
            quarantine_path = self.quarantine_manager.quarantine_file(
                data["file_path"], data["sha256"], "Signature match during scan", data["severity"], data["signature_name"]
            )
            self.db.add_realtime_event("scan", quarantine_path, "quarantined", data["severity"])
            self.scan_event_console.append(f"[{datetime.now().strftime('%H:%M:%S')}] QUARANTINED -> {quarantine_path}")

    def on_scan_complete(self, payload: dict) -> None:
        self.scan_progress.setValue(100)
        self.scan_info.setText(f"Scan completed in {format_duration(payload['duration'])} | {payload['summary']}")
        self.scan_event_console.append(f"[{datetime.now().strftime('%H:%M:%S')}] Scan completed")
        self._refresh_all()

    def toggle_realtime(self) -> None:
        if self.realtime_monitor._running:
            self.realtime_monitor.stop()
            self.realtime_toggle_btn.setText("Enable Realtime Protection")
            self.realtime_status.setText("Realtime status: Disabled")
            return
        folder = self.monitor_path_input.text().strip()
        if not folder or not Path(folder).exists():
            QMessageBox.warning(self, "Invalid Monitor Path", "Monitor folder is invalid.")
            return
        self.realtime_monitor.event_signal.connect(self.on_realtime_event)
        self.realtime_monitor.start([folder])
        self.realtime_toggle_btn.setText("Disable Realtime Protection")
        self.realtime_status.setText(f"Realtime status: Active ({folder})")

    def on_realtime_event(self, payload: dict) -> None:
        self.refresh_realtime_events_table()
        self.events_series = self.events_series[1:] + [self.events_series[-1] + 1]
        self.curve_events.setData(self.metric_points, self.events_series)

    def refresh_realtime_events_table(self) -> None:
        rows = self.db.get_recent_events(300)
        query = self.realtime_filter_input.text().lower().strip()
        filtered = [row for row in rows if query in str(dict(row)).lower()] if query else rows
        self.realtime_events_table.setRowCount(0)
        for row_data in filtered:
            row = self.realtime_events_table.rowCount()
            self.realtime_events_table.insertRow(row)
            self.realtime_events_table.setItem(row, 0, QTableWidgetItem(row_data["created_at"].split("T")[-1]))
            self.realtime_events_table.setItem(row, 1, QTableWidgetItem(row_data["event_type"]))
            self.realtime_events_table.setItem(row, 2, QTableWidgetItem(row_data["file_path"]))
            self.realtime_events_table.setItem(row, 3, QTableWidgetItem(row_data["action"]))
            self.realtime_events_table.setItem(row, 4, QTableWidgetItem(row_data["severity"]))

    def refresh_quarantine_table(self) -> None:
        data = self.db.get_quarantine()
        query = self.quarantine_search.text().lower().strip()
        rows = [row for row in data if query in str(dict(row)).lower()] if query else data
        self.quarantine_table.setRowCount(0)
        for row_data in rows:
            row = self.quarantine_table.rowCount()
            self.quarantine_table.insertRow(row)
            values = [
                str(row_data["id"]),
                row_data["signature_name"],
                row_data["severity"],
                row_data["reason"],
                row_data["original_path"],
                row_data["quarantine_path"],
                row_data["quarantined_at"],
            ]
            for col, value in enumerate(values):
                self.quarantine_table.setItem(row, col, QTableWidgetItem(value))

    def restore_selected_quarantine(self) -> None:
        current = self.quarantine_table.currentRow()
        if current < 0:
            return
        record_id = int(self.quarantine_table.item(current, 0).text())
        self.quarantine_manager.restore_file(record_id)
        self.refresh_quarantine_table()

    def delete_selected_quarantine(self) -> None:
        current = self.quarantine_table.currentRow()
        if current < 0:
            return
        record_id = int(self.quarantine_table.item(current, 0).text())
        self.quarantine_manager.delete_permanently(record_id)
        self.refresh_quarantine_table()

    def refresh_history_table(self) -> None:
        rows = self.db.get_scan_history()
        self.history_table.setRowCount(0)
        for row_data in rows:
            row = self.history_table.rowCount()
            self.history_table.insertRow(row)
            values = [
                row_data["id"],
                row_data["scan_type"],
                row_data["target_path"],
                row_data["start_time"],
                row_data["end_time"],
                row_data["total_scanned"],
                row_data["detections"],
                row_data["summary"],
            ]
            for col, value in enumerate(values):
                self.history_table.setItem(row, col, QTableWidgetItem(str(value)))

    def refresh_intel_panel(self) -> None:
        detections = self.db.get_recent_detections(50)
        events = self.db.get_recent_events(50)
        families = {}
        severities = {}
        targets = {}
        signatures = {}
        for d in detections:
            families[d["family"]] = families.get(d["family"], 0) + 1
            severities[d["severity"]] = severities.get(d["severity"], 0) + 1
            signatures[d["signature_name"]] = signatures.get(d["signature_name"], 0) + 1
            folder = str(Path(d["file_path"]).parent)
            targets[folder] = targets.get(folder, 0) + 1
        ai_confidence = 95 + random.randint(0, 4)
        text = (
            f"AI Confidence Badge: {ai_confidence}%\n\n"
            f"Top Families:\n{families}\n\n"
            f"Severity Breakdown:\n{severities}\n\n"
            f"Most Detected Signatures:\n{dict(sorted(signatures.items(), key=lambda i: i[1], reverse=True)[:5])}\n\n"
            f"Most Targeted Folders:\n{dict(sorted(targets.items(), key=lambda i: i[1], reverse=True)[:5])}\n\n"
            f"Recent Detections: {len(detections)}\nRecent Realtime Events: {len(events)}"
        )
        self.intel_text.setPlainText(text)

    def export_scan_pdf(self) -> None:
        output = self.report_manager.export_scan_pdf()
        self.report_preview.append(f"PDF exported: {output}")

    def export_scan_csv(self) -> None:
        output = self.report_manager.export_scan_history_csv()
        self.report_preview.append(f"CSV exported: {output}")

    def export_quarantine_pdf(self) -> None:
        output = self.report_manager.export_quarantine_pdf()
        self.report_preview.append(f"Quarantine PDF exported: {output}")

    def _refresh_all(self) -> None:
        self.refresh_quarantine_table()
        self.refresh_history_table()
        self.refresh_realtime_events_table()
        self.refresh_intel_panel()
        self._update_dashboard_metrics()

    def _update_dashboard_metrics(self) -> None:
        scan_history = self.db.get_scan_history()
        detections = self.db.get_recent_detections(1000)
        quarantine_items = self.db.get_quarantine()
        events = self.db.get_recent_events(1000)
        self.metric_labels["Files Scanned"].setText(str(sum(int(row["total_scanned"]) for row in scan_history)))
        self.metric_labels["Threats Detected"].setText(str(len(detections)))
        self.metric_labels["Quarantined"].setText(str(len(quarantine_items)))
        self.metric_labels["Realtime Events"].setText(str(len(events)))

    def _start_dashboard_timer(self) -> None:
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick_graphs)
        self.timer.start(1200)

    def _tick_graphs(self) -> None:
        self.cpu_series = self.cpu_series[1:] + [random.randint(6, 48)]
        self.mem_series = self.mem_series[1:] + [random.randint(20, 72)]
        self.curve_cpu.setData(self.metric_points, self.cpu_series)
        self.curve_mem.setData(self.metric_points, self.mem_series)


class ScanDropTarget(QLabel):
    def __init__(self, window: MainWindow) -> None:
        super().__init__("Drop file or folder here for instant scan")
        self.window = window
        self.setAcceptDrops(True)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setMinimumHeight(80)
        self.setStyleSheet("border: 1px dashed #5ad0ff; border-radius: 10px; color: #7ce7ff;")

    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:
        urls = event.mimeData().urls()
        if not urls:
            return
        path = urls[0].toLocalFile()
        self.window.start_scan("Drag-and-Drop Scan", path)
