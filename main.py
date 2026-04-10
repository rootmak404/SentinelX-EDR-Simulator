import sys

from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import QApplication, QSplashScreen

from config import APP_NAME, ensure_directories
from database import DatabaseManager
from demo_data import seed_signatures
from theme import MAIN_STYLESHEET
from ui.main_window import MainWindow


def build_splash() -> QSplashScreen:
    pix = QPixmap(720, 280)
    pix.fill()
    splash = QSplashScreen(pix)
    splash.showMessage(
        f"{APP_NAME}\nInitializing threat intelligence modules...",
        alignment=Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignBottom,
    )
    return splash


def run() -> int:
    ensure_directories()
    app = QApplication(sys.argv)
    app.setStyleSheet(MAIN_STYLESHEET)
    db = DatabaseManager()
    seed_signatures(db)
    splash = build_splash()
    splash.show()
    window = MainWindow(db)

    def show_window() -> None:
        splash.finish(window)
        window.show()

    QTimer.singleShot(1200, show_window)
    exit_code = app.exec()
    db.close()
    return exit_code


if __name__ == "__main__":
    raise SystemExit(run())
