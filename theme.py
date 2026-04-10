MAIN_STYLESHEET = """
QWidget {
    background-color: #0b0f1a;
    color: #d9e9ff;
    font-family: Segoe UI, Inter, Arial;
    font-size: 13px;
}
QMainWindow {
    background-color: #080c15;
}
#Sidebar {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #101a2b, stop:1 #0d1322);
    border-right: 1px solid #23314f;
}
QPushButton {
    background-color: #141f33;
    border: 1px solid #2d3f65;
    border-radius: 10px;
    padding: 8px 12px;
}
QPushButton:hover {
    border: 1px solid #43d7ff;
    background-color: #1a2945;
}
QPushButton:checked {
    background-color: #1f3d63;
    border: 1px solid #5cf4ff;
}
QFrame[class="glassCard"] {
    background-color: rgba(22, 30, 52, 170);
    border: 1px solid #2e4e78;
    border-radius: 14px;
}
QLineEdit, QComboBox {
    background-color: #0f1a2a;
    border: 1px solid #304a76;
    border-radius: 8px;
    padding: 7px;
}
QTableWidget {
    gridline-color: #22345a;
    border: 1px solid #2b3f66;
    border-radius: 10px;
    background-color: #0e1728;
}
QHeaderView::section {
    background-color: #11213a;
    border: none;
    padding: 6px;
    color: #9ed8ff;
}
QProgressBar {
    border: 1px solid #2d4b74;
    border-radius: 8px;
    background-color: #101d31;
    text-align: center;
}
QProgressBar::chunk {
    background-color: #36d8ff;
    border-radius: 7px;
}
"""
