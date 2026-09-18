// Wallet presentation styles.
#ifndef WALLET_STYLES_H
#define WALLET_STYLES_H

#include <QString>

namespace WalletStyles {

const QString DARK_FUTURISTIC = R"(
/* Main Window */
QWidget {
    background-color: #0a0e1a;
    color: #e0e0e0;
    font-family: 'Segoe UI', 'Roboto', sans-serif;
}

/* Tab Widget */
QTabWidget::pane {
    border: 1px solid #1e2936;
    background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                stop: 0 #0f1419, stop: 1 #0a0e1a);
    border-radius: 8px;
}

QTabBar::tab {
    background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                stop: 0 #1e2936, stop: 1 #151922);
    border: 1px solid #2a3441;
    border-bottom: none;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    padding: 8px 20px;
    margin-right: 2px;
    color: #7a8499;
    font-weight: bold;
}

QTabBar::tab:selected {
    background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                stop: 0 #00d4ff, stop: 1 #0099cc);
    color: #ffffff;
    border-color: #00d4ff;
}

QTabBar::tab:hover:!selected {
    background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                stop: 0 #2a3441, stop: 1 #1e2936);
    color: #a0a8b8;
}

/* Push Buttons */
QPushButton {
    background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 1,
                                stop: 0 #1e2936, stop: 1 #151922);
    border: 2px solid #00d4ff;
    border-radius: 6px;
    padding: 8px 16px;
    color: #00d4ff;
    font-weight: bold;
    font-size: 14px;
}

QPushButton:hover {
    background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 1,
                                stop: 0 #00d4ff, stop: 0.5 #0099cc, stop: 1 #006699);
    color: #ffffff;
    border-color: #00ffff;
}

QPushButton:pressed {
    background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 1,
                                stop: 0 #006699, stop: 1 #004466);
    border-color: #0099cc;
}

/* Special Mining Button */
QPushButton#mine_button {
    background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 1,
                                stop: 0 #ff6b00, stop: 1 #ff4500);
    border-color: #ff6b00;
    color: #ffffff;
}

QPushButton#mine_button:hover {
    background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 1,
                                stop: 0 #ff8c00, stop: 1 #ff6b00);

}

/* Line Edits */
QLineEdit {
    background-color: #0f1419;
    border: 2px solid #1e2936;
    border-radius: 6px;
    padding: 8px;
    color: #e0e0e0;
    font-size: 14px;
}

QLineEdit:focus {
    border-color: #00d4ff;
    background-color: #151922;

}

/* Combo Box */
QComboBox {
    background-color: #0f1419;
    border: 2px solid #1e2936;
    border-radius: 6px;
    padding: 8px;
    color: #e0e0e0;
    min-height: 25px;
}

QComboBox:hover {
    border-color: #00d4ff;
}

QComboBox::drop-down {
    border: none;
    background: transparent;
}

QComboBox::down-arrow {
    image: none;
    border-left: 5px solid transparent;
    border-right: 5px solid transparent;
    border-top: 5px solid #00d4ff;
    margin-right: 5px;
}

/* Table Widget */
QTableWidget {
    background-color: #0f1419;
    border: 2px solid #1e2936;
    border-radius: 6px;
    gridline-color: #1e2936;
}

QTableWidget::item {
    padding: 8px;
    border-bottom: 1px solid #1e2936;
}

QTableWidget::item:selected {
    background-color: #00d4ff;
    color: #0a0e1a;
}

QHeaderView::section {
    background-color: #151922;
    color: #00d4ff;
    border: none;
    padding: 8px;
    font-weight: bold;
    border-bottom: 2px solid #00d4ff;
}

/* Group Box */
QGroupBox {
    border: 2px solid #1e2936;
    border-radius: 8px;
    margin-top: 10px;
    padding-top: 10px;
    font-weight: bold;
    color: #00d4ff;
}

QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 10px 0 10px;
    background-color: #0a0e1a;
}

/* Progress Bar */
QProgressBar {
    border: 2px solid #1e2936;
    border-radius: 6px;
    background-color: #0f1419;
    text-align: center;
    color: #00d4ff;
}

QProgressBar::chunk {
    background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
                                stop: 0 #00d4ff, stop: 1 #00ffff);
    border-radius: 4px;
}

/* Scroll Bar */
QScrollBar:vertical {
    background-color: #0f1419;
    width: 12px;
    border-radius: 6px;
}

QScrollBar::handle:vertical {
    background-color: #1e2936;
    border-radius: 6px;
    min-height: 20px;
}

QScrollBar::handle:vertical:hover {
    background-color: #00d4ff;
}

/* Labels */
QLabel {
    color: #a0a8b8;
}

QLabel#balance_label {
    color: #00ff88;
    font-size: 16px;
    font-weight: bold;
    padding: 5px;
    background-color: #0f1419;
    border-radius: 4px;
    border: 1px solid #00ff88;
}

/* Text Edit */
QTextEdit {
    background-color: #0f1419;
    border: 2px solid #1e2936;
    border-radius: 6px;
    padding: 8px;
    color: #e0e0e0;
}

QTextEdit:focus {
    border-color: #00d4ff;

}

/* Check Box */
QCheckBox {
    spacing: 8px;
    color: #a0a8b8;
}

QCheckBox::indicator {
    width: 20px;
    height: 20px;
    border-radius: 4px;
    border: 2px solid #1e2936;
    background-color: #0f1419;
}

QCheckBox::indicator:checked {
    background-color: #00d4ff;
    border-color: #00d4ff;
    image: none;
}

QCheckBox::indicator:hover {
    border-color: #00d4ff;
}

/* Spin Box */
QSpinBox {
    background-color: #0f1419;
    border: 2px solid #1e2936;
    border-radius: 6px;
    padding: 5px;
    color: #e0e0e0;
}

QSpinBox:focus {
    border-color: #00d4ff;
}

QSpinBox::up-button, QSpinBox::down-button {
    background-color: #1e2936;
    border: none;
    width: 20px;
}

QSpinBox::up-button:hover, QSpinBox::down-button:hover {
    background-color: #00d4ff;
}
)";

const QString CYBERPUNK_PINK = R"(
/* Cyberpunk Pink Theme */
QWidget {
    background-color: #0a0014;
    color: #ff00ff;
    font-family: 'Orbitron', 'Courier New', monospace;
}

QPushButton {
    background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 1,
                                stop: 0 #ff006e, stop: 1 #8b00ff);
    border: 2px solid #ff00ff;
    border-radius: 0px;
    padding: 10px 20px;
    color: #ffffff;
    font-weight: bold;
    text-transform: uppercase;
}

QPushButton:hover {
    background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 1,
                                stop: 0 #ff00ff, stop: 1 #00ffff);
    inset 0 0 20px #ff00ff;
}
)";

} // namespace WalletStyles

#endif // WALLET_STYLES_H
