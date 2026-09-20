#include "desktop_panel.h"
#include <QApplication>
#include <QFont>
#include <QTimer>
#include <QScreen>
int main(int argc, char** argv) {
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
#endif
    QApplication app(argc, argv);
    app.setApplicationName("TRU Core Desktop");
    app.setOrganizationName("TRUBlockchain");
    app.setFont(QFont("Sans Serif", 10));
    app.setStyleSheet(
        "QWidget {background:#0b1220;color:#dce8f3;}"
        "QGroupBox {border:1px solid #294056;border-radius:8px;margin-top:14px;padding:12px;}"
        "QGroupBox::title {subcontrol-origin:margin;left:14px;color:#92a8bd;}"
        "QLineEdit,QPlainTextEdit,QTableWidget,QComboBox {background:#101e30;border:1px solid #31465d;padding:8px;selection-background-color:#17697b;}"
        "QPushButton {background:#153448;border:1px solid #287d91;border-radius:6px;padding:9px 16px;}"
        "QPushButton:hover {background:#205269;} QPushButton:disabled {color:#668093;border-color:#243545;}"
        "QHeaderView::section,QTabBar::tab {background:#162638;color:#bfd5e6;padding:10px;border:0;}"
        "QTabBar::tab:selected {background:#205269;color:#72f0db;}"
        "QTabWidget::pane {border:1px solid #294056;}");
    DesktopPanel desktop;
    desktop.setWindowTitle("TRU Core Desktop — local node client");
    desktop.resize(1120, 780);
    desktop.show();
    // A deterministic screenshot hook is useful for package QA; no connection,
    // signing, mining or external action occurs during this preview.
    const auto args = app.arguments();
    const int shot = args.indexOf("--preview-png");
    if (shot >= 0 && shot + 1 < args.size()) {
        QTimer::singleShot(400, &desktop, [&desktop, &app, args, shot] {
            const bool saved = desktop.grab().save(args[shot + 1]);
            app.exit(saved ? 0 : 2);
        });
    }
    return app.exec();
}
