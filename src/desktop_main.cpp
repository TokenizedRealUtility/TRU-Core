#include "desktop_panel.h"
#if __has_include("tru_desktop_version.h")
#include "tru_desktop_version.h"
#else
#define TRU_DESKTOP_BUILD_VERSION "source"
#endif
#include <QApplication>
#include <QFileOpenEvent>
#include <QFont>
#include <QTimer>
#include <QScreen>
#include <cstring>
#include <functional>
#include <utility>

class TruDesktopApplication final : public QApplication {
public:
    using QApplication::QApplication;
    void setAxonHandler(std::function<void(const QString&)> handler) {
        axonHandler_ = std::move(handler);
        if (!pendingAxon_.isEmpty()) {
            const QString pending = pendingAxon_;
            pendingAxon_.clear();
            QTimer::singleShot(0, this, [this, pending] { deliverAxon(pending); });
        }
    }
    void queueAxon(const QString& uri) {
        if (!uri.startsWith("tru://axon/fund/")) return;
        if (axonHandler_) QTimer::singleShot(0, this, [this, uri] { deliverAxon(uri); });
        else pendingAxon_ = uri;
    }
protected:
    bool event(QEvent* event) override {
        if (event && event->type() == QEvent::FileOpen) {
            auto* open = static_cast<QFileOpenEvent*>(event);
            const QString uri = open->url().toString();
            if (uri.startsWith("tru://axon/fund/")) {
                queueAxon(uri);
                return true;
            }
        }
        return QApplication::event(event);
    }
private:
    void deliverAxon(const QString& uri) { if (axonHandler_) axonHandler_(uri); }
    QString pendingAxon_;
    std::function<void(const QString&)> axonHandler_;
};

int main(int argc, char** argv) {
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
#endif
    TruDesktopApplication app(argc, argv);
    // AXON UX-03B: capture tru:// only in process memory. Never write axc_ to
    // QSettings, wallet files or the local non-secret funding journal.
    const QStringList launchArgs = app.arguments();
    for (int i = 0; i < launchArgs.size(); ++i) {
        const QString& arg = launchArgs.at(i);
        if (arg.startsWith("tru://axon/fund/")) {
            app.queueAxon(arg);
            if (i < argc && argv[i]) {
                const std::size_t n = std::strlen(argv[i]);
                std::memset(argv[i], 0, n);
            }
            break;
        }
    }
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
    app.setAxonHandler([&desktop](const QString& uri) { desktop.openAxonHandoff(uri); });
    // Explicit native window controls; no fixed-size constraint.
    desktop.setWindowFlags(Qt::Window | Qt::WindowTitleHint |
                           Qt::WindowSystemMenuHint | Qt::WindowMinMaxButtonsHint |
                           Qt::WindowCloseButtonHint);
    desktop.setWindowTitle(QString("TRU Core Desktop v%1").arg(TRU_DESKTOP_BUILD_VERSION));
    desktop.setMinimumSize(720, 520);
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
