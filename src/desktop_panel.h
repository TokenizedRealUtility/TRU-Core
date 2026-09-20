#pragma once
#include <QWidget>
#include <QJsonObject>
#include "desktop_rpc.h"
class QComboBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QTableWidget;
class QPushButton;
class QTimer;
class QSpinBox;
class QTabWidget;

class DesktopPanel : public QWidget {
public:
    explicit DesktopPanel(QWidget* parent = nullptr);
    void useLocalNode(int port, const QByteArray& token);
    DesktopRpc* rpc() { return &rpc_; }
private:
    void refreshOverview();
    void selectOperation();
    void runOperation();
    void applyConnection();
    DesktopRpc rpc_;
    QTabWidget* pages_;
    QLineEdit *endpoint_, *cookie_, *sessionToken_;
    QLabel *connection_, *height_, *peers_, *rate_, *tip_, *operationHelp_;
    QComboBox *category_, *operation_;
    QPlainTextEdit *params_, *output_;
    QPushButton *run_;
    QTableWidget *miners_;
    QTimer* refresh_;
    bool overviewPending_ = false;
    bool writePending_ = false;
};
