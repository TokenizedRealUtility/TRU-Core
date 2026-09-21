#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <QStringList>
#include <QWidget>

class DesktopRpc;
class DesktopWalletWidget;
class QLabel;
class QPushButton;
class QGridLayout;
class QNetworkAccessManager;

class DesktopAssetsWidget : public QWidget {
public:
    explicit DesktopAssetsWidget(
        DesktopRpc* rpc,
        DesktopWalletWidget* wallet,
        QWidget* parent = nullptr);
    ~DesktopAssetsWidget() override = default;

private:
    DesktopRpc* rpc_;
    DesktopWalletWidget* wallet_;
    QNetworkAccessManager* imageNetwork_;

    QLabel* status_ = nullptr;
    QLabel* tokenCount_ = nullptr;
    QLabel* scriptCount_ = nullptr;
    QPushButton* refresh_ = nullptr;
    QGridLayout* tokenGrid_ = nullptr;
    QGridLayout* scriptGrid_ = nullptr;

    void refreshAssets();
    void renderTokens(const QJsonArray& tokens);
    void renderScripts(const QJsonArray& scripts);
    void sendToken(
        const QJsonObject& token,
        const QJsonObject& metadata);
    void sendTRUScript(const QJsonObject& script);
    void loadScriptsSequential(
        const QStringList& addresses,
        int index,
        QJsonArray collected,
        QStringList errors,
        int tokenCount);
    void clearGrid(QGridLayout* grid);
    void loadArtwork(
        QLabel* target,
        const QString& artwork,
        const QString& fallbackText);

    static QString safeArtworkUrl(const QString& value);
    static QString truscriptArtwork(const QString& data);
    static QString shortText(const QString& value, int maxChars);
    static QString decimalAmount(
        const QJsonValue& amount,
        const QJsonObject& metadata,
        const QString& type);
};
