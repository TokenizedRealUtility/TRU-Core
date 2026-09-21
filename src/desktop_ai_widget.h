#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <QString>
#include <QWidget>

class DesktopRpc;
class DesktopWalletWidget;
class QLabel;
class QPushButton;
class QGridLayout;
class QVBoxLayout;
class QNetworkAccessManager;
class QComboBox;
class QLineEdit;
class QRadioButton;
class QFrame;

class DesktopAIWidget : public QWidget {
public:
    explicit DesktopAIWidget(
        DesktopRpc* rpc,
        DesktopWalletWidget* wallet,
        QWidget* parent = nullptr);
    ~DesktopAIWidget() override = default;

    // Presentation-only theme switch. No provider/RPC semantics are changed.
    void applyTheme(const QString& theme);

private:
    DesktopRpc* rpc_;
    DesktopWalletWidget* wallet_;
    QNetworkAccessManager* imageNetwork_;
    QNetworkAccessManager* directNetwork_;

    QLabel* status_ = nullptr;
    QLabel* aiCount_ = nullptr;
    QLabel* providerCount_ = nullptr;
    QPushButton* refresh_ = nullptr;
    QGridLayout* aiGrid_ = nullptr;
    QGridLayout* providerGrid_ = nullptr;
    QVBoxLayout* provenanceList_ = nullptr;

    QRadioButton* coreMode_ = nullptr;
    QRadioButton* cloudMode_ = nullptr;
    QRadioButton* localMode_ = nullptr;
    QFrame* coreSettingsFrame_ = nullptr;
    QFrame* cloudSettingsFrame_ = nullptr;
    QFrame* localSettingsFrame_ = nullptr;
    QComboBox* coreProvider_ = nullptr;
    QComboBox* cloudProvider_ = nullptr;
    QLineEdit* cloudEndpoint_ = nullptr;
    QLineEdit* cloudModel_ = nullptr;
    QLineEdit* cloudApiKey_ = nullptr;
    QComboBox* localFlavor_ = nullptr;
    QLineEdit* localEndpoint_ = nullptr;
    QLineEdit* localModel_ = nullptr;
    QLineEdit* localApiKey_ = nullptr;
    QLabel* settingsStatus_ = nullptr;
    QLabel* coreAiIndicator_ = nullptr;

    QJsonArray aiTokens_;
    QJsonObject coreProviders_;
    QString testedCoreProvider_;
    bool coreProviderTestKnown_ = false;
    bool coreProviderReachable_ = false;

    void refreshAll();
    void renderAiAssets(const QJsonArray& tokens);
    void renderProviders(const QJsonObject& providers);
    void renderProvenance(const QJsonArray& tokens);
    void requestAiState(const QJsonObject& token);
    void evolveToken(const QJsonObject& token);
    void verifyProvenance(const QJsonObject& token);
    void clearGrid(QGridLayout* grid);
    void clearLayout(QVBoxLayout* layout);
    void loadArtwork(
        QLabel* target,
        const QString& artwork,
        const QString& fallbackText);

    void loadAiSettings();
    void saveAiSettings();
    void updateSettingsModeUi();
    void applyCloudProviderDefaults(const QString& provider);
    void applyLocalProviderDefaults(const QString& provider);
    void testCoreProvider();
    void testCoreProviderNamed(const QString& provider);
    void updateCoreAiIndicator();
    void testDirectProvider(bool localMode);
    void saveEncryptedCredential();
    void loadEncryptedCredential();
    void deleteEncryptedCredential();
    QString credentialVaultPath() const;
};
