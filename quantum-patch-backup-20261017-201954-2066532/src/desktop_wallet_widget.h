#pragma once

#include "desktop_wallet_core.h"

#include <QJsonArray>
#include <QJsonObject>
#include <QStringList>
#include <QWidget>
#include <cstdint>
#include <functional>
#include <vector>

class DesktopRpc;
class QLabel;
class QPlainTextEdit;

class DesktopWalletWidget : public QWidget {
public:
    explicit DesktopWalletWidget(
        DesktopRpc* rpc, QWidget* parent = nullptr);
    ~DesktopWalletWidget() override = default;

    // Read-only address exposure for the Desktop asset gallery.
    // Seed/private key material never leaves DesktopWalletCore.
    QStringList walletAddresses() const;

    // Public self-custody helpers used by Assets / AI surfaces. No seed or
    // private key leaves DesktopWalletCore.
    bool walletUnlocked() const noexcept;
    QString currentWalletAddress() const;
    bool validateWalletAddress(const QString& address) const;

    // AXON UX-03B: consume a short-lived tru:// funding handoff through a local Core.
    void openAxonHandoff(const QString& uri);

    void selectSafeFeeUtxo(
        std::uint64_t minimumAtoms,
        std::function<void(QJsonObject, QString)> done);

    bool inspectPreparedIntent(
        const QString& unsignedTxHex,
        const QJsonObject& selectedUtxo,
        const QJsonArray& approvedOutputs,
        std::uint64_t maxFeeAtoms,
        QString& metadataTailHex,
        QJsonObject& embeddedMetadata,
        QString& errorOut) const;
    QString walletScriptForAddress(const QString& address) const;

    bool signPreparedTransaction(
        const QString& unsignedTxHex,
        const QJsonArray& signingInputs,
        QString& signedTxHexOut,
        QString& txidOut,
        QString& errorOut);

    bool signVotingV1Ballot(const QString& unsignedTxHex,
        const QJsonObject& feeUtxo,const QString& liveAnchor,
        const QString& anchorAtoms,const QString& unlockHex,
        const QString& callHex,QString& signedTxOut,
        QString& txidOut,QString& errorOut) const;

    // 07B: derive and sign a canonical lock redemption locally. Never expose keys.
    bool signContractRedemption(
        const QJsonObject& confirmedOutpoint, const QString& family,
        const QString& preimage, const QString& destination,
        QString& rawHexOut, QString& txidOut, QString& errorOut) const;

    bool signAuthorization(
        const QString& ownerAddress,
        const QString& canonicalMessage,
        QString& publicKeyHexOut,
        QString& signatureHexOut,
        QString& errorOut) const;

private:
    DesktopRpc* rpc_;
    DesktopWalletCore wallet_;
    QString walletPath_;

    QLabel* state_;
    QLabel* address_;
    QLabel* balance_;
    QLabel* addressCount_;
    QLabel* did_;
    QLabel* didStatus_;
    QPlainTextEdit* activity_;

    void updateUi();
    void logLine(const QString& text);
    QString askPassphrase(
        const QString& title, bool confirm, bool* okOut);

    void createWallet();
    void unlockWallet();
    void lockWallet();
    void newAddress();
    void backupWallet();
    void restoreBackup();
    void showRecovery();
    void restoreRecovery();
    void refreshBalance();
    void sendTru();
    void refreshDidStatus(const QString& address, const QString& did);
    void showQrCodes();

    void collectUtxos(
        std::function<void(
            std::vector<DesktopWalletUtxo>, QString)> done);

    void safetyFilter(
        std::vector<DesktopWalletUtxo> all,
        std::function<void(
            std::vector<DesktopWalletUtxo>, QString)> done);
};
