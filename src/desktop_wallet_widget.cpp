#include "desktop_wallet_widget.h"
#include "desktop_rpc.h"

#include <QApplication>
#include <QClipboard>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDialog>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QImage>
#include <QFrame>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPainter>
#include <QPixmap>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QStandardPaths>
#include <QStyle>
#include <QTabWidget>
#include <QVBoxLayout>

#include <qrencode.h>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <stdexcept>
#include <utility>

namespace {

QByteArray objectParams(const QJsonObject& o) {
    return QJsonDocument(o).toJson(QJsonDocument::Compact);
}

QString scriptHex(const QJsonValue& value) {
    if (value.isString()) return value.toString().toLower();
    if (value.isObject())
        return value.toObject().value("hex").toString().toLower();
    return {};
}

bool exactAtoms(
    const QJsonObject& o, std::uint64_t& atomsOut) {
    if (!o.contains("amount_atoms")) return false;
    const QJsonValue v = o.value("amount_atoms");

    if (v.isString()) {
        bool ok = false;
        const qulonglong n = v.toString().toULongLong(&ok);
        if (!ok) return false;
        atomsOut = static_cast<std::uint64_t>(n);
        return true;
    }

    if (v.isDouble()) {
        const double d = v.toDouble();
        if (d < 0.0 || d > 9007199254740991.0) return false;
        const auto n = static_cast<std::uint64_t>(d);
        if (static_cast<double>(n) != d) return false;
        atomsOut = n;
        return true;
    }

    return false;
}

void wipeStdString(std::string& s) {
    std::fill(s.begin(), s.end(), '\0');
    s.clear();
}

QString deterministicTruDid(const QString& address) {
    if (address.trimmed().isEmpty()) return {};
    const QByteArray first = QCryptographicHash::hash(
        (address + "mySpecialRandomSalt42").toUtf8(),
        QCryptographicHash::Sha256).toHex();
    const QByteArray second = QCryptographicHash::hash(
        first, QCryptographicHash::Sha256).toHex();
    return "did:on_tru:" + QString::fromLatin1(second.left(16));
}

QPixmap qrPixmap(const QString& payload, int modulePixels = 7) {
    const QByteArray utf8 = payload.toUtf8();
    QRcode* code = QRcode_encodeString8bit(
        utf8.constData(), 0, QR_ECLEVEL_M);
    if (!code || code->width <= 0 || !code->data) {
        if (code) QRcode_free(code);
        return {};
    }

    constexpr int quiet = 4;
    const int modules = code->width + quiet * 2;
    const int imageSize = modules * modulePixels;
    QImage image(imageSize, imageSize, QImage::Format_ARGB32);
    image.fill(Qt::white);

    QPainter painter(&image);
    painter.setPen(Qt::NoPen);
    painter.setBrush(Qt::black);
    for (int y = 0; y < code->width; ++y) {
        for (int x = 0; x < code->width; ++x) {
            if ((code->data[y * code->width + x] & 0x01U) == 0U)
                continue;
            painter.drawRect(
                (x + quiet) * modulePixels,
                (y + quiet) * modulePixels,
                modulePixels,
                modulePixels);
        }
    }
    painter.end();
    QRcode_free(code);
    return QPixmap::fromImage(image);
}

QWidget* qrPage(const QString& title, const QString& value) {
    auto* page = new QWidget;
    auto* layout = new QVBoxLayout(page);
    layout->setContentsMargins(18, 18, 18, 18);
    layout->setSpacing(12);

    auto* heading = new QLabel(title);
    heading->setStyleSheet(
        "color:#6ef5ef;font-size:18px;font-weight:800;");
    layout->addWidget(heading, 0, Qt::AlignHCenter);

    auto* qr = new QLabel;
    qr->setAlignment(Qt::AlignCenter);
    qr->setStyleSheet(
        "background:#ffffff;border:10px solid #ffffff;border-radius:10px;");
    const QPixmap pix = qrPixmap(value);
    if (pix.isNull()) {
        qr->setText("QR generation failed");
        qr->setStyleSheet(
            "background:#071a2a;color:#ff9aa2;border:1px solid #6f3447;"
            "border-radius:10px;padding:30px;");
    } else {
        qr->setPixmap(pix);
    }
    layout->addWidget(qr, 0, Qt::AlignHCenter);

    auto* raw = new QLabel(value);
    raw->setTextFormat(Qt::PlainText);
    raw->setTextInteractionFlags(Qt::TextSelectableByMouse);
    raw->setWordWrap(true);
    raw->setAlignment(Qt::AlignCenter);
    raw->setStyleSheet(
        "background:#071a2a;color:#dffcff;border:1px solid #1f5970;"
        "border-radius:8px;padding:10px;font-family:'DejaVu Sans Mono','Menlo','Consolas';");
    layout->addWidget(raw);

    auto* copy = new QPushButton("Copy " + title);
    copy->setObjectName("truSecondaryAction");
    QObject::connect(copy, &QPushButton::clicked, page, [value] {
        QApplication::clipboard()->setText(value);
    });
    layout->addWidget(copy, 0, Qt::AlignHCenter);
    layout->addStretch();
    return page;
}

} // namespace

DesktopWalletWidget::DesktopWalletWidget(
    DesktopRpc* rpc, QWidget* parent)
    : QWidget(parent), rpc_(rpc) {
    const QString appData =
        QStandardPaths::writableLocation(
            QStandardPaths::AppDataLocation);
    QDir().mkpath(appData);
    walletPath_ =
        QDir(appData).filePath("standalone-wallet-v1.enc");

    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(14, 14, 14, 14);
    root->setSpacing(12);

    auto* hero = new QFrame;
    hero->setObjectName("truWalletHero");
    auto* heroLayout = new QHBoxLayout(hero);
    heroLayout->setContentsMargins(18, 15, 18, 15);
    heroLayout->setSpacing(18);

    auto* heroLeft = new QVBoxLayout;
    auto* eyebrow = new QLabel("SELF-CUSTODY  //  LOCAL KEYS  //  LOCAL SIGNING");
    eyebrow->setObjectName("truWalletEyebrow");
    auto* title = new QLabel("Standalone TRU Wallet");
    title->setObjectName("truWalletTitle");
    state_ = new QLabel;
    state_->setObjectName("truWalletState");
    heroLeft->addWidget(eyebrow);
    heroLeft->addWidget(title);
    heroLeft->addWidget(state_, 0, Qt::AlignLeft);
    heroLeft->addStretch();

    auto* heroRight = new QVBoxLayout;
    auto* balanceCaption = new QLabel("SAFE SPENDABLE");
    balanceCaption->setObjectName("truWalletBalanceCaption");
    balance_ = new QLabel("— TRU");
    balance_->setObjectName("truWalletBalanceValue");
    balance_->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    heroRight->addWidget(balanceCaption, 0, Qt::AlignRight);
    heroRight->addWidget(balance_, 0, Qt::AlignRight);
    heroRight->addStretch();

    heroLayout->addLayout(heroLeft, 1);
    heroLayout->addLayout(heroRight);
    root->addWidget(hero);

    auto* receiveCard = new QFrame;
    receiveCard->setObjectName("truReceiveCard");
    auto* receiveLayout = new QGridLayout(receiveCard);
    receiveLayout->setContentsMargins(18, 15, 18, 15);
    receiveLayout->setHorizontalSpacing(14);
    receiveLayout->setVerticalSpacing(9);
    receiveLayout->setColumnStretch(1, 1);

    auto* identityTitle = new QLabel("RECEIVE & IDENTITY");
    identityTitle->setObjectName("truWalletEyebrow");
    receiveLayout->addWidget(identityTitle, 0, 0, 1, 3);

    auto* receiveLabel = new QLabel("TRU ADDRESS");
    receiveLabel->setObjectName("truWalletEyebrow");
    address_ = new QLabel("—");
    address_->setObjectName("truWalletAddress");
    address_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    address_->setWordWrap(false);

    auto* copyAddress = new QPushButton("Copy Address");
    copyAddress->setObjectName("truSecondaryAction");
    copyAddress->setMinimumWidth(140);

    receiveLayout->addWidget(receiveLabel, 1, 0, Qt::AlignTop);
    receiveLayout->addWidget(address_, 1, 1);
    receiveLayout->addWidget(copyAddress, 1, 2);

    auto* didLabel = new QLabel("TRU DID");
    didLabel->setObjectName("truWalletEyebrow");
    did_ = new QLabel("—");
    did_->setObjectName("truWalletDid");
    did_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    did_->setWordWrap(false);
    did_->setStyleSheet(
        "QLabel#truWalletDid{background:#041624;color:#8af8ef;"
        "border:1px solid #1c536b;border-radius:6px;padding:9px 11px;"
        "font-family:'DejaVu Sans Mono','Menlo','Consolas';font-weight:700;}");

    auto* didActions = new QHBoxLayout;
    didActions->setContentsMargins(0, 0, 0, 0);
    didActions->setSpacing(8);
    didStatus_ = new QLabel("—");
    didStatus_->setObjectName("truAssetCountBadge");
    auto* copyDid = new QPushButton("Copy DID");
    copyDid->setObjectName("truSecondaryAction");
    copyDid->setMinimumWidth(140);
    didActions->addWidget(didStatus_);
    didActions->addWidget(copyDid);

    receiveLayout->addWidget(didLabel, 2, 0, Qt::AlignTop);
    receiveLayout->addWidget(did_, 2, 1);
    receiveLayout->addLayout(didActions, 2, 2);

    addressCount_ = new QLabel("— generated addresses");
    addressCount_->setObjectName("truWalletMeta");
    auto* walletFile = new QLabel(
        "Encrypted  ·  " + QFileInfo(walletPath_).fileName());
    walletFile->setObjectName("truWalletMeta");
    auto* showQr = new QPushButton("Show QR Codes");
    showQr->setObjectName("truSecondaryAction");
    showQr->setMinimumWidth(140);

    auto* receiveMeta = new QHBoxLayout;
    receiveMeta->setContentsMargins(0, 2, 0, 0);
    receiveMeta->addWidget(addressCount_);
    receiveMeta->addSpacing(10);
    receiveMeta->addWidget(walletFile);
    receiveMeta->addStretch();

    receiveLayout->addLayout(receiveMeta, 3, 1);
    receiveLayout->addWidget(showQr, 3, 2);

    root->addWidget(receiveCard);

    auto* actionsBox = new QGroupBox("TRU WALLET");
    auto* actions = new QGridLayout(actionsBox);
    actions->setHorizontalSpacing(9);
    actions->setVerticalSpacing(9);

    auto* send = new QPushButton("Send TRU");
    send->setObjectName("truPrimaryAction");
    auto* next = new QPushButton("New Address");
    auto* refresh = new QPushButton("Refresh");
    auto* create = new QPushButton("Create Wallet");
    auto* unlock = new QPushButton("Unlock");
    auto* lock = new QPushButton("Lock");
    lock->setObjectName("truSecondaryAction");

    actions->addWidget(send, 0, 0);
    actions->addWidget(next, 0, 1);
    actions->addWidget(refresh, 0, 2);
    actions->addWidget(create, 1, 0);
    actions->addWidget(unlock, 1, 1);
    actions->addWidget(lock, 1, 2);
    for (int column = 0; column < 3; ++column)
        actions->setColumnStretch(column, 1);
    root->addWidget(actionsBox);

    auto* securityBox = new QGroupBox("SECURITY & RECOVERY");
    auto* security = new QHBoxLayout(securityBox);
    auto* backup = new QPushButton("Backup Wallet");
    auto* restore = new QPushButton("Restore Backup");
    auto* recovery = new QPushButton("Show Recovery Secret");
    auto* restoreCode = new QPushButton("Restore Recovery Secret");
    recovery->setObjectName("truSensitiveAction");
    restoreCode->setObjectName("truSensitiveAction");
    security->addWidget(backup);
    security->addWidget(restore);
    security->addWidget(recovery);
    security->addWidget(restoreCode);
    root->addWidget(securityBox);

    auto* activityHeader = new QHBoxLayout;
    auto* activityTitle = new QLabel("RECENT WALLET ACTIVITY");
    activityTitle->setObjectName("truAssetSectionTitle");
    auto* activityHint = new QLabel("Local events only  ·  secrets are never logged");
    activityHint->setObjectName("truWalletMeta");
    activityHeader->addWidget(activityTitle);
    activityHeader->addStretch();
    activityHeader->addWidget(activityHint);
    root->addLayout(activityHeader);

    activity_ = new QPlainTextEdit;
    activity_->setObjectName("truWalletActivity");
    activity_->setReadOnly(true);
    activity_->setPlaceholderText("Wallet activity will appear here.");
    root->addWidget(activity_, 1);

    connect(create, &QPushButton::clicked,
            this, [this]{ createWallet(); });
    connect(unlock, &QPushButton::clicked,
            this, [this]{ unlockWallet(); });
    connect(lock, &QPushButton::clicked,
            this, [this]{ lockWallet(); });
    connect(next, &QPushButton::clicked,
            this, [this]{ newAddress(); });
    connect(refresh, &QPushButton::clicked,
            this, [this]{ refreshBalance(); });
    connect(send, &QPushButton::clicked,
            this, [this]{ sendTru(); });
    connect(backup, &QPushButton::clicked,
            this, [this]{ backupWallet(); });
    connect(restore, &QPushButton::clicked,
            this, [this]{ restoreBackup(); });
    connect(recovery, &QPushButton::clicked,
            this, [this]{ showRecovery(); });
    connect(restoreCode, &QPushButton::clicked,
            this, [this]{ restoreRecovery(); });
    connect(copyAddress, &QPushButton::clicked,
            this, [this] {
        if (!wallet_.isUnlocked()) {
            QMessageBox::information(
                this, "Copy Address", "Unlock the wallet first.");
            return;
        }
        const QString current =
            QString::fromStdString(wallet_.currentAddress());
        QApplication::clipboard()->setText(current);
        logLine("Receive address copied to clipboard.");
    });
    connect(copyDid, &QPushButton::clicked,
            this, [this] {
        if (!wallet_.isUnlocked()) {
            QMessageBox::information(
                this, "Copy DID", "Unlock the wallet first.");
            return;
        }
        const QString current =
            QString::fromStdString(wallet_.currentAddress());
        const QString did = deterministicTruDid(current);
        QApplication::clipboard()->setText(did);
        logLine("Current address TRU DID copied to clipboard.");
    });
    connect(showQr, &QPushButton::clicked,
            this, [this] { showQrCodes(); });

    updateUi();
}

QStringList DesktopWalletWidget::walletAddresses() const {
    QStringList result;
    if (!wallet_.isUnlocked()) return result;
    try {
        for (const auto& address : wallet_.addresses())
            result.push_back(QString::fromStdString(address));
    } catch (...) {
        result.clear();
    }
    return result;
}

bool DesktopWalletWidget::walletUnlocked() const noexcept {
    return wallet_.isUnlocked();
}

QString DesktopWalletWidget::currentWalletAddress() const {
    if (!wallet_.isUnlocked()) return {};
    try {
        return QString::fromStdString(wallet_.currentAddress());
    } catch (...) {
        return {};
    }
}

bool DesktopWalletWidget::validateWalletAddress(
    const QString& address) const {
    try {
        return wallet_.validateAddress(
            address.trimmed().toStdString());
    } catch (...) {
        return false;
    }
}

void DesktopWalletWidget::selectSafeFeeUtxo(
    std::uint64_t minimumAtoms,
    std::function<void(QJsonObject, QString)> done) {
    if (!wallet_.isUnlocked()) {
        done({}, "Unlock the standalone wallet first.");
        return;
    }

    collectUtxos(
        [this, minimumAtoms, done = std::move(done)](
            std::vector<DesktopWalletUtxo> all,
            QString error) mutable {
            if (!error.isEmpty()) {
                done({}, error);
                return;
            }

            safetyFilter(
                std::move(all),
                [minimumAtoms, done = std::move(done)](
                    std::vector<DesktopWalletUtxo> safe,
                    QString error2) mutable {
                    if (!error2.isEmpty()) {
                        done({}, error2);
                        return;
                    }

                    const DesktopWalletUtxo* selected = nullptr;
                    for (const auto& candidate : safe) {
                        if (candidate.amountAtoms < minimumAtoms)
                            continue;
                        if (!selected ||
                            candidate.amountAtoms < selected->amountAtoms)
                            selected = &candidate;
                    }

                    if (!selected) {
                        done(
                            {},
                            QString(
                                "No confirmed safe TRU UTXO has at least %1 atoms "
                                "for the transaction fee/control output.")
                                .arg(QString::number(
                                    static_cast<qulonglong>(
                                        minimumAtoms))));
                        return;
                    }

                    QJsonObject result;
                    result.insert(
                        "txid",
                        QString::fromStdString(selected->txid));
                    result.insert(
                        "vout",
                        static_cast<int>(selected->vout));
                    result.insert(
                        "amount_atoms",
                        QString::number(
                            static_cast<qulonglong>(
                                selected->amountAtoms)));
                    result.insert(
                        "scriptPubKey",
                        QString::fromStdString(
                            selected->scriptPubKey));
                    done(result, {});
                });
        });
}

bool DesktopWalletWidget::signPreparedTransaction(
    const QString& unsignedTxHex,
    const QJsonArray& signingInputs,
    QString& signedTxHexOut,
    QString& txidOut,
    QString& errorOut) {
    signedTxHexOut.clear();
    txidOut.clear();
    errorOut.clear();

    if (!wallet_.isUnlocked()) {
        errorOut = "Unlock the standalone wallet first.";
        return false;
    }
    if (unsignedTxHex.trimmed().isEmpty() ||
        signingInputs.isEmpty()) {
        errorOut =
            "Prepared transaction or signing descriptors are missing.";
        return false;
    }

    try {
        std::vector<DesktopWalletUtxo> descriptors;
        descriptors.reserve(
            static_cast<std::size_t>(signingInputs.size()));

        for (const QJsonValue& value : signingInputs) {
            if (!value.isObject())
                throw std::runtime_error(
                    "Signing descriptor is not an object.");

            const QJsonObject object = value.toObject();
            const QString txid = object.value("txid").toString();
            const int vout = object.value("vout").toInt(-1);
            const QString script =
                scriptHex(object.value("scriptPubKey"));

            std::uint64_t atoms = 0;
            if (!exactAtoms(object, atoms) || atoms == 0)
                throw std::runtime_error(
                    "Signing descriptor lacks exact amount_atoms.");
            if (txid.size() != 64 || vout < 0 || script.isEmpty())
                throw std::runtime_error(
                    "Signing descriptor identity is malformed.");

            std::uint32_t keyIndex = wallet_.addressCount();
            for (std::uint32_t i = 0;
                 i < wallet_.addressCount(); ++i) {
                const QString expected =
                    QString::fromStdString(
                        wallet_.scriptForAddress(
                            wallet_.address(i)));
                if (expected.compare(
                        script, Qt::CaseInsensitive) == 0) {
                    keyIndex = i;
                    break;
                }
            }

            if (keyIndex >= wallet_.addressCount())
                throw std::runtime_error(
                    "Prepared input is not controlled by this "
                    "standalone wallet.");

            DesktopWalletUtxo descriptor;
            descriptor.txid = txid.toStdString();
            descriptor.vout =
                static_cast<std::uint32_t>(vout);
            descriptor.amountAtoms = atoms;
            descriptor.scriptPubKey =
                script.toStdString();
            descriptor.keyIndex = keyIndex;
            descriptors.push_back(std::move(descriptor));
        }

        const auto signedTx = wallet_.signPrepared(
            unsignedTxHex.trimmed().toStdString(),
            descriptors);
        signedTxHexOut =
            QString::fromStdString(signedTx.rawHex);
        txidOut = QString::fromStdString(signedTx.txid);
        return true;
    } catch (const std::exception& e) {
        errorOut = QString::fromUtf8(e.what());
        return false;
    }
}

bool DesktopWalletWidget::signAuthorization(
    const QString& ownerAddress,
    const QString& canonicalMessage,
    QString& publicKeyHexOut,
    QString& signatureHexOut,
    QString& errorOut) const {
    publicKeyHexOut.clear();
    signatureHexOut.clear();
    errorOut.clear();

    std::string pub;
    std::string sig;
    std::string error;
    if (!wallet_.signMessageSha256(
            ownerAddress.trimmed().toStdString(),
            canonicalMessage.toStdString(),
            pub,
            sig,
            &error)) {
        errorOut = QString::fromStdString(error);
        return false;
    }

    publicKeyHexOut = QString::fromStdString(pub);
    signatureHexOut = QString::fromStdString(sig);
    return true;
}

void DesktopWalletWidget::logLine(const QString& text) {
    activity_->appendPlainText(
        QDateTime::currentDateTime().toString("HH:mm:ss") +
        "  " + text);
}

void DesktopWalletWidget::updateUi() {
    const bool present =
        wallet_.exists(walletPath_.toStdString());

    const QString state = wallet_.isUnlocked()
        ? "UNLOCKED"
        : (present ? "LOCKED" : "NOT CREATED");
    state_->setText(state);
    state_->setProperty(
        "walletState",
        wallet_.isUnlocked()
            ? "unlocked"
            : (present ? "locked" : "missing"));
    state_->style()->unpolish(state_);
    state_->style()->polish(state_);

    if (wallet_.isUnlocked()) {
        const QString currentAddress =
            QString::fromStdString(wallet_.currentAddress());
        address_->setText(currentAddress);
        const QString did = deterministicTruDid(currentAddress);
        did_->setText(did);
        didStatus_->setText("CHECKING REGISTRY");
        refreshDidStatus(currentAddress, did);
        addressCount_->setText(
            QString("%1 generated address%2")
                .arg(wallet_.addressCount())
                .arg(wallet_.addressCount() == 1 ? "" : "es"));
        if (balance_->text().trimmed().isEmpty())
            balance_->setText("— TRU");
    } else {
        address_->setText("—");
        did_->setText("—");
        didStatus_->setText("—");
        addressCount_->setText("— generated addresses");
        balance_->setText("— TRU");
    }
}

void DesktopWalletWidget::refreshDidStatus(
    const QString& address,
    const QString& did) {
    if (!rpc_ || address.isEmpty() || did.isEmpty()) {
        didStatus_->setText("DERIVED");
        return;
    }

    QJsonObject params;
    params.insert("did", did);
    rpc_->call(
        "getDIDMapping", objectParams(params),
        [this, address, did](
            const QJsonValue& value,
            const QByteArray&,
            const QString& error) {
            if (!wallet_.isUnlocked()) return;
            const QString current =
                QString::fromStdString(wallet_.currentAddress());
            if (current != address || deterministicTruDid(current) != did)
                return;

            if (!error.isEmpty() || !value.isObject()) {
                didStatus_->setText("DERIVED");
                return;
            }

            const QJsonObject object = value.toObject();
            const bool found = object.value("found").toBool(false);
            const QString mapped = object.value("address").toString();
            if (found && mapped == address) {
                didStatus_->setText("REGISTERED");
            } else if (found && !mapped.isEmpty()) {
                didStatus_->setText("REGISTRY CONFLICT");
            } else {
                didStatus_->setText("DERIVED · NOT REGISTERED");
            }
        });
}

void DesktopWalletWidget::showQrCodes() {
    if (!wallet_.isUnlocked()) {
        QMessageBox::information(
            this, "Wallet QR Codes", "Unlock the wallet first.");
        return;
    }

    const QString address =
        QString::fromStdString(wallet_.currentAddress());
    const QString did = deterministicTruDid(address);

    QDialog dialog(this);
    dialog.setWindowTitle("TRU Wallet QR Codes");
    dialog.resize(470, 560);
    dialog.setStyleSheet(
        "QDialog{background:#050c1a;color:#e8f8ff;}"
        "QTabWidget::pane{border:1px solid #1e5d77;border-radius:8px;background:#071423;}"
        "QTabBar::tab{background:#0b2639;color:#8fb8cf;border:1px solid #1a516a;"
        "padding:9px 18px;}"
        "QTabBar::tab:selected{background:#10465a;color:#7ef2e6;border-color:#47dbe0;}"
        "QPushButton{background:#0b2c42;color:#e8fbff;border:1px solid #2b718d;"
        "border-radius:8px;padding:9px 15px;font-weight:700;}"
        "QPushButton:hover{background:#10445d;border-color:#4ce3e6;}");

    auto* root = new QVBoxLayout(&dialog);
    auto* title = new QLabel("TRU RECEIVE IDENTITY");
    title->setStyleSheet("color:#48f4e7;font-size:22px;font-weight:800;");
    root->addWidget(title);

    auto* note = new QLabel(
        "QR codes contain the exact raw TRU address or deterministic TRU DID. "
        "They do not expose private keys or recovery material.");
    note->setWordWrap(true);
    note->setStyleSheet("color:#88a9bd;padding-bottom:6px;");
    root->addWidget(note);

    auto* tabs = new QTabWidget;
    tabs->addTab(qrPage("TRU Address", address), "Address");
    tabs->addTab(qrPage("TRU DID", did), "DID");
    root->addWidget(tabs, 1);

    auto* close = new QPushButton("Close");
    connect(close, &QPushButton::clicked, &dialog, &QDialog::accept);
    root->addWidget(close, 0, Qt::AlignRight);
    dialog.exec();
}

QString DesktopWalletWidget::askPassphrase(
    const QString& title, bool confirm, bool* okOut) {
    bool ok = false;
    QString pass = QInputDialog::getText(
        this, title,
        "Wallet passphrase (minimum 12 characters):",
        QLineEdit::Password, {}, &ok);

    if (!ok || pass.size() < 12) {
        if (ok)
            QMessageBox::warning(
                this, title,
                "Passphrase must contain at least 12 characters.");
        *okOut = false;
        pass.fill(QChar(0));
        return {};
    }

    if (confirm) {
        bool secondOk = false;
        QString second = QInputDialog::getText(
            this, title, "Confirm wallet passphrase:",
            QLineEdit::Password, {}, &secondOk);

        if (!secondOk || second != pass) {
            QMessageBox::warning(
                this, title, "Passphrases do not match.");
            pass.fill(QChar(0));
            second.fill(QChar(0));
            *okOut = false;
            return {};
        }
        second.fill(QChar(0));
    }

    *okOut = true;
    return pass;
}

void DesktopWalletWidget::createWallet() {
    if (wallet_.exists(walletPath_.toStdString())) {
        QMessageBox::warning(
            this, "Create Wallet",
            "A standalone wallet already exists. "
            "Back it up before replacing it.");
        return;
    }

    bool ok = false;
    QString pass =
        askPassphrase("Create Standalone Wallet", true, &ok);
    if (!ok) return;

    std::string passStd = pass.toStdString();
    std::string error;
    const bool created =
        wallet_.create(
            walletPath_.toStdString(), passStd, &error);
    wipeStdString(passStd);
    pass.fill(QChar(0));

    if (!created) {
        QMessageBox::critical(
            this, "Create Wallet",
            QString::fromStdString(error));
        return;
    }

    logLine("Standalone encrypted wallet created.");
    updateUi();

    QMessageBox::information(
        this, "Wallet Created",
        "Wallet created and unlocked. Back it up and record the "
        "recovery secret before funding it.");
}

void DesktopWalletWidget::unlockWallet() {
    if (!wallet_.exists(walletPath_.toStdString())) {
        QMessageBox::warning(
            this, "Unlock Wallet", "No standalone wallet exists.");
        return;
    }

    bool ok = false;
    QString pass =
        askPassphrase("Unlock Standalone Wallet", false, &ok);
    if (!ok) return;

    std::string passStd = pass.toStdString();
    std::string error;
    const bool unlocked =
        wallet_.unlock(
            walletPath_.toStdString(), passStd, &error);
    wipeStdString(passStd);
    pass.fill(QChar(0));

    if (!unlocked) {
        QMessageBox::critical(
            this, "Unlock Wallet",
            QString::fromStdString(error));
        return;
    }

    logLine("Wallet unlocked locally.");
    updateUi();
}

void DesktopWalletWidget::lockWallet() {
    wallet_.lock();
    logLine("Wallet locked; in-memory seed cleared.");
    updateUi();
}

void DesktopWalletWidget::newAddress() {
    if (!wallet_.isUnlocked()) {
        QMessageBox::warning(
            this, "New Address", "Unlock the wallet first.");
        return;
    }

    bool ok = false;
    QString pass =
        askPassphrase("Generate Receive Address", false, &ok);
    if (!ok) return;

    std::string passStd = pass.toStdString();
    std::string addressOut;
    std::string error;
    const bool created =
        wallet_.createNextAddress(
            walletPath_.toStdString(),
            passStd, addressOut, &error);
    wipeStdString(passStd);
    pass.fill(QChar(0));

    if (!created) {
        QMessageBox::critical(
            this, "New Address",
            QString::fromStdString(error));
        return;
    }

    logLine(
        "Generated and encrypted a new deterministic receive address.");
    updateUi();
}

void DesktopWalletWidget::backupWallet() {
    if (!wallet_.exists(walletPath_.toStdString())) {
        QMessageBox::warning(
            this, "Backup Wallet", "No wallet exists.");
        return;
    }

    const QString destination =
        QFileDialog::getSaveFileName(
            this, "Save Encrypted Wallet Backup",
            QDir::home().filePath(
                "TRU-Desktop-Wallet-v1.backup"));
    if (destination.isEmpty()) return;

    std::string error;
    if (!wallet_.backup(
            walletPath_.toStdString(),
            destination.toStdString(), &error)) {
        QMessageBox::critical(
            this, "Backup Wallet",
            QString::fromStdString(error));
        return;
    }

    logLine("Encrypted wallet backup written.");
}

void DesktopWalletWidget::restoreBackup() {
    const QString source =
        QFileDialog::getOpenFileName(
            this, "Restore Encrypted Wallet Backup",
            QDir::homePath());
    if (source.isEmpty()) return;

    bool ok = false;
    QString pass =
        askPassphrase("Verify Backup Passphrase", false, &ok);
    if (!ok) return;

    if (wallet_.exists(walletPath_.toStdString())) {
        const auto choice = QMessageBox::warning(
            this, "Restore Backup",
            "This replaces the current standalone wallet file. "
            "Continue only if the current wallet is safely backed up.",
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (choice != QMessageBox::Yes) {
            pass.fill(QChar(0));
            return;
        }
    }

    std::string passStd = pass.toStdString();
    std::string error;
    const bool restored =
        wallet_.restoreBackup(
            source.toStdString(),
            walletPath_.toStdString(),
            passStd, &error);
    wipeStdString(passStd);
    pass.fill(QChar(0));

    if (!restored) {
        QMessageBox::critical(
            this, "Restore Backup",
            QString::fromStdString(error));
        return;
    }

    logLine("Encrypted backup restored and authenticated.");
    updateUi();
}

void DesktopWalletWidget::showRecovery() {
    if (!wallet_.isUnlocked()) {
        QMessageBox::warning(
            this, "Recovery Secret",
            "Unlock the wallet first.");
        return;
    }

    const auto choice = QMessageBox::warning(
        this, "Expose Recovery Secret",
        "The recovery secret is equivalent to the wallet seed. "
        "Anyone who sees it can control the wallet. Show it now?",
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (choice != QMessageBox::Yes) return;

    const QString secret =
        QString::fromStdString(wallet_.recoveryCode());

    QMessageBox box(
        QMessageBox::Warning,
        "TRU Desktop Recovery Secret",
        "Store this offline. Never send it to a node, website, "
        "chat, or support person.",
        QMessageBox::Ok, this);
    box.setDetailedText(secret);
    box.exec();

    logLine("Recovery secret was explicitly displayed.");
}

void DesktopWalletWidget::restoreRecovery() {
    bool ok = false;
    QString code = QInputDialog::getMultiLineText(
        this, "Restore Recovery Secret",
        "Paste TRU-DESKTOP-V1 recovery secret:",
        {}, &ok).trimmed();
    if (!ok || code.isEmpty()) return;

    bool passOk = false;
    QString pass =
        askPassphrase(
            "Encrypt Restored Wallet", true, &passOk);
    if (!passOk) {
        code.fill(QChar(0));
        return;
    }

    if (wallet_.exists(walletPath_.toStdString())) {
        const auto choice = QMessageBox::warning(
            this, "Restore Recovery Secret",
            "This replaces the current standalone wallet file. "
            "Continue only if the current wallet is safely backed up.",
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (choice != QMessageBox::Yes) {
            pass.fill(QChar(0));
            code.fill(QChar(0));
            return;
        }
    }

    std::string codeStd = code.toStdString();
    std::string passStd = pass.toStdString();
    std::string error;

    const bool restored =
        wallet_.restoreRecovery(
            codeStd,
            walletPath_.toStdString(),
            passStd, &error);

    wipeStdString(codeStd);
    wipeStdString(passStd);
    pass.fill(QChar(0));
    code.fill(QChar(0));

    if (!restored) {
        QMessageBox::critical(
            this, "Restore Recovery Secret",
            QString::fromStdString(error));
        return;
    }

    logLine("Recovery secret restored into a new encrypted wallet.");
    updateUi();
}

void DesktopWalletWidget::collectUtxos(
    std::function<void(
        std::vector<DesktopWalletUtxo>, QString)> done) {
    if (!wallet_.isUnlocked()) {
        done({}, "Unlock wallet first.");
        return;
    }
    if (!rpc_ || !rpc_->endpoint().isValid()) {
        done({}, "Connect to a TRU node first.");
        return;
    }

    auto addresses =
        std::make_shared<std::vector<std::string>>(
            wallet_.addresses());
    auto cursor = std::make_shared<std::size_t>(0);
    auto result =
        std::make_shared<std::vector<DesktopWalletUtxo>>();
    auto step =
        std::make_shared<std::function<void()>>();

    *step = [
        this, addresses, cursor, result, step, done
    ]() {
        if (*cursor >= addresses->size()) {
            done(*result, {});
            return;
        }

        const std::uint32_t keyIndex =
            static_cast<std::uint32_t>(*cursor);
        const QString addressText =
            QString::fromStdString((*addresses)[*cursor]);
        ++(*cursor);

        QJsonObject params;
        params.insert("address", addressText);

        // NET-01/BALANCE-02: use the live UTXO-set backed reader.
        // The older listunspent path reads legacy serialized UTXO records and
        // can return an empty set even while Core calculate_balance() sees the
        // confirmed output. listunspentWeb is read-only, exact-atom aware,
        // mempool-spend aware, and is also the reviewed public-gateway method.
        rpc_->call(
            "listunspentWeb", objectParams(params),
            [this, keyIndex, addressText, result, step, done](
                const QJsonValue& value,
                const QByteArray&,
                const QString& error) {
                if (!error.isEmpty()) {
                    done(
                        {},
                        "listunspentWeb failed for " +
                        addressText + ": " + error);
                    return;
                }

                QJsonArray array;
                if (value.isArray()) {
                    array = value.toArray();
                } else if (
                    value.isObject() &&
                    value.toObject().value("utxos").isArray()) {
                    array =
                        value.toObject().value("utxos").toArray();
                } else {
                    done(
                        {},
                        "listunspent returned an unexpected shape.");
                    return;
                }

                for (const QJsonValue& item : array) {
                    if (!item.isObject()) continue;
                    const QJsonObject o = item.toObject();

                    if (o.contains("spendable") &&
                        !o.value("spendable").toBool(true))
                        continue;
                    if (o.value("confirmations").toInt(0) < 1)
                        continue;

                    std::uint64_t atoms = 0;
                    if (!exactAtoms(o, atoms) || atoms == 0) {
                        done(
                            {},
                            "Node listunspentWeb omitted exact "
                            "amount_atoms; standalone wallet refuses "
                            "floating-point money.");
                        return;
                    }

                    const QString txid =
                        o.value("txid").toString();
                    const int vout =
                        o.value("vout").toInt(-1);
                    const QString script =
                        scriptHex(o.value("scriptPubKey"));

                    if (txid.size() != 64 ||
                        vout < 0 ||
                        script.isEmpty())
                        continue;

                    DesktopWalletUtxo u;
                    u.txid = txid.toStdString();
                    u.vout =
                        static_cast<std::uint32_t>(vout);
                    u.amountAtoms = atoms;
                    u.scriptPubKey = script.toStdString();
                    u.keyIndex = keyIndex;
                    result->push_back(std::move(u));

                    if (result->size() > 200) {
                        done(
                            {},
                            "More than 200 UTXOs returned; "
                            "refusing oversized automatic selection.");
                        return;
                    }
                }

                (*step)();
            });
    };

    (*step)();
}

void DesktopWalletWidget::safetyFilter(
    std::vector<DesktopWalletUtxo> all,
    std::function<void(
        std::vector<DesktopWalletUtxo>, QString)> done) {
    auto input =
        std::make_shared<std::vector<DesktopWalletUtxo>>(
            std::move(all));
    auto safe =
        std::make_shared<std::vector<DesktopWalletUtxo>>();
    auto cursor = std::make_shared<std::size_t>(0);
    auto step =
        std::make_shared<std::function<void()>>();

    *step = [
        this, input, safe, cursor, step, done
    ]() {
        if (*cursor >= input->size()) {
            done(*safe, {});
            return;
        }

        const DesktopWalletUtxo candidate =
            (*input)[(*cursor)++];

        QJsonObject lookup;
        lookup.insert(
            "txid", QString::fromStdString(candidate.txid));

        // gettransaction exposes immutable serialized bytes. We decode those
        // bytes with the node's decoder only to classify the referenced output.
        rpc_->call(
            "gettransaction", objectParams(lookup),
            [this, candidate, safe, step, done](
                const QJsonValue& txValue,
                const QByteArray&,
                const QString& txError) {
                if (!txError.isEmpty() ||
                    !txValue.isObject()) {
                    // Fail closed for this UTXO and continue.
                    (*step)();
                    return;
                }

                const QString rawHex =
                    txValue.toObject().value("hex").toString();
                if (rawHex.isEmpty()) {
                    (*step)();
                    return;
                }

                QJsonObject decode;
                decode.insert("txHex", rawHex);

                rpc_->call(
                    "decoderawtransaction",
                    objectParams(decode),
                    [this, candidate, safe, step, done](
                        const QJsonValue& decodedValue,
                        const QByteArray&,
                        const QString& decodeError) {
                        if (!decodeError.isEmpty() ||
                            !decodedValue.isObject()) {
                            (*step)();
                            return;
                        }

                        const QJsonArray outputs =
                            decodedValue.toObject()
                                .value("vout").toArray();

                        if (candidate.vout >=
                            static_cast<std::uint32_t>(
                                outputs.size())) {
                            (*step)();
                            return;
                        }

                        const QJsonObject target =
                            outputs
                                .at(static_cast<int>(
                                    candidate.vout))
                                .toObject();
                        const QString actualScript =
                            scriptHex(
                                target.value("scriptPubKey"));

                        QString expectedScript;
                        try {
                            expectedScript =
                                QString::fromStdString(
                                    wallet_.scriptForAddress(
                                        wallet_.address(
                                            candidate.keyIndex)));
                        } catch (...) {
                            done(
                                {},
                                "Wallet key/script verification failed.");
                            return;
                        }

                        if (actualScript != expectedScript) {
                            (*step)();
                            return;
                        }

                        auto isOpReturn =
                            [&outputs](int index) {
                                if (index < 0 ||
                                    index >= outputs.size())
                                    return false;
                                const QString script =
                                    scriptHex(
                                        outputs
                                            .at(index)
                                            .toObject()
                                            .value("scriptPubKey"));
                                return script.startsWith(
                                    "6a",
                                    Qt::CaseInsensitive);
                            };

                        // UI-07R2 SAFE-SPEND REPAIR:
                        //
                        // Token / TRUScript ownership can use a small P2PKH
                        // control output adjacent to an OP_RETURN/protocol
                        // marker. The prior Desktop heuristic rejected EVERY
                        // P2PKH output next to OP_RETURN, which also rejected
                        // ordinary wallet change from AI-evolution/data
                        // transactions.
                        //
                        // Preserve the protocol-control exclusion only for the
                        // established control values:
                        //   * extended-token control: 1 TRU atom
                        //   * TRUScript control/dust: 546 TRU atoms
                        //
                        // A normal-value P2PKH change output remains ordinary
                        // spendable TRU even when its transaction also carries
                        // an OP_RETURN anchor.
                        const bool adjacentOpReturn =
                            isOpReturn(
                                static_cast<int>(
                                    candidate.vout) - 1) ||
                            isOpReturn(
                                static_cast<int>(
                                    candidate.vout) + 1);

                        const bool reservedProtocolControl =
                            candidate.amountAtoms == 1ULL ||
                            candidate.amountAtoms == 546ULL;

                        if (adjacentOpReturn &&
                            reservedProtocolControl) {
                            (*step)();
                            return;
                        }

                        safe->push_back(candidate);
                        (*step)();
                    });
            });
    };

    (*step)();
}

void DesktopWalletWidget::refreshBalance() {
    if (!wallet_.isUnlocked()) {
        QMessageBox::warning(
            this, "Refresh Balance",
            "Unlock wallet first.");
        return;
    }

    logLine("Reading and safety-checking wallet UTXOs…");

    collectUtxos(
        [this](
            std::vector<DesktopWalletUtxo> all,
            QString error) {
            if (!error.isEmpty()) {
                logLine(error);
                return;
            }

            safetyFilter(
                std::move(all),
                [this](
                    std::vector<DesktopWalletUtxo> safe,
                    QString error2) {
                    if (!error2.isEmpty()) {
                        logLine(error2);
                        return;
                    }

                    std::uint64_t total = 0;
                    for (const auto& u : safe) {
                        if (total >
                            std::numeric_limits<
                                std::uint64_t>::max() -
                            u.amountAtoms) {
                            logLine(
                                "Balance overflow guard triggered.");
                            return;
                        }
                        total += u.amountAtoms;
                    }

                    balance_->setText(
                        QString::fromStdString(
                            DesktopWalletCore::formatAmount(
                                total)) +
                        " TRU");
                    logLine(
                        QString("Safe spendable UTXOs: %1")
                            .arg(safe.size()));
                });
        });
}

void DesktopWalletWidget::sendTru() {
    if (!wallet_.isUnlocked()) {
        QMessageBox::warning(
            this, "Send TRU", "Unlock wallet first.");
        return;
    }

    bool ok = false;
    QString recipient = QInputDialog::getText(
        this, "Send TRU",
        "Recipient TRU address:",
        QLineEdit::Normal, {}, &ok);
    if (!ok) return;

    if (!wallet_.validateAddress(
            recipient.toStdString())) {
        QMessageBox::critical(
            this, "Send TRU",
            "Invalid TRU mainnet address.");
        return;
    }

    QString amountText = QInputDialog::getText(
        this, "Send TRU",
        "Amount (TRU):",
        QLineEdit::Normal, {}, &ok);
    if (!ok) return;

    std::uint64_t amount = 0;
    std::string parseError;
    if (!DesktopWalletCore::parseAmount(
            amountText.toStdString(),
            amount, &parseError) ||
        amount == 0) {
        QMessageBox::critical(
            this, "Send TRU",
            QString::fromStdString(parseError));
        return;
    }

    QString feeText = QInputDialog::getText(
        this, "Send TRU",
        "Fee (TRU, minimum 0.00010000):",
        QLineEdit::Normal,
        "0.00010000", &ok);
    if (!ok) return;

    std::uint64_t fee = 0;
    if (!DesktopWalletCore::parseAmount(
            feeText.toStdString(),
            fee, &parseError)) {
        QMessageBox::critical(
            this, "Send TRU",
            QString::fromStdString(parseError));
        return;
    }

    logLine(
        "Collecting and safety-checking ordinary P2PKH UTXOs…");

    collectUtxos(
        [this, recipient, amount, fee](
            std::vector<DesktopWalletUtxo> all,
            QString error) {
            if (!error.isEmpty()) {
                QMessageBox::critical(
                    this, "Send TRU", error);
                return;
            }

            safetyFilter(
                std::move(all),
                [this, recipient, amount, fee](
                    std::vector<DesktopWalletUtxo> safe,
                    QString error2) {
                    if (!error2.isEmpty()) {
                        QMessageBox::critical(
                            this, "Send TRU", error2);
                        return;
                    }

                    std::sort(
                        safe.begin(), safe.end(),
                        [](const DesktopWalletUtxo& a,
                           const DesktopWalletUtxo& b) {
                            return a.amountAtoms >
                                   b.amountAtoms;
                        });

                    if (amount >
                        std::numeric_limits<
                            std::uint64_t>::max() - fee) {
                        QMessageBox::critical(
                            this, "Send TRU",
                            "Amount + fee overflow.");
                        return;
                    }

                    const std::uint64_t needed =
                        amount + fee;
                    std::uint64_t total = 0;
                    std::vector<DesktopWalletUtxo>
                        selected;

                    for (const auto& u : safe) {
                        if (total >
                            std::numeric_limits<
                                std::uint64_t>::max() -
                            u.amountAtoms) {
                            QMessageBox::critical(
                                this, "Send TRU",
                                "UTXO sum overflow.");
                            return;
                        }

                        selected.push_back(u);
                        total += u.amountAtoms;
                        if (total >= needed) break;
                    }

                    if (total < needed) {
                        QMessageBox::critical(
                            this, "Send TRU",
                            "Insufficient safe spendable balance.");
                        return;
                    }

                    DesktopWalletSignedTx tx;
                    try {
                        tx = wallet_.buildAndSign(
                            selected,
                            recipient.toStdString(),
                            amount, fee);
                    } catch (const std::exception& e) {
                        QMessageBox::critical(
                            this, "Send TRU",
                            QString(
                                "Local construction/signing failed: %1")
                                .arg(e.what()));
                        return;
                    }

                    const QString summary =
                        QString(
                            "Recipient: %1\n"
                            "Amount: %2 TRU\n"
                            "Fee: %3 TRU\n"
                            "Change: %4 TRU\n"
                            "Inputs: %5\n"
                            "Local TRU txid: %6\n\n"
                            "Broadcast this fully signed transaction?")
                            .arg(recipient)
                            .arg(QString::fromStdString(
                                DesktopWalletCore::formatAmount(
                                    tx.sendAtoms)))
                            .arg(QString::fromStdString(
                                DesktopWalletCore::formatAmount(
                                    tx.feeAtoms)))
                            .arg(QString::fromStdString(
                                DesktopWalletCore::formatAmount(
                                    tx.changeAtoms)))
                            .arg(selected.size())
                            .arg(QString::fromStdString(tx.txid));

                    if (QMessageBox::question(
                            this,
                            "Confirm Signed Transaction",
                            summary,
                            QMessageBox::Yes |
                                QMessageBox::No,
                            QMessageBox::No)
                        != QMessageBox::Yes) {
                        return;
                    }

                    // CRITICAL boundary: only signed transaction bytes
                    // cross DesktopRpc. No private key/seed/passphrase.
                    QJsonObject params;
                    params.insert(
                        "txHex",
                        QString::fromStdString(tx.rawHex));

                    rpc_->call(
                        "sendrawtransaction",
                        objectParams(params),
                        [this, tx](
                            const QJsonValue& value,
                            const QByteArray&,
                            const QString& error3) {
                            if (!error3.isEmpty()) {
                                QMessageBox::critical(
                                    this,
                                    "Broadcast Rejected",
                                    error3);
                                logLine(
                                    "Node rejected the signed "
                                    "transaction.");
                                return;
                            }

                            QString returned;
                            if (value.isString())
                                returned = value.toString();
                            else if (value.isObject())
                                returned =
                                    value.toObject()
                                        .value("txid")
                                        .toString();

                            logLine(
                                "Signed transaction accepted by "
                                "RPC: " +
                                (returned.isEmpty()
                                     ? QString::fromStdString(
                                           tx.txid)
                                     : returned));
                            refreshBalance();
                        });
                });
        });
}
