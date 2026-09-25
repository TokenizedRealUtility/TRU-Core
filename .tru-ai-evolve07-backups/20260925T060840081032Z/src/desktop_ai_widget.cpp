#include "desktop_ai_widget.h"
#include "token_media_file.h"

#include "desktop_rpc.h"
#include "desktop_wallet_widget.h"
#include "wallet_encryption_v1.h"

#include <QBuffer>
#include <QButtonGroup>
#include <QComboBox>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QFormLayout>
#include <QGroupBox>
#include <QInputDialog>
#include <QLineEdit>
#include <QMessageBox>
#include <QRadioButton>
#include <QSaveFile>
#include <QSettings>
#include <QStandardPaths>
#include <QStyle>
#include <QDialog>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QImage>
#include <QImageReader>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QList>
#include <QMovie>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPlainTextEdit>
#include <QPixmap>
#include <QPushButton>
#include <QRegularExpression>
#include <QScrollArea>
#include <QTabWidget>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>

#include <sodium.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <vector>

namespace {

QByteArray objectParams(const QJsonObject& object) {
    return QJsonDocument(object).toJson(QJsonDocument::Compact);
}

QString metadataText(
    const QJsonObject& meta,
    const QString& key,
    const QString& fallback = {}) {
    const QJsonValue value = meta.value(key);
    if (value.isString()) return value.toString().trimmed();
    if (value.isDouble()) return QString::number(value.toDouble(), 'g', 15);
    if (value.isBool()) return value.toBool() ? "true" : "false";
    return fallback;
}

QString shortText(const QString& value, int maxChars) {
    const QString text = value.simplified();
    if (text.size() <= maxChars) return text;
    return text.left(std::max(0, maxChars - 1)) + QChar(0x2026);
}

QString safeArtworkUrl(QString raw) {
    raw = raw.trimmed();
    if (raw.isEmpty()) return {};

    static const QRegularExpression markdownLink(
        QStringLiteral("^\\[[^\\]]*\\]\\(([^)]+)\\)$"));
    const auto markdownMatch = markdownLink.match(raw);
    if (markdownMatch.hasMatch())
        raw = markdownMatch.captured(1).trimmed();

    if (raw.startsWith("ipfs://", Qt::CaseInsensitive)) {
        QString path = raw.mid(7);
        while (path.startsWith('/')) path.remove(0, 1);
        static const QRegularExpression allowed(
            QStringLiteral("^[A-Za-z0-9._~/%\\-]+$"));
        if (path.isEmpty() || !allowed.match(path).hasMatch()) return {};
        return "https://ipfs.io/ipfs/" + path;
    }

    const QUrl url(raw);
    const QString scheme = url.scheme().toLower();
    if (!url.isValid() || url.host().isEmpty() ||
        (scheme != "https" && scheme != "http") ||
        !url.userInfo().isEmpty()) {
        return {};
    }
    return url.toString(QUrl::FullyEncoded);
}

QString tokenArtwork(const QJsonObject& meta) {
    QString artwork = metadataText(meta, "image");
    if (artwork.isEmpty()) artwork = metadataText(meta, "image_url");
    if (artwork.isEmpty()) artwork = metadataText(meta, "imageUrl");
    if (artwork.isEmpty()) {
        QString ipfs = metadataText(meta, "ipfs_image");
        if (!ipfs.isEmpty() && !ipfs.contains("://"))
            ipfs.prepend("ipfs://");
        artwork = ipfs;
    }
    return artwork;
}

QString tokenAccent(const QJsonObject& meta) {
    QString accent = metadataText(meta, "dynamic_visual");
    if (accent.isEmpty()) accent = metadataText(meta, "colour");
    static const QRegularExpression color(
        QStringLiteral("^#[0-9A-Fa-f]{6}$"));
    if (!color.match(accent).hasMatch())
        accent = "#35f0ff";
    return accent;
}

bool isAiToken(const QJsonObject& token) {
    QJsonObject meta = token.value("meta").toObject();
    if (meta.isEmpty() && token.value("metadata").isObject())
        meta = token.value("metadata").toObject();

    if (meta.value("ai_enabled").toBool(false)) return true;

    for (const char* key : {
            "ai_engine", "ai_provider", "creator_signature",
            "dynamic_morph", "last_evolution", "update_interval",
            "style_descriptor"}) {
        if (!metadataText(meta, QString::fromLatin1(key)).isEmpty())
            return true;
    }
    return false;
}

QScrollArea* makeGridScroll(QWidget*& host, QGridLayout*& grid) {
    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);

    host = new QWidget;
    grid = new QGridLayout(host);
    grid->setContentsMargins(8, 8, 8, 8);
    grid->setHorizontalSpacing(14);
    grid->setVerticalSpacing(14);
    grid->setAlignment(Qt::AlignTop | Qt::AlignLeft);
    scroll->setWidget(host);
    return scroll;
}

QLabel* badge(const QString& text) {
    auto* label = new QLabel(text);
    label->setStyleSheet(
        "background:#0b3141;color:#75f2e5;border:1px solid #2b7287;"
        "border-radius:9px;padding:4px 8px;font-size:10px;font-weight:800;");
    return label;
}

QString jsonScalar(const QJsonValue& value) {
    if (value.isString()) return value.toString();
    if (value.isBool()) return value.toBool() ? "true" : "false";
    if (value.isDouble()) return QString::number(value.toDouble(), 'g', 15);
    if (value.isNull() || value.isUndefined()) return "—";
    if (value.isArray()) return QString("%1 items").arg(value.toArray().size());
    if (value.isObject()) return QString("%1 fields").arg(value.toObject().size());
    return "—";
}

struct AiDetailRow {
    QString label;
    QString value;
    bool mono = false;
};

void showAiDetailDialog(
    QWidget* parent,
    const QString& title,
    const QString& subtitle,
    const QString& accent,
    const QList<AiDetailRow>& rows,
    const QJsonObject& raw) {

    QDialog dialog(parent);
    dialog.setModal(true);
    dialog.setWindowTitle(title);
    dialog.resize(760, 720);
    dialog.setMinimumSize(560, 480);

    QString sheet = R"AIQSS(
        QDialog { background:#050c1a; color:#dcecf6; }
        QScrollArea { background:transparent; border:none; }
        QWidget#aiDetailViewport { background:transparent; }
        QFrame#aiDetailShell {
            background:qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #17193a, stop:1 #11172b);
            border:1px solid __ACCENT__; border-radius:18px;
        }
        QLabel#aiDetailTitle { color:__ACCENT__; font-size:26px; font-weight:800; }
        QLabel#aiDetailSubtitle { color:#a8bdd1; font-size:13px; }
        QLabel#aiDetailKey { color:#7d97ab; font-size:11px; font-weight:800; letter-spacing:1px; }
        QLabel#aiDetailValue {
            background:#20213f; color:#eef6ff; border:1px solid #315067;
            border-radius:9px; padding:10px 12px; font-size:14px;
        }
        QPlainTextEdit#aiRawJson {
            background:#081426; color:#d8eef8; border:1px solid #29536f;
            border-radius:10px; padding:10px;
            font-family:'DejaVu Sans Mono','Menlo','Consolas'; font-size:12px;
        }
        QPushButton {
            background:#102b43; color:#e4f8ff; border:1px solid #2a7591;
            border-radius:9px; padding:9px 15px; font-weight:700;
        }
        QPushButton:hover { border-color:__ACCENT__; background:#173c57; }
        QPushButton:checked { border-color:__ACCENT__; background:#252052; }
    )AIQSS";
    if (QSettings("TRUBlockchain", "CoreDesktop")
            .value("theme", "dark").toString().trimmed().toLower() == "light") {
        sheet += R"AILIGHTDETAIL(
            QDialog { background:#f4f7fb; color:#183443; }
            QFrame#aiDetailShell { background:#ffffff; }
            QLabel#aiDetailSubtitle { color:#617b8e; }
            QLabel#aiDetailKey { color:#567184; }
            QLabel#aiDetailValue {
                background:#f7f9fc; color:#193448; border-color:#a8becb;
            }
            QPlainTextEdit#aiRawJson {
                background:#ffffff; color:#183443; border-color:#9eb8c7;
            }
            QPushButton {
                background:#e6f0f5; color:#183c50; border-color:#8dabbc;
            }
            QPushButton:hover { background:#d8ecef; }
            QPushButton:checked { background:#e8e1f3; }
        )AILIGHTDETAIL";
    }
    sheet.replace("__ACCENT__", accent);
    dialog.setStyleSheet(sheet);

    auto* root = new QVBoxLayout(&dialog);
    root->setContentsMargins(12, 12, 12, 12);

    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

    auto* viewport = new QWidget;
    viewport->setObjectName("aiDetailViewport");
    auto* viewportLayout = new QVBoxLayout(viewport);
    viewportLayout->setContentsMargins(6, 6, 6, 6);

    auto* shell = new QFrame;
    shell->setObjectName("aiDetailShell");
    auto* shellLayout = new QVBoxLayout(shell);
    shellLayout->setContentsMargins(24, 22, 24, 22);
    shellLayout->setSpacing(14);

    auto* heading = new QLabel(title);
    heading->setObjectName("aiDetailTitle");
    heading->setWordWrap(true);
    shellLayout->addWidget(heading);

    auto* sub = new QLabel(subtitle);
    sub->setObjectName("aiDetailSubtitle");
    sub->setWordWrap(true);
    shellLayout->addWidget(sub);

    auto* grid = new QGridLayout;
    grid->setHorizontalSpacing(16);
    grid->setVerticalSpacing(12);
    grid->setColumnStretch(1, 1);
    int row = 0;
    for (const auto& item : rows) {
        if (item.value.trimmed().isEmpty()) continue;
        auto* key = new QLabel(item.label.toUpper());
        key->setObjectName("aiDetailKey");
        key->setAlignment(Qt::AlignTop | Qt::AlignLeft);
        auto* value = new QLabel(item.value);
        value->setObjectName("aiDetailValue");
        value->setWordWrap(true);
        value->setTextFormat(Qt::PlainText);
        value->setTextInteractionFlags(Qt::TextSelectableByMouse);
        if (item.mono) {
            value->setStyleSheet(
                "font-family:'DejaVu Sans Mono','Menlo','Consolas';");
        }
        grid->addWidget(key, row, 0, Qt::AlignTop);
        grid->addWidget(value, row, 1);
        ++row;
    }
    shellLayout->addLayout(grid);

    auto* rawLabel = new QLabel("RAW JSON");
    rawLabel->setObjectName("aiDetailKey");
    rawLabel->hide();
    shellLayout->addWidget(rawLabel);

    auto* rawJson = new QPlainTextEdit;
    rawJson->setObjectName("aiRawJson");
    rawJson->setReadOnly(true);
    rawJson->setMinimumHeight(220);
    rawJson->setPlainText(QString::fromUtf8(
        QJsonDocument(raw).toJson(QJsonDocument::Indented)));
    rawJson->hide();
    shellLayout->addWidget(rawJson);

    auto* actions = new QHBoxLayout;
    actions->addStretch();
    auto* json = new QPushButton("View JSON");
    json->setCheckable(true);
    auto* close = new QPushButton("Close");
    actions->addWidget(json);
    actions->addWidget(close);
    shellLayout->addLayout(actions);

    viewportLayout->addWidget(shell);
    viewportLayout->addStretch();
    scroll->setWidget(viewport);
    root->addWidget(scroll, 1);

    QObject::connect(json, &QPushButton::toggled, &dialog,
                     [json, rawLabel, rawJson](bool on) {
        json->setText(on ? "Hide JSON" : "View JSON");
        rawLabel->setVisible(on);
        rawJson->setVisible(on);
    });
    QObject::connect(close, &QPushButton::clicked,
                     &dialog, &QDialog::accept);

    dialog.exec();
}

} // namespace

void DesktopAIWidget::applyTheme(const QString& theme) {
    QString sheet = R"AIROOT(
        QFrame#aiHero {
            background:qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #071d31, stop:0.55 #10213b, stop:1 #1d163d);
            border:1px solid #2a758d; border-radius:14px;
        }
        QLabel#aiEyebrow { color:#5ed7ef; font-size:10px; font-weight:800; letter-spacing:1.2px; }
        QLabel#aiTitle { color:#eafcff; font-size:23px; font-weight:800; }
        QLabel#aiSubtitle { color:#8fb3c7; }
        QLabel#aiStatus { color:#8fb1c2; padding:3px 5px; }
        QFrame#aiCard {
            background:qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #08192a, stop:1 #121936);
            border:1px solid #245a75; border-radius:13px;
        }
        QLabel#aiCardTitle { color:#f0fbff; font-size:16px; font-weight:800; }
        QLabel#aiCardMeta { color:#7e9fb4; font-size:11px; }
        QLabel#aiEngine { color:#8af4df; font-size:13px; font-weight:800; }
        QLabel#aiImage {
            background:#03101b; color:#4d809a; border:1px solid #1c506a;
            border-radius:9px; font-weight:800;
        }
        QLabel#aiEmpty {
            background:#061522; color:#64879a; border:1px dashed #1d455b;
            border-radius:10px; padding:38px; min-height:70px;
        }
        QScrollArea { background:transparent; border:none; }
    )AIROOT";
    if (theme.trimmed().toLower() == "light") {
        sheet += R"AILIGHT(
            QFrame#aiHero { background:#ffffff; border-color:#7faebc; }
            QLabel#aiEyebrow { color:#08758a; }
            QLabel#aiTitle { color:#173548; }
            QLabel#aiSubtitle, QLabel#aiStatus { color:#607b8d; }
            QFrame#aiCard { background:#ffffff; border-color:#98bac9; }
            QLabel#aiCardTitle { color:#173548; }
            QLabel#aiCardMeta { color:#607b8d; }
            QLabel#aiEngine { color:#08766d; }
            QLabel#aiImage {
                background:#edf4f7; color:#517487; border-color:#9ab8c6;
            }
            QLabel#aiEmpty {
                background:#f3f7f9; color:#6d8795; border-color:#a9c0cb;
            }
            QLabel#aiCoreIndicator {
                background:#edf6f8; color:#29656a;
                border:1px solid #8cb6bd; border-radius:11px;
                padding:7px 11px; font-weight:800;
            }
            QLabel#aiCoreIndicator[live="true"] {
                background:#e4f7ec; color:#17653b; border-color:#69b98c;
            }
            QLabel#aiCoreIndicator[failed="true"] {
                background:#fff0ef; color:#9a413c; border-color:#dc9b95;
            }
            QPushButton#aiEvolveAction {
                background:#168d89; color:#ffffff;
                border:1px solid #08716d; font-weight:800;
            }
        )AILIGHT";
    } else {
        sheet += R"AIDARKEXTRA(
            QLabel#aiCoreIndicator {
                background:#092238; color:#78d8e3;
                border:1px solid #246680; border-radius:11px;
                padding:7px 11px; font-weight:800;
            }
            QLabel#aiCoreIndicator[live="true"] {
                background:#0a2c22; color:#72efaa; border-color:#3ebf7b;
            }
            QLabel#aiCoreIndicator[failed="true"] {
                background:#32191d; color:#ff9d9d; border-color:#a74e56;
            }
            QPushButton#aiEvolveAction {
                background:#116a73; border:1px solid #38d9d2;
                color:#f3ffff; font-weight:800;
            }
        )AIDARKEXTRA";
    }
    setProperty(
        "truTheme",
        theme.trimmed().toLower() == "light" ? "light" : "dark");
    setStyleSheet(sheet);
    if (coreAiIndicator_) {
        coreAiIndicator_->style()->unpolish(coreAiIndicator_);
        coreAiIndicator_->style()->polish(coreAiIndicator_);
    }
}

DesktopAIWidget::DesktopAIWidget(
    DesktopRpc* rpc,
    DesktopWalletWidget* wallet,
    QWidget* parent)
    : QWidget(parent),
      rpc_(rpc),
      wallet_(wallet),
      imageNetwork_(new QNetworkAccessManager(this)),
      directNetwork_(new QNetworkAccessManager(this)) {

    applyTheme(
        QSettings("TRUBlockchain", "CoreDesktop")
            .value("theme", "dark").toString());

    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(14, 14, 14, 14);
    root->setSpacing(12);

    auto* hero = new QFrame;
    hero->setObjectName("aiHero");
    auto* heroRow = new QHBoxLayout(hero);
    heroRow->setContentsMargins(18, 15, 18, 15);

    auto* titleStack = new QVBoxLayout;
    auto* eyebrow = new QLabel("TRU AI / LIVING TOKEN CONTROL PLANE");
    eyebrow->setObjectName("aiEyebrow");
    auto* title = new QLabel("AI Assets & Provenance");
    title->setObjectName("aiTitle");
    auto* subtitle = new QLabel(
        "Read-only view of AI-marked wallet assets, configured AI providers, "
        "runtime state and on-chain evolution provenance.");
    subtitle->setObjectName("aiSubtitle");
    subtitle->setWordWrap(true);
    titleStack->addWidget(eyebrow);
    titleStack->addWidget(title);
    titleStack->addWidget(subtitle);
    heroRow->addLayout(titleStack, 1);

    coreAiIndicator_ = new QLabel("○ CORE AI NOT TESTED");
    coreAiIndicator_->setObjectName("aiCoreIndicator");
    coreAiIndicator_->setToolTip(
        "CONFIGURED means the Core has provider configuration. "
        "REACHABLE appears only after an explicit live provider test.");
    heroRow->addWidget(coreAiIndicator_, 0, Qt::AlignVCenter);

    refresh_ = new QPushButton("Refresh AI");
    refresh_->setObjectName("truPrimaryAction");
    heroRow->addWidget(refresh_, 0, Qt::AlignVCenter);
    root->addWidget(hero);

    status_ = new QLabel(
        "Unlock the standalone wallet, then refresh to discover its AI-marked assets.");
    status_->setObjectName("aiStatus");
    status_->setWordWrap(true);
    root->addWidget(status_);

    auto* tabs = new QTabWidget;

    QWidget* aiHost = nullptr;
    auto* aiPage = new QWidget;
    auto* aiPageLayout = new QVBoxLayout(aiPage);
    auto* aiHeader = new QHBoxLayout;
    auto* aiHeading = new QLabel("AI ASSETS");
    aiHeading->setObjectName("truAssetSectionTitle");
    aiCount_ = badge("0 AI assets");
    aiHeader->addWidget(aiHeading);
    aiHeader->addStretch();
    aiHeader->addWidget(aiCount_);
    aiPageLayout->addLayout(aiHeader);
    aiPageLayout->addWidget(makeGridScroll(aiHost, aiGrid_), 1);
    tabs->addTab(aiPage, "AI Assets");

    QWidget* providerHost = nullptr;
    auto* providerPage = new QWidget;
    auto* providerLayout = new QVBoxLayout(providerPage);
    auto* providerHeader = new QHBoxLayout;
    auto* providerHeading = new QLabel("CONNECTED AI / PROVIDERS");
    providerHeading->setObjectName("truAssetSectionTitle");
    providerCount_ = badge("0 providers");
    providerHeader->addWidget(providerHeading);
    providerHeader->addStretch();
    providerHeader->addWidget(providerCount_);
    providerLayout->addLayout(providerHeader);
    auto* providerNote = new QLabel(
        "Core reports provider availability/configuration and endpoint data. "
        "CONFIGURED does not claim a live external health check.");
    providerNote->setObjectName("aiStatus");
    providerNote->setWordWrap(true);
    providerLayout->addWidget(providerNote);
    providerLayout->addWidget(makeGridScroll(providerHost, providerGrid_), 1);
    tabs->addTab(providerPage, "Connected AI");

    auto* provenancePage = new QWidget;
    auto* provenanceOuter = new QVBoxLayout(provenancePage);
    auto* provenanceHeading = new QLabel("PROVENANCE / EVOLUTION");
    provenanceHeading->setObjectName("truAssetSectionTitle");
    provenanceOuter->addWidget(provenanceHeading);
    auto* provenanceNote = new QLabel(
        "Verify AI-token evolution against confirmed issuance and anchor transactions. "
        "A failed or absent evolution record is shown separately from ownership.");
    provenanceNote->setObjectName("aiStatus");
    provenanceNote->setWordWrap(true);
    provenanceOuter->addWidget(provenanceNote);

    auto* provenanceScroll = new QScrollArea;
    provenanceScroll->setWidgetResizable(true);
    provenanceScroll->setFrameShape(QFrame::NoFrame);
    auto* provenanceHost = new QWidget;
    provenanceList_ = new QVBoxLayout(provenanceHost);
    provenanceList_->setContentsMargins(8, 8, 8, 8);
    provenanceList_->setSpacing(12);
    provenanceList_->setAlignment(Qt::AlignTop);
    provenanceScroll->setWidget(provenanceHost);
    provenanceOuter->addWidget(provenanceScroll, 1);
    tabs->addTab(provenancePage, "Provenance / Evolution");

    auto* settingsPage = new QWidget;
    auto* settingsOuter = new QVBoxLayout(settingsPage);
    settingsOuter->setContentsMargins(10, 10, 10, 10);
    settingsOuter->setSpacing(12);

    auto* settingsHeading = new QLabel("AI PROVIDER SETTINGS");
    settingsHeading->setObjectName("truAssetSectionTitle");
    settingsOuter->addWidget(settingsHeading);

    auto* settingsIntro = new QLabel(
        "Choose where AI inference runs. Core AI uses the connected TRU Core's provider configuration. "
        "My AI talks directly from this Desktop to a provider you control. Local AI connects to an instance "
        "running on this Windows, macOS or Linux computer. Private API keys are never sent to TRU Core.");
    settingsIntro->setObjectName("aiStatus");
    settingsIntro->setWordWrap(true);
    settingsOuter->addWidget(settingsIntro);

    auto* modes = new QButtonGroup(this);
    coreMode_ = new QRadioButton("Use Connected Core AI");
    cloudMode_ = new QRadioButton("Use My AI / Cloud Provider");
    localMode_ = new QRadioButton("Use Local AI on This Computer");
    modes->addButton(coreMode_);
    modes->addButton(cloudMode_);
    modes->addButton(localMode_);

    auto* modeRow = new QHBoxLayout;
    modeRow->addWidget(coreMode_);
    modeRow->addWidget(cloudMode_);
    modeRow->addWidget(localMode_);
    modeRow->addStretch();
    settingsOuter->addLayout(modeRow);

    coreSettingsFrame_ = new QFrame;
    coreSettingsFrame_->setObjectName("aiCard");
    auto* coreForm = new QFormLayout(coreSettingsFrame_);
    coreForm->setContentsMargins(16, 14, 16, 14);
    coreProvider_ = new QComboBox;
    coreForm->addRow("Core provider", coreProvider_);
    auto* coreNote = new QLabel(
        "The selected provider is owned and configured by the connected Core. Core-side Test Connection "
        "uses that Core's stored/environment credentials; this Desktop never receives them. "
        "The test sends a minimal inference request and may incur the provider's normal API cost.");
    coreNote->setObjectName("aiCardMeta");
    coreNote->setWordWrap(true);
    coreForm->addRow(coreNote);
    auto* coreTest = new QPushButton("Test Core Provider");
    coreForm->addRow(coreTest);
    settingsOuter->addWidget(coreSettingsFrame_);

    cloudSettingsFrame_ = new QFrame;
    cloudSettingsFrame_->setObjectName("aiCard");
    auto* cloudForm = new QFormLayout(cloudSettingsFrame_);
    cloudForm->setContentsMargins(16, 14, 16, 14);
    cloudProvider_ = new QComboBox;
    cloudProvider_->addItems({"OpenAI", "Anthropic", "Gemini", "Grok", "Custom OpenAI-compatible"});
    cloudEndpoint_ = new QLineEdit;
    cloudModel_ = new QLineEdit;
    cloudApiKey_ = new QLineEdit;
    cloudApiKey_->setEchoMode(QLineEdit::Password);
    cloudApiKey_->setPlaceholderText("API key stays on this computer");
    cloudForm->addRow("Provider", cloudProvider_);
    cloudForm->addRow("Endpoint", cloudEndpoint_);
    cloudForm->addRow("Model", cloudModel_);
    cloudForm->addRow("API key", cloudApiKey_);
    auto* cloudActions = new QHBoxLayout;
    auto* cloudTest = new QPushButton("Test Direct AI");
    auto* saveSettings = new QPushButton("Save Non-secret Settings");
    auto* saveVault = new QPushButton("Save Key Encrypted");
    auto* loadVault = new QPushButton("Load Encrypted Key");
    auto* forgetVault = new QPushButton("Forget Encrypted Key");
    cloudActions->addWidget(cloudTest);
    cloudActions->addWidget(saveSettings);
    cloudActions->addWidget(saveVault);
    cloudActions->addWidget(loadVault);
    cloudActions->addWidget(forgetVault);
    cloudForm->addRow(cloudActions);
    auto* cloudNote = new QLabel(
        "Non-secret settings use the Desktop preferences file. API keys are session-only unless you explicitly "
        "save them into the authenticated TRU AI credential vault. The vault uses Argon2id + XChaCha20-Poly1305 "
        "and a separate passphrase that is never stored.");
    cloudNote->setObjectName("aiCardMeta");
    cloudNote->setWordWrap(true);
    cloudForm->addRow(cloudNote);
    settingsOuter->addWidget(cloudSettingsFrame_);

    localSettingsFrame_ = new QFrame;
    localSettingsFrame_->setObjectName("aiCard");
    auto* localForm = new QFormLayout(localSettingsFrame_);
    localForm->setContentsMargins(16, 14, 16, 14);
    localFlavor_ = new QComboBox;
    localFlavor_->addItems({"OpenAI-compatible / Nemotron", "Ollama"});
    localEndpoint_ = new QLineEdit;
    localModel_ = new QLineEdit;
    localApiKey_ = new QLineEdit;
    localApiKey_->setEchoMode(QLineEdit::Password);
    localApiKey_->setPlaceholderText("Optional for local/private endpoints");
    localForm->addRow("Local engine", localFlavor_);
    localForm->addRow("Endpoint", localEndpoint_);
    localForm->addRow("Model", localModel_);
    localForm->addRow("API key", localApiKey_);
    auto* localActions = new QHBoxLayout;
    auto* localTest = new QPushButton("Test Local AI");
    auto* localSave = new QPushButton("Save Non-secret Settings");
    localActions->addWidget(localTest);
    localActions->addWidget(localSave);
    localForm->addRow(localActions);
    auto* localNote = new QLabel(
        "127.0.0.1 here means the computer running TRU Desktop. Use this mode for a model running locally on "
        "Windows, macOS or Linux. A LAN endpoint may also be used if you intentionally expose one.");
    localNote->setObjectName("aiCardMeta");
    localNote->setWordWrap(true);
    localForm->addRow(localNote);
    settingsOuter->addWidget(localSettingsFrame_);

    settingsStatus_ = new QLabel("AI settings are local to this Desktop unless Core AI mode is selected.");
    settingsStatus_->setObjectName("aiStatus");
    settingsStatus_->setWordWrap(true);
    settingsOuter->addWidget(settingsStatus_);
    settingsOuter->addStretch();

    auto* settingsScroll = new QScrollArea;
    settingsScroll->setWidgetResizable(true);
    settingsScroll->setFrameShape(QFrame::NoFrame);
    settingsScroll->setWidget(settingsPage);
    tabs->addTab(settingsScroll, "Settings");

    root->addWidget(tabs, 1);

    connect(refresh_, &QPushButton::clicked,
            this, [this] { refreshAll(); });

    connect(coreMode_, &QRadioButton::toggled, this, [this](bool) { updateSettingsModeUi(); });
    connect(cloudMode_, &QRadioButton::toggled, this, [this](bool) { updateSettingsModeUi(); });
    connect(localMode_, &QRadioButton::toggled, this, [this](bool) { updateSettingsModeUi(); });
    connect(coreTest, &QPushButton::clicked, this, [this] { testCoreProvider(); });
    connect(cloudTest, &QPushButton::clicked, this, [this] { testDirectProvider(false); });
    connect(localTest, &QPushButton::clicked, this, [this] { testDirectProvider(true); });
    connect(saveSettings, &QPushButton::clicked, this, [this] { saveAiSettings(); });
    connect(localSave, &QPushButton::clicked, this, [this] { saveAiSettings(); });
    connect(saveVault, &QPushButton::clicked, this, [this] { saveEncryptedCredential(); });
    connect(loadVault, &QPushButton::clicked, this, [this] { loadEncryptedCredential(); });
    connect(forgetVault, &QPushButton::clicked, this, [this] { deleteEncryptedCredential(); });
    connect(cloudProvider_, &QComboBox::currentTextChanged, this,
            [this](const QString& provider) { applyCloudProviderDefaults(provider); });
    connect(localFlavor_, &QComboBox::currentTextChanged, this,
            [this](const QString& provider) { applyLocalProviderDefaults(provider); });

    loadAiSettings();

    renderAiAssets({});
    renderProviders({});
    renderProvenance({});
}

void DesktopAIWidget::clearGrid(QGridLayout* grid) {
    if (!grid) return;
    while (auto* item = grid->takeAt(0)) {
        if (auto* widget = item->widget()) delete widget;
        delete item;
    }
}

void DesktopAIWidget::clearLayout(QVBoxLayout* layout) {
    if (!layout) return;
    while (auto* item = layout->takeAt(0)) {
        if (auto* widget = item->widget()) delete widget;
        delete item;
    }
}

void DesktopAIWidget::loadArtwork(
    QLabel* target,
    const QString& artwork,
    const QString& fallbackText) {
    if (!target) return;
    const QString safe = safeArtworkUrl(artwork);
    target->setTextFormat(Qt::PlainText);
    target->setText(fallbackText);
    target->setPixmap({});
    target->setAlignment(Qt::AlignCenter);
    if (safe.isEmpty()) return;

    QNetworkRequest request{QUrl(safe)};
    request.setAttribute(
        QNetworkRequest::RedirectPolicyAttribute,
        QNetworkRequest::NoLessSafeRedirectPolicy);
    request.setRawHeader("User-Agent", "TRU-Desktop/0.06-preview");

    auto* reply = imageNetwork_->get(request);
    auto bytes = std::make_shared<QByteArray>();
    connect(reply, &QNetworkReply::finished,
            reply, &QObject::deleteLater);
    connect(reply, &QIODevice::readyRead, reply,
            [reply, bytes] {
        bytes->append(reply->readAll());
        if (bytes->size() > 4 * 1024 * 1024) {
            reply->setProperty("truAiArtworkOversize", true);
            reply->abort();
        }
    });
    QTimer::singleShot(10000, reply, [reply] {
        if (reply->isRunning()) {
            reply->setProperty("truAiArtworkTimeout", true);
            reply->abort();
        }
    });
    connect(reply, &QNetworkReply::finished, target,
            [reply, bytes, target, fallbackText] {
        bytes->append(reply->readAll());
        if (reply->error() != QNetworkReply::NoError ||
            reply->property("truAiArtworkOversize").toBool() ||
            reply->property("truAiArtworkTimeout").toBool() ||
            bytes->isEmpty()) {
            target->setText(fallbackText);
            return;
        }

        QBuffer probe(bytes.get());
        probe.open(QIODevice::ReadOnly);
        QImageReader reader(&probe);
        reader.setAutoTransform(true);
        const QSize sourceSize = reader.size();
        if (sourceSize.isValid()) {
            const qint64 pixels =
                static_cast<qint64>(sourceSize.width()) *
                static_cast<qint64>(sourceSize.height());
            if (sourceSize.width() > 8192 ||
                sourceSize.height() > 8192 ||
                pixels > 32LL * 1024LL * 1024LL) {
                target->setText(fallbackText);
                return;
            }
        }

        if (reader.format().toLower() == QByteArray("gif")) {
            auto* animationBuffer = new QBuffer(target);
            animationBuffer->setData(*bytes);
            if (animationBuffer->open(QIODevice::ReadOnly)) {
                auto* movie = new QMovie(
                    animationBuffer, QByteArray("gif"), target);
                movie->setCacheMode(QMovie::CacheAll);
                movie->setScaledSize(target->size());
                if (movie->isValid()) {
                    target->setText({});
                    target->setMovie(movie);
                    movie->start();
                    return;
                }
                movie->deleteLater();
            }
            animationBuffer->deleteLater();
        }

        const QImage image = reader.read();
        if (image.isNull()) {
            target->setText(fallbackText);
            return;
        }
        target->setText({});
        target->setPixmap(QPixmap::fromImage(image).scaled(
            target->size(), Qt::KeepAspectRatio, Qt::SmoothTransformation));
    });
}

void DesktopAIWidget::renderAiAssets(const QJsonArray& tokens) {
    clearGrid(aiGrid_);
    aiTokens_ = tokens;
    aiCount_->setText(
        QString("%1 AI asset%2")
            .arg(tokens.size())
            .arg(tokens.size() == 1 ? "" : "s"));

    if (tokens.isEmpty()) {
        auto* empty = new QLabel(
            "No AI-marked token holdings found for this standalone wallet.");
        empty->setObjectName("aiEmpty");
        empty->setAlignment(Qt::AlignCenter);
        aiGrid_->addWidget(empty, 0, 0, 1, 3);
        return;
    }

    int cardIndex = 0;
    for (const QJsonValue& value : tokens) {
        if (!value.isObject()) continue;
        const QJsonObject token = value.toObject();
        QJsonObject meta = token.value("meta").toObject();
        if (meta.isEmpty() && token.value("metadata").isObject())
            meta = token.value("metadata").toObject();

        const QString tokenId = token.value("tokenID").toString("Unknown");
        const QString name = metadataText(meta, "name", tokenId);
        const QString type = token.value("type").toString("Unknown");
        QString engine = metadataText(meta, "ai_engine");
        if (engine.isEmpty()) engine = metadataText(meta, "ai_provider", "AI-enabled metadata");
        const QString accent = tokenAccent(meta);

        auto* card = new QFrame;
        card->setObjectName("aiCard");
        card->setMinimumWidth(245);
        card->setMaximumWidth(370);
        card->setStyleSheet(QString(
            "QFrame#aiCard{border-left:4px solid %1;}"
            "QPushButton:hover{border-color:%1;}").arg(accent));
        auto* layout = new QVBoxLayout(card);
        layout->setContentsMargins(12, 12, 12, 12);
        layout->setSpacing(8);

        auto* image = new QLabel("AI\nASSET");
        image->setObjectName("aiImage");
        image->setFixedHeight(145);
        image->setMinimumWidth(215);
        image->setAlignment(Qt::AlignCenter);
        layout->addWidget(image);
        loadArtwork(image, tokenArtwork(meta), "AI\nASSET");

        auto* title = new QLabel(name);
        title->setObjectName("aiCardTitle");
        title->setWordWrap(true);
        title->setTextFormat(Qt::PlainText);
        layout->addWidget(title);

        auto* engineLabel = new QLabel(engine);
        engineLabel->setObjectName("aiEngine");
        engineLabel->setWordWrap(true);
        engineLabel->setTextFormat(Qt::PlainText);
        layout->addWidget(engineLabel);

        auto* typeLabel = badge(type.toUpper() + "  ·  AI");
        layout->addWidget(typeLabel, 0, Qt::AlignLeft);

        auto* id = new QLabel("ID  " + shortText(tokenId, 30));
        id->setObjectName("aiCardMeta");
        id->setTextFormat(Qt::PlainText);
        id->setToolTip(tokenId);
        layout->addWidget(id);

        const QString metaId = metadataText(meta, "meta_id");
        if (!metaId.isEmpty()) {
            auto* did = new QLabel("META ID  " + shortText(metaId, 34));
            did->setObjectName("aiCardMeta");
            did->setTextFormat(Qt::PlainText);
            did->setToolTip(metaId);
            layout->addWidget(did);
        }

        auto* actions = new QGridLayout;
        actions->setHorizontalSpacing(8);
        actions->setVerticalSpacing(8);
        auto* evolve = new QPushButton("Evolve");
        evolve->setObjectName("aiEvolveAction");
        auto* state = new QPushButton("Runtime State");
        auto* provenance = new QPushButton("Provenance");
        actions->addWidget(evolve, 0, 0, 1, 2);
        actions->addWidget(state, 1, 0);
        actions->addWidget(provenance, 1, 1);
        layout->addLayout(actions);

        connect(evolve, &QPushButton::clicked, card,
                [this, token] { evolveToken(token); });
        connect(state, &QPushButton::clicked, card,
                [this, token] { requestAiState(token); });
        connect(provenance, &QPushButton::clicked, card,
                [this, token] { verifyProvenance(token); });

        aiGrid_->addWidget(card, cardIndex / 3, cardIndex % 3);
        ++cardIndex;
    }
}

void DesktopAIWidget::renderProviders(const QJsonObject& providers) {
    coreProviders_ = providers;
    clearGrid(providerGrid_);

    if (coreProvider_) {
        const QString selected = coreProvider_->currentText();
        coreProvider_->blockSignals(true);
        coreProvider_->clear();
        for (auto it = providers.begin(); it != providers.end(); ++it)
            coreProvider_->addItem(it.key());
        int restore = coreProvider_->findText(selected);
        if (restore < 0) {
            QSettings settings("TRU", "TRU Desktop");
            restore = coreProvider_->findText(settings.value("ai/core_provider").toString());
        }
        if (restore >= 0) coreProvider_->setCurrentIndex(restore);
        coreProvider_->blockSignals(false);
    }

    providerCount_->setText(
        QString("%1 provider%2")
            .arg(providers.size())
            .arg(providers.size() == 1 ? "" : "s"));
    updateCoreAiIndicator();

    if (providers.isEmpty()) {
        auto* empty = new QLabel("No AI providers were reported by the connected Core node.");
        empty->setObjectName("aiEmpty");
        empty->setAlignment(Qt::AlignCenter);
        providerGrid_->addWidget(empty, 0, 0, 1, 3);
        return;
    }

    int index = 0;
    for (auto it = providers.begin(); it != providers.end(); ++it) {
        if (!it.value().isObject()) continue;
        const QString providerName = it.key();
        const QJsonObject provider = it.value().toObject();
        const bool configured = provider.value("configured").toBool(false);
        const bool available = provider.value("available").toBool(false);
        const bool isDefault = provider.value("default").toBool(false);
        const QString endpoint = provider.value("endpoint").toString();

        auto* card = new QFrame;
        card->setObjectName("aiCard");
        card->setMinimumWidth(245);
        card->setMaximumWidth(390);
        const bool isLastTested =
            coreProviderTestKnown_ && testedCoreProvider_ == providerName;
        if (isLastTested && coreProviderReachable_) {
            card->setStyleSheet(
                "QFrame#aiCard{border-left:5px solid #36d67d;}");
        } else if (isLastTested && !coreProviderReachable_) {
            card->setStyleSheet(
                "QFrame#aiCard{border-left:5px solid #e56f72;}");
        } else if (configured) {
            card->setStyleSheet(
                "QFrame#aiCard{border-left:4px solid #45e6ba;}");
        }

        auto* layout = new QVBoxLayout(card);
        layout->setContentsMargins(14, 14, 14, 14);
        layout->setSpacing(9);

        auto* title = new QLabel(providerName);
        title->setObjectName("aiCardTitle");
        title->setTextFormat(Qt::PlainText);
        layout->addWidget(title);

        auto* state = badge(configured ? "CONFIGURED" : (available ? "AVAILABLE" : "UNAVAILABLE"));
        layout->addWidget(state, 0, Qt::AlignLeft);

        if (isDefault) {
            auto* def = new QLabel("DEFAULT PROVIDER");
            def->setObjectName("aiEngine");
            layout->addWidget(def);
        }

        auto* endpointLabel = new QLabel(
            endpoint.isEmpty() ? "Endpoint not reported" : endpoint);
        endpointLabel->setObjectName("aiCardMeta");
        endpointLabel->setWordWrap(true);
        endpointLabel->setTextFormat(Qt::PlainText);
        endpointLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        layout->addWidget(endpointLabel);

        if (isLastTested) {
            auto* live = new QLabel(
                coreProviderReachable_
                    ? "● LIVE TEST: REACHABLE"
                    : "● LIVE TEST: NOT REACHABLE");
            live->setObjectName("aiEngine");
            live->setStyleSheet(
                coreProviderReachable_
                    ? "color:#54e69a;font-weight:900;"
                    : "color:#ff8f91;font-weight:900;");
            layout->addWidget(live);
        }

        auto* test = new QPushButton("Test Core Connection");
        test->setEnabled(configured);
        test->setToolTip(
            configured
                ? "Run an explicit live provider test from the connected Core host."
                : "This Core reports the provider as available but not configured.");
        layout->addWidget(test);
        connect(test, &QPushButton::clicked, card,
                [this, providerName] {
            testCoreProviderNamed(providerName);
        });

        auto* note = new QLabel(
            isLastTested
                ? "Live status above is from the most recent explicit test."
                : "CONFIGURED is Core configuration state; use Test Core Connection for live reachability.");
        note->setObjectName("aiCardMeta");
        note->setWordWrap(true);
        layout->addWidget(note);

        providerGrid_->addWidget(card, index / 3, index % 3);
        ++index;
    }
}

void DesktopAIWidget::renderProvenance(const QJsonArray& tokens) {
    clearLayout(provenanceList_);

    if (tokens.isEmpty()) {
        auto* empty = new QLabel(
            "No AI-marked wallet assets are available for provenance verification.");
        empty->setObjectName("aiEmpty");
        empty->setAlignment(Qt::AlignCenter);
        provenanceList_->addWidget(empty);
        return;
    }

    for (const QJsonValue& value : tokens) {
        if (!value.isObject()) continue;
        const QJsonObject token = value.toObject();
        QJsonObject meta = token.value("meta").toObject();
        if (meta.isEmpty() && token.value("metadata").isObject())
            meta = token.value("metadata").toObject();

        const QString tokenId = token.value("tokenID").toString();
        const QString name = metadataText(meta, "name", tokenId);
        const QString lastEvolution = metadataText(meta, "last_evolution", "none reported");

        auto* card = new QFrame;
        card->setObjectName("aiCard");
        auto* row = new QHBoxLayout(card);
        row->setContentsMargins(14, 12, 14, 12);

        auto* text = new QVBoxLayout;
        auto* title = new QLabel(name);
        title->setObjectName("aiCardTitle");
        auto* id = new QLabel("Token " + tokenId);
        id->setObjectName("aiCardMeta");
        auto* evolution = new QLabel("Last evolution: " + lastEvolution);
        evolution->setObjectName("aiCardMeta");
        text->addWidget(title);
        text->addWidget(id);
        text->addWidget(evolution);
        row->addLayout(text, 1);

        auto* actionColumn = new QVBoxLayout;
        auto* evolve = new QPushButton("Evolve");
        evolve->setStyleSheet(
            "QPushButton{background:#116a73;border:1px solid #38d9d2;"
            "color:#f3ffff;font-weight:800;}");
        auto* verify = new QPushButton("Verify Provenance");
        actionColumn->addWidget(evolve);
        actionColumn->addWidget(verify);
        row->addLayout(actionColumn);
        connect(evolve, &QPushButton::clicked, card,
                [this, token] { evolveToken(token); });
        connect(verify, &QPushButton::clicked, card,
                [this, token] { verifyProvenance(token); });

        provenanceList_->addWidget(card);
    }
    provenanceList_->addStretch();
}

void DesktopAIWidget::requestAiState(const QJsonObject& token) {
    const QString tokenId = token.value("tokenID").toString();
    if (tokenId.isEmpty()) return;

    QJsonObject params;
    params.insert("tokenID", tokenId);
    rpc_->call(
        "getAITokenState", objectParams(params),
        [this, token, tokenId](
            const QJsonValue& value,
            const QByteArray&,
            const QString& error) {
            QJsonObject meta = token.value("meta").toObject();
            const QString name = metadataText(meta, "name", tokenId);
            const QString accent = tokenAccent(meta);

            if (!error.isEmpty() || !value.isObject()) {
                QJsonObject raw;
                raw.insert("tokenID", tokenId);
                raw.insert("status", "No legacy interaction runtime state");
                if (!error.isEmpty()) raw.insert("rpc_message", error);
                showAiDetailDialog(
                    this,
                    "AI Runtime State",
                    name + " · no legacy interaction-state record exists. Evolution and provenance remain available.",
                    accent,
                    {
                        {"Token ID", tokenId, true},
                        {"Status", "No legacy interaction state (optional)"},
                        {"Evolution", "Available through TOKEN_EVOLUTION / provenance"},
                        {"Note", "AI metadata/evolution and the older ai_token interaction runtime index are separate. This is not an ownership or provenance error."}
                    },
                    raw);
                return;
            }

            const QJsonObject state = value.toObject();
            QList<AiDetailRow> rows = {
                {"Token ID", tokenId, true},
                {"AI enabled", jsonScalar(state.value("ai_enabled"))},
                {"Interactions", jsonScalar(state.value("interaction_count"))},
                {"Configuration", jsonScalar(state.value("config"))},
                {"Consciousness", jsonScalar(state.value("consciousness"))},
                {"Evolution", jsonScalar(state.value("evolution"))},
                {"Last interaction", jsonScalar(state.value("last_interaction"))},
                {"Last AI response", jsonScalar(state.value("last_ai_response"))}
            };
            showAiDetailDialog(
                this,
                "AI Runtime State",
                name + " · read-only AI state from the connected TRU Core node.",
                accent,
                rows,
                state);
        });
}

void DesktopAIWidget::evolveToken(
    const QJsonObject& token) {
    if (!rpc_ || !wallet_ || !wallet_->walletUnlocked()) {
        QMessageBox::warning(
            this,
            "Evolve AI Token",
            "Unlock the standalone wallet first.");
        return;
    }

    const QString tokenId =
        token.value("tokenID").toString().trimmed();
    const QString owner =
        token.value("owner").toString().trimmed();
    QJsonObject meta = token.value("meta").toObject();
    if (meta.isEmpty() &&
        token.value("metadata").isObject())
        meta = token.value("metadata").toObject();

    const QString name =
        metadataText(meta, "name", tokenId);
    const QString type =
        token.value("type").toString().toUpper();
    const QString accent = tokenAccent(meta);

    if ((type != "SFT" && type != "NCFT") ||
        tokenId.isEmpty() ||
        owner.isEmpty() ||
        !wallet_->walletAddresses().contains(owner)) {
        QMessageBox::warning(
            this,
            "Evolve AI Token",
            "Only a wallet-owned SFT/NCFT AI asset can be evolved.");
        return;
    }

    QSettings settings("TRU", "TRU Desktop");
    const QString mode =
        settings.value("ai/mode", "core").toString();
    QString provider =
        coreProvider_ ? coreProvider_->currentText().trimmed()
                      : QString();
    if (provider.isEmpty())
        provider =
            settings.value("ai/core_provider")
                .toString().trimmed();

    if (provider.isEmpty()) {
        QMessageBox::warning(
            this,
            "Evolve AI Token",
            "No Connected Core AI provider is selected. "
            "Open AI → Settings, choose a Core provider, "
            "and test it first.");
        return;
    }

    if (mode != "core") {
        QMessageBox::information(
            this,
            "Evolution Provider Boundary",
            "Your current general AI mode is My AI or Local AI.\n\n"
            "For v0.06 token evolution, the canonical "
            "TokenEvolutionEngine runs on the connected Core and therefore "
            "uses the selected Connected Core AI provider. Your personal/"
            "local API credentials are never sent to Core.");
    }

    bool ok = false;
    const QString trigger = QInputDialog::getText(
        this,
        "Evolve " + name,
        "Evolution trigger / instruction:",
        QLineEdit::Normal,
        "manual evolution",
        &ok);
    if (!ok) return;
    if (trigger.isEmpty() || trigger.size() > 1024) {
        QMessageBox::warning(
            this,
            "Evolve AI Token",
            "Trigger must contain 1 to 1024 characters.");
        return;
    }

    QJsonObject params;
    params.insert("tokenID", tokenId);
    params.insert("owner", owner);
    params.insert("provider", provider);
    params.insert("trigger", trigger);

    if (QMessageBox::question(this, "Extended AI / Artwork",
            "Use V4 descriptive fields and optional artwork import? Old cores cannot verify V4 history. "
            "This does not generate or upload images.",
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No) == QMessageBox::Yes) {
        bool accepted = false;
        const auto text = QInputDialog::getMultiLineText(this, "Media inputs",
            "JSON object; {} for text-only. Image requires image, artwork_file and change_note. "
            "Only public metadata: these inputs may be sent to the configured AI provider.",
            "{}", &accepted);
        if (!accepted) return;
        try {
            if (text.toUtf8().size() > 16384) throw std::runtime_error("Input exceeds 16 KiB");
            const auto imported = tru_media_v4::importLocalInputs(nlohmann::json::parse(text.toStdString()));
            params.insert("media_inputs", QJsonDocument::fromJson(QByteArray::fromStdString(imported.dump())).object());
        } catch (const std::exception& e) {
            QMessageBox::warning(this, "Media input refused", QString::fromUtf8(e.what()));
            return;
        }
    }

    status_->setText(
        "Generating constrained evolution preview for " +
        name + " via Core provider " + provider + "…");

    rpc_->call(
        "previewtokenevolution",
        objectParams(params),
        [this, tokenId, owner, name, provider, accent](
            const QJsonValue& value,
            const QByteArray&,
            const QString& error) {
            if (!error.isEmpty() || !value.isObject()) {
                status_->setText(
                    "Evolution preview refused for " + name + ".");
                QMessageBox::warning(
                    this,
                    "Evolution Preview",
                    error.isEmpty()
                        ? "Core returned an invalid evolution preview."
                        : error);
                return;
            }

            const QJsonObject preview = value.toObject();
            const QJsonObject record =
                preview.value("record").toObject();
            const QString recordJson =
                preview.value("record_json").toString();
            const QString commitMessage =
                preview.value("commit_message").toString();

            if (record.isEmpty() ||
                recordJson.isEmpty() ||
                commitMessage.isEmpty() ||
                preview.value("owner").toString() != owner ||
                preview.value("tokenID").toString() != tokenId ||
                preview.value("provider").toString() != provider) {
                QMessageBox::critical(
                    this,
                    "Evolution Preview",
                    "Evolution preview failed the Desktop binding check. "
                    "Nothing was signed or committed.");
                return;
            }

            const QString epoch =
                QString("%1 → %2")
                    .arg(jsonScalar(
                        record.value("epoch_before")))
                    .arg(jsonScalar(
                        record.value("epoch_after")));
            const QString updates =
                QString::fromUtf8(
                    QJsonDocument(
                        record.value("updated_fields")
                            .toObject())
                        .toJson(QJsonDocument::Indented));
            const QString resulting =
                QString::fromUtf8(
                    QJsonDocument(
                        record.value("metadata")
                            .toObject())
                        .toJson(QJsonDocument::Indented));

            showAiDetailDialog(
                this,
                "AI Evolution Preview",
                name +
                    " · PREVIEW ONLY · nothing has been persisted "
                    "or anchored.",
                accent,
                {
                    {"Token ID", tokenId, true},
                    {"Owner", owner, true},
                    {"Provider", provider},
                    {"Epoch", epoch},
                    {"Previous hash",
                     record.value(
                         "previous_metadata_hash")
                         .toString(),
                     true},
                    {"New hash",
                     record.value(
                         "new_metadata_hash")
                         .toString(),
                     true},
                    {"Permitted updates", updates, true},
                    {"Resulting metadata", resulting, true}
                },
                preview);

            bool confirmOk = false;
            const QString confirmation =
                QInputDialog::getText(
                    this,
                    "Commit Exact Evolution Preview",
                    "Review complete.\n\n"
                    "Type COMMIT exactly to sign and persist THIS exact "
                    "preview.\nAnything else cancels:",
                    QLineEdit::Normal,
                    {},
                    &confirmOk);
            if (!confirmOk || confirmation != "COMMIT") {
                status_->setText(
                    "Evolution preview cancelled; nothing was committed.");
                return;
            }

            QString publicKey;
            QString signature;
            QString signError;
            if (!wallet_->signAuthorization(
                    owner,
                    commitMessage,
                    publicKey,
                    signature,
                    signError)) {
                QMessageBox::critical(
                    this,
                    "Evolution Authorization",
                    "Local owner signature refused: " +
                    signError);
                return;
            }

            QJsonObject commit;
            commit.insert("tokenID", tokenId);
            commit.insert("owner", owner);
            commit.insert("record_json", recordJson);
            commit.insert("publicKey", publicKey);
            commit.insert("signature", signature);
            commit.insert("confirmation", "COMMIT");

            status_->setText(
                "Submitting signed exact evolution preview…");

            rpc_->call(
                "committokenevolutionsigned",
                objectParams(commit),
                [this, tokenId, name, accent](
                    const QJsonValue& commitValue,
                    const QByteArray&,
                    const QString& commitError) {
                    if (!commitError.isEmpty() ||
                        !commitValue.isObject()) {
                        status_->setText(
                            "Evolution commit refused for " +
                            name + ".");
                        QMessageBox::critical(
                            this,
                            "Evolution Commit",
                            commitError.isEmpty()
                                ? "Core returned an invalid evolution "
                                  "commit result."
                                : commitError);
                        return;
                    }

                    const QJsonObject result =
                        commitValue.toObject();
                    showAiDetailDialog(
                        this,
                        "Evolution Committed",
                        name +
                            " · exact signed preview persisted; "
                            "provenance anchor queued.",
                        accent,
                        {
                            {"Token ID", tokenId, true},
                            {"Epoch",
                             jsonScalar(result.value("epoch"))},
                            {"Persisted",
                             jsonScalar(result.value("persisted"))},
                            {"Anchor queued",
                             jsonScalar(result.value("anchor_queued"))},
                            {"Record hash",
                             result.value("record_sha256").toString(),
                             true},
                            {"Status",
                             result.value("note").toString()}
                        },
                        result);
                    status_->setText(
                        "Evolution epoch committed for " +
                        name +
                        "; wait for the provenance anchor to confirm.");
                    refreshAll();
                });
        });
}

void DesktopAIWidget::verifyProvenance(const QJsonObject& token) {
    const QString tokenId = token.value("tokenID").toString();
    if (tokenId.isEmpty()) return;

    QJsonObject params;
    params.insert("tokenID", tokenId);
    params.insert("require_confirmed", true);

    rpc_->call(
        "verifytokenevolution", objectParams(params),
        [this, token, tokenId](
            const QJsonValue& value,
            const QByteArray&,
            const QString& error) {
            QJsonObject meta = token.value("meta").toObject();
            const QString name = metadataText(meta, "name", tokenId);
            const QString accent = tokenAccent(meta);

            if (!error.isEmpty() || !value.isObject()) {
                QJsonObject raw;
                raw.insert("tokenID", tokenId);
                raw.insert("runtime_ok", false);
                if (!error.isEmpty()) raw.insert("rpc_message", error);
                showAiDetailDialog(
                    this,
                    "AI Provenance",
                    name + " · provenance verification could not be completed.",
                    accent,
                    {
                        {"Token ID", tokenId, true},
                        {"Verification", "Unavailable"},
                        {"Note", "Ownership remains separate from evolution provenance."}
                    },
                    raw);
                return;
            }

            const QJsonObject result = value.toObject();
            const bool runtimeOk = result.value("runtime_ok").toBool(false);
            const QString verification = runtimeOk
                ? "PROVENANCE VERIFIED"
                : "NOT VERIFIED / INCOMPLETE";

            QList<AiDetailRow> rows = {
                {"Token ID", tokenId, true},
                {"Verification", verification},
                {"Token type", jsonScalar(result.value("token_type"))},
                {"Issuance", jsonScalar(result.value("issuance_status"))},
                {"History valid", jsonScalar(result.value("history_ok"))},
                {"Fully anchored", jsonScalar(result.value("fully_anchored"))},
                {"Confirmed anchors", jsonScalar(result.value("confirmed_anchor_txs"))},
                {"Mempool anchors", jsonScalar(result.value("mempool_anchor_txs"))},
                {"Missing anchors", jsonScalar(result.value("missing_anchor_txs"))},
                {"Valid anchor payloads", jsonScalar(result.value("valid_anchor_payloads"))},
                {"Error", jsonScalar(result.value("error"))}
            };

            showAiDetailDialog(
                this,
                "AI Provenance",
                name + " · confirmed evolution and anchor verification.",
                runtimeOk ? accent : QString("#c5a2ff"),
                rows,
                result);
        });
}

void DesktopAIWidget::refreshAll() {
    const QStringList addresses = wallet_->walletAddresses();
    if (addresses.isEmpty()) {
        status_->setText(
            "Unlock the standalone wallet first. AI asset discovery reads only its locally derived addresses.");
        renderAiAssets({});
        renderProvenance({});
    }

    refresh_->setEnabled(false);
    status_->setText("Reading AI-marked assets and configured AI providers from the connected TRU node…");

    QJsonObject providerParams;
    if (!addresses.isEmpty())
        providerParams.insert("address", addresses.first());

    rpc_->call(
        "getAIProviders", objectParams(providerParams),
        [this](const QJsonValue& value, const QByteArray&, const QString& error) {
            if (!error.isEmpty() || !value.isObject()) {
                renderProviders({});
            } else {
                renderProviders(value.toObject());
            }
        });

    if (addresses.isEmpty()) {
        refresh_->setEnabled(true);
        status_->setText(
            "AI provider information refreshed. Unlock the wallet to discover AI asset holdings.");
        return;
    }

    QJsonArray addressArray;
    for (const QString& address : addresses)
        addressArray.append(address);
    QJsonObject params;
    params.insert("addresses", addressArray);

    rpc_->call(
        "tokenmetadisplay", objectParams(params),
        [this, addresses](
            const QJsonValue& value,
            const QByteArray&,
            const QString& error) {
            QJsonArray ai;
            if (error.isEmpty() && value.isArray()) {
                for (const QJsonValue& item : value.toArray()) {
                    if (item.isObject() && isAiToken(item.toObject()))
                        ai.append(item);
                }
            }

            renderAiAssets(ai);
            renderProvenance(ai);
            refresh_->setEnabled(true);

            QString summary = QString(
                "%1 AI asset%2  ·  %3 wallet address%4")
                .arg(ai.size())
                .arg(ai.size() == 1 ? "" : "s")
                .arg(addresses.size())
                .arg(addresses.size() == 1 ? "" : "es");
            if (!error.isEmpty())
                summary += "  ·  Asset read failed: " + error;
            status_->setText(summary);
        });
}


QString DesktopAIWidget::credentialVaultPath() const {
    const QString base = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    return QDir(base).filePath("truo-ai-credentials-v1.enc");
}

void DesktopAIWidget::loadAiSettings() {
    QSettings settings("TRU", "TRU Desktop");
    const QString mode = settings.value("ai/mode", "core").toString();
    coreMode_->setChecked(mode == "core");
    cloudMode_->setChecked(mode == "cloud");
    localMode_->setChecked(mode == "local");
    if (!coreMode_->isChecked() && !cloudMode_->isChecked() && !localMode_->isChecked())
        coreMode_->setChecked(true);

    const QString cloudProvider = settings.value("ai/cloud/provider", "OpenAI").toString();
    int cloudIndex = cloudProvider_->findText(cloudProvider);
    if (cloudIndex >= 0) cloudProvider_->setCurrentIndex(cloudIndex);
    applyCloudProviderDefaults(cloudProvider_->currentText());
    const QString savedCloudEndpoint = settings.value("ai/cloud/endpoint").toString();
    const QString savedCloudModel = settings.value("ai/cloud/model").toString();
    if (!savedCloudEndpoint.isEmpty()) cloudEndpoint_->setText(savedCloudEndpoint);
    if (!savedCloudModel.isEmpty()) cloudModel_->setText(savedCloudModel);

    const QString localFlavor = settings.value(
        "ai/local/flavor", "OpenAI-compatible / Nemotron").toString();
    int localIndex = localFlavor_->findText(localFlavor);
    if (localIndex >= 0) localFlavor_->setCurrentIndex(localIndex);
    applyLocalProviderDefaults(localFlavor_->currentText());
    const QString savedLocalEndpoint = settings.value("ai/local/endpoint").toString();
    const QString savedLocalModel = settings.value("ai/local/model").toString();
    if (!savedLocalEndpoint.isEmpty()) localEndpoint_->setText(savedLocalEndpoint);
    if (!savedLocalModel.isEmpty()) localModel_->setText(savedLocalModel);

    updateSettingsModeUi();
}

void DesktopAIWidget::saveAiSettings() {
    QSettings settings("TRU", "TRU Desktop");
    const QString mode = coreMode_->isChecked() ? "core" : (cloudMode_->isChecked() ? "cloud" : "local");
    settings.setValue("ai/mode", mode);
    settings.setValue("ai/core_provider", coreProvider_->currentText());
    settings.setValue("ai/cloud/provider", cloudProvider_->currentText());
    settings.setValue("ai/cloud/endpoint", cloudEndpoint_->text().trimmed());
    settings.setValue("ai/cloud/model", cloudModel_->text().trimmed());
    settings.setValue("ai/local/flavor", localFlavor_->currentText());
    settings.setValue("ai/local/endpoint", localEndpoint_->text().trimmed());
    settings.setValue("ai/local/model", localModel_->text().trimmed());
    settings.sync();
    settingsStatus_->setText(
        "Non-secret AI settings saved locally. API keys were not written to Desktop preferences.");
}

void DesktopAIWidget::updateSettingsModeUi() {
    const bool core = coreMode_->isChecked();
    const bool cloud = cloudMode_->isChecked();
    const bool local = localMode_->isChecked();
    coreSettingsFrame_->setEnabled(core);
    cloudSettingsFrame_->setEnabled(cloud);
    localSettingsFrame_->setEnabled(local);
}

void DesktopAIWidget::applyCloudProviderDefaults(const QString& provider) {
    const bool endpointBlank = cloudEndpoint_->text().trimmed().isEmpty();
    const bool modelBlank = cloudModel_->text().trimmed().isEmpty();
    if (provider == "OpenAI") {
        if (endpointBlank) cloudEndpoint_->setText("https://api.openai.com/v1/chat/completions");
    } else if (provider == "Anthropic") {
        if (endpointBlank) cloudEndpoint_->setText("https://api.anthropic.com/v1/messages");
    } else if (provider == "Gemini") {
        if (endpointBlank) cloudEndpoint_->setText(
            "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent");
    } else if (provider == "Grok") {
        if (endpointBlank) cloudEndpoint_->setText("https://api.x.ai/v1/chat/completions");
    } else if (provider.startsWith("Custom")) {
        if (endpointBlank) cloudEndpoint_->clear();
    }
    if (modelBlank) cloudModel_->clear();
}

void DesktopAIWidget::applyLocalProviderDefaults(const QString& provider) {
    if (provider.startsWith("Ollama")) {
        if (localEndpoint_->text().trimmed().isEmpty() ||
            localEndpoint_->text().contains(":5051"))
            localEndpoint_->setText("http://127.0.0.1:11434/api/chat");
        if (localModel_->text().trimmed().isEmpty()) localModel_->setText("llama3");
    } else {
        if (localEndpoint_->text().trimmed().isEmpty() ||
            localEndpoint_->text().contains(":11434"))
            localEndpoint_->setText("http://127.0.0.1:5051/v1/chat/completions");
        if (localModel_->text().trimmed().isEmpty()) localModel_->setText("nemotron");
    }
}

void DesktopAIWidget::updateCoreAiIndicator() {
    if (!coreAiIndicator_) return;

    int configured = 0;
    for (auto it = coreProviders_.begin(); it != coreProviders_.end(); ++it) {
        if (it.value().isObject() &&
            it.value().toObject().value("configured").toBool(false))
            ++configured;
    }

    coreAiIndicator_->setProperty("live", false);
    coreAiIndicator_->setProperty("failed", false);

    if (coreProviderTestKnown_) {
        if (coreProviderReachable_) {
            coreAiIndicator_->setText(
                "● CORE AI REACHABLE · " + testedCoreProvider_);
            coreAiIndicator_->setProperty("live", true);
        } else {
            coreAiIndicator_->setText(
                "● CORE AI NOT REACHABLE · " + testedCoreProvider_);
            coreAiIndicator_->setProperty("failed", true);
        }
    } else if (configured > 0) {
        coreAiIndicator_->setText(
            QString("● CORE AI CONFIGURED · %1").arg(configured));
    } else if (!coreProviders_.isEmpty()) {
        coreAiIndicator_->setText("○ CORE AI NOT CONFIGURED");
    } else {
        coreAiIndicator_->setText("○ CORE AI NOT TESTED");
    }

    coreAiIndicator_->style()->unpolish(coreAiIndicator_);
    coreAiIndicator_->style()->polish(coreAiIndicator_);
    coreAiIndicator_->update();
}

void DesktopAIWidget::testCoreProvider() {
    testCoreProviderNamed(coreProvider_->currentText().trimmed());
}

void DesktopAIWidget::testCoreProviderNamed(const QString& provider) {
    if (provider.isEmpty()) {
        settingsStatus_->setText(
            "Refresh AI first so the connected Core can report its providers.");
        QMessageBox::information(
            this,
            "Core AI Test",
            "Refresh AI first so the connected Core can report its providers.");
        return;
    }

    if (coreAiIndicator_) {
        coreAiIndicator_->setText("◌ TESTING CORE AI · " + provider);
        coreAiIndicator_->setProperty("live", false);
        coreAiIndicator_->setProperty("failed", false);
        coreAiIndicator_->style()->unpolish(coreAiIndicator_);
        coreAiIndicator_->style()->polish(coreAiIndicator_);
    }

    settingsStatus_->setText(
        "Testing " + provider + " from the connected Core host…");

    QJsonObject params;
    params.insert("provider", provider);

    rpc_->call(
        "testAIProvider", objectParams(params),
        [this, provider](
            const QJsonValue& value,
            const QByteArray&,
            const QString& error) {

            testedCoreProvider_ = provider;
            coreProviderTestKnown_ = true;

            if (!error.isEmpty() || !value.isObject()) {
                coreProviderReachable_ = false;
                const QString message =
                    "Core provider test failed for " + provider +
                    (error.isEmpty() ? "." : ": " + error);
                settingsStatus_->setText(message);
                updateCoreAiIndicator();
                renderProviders(coreProviders_);
                QMessageBox::warning(
                    this, "AI Provider Not Reachable", message);
                return;
            }

            const QJsonObject result = value.toObject();
            coreProviderReachable_ =
                result.value("reachable").toBool(false);
            const QString endpoint =
                result.value("endpoint").toString();

            const QString message =
                QString("Core AI %1: %2%3")
                    .arg(
                        provider,
                        coreProviderReachable_
                            ? "REACHABLE"
                            : "NOT REACHABLE",
                        endpoint.isEmpty()
                            ? QString()
                            : "  ·  " + endpoint);

            settingsStatus_->setText(message);
            updateCoreAiIndicator();
            renderProviders(coreProviders_);

            if (coreProviderReachable_) {
                QMessageBox::information(
                    this,
                    "AI Provider Connected",
                    provider +
                    " is reachable from the connected TRU Core." +
                    (endpoint.isEmpty()
                         ? QString()
                         : "\n\nEndpoint:\n" + endpoint));
            } else {
                QMessageBox::warning(
                    this,
                    "AI Provider Not Reachable",
                    provider +
                    " is configured on the connected Core, "
                    "but the live provider test did not succeed." +
                    (endpoint.isEmpty()
                         ? QString()
                         : "\n\nEndpoint:\n" + endpoint));
            }
        });
}

void DesktopAIWidget::testDirectProvider(bool localMode) {
    const QString provider = localMode ? localFlavor_->currentText() : cloudProvider_->currentText();
    QString endpoint = (localMode ? localEndpoint_->text() : cloudEndpoint_->text()).trimmed();
    const QString model = (localMode ? localModel_->text() : cloudModel_->text()).trimmed();
    const QString apiKey = localMode ? localApiKey_->text() : cloudApiKey_->text();

    if (endpoint.isEmpty()) {
        settingsStatus_->setText("Endpoint is required.");
        return;
    }
    if (model.isEmpty()) {
        settingsStatus_->setText("Model is required for a direct AI test.");
        return;
    }

    if (!localMode && provider == "Gemini")
        endpoint.replace("{model}", QString::fromUtf8(QUrl::toPercentEncoding(model)));

    const QUrl url(endpoint);
    if (!url.isValid() || url.host().isEmpty() ||
        (url.scheme().toLower() != "https" && url.scheme().toLower() != "http")) {
        settingsStatus_->setText("Endpoint must be a valid HTTP or HTTPS URL.");
        return;
    }

    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QNetworkRequest::NoLessSafeRedirectPolicy);
    request.setRawHeader("User-Agent", "TRU-Desktop/0.06");

    QJsonObject payload;
    if (localMode && provider.startsWith("Ollama")) {
        payload.insert("model", model);
        payload.insert("stream", false);
        payload.insert("messages", QJsonArray{
            QJsonObject{{"role", "user"}, {"content", "Reply TRU_AI_OK"}}
        });
        payload.insert("options", QJsonObject{{"num_predict", 1}});
        if (!apiKey.isEmpty())
            request.setRawHeader("Authorization", "Bearer " + apiKey.toUtf8());
    } else if (!localMode && provider == "Anthropic") {
        payload.insert("model", model);
        payload.insert("max_tokens", 1);
        payload.insert("messages", QJsonArray{
            QJsonObject{{"role", "user"}, {"content", "Reply TRU_AI_OK"}}
        });
        request.setRawHeader("anthropic-version", "2023-06-01");
        if (!apiKey.isEmpty()) request.setRawHeader("x-api-key", apiKey.toUtf8());
    } else if (!localMode && provider == "Gemini") {
        payload.insert("contents", QJsonArray{
            QJsonObject{{"parts", QJsonArray{
                QJsonObject{{"text", "Reply TRU_AI_OK"}}
            }}}
        });
        if (!apiKey.isEmpty()) request.setRawHeader("x-goog-api-key", apiKey.toUtf8());
    } else {
        payload.insert("model", model);
        payload.insert("max_tokens", 1);
        payload.insert("messages", QJsonArray{
            QJsonObject{{"role", "user"}, {"content", "Reply TRU_AI_OK"}}
        });
        if (!apiKey.isEmpty())
            request.setRawHeader("Authorization", "Bearer " + apiKey.toUtf8());
    }

    settingsStatus_->setText(
        QString("Testing %1 directly from this Desktop…").arg(provider));

    auto* reply = directNetwork_->post(request, QJsonDocument(payload).toJson(QJsonDocument::Compact));
    auto timer = std::make_shared<QElapsedTimer>();
    timer->start();
    auto body = std::make_shared<QByteArray>();

    connect(reply, &QIODevice::readyRead, reply, [reply, body] {
        body->append(reply->readAll());
        if (body->size() > 1024 * 1024) {
            reply->setProperty("truAiProbeOversize", true);
            reply->abort();
        }
    });
    QTimer::singleShot(15000, reply, [reply] {
        if (reply->isRunning()) {
            reply->setProperty("truAiProbeTimeout", true);
            reply->abort();
        }
    });
    connect(reply, &QNetworkReply::finished, this,
            [this, reply, body, timer, provider] {
        body->append(reply->readAll());
        const int http = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const qint64 ms = timer->elapsed();
        const bool ok = reply->error() == QNetworkReply::NoError && http >= 200 && http < 300;
        QString detail;
        if (reply->property("truAiProbeTimeout").toBool()) detail = "timeout";
        else if (reply->property("truAiProbeOversize").toBool()) detail = "response exceeded 1 MiB";
        else if (!ok) detail = reply->errorString();

        settingsStatus_->setText(
            ok ? QString("Direct AI %1: REACHABLE  ·  HTTP %2  ·  %3 ms")
                     .arg(provider).arg(http).arg(ms)
               : QString("Direct AI %1: NOT REACHABLE  ·  HTTP %2  ·  %3")
                     .arg(provider).arg(http).arg(detail));
        reply->deleteLater();
    });
}

void DesktopAIWidget::saveEncryptedCredential() {
    const bool cloud = cloudMode_->isChecked();
    const bool local = localMode_->isChecked();
    if (!cloud && !local) {
        settingsStatus_->setText("Encrypted credential storage is for My AI or Local AI modes.");
        return;
    }

    const QString key = cloud ? cloudApiKey_->text() : localApiKey_->text();
    if (key.isEmpty()) {
        settingsStatus_->setText("Enter an API key first. Local AI without a key does not require a vault entry.");
        return;
    }

    bool ok = false;
    QString pass = QInputDialog::getText(
        this, "AI Credential Vault", "Create / enter AI vault passphrase:",
        QLineEdit::Password, {}, &ok);
    if (!ok || pass.isEmpty()) return;
    QString confirm = QInputDialog::getText(
        this, "AI Credential Vault", "Confirm AI vault passphrase:",
        QLineEdit::Password, {}, &ok);
    if (!ok || confirm != pass) {
        settingsStatus_->setText("AI vault passphrase confirmation did not match.");
        pass.fill(QChar('\0')); confirm.fill(QChar('\0'));
        return;
    }

    QJsonObject secret;
    secret.insert("format", "TRU_DESKTOP_AI_VAULT_V1");
    secret.insert("mode", cloud ? "cloud" : "local");
    secret.insert("provider", cloud ? cloudProvider_->currentText() : localFlavor_->currentText());
    secret.insert("endpoint", cloud ? cloudEndpoint_->text().trimmed() : localEndpoint_->text().trimmed());
    secret.insert("model", cloud ? cloudModel_->text().trimmed() : localModel_->text().trimmed());
    secret.insert("api_key", key);

    QByteArray plainBytes = QJsonDocument(secret).toJson(QJsonDocument::Compact);
    std::vector<std::uint8_t> plain(
        reinterpret_cast<const std::uint8_t*>(plainBytes.constData()),
        reinterpret_cast<const std::uint8_t*>(plainBytes.constData()) + plainBytes.size());
    std::vector<std::uint8_t> envelope;
    std::string error;
    std::string passUtf8 = pass.toUtf8().toStdString();
    const bool encrypted = tru_wallet_encryption_v1::encrypt(
        plain, passUtf8, envelope, &error);

    if (!plain.empty()) sodium_memzero(plain.data(), plain.size());
    if (!plainBytes.isEmpty()) {
        plainBytes.fill('\0');
        plainBytes.clear();
    }
    if (!passUtf8.empty()) sodium_memzero(passUtf8.data(), passUtf8.size());
    pass.fill(QChar('\0')); confirm.fill(QChar('\0'));

    if (!encrypted) {
        settingsStatus_->setText("Could not encrypt AI credential vault: " + QString::fromStdString(error));
        return;
    }

    const QString path = credentialVaultPath();
    QDir().mkpath(QFileInfo(path).absolutePath());
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly) ||
        file.write(reinterpret_cast<const char*>(envelope.data()),
                   static_cast<qint64>(envelope.size())) != static_cast<qint64>(envelope.size()) ||
        !file.commit()) {
        settingsStatus_->setText("Could not write encrypted AI credential vault.");
        if (!envelope.empty()) sodium_memzero(envelope.data(), envelope.size());
        return;
    }
    QFile::setPermissions(path, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    if (!envelope.empty()) sodium_memzero(envelope.data(), envelope.size());
    saveAiSettings();
    settingsStatus_->setText("API key saved in authenticated local AI credential vault: " + path);
}

void DesktopAIWidget::loadEncryptedCredential() {
    const QString path = credentialVaultPath();
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        settingsStatus_->setText("No encrypted AI credential vault found.");
        return;
    }
    const QByteArray envelopeBytes = file.readAll();
    std::vector<std::uint8_t> envelope(
        reinterpret_cast<const std::uint8_t*>(envelopeBytes.constData()),
        reinterpret_cast<const std::uint8_t*>(envelopeBytes.constData()) + envelopeBytes.size());

    bool ok = false;
    QString pass = QInputDialog::getText(
        this, "AI Credential Vault", "AI vault passphrase:",
        QLineEdit::Password, {}, &ok);
    if (!ok || pass.isEmpty()) return;
    std::string passUtf8 = pass.toUtf8().toStdString();
    std::vector<std::uint8_t> plain;
    std::string error;
    const bool decrypted = tru_wallet_encryption_v1::decrypt(
        envelope, passUtf8, plain, &error);
    if (!passUtf8.empty()) sodium_memzero(passUtf8.data(), passUtf8.size());
    pass.fill(QChar('\0'));
    if (!envelope.empty()) sodium_memzero(envelope.data(), envelope.size());

    if (!decrypted) {
        settingsStatus_->setText("AI credential vault unlock failed: " + QString::fromStdString(error));
        return;
    }

    QByteArray plainBytes(
        reinterpret_cast<const char*>(plain.data()), static_cast<int>(plain.size()));
    QJsonParseError parseError;
    const QJsonDocument doc = QJsonDocument::fromJson(plainBytes, &parseError);
    if (!plain.empty()) sodium_memzero(plain.data(), plain.size());
    if (!plainBytes.isEmpty()) { plainBytes.fill('\0'); plainBytes.clear(); }
    if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
        settingsStatus_->setText("AI credential vault payload is invalid.");
        return;
    }

    const QJsonObject secret = doc.object();
    if (secret.value("format").toString() != "TRU_DESKTOP_AI_VAULT_V1") {
        settingsStatus_->setText("AI credential vault format mismatch.");
        return;
    }
    const QString mode = secret.value("mode").toString();
    if (mode == "cloud") {
        cloudMode_->setChecked(true);
        int i = cloudProvider_->findText(secret.value("provider").toString());
        if (i >= 0) cloudProvider_->setCurrentIndex(i);
        cloudEndpoint_->setText(secret.value("endpoint").toString());
        cloudModel_->setText(secret.value("model").toString());
        cloudApiKey_->setText(secret.value("api_key").toString());
    } else if (mode == "local") {
        localMode_->setChecked(true);
        int i = localFlavor_->findText(secret.value("provider").toString());
        if (i >= 0) localFlavor_->setCurrentIndex(i);
        localEndpoint_->setText(secret.value("endpoint").toString());
        localModel_->setText(secret.value("model").toString());
        localApiKey_->setText(secret.value("api_key").toString());
    }
    updateSettingsModeUi();
    settingsStatus_->setText("Encrypted AI credential loaded into this Desktop session.");
}

void DesktopAIWidget::deleteEncryptedCredential() {
    const QString path = credentialVaultPath();
    if (!QFileInfo::exists(path)) {
        settingsStatus_->setText("No encrypted AI credential vault exists.");
        return;
    }
    if (QMessageBox::question(
            this, "Forget AI Credential",
            "Delete the encrypted AI credential vault from this computer?") != QMessageBox::Yes)
        return;
    if (QFile::remove(path)) {
        cloudApiKey_->clear();
        localApiKey_->clear();
        settingsStatus_->setText("Encrypted AI credential vault deleted.");
    } else {
        settingsStatus_->setText("Could not delete encrypted AI credential vault.");
    }
}
