#include "desktop_assets_widget.h"

#include "desktop_rpc.h"
#include "desktop_wallet_widget.h"

#include <QBuffer>
#include <QDateTime>
#include <QDialog>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QImage>
#include <QImageReader>
#include <QInputDialog>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMovie>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPlainTextEdit>
#include <QPixmap>
#include <QPushButton>
#include <QRegularExpression>
#include <QScrollArea>
#include <QSettings>
#include <QTabWidget>
#include <QTimer>
#include <QUrl>
#include <QVariant>
#include <QVBoxLayout>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <memory>
#include <utility>

namespace {

QByteArray objectParams(const QJsonObject& object) {
    return QJsonDocument(object).toJson(QJsonDocument::Compact);
}

QString normalizeArtworkValue(QString raw) {
    raw = raw.trimmed();
    if (raw.isEmpty()) return {};

    // Mirrors the web explorer's display normalization without changing
    // any on-chain metadata: [label](URL) and <URL> are wrappers only.
    static const QRegularExpression markdownLink(
        QStringLiteral("^\\[[^\\]]*\\]\\(([^)]+)\\)$"));
    const auto markdownMatch = markdownLink.match(raw);
    if (markdownMatch.hasMatch())
        raw = markdownMatch.captured(1).trimmed();

    static const QRegularExpression angleWrapped(
        QStringLiteral("^<([^<>]+)>$"));
    const auto angleMatch = angleWrapped.match(raw);
    if (angleMatch.hasMatch())
        raw = angleMatch.captured(1).trimmed();

    return raw;
}

QString metadataText(const QJsonObject& meta,
                     const QString& key,
                     const QString& fallback = {}) {
    const auto value = meta.value(key);
    if (value.isString()) return value.toString();
    if (value.isDouble())
        return QString::number(value.toDouble(), 'g', 15);
    return fallback;
}

QLabel* makeCountBadge(const QString& text) {
    auto* label = new QLabel(text);
    label->setObjectName("truAssetCountBadge");
    return label;
}

QScrollArea* makeAssetScroll(QWidget*& host, QGridLayout*& grid) {
    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setObjectName("truAssetScroll");

    host = new QWidget;
    host->setObjectName("truAssetHost");
    grid = new QGridLayout(host);
    grid->setContentsMargins(8, 8, 8, 8);
    grid->setHorizontalSpacing(14);
    grid->setVerticalSpacing(14);
    grid->setAlignment(Qt::AlignTop | Qt::AlignLeft);

    scroll->setWidget(host);
    return scroll;
}


QString detailArtworkUrl(const QString& value) {
    const QString raw = normalizeArtworkValue(value);
    if (raw.isEmpty()) return {};

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

QString tokenAccent(const QJsonObject& meta) {
    QString accent = metadataText(meta, "dynamic_visual").trimmed();
    if (accent.isEmpty()) accent = metadataText(meta, "colour").trimmed();
    static const QRegularExpression color(
        QStringLiteral("^#[0-9A-Fa-f]{6}$"));
    if (!color.match(accent).hasMatch())
        accent = "#35f0ff";
    return accent;
}

struct DetailRow {
    QString label;
    QString value;
    bool mono = false;
};

void addDetailRow(QGridLayout* grid, int row, const DetailRow& item) {
    auto* key = new QLabel(item.label);
    key->setStyleSheet(
        "color:#7d97ab;"
        "font-size:11px;"
        "font-weight:700;"
        "letter-spacing:1.2px;"
        "padding-top:4px;");
    key->setAlignment(Qt::AlignTop | Qt::AlignLeft);

    auto* value = new QLabel(item.value);
    value->setWordWrap(true);
    value->setTextFormat(Qt::PlainText);
    value->setTextInteractionFlags(Qt::TextSelectableByMouse);
    QString style =
        "background-color:#222242;"
        "border:1px solid #2f4f68;"
        "border-radius:10px;"
        "padding:11px 13px;"
        "color:#eef6ff;"
        "font-size:15px;";
    if (item.mono)
        style += "font-family:'DejaVu Sans Mono','Menlo','Consolas';font-size:14px;";
    value->setStyleSheet(style);

    grid->addWidget(key, row, 0, Qt::AlignTop);
    grid->addWidget(value, row, 1);
}

void setArtworkFromBytes(
    QLabel* target,
    const std::shared_ptr<QByteArray>& bytes,
    const QString& fallbackText) {
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

    // UI-03A: QImageReader::read() renders only a single frame. For GIF
    // artwork keep the downloaded bytes in a QBuffer owned by the label and
    // let QMovie drive the frames. No network or metadata semantics change.
    if (reader.format().toLower() == QByteArray("gif")) {
        auto* animationBuffer = new QBuffer(target);
        animationBuffer->setData(*bytes);
        if (animationBuffer->open(QIODevice::ReadOnly)) {
            auto* movie = new QMovie(animationBuffer, QByteArray("gif"), target);
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

    if (sourceSize.isValid()) {
        const QSize decodeSize = sourceSize.scaled(
            QSize(720, 480), Qt::KeepAspectRatio);
        if (decodeSize.width() < sourceSize.width() ||
            decodeSize.height() < sourceSize.height())
            reader.setScaledSize(decodeSize);
    }

    const QImage image = reader.read();
    if (image.isNull()) {
        target->setText(fallbackText);
        return;
    }

    target->setText({});
    target->setPixmap(
        QPixmap::fromImage(image).scaled(
            target->size(),
            Qt::KeepAspectRatio,
            Qt::SmoothTransformation));
}

void loadDetailArtwork(
    QNetworkAccessManager* manager,
    QLabel* target,
    const QString& artwork,
    const QString& fallbackText) {
    if (!manager || !target) return;

    const QString safe = detailArtworkUrl(artwork);
    target->setTextFormat(Qt::PlainText);
    target->setText(fallbackText);
    target->setPixmap({});
    target->setAlignment(Qt::AlignCenter);
    if (safe.isEmpty()) return;

    QNetworkRequest request{QUrl(safe)};
    request.setAttribute(
        QNetworkRequest::RedirectPolicyAttribute,
        QNetworkRequest::NoLessSafeRedirectPolicy);
    request.setRawHeader("User-Agent", "TRU-Desktop/0.05.5");

    auto* reply = manager->get(request);
    auto bytes = std::make_shared<QByteArray>();
    QObject::connect(reply, &QNetworkReply::finished,
                     reply, &QObject::deleteLater);
    QObject::connect(reply, &QIODevice::readyRead, reply,
                     [reply, bytes] {
        bytes->append(reply->readAll());
        if (bytes->size() > 4 * 1024 * 1024) {
            reply->setProperty("truArtworkOversize", true);
            reply->abort();
        }
    });
    QTimer::singleShot(10000, reply, [reply] {
        if (reply->isRunning()) {
            reply->setProperty("truArtworkTimeout", true);
            reply->abort();
        }
    });
    QObject::connect(reply, &QNetworkReply::finished, target,
                     [reply, bytes, target, fallbackText] {
        bytes->append(reply->readAll());
        if (reply->error() != QNetworkReply::NoError ||
            reply->property("truArtworkOversize").toBool() ||
            reply->property("truArtworkTimeout").toBool() ||
            bytes->isEmpty()) {
            target->setText(fallbackText);
            return;
        }
        setArtworkFromBytes(target, bytes, fallbackText);
    });
}

void showStyledDetailsDialog(
    QWidget* parent,
    const QString& windowTitle,
    const QString& heading,
    const QString& subtitle,
    const QString& artwork,
    const QString& artworkFallback,
    const QString& accent,
    const QList<DetailRow>& rows,
    const QJsonObject& raw,
    const QString& jsonHelp) {

    QDialog dialog(parent);
    dialog.setModal(true);
    dialog.setWindowTitle(windowTitle);
    dialog.resize(760, 720);
    dialog.setMinimumSize(560, 480);

    QString sheet = R"TRUDETAIL(
        QDialog { background-color:#050c1a; }
        QScrollArea { background:transparent; border:none; }
        QWidget#truDetailViewport { background:transparent; }
        QFrame#truDetailShell {
            background:qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #17193a, stop:1 #141532);
            border:1px solid __ACCENT__;
            border-radius:18px;
        }
        QLabel#truDetailTitle { color:__ACCENT__; font-size:27px; font-weight:800; }
        QLabel#truDetailName { color:#ffffff; font-size:20px; font-weight:700; }
        QLabel#truDetailSubtitle { color:#b7b9d7; font-size:12px; font-weight:700; letter-spacing:1.5px; }
        QLabel#truDetailHint { color:#99abc2; font-size:13px; }
        QLabel#truDetailArtwork {
            background-color:#1b2143;
            border:1px solid __ACCENT__;
            border-radius:26px;
            color:__ACCENT__;
            font-weight:800;
        }
        QFrame#truDivider { background-color:#183857; min-height:1px; max-height:1px; }
        QPushButton {
            background-color:#102b43; color:#e4f8ff; border:1px solid #2a7591;
            border-radius:10px; padding:10px 18px; font-weight:700;
        }
        QPushButton:hover { border-color:__ACCENT__; background-color:#163b59; }
        QPushButton#truJsonToggle:checked { border-color:__ACCENT__; background-color:#252052; }
        QPlainTextEdit#truJsonView {
            background-color:#0b1528; color:#d8eef8; border:1px solid #29536f;
            border-radius:12px; padding:10px;
            font-family:'DejaVu Sans Mono','Menlo','Consolas'; font-size:13px;
        }
        QLabel#truJsonLabel { color:#88a7be; font-size:12px; letter-spacing:1.1px; font-weight:700; }
    )TRUDETAIL";
    if (QSettings("TRUBlockchain", "CoreDesktop")
            .value("theme", "dark").toString().trimmed().toLower() == "light") {
        sheet += R"TRULIGHTDETAIL(
            QDialog { background-color:#f4f7fb; }
            QFrame#truDetailShell { background:#ffffff; }
            QLabel#truDetailName { color:#173548; }
            QLabel#truDetailSubtitle { color:#667d8f; }
            QLabel#truDetailHint { color:#627b8d; }
            QLabel#truDetailArtwork { background-color:#edf4f7; }
            QFrame#truDivider { background-color:#b8cbd6; }
            QPushButton {
                background-color:#e7f0f5; color:#17394c;
                border-color:#8caabb;
            }
            QPushButton:hover { background-color:#d8ecef; }
            QPushButton#truJsonToggle:checked { background-color:#e9e2f3; }
            QPlainTextEdit#truJsonView {
                background-color:#ffffff; color:#17394c;
                border-color:#9eb8c7;
            }
            QLabel#truJsonLabel { color:#5f798b; }
        )TRULIGHTDETAIL";
    }
    sheet.replace("__ACCENT__", accent);
    dialog.setStyleSheet(sheet);

    auto* artManager = new QNetworkAccessManager(&dialog);
    auto* root = new QVBoxLayout(&dialog);
    root->setContentsMargins(12, 12, 12, 12);

    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

    auto* viewport = new QWidget;
    viewport->setObjectName("truDetailViewport");
    auto* viewportLayout = new QVBoxLayout(viewport);
    viewportLayout->setContentsMargins(6, 6, 6, 6);

    auto* shell = new QFrame;
    shell->setObjectName("truDetailShell");
    auto* shellLayout = new QVBoxLayout(shell);
    shellLayout->setContentsMargins(26, 24, 26, 22);
    shellLayout->setSpacing(16);

    auto* header = new QHBoxLayout;
    auto* title = new QLabel(windowTitle);
    title->setObjectName("truDetailTitle");
    auto* close = new QPushButton(QString::fromUtf8("×"));
    close->setFixedSize(42, 42);
    close->setStyleSheet(
        "QPushButton{background:transparent;color:#bdb8d7;border:none;font-size:30px;font-weight:600;padding:0;}"
        "QPushButton:hover{color:#ffffff;}");
    header->addWidget(title);
    header->addStretch();
    header->addWidget(close);
    shellLayout->addLayout(header);

    auto* divider1 = new QFrame;
    divider1->setObjectName("truDivider");
    shellLayout->addWidget(divider1);

    auto* top = new QHBoxLayout;
    top->setSpacing(18);
    auto* art = new QLabel(artworkFallback);
    art->setObjectName("truDetailArtwork");
    art->setAlignment(Qt::AlignCenter);
    art->setFixedSize(78, 78);
    loadDetailArtwork(artManager, art, artwork, artworkFallback);
    top->addWidget(art, 0, Qt::AlignTop);

    auto* identity = new QVBoxLayout;
    auto* nameLabel = new QLabel(heading);
    nameLabel->setObjectName("truDetailName");
    nameLabel->setWordWrap(true);
    auto* subLabel = new QLabel(subtitle);
    subLabel->setObjectName("truDetailSubtitle");
    subLabel->setWordWrap(true);
    auto* hint = new QLabel(jsonHelp);
    hint->setObjectName("truDetailHint");
    hint->setWordWrap(true);
    identity->addWidget(nameLabel);
    identity->addWidget(subLabel);
    identity->addSpacing(4);
    identity->addWidget(hint);
    top->addLayout(identity, 1);
    shellLayout->addLayout(top);

    auto* divider2 = new QFrame;
    divider2->setObjectName("truDivider");
    shellLayout->addWidget(divider2);

    auto* grid = new QGridLayout;
    grid->setHorizontalSpacing(18);
    grid->setVerticalSpacing(14);
    grid->setColumnStretch(1, 1);
    int row = 0;
    for (const auto& item : rows) {
        if (item.value.trimmed().isEmpty()) continue;
        addDetailRow(grid, row++, item);
    }
    shellLayout->addLayout(grid);

    auto* divider3 = new QFrame;
    divider3->setObjectName("truDivider");
    shellLayout->addWidget(divider3);

    auto* jsonLabel = new QLabel("RAW JSON");
    jsonLabel->setObjectName("truJsonLabel");
    jsonLabel->hide();
    shellLayout->addWidget(jsonLabel);

    auto* jsonView = new QPlainTextEdit;
    jsonView->setObjectName("truJsonView");
    jsonView->setReadOnly(true);
    jsonView->setPlainText(QString::fromUtf8(QJsonDocument(raw).toJson(QJsonDocument::Indented)));
    jsonView->setMinimumHeight(210);
    jsonView->hide();
    shellLayout->addWidget(jsonView);

    auto* actions = new QHBoxLayout;
    auto* toggle = new QPushButton("View JSON");
    toggle->setObjectName("truJsonToggle");
    toggle->setCheckable(true);
    auto* ok = new QPushButton("Close");
    actions->addStretch();
    actions->addWidget(toggle);
    actions->addWidget(ok);
    shellLayout->addLayout(actions);

    viewportLayout->addWidget(shell);
    viewportLayout->addStretch();
    scroll->setWidget(viewport);
    root->addWidget(scroll, 1);
    QObject::connect(close, &QPushButton::clicked, &dialog, &QDialog::accept);
    QObject::connect(ok, &QPushButton::clicked, &dialog, &QDialog::accept);
    QObject::connect(toggle, &QPushButton::toggled, &dialog,
                     [toggle, jsonView, jsonLabel](bool on) {
        toggle->setText(on ? "Hide JSON" : "View JSON");
        jsonView->setVisible(on);
        jsonLabel->setVisible(on);
    });

    dialog.exec();
}

} // namespace

DesktopAssetsWidget::DesktopAssetsWidget(
    DesktopRpc* rpc,
    DesktopWalletWidget* wallet,
    QWidget* parent)
    : QWidget(parent),
      rpc_(rpc),
      wallet_(wallet),
      imageNetwork_(new QNetworkAccessManager(this)) {

    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(14, 14, 14, 14);
    root->setSpacing(12);

    auto* hero = new QFrame;
    hero->setObjectName("truAssetsHero");
    auto* heroLayout = new QHBoxLayout(hero);
    heroLayout->setContentsMargins(18, 15, 18, 15);

    auto* titleStack = new QVBoxLayout;
    auto* eyebrow = new QLabel("ON-CHAIN ASSET GALLERY");
    eyebrow->setObjectName("truAssetEyebrow");
    auto* title = new QLabel("Tokens & TRUScripts");
    title->setObjectName("truAssetTitle");
    auto* subtitle = new QLabel(
        "Read-only ownership view for the addresses in your standalone wallet. "
        "Token artwork follows on-chain metadata; TRUScripts preview image references when present.");
    subtitle->setObjectName("truAssetSubtitle");
    subtitle->setWordWrap(true);

    titleStack->addWidget(eyebrow);
    titleStack->addWidget(title);
    titleStack->addWidget(subtitle);

    heroLayout->addLayout(titleStack, 1);

    refresh_ = new QPushButton("Refresh Assets");
    refresh_->setObjectName("truPrimaryAction");
    heroLayout->addWidget(refresh_, 0, Qt::AlignVCenter);

    root->addWidget(hero);

    status_ = new QLabel(
        "Unlock the standalone wallet, then refresh to read its on-chain assets.");
    status_->setObjectName("truAssetStatus");
    status_->setWordWrap(true);
    status_->setTextFormat(Qt::PlainText);
    root->addWidget(status_);

    auto* tabs = new QTabWidget;
    tabs->setObjectName("truAssetTabs");

    QWidget* tokenHost = nullptr;
    auto* tokenPage = new QWidget;
    auto* tokenPageLayout = new QVBoxLayout(tokenPage);
    tokenPageLayout->setContentsMargins(4, 8, 4, 4);

    auto* tokenHeader = new QHBoxLayout;
    auto* tokenHeading = new QLabel("TOKENS");
    tokenHeading->setObjectName("truAssetSectionTitle");
    tokenCount_ = makeCountBadge("0 holdings");
    tokenHeader->addWidget(tokenHeading);
    tokenHeader->addStretch();
    tokenHeader->addWidget(tokenCount_);
    tokenPageLayout->addLayout(tokenHeader);
    tokenPageLayout->addWidget(makeAssetScroll(tokenHost, tokenGrid_), 1);

    QWidget* scriptHost = nullptr;
    auto* scriptPage = new QWidget;
    auto* scriptPageLayout = new QVBoxLayout(scriptPage);
    scriptPageLayout->setContentsMargins(4, 8, 4, 4);

    auto* scriptHeader = new QHBoxLayout;
    auto* scriptHeading = new QLabel("TRUSCRIPTS");
    scriptHeading->setObjectName("truAssetSectionTitle");
    scriptCount_ = makeCountBadge("0 inscriptions");
    scriptHeader->addWidget(scriptHeading);
    scriptHeader->addStretch();
    scriptHeader->addWidget(scriptCount_);
    scriptPageLayout->addLayout(scriptHeader);
    scriptPageLayout->addWidget(makeAssetScroll(scriptHost, scriptGrid_), 1);

    tabs->addTab(tokenPage, "Tokens");
    tabs->addTab(scriptPage, "TRUScripts");
    root->addWidget(tabs, 1);

    auto* privacy = new QLabel(
        "Artwork privacy note: external image metadata may contact third-party HTTP/HTTPS hosts. "
        "IPFS artwork is requested through https://ipfs.io. Images are treated as untrusted media, "
        "size-limited, decoded only as images, and never executed.");
    privacy->setObjectName("truAssetPrivacy");
    privacy->setWordWrap(true);
    root->addWidget(privacy);

    connect(refresh_, &QPushButton::clicked,
            this, [this] { refreshAssets(); });

    renderTokens({});
    renderScripts({});
}

void DesktopAssetsWidget::clearGrid(QGridLayout* grid) {
    if (!grid) return;
    while (auto* item = grid->takeAt(0)) {
        if (auto* widget = item->widget()) delete widget;
        delete item;
    }
}

QString DesktopAssetsWidget::shortText(
    const QString& value, int maxChars) {
    const QString text = value.simplified();
    if (text.size() <= maxChars) return text;
    return text.left(std::max(0, maxChars - 1)) + QChar(0x2026);
}

QString DesktopAssetsWidget::safeArtworkUrl(const QString& value) {
    const QString raw = normalizeArtworkValue(value);
    if (raw.isEmpty()) return {};

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

QString DesktopAssetsWidget::truscriptArtwork(const QString& data) {
    const QString direct = safeArtworkUrl(data);
    if (!direct.isEmpty()) return direct;

    QJsonParseError error;
    const auto document = QJsonDocument::fromJson(
        data.toUtf8(), &error);
    if (error.error == QJsonParseError::NoError &&
        document.isObject()) {
        const auto object = document.object();
        for (const char* key : {"image", "image_url", "ipfs_image"}) {
            const QString raw = normalizeArtworkValue(
                object.value(key).toString());
            QString candidate = safeArtworkUrl(raw);
            if (candidate.isEmpty() &&
                QString::fromLatin1(key) == "ipfs_image" &&
                !raw.isEmpty() && !raw.contains("://")) {
                candidate = safeArtworkUrl("ipfs://" + raw);
            }
            if (!candidate.isEmpty()) return candidate;
        }
    }

    static const QRegularExpression markdown(
        QStringLiteral("!\\[[^\\]]*\\]\\(([^)]+)\\)"));
    const auto match = markdown.match(data);
    if (match.hasMatch())
        return safeArtworkUrl(match.captured(1));

    static const QRegularExpression imagePrefix(
        QStringLiteral("^(?:image|image_url|ipfs_image)\\s*[:=]\\s*(\\S+)$"),
        QRegularExpression::CaseInsensitiveOption);
    const QString trimmed = data.trimmed();
    const auto prefixMatch = imagePrefix.match(trimmed);
    if (prefixMatch.hasMatch()) {
        QString candidate = safeArtworkUrl(prefixMatch.captured(1));
        if (candidate.isEmpty() &&
            trimmed.startsWith("ipfs_image", Qt::CaseInsensitive) &&
            !prefixMatch.captured(1).contains("://")) {
            candidate = safeArtworkUrl(
                "ipfs://" + prefixMatch.captured(1));
        }
        return candidate;
    }

    return {};
}

int tokenDecimals(
    const QJsonObject& metadata,
    const QString& type) {
    if (type.compare("NFT", Qt::CaseInsensitive) == 0)
        return 0;

    const QJsonValue value = metadata.value("decimals");
    int decimals = 8;
    if (value.isDouble()) {
        decimals = value.toInt(8);
    } else if (value.isString()) {
        bool ok = false;
        const int parsed = value.toString().trimmed().toInt(&ok);
        if (ok) decimals = parsed;
    }
    return std::max(0, std::min(decimals, 18));
}

bool rawTokenAmount(
    const QJsonValue& amount,
    std::uint64_t& rawOut) {
    rawOut = 0;
    QString text;
    if (amount.isString()) {
        text = amount.toString().trimmed();
    } else if (amount.isDouble()) {
        const double d = amount.toDouble();
        if (d < 0.0 || d > 9007199254740991.0)
            return false;
        const auto n = static_cast<std::uint64_t>(d);
        if (static_cast<double>(n) != d)
            return false;
        rawOut = n;
        return true;
    } else {
        return false;
    }

    static const QRegularExpression digits(
        QStringLiteral("^[0-9]+$"));
    if (!digits.match(text).hasMatch())
        return false;
    bool ok = false;
    const qulonglong parsed = text.toULongLong(&ok);
    if (!ok) return false;
    rawOut = static_cast<std::uint64_t>(parsed);
    return true;
}

bool parseTokenDisplayAmount(
    QString text,
    int decimals,
    std::uint64_t& rawOut) {
    rawOut = 0;
    text = text.trimmed();
    if (text.isEmpty() || text.startsWith('-'))
        return false;
    if (text.startsWith('+'))
        text.remove(0, 1);

    const int dot = text.indexOf('.');
    if (dot >= 0 && text.indexOf('.', dot + 1) >= 0)
        return false;

    QString whole = dot >= 0 ? text.left(dot) : text;
    QString fraction = dot >= 0 ? text.mid(dot + 1) : QString();
    if (whole.isEmpty()) whole = "0";

    static const QRegularExpression digits(
        QStringLiteral("^[0-9]+$"));
    if (!digits.match(whole).hasMatch())
        return false;
    if (!fraction.isEmpty() &&
        !digits.match(fraction).hasMatch())
        return false;
    if (fraction.size() > decimals)
        return false;

    fraction += QString(decimals - fraction.size(), QChar('0'));
    QString combined = whole + fraction;
    while (combined.size() > 1 && combined.startsWith('0'))
        combined.remove(0, 1);

    bool ok = false;
    const qulonglong parsed = combined.toULongLong(&ok);
    if (!ok) return false;
    rawOut = static_cast<std::uint64_t>(parsed);
    return true;
}

QString DesktopAssetsWidget::decimalAmount(
    const QJsonValue& amount,
    const QJsonObject& metadata,
    const QString& type) {
    const int decimals = tokenDecimals(metadata, type);

    QString atoms;
    if (amount.isString()) {
        atoms = amount.toString().trimmed();
    } else if (amount.isDouble()) {
        const double value = amount.toDouble();
        if (value >= 0.0 && value <= 9007199254740991.0)
            atoms = QString::number(value, 'f', 0);
    }

    if (atoms.isEmpty()) return "—";
    if (atoms.startsWith('+')) atoms.remove(0, 1);
    static const QRegularExpression digits(QStringLiteral("^[0-9]+$"));
    if (!digits.match(atoms).hasMatch()) return atoms;

    while (atoms.size() > 1 && atoms.startsWith('0')) atoms.remove(0, 1);
    if (decimals == 0) return atoms;

    while (atoms.size() <= decimals) atoms.prepend('0');
    const int split = atoms.size() - decimals;
    QString display = atoms.left(split) + "." + atoms.mid(split);
    while (display.endsWith('0')) display.chop(1);
    if (display.endsWith('.')) display.chop(1);
    return display;
}

void DesktopAssetsWidget::loadArtwork(
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
    request.setRawHeader("User-Agent", "TRU-Desktop/0.05.5");

    auto* reply = imageNetwork_->get(request);
    auto bytes = std::make_shared<QByteArray>();
    connect(reply, &QNetworkReply::finished,
            reply, &QObject::deleteLater);

    connect(reply, &QIODevice::readyRead, reply,
            [reply, bytes] {
        bytes->append(reply->readAll());
        if (bytes->size() > 4 * 1024 * 1024) {
            reply->setProperty("truArtworkOversize", true);
            reply->abort();
        }
    });

    QTimer::singleShot(10000, reply, [reply] {
        if (reply->isRunning()) {
            reply->setProperty("truArtworkTimeout", true);
            reply->abort();
        }
    });

    connect(reply, &QNetworkReply::finished, target,
            [reply, bytes, target, fallbackText] {
        bytes->append(reply->readAll());

        if (reply->error() != QNetworkReply::NoError ||
            reply->property("truArtworkOversize").toBool() ||
            reply->property("truArtworkTimeout").toBool() ||
            bytes->isEmpty()) {
            target->setText(fallbackText);
            return;
        }

        setArtworkFromBytes(target, bytes, fallbackText);
    });
}

void DesktopAssetsWidget::renderTokens(const QJsonArray& tokens) {
    clearGrid(tokenGrid_);
    tokenCount_->setText(
        QString("%1 holding%2")
            .arg(tokens.size())
            .arg(tokens.size() == 1 ? "" : "s"));

    if (tokens.isEmpty()) {
        auto* empty = new QLabel(
            "No token holdings found for the unlocked standalone wallet.");
        empty->setObjectName("truAssetEmpty");
        empty->setAlignment(Qt::AlignCenter);
        tokenGrid_->addWidget(empty, 0, 0, 1, 3);
        return;
    }

    int cardIndex = 0;
    for (const QJsonValue& value : tokens) {
        if (!value.isObject()) continue;
        const QJsonObject token = value.toObject();
        const QString type = token.value("type").toString("Unknown");
        if (type.compare("TRUSCRIPT", Qt::CaseInsensitive) == 0)
            continue;

        QJsonObject meta = token.value("meta").toObject();
        if (meta.isEmpty() && token.value("metadata").isObject())
            meta = token.value("metadata").toObject();

        const QString tokenId = token.value("tokenID").toString("Unknown");
        const QString name = metadataText(meta, "name", tokenId);
        const QString symbol = metadataText(meta, "symbol");
        const QString amount = decimalAmount(
            token.value("amount"), meta, type);
        const QString accent = tokenAccent(meta);

        QString artwork = metadataText(meta, "image");
        if (artwork.isEmpty()) artwork = metadataText(meta, "image_url");
        if (artwork.isEmpty()) {
            QString ipfsArtwork = normalizeArtworkValue(
                metadataText(meta, "ipfs_image"));
            if (!ipfsArtwork.isEmpty()) {
                if (safeArtworkUrl(ipfsArtwork).isEmpty() &&
                    !ipfsArtwork.contains("://")) {
                    ipfsArtwork.prepend("ipfs://");
                }
                artwork = ipfsArtwork;
            }
        }

        auto* card = new QFrame;
        card->setObjectName("truAssetCard");
        card->setMinimumWidth(235);
        card->setMaximumWidth(360);
        card->setStyleSheet(
            QString("QFrame#truAssetCard{border:1px solid %1;border-left:4px solid %1;}")
                .arg(accent));

        auto* layout = new QVBoxLayout(card);
        layout->setContentsMargins(12, 12, 12, 12);
        layout->setSpacing(8);

        auto* image = new QLabel(type.toUpper() + "\nARTWORK");
        image->setObjectName("truAssetImage");
        image->setFixedHeight(150);
        image->setMinimumWidth(210);
        image->setAlignment(Qt::AlignCenter);
        layout->addWidget(image);
        loadArtwork(image, artwork, type.toUpper() + "\nARTWORK");

        auto* nameLabel = new QLabel(
            symbol.isEmpty() ? name : name + "  ·  " + symbol);
        nameLabel->setObjectName("truAssetCardTitle");
        nameLabel->setWordWrap(true);
        nameLabel->setTextFormat(Qt::PlainText);
        layout->addWidget(nameLabel);

        auto* typeLabel = new QLabel(type.toUpper());
        typeLabel->setObjectName("truAssetTypeBadge");
        typeLabel->setTextFormat(Qt::PlainText);
        layout->addWidget(typeLabel, 0, Qt::AlignLeft);

        auto* amountLabel = new QLabel("Balance  " + amount);
        amountLabel->setObjectName("truAssetAmount");
        amountLabel->setTextFormat(Qt::PlainText);
        layout->addWidget(amountLabel);

        auto* idLabel = new QLabel("ID  " + shortText(tokenId, 30));
        idLabel->setObjectName("truAssetMeta");
        idLabel->setTextFormat(Qt::PlainText);
        idLabel->setToolTip(Qt::convertFromPlainText(tokenId));
        layout->addWidget(idLabel);

        auto* actions = new QHBoxLayout;
        actions->setSpacing(8);
        auto* send = new QPushButton("Send Token");
        send->setObjectName("truPrimaryAction");
        auto* details = new QPushButton("Details");
        details->setObjectName("truSecondaryAction");
        actions->addWidget(send);
        actions->addWidget(details);
        layout->addLayout(actions);

        connect(send, &QPushButton::clicked, card,
                [this, token, meta] { sendToken(token, meta); });

        connect(details, &QPushButton::clicked, card,
                [this, token, meta, name, type, amount, artwork, accent] {
            const QString tokenId = token.value("tokenID").toString();
            const QString owner = token.value("owner").toString();
            QString colour = metadataText(meta, "dynamic_visual");
            if (colour.isEmpty()) colour = metadataText(meta, "colour");
            QString imageField = metadataText(meta, "image");
            if (imageField.isEmpty()) imageField = metadataText(meta, "image_url");
            if (imageField.isEmpty()) imageField = metadataText(meta, "ipfs_image");

            const QList<DetailRow> rows = {
                {"Name", name},
                {"Asset class", type.toUpper()},
                {"Balance", amount, true},
                {"Token ID", tokenId, true},
                {"Owner", owner, true},
                {"Symbol", metadataText(meta, "symbol")},
                {"Decimals", metadataText(meta, "decimals")},
                {"Description", metadataText(meta, "description")},
                {"Colour", colour},
                {"Image", imageField, true},
                {"Meta ID", metadataText(meta, "meta_id"), true},
                {"Meta hash", metadataText(meta, "meta_hash"), true},
                {"AI engine", metadataText(meta, "ai_engine")},
                {"Creator signature", metadataText(meta, "creator_signature"), true},
                {"Dynamic morph", metadataText(meta, "dynamic_morph")},
                {"Last evolution", metadataText(meta, "last_evolution")},
                {"Style descriptor", metadataText(meta, "style_descriptor")},
                {"Update interval", metadataText(meta, "update_interval")}
            };

            showStyledDetailsDialog(
                this,
                "Token Metadata",
                name,
                QString(type.toUpper()) + "  •  Metadata",
                artwork,
                type.left(1).toUpper(),
                accent,
                rows,
                token,
                "Clean ownership and metadata view from the connected TRU node. Raw JSON stays hidden until requested.");
        });

        const int row = cardIndex / 3;
        const int column = cardIndex % 3;
        tokenGrid_->addWidget(card, row, column);
        ++cardIndex;
    }

    if (cardIndex == 0) {
        auto* empty = new QLabel("No standard token holdings found.");
        empty->setObjectName("truAssetEmpty");
        empty->setAlignment(Qt::AlignCenter);
        tokenGrid_->addWidget(empty, 0, 0, 1, 3);
    }
}

void DesktopAssetsWidget::renderScripts(const QJsonArray& scripts) {
    clearGrid(scriptGrid_);
    scriptCount_->setText(
        QString("%1 inscription%2")
            .arg(scripts.size())
            .arg(scripts.size() == 1 ? "" : "s"));

    if (scripts.isEmpty()) {
        auto* empty = new QLabel(
            "No TRUScripts found for the unlocked standalone wallet.");
        empty->setObjectName("truAssetEmpty");
        empty->setAlignment(Qt::AlignCenter);
        scriptGrid_->addWidget(empty, 0, 0, 1, 3);
        return;
    }

    int cardIndex = 0;
    for (const QJsonValue& value : scripts) {
        if (!value.isObject()) continue;
        const QJsonObject script = value.toObject();
        const QString data = script.value("data").toString();
        const QString txid = script.value("txid").toString();
        const qint64 timestamp =
            static_cast<qint64>(script.value("timestamp").toDouble());
        const QString indexText = script.value("inscriptionIndex").toVariant().toString();
        const QString sizeText = script.value("sizeBytes").toVariant().toString();
        const QString artwork = truscriptArtwork(data);

        auto* card = new QFrame;
        card->setObjectName("truAssetCard");
        card->setMinimumWidth(235);
        card->setMaximumWidth(360);

        auto* layout = new QVBoxLayout(card);
        layout->setContentsMargins(12, 12, 12, 12);
        layout->setSpacing(8);

        if (!artwork.isEmpty()) {
            auto* image = new QLabel("TRUSCRIPT\nMEDIA");
            image->setObjectName("truAssetImage");
            image->setFixedHeight(150);
            image->setMinimumWidth(210);
            layout->addWidget(image);
            loadArtwork(image, artwork, "TRUSCRIPT\nMEDIA");
        } else {
            auto* glyph = new QLabel("</>  TRUSCRIPT");
            glyph->setObjectName("truScriptGlyph");
            glyph->setAlignment(Qt::AlignCenter);
            glyph->setFixedHeight(72);
            layout->addWidget(glyph);
        }

        auto* title = new QLabel(
            "Inscription #" + (indexText.isEmpty() ? "—" : indexText));
        title->setObjectName("truAssetCardTitle");
        title->setTextFormat(Qt::PlainText);
        layout->addWidget(title);

        auto* preview = new QLabel(
            data.isEmpty() ? "No inscription text" : shortText(data, 110));
        preview->setObjectName("truScriptPreview");
        preview->setWordWrap(true);
        preview->setTextFormat(Qt::PlainText);
        layout->addWidget(preview);

        QString meta = (sizeText.isEmpty() ? "0" : sizeText) + " bytes";
        if (timestamp > 0) {
            meta += "  ·  " +
                QDateTime::fromSecsSinceEpoch(timestamp)
                    .toLocalTime().toString("yyyy-MM-dd");
        }
        auto* metaLabel = new QLabel(meta);
        metaLabel->setObjectName("truAssetMeta");
        metaLabel->setTextFormat(Qt::PlainText);
        layout->addWidget(metaLabel);

        auto* tx = new QLabel("TX  " + shortText(txid, 30));
        tx->setObjectName("truAssetMeta");
        tx->setTextFormat(Qt::PlainText);
        tx->setToolTip(Qt::convertFromPlainText(txid));
        layout->addWidget(tx);

        auto* actions = new QHBoxLayout;
        actions->setSpacing(8);
        auto* send = new QPushButton("Send TRUScript");
        send->setObjectName("truPrimaryAction");
        auto* details = new QPushButton("Details");
        details->setObjectName("truSecondaryAction");
        actions->addWidget(send);
        actions->addWidget(details);
        layout->addLayout(actions);

        connect(send, &QPushButton::clicked, card,
                [this, script] { sendTRUScript(script); });

        connect(details, &QPushButton::clicked, card,
                [this, script, data, artwork, txid, indexText, sizeText, timestamp] {
            const QString owner = script.value("ownerAddress").toString();
            QString when;
            if (timestamp > 0) {
                when = QDateTime::fromSecsSinceEpoch(timestamp)
                    .toLocalTime().toString("yyyy-MM-dd hh:mm:ss");
            }
            const QList<DetailRow> rows = {
                {"Inscription", indexText},
                {"Owner", owner, true},
                {"Transaction", txid, true},
                {"Size", sizeText.isEmpty() ? QString() : sizeText + " bytes"},
                {"Timestamp", when},
                {"Preview", data.isEmpty() ? QString("No inscription text") : data, true},
                {"Artwork", artwork, true}
            };
            showStyledDetailsDialog(
                this,
                "TRUScript Details",
                indexText.isEmpty() ? QString("TRUScript inscription")
                                    : QString("Inscription #") + indexText,
                "On-chain inscription  •  Read-only preview",
                artwork,
                "</>",
                "#35f0ff",
                rows,
                script,
                "Raw inscription data is preserved exactly; media preview is display-only. Raw JSON stays hidden until requested.");
        });

        const int row = cardIndex / 3;
        const int column = cardIndex % 3;
        scriptGrid_->addWidget(card, row, column);
        ++cardIndex;
    }
}

void DesktopAssetsWidget::loadScriptsSequential(
    const QStringList& addresses,
    int index,
    QJsonArray collected,
    QStringList errors,
    int tokenCount) {
    if (index >= addresses.size()) {
        renderScripts(collected);
        refresh_->setEnabled(true);
        QString summary =
            QString("%1 token holding%2  ·  %3 TRUScript%4  ·  %5 wallet address%6")
                .arg(tokenCount)
                .arg(tokenCount == 1 ? "" : "s")
                .arg(collected.size())
                .arg(collected.size() == 1 ? "" : "s")
                .arg(addresses.size())
                .arg(addresses.size() == 1 ? "" : "es");
        if (!errors.isEmpty())
            summary += "  ·  Some reads failed: " + errors.join(" | ");
        status_->setText(summary);
        return;
    }

    QJsonObject params;
    params.insert("ownerAddress", addresses.at(index));
    rpc_->call(
        "getTRUScripts", objectParams(params),
        [this, addresses, index, collected, errors, tokenCount](
            const QJsonValue& value,
            const QByteArray&,
            const QString& error) mutable {
            if (!error.isEmpty()) {
                errors.push_back(
                    shortText(addresses.at(index), 18) + ": " + error);
            } else if (value.isArray()) {
                for (const auto& item : value.toArray())
                    collected.append(item);
            }
            loadScriptsSequential(
                addresses, index + 1,
                std::move(collected),
                std::move(errors),
                tokenCount);
        });
}

void DesktopAssetsWidget::sendToken(
    const QJsonObject& token,
    const QJsonObject& metadata) {
    if (!rpc_ || !wallet_ || !wallet_->walletUnlocked()) {
        QMessageBox::warning(
            this, "Send Token",
            "Unlock the standalone wallet first.");
        return;
    }

    const QString tokenID =
        token.value("tokenID").toString().trimmed();
    const QString owner =
        token.value("owner").toString().trimmed();
    const QString type =
        token.value("type").toString().trimmed().toUpper();

    if (tokenID.isEmpty() || owner.isEmpty() ||
        !wallet_->walletAddresses().contains(owner)) {
        QMessageBox::warning(
            this, "Send Token",
            "This holding is not controlled by the unlocked standalone wallet.");
        return;
    }

    std::uint64_t availableRaw = 0;
    if (!rawTokenAmount(token.value("amount"), availableRaw) ||
        availableRaw == 0) {
        QMessageBox::warning(
            this, "Send Token",
            "The node did not return an exact token amount.");
        return;
    }

    bool ok = false;
    const QString recipient = QInputDialog::getText(
        this, "Send Token", "Recipient TRU address:",
        QLineEdit::Normal, {}, &ok).trimmed();
    if (!ok) return;
    if (!wallet_->validateWalletAddress(recipient)) {
        QMessageBox::warning(
            this, "Send Token",
            "Recipient is not a valid TRU mainnet address.");
        return;
    }
    if (recipient == owner) {
        QMessageBox::warning(
            this, "Send Token",
            "Recipient is the current owner address.");
        return;
    }

    const int decimals = tokenDecimals(metadata, type);
    std::uint64_t sendRaw = availableRaw;

    if (type != "NFT") {
        const QString currentDisplay =
            decimalAmount(token.value("amount"), metadata, type);
        const QString entered = QInputDialog::getText(
            this,
            "Send Token",
            QString("Amount to send (%1 available):")
                .arg(currentDisplay),
            QLineEdit::Normal,
            currentDisplay,
            &ok);
        if (!ok) return;

        if (!parseTokenDisplayAmount(
                entered, decimals, sendRaw) ||
            sendRaw == 0 ||
            sendRaw > availableRaw) {
            QMessageBox::warning(
                this, "Send Token",
                "Amount is invalid or exceeds the confirmed holding.");
            return;
        }
    }

    if (type == "NFT" && sendRaw != availableRaw) {
        QMessageBox::warning(
            this, "Send Token",
            "NFT holdings must be transferred in full.");
        return;
    }

    const QString displaySend =
        decimalAmount(
            QJsonValue(QString::number(
                static_cast<qulonglong>(sendRaw))),
            metadata,
            type);

    if (QMessageBox::question(
            this,
            "Confirm Token Transfer",
            QString(
                "Token: %1\n"
                "Type: %2\n"
                "Amount: %3\n"
                "From: %4\n"
                "To: %5\n\n"
                "TRU Desktop will ask Core only to BUILD the unsigned "
                "transaction. Every input is then verified and signed "
                "locally by this standalone wallet.")
                .arg(tokenID, type, displaySend, owner, recipient),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No) != QMessageBox::Yes) {
        return;
    }

    constexpr std::uint64_t feeAtoms = 10000ULL;
    constexpr std::uint64_t minimumFeeUtxo = feeAtoms + 546ULL;

    wallet_->selectSafeFeeUtxo(
        minimumFeeUtxo,
        [this, tokenID, owner, recipient, sendRaw](
            QJsonObject feeUtxo,
            QString feeError) {
            if (!feeError.isEmpty()) {
                QMessageBox::warning(
                    this, "Send Token", feeError);
                return;
            }

            QJsonObject params;
            params.insert("tokenID", tokenID);
            params.insert(
                "amount",
                QString::number(
                    static_cast<qulonglong>(sendRaw)));
            params.insert("recipient", recipient);
            params.insert("senderAddress", owner);
            params.insert("feeUtxo", feeUtxo);
            params.insert("fee", 10000);

            rpc_->call(
                "createsendtokentransaction",
                objectParams(params),
                [this, tokenID, owner, recipient](
                    const QJsonValue& value,
                    const QByteArray&,
                    const QString& error) {
                    if (!error.isEmpty() || !value.isObject()) {
                        QMessageBox::warning(
                            this,
                            "Send Token",
                            error.isEmpty()
                                ? "Core returned an invalid unsigned token transaction."
                                : error);
                        return;
                    }

                    const QJsonObject built = value.toObject();
                    if (built.value("tokenID").toString() != tokenID ||
                        built.value("from").toString() != owner ||
                        built.value("to").toString() != recipient ||
                        !built.value("metadataAttachedBeforeSigning")
                             .toBool(false)) {
                        QMessageBox::critical(
                            this,
                            "Send Token",
                            "Unsigned token transaction failed the Desktop "
                            "binding check. Nothing was signed.");
                        return;
                    }

                    const QString unsignedHex =
                        built.value("unsignedTxHex").toString();
                    const QJsonArray signingInputs =
                        built.value("signingInputs").toArray();
                    const QString expectedTxid =
                        built.value("txid").toString();

                    QString signedHex;
                    QString localTxid;
                    QString signError;
                    if (!wallet_->signPreparedTransaction(
                            unsignedHex,
                            signingInputs,
                            signedHex,
                            localTxid,
                            signError)) {
                        QMessageBox::critical(
                            this,
                            "Send Token",
                            "Local signing refused: " + signError);
                        return;
                    }

                    if (!expectedTxid.isEmpty() &&
                        localTxid != expectedTxid) {
                        QMessageBox::critical(
                            this,
                            "Send Token",
                            "Prepared transaction ID changed during local "
                            "verification. Nothing was broadcast.");
                        return;
                    }

                    if (QMessageBox::question(
                            this,
                            "Broadcast Token Transfer",
                            QString(
                                "Local signing complete.\n\n"
                                "TXID: %1\n"
                                "Fee: 0.00010000 TRU\n\n"
                                "Broadcast this signed token transfer?")
                                .arg(localTxid),
                            QMessageBox::Yes | QMessageBox::No,
                            QMessageBox::No) != QMessageBox::Yes) {
                        return;
                    }

                    QJsonObject broadcast;
                    broadcast.insert("txHex", signedHex);
                    rpc_->call(
                        "sendrawtransaction",
                        objectParams(broadcast),
                        [this, localTxid](
                            const QJsonValue& result,
                            const QByteArray&,
                            const QString& broadcastError) {
                            if (!broadcastError.isEmpty()) {
                                QMessageBox::critical(
                                    this,
                                    "Send Token",
                                    "Broadcast failed: " +
                                    broadcastError);
                                return;
                            }

                            QString txid = result.toString();
                            if (txid.isEmpty()) txid = localTxid;
                            QMessageBox::information(
                                this,
                                "Token Transfer Submitted",
                                "Signed token transfer accepted by the "
                                "connected Core mempool.\n\nTXID:\n" +
                                txid +
                                "\n\nOwnership changes after confirmation.");
                        });
                });
        });
}

void DesktopAssetsWidget::sendTRUScript(
    const QJsonObject& script) {
    if (!rpc_ || !wallet_ || !wallet_->walletUnlocked()) {
        QMessageBox::warning(
            this, "Send TRUScript",
            "Unlock the standalone wallet first.");
        return;
    }

    const QString inscriptionTxid =
        script.value("txid").toString().trimmed();
    QString owner =
        script.value("ownerAddress").toString().trimmed();
    if (owner.isEmpty())
        owner = script.value("owner").toString().trimmed();

    if (inscriptionTxid.size() != 64 ||
        owner.isEmpty() ||
        !wallet_->walletAddresses().contains(owner)) {
        QMessageBox::warning(
            this, "Send TRUScript",
            "This TRUScript is not controlled by the unlocked "
            "standalone wallet.");
        return;
    }

    bool ok = false;
    const QString recipient = QInputDialog::getText(
        this,
        "Send TRUScript",
        "Recipient TRU address:",
        QLineEdit::Normal,
        {},
        &ok).trimmed();
    if (!ok) return;

    if (!wallet_->validateWalletAddress(recipient)) {
        QMessageBox::warning(
            this, "Send TRUScript",
            "Recipient is not a valid TRU mainnet address.");
        return;
    }

    if (QMessageBox::question(
            this,
            "Confirm TRUScript Transfer",
            QString(
                "Inscription: %1\nFrom: %2\nTo: %3\n\n"
                "Core builds the unsigned transfer; this Desktop wallet "
                "verifies and signs the fee input locally.")
                .arg(inscriptionTxid, owner, recipient),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No) != QMessageBox::Yes) {
        return;
    }

    constexpr std::uint64_t feeAtoms = 10000ULL;
    constexpr std::uint64_t dustAtoms = 546ULL;

    wallet_->selectSafeFeeUtxo(
        feeAtoms + dustAtoms,
        [this, inscriptionTxid, owner, recipient](
            QJsonObject feeUtxo,
            QString feeError) {
            if (!feeError.isEmpty()) {
                QMessageBox::warning(
                    this, "Send TRUScript", feeError);
                return;
            }

            QJsonObject params;
            params.insert("inscriptionTxid", inscriptionTxid);
            params.insert("recipient", recipient);
            params.insert("senderAddress", owner);
            params.insert("feeUtxo", feeUtxo);
            params.insert("fee", 10000);

            rpc_->call(
                "createTransferTRUScriptTransaction",
                objectParams(params),
                [this, inscriptionTxid, owner, recipient](
                    const QJsonValue& value,
                    const QByteArray&,
                    const QString& error) {
                    if (!error.isEmpty() || !value.isObject()) {
                        QMessageBox::warning(
                            this,
                            "Send TRUScript",
                            error.isEmpty()
                                ? "Core returned an invalid unsigned TRUScript transfer."
                                : error);
                        return;
                    }

                    const QJsonObject built = value.toObject();
                    if (built.value("inscriptionTxid").toString() !=
                            inscriptionTxid ||
                        built.value("from").toString() != owner ||
                        built.value("to").toString() != recipient) {
                        QMessageBox::critical(
                            this,
                            "Send TRUScript",
                            "Unsigned TRUScript transaction failed the "
                            "Desktop binding check. Nothing was signed.");
                        return;
                    }

                    QString signedHex;
                    QString localTxid;
                    QString signError;
                    if (!wallet_->signPreparedTransaction(
                            built.value("unsignedTxHex").toString(),
                            built.value("signingInputs").toArray(),
                            signedHex,
                            localTxid,
                            signError)) {
                        QMessageBox::critical(
                            this,
                            "Send TRUScript",
                            "Local signing refused: " + signError);
                        return;
                    }

                    const QString expectedTxid =
                        built.value("txid").toString();
                    if (!expectedTxid.isEmpty() &&
                        localTxid != expectedTxid) {
                        QMessageBox::critical(
                            this,
                            "Send TRUScript",
                            "Prepared transaction ID changed during local "
                            "verification. Nothing was broadcast.");
                        return;
                    }

                    if (QMessageBox::question(
                            this,
                            "Broadcast TRUScript Transfer",
                            QString(
                                "Local signing complete.\n\n"
                                "TXID: %1\n"
                                "Fee: 0.00010000 TRU\n\n"
                                "Broadcast this signed TRUScript transfer?")
                                .arg(localTxid),
                            QMessageBox::Yes | QMessageBox::No,
                            QMessageBox::No) != QMessageBox::Yes) {
                        return;
                    }

                    QJsonObject broadcast;
                    broadcast.insert("txHex", signedHex);
                    rpc_->call(
                        "sendrawtransaction",
                        objectParams(broadcast),
                        [this, localTxid](
                            const QJsonValue& result,
                            const QByteArray&,
                            const QString& broadcastError) {
                            if (!broadcastError.isEmpty()) {
                                QMessageBox::critical(
                                    this,
                                    "Send TRUScript",
                                    "Broadcast failed: " +
                                    broadcastError);
                                return;
                            }

                            QString txid = result.toString();
                            if (txid.isEmpty()) txid = localTxid;
                            QMessageBox::information(
                                this,
                                "TRUScript Transfer Submitted",
                                "Signed TRUScript transfer accepted by the "
                                "connected Core mempool.\n\nTXID:\n" +
                                txid +
                                "\n\nOwnership changes after confirmation.");
                        });
                });
        });
}

void DesktopAssetsWidget::refreshAssets() {
    const QStringList addresses = wallet_->walletAddresses();
    if (addresses.isEmpty()) {
        status_->setText(
            "Unlock the standalone wallet first. Asset discovery reads only its locally derived addresses.");
        renderTokens({});
        renderScripts({});
        return;
    }

    refresh_->setEnabled(false);
    status_->setText("Reading token ownership and TRUScript inscriptions from the connected TRU node…");

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
            QJsonArray tokens;
            QStringList errors;

            if (!error.isEmpty()) {
                errors.push_back("tokens: " + error);
            } else if (!value.isArray()) {
                errors.push_back("tokens: unexpected response shape");
            } else {
                for (const auto& item : value.toArray()) {
                    if (!item.isObject()) continue;
                    const QString type =
                        item.toObject().value("type").toString();
                    if (type.compare(
                            "TRUSCRIPT",
                            Qt::CaseInsensitive) != 0)
                        tokens.append(item);
                }
            }

            renderTokens(tokens);
            loadScriptsSequential(
                addresses, 0, {}, std::move(errors), tokens.size());
        });
}
