#include "desktop_panel.h"
#include "desktop_assets_widget.h"
#include "desktop_ai_widget.h"
#include "desktop_wallet_widget.h"
#include "tru_network_params.h"
#include <QComboBox>
#include <QDateTime>
#include <QDir>
#include <QFileDialog>
#include <QFormLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLabel>
#include <QLocale>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPixmap>
#include <QIcon>
#include <QPushButton>
#include <QRadioButton>
#include <QSettings>
#include <QSplitter>
#include <QTabWidget>
#include <QTableWidget>
#include <QTimer>
#include <QVariant>
#include <QVBoxLayout>
#include <cmath>
#include <cstdint>

namespace {
struct Operation { const char* group; const char* title; const char* method; const char* params; bool write; const char* help; };
// Exact method names/parameters are drawn from the uploaded rpc_server.cpp.
// No generic editable method box: unreviewed RPCs cannot be misclassified read-only.
const Operation operations[] = {
 {"Network", "Chain overview", "getchaininfo", "{}", false, "Current height, hash and difficulty from this node."},
 {"Network", "Node and balance", "getinfo", "{}", false, "Snapshot of the node's current wallet address and chain."},
 {"Network", "Connected peers", "getpeerinfo", "{}", false, "Live peer endpoints and reported heights."},
 {"Network", "Mempool", "getrawmempool", "{}", false, "Pending transactions; inclusion is not confirmation."},
 {"Network", "Block by height", "getblockbyheight", R"({"height":0})", false, "Enter a block height."},
 {"Network", "Transaction", "gettransaction", R"({"txid":""})", false, "Enter a full transaction ID."},
 {"Network", "Unspent output", "gettxout", R"({"txid":"","n":0})", false, "Inspect one output before acting."},
 {"Wallet", "Addresses", "listaddresses", "{}", false, "Addresses owned by the connected core wallet."},
 {"Wallet", "Balance", "getbalance", "{}", false, "Connected node wallet balance."},
 {"Wallet", "Generate receive address", "getnewaddress", "{}", true, "Requires the connected core's authenticated encrypted wallet to be unlocked locally."},
 {"Wallet", "Unspent coins", "listunspent", R"({"address":""})", false, "Enter a TRU address."},
 {"Wallet", "Address transactions", "getaddresstransactions", R"({"address":""})", false, "Inspect transaction history for an address."},
 {"Tokens", "Token vault", "tokenmetadisplay", R"({"addresses":[""]})", false, "Confirmed token holdings for the addresses you enter."},
 {"Tokens", "Token UTXOs", "gettokenutxo", R"({"tokenID":"","address":""})", false, "Inspect the controlling UTXO before a transfer or retirement."},
 {"Tokens", "Token metadata", "gettokenmetadata", R"({"txid":""})", false, "Read indexed token metadata by issuance transaction ID."},
 {"Tokens", "Retirement sink", "gettokenburninfo", "{}", false, "Canonical token retirement destination and semantics."},
 {"Tokens", "Retire token holding", "burntoken", R"({"tokenID":"","senderAddress":"","confirm":"BURN"})", true, "Permanently transfers the selected controlling holding to the canonical sink. History remains on chain."},
 {"Scripts", "Script vault", "getTRUScripts", R"({"ownerAddress":""})", false, "Read TRUScript records for an owner."},
 {"Scripts", "Inscription details", "getTRUScriptDetails", R"({"txid":""})", false, "Enter the inscription transaction ID."},
 {"Scripts", "Inscribe data", "inscribeTRUScript", R"({"data":"","owner":""})", true, "Publishes data on chain using the connected node wallet; requires funds and signing access."},
 {"Contracts", "Contract vault", "getcontracts", "{}", false, "Authoritative family, status and stable-root/live-anchor data from the core."},
 {"Contracts", "Redeem hash lock", "redeemhashlock", R"({"contractAddress":"","preimage":""})", true, "The preimage is disclosed by redemption. Enter lowercase txid:vout."},
 {"Contracts", "Redeem time lock", "redeemtimelock", R"({"contractAddress":""})", true, "Core validates maturity using chain median time past, not the desktop clock."},
 {"Mining", "Active miners", "getallminers", "{}", false, "Reporting telemetry known to this node; an empty response does not prove there are no network miners."},
 {"Mining", "Miner status", "getminerstatus", R"({"minerAddress":""})", false, "Registration, activity, hash rate and mined-block count for one address."},
 {"AI / Living Tokens", "Evolution provenance", "verifytokenevolution", R"({"tokenID":"","require_confirmed":true})", false, "Checks evolution provenance and confirmed anchors. Does not activate VAH writers."},
 {"AI / Living Tokens", "Configured providers", "getAIProviders", R"({"address":""})", false, "Public provider capabilities/configuration reported by the core."},
 {"AI / Living Tokens", "AI token state", "getAITokenState", R"({"tokenID":""})", false, "Read the current AI token state."},
 {"AI / Living Tokens", "Interact with AI token", "interactWithAIToken", R"({"tokenID":"","address":"","message":""})", true, "Creates an AI request. Provider use may incur costs; prompts may be logged by the core."},
 {"AI / Living Tokens", "AI response", "getAIResponse", R"({"requestID":""})", false, "Look up the request ID returned by an interaction."},
 {"Swaps", "Swap records", "swaprecordlist", "{}", false, "Requires the separate swap capability token below. Observes the existing coordinator; does not run the Agent."},
 {"Swaps", "One swap", "swaprecordget", R"({"swapId":""})", false, "Read a canonical swap record."},
 {"Swaps", "Prepared funding status", "htlcpreparedstatus", R"({"operationId":""})", false, "Inspect an existing operation without broadcasting it."},
 {"Swaps", "Wallet role addresses", "swapwalletrolekeys", "{}", false, "Public claim/refund addresses from an already provisioned encrypted wallet."}
};
QString readable(const QJsonValue& v) {
    if (v.isString()) return v.toString();
    if (v.isDouble()) return QString::number(v.toDouble(), 'g', 15);
    if (v.isBool()) return v.toBool() ? "true" : "false";
    return "—";
}
QLabel* makeMetric(QHBoxLayout* row, const QString& title) {
    auto box = new QGroupBox(title);
    box->setProperty("truMetric", true);

    auto layout = new QVBoxLayout(box);

    auto value = new QLabel("—");
    value->setObjectName("truMetricValue");
    value->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);

    layout->addWidget(value);
    row->addWidget(box);

    return value;
}

double difficultyFromCompactBits(std::uint32_t bits) {
    if (bits == 0) return 0.0;

    constexpr std::uint32_t powLimitBits = 0x1e00ffffU;
    const int exponent = static_cast<int>(bits >> 24);
    const std::uint32_t mantissa = bits & 0x00ffffffU;
    const int limitExponent = static_cast<int>(powLimitBits >> 24);
    const std::uint32_t limitMantissa = powLimitBits & 0x00ffffffU;

    if (mantissa == 0 || exponent < 3 || exponent > 32) return 0.0;

    long double ratio =
        static_cast<long double>(limitMantissa) /
        static_cast<long double>(mantissa);

    const int exponentDelta = limitExponent - exponent;
    ratio *= std::pow(256.0L, static_cast<long double>(exponentDelta));

    return ratio > 0.0L ? static_cast<double>(ratio) : 0.0;
}

QString formatDifficulty(std::uint32_t bits) {
    const double d = difficultyFromCompactBits(bits);
    if (!(d > 0.0) || !std::isfinite(d)) return "—";

    QLocale english(QLocale::English);
    return english.toString(d, 'f', 4);
}

QString formatCoreVersion(QString version) {
    version = version.trimmed();
    if (version.isEmpty() || version == "TRU-node") return "—";
    if (!version.startsWith('v', Qt::CaseInsensitive)) version.prepend('v');
    return version;
}
}

DesktopPanel::DesktopPanel(QWidget* parent) : QWidget(parent), rpc_(this) {

    // RPC-01C — final cross-platform TRU Desktop visual layer.
    // Presentation only: no RPC, wallet, consensus or P2P semantics.
    setStyleSheet(R"TRUQSS(
        QWidget {
            background-color: #040d18;
            color: #dcecf6;
            font-size: 13px;
        }

        QTabWidget::pane {
            border: 1px solid #163d57;
            border-radius: 10px;
            background-color: #06131f;
            top: -1px;
        }

        QTabBar::tab {
            background-color: #081a2a;
            color: #809fb4;
            border: 1px solid #15374f;
            border-bottom: none;
            padding: 11px 20px;
            min-width: 92px;
        }
        QTabBar::tab:selected {
            background-color: #0b3144;
            color: #78f5e5;
            border-color: #277b94;
        }
        QTabBar::tab:hover {
            color: #a7fff6;
            background-color: #0a2638;
        }

        QGroupBox {
            background-color: #071725;
            border: 1px solid #19445f;
            border-radius: 12px;
            margin-top: 13px;
            padding: 18px 12px 12px 12px;
            color: #91bdd2;
            font-weight: 700;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 14px;
            padding: 0 7px;
            color: #a1cde1;
        }
        QGroupBox[truMetric="true"] {
            background: qlineargradient(
                x1:0, y1:0, x2:1, y2:1,
                stop:0 #071927,
                stop:0.55 #082033,
                stop:1 #092a40);
            border: 1px solid #245d7a;
            min-height: 100px;
        }

        QLabel#truMetricValue {
            color: #67f4df;
            font-size: 31px;
            font-weight: 800;
            padding: 8px;
        }
        QLabel#truLogo {
            background: transparent;
            padding: 0px;
        }
        QLabel#truBrand {
            color: #73ecff;
            font-size: 25px;
            font-weight: 800;
            padding: 0px;
        }
        QLabel#truSubtitle {
            color: #6f91a8;
            font-size: 11px;
            font-weight: 700;
            padding-top: 2px;
        }
        QLabel#truModeBadge,
        QLabel#truSecurityBadge,
        QLabel#truMainnetBadge {
            background-color: #092238;
            color: #77eadf;
            border: 1px solid #246680;
            border-radius: 11px;
            padding: 6px 11px;
            font-size: 10px;
            font-weight: 800;
        }
        QLabel#truSecurityBadge { color: #71caff; }
        QLabel#truMainnetBadge {
            color: #c5a2ff;
            border-color: #65528f;
        }
        QLabel#truSignalRail {
            background-color: #061520;
            color: #4c819f;
            border-top: 1px solid #12344b;
            border-bottom: 1px solid #12344b;
            padding: 6px 10px;
            font-size: 10px;
            font-weight: 700;
        }
        QLabel#truConnectionBanner {
            background: qlineargradient(
                x1:0, y1:0, x2:1, y2:0,
                stop:0 #082137,
                stop:0.55 #09283a,
                stop:1 #071b2b);
            color: #8ee9de;
            border: 1px solid #215b74;
            border-left: 3px solid #49dccd;
            border-radius: 8px;
            padding: 10px 13px;
            font-weight: 700;
        }
        QLabel#truTip {
            background-color: #061521;
            color: #7ea6bd;
            border: 1px solid #173b52;
            border-radius: 7px;
            padding: 9px 11px;
            font-family: "DejaVu Sans Mono", "Menlo", "Consolas";
        }
        QLabel#truSectionTitle,
        QLabel#truAssetSectionTitle {
            color: #e8f6fc;
            font-size: 17px;
            font-weight: 800;
            padding: 7px 0px 4px 1px;
        }
        QLabel#truSecurityNote {
            background-color: #071a2a;
            color: #8caec0;
            border: 1px solid #19445e;
            border-radius: 8px;
            padding: 11px;
        }
        QLabel#truSourceNote {
            color: #668aa1;
            padding: 5px 2px;
        }

        QFrame#truWalletHero,
        QFrame#truAssetsHero {
            background: qlineargradient(
                x1:0, y1:0, x2:1, y2:0,
                stop:0 #071a2b,
                stop:0.55 #0a2c40,
                stop:1 #081a2d);
            border: 1px solid #286882;
            border-radius: 13px;
        }
        QLabel#truWalletEyebrow,
        QLabel#truAssetEyebrow {
            color: #62a6c4;
            font-size: 10px;
            font-weight: 800;
        }
        QLabel#truWalletTitle,
        QLabel#truAssetTitle {
            color: #f1fbff;
            font-size: 22px;
            font-weight: 800;
        }
        QLabel#truAssetSubtitle {
            color: #91adbd;
            max-width: 760px;
        }
        QLabel#truWalletState {
            background-color: #0b2637;
            color: #8ab0c3;
            border: 1px solid #28536a;
            border-radius: 10px;
            padding: 4px 10px;
            font-size: 10px;
            font-weight: 800;
        }
        QLabel#truWalletState[walletState="unlocked"] {
            color: #6ff4c6;
            border-color: #2a8c73;
            background-color: #092c2d;
        }
        QLabel#truWalletState[walletState="locked"] {
            color: #8fc7ff;
            border-color: #356f9e;
        }
        QLabel#truWalletState[walletState="missing"] {
            color: #d5b57c;
            border-color: #7d633b;
        }
        QLabel#truWalletBalanceCaption {
            color: #6c9db7;
            font-size: 10px;
            font-weight: 800;
        }
        QLabel#truWalletBalanceValue {
            color: #75f6df;
            font-size: 30px;
            font-weight: 800;
        }
        QLabel#truWalletBoundary,
        QLabel#truAssetPrivacy {
            background-color: #061824;
            color: #789caf;
            border: 1px solid #15394e;
            border-radius: 8px;
            padding: 9px 11px;
        }
        QFrame#truReceiveCard {
            background-color: #071827;
            border: 1px solid #1d4a64;
            border-radius: 11px;
        }
        QLabel#truWalletAddress {
            color: #dff8ff;
            font-size: 15px;
            font-weight: 700;
            font-family: "DejaVu Sans Mono", "Menlo", "Consolas";
        }
        QLabel#truWalletMeta,
        QLabel#truAssetMeta {
            color: #6f91a5;
            font-size: 11px;
        }
        QPlainTextEdit#truWalletActivity {
            background-color: #05131f;
            color: #b7d7e5;
            border: 1px solid #173e56;
            border-radius: 9px;
            padding: 9px;
            font-family: "DejaVu Sans Mono", "Menlo", "Consolas";
            font-size: 12px;
        }

        QFrame#truAssetCard {
            background: qlineargradient(
                x1:0, y1:0, x2:1, y2:1,
                stop:0 #071725,
                stop:1 #0a2133);
            border: 1px solid #1e516d;
            border-radius: 12px;
        }
        QLabel#truAssetImage {
            background-color: #03101b;
            color: #4d809a;
            border: 1px solid #173f58;
            border-radius: 9px;
            font-size: 14px;
            font-weight: 800;
        }
        QLabel#truScriptGlyph {
            background-color: #06131f;
            color: #63e7dc;
            border: 1px solid #1e536d;
            border-radius: 9px;
            font-family: "DejaVu Sans Mono", "Menlo", "Consolas";
            font-size: 17px;
            font-weight: 800;
        }
        QLabel#truAssetCardTitle {
            color: #ecf9ff;
            font-size: 15px;
            font-weight: 800;
        }
        QLabel#truAssetTypeBadge,
        QLabel#truAssetCountBadge {
            background-color: #0b3141;
            color: #71eadf;
            border: 1px solid #28667b;
            border-radius: 9px;
            padding: 4px 8px;
            font-size: 10px;
            font-weight: 800;
        }
        QLabel#truAssetAmount {
            color: #74f2d9;
            font-size: 17px;
            font-weight: 800;
        }
        QLabel#truScriptPreview {
            color: #b8d3df;
            background-color: #05131f;
            border: 1px solid #15394f;
            border-radius: 7px;
            padding: 8px;
        }
        QLabel#truAssetStatus {
            color: #8fb1c2;
            padding: 3px 5px;
        }
        QLabel#truAssetEmpty {
            background-color: #061522;
            color: #64879a;
            border: 1px dashed #1d455b;
            border-radius: 10px;
            padding: 42px;
            min-height: 80px;
        }
        QScrollArea#truAssetScroll,
        QWidget#truAssetHost {
            background: transparent;
            border: none;
        }

        QPushButton {
            background-color: #0b2b41;
            color: #dcf6fb;
            border: 1px solid #256783;
            border-radius: 8px;
            padding: 9px 15px;
            font-weight: 700;
        }
        QPushButton:hover {
            background-color: #10445d;
            border-color: #48d1ea;
            color: #ffffff;
        }
        QPushButton:pressed { background-color: #09283b; }
        QPushButton:disabled {
            background-color: #081927;
            color: #496273;
            border-color: #173346;
        }
        QPushButton#truPrimaryAction {
            background: qlineargradient(
                x1:0, y1:0, x2:1, y2:0,
                stop:0 #0d4b62,
                stop:1 #08706f);
            color: #efffff;
            border-color: #43d8d0;
        }
        QPushButton#truSecondaryAction {
            background-color: #0a2437;
            border-color: #285a73;
        }
        QPushButton#truSensitiveAction {
            background-color: #211c31;
            color: #dcc9ff;
            border-color: #604d83;
        }

        QLineEdit,
        QPlainTextEdit,
        QComboBox {
            background-color: #081a2a;
            color: #daedf7;
            border: 1px solid #294b63;
            border-radius: 7px;
            padding: 8px;
            selection-background-color: #17697b;
        }
        QLineEdit:focus,
        QPlainTextEdit:focus,
        QComboBox:focus {
            border: 1px solid #43cfe1;
            background-color: #0a2032;
        }
        QLineEdit:disabled {
            background-color: #061420;
            color: #5d7484;
            border-color: #173347;
        }
        QLineEdit#truEndpoint,
        QLineEdit#truCookie {
            font-family: "DejaVu Sans Mono", "Menlo", "Consolas";
        }
        QPlainTextEdit#rpcParameters,
        QPlainTextEdit#rpcResult {
            font-family: "DejaVu Sans Mono", "Menlo", "Consolas";
            font-size: 12px;
        }

        QTableWidget {
            background-color: #061522;
            alternate-background-color: #081b2b;
            border: 1px solid #1d4964;
            border-radius: 8px;
            gridline-color: #15384f;
            selection-background-color: #113d56;
            selection-color: #e9ffff;
        }
        QHeaderView::section {
            background-color: #0a2133;
            color: #8fb9d0;
            border: none;
            border-right: 1px solid #183d55;
            border-bottom: 1px solid #24526c;
            padding: 9px;
            font-weight: 700;
        }
        QRadioButton {
            color: #c3dbe8;
            spacing: 7px;
            padding: 3px;
        }
        QRadioButton:checked {
            color: #7ef2e6;
            font-weight: 700;
        }
        QSplitter::handle {
            background-color: #173a50;
            height: 2px;
        }
        QToolTip {
            background-color: #071827;
            color: #d9f5fa;
            border: 1px solid #2b7189;
            padding: 6px;
        }
    )TRUQSS");

    const QString darkThemeSheet = styleSheet();
    const QString lightThemeOverrides = R"TRULIGHT(
        QWidget { background-color:#f4f7fb; color:#16283a; }
        QTabWidget::pane { border-color:#9bb5c7; background-color:#ffffff; }
        QTabBar::tab {
            background-color:#e8f0f6; color:#587186;
            border-color:#b8cad7;
        }
        QTabBar::tab:selected {
            background-color:#d5f4f1; color:#0b625f;
            border-color:#4baaa6;
        }
        QTabBar::tab:hover { color:#084f58; background-color:#dff1f4; }
        QGroupBox {
            background-color:#ffffff; border-color:#a8c2d1;
            color:#365c72;
        }
        QGroupBox::title { color:#31596e; }
        QGroupBox[truMetric="true"] {
            background:#ffffff; border-color:#8fb8c8;
        }
        QLabel#truMetricValue { color:#087a70; }
        QLabel#truBrand { color:#08758a; }
        QLabel#truWalletAddress {
            color:#17384a;
            background-color:#ffffff;
            border:1px solid #b5cbd7;
            border-radius:6px;
            padding:7px 9px;
        }
        QLabel#truWalletBalanceCaption { color:#4f7184; }
        QLabel#truWalletBalanceValue { color:#087a70; }
        QLabel#truWalletMeta { color:#59768a; }
        QLabel#truSubtitle, QLabel#truSourceNote { color:#607b8d; }
        QLabel#truModeBadge, QLabel#truSecurityBadge {
            background-color:#edf6f8; color:#176967;
            border-color:#86afb9;
        }
        QLabel#truMainnetBadge {
            color:#6c4c97; border-color:#b7a8d0;
            background-color:#f3eff9;
        }
        QLabel#truConnectionBanner {
            background:#e7f7f5; color:#155d5a;
            border-color:#63aaa6;
        }
        QLabel#truTip {
            background-color:#ffffff; color:#1c3547;
            border-color:#aec4d0;
        }
        QLabel#truSectionTitle, QLabel#truAssetSectionTitle {
            color:#173c51;
        }
        QPushButton {
            background-color:#e9f2f7; color:#17394c;
            border-color:#8aaec0;
        }
        QPushButton:hover {
            background-color:#d9edf2; border-color:#398da0;
        }
        QPushButton#truPrimaryAction {
            background-color:#148a87; color:#ffffff;
            border-color:#0b6f6c;
        }
        QPushButton#truSecondaryAction {
            background-color:#e5f0f5; color:#244b60;
            border-color:#86aebe;
        }
        QPushButton#truSensitiveAction {
            background-color:#f3eaf7; color:#6b4781;
            border-color:#b69ac6;
        }
        QPushButton#truThemeToggle {
            background-color:#fff8e7; color:#705716;
            border:1px solid #ccb970; border-radius:11px;
            padding:6px 11px; font-size:10px; font-weight:800;
        }
        QLineEdit, QPlainTextEdit, QComboBox {
            background-color:#ffffff; color:#1b3142;
            border-color:#9cb7c6;
            selection-background-color:#bde6e3;
        }
        QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus {
            border-color:#318f9a; background-color:#ffffff;
        }
        QLineEdit:disabled {
            background-color:#eef2f5; color:#8798a3;
        }
        QTableWidget {
            background-color:#ffffff;
            alternate-background-color:#f2f6f9;
            border-color:#9db7c6; gridline-color:#c7d7e0;
            selection-background-color:#cceae7;
            selection-color:#15313d;
        }
        QHeaderView::section {
            background-color:#dfeaf0; color:#36566a;
            border-right-color:#b7cbd6;
            border-bottom-color:#a9bfcb;
        }
        QRadioButton { color:#29495b; }
        QRadioButton:checked { color:#0a7169; }
        QScrollArea { background:transparent; }
        QToolTip {
            background-color:#ffffff; color:#183443;
            border-color:#7ca7b5;
        }
    )TRULIGHT";

    QSettings themeSettings("TRUBlockchain", "CoreDesktop");
    QString initialTheme =
        themeSettings.value("theme", "dark").toString().trimmed().toLower();
    if (initialTheme != "light") initialTheme = "dark";
    setProperty("truTheme", initialTheme);
    if (initialTheme == "light")
        setStyleSheet(darkThemeSheet + lightThemeOverrides);


    setObjectName("truAppRoot");
    QTimer::singleShot(0, this, [this] {
        if (window()) {
            window()->setWindowTitle("TRU Desktop");
            window()->setWindowIcon(QIcon(":/tru/assets/tru_logo.png"));
        }
    });
    auto root = new QVBoxLayout(this);
    root->setContentsMargins(18, 14, 18, 14);
    root->setSpacing(9);
    auto brandRow = new QHBoxLayout;
    brandRow->setSpacing(12);

    auto logo = new QLabel;
    logo->setObjectName("truLogo");
    logo->setFixedSize(58, 58);
    const QPixmap logoPixmap(":/tru/assets/tru_logo.png");
    if (!logoPixmap.isNull()) {
        logo->setPixmap(logoPixmap.scaled(
            logo->size(), Qt::KeepAspectRatio, Qt::SmoothTransformation));
    } else {
        // Fail visibly instead of silently leaving an empty logo slot.
        logo->setText("TRU");
        logo->setAlignment(Qt::AlignCenter);
        logo->setStyleSheet(
            "font-size:18px;font-weight:900;color:#6debf3;"
            "border:1px solid #246680;border-radius:10px;");
    }
    brandRow->addWidget(logo, 0, Qt::AlignVCenter);

    auto brand = new QLabel("TRU  /  CORE DESKTOP");
    brand->setObjectName("truBrand");
    brandRow->addWidget(brand, 0, Qt::AlignVCenter);
    brandRow->addStretch();

    auto mainnetBadge = new QLabel("TRU MAINNET");
    mainnetBadge->setObjectName("truMainnetBadge");

    modeBadge_ = new QLabel("LOCAL NODE");
    modeBadge_->setObjectName("truModeBadge");

    securityBadge_ = new QLabel("LOOPBACK / COOKIE");
    securityBadge_->setObjectName("truSecurityBadge");

    auto* themeToggle = new QPushButton(
        initialTheme == "light" ? "DARK THEME" : "LIGHT THEME");
    themeToggle->setObjectName("truThemeToggle");
    themeToggle->setToolTip(
        "Switch TRU Desktop between dark and light appearance. "
        "The preference is saved on this computer.");

    brandRow->addWidget(mainnetBadge, 0, Qt::AlignVCenter);
    brandRow->addWidget(modeBadge_, 0, Qt::AlignVCenter);
    brandRow->addWidget(securityBadge_, 0, Qt::AlignVCenter);
    brandRow->addWidget(themeToggle, 0, Qt::AlignVCenter);

    root->addLayout(brandRow);

    connection_ = new QLabel(
        "Configure a local or secure remote TRU node connection."
    );
    connection_->setObjectName("truConnectionBanner");
    connection_->setWordWrap(true);
    connection_->setTextFormat(Qt::PlainText);

    root->addWidget(connection_);

    pages_ = new QTabWidget;
    root->addWidget(pages_);
    auto overview = new QWidget;
    auto overviewLayout = new QVBoxLayout(overview);
    auto metrics = new QHBoxLayout;
    height_ = makeMetric(metrics, "CHAIN HEIGHT");
    peers_ = makeMetric(metrics, "CONNECTED PEERS");
    rate_ = makeMetric(metrics, "REPORTED HASH RATE");
    overviewLayout->addLayout(metrics);

    // UI-08: dashboard-style chain details that are relevant to a wallet user.
    // These are read-only observations from the connected Core.
    auto networkMetrics = new QHBoxLayout;

    auto* difficultyValue =
        makeMetric(networkMetrics, "DIFFICULTY");
    difficultyValue->setObjectName("truDifficultyValue");
    difficultyValue->setToolTip(
        "Current proof-of-work difficulty derived from the connected Core's compact nBits value.");

    auto* coreVersionValue =
        makeMetric(networkMetrics, "CONNECTED CORE VERSION");
    coreVersionValue->setObjectName("truCoreVersionValue");
    coreVersionValue->setToolTip(
        "Release version reported by the connected TRU Core node.");

    overviewLayout->addLayout(networkMetrics);
    tip_ = new QLabel("Best tip: —");
    tip_->setObjectName("truTip");
    tip_->setTextFormat(Qt::PlainText);
    tip_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    tip_->setWordWrap(true);
    overviewLayout->addWidget(tip_);
    auto refreshButton = new QPushButton("Refresh node snapshot");
    refreshButton->setObjectName("truSecondaryAction");
    overviewLayout->addWidget(refreshButton, 0, Qt::AlignLeft);
    auto miningTitle = new QLabel("ACTIVE MINERS");
    miningTitle->setObjectName("truSectionTitle");
    overviewLayout->addWidget(miningTitle);
    miners_ = new QTableWidget(0, 4);
    miners_->setHorizontalHeaderLabels({"Address", "Status", "Hash rate (H/s)", "Blocks mined"});
    miners_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    miners_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    miners_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    miners_->setSelectionBehavior(QAbstractItemView::SelectRows);
    overviewLayout->addWidget(miners_);
    auto sourceNote = new QLabel("Telemetry from the connected node. Unreported producers may not appear in this RPC view.");
    sourceNote->setObjectName("truSourceNote");
    sourceNote->setWordWrap(true);
    overviewLayout->addWidget(sourceNote);
    pages_->addTab(overview, "Overview");
    connect(refreshButton, &QPushButton::clicked, this, [this]{ refreshOverview(); });

    auto tools = new QWidget;
    auto toolsLayout = new QVBoxLayout(tools);
    auto advancedTitle = new QLabel("ADVANCED CORE TOOLS");
    advancedTitle->setObjectName("truSectionTitle");
    auto advancedNote = new QLabel(
        "Direct RPC workspace for operators and developers. Standard wallet use does not require this panel.");
    advancedNote->setObjectName("truSourceNote");
    advancedNote->setWordWrap(true);
    toolsLayout->addWidget(advancedTitle);
    toolsLayout->addWidget(advancedNote);
    auto selectors = new QHBoxLayout;
    category_ = new QComboBox;
    operation_ = new QComboBox;
    for (const auto& op : operations)
        if (category_->findText(op.group) < 0) category_->addItem(op.group);
    selectors->addWidget(category_);
    selectors->addWidget(operation_, 1);
    toolsLayout->addLayout(selectors);
    operationHelp_ = new QLabel;
    operationHelp_->setWordWrap(true);
    toolsLayout->addWidget(operationHelp_);
    auto splitter = new QSplitter(Qt::Vertical);
    params_ = new QPlainTextEdit;
    params_->setPlaceholderText("JSON parameters");
    params_->setObjectName("rpcParameters");
    output_ = new QPlainTextEdit;
    output_->setReadOnly(true);
    output_->setObjectName("rpcResult");
    splitter->addWidget(params_);
    splitter->addWidget(output_);
    toolsLayout->addWidget(new QLabel("Parameters (JSON; integer quantities are raw units unless the field says otherwise)"));
    toolsLayout->addWidget(splitter, 1);
    auto actions = new QHBoxLayout;
    run_ = new QPushButton("Run query");
    auto clear = new QPushButton("Clear result");
    actions->addWidget(run_);
    actions->addStretch();
    actions->addWidget(clear);
    toolsLayout->addLayout(actions);
    pages_->addTab(tools, "Advanced");
    connect(clear, &QPushButton::clicked, output_, &QPlainTextEdit::clear);
    connect(run_, &QPushButton::clicked, this, [this]{ runOperation(); });
    connect(category_, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this] {
        operation_->clear();
        int i = 0;
        for (const auto& op : operations) {
            if (category_->currentText() == op.group) operation_->addItem(op.title, i);
            ++i;
        }
        selectOperation();
    });
    connect(operation_, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this]{ selectOperation(); });
    for (int i = 0; i < int(sizeof(operations)/sizeof(operations[0])); ++i)
        if (category_->currentText() == operations[i].group) operation_->addItem(operations[i].title, i);
    selectOperation();

    auto config = new QWidget;
    auto form = new QFormLayout(config);

    QSettings settings("TRUBlockchain", "CoreDesktop");

    auto modeRow = new QWidget;
    auto modeLayout = new QHBoxLayout(modeRow);
    modeLayout->setContentsMargins(0, 0, 0, 0);

    localMode_ = new QRadioButton("Local Node");
    remoteMode_ = new QRadioButton("Remote Node");

    const QString savedMode =
        settings.value("connectionMode", "remote").toString();

    remoteMode_->setChecked(savedMode == "remote");
    localMode_->setChecked(!remoteMode_->isChecked());

    remoteProfile_ = new QComboBox;
    remoteProfile_->setObjectName("truRemoteProfile");
    remoteProfile_->addItem(
        "TRU Public Network (No Core Required)",
        "public");
    remoteProfile_->addItem(
        "Custom Remote Core",
        "custom");

    const QString savedRemoteProfile =
        settings.value("remoteProfile", "public").toString();
    remoteProfile_->setCurrentIndex(
        savedRemoteProfile == "custom" ? 1 : 0);

    modeLayout->addWidget(localMode_);
    modeLayout->addWidget(remoteMode_);
    modeLayout->addStretch();

    form->addRow("CONNECTION MODE", modeRow);
    form->addRow("REMOTE PROFILE", remoteProfile_);

    const QString localDefault =
        QString("http://127.0.0.1:%1/rpc")
            .arg(tru_network::MAINNET_RPC_PORT);

    const QString publicGatewayDefault =
        QStringLiteral(
            "https://tokenizedrealutility.com/api/wallet/rpc"
        );

    const QString customRemoteDefault =
        QStringLiteral(
            "https://node.tokenizedrealutility.com/rpc"
        );

    const bool publicRemoteSelected =
        remoteMode_->isChecked() &&
        remoteProfile_->currentData().toString() == "public";

    endpoint_ = new QLineEdit(
        remoteMode_->isChecked()
            ? (publicRemoteSelected
                ? publicGatewayDefault
                : settings.value(
                    "remoteEndpoint",
                    customRemoteDefault).toString())
            : settings.value(
                "localEndpoint",
                localDefault).toString()
    );

    endpoint_->setObjectName("truEndpoint");
    endpoint_->setClearButtonEnabled(true);

    cookie_ = new QLineEdit(
        settings.value(
            "cookie",
            DesktopRpc::defaultCookiePath(
                tru_network::MAINNET_RPC_PORT
            )
        ).toString()
    );

    cookie_->setObjectName("truCookie");
    cookie_->setProperty(
        "truLocalCookiePath",
        cookie_->text()
    );

    sessionToken_ = new QLineEdit;
    sessionToken_->setEchoMode(QLineEdit::Password);
    sessionToken_->setObjectName("truSessionToken");
    sessionToken_->setClearButtonEnabled(true);
    sessionToken_->setPlaceholderText(
        "Session only — never saved"
    );

    form->addRow("Endpoint", endpoint_);
    form->addRow("RPC cookie file", cookie_);

    browseCookie_ =
        new QPushButton("Select cookie file…");

    form->addRow("", browseCookie_);
    form->addRow(
        "Access / session token",
        sessionToken_
    );

    auto actionRow = new QWidget;
    auto actionLayout = new QHBoxLayout(actionRow);

    actionLayout->setContentsMargins(0, 0, 0, 0);

    testConnection_ =
        new QPushButton("Test Connection");
    testConnection_->setObjectName("truSecondaryAction");

    connectButton_ =
        new QPushButton("Connect");
    connectButton_->setObjectName("truPrimaryAction");

    actionLayout->addWidget(testConnection_);
    actionLayout->addWidget(connectButton_);
    actionLayout->addStretch();

    form->addRow("", actionRow);

    auto help = new QLabel(
        "Local Node connects directly to TRU Core on this "
        "computer using loopback HTTP and may authenticate "
        "with the local RPC cookie or an in-memory token. "
        "Remote Node can use the fixed TRU Public Network gateway "
        "without running Core, or an authenticated Custom Remote Core. "
        "The public gateway is HTTPS, server-allowlisted and never receives "
        "a Core cookie/session credential. Custom Remote Core requires HTTPS "
        "and an explicit session access token. Remote cookie files are never used. "
        "Connection mode/profile and endpoint may be remembered; "
        "access tokens are never written to QSettings. "
        "Wallet passphrases and private keys are never "
        "requested by this Desktop RPC client."
    );

    help->setObjectName("truSecurityNote");
    help->setWordWrap(true);
    form->addRow(help);

    pages_->addTab(config, "Connection");

    // DESKTOP-WALLET-01: independent local-key wallet.
    // UI-02 adds only presentation and read-only asset discovery.
    auto* walletPage = new DesktopWalletWidget(&rpc_, pages_);
    pages_->insertTab(1, walletPage, "Wallet");

    auto* assetsPage =
        new DesktopAssetsWidget(&rpc_, walletPage, pages_);
    pages_->insertTab(2, assetsPage, "Assets");

    auto* aiPage =
        new DesktopAIWidget(&rpc_, walletPage, pages_);
    pages_->insertTab(3, aiPage, "AI");
    aiPage->applyTheme(initialTheme);

    connect(themeToggle, &QPushButton::clicked, this,
            [this, themeToggle, aiPage, darkThemeSheet, lightThemeOverrides] {
        const bool currentlyLight =
            property("truTheme").toString() == "light";
        const QString next = currentlyLight ? "dark" : "light";
        setProperty("truTheme", next);
        setStyleSheet(
            next == "light"
                ? darkThemeSheet + lightThemeOverrides
                : darkThemeSheet);
        aiPage->applyTheme(next);
        themeToggle->setText(
            next == "light" ? "DARK THEME" : "LIGHT THEME");
        QSettings settings("TRUBlockchain", "CoreDesktop");
        settings.setValue("theme", next);
        settings.sync();
    });

    // Keep consumer-facing pages first; direct RPC remains available
    // as the Advanced workspace rather than defining the wallet UI.
    const int configIndex = pages_->indexOf(config);
    if (configIndex >= 0) {
        pages_->removeTab(configIndex);
        pages_->insertTab(4, config, "Connection");
    }

    connect(
        browseCookie_,
        &QPushButton::clicked,
        this,
        [this] {
            auto path =
                QFileDialog::getOpenFileName(
                    this,
                    "Select local RPC cookie",
                    QDir::homePath()
                );

            if (!path.isEmpty()) {
                cookie_->setText(path);
                cookie_->setProperty(
                    "truLocalCookiePath",
                    path
                );
            }
        }
    );

    connect(
        localMode_,
        &QRadioButton::toggled,
        this,
        [this](bool checked) {
            if (checked)
                updateConnectionMode();
        }
    );

    connect(
        remoteMode_,
        &QRadioButton::toggled,
        this,
        [this](bool checked) {
            if (checked)
                updateConnectionMode();
        }
    );

    connect(
        remoteProfile_,
        QOverload<int>::of(&QComboBox::currentIndexChanged),
        this,
        [this](int) {
            if (remoteMode_->isChecked())
                updateConnectionMode();
        }
    );

    connect(
        testConnection_,
        &QPushButton::clicked,
        this,
        [this] {
            testConnection();
        }
    );

    connect(
        connectButton_,
        &QPushButton::clicked,
        this,
        [this] {
            applyConnection();
        }
    );

    updateConnectionMode();

    refresh_ = new QTimer(this);
    refresh_->setInterval(30000);
    connect(refresh_, &QTimer::timeout, this, [this] {
        if (isVisible() && pages_->currentIndex() == 0 && !writePending_) refreshOverview();
    });
    QString error;
    rpc_.configure(QUrl(endpoint_->text()), cookie_->text(), error);

    // NET-01: a fresh standalone Desktop defaults to the restricted public
    // gateway so ordinary users can read chain state and use the self-custody
    // wallet without installing Core. Integrated Core mode immediately calls
    // useLocalNode() after construction and replaces this transport.
    if (DesktopRpc::isPublicGatewayEndpoint(rpc_.endpoint())) {
        refresh_->start();
        QTimer::singleShot(
            500,
            this,
            [this] {
                refreshOverview();
            }
        );
    }
}

void DesktopPanel::useLocalNode(
    int port,
    const QByteArray& token) {

    localMode_->setChecked(true);

    endpoint_->setText(
        QString("http://127.0.0.1:%1/rpc")
            .arg(port)
    );

    cookie_->setText(
        DesktopRpc::defaultCookiePath(port)
    );

    cookie_->setProperty(
        "truLocalCookiePath",
        cookie_->text()
    );

    rpc_.setSessionToken(token);

    QString error;

    if (!rpc_.configure(
            QUrl(endpoint_->text()),
            cookie_->text(),
            error)) {

        connection_->setText(error);
        return;
    }

    // Integrated mode cannot accidentally switch
    // the wallet UI to another Core.
    for (int i = 0; i < pages_->count(); ++i) {
        if (pages_->tabText(i) == "Connection") {
            pages_->setTabEnabled(i, false);
            break;
        }
    }

    refresh_->start();

    QTimer::singleShot(
        500,
        this,
        [this] {
            refreshOverview();
        }
    );
}


void DesktopPanel::updateConnectionMode() {

    QSettings settings(
        "TRUBlockchain",
        "CoreDesktop"
    );

    const bool remote =
        remoteMode_->isChecked();

    const bool publicGateway =
        remote &&
        remoteProfile_->currentData().toString() == "public";

    const QString localDefault =
        QString("http://127.0.0.1:%1/rpc")
            .arg(tru_network::MAINNET_RPC_PORT);

    const QString publicGatewayDefault =
        QStringLiteral(
            "https://tokenizedrealutility.com/api/wallet/rpc"
        );

    const QString customRemoteDefault =
        QStringLiteral(
            "https://node.tokenizedrealutility.com/rpc"
        );

    remoteProfile_->setEnabled(remote);

    // Authentication material never crosses connection profiles.
    rpc_.setSessionToken(QByteArray());
    sessionToken_->clear();

    if (remote) {
        // Preserve the real local cookie path in memory, but make it
        // visually explicit that remote modes cannot consume it.
        if (cookie_->text() !=
            "Not used in Remote Node mode") {

            cookie_->setProperty(
                "truLocalCookiePath",
                cookie_->text()
            );
        }

        cookie_->setText(
            "Not used in Remote Node mode"
        );

        cookie_->setEnabled(false);
        browseCookie_->setEnabled(false);

        modeBadge_->setText("REMOTE NODE");

        if (publicGateway) {
            endpoint_->setText(publicGatewayDefault);
            endpoint_->setReadOnly(true);

            sessionToken_->clear();
            sessionToken_->setEnabled(false);
            sessionToken_->setPlaceholderText(
                "Not used — public gateway is server-allowlisted"
            );

            securityBadge_->setText(
                "PUBLIC GATEWAY"
            );

            connection_->setText(
                "Remote Node · TRU Public Network · "
                "restricted self-custody gateway · no local Core required."
            );
        } else {
            const QString current =
                endpoint_->text().trimmed();

            if (current.isEmpty() ||
                DesktopRpc::isPublicGatewayEndpoint(QUrl(current)) ||
                current.startsWith("http://127.0.0.1") ||
                current.startsWith("http://localhost") ||
                current.startsWith("http://[::1]")) {

                endpoint_->setText(
                    settings.value(
                        "remoteEndpoint",
                        customRemoteDefault
                    ).toString()
                );
            }

            endpoint_->setReadOnly(false);

            sessionToken_->setEnabled(true);
            sessionToken_->setPlaceholderText(
                "Paste session access token here — session only"
            );

            securityBadge_->setText(
                "HTTPS / SESSION TOKEN"
            );

            connection_->setText(
                "Remote Node · Custom Remote Core · "
                "TLS transport · session access token required."
            );
        }

    } else {
        const QString current =
            endpoint_->text().trimmed();

        if (current.startsWith("https://") ||
            current.isEmpty()) {

            endpoint_->setText(
                settings.value(
                    "localEndpoint",
                    localDefault
                ).toString()
            );
        }

        endpoint_->setReadOnly(false);

        QString localCookie =
            cookie_->property(
                "truLocalCookiePath"
            ).toString();

        if (localCookie.isEmpty() ||
            localCookie ==
                "Not used in Remote Node mode") {

            localCookie =
                settings.value(
                    "cookie",
                    DesktopRpc::defaultCookiePath(
                        tru_network::MAINNET_RPC_PORT
                    )
                ).toString();
        }

        cookie_->setText(localCookie);
        cookie_->setProperty(
            "truLocalCookiePath",
            localCookie
        );

        cookie_->setEnabled(true);
        browseCookie_->setEnabled(true);

        sessionToken_->setEnabled(true);
        sessionToken_->setPlaceholderText(
            "Optional — local cookie may authenticate instead"
        );

        modeBadge_->setText("LOCAL NODE");
        securityBadge_->setText(
            "LOOPBACK / COOKIE"
        );

        connection_->setText(
            "Local Node mode · loopback transport · "
            "TRU Core on this computer."
        );
    }

    // Public gateway exposes only the reviewed self-custody wallet surface.
    // Operator RPC workspace remains available for Local Node and authenticated
    // Custom Remote Core connections.
    for (int i = 0; i < pages_->count(); ++i) {
        if (pages_->tabText(i) == "Advanced") {
            pages_->setTabEnabled(i, !publicGateway);
            pages_->setTabToolTip(
                i,
                publicGateway
                    ? "Advanced Core Tools are unavailable through the restricted TRU Public Network gateway."
                    : QString());
            break;
        }
    }
}


void DesktopPanel::testConnection() {

    const QUrl endpoint(
        endpoint_->text().trimmed()
    );

    const bool publicGateway =
        DesktopRpc::isPublicGatewayEndpoint(endpoint);

    if (DesktopRpc::requiresSessionToken(endpoint) &&
        sessionToken_->text()
            .trimmed()
            .isEmpty()) {

        connection_->setText(
            "Custom Remote Core requires a session access token."
        );

        return;
    }

    // Probe using a temporary transport so Test Connection
    // never silently changes the active Desktop connection.
    auto probe = new DesktopRpc(this);

    QString error;

    if (!probe->configure(
            endpoint,
            DesktopRpc::isRemoteEndpoint(endpoint)
                ? QString()
                : cookie_->text().trimmed(),
            error)) {

        connection_->setText(error);
        probe->deleteLater();
        return;
    }

    probe->setSessionToken(
        publicGateway
            ? QByteArray()
            : sessionToken_->text().toUtf8()
    );

    connection_->setText(
        "Testing connection…"
    );

    testConnection_->setEnabled(false);
    connectButton_->setEnabled(false);

    probe->call(
        "getdesktopinfo",
        "{}",
        [this, probe, endpoint, publicGateway](
            const QJsonValue& value,
            const QByteArray&,
            const QString& error) {

            testConnection_->setEnabled(true);
            connectButton_->setEnabled(true);

            // Explicitly erase any probe token before disposal.
            probe->setSessionToken(QByteArray());
            probe->deleteLater();

            if (!error.isEmpty()) {
                connection_->setText(
                    "Connection test failed: " +
                    error
                );

                return;
            }

            const auto obj =
                value.toObject();

            const QString mode =
                publicGateway
                    ? "TRU Public Network"
                    : (DesktopRpc::isRemoteEndpoint(endpoint)
                        ? "Custom Remote Core"
                        : "Local Node");

            connection_->setText(
                "Connection test passed · " +
                mode +
                " · TRU Mainnet · height " +
                readable(obj.value("blocks"))
            );
        }
    );
}


void DesktopPanel::applyConnection() {

    const QUrl endpoint(
        endpoint_->text().trimmed()
    );

    const bool publicGateway =
        DesktopRpc::isPublicGatewayEndpoint(endpoint);

    if (DesktopRpc::requiresSessionToken(endpoint) &&
        sessionToken_->text()
            .trimmed()
            .isEmpty()) {

        connection_->setText(
            "Custom Remote Core requires a session access token."
        );

        return;
    }

    QString error;

    if (!rpc_.configure(
            endpoint,
            DesktopRpc::isRemoteEndpoint(endpoint)
                ? QString()
                : cookie_->text().trimmed(),
            error)) {

        connection_->setText(error);
        return;
    }

    rpc_.setSessionToken(
        publicGateway
            ? QByteArray()
            : sessionToken_->text().toUtf8()
    );

    // The visible secret is removed immediately.
    // It is never persisted in QSettings.
    sessionToken_->clear();

    QSettings settings(
        "TRUBlockchain",
        "CoreDesktop"
    );

    if (remoteMode_->isChecked()) {
        settings.setValue(
            "connectionMode",
            "remote"
        );

        const QString profile =
            publicGateway ? "public" : "custom";

        settings.setValue(
            "remoteProfile",
            profile
        );

        if (!publicGateway) {
            settings.setValue(
                "remoteEndpoint",
                endpoint_->text()
            );
        }

    } else {
        settings.setValue(
            "connectionMode",
            "local"
        );

        settings.setValue(
            "localEndpoint",
            endpoint_->text()
        );

        settings.setValue(
            "cookie",
            cookie_->text()
        );
    }

    refresh_->start();
    refreshOverview();
}


void DesktopPanel::refreshOverview() {
    if (overviewPending_) return;
    overviewPending_ = true;
    rpc_.call("getdesktopinfo", "{}", [this](const QJsonValue& value, const QByteArray&, const QString& error) {
        if (!error.isEmpty()) {
            overviewPending_ = false;
            connection_->setText("Disconnected / stale: " + error);
            height_->setText("—"); peers_->setText("—"); rate_->setText("—");
            if (auto* difficulty =
                    findChild<QLabel*>("truDifficultyValue")) {
                difficulty->setText("—");
            }
            if (auto* coreVersion =
                    findChild<QLabel*>("truCoreVersionValue")) {
                coreVersion->setText("—");
            }
            tip_->setText("Best tip: unavailable"); miners_->setRowCount(0);
            return;
        }
        auto obj = value.toObject();
        height_->setText(readable(obj.value("blocks")));
        peers_->setText(readable(obj.value("connections")));

        if (auto* difficulty =
                findChild<QLabel*>("truDifficultyValue")) {
            const std::uint32_t bits =
                static_cast<std::uint32_t>(
                    obj.value("difficulty").toVariant().toULongLong());
            difficulty->setText(formatDifficulty(bits));
            difficulty->setToolTip(
                "Compact target: " +
                obj.value("difficultyhex").toString("—"));
        }

        if (auto* coreVersion =
                findChild<QLabel*>("truCoreVersionValue")) {
            coreVersion->setText(
                formatCoreVersion(
                    obj.value("version").toString()));
        }

        tip_->setText("Best tip: " + obj.value("bestblockhash").toString());
        const QString connectionMode =
            DesktopRpc::isPublicGatewayEndpoint(
                rpc_.endpoint()
            )
                ? "TRU Public Network"
                : (DesktopRpc::isRemoteEndpoint(
                        rpc_.endpoint())
                    ? "Custom Remote Core"
                    : "Local Node");

        connection_->setText(
            "Connected · " +
            connectionMode +
            " · TRU Mainnet · " +
            rpc_.endpoint().toString() +
            " · " +
            QDateTime::currentDateTime()
                .toString("HH:mm:ss")
        );
        rpc_.call("getallminers", "{}", [this](const QJsonValue& v, const QByteArray&, const QString& err) {
            overviewPending_ = false;
            miners_->setRowCount(0);
            if (!err.isEmpty()) { rate_->setText("—"); connection_->setText("Node connected; miner data unavailable: " + err); return; }
            auto data = v.toObject();
            const double rate = data.value("totalHashRate").toDouble();
            rate_->setText(QString::number(rate / 1e6, 'f', 2) + " MH/s");
            for (const auto& entry : data.value("miners").toArray()) {
                auto miner = entry.toObject();
                const int row = miners_->rowCount();
                miners_->insertRow(row);
                const bool reporting = miner.value("isActive").toBool();
                QStringList cols{miner.value("address").toString(miner.value("minerAddress").toString()),
                    reporting ? "reporting" : "unreported", readable(miner.value("hashRate")), readable(miner.value("blocksMined"))};
                for (int c = 0; c < cols.size(); ++c) {
                    auto item = new QTableWidgetItem(cols[c]);
                    item->setForeground(QColor(reporting ? "#52d6a0" : "#62aaf8"));
                    miners_->setItem(row, c, item);
                }
            }
        });
    });
}

void DesktopPanel::selectOperation() {
    if (operation_->currentIndex() < 0) return;
    const auto& op = operations[operation_->currentData().toInt()];
    params_->setPlainText(op.params);
    operationHelp_->setText(QString(op.help) + "\nMethod: " + op.method);
    run_->setText(op.write ? "Review operation…" : "Run query");
}

void DesktopPanel::runOperation() {
    if (writePending_ || operation_->currentIndex() < 0) return;
    const auto op = operations[operation_->currentData().toInt()];
    QByteArray params = params_->toPlainText().toUtf8().trimmed();
    QJsonParseError pe;
    const auto doc = QJsonDocument::fromJson(params, &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isObject()) {
        output_->setPlainText("Enter a valid JSON object: " + pe.errorString()); return;
    }
    if (QString(op.group) == "Swaps") {
        bool ok = false;
        auto secret = QInputDialog::getText(this, "Swap capability", "Local TRU_SWAP_RPC_TOKEN (not saved):", QLineEdit::Password, {}, &ok);
        if (!ok || secret.isEmpty()) return;
        if (doc.object().contains("authToken")) { output_->setPlainText("Remove authToken from the editor; enter it only in the password dialog."); return; }
        QByteArray encoded = QJsonDocument(QJsonArray{secret}).toJson(QJsonDocument::Compact);
        encoded = encoded.mid(1, encoded.size() - 2);
        secret.fill(QChar('\0')); secret.clear();
        params.chop(1);
        params += (doc.object().isEmpty() ? "" : ",") + QByteArray("\"authToken\":") + encoded + "}";
        encoded.fill('\0');
    }
    if (op.write) {
        QMessageBox confirm(QMessageBox::Warning, "Review " + QString(op.title),
            "Method: " + QString(op.method) + "\n\n" + QString(op.help) + "\n\nSubmit once to the connected node?",
            QMessageBox::Yes | QMessageBox::Cancel, this);
        confirm.setTextFormat(Qt::PlainText);
        confirm.setDefaultButton(QMessageBox::Cancel);
        confirm.setDetailedText(params_->toPlainText());
        if (confirm.exec() != QMessageBox::Yes) return;
        if (QString(op.method) == "burntoken") {
            bool ok = false;
            const auto typed = QInputDialog::getText(this, "Permanent token retirement", "Type BURN to retire this holding permanently:", QLineEdit::Normal, {}, &ok);
            if (!ok || typed != "BURN") return;
        }
    }
    writePending_ = true;
    run_->setEnabled(false);
    category_->setEnabled(false); operation_->setEnabled(false); params_->setEnabled(false);
    output_->setPlainText("Request in progress…");
    rpc_.call(op.method, params, [this, op](const QJsonValue&, const QByteArray& raw, const QString& error) {
        writePending_ = false;
        run_->setEnabled(true);
        category_->setEnabled(true); operation_->setEnabled(true); params_->setEnabled(true);
        // Preserve raw numeric representations in receipts; never pretty-print
        // monetary uint64 values through QJsonDocument.
        output_->setPlainText(error.isEmpty() ? QString::fromUtf8(raw) : "ERROR: " + error);
        if (op.write && error.isEmpty()) output_->appendPlainText("\nRequest completed. Check transaction confirmation separately where applicable.");
    });
    params.fill('\0');
}
