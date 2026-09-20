#include "desktop_panel.h"
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
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRadioButton>
#include <QSettings>
#include <QSplitter>
#include <QTabWidget>
#include <QTableWidget>
#include <QTimer>
#include <QVariant>
#include <QVBoxLayout>

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
}

DesktopPanel::DesktopPanel(QWidget* parent) : QWidget(parent), rpc_(this) {

    // RPC-01C — final cross-platform TRU Desktop visual layer.
    // Presentation only: no RPC, wallet, consensus or P2P semantics.
    setStyleSheet(R"TRUQSS(
        QWidget {
            background-color: #05111e;
            color: #d9e9f5;
            font-size: 13px;
        }

        QTabWidget::pane {
            border: 1px solid #1b4562;
            border-radius: 8px;
            background-color: #061522;
            top: -1px;
        }

        QTabBar::tab {
            background-color: #0a1c2d;
            color: #8eaec4;
            border: 1px solid #173c56;
            border-bottom: none;
            padding: 10px 18px;
            min-width: 86px;
        }

        QTabBar::tab:selected {
            background-color: #0d3549;
            color: #70f0e1;
            border-color: #2b7792;
        }

        QTabBar::tab:hover {
            color: #9df8ef;
            background-color: #0c2a3d;
        }

        QGroupBox {
            background-color: #071827;
            border: 1px solid #1a4764;
            border-radius: 11px;
            margin-top: 13px;
            padding: 17px 10px 10px 10px;
            color: #8fbbd2;
            font-weight: 700;
        }

        QGroupBox::title {
            subcontrol-origin: margin;
            left: 13px;
            padding: 0 7px;
            color: #9ccbe2;
        }

        QGroupBox[truMetric="true"] {
            background: qlineargradient(
                x1:0, y1:0, x2:1, y2:1,
                stop:0 #071827,
                stop:0.55 #081c2c,
                stop:1 #092338
            );
            border: 1px solid #245875;
            min-height: 92px;
        }

        QLabel#truMetricValue {
            color: #67f4df;
            font-size: 29px;
            font-weight: 800;
            padding: 7px;
        }

        QLabel#truBrand {
            color: #69eaff;
            font-size: 25px;
            font-weight: 800;
            padding: 0px;
        }

        QLabel#truSubtitle {
            color: #688da5;
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
            border-radius: 10px;
            padding: 5px 10px;
            font-size: 10px;
            font-weight: 800;
        }

        QLabel#truSecurityBadge {
            color: #71caff;
        }

        QLabel#truMainnetBadge {
            color: #c09aff;
            border-color: #594b85;
        }

        QLabel#truSignalRail {
            background-color: #061723;
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
                stop:1 #071b2b
            );
            color: #8ee9de;
            border: 1px solid #215b74;
            border-left: 3px solid #49dccd;
            border-radius: 7px;
            padding: 9px 12px;
            font-weight: 700;
        }

        QLabel#truTip {
            background-color: #061521;
            color: #7ea6bd;
            border: 1px solid #173b52;
            border-radius: 6px;
            padding: 8px 10px;
            font-family: "DejaVu Sans Mono", "Menlo", "Consolas";
        }

        QLabel#truSectionTitle {
            color: #e4f3fb;
            font-size: 18px;
            font-weight: 800;
            padding: 8px 0px 4px 1px;
        }

        QLabel#truSecurityNote {
            background-color: #071a2a;
            color: #89aabc;
            border: 1px solid #19445e;
            border-radius: 7px;
            padding: 10px;
        }

        QLabel#truSourceNote {
            color: #668aa1;
            padding: 5px 2px;
        }

        QPushButton {
            background-color: #0c3047;
            color: #d9f7fb;
            border: 1px solid #24708d;
            border-radius: 7px;
            padding: 9px 15px;
            font-weight: 700;
        }

        QPushButton:hover {
            background-color: #10435c;
            border-color: #47cce8;
            color: #ffffff;
        }

        QPushButton:pressed {
            background-color: #09283b;
        }

        QPushButton:disabled {
            background-color: #081927;
            color: #496273;
            border-color: #173346;
        }

        QPushButton#truPrimaryAction {
            background: qlineargradient(
                x1:0, y1:0, x2:1, y2:0,
                stop:0 #0d4b62,
                stop:1 #0b6670
            );
            color: #eaffff;
            border-color: #43d8d0;
        }

        QPushButton#truSecondaryAction {
            background-color: #0b273d;
            border-color: #29617e;
        }

        QLineEdit,
        QPlainTextEdit,
        QComboBox {
            background-color: #091a2b;
            color: #d9edf7;
            border: 1px solid #294b63;
            border-radius: 6px;
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

        QTableWidget {
            background-color: #071625;
            alternate-background-color: #091c2d;
            border: 1px solid #1d4964;
            border-radius: 7px;
            gridline-color: #15384f;
            selection-background-color: #113d56;
            selection-color: #e9ffff;
        }

        QHeaderView::section {
            background-color: #0b2235;
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

    auto root = new QVBoxLayout(this);
    auto brandRow = new QHBoxLayout;

    auto brandStack = new QVBoxLayout;

    auto brand = new QLabel("TRU  /  CORE DESKTOP");
    brand->setObjectName("truBrand");

    auto subtitle =
        new QLabel("MAINNET RPC CONTROL PLANE  //  LOCAL + REMOTE");
    subtitle->setObjectName("truSubtitle");

    brandStack->addWidget(brand);
    brandStack->addWidget(subtitle);

    brandRow->addLayout(brandStack);
    brandRow->addStretch();

    auto mainnetBadge = new QLabel("TRU MAINNET");
    mainnetBadge->setObjectName("truMainnetBadge");

    modeBadge_ = new QLabel("LOCAL NODE");
    modeBadge_->setObjectName("truModeBadge");

    securityBadge_ = new QLabel("LOOPBACK / COOKIE");
    securityBadge_->setObjectName("truSecurityBadge");

    brandRow->addWidget(mainnetBadge, 0, Qt::AlignVCenter);
    brandRow->addWidget(modeBadge_, 0, Qt::AlignVCenter);
    brandRow->addWidget(securityBadge_, 0, Qt::AlignVCenter);

    root->addLayout(brandRow);

    auto signalRail = new QLabel(
        "BLOCKCHAIN TELEMETRY  //  PEER MESH  //  MINER NETWORK  //  SECURE RPC"
    );
    signalRail->setObjectName("truSignalRail");
    root->addWidget(signalRail);

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
    pages_->addTab(tools, "Core tools");
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
        settings.value("connectionMode", "local").toString();

    remoteMode_->setChecked(savedMode == "remote");
    localMode_->setChecked(!remoteMode_->isChecked());

    modeLayout->addWidget(localMode_);
    modeLayout->addWidget(remoteMode_);
    modeLayout->addStretch();

    form->addRow("CONNECTION MODE", modeRow);

    const QString localDefault =
        QString("http://127.0.0.1:%1/rpc")
            .arg(tru_network::MAINNET_RPC_PORT);

    const QString remoteDefault =
        QStringLiteral(
            "https://node.tokenizedrealutility.com/rpc"
        );

    endpoint_ = new QLineEdit(
        settings.value(
            remoteMode_->isChecked()
                ? "remoteEndpoint"
                : "localEndpoint",
            remoteMode_->isChecked()
                ? remoteDefault
                : localDefault
        ).toString()
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
        "Remote Node requires HTTPS and an explicit session "
        "access token. Remote cookie files are never used. "
        "Connection mode and endpoint may be remembered; "
        "access tokens are never written to QSettings. "
        "Wallet passphrases and private keys are never "
        "requested by this Desktop RPC client."
    );

    help->setObjectName("truSecurityNote");
    help->setWordWrap(true);
    form->addRow(help);

    pages_->addTab(config, "Connection");

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
    // No automatic connection in constructor: integrated mode supplies its
    // actual port/token after construction, before the first request.
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
    pages_->setTabEnabled(2, false);

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

    const QString localDefault =
        QString("http://127.0.0.1:%1/rpc")
            .arg(tru_network::MAINNET_RPC_PORT);

    const QString remoteDefault =
        QStringLiteral(
            "https://node.tokenizedrealutility.com/rpc"
        );

    // Authentication material never crosses connection modes.
    rpc_.setSessionToken(QByteArray());
    sessionToken_->clear();

    if (remote) {
        const QString current =
            endpoint_->text().trimmed();

        if (current.startsWith("http://127.0.0.1") ||
            current.startsWith("http://localhost") ||
            current.startsWith("http://[::1]")) {

            endpoint_->setText(
                settings.value(
                    "remoteEndpoint",
                    remoteDefault
                ).toString()
            );
        }

        // Preserve the real local cookie path in memory, but make it
        // visually explicit that remote mode cannot consume it.
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

        sessionToken_->setPlaceholderText(
            "Paste session access token here — session only"
        );

        modeBadge_->setText("REMOTE NODE");
        securityBadge_->setText(
            "HTTPS / SESSION TOKEN"
        );

        connection_->setText(
            "Remote Node mode  //  TLS transport armed  //  "
            "session access token required."
        );

    } else {
        if (endpoint_->text()
                .trimmed()
                .startsWith("https://")) {

            endpoint_->setText(
                settings.value(
                    "localEndpoint",
                    localDefault
                ).toString()
            );
        }

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

        sessionToken_->setPlaceholderText(
            "Optional — local cookie may authenticate instead"
        );

        modeBadge_->setText("LOCAL NODE");
        securityBadge_->setText(
            "LOOPBACK / COOKIE"
        );

        connection_->setText(
            "Local Node mode  //  loopback transport  //  "
            "TRU Core on this computer."
        );
    }
}


void DesktopPanel::testConnection() {

    const QUrl endpoint(
        endpoint_->text().trimmed()
    );

    if (remoteMode_->isChecked() &&
        sessionToken_->text()
            .trimmed()
            .isEmpty()) {

        connection_->setText(
            "Remote Node requires a session access token."
        );

        return;
    }

    // Probe using a temporary transport so Test Connection
    // never silently changes the active Desktop connection.
    auto probe = new DesktopRpc(this);

    QString error;

    if (!probe->configure(
            endpoint,
            remoteMode_->isChecked()
                ? QString()
                : cookie_->text().trimmed(),
            error)) {

        connection_->setText(error);
        probe->deleteLater();
        return;
    }

    probe->setSessionToken(
        sessionToken_->text().toUtf8()
    );

    connection_->setText(
        "Testing connection…"
    );

    testConnection_->setEnabled(false);
    connectButton_->setEnabled(false);

    probe->call(
        "getinfo",
        "{}",
        [this, probe, endpoint](
            const QJsonValue& value,
            const QByteArray&,
            const QString& error) {

            testConnection_->setEnabled(true);
            connectButton_->setEnabled(true);

            // Explicitly erase the probe token before disposal.
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
                DesktopRpc::isRemoteEndpoint(endpoint)
                    ? "Remote Node"
                    : "Local Node";

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

    if (remoteMode_->isChecked() &&
        sessionToken_->text()
            .trimmed()
            .isEmpty()) {

        connection_->setText(
            "Remote Node requires a session access token."
        );

        return;
    }

    QString error;

    if (!rpc_.configure(
            endpoint,
            remoteMode_->isChecked()
                ? QString()
                : cookie_->text().trimmed(),
            error)) {

        connection_->setText(error);
        return;
    }

    rpc_.setSessionToken(
        sessionToken_->text().toUtf8()
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

        settings.setValue(
            "remoteEndpoint",
            endpoint_->text()
        );

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
    rpc_.call("getinfo", "{}", [this](const QJsonValue& value, const QByteArray&, const QString& error) {
        if (!error.isEmpty()) {
            overviewPending_ = false;
            connection_->setText("Disconnected / stale: " + error);
            height_->setText("—"); peers_->setText("—"); rate_->setText("—");
            tip_->setText("Best tip: unavailable"); miners_->setRowCount(0);
            return;
        }
        auto obj = value.toObject();
        height_->setText(readable(obj.value("blocks")));
        peers_->setText(readable(obj.value("connections")));
        tip_->setText("Best tip: " + obj.value("bestblockhash").toString());
        const QString connectionMode =
            DesktopRpc::isRemoteEndpoint(
                rpc_.endpoint()
            )
                ? "Remote Node"
                : "Local Node";

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
