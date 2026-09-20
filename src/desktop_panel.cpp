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
#include <QSettings>
#include <QSplitter>
#include <QTabWidget>
#include <QTableWidget>
#include <QTimer>
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
    auto layout = new QVBoxLayout(box);
    auto value = new QLabel("—");
    value->setStyleSheet("font-size: 27px; font-weight: bold; color: #5fe0cf; padding: 8px;");
    layout->addWidget(value);
    row->addWidget(box);
    return value;
}
}

DesktopPanel::DesktopPanel(QWidget* parent) : QWidget(parent), rpc_(this) {
    auto root = new QVBoxLayout(this);
    auto brand = new QLabel("TRU  /  CORE DESKTOP");
    brand->setStyleSheet("font-size: 23px; font-weight: bold; color: #66dbef; padding: 8px 0;");
    root->addWidget(brand);
    connection_ = new QLabel("Configure your local node connection.");
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
    tip_->setTextFormat(Qt::PlainText);
    tip_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    tip_->setWordWrap(true);
    overviewLayout->addWidget(tip_);
    auto refreshButton = new QPushButton("Refresh node snapshot");
    overviewLayout->addWidget(refreshButton, 0, Qt::AlignLeft);
    auto miningTitle = new QLabel("ACTIVE MINERS");
    miningTitle->setStyleSheet("font-weight: bold; font-size: 17px; padding-top: 12px;");
    overviewLayout->addWidget(miningTitle);
    miners_ = new QTableWidget(0, 4);
    miners_->setHorizontalHeaderLabels({"Address", "Status", "Hash rate (H/s)", "Blocks mined"});
    miners_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    miners_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    miners_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    miners_->setSelectionBehavior(QAbstractItemView::SelectRows);
    overviewLayout->addWidget(miners_);
    auto sourceNote = new QLabel("Telemetry from the connected node. Unreported producers may not appear in this RPC view.");
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
    endpoint_ = new QLineEdit(settings.value("endpoint", QString("http://127.0.0.1:%1/rpc").arg(tru_network::MAINNET_RPC_PORT)).toString());
    cookie_ = new QLineEdit(settings.value("cookie", DesktopRpc::defaultCookiePath(tru_network::MAINNET_RPC_PORT)).toString());
    sessionToken_ = new QLineEdit;
    sessionToken_->setEchoMode(QLineEdit::Password);
    sessionToken_->setPlaceholderText("Optional; retained only for this session");
    form->addRow("Local RPC endpoint", endpoint_);
    form->addRow("RPC cookie file", cookie_);
    auto browse = new QPushButton("Select cookie file…");
    form->addRow("", browse);
    form->addRow("Session RPC token", sessionToken_);
    auto apply = new QPushButton("Connect");
    form->addRow("", apply);
    auto help = new QLabel("Use the existing node's cookie or TRU_RPC_TOKEN. RPC credentials never go to a public host. "
        "A desktop client does not start, unlock or synchronize a full node. On Windows, connect to a local forward to your running Linux node. "
        "Wallet passphrases and private keys are never requested by this RPC client.");
    help->setWordWrap(true);
    form->addRow(help);
    pages_->addTab(config, "Connection");
    connect(browse, &QPushButton::clicked, this, [this] {
        auto path = QFileDialog::getOpenFileName(this, "Select local RPC cookie", QDir::homePath());
        if (!path.isEmpty()) cookie_->setText(path);
    });
    connect(apply, &QPushButton::clicked, this, [this]{ applyConnection(); });
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

void DesktopPanel::useLocalNode(int port, const QByteArray& token) {
    endpoint_->setText(QString("http://127.0.0.1:%1/rpc").arg(port));
    cookie_->setText(DesktopRpc::defaultCookiePath(port));
    rpc_.setSessionToken(token);
    QString error;
    if (!rpc_.configure(QUrl(endpoint_->text()), cookie_->text(), error)) {
        connection_->setText(error); return;
    }
    // Embedded mode cannot accidentally switch the wallet UI to another core.
    pages_->setTabEnabled(2, false);
    refresh_->start();
    QTimer::singleShot(500, this, [this]{ refreshOverview(); });
}

void DesktopPanel::applyConnection() {
    QString error;
    if (!rpc_.configure(QUrl(endpoint_->text().trimmed()), cookie_->text().trimmed(), error)) {
        connection_->setText(error); return;
    }
    rpc_.setSessionToken(sessionToken_->text().toUtf8());
    sessionToken_->clear();
    QSettings settings("TRUBlockchain", "CoreDesktop");
    settings.setValue("endpoint", endpoint_->text());
    settings.setValue("cookie", cookie_->text());
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
        connection_->setText("Connected  ·  " + rpc_.endpoint().toString() + "  ·  " + QDateTime::currentDateTime().toString("HH:mm:ss"));
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
