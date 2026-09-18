// walletgui.cpp
#include "tru_network_params.h"
#include "walletgui.h"
#include <QMessageBox>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QGroupBox>
#include <QHeaderView>
#include <QClipboard>
#include <QApplication>
#include <QFileDialog>
#include <QInputDialog>
#include <QSettings>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDialog>
#include <qrencode.h>
#include <QPainter>
#include <QPixmap>
#include <QResizeEvent>
#include <sstream>
#include <iomanip>
#include <cmath>
#include "wallet_styles.h"
#include "animated_background.h"
#include "tokens.h"
#include <algorithm> 
#include <cmath>
#include "utils.h"           
#include "script_interpreter.h"  
#include <openssl/sha.h>     
#include <openssl/ripemd.h>  
#include <inttypes.h>
#include "address_helpers.h"
#include "tru_amount.h"
#include <QMenu>

//HELPER FUNCTIONS
std::string getJsonString(const nlohmann::json& j, const std::string& key, const std::string& defaultValue = "") {
    try {
        if (j.contains(key)) {
            if (j[key].is_string()) {
                return j[key].get<std::string>();
            } else if (j[key].is_number()) {
                // Convert number to string
                return std::to_string(j[key].get<int>());
            } else if (j[key].is_boolean()) {
                return j[key].get<bool>() ? "true" : "false";
            }
        }
    } catch (...) {
        // Return default on any error
    }
    return defaultValue;
}


int getJsonInt(const nlohmann::json& j, const std::string& key, int defaultValue = 0) {
    try {
        if (j.contains(key)) {
            if (j[key].is_number()) {
                return j[key].get<int>();
            } else if (j[key].is_string()) {
                // Try to parse string as integer
                std::string str = j[key].get<std::string>();
                return std::stoi(str);
            }
        }
    } catch (...) {
        // Return default on any error
    }
    return defaultValue;
}


uint64_t getJsonUint64(const nlohmann::json& j, const std::string& key, uint64_t defaultValue = 0) {
    try {
        if (j.contains(key)) {
            if (j[key].is_number()) {
                return j[key].get<uint64_t>();
            } else if (j[key].is_string()) {
                // Try to parse string as uint64_t
                std::string str = j[key].get<std::string>();
                return std::stoull(str);
            }
        }
    } catch (...) {
        // Return default on any error
    }
    return defaultValue;
}


WalletGUI::WalletGUI(Wallet &walletRef, QWidget *parent)
    : QWidget(parent), wallet(walletRef), is_mining(false), cached_balance(0.0), currentTheme("dark_futuristic") {
    setupUI();
    
    // Apply modern theme
    applyTheme(currentTheme);
    
    // Setup auto-refresh timer
    refresh_timer = new QTimer(this);
    connect(refresh_timer, &QTimer::timeout, this, &WalletGUI::auto_refresh);
    
    // Load settings
    load_settings();

    if (wallet.isLocalChainAvailable()) {
        wallet.updateLocalUTXOSetFromChain();
    }
        
    // Initial refresh
    refresh_addresses();
    updateBalanceDisplay();
    updateBlockHeight();
    refresh_tokens();
    updateNetworkStatus();
    
    // Set window properties
    setWindowTitle("TRU Blockchain Wallet - Futuristic Edition");
    resize(1100, 750);
    
    // Load custom logo/branding
    loadCustomLogo();
}

WalletGUI::~WalletGUI() {
    save_settings();
}

void WalletGUI::setupUI() {
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(15, 15, 15, 15);
    
    // Create animated background
    backgroundWidget = new AnimatedBackground(this);
    backgroundWidget->lower();
    
    // Create glow border effect
    glowBorder = new GlowBorder(this);
    glowBorder->lower();
    
    // Logo/branding area
    QHBoxLayout *headerLayout = new QHBoxLayout();
    logoLabel = new QLabel(this);
    logoLabel->setAlignment(Qt::AlignCenter);
    headerLayout->addWidget(logoLabel);
    mainLayout->addLayout(headerLayout);
    
    // Create tab widget
    tabWidget = new QTabWidget(this);
    tabWidget->setDocumentMode(true);
    
    // Setup individual tabs
    setupWalletTab();
    setupSendTab();
    setupTokensTab();
    setupTRUScriptTab();
    setupTransactionsTab();
    setupSettingsTab();
    setupContractsTab();
    
    mainLayout->addWidget(tabWidget);
    
    // Status bar area with futuristic styling
    QHBoxLayout *statusLayout = new QHBoxLayout();
    balance_label = new QLabel("Balance: 0.00000000 TRU", this);
    balance_label->setObjectName("balance_label");
    network_status_label = new QLabel("Network: Disconnected", this);
    network_status_label->setStyleSheet("QLabel { color: red; font-weight: bold; }");
    statusLayout->addWidget(network_status_label);
        
    // Initialize block_height_label HERE before using it
    block_height_label = new QLabel("Block: 0", this);
    block_height_label->setStyleSheet("QLabel { color: #00d4ff; font-weight: bold; }");
    
    mining_status_label = new QLabel("Mining: Idle", this);
    mining_status_label->setStyleSheet("QLabel { color: #00d4ff; font-weight: bold; }");
    
    statusLayout->addWidget(balance_label);
    statusLayout->addStretch();
    statusLayout->addWidget(block_height_label);
    statusLayout->addWidget(mining_status_label);
    
    mainLayout->addLayout(statusLayout);
}

void WalletGUI::setupWalletTab() {
    QWidget *walletTab = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(walletTab);
    
    // Wallet controls
    QGroupBox *walletGroup = new QGroupBox("Wallet Management");
    QVBoxLayout *walletLayout = new QVBoxLayout();
    
    // Button row 1
    QHBoxLayout *buttonRow1 = new QHBoxLayout();
    create_wallet_button = new QPushButton("Create New Wallet", this);
    import_key_button = new QPushButton("Import Private Key", this);
    backup_button = new QPushButton("Backup Wallet", this);
    restore_button = new QPushButton("Restore Wallet", this);
    
    buttonRow1->addWidget(create_wallet_button);
    buttonRow1->addWidget(import_key_button);
    buttonRow1->addWidget(backup_button);
    buttonRow1->addWidget(restore_button);
    
    walletLayout->addLayout(buttonRow1);
    
    // Current address selection
    QHBoxLayout *addressRow = new QHBoxLayout();
    addressRow->addWidget(new QLabel("Current Address:"));
    address_combo = new QComboBox(this);
    address_combo->setMinimumWidth(400);
    copy_address_button = new QPushButton("Copy", this);
    show_qr_button = new QPushButton("QR Code", this);
    generate_address_button = new QPushButton("Generate New", this);
    
    addressRow->addWidget(address_combo);
    addressRow->addWidget(copy_address_button);
    addressRow->addWidget(show_qr_button);
    addressRow->addWidget(generate_address_button);
    
    walletLayout->addLayout(addressRow);
    walletGroup->setLayout(walletLayout);
    layout->addWidget(walletGroup);
    
    // Address table
    QGroupBox *addressGroup = new QGroupBox("All Addresses");
    QVBoxLayout *addressTableLayout = new QVBoxLayout();
    
    address_table = new QTableWidget(0, 3, this);
    address_table->setHorizontalHeaderLabels(QStringList() << "Index" << "Address" << "Balance");
    address_table->horizontalHeader()->setStretchLastSection(true);
    address_table->setAlternatingRowColors(true);
    address_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    
    addressTableLayout->addWidget(address_table);
    addressGroup->setLayout(addressTableLayout);
    layout->addWidget(addressGroup);
    
    // Mining controls
    QGroupBox *miningGroup = new QGroupBox("Mining");
    QHBoxLayout *miningLayout = new QHBoxLayout();
    mine_button = new QPushButton("Start Mining", this);
    mine_button->setObjectName("mine_button"); // For special styling
    mine_button->setMinimumHeight(50);
    mine_button->setIcon(QIcon::fromTheme("applications-engineering"));
    miningLayout->addWidget(mine_button);
    miningGroup->setLayout(miningLayout);
    layout->addWidget(miningGroup);
    
    // Connect signals
    connect(create_wallet_button, &QPushButton::clicked, this, &WalletGUI::create_wallet);
    connect(import_key_button, &QPushButton::clicked, this, &WalletGUI::import_private_key);
    connect(generate_address_button, &QPushButton::clicked, this, &WalletGUI::generate_new_address);
    connect(copy_address_button, &QPushButton::clicked, this, &WalletGUI::copy_current_address);
    connect(show_qr_button, &QPushButton::clicked, this, &WalletGUI::show_qr_code);
    connect(backup_button, &QPushButton::clicked, this, &WalletGUI::backup_wallet);
    connect(restore_button, &QPushButton::clicked, this, &WalletGUI::restore_wallet);
    connect(mine_button, &QPushButton::clicked, this, &WalletGUI::mine);
    connect(address_combo, QOverload<int>::of(&QComboBox::currentIndexChanged), 
            this, &WalletGUI::on_address_selection_changed);
    
    tabWidget->addTab(walletTab, "Wallet");

    QPushButton *refresh_wallet_button = new QPushButton("Refresh Wallet", this);
    refresh_wallet_button->setIcon(QIcon::fromTheme("view-refresh"));
    connect(refresh_wallet_button, &QPushButton::clicked, [this]() {
        if (wallet.isLocalChainAvailable()) {
            try {
                wallet.updateLocalUTXOSetFromChain();
                updateBalanceDisplay();
                updateBlockHeight();
                refresh_addresses();
                showMessage("Wallet Refreshed", "Wallet synchronized with blockchain");
            } catch (const std::exception& e) {
                showMessage("Refresh Error", QString::fromStdString(e.what()), true);
            }
        } else {
            showMessage("No Local Chain", "No local blockchain available to sync with");
        }
    });
    buttonRow1->addWidget(refresh_wallet_button);
    
    QPushButton *sync_blockchain_button = new QPushButton("Sync Blockchain", this);
    sync_blockchain_button->setIcon(QIcon::fromTheme("network-connect"));
    connect(sync_blockchain_button, &QPushButton::clicked, [this]() {
        try {
            if (wallet.isLocalChainAvailable()) {
                showMessage("Sync Status", "Manual sync not yet implemented.\nThe blockchain syncs automatically when connected to peers.");
                updateBlockHeight();
            
                const Blockchain& blockchain = wallet.getBlockchain();
                int height = blockchain.getBestTipHeight();
                showMessage("Current Status", 
                        QString("Current block height: %1").arg(height));
            }
        } catch (const std::exception& e) {
            showMessage("Sync Error", QString::fromStdString(e.what()), true);
        }
    });
    buttonRow1->addWidget(sync_blockchain_button);    
        
}

void WalletGUI::setupSendTab() {
    QWidget *sendTab = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(sendTab);
    
    QGroupBox *sendGroup = new QGroupBox("Send Transaction");
    QGridLayout *sendLayout = new QGridLayout();
    
    // From address
    sendLayout->addWidget(new QLabel("From:"), 0, 0);
    from_address_combo = new QComboBox(this);
    from_address_combo->setMinimumWidth(400);
    sendLayout->addWidget(from_address_combo, 0, 1);
    
    available_balance_label = new QLabel("Available: 0.00000000 TRU", this);
    sendLayout->addWidget(available_balance_label, 0, 2);
    
    // To address
    sendLayout->addWidget(new QLabel("To:"), 1, 0);
    recipient_edit = new QLineEdit(this);
    recipient_edit->setPlaceholderText("Recipient Address");
    sendLayout->addWidget(recipient_edit, 1, 1, 1, 2);
    
    // Amount
    sendLayout->addWidget(new QLabel("Amount:"), 2, 0);
    amount_edit = new QLineEdit(this);
    amount_edit->setPlaceholderText("0.00000000");
    sendLayout->addWidget(amount_edit, 2, 1);
    sendLayout->addWidget(new QLabel("TRU"), 2, 2);
    
    // Fee
    sendLayout->addWidget(new QLabel("Fee:"), 3, 0);
    fee_edit = new QLineEdit(this);
    fee_edit->setText("0.0001");
    sendLayout->addWidget(fee_edit, 3, 1);
    sendLayout->addWidget(new QLabel("TRU"), 3, 2);
    
    // Send button and progress
    send_button = new QPushButton("Send Transaction", this);
    send_button->setMinimumHeight(40);
    sendLayout->addWidget(send_button, 4, 0, 1, 3);
    
    send_progress = new QProgressBar(this);
    send_progress->setVisible(false);
    sendLayout->addWidget(send_progress, 5, 0, 1, 3);
    
    sendGroup->setLayout(sendLayout);
    layout->addWidget(sendGroup);
    layout->addStretch();
    
    // Connect signals
    connect(send_button, &QPushButton::clicked, this, &WalletGUI::send_transaction);
    connect(from_address_combo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            [this]() {
                QString addr = from_address_combo->currentText();
                if (!addr.isEmpty()) {
                    double balance = wallet.getAddressBalance(addr.toStdString());
                    available_balance_label->setText(QString("Available: %1 TRU").arg(formatBalance(balance)));
                }
            });
    
    tabWidget->addTab(sendTab, "Send");
}

void WalletGUI::setupTokensTab() {
    QWidget *tokensTab = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(tokensTab);
    
    // Token creation
    token_creation_group = new QGroupBox("Create Token");
    QGridLayout *createLayout = new QGridLayout();
    
    // Token type
    createLayout->addWidget(new QLabel("Token Type:"), 0, 0);
    token_type_combo = new QComboBox(this);
    token_type_combo->addItems(QStringList() << "Fungible (FT)" << "Non-Fungible (NFT)" 
                              << "Semi-Fungible (SFT)" << "Non-Custodial Fungible (NCFT)");
    createLayout->addWidget(token_type_combo, 0, 1);
    
    // Common fields
    createLayout->addWidget(new QLabel("Token ID:"), 1, 0);
    token_id_edit = new QLineEdit(this);
    createLayout->addWidget(token_id_edit, 1, 1);
    
    createLayout->addWidget(new QLabel("Name:"), 2, 0);
    token_name_edit = new QLineEdit(this);
    createLayout->addWidget(token_name_edit, 2, 1);
    
    createLayout->addWidget(new QLabel("Symbol:"), 3, 0);
    token_symbol_edit = new QLineEdit(this);
    createLayout->addWidget(token_symbol_edit, 3, 1);
    
    createLayout->addWidget(new QLabel("Supply:"), 4, 0);
    token_supply_edit = new QLineEdit(this);
    createLayout->addWidget(token_supply_edit, 4, 1);
    
    createLayout->addWidget(new QLabel("Decimals:"), 5, 0);
    token_decimals_spin = new QSpinBox(this);
    token_decimals_spin->setRange(0, 18);
    token_decimals_spin->setValue(8);
    createLayout->addWidget(token_decimals_spin, 5, 1);
    
    createLayout->addWidget(new QLabel("Description:"), 6, 0);
    token_description_edit = new QTextEdit(this);
    token_description_edit->setMaximumHeight(80);
    createLayout->addWidget(token_description_edit, 6, 1);
    
    createLayout->addWidget(new QLabel("Image URL:"), 7, 0);
    token_image_url_edit = new QLineEdit(this);
    createLayout->addWidget(token_image_url_edit, 7, 1);
    
    issue_token_button = new QPushButton("Issue Token", this);
    issue_token_button->setMinimumHeight(40);
    createLayout->addWidget(issue_token_button, 8, 0, 1, 2);
    
    token_creation_group->setLayout(createLayout);
    layout->addWidget(token_creation_group);
    
    // Token list
    QGroupBox *tokenListGroup = new QGroupBox("My Tokens");
    QVBoxLayout *tokenListLayout = new QVBoxLayout();
    
    // Add refresh button at the top
    QHBoxLayout *tokenControlsLayout = new QHBoxLayout();
    refresh_tokens_button = new QPushButton("Refresh Tokens", this);
    refresh_tokens_button->setIcon(QIcon::fromTheme("view-refresh"));
    tokenControlsLayout->addStretch();
    tokenControlsLayout->addWidget(refresh_tokens_button);
    tokenListLayout->addLayout(tokenControlsLayout);
    
    tokens_table = new QTableWidget(0, 5, this);
    tokens_table->setHorizontalHeaderLabels(QStringList() << "Token ID" << "Type" << "Amount" << "Symbol" << "Name");
    tokens_table->horizontalHeader()->setStretchLastSection(true);
    tokens_table->setAlternatingRowColors(true);
    tokens_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    
    transfer_token_button = new QPushButton("Transfer Selected Token", this);
    transfer_token_button->setEnabled(false);
    
    tokenListLayout->addWidget(tokens_table);
    tokenListLayout->addWidget(transfer_token_button);
    tokenListGroup->setLayout(tokenListLayout);
    layout->addWidget(tokenListGroup);
    
    // Connect signals
    connect(token_type_combo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &WalletGUI::on_token_type_changed);
    connect(issue_token_button, &QPushButton::clicked, this, &WalletGUI::issue_token);
    connect(transfer_token_button, &QPushButton::clicked, this, &WalletGUI::transfer_token);
    connect(refresh_tokens_button, &QPushButton::clicked, this, &WalletGUI::refresh_tokens);
    connect(tokens_table, &QTableWidget::itemSelectionChanged,
            [this]() { transfer_token_button->setEnabled(tokens_table->currentRow() >= 0); });
    
    tabWidget->addTab(tokensTab, "Tokens");
}

void WalletGUI::setupTRUScriptTab() {
    QWidget *scriptTab = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(scriptTab);
    
    // Inscription creation
    QGroupBox *inscribeGroup = new QGroupBox("Inscribe TRUScript");
    QVBoxLayout *inscribeLayout = new QVBoxLayout();
    
    inscribeLayout->addWidget(new QLabel("Script Data:"));
    tru_script_data_edit = new QTextEdit(this);
    tru_script_data_edit->setPlaceholderText("Enter your script data, text, or JSON...");
    tru_script_data_edit->setMaximumHeight(150);
    inscribeLayout->addWidget(tru_script_data_edit);
    
    QHBoxLayout *ownerRow = new QHBoxLayout();
    ownerRow->addWidget(new QLabel("Owner Address:"));
    tru_script_owner_edit = new QLineEdit(this);
    tru_script_owner_edit->setPlaceholderText("Leave empty to use current address");
    ownerRow->addWidget(tru_script_owner_edit);
    inscribeLayout->addLayout(ownerRow);
    
    inscribe_button = new QPushButton("Inscribe TRUScript", this);
    inscribe_button->setMinimumHeight(40);
    inscribeLayout->addWidget(inscribe_button);
    
    inscribeGroup->setLayout(inscribeLayout);
    layout->addWidget(inscribeGroup);
    
    // TRUScript list
    QGroupBox *scriptListGroup = new QGroupBox("My TRUScripts");
    QVBoxLayout *scriptListLayout = new QVBoxLayout();
    
    tru_scripts_table = new QTableWidget(0, 4, this);
    tru_scripts_table->setHorizontalHeaderLabels(QStringList() << "TXID" << "Type" << "Size" << "Data Preview");
    tru_scripts_table->horizontalHeader()->setStretchLastSection(true);
    tru_scripts_table->setAlternatingRowColors(true);
    tru_scripts_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    
    transfer_script_button = new QPushButton("Transfer Selected TRUScript", this);
    transfer_script_button->setEnabled(false);
    
    scriptListLayout->addWidget(tru_scripts_table);
    scriptListLayout->addWidget(transfer_script_button);
    scriptListGroup->setLayout(scriptListLayout);
    layout->addWidget(scriptListGroup);
    
    // Connect signals
    connect(inscribe_button, &QPushButton::clicked, this, &WalletGUI::inscribe_tru_script);
    connect(transfer_script_button, &QPushButton::clicked, this, &WalletGUI::transfer_tru_script);
    connect(tru_scripts_table, &QTableWidget::itemSelectionChanged,
            [this]() { transfer_script_button->setEnabled(tru_scripts_table->currentRow() >= 0); });
    
    tabWidget->addTab(scriptTab, "TRUScript");
}

void WalletGUI::setupTransactionsTab() {
    QWidget *txTab = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(txTab);
    
    // Controls
    QHBoxLayout *controlsLayout = new QHBoxLayout();
    show_all_addresses_check = new QCheckBox("Show all addresses", this);
    refresh_tx_button = new QPushButton("Refresh", this);
    
    controlsLayout->addWidget(show_all_addresses_check);
    controlsLayout->addStretch();
    controlsLayout->addWidget(refresh_tx_button);
    layout->addLayout(controlsLayout);
    
    // Transaction table
    transactions_table = new QTableWidget(0, 6, this);
    transactions_table->setHorizontalHeaderLabels(QStringList() 
        << "Time" << "Type" << "Address" << "Amount" << "TXID" << "Confirmations");
    transactions_table->horizontalHeader()->setStretchLastSection(true);
    transactions_table->setAlternatingRowColors(true);
    transactions_table->setSortingEnabled(true);
    
    layout->addWidget(transactions_table);
    
    // Connect signals
    connect(refresh_tx_button, &QPushButton::clicked, this, &WalletGUI::refresh_transactions);
    connect(show_all_addresses_check, &QCheckBox::toggled, this, &WalletGUI::refresh_transactions);

    tabWidget->addTab(txTab, "Transactions");
   
}

void WalletGUI::setupSettingsTab() {
    QWidget *settingsTab = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(settingsTab);
    
    // Network settings
    QGroupBox *networkGroup = new QGroupBox("Network Settings");
    QGridLayout *networkLayout = new QGridLayout();
    
    networkLayout->addWidget(new QLabel("Node IP:"), 0, 0);
    nodeIP_edit = new QLineEdit(this);
    nodeIP_edit->setText("127.0.0.1");
    networkLayout->addWidget(nodeIP_edit, 0, 1);
    
    networkLayout->addWidget(new QLabel("Node Port:"), 1, 0);
    nodePort_edit = new QLineEdit(this);
    nodePort_edit->setText(QString::number(tru_network::MAINNET_RPC_PORT));
    networkLayout->addWidget(nodePort_edit, 1, 1);
    
    networkGroup->setLayout(networkLayout);
    layout->addWidget(networkGroup);
    
    // UI settings
    QGroupBox *uiGroup = new QGroupBox("UI Settings");
    QGridLayout *uiLayout = new QGridLayout();
    
    // Theme selection
    uiLayout->addWidget(new QLabel("Theme:"), 0, 0);
    theme_combo = new QComboBox(this);
    theme_combo->addItems(QStringList() << "dark_futuristic" << "cyberpunk_pink");
    theme_combo->setCurrentText(currentTheme);
    uiLayout->addWidget(theme_combo, 0, 1);
    
    auto_refresh_check = new QCheckBox("Enable auto-refresh", this);
    uiLayout->addWidget(auto_refresh_check, 1, 0);
    
    uiLayout->addWidget(new QLabel("Refresh interval (seconds):"), 2, 0);
    refresh_interval_spin = new QSpinBox(this);
    refresh_interval_spin->setRange(5, 300);
    refresh_interval_spin->setValue(30);
    uiLayout->addWidget(refresh_interval_spin, 2, 1);
    
    uiGroup->setLayout(uiLayout);
    layout->addWidget(uiGroup);
    
    // Save button
    save_settings_button = new QPushButton("Save Settings", this);
    save_settings_button->setMinimumHeight(40);
    layout->addWidget(save_settings_button);
    
    layout->addStretch();
    
    // Connect signals
    connect(save_settings_button, &QPushButton::clicked, this, &WalletGUI::save_settings);
    connect(theme_combo, QOverload<const QString &>::of(&QComboBox::currentTextChanged), 
            this, &WalletGUI::change_theme);
    connect(auto_refresh_check, &QCheckBox::toggled, [this](bool checked) {
        if (checked) {
            refresh_timer->start(refresh_interval_spin->value() * 1000);
        } else {
            refresh_timer->stop();
        }
    });
    
    tabWidget->addTab(settingsTab, "Settings");
}

void WalletGUI::create_wallet() {
    int ret = QMessageBox::warning(this, "Create New Wallet",
                                  "This will create a new wallet. Make sure to backup your existing wallet first!\n"
                                  "Continue?",
                                  QMessageBox::Yes | QMessageBox::No);
    if (ret == QMessageBox::No) return;
    
    try {
        std::string result = wallet.create_wallet("tru.dat");
        showMessage("Wallet Created",
                   QString("Wallet created successfully!\nSeed: %1\n\nPLEASE SAVE THIS SEED PHRASE!")
                   .arg(QString::fromStdString(result)));
        refresh_addresses();
        updateBalanceDisplay();
    } catch (const std::exception &e) {
        showMessage("Error", QString::fromStdString(e.what()), true);
    }
}

void WalletGUI::import_private_key() {
    bool ok;
    QString privKey = QInputDialog::getText(this, "Import Private Key",
                                           "Enter private key (hex format):",
                                           QLineEdit::Password, "", &ok);
    if (!ok || privKey.isEmpty()) return;
    
    try {
        std::string address = wallet.importPrivateKey(privKey.toStdString());
        showMessage("Success", QString("Private key imported successfully!\nAddress: %1")
                              .arg(QString::fromStdString(address)));
        refresh_addresses();
        updateBalanceDisplay();
    } catch (const std::exception &e) {
        showMessage("Error", QString::fromStdString(e.what()), true);
    }
}

void WalletGUI::generate_new_address() {
    try {
        std::string newAddr = wallet.generateNewAddress();
        showMessage("New Address Generated",
                   QString("New address: %1").arg(QString::fromStdString(newAddr)));
        refresh_addresses();
    } catch (const std::exception &e) {
        showMessage("Error", QString::fromStdString(e.what()), true);
    }
}

void WalletGUI::refresh_addresses() {
    // Update address combo boxes
    address_combo->clear();
    from_address_combo->clear();
    
    std::vector<std::string> addresses = wallet.getAllAddresses();
    cached_addresses.clear();
    
    for (const auto& addr : addresses) {
        QString qaddr = QString::fromStdString(addr);
        cached_addresses.append(qaddr);
        address_combo->addItem(qaddr);
        from_address_combo->addItem(qaddr);
    }
    
    // Set current address
    std::string currentAddr = wallet.getCurrentAddress();
    if (!currentAddr.empty()) {
        address_combo->setCurrentText(QString::fromStdString(currentAddr));
        from_address_combo->setCurrentText(QString::fromStdString(currentAddr));
    }
    
    // Update address table
    address_table->setRowCount(0);
    auto addressesWithBalance = wallet.getAddressesWithBalance();
    
    for (size_t i = 0; i < addressesWithBalance.size(); ++i) {
        const auto& [addr, balance] = addressesWithBalance[i];
        int row = address_table->rowCount();
        address_table->insertRow(row);
        
        address_table->setItem(row, 0, new QTableWidgetItem(QString::number(i)));
        address_table->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(addr)));
        address_table->setItem(row, 2, new QTableWidgetItem(formatBalance(balance)));
    }
}

void WalletGUI::copy_current_address() {
    QString addr = address_combo->currentText();
    if (!addr.isEmpty()) {
        QApplication::clipboard()->setText(addr);
        showMessage("Copied", "Address copied to clipboard");
    }
}

void WalletGUI::show_qr_code() {
    QString addr = address_combo->currentText();
    if (addr.isEmpty()) return;
    
    // Generate QR code
    QRcode *qr = QRcode_encodeString(addr.toStdString().c_str(), 0, QR_ECLEVEL_L, QR_MODE_8, 1);
    if (!qr) {
        showMessage("Error", "Failed to generate QR code", true);
        return;
    }
    
    int scale = 8;
    int size = qr->width * scale;
    QImage img(size, size, QImage::Format_RGB32);
    img.fill(Qt::white);
    
    QPainter painter(&img);
    for (int y = 0; y < qr->width; y++) {
        for (int x = 0; x < qr->width; x++) {
            if (qr->data[y * qr->width + x] & 1) {
                painter.fillRect(x * scale, y * scale, scale, scale, Qt::black);
            }
        }
    }
    
    QRcode_free(qr);
    
    // Show QR code in dialog
    QDialog dialog(this);
    dialog.setWindowTitle("QR Code - " + addr);
    QVBoxLayout *layout = new QVBoxLayout(&dialog);
    
    QLabel *qrLabel = new QLabel();
    qrLabel->setPixmap(QPixmap::fromImage(img));
    layout->addWidget(qrLabel, 0, Qt::AlignCenter);
    
    QLabel *addrLabel = new QLabel(addr);
    addrLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(addrLabel);
    
    dialog.exec();
}

void WalletGUI::backup_wallet() {
    QString fileName = QFileDialog::getSaveFileName(this, "Backup Wallet", 
                                                   "wallet_backup.dat",
                                                   "Wallet Files (*.dat)");
    if (fileName.isEmpty()) return;
    
    try {
        wallet.saveToFile(fileName.toStdString());
        showMessage("Success", "Wallet backed up successfully");
    } catch (const std::exception &e) {
        showMessage("Error", QString::fromStdString(e.what()), true);
    }
}

void WalletGUI::restore_wallet() {
    QString fileName = QFileDialog::getOpenFileName(this, "Restore Wallet",
                                                   "",
                                                   "Wallet Files (*.dat)");
    if (fileName.isEmpty()) return;
    
    try {
        wallet.loadFromFile(fileName.toStdString());
        showMessage("Success", "Wallet restored successfully");
        refresh_addresses();
        updateBalanceDisplay();
    } catch (const std::exception &e) {
        showMessage("Error", QString::fromStdString(e.what()), true);
    }
}

void WalletGUI::send_transaction() {
    std::string from = from_address_combo->currentText().toStdString();
    std::string recipient = recipient_edit->text().toStdString();
    std::string amountText = amount_edit->text().toStdString();
    std::uint64_t amountAtoms = 0;
    std::string amountReason;
    std::string nodeIP = nodeIP_edit->text().toStdString();
    int port = nodePort_edit->text().toInt();
    
    if (from.empty() || recipient.empty()) {
        showMessage("Invalid Input", "Please fill all fields correctly", true);
        return;
    }
    if (!tru_amount::parse(amountText, amountAtoms, amountReason) || amountAtoms == 0) {
        if (amountReason.empty()) amountReason = "amount must be greater than 0";
        showMessage("Invalid Amount", QString::fromStdString(amountReason), true);
        return;
    }
    
    if (nodeIP.empty()) nodeIP = "127.0.0.1";
    if (port <= 0) port = tru_network::MAINNET_RPC_PORT;
    
    send_progress->setVisible(true);
    send_progress->setRange(0, 0);
    send_button->setEnabled(false);
    
    try {
        wallet.setCurrentAddress(from);
        std::string txid = wallet.send_transaction(recipient, amountAtoms, nodeIP, port);
        showMessage("Transaction Sent",
                   QString("Transaction sent successfully!\nTXID: %1")
                   .arg(QString::fromStdString(txid)));

        if (wallet.isLocalChainAvailable()) {
            wallet.updateLocalUTXOSetFromChain();
        }
                           
        updateBalanceDisplay();
        refresh_transactions();
    } catch (const std::exception &e) {
        showMessage("Error", QString::fromStdString(e.what()), true);
    }
    
    send_progress->setVisible(false);
    send_button->setEnabled(true);
}

void WalletGUI::check_balance() {
    updateBalanceDisplay();
}

void WalletGUI::mine() {
    if (!is_mining) {
        is_mining = true;
        mine_button->setText("Stop Mining");
        mining_status_label->setText("Mining: Syncing...");
        mining_status_label->setStyleSheet("QLabel { color: blue; }");
        
        try {
            // First, sync with the network
            if (wallet.isLocalChainAvailable()) {
                // Use const reference since getBlockchain() returns const
                const Blockchain& blockchain = wallet.getBlockchain();
                
                // Update status
                mining_status_label->setText("Mining: Checking blockchain...");
                QApplication::processEvents(); // Update UI
                
                // For now, we'll just check the height since syncWithPeers 
                // requires P2PNode and running flag which we don't have here
                int localHeight = blockchain.getBestTipHeight();
                
                // Update wallet UTXOs after checking
                wallet.updateLocalUTXOSetFromChain();
                updateBlockHeight();
                
                // Show current status
                showMessage("Chain Status", 
                           QString("Local chain height: %1\nReady to mine.").arg(localHeight));
            }
            
            // Now mine
            mining_status_label->setText("Mining: Active");
            mining_status_label->setStyleSheet("QLabel { color: green; }");
            
            wallet.mine();
            showMessage("Block Mined", "Block mined successfully!");
            
            // Update wallet state after mining
            wallet.updateLocalUTXOSetFromChain();
            updateBalanceDisplay();
            updateBlockHeight();
            refresh_addresses();
            refresh_tokens();
            
        } catch (const std::exception &e) {
            showMessage("Error", QString::fromStdString(e.what()), true);
        }
        
        is_mining = false;
        mine_button->setText("Start Mining");
        mining_status_label->setText("Mining: Idle");
        mining_status_label->setStyleSheet("QLabel { color: black; }");
    }
}

void WalletGUI::refresh_transactions() {
    transactions_table->setRowCount(0);
    
    // Get transactions for current address or all addresses
    std::vector<std::string> addresses;
    if (show_all_addresses_check->isChecked()) {
        addresses = wallet.getAllAddresses();
    } else {
        QString currentAddr = address_combo->currentText();
        if (!currentAddr.isEmpty()) {
            addresses.push_back(currentAddr.toStdString());
        }
    }
    
    if (addresses.empty()) {
        return;
    }
    
    try {
        // Get transaction history from wallet
        std::vector<TransactionInfo> history = wallet.getTransactionHistory(addresses);
        
        // Display each transaction
        for (const auto& tx : history) {
            int row = transactions_table->rowCount();
            transactions_table->insertRow(row);
            
            // Time
            QString timeStr;
            if (tx.timestamp > 0) {
                QDateTime dt = QDateTime::fromSecsSinceEpoch(tx.timestamp);
                timeStr = dt.toString("yyyy-MM-dd HH:mm:ss");
            } else {
                timeStr = "Pending";
            }
            transactions_table->setItem(row, 0, new QTableWidgetItem(timeStr));
            
            // Type
            QTableWidgetItem* typeItem = new QTableWidgetItem(QString::fromStdString(tx.type));
            if (tx.type == "Sent") {
                typeItem->setForeground(QBrush(QColor(255, 100, 100))); // Red for sent
            } else {
                typeItem->setForeground(QBrush(QColor(100, 255, 100))); // Green for received
            }
            transactions_table->setItem(row, 1, typeItem);
            
            // Address (truncate for display)
            QString addr = QString::fromStdString(tx.address);
            if (addr.length() > 20) {
                addr = addr.left(10) + "..." + addr.right(10);
            }
            transactions_table->setItem(row, 2, new QTableWidgetItem(addr));
            
            // Amount
            QString amountStr = formatBalance(std::abs(tx.amount));
            if (tx.type == "Sent") {
                amountStr = "-" + amountStr;
            }
            QTableWidgetItem* amountItem = new QTableWidgetItem(amountStr);
            amountItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            transactions_table->setItem(row, 3, amountItem);
            
            // TXID (truncate for display)
            QString txid = QString::fromStdString(tx.txid);
            if (txid.length() > 16) {
                txid = txid.left(8) + "..." + txid.right(8);
            }
            QTableWidgetItem* txidItem = new QTableWidgetItem(txid);
            txidItem->setData(Qt::UserRole, QString::fromStdString(tx.txid)); // Store full txid
            transactions_table->setItem(row, 4, txidItem);
            
            // Confirmations
            QString confirmStr = tx.confirmations > 0 ? 
                                QString::number(tx.confirmations) : "Unconfirmed";
            transactions_table->setItem(row, 5, new QTableWidgetItem(confirmStr));
        }
        
        // Resize columns to content
        transactions_table->resizeColumnsToContents();
                
    } catch (const std::exception& e) {
        // Don't show error message during initial load
        // Only log the error
        qDebug() << "Failed to load transactions:" << e.what();
    }
}

void WalletGUI::on_address_selection_changed() {
    QString addr = address_combo->currentText();
    if (!addr.isEmpty()) {
        wallet.setCurrentAddress(addr.toStdString());
        updateBalanceDisplay();
    }
}

void WalletGUI::issue_token() {
    try {
        std::string tokenID = token_id_edit->text().toStdString();
        std::string name = token_name_edit->text().toStdString();
        std::string symbol = token_symbol_edit->text().toStdString();
        uint64_t supply = token_supply_edit->text().toULongLong();
        std::string desc = token_description_edit->toPlainText().toStdString();
        std::string imageUrl = token_image_url_edit->text().toStdString();
        uint32_t decimals = token_decimals_spin->value();
        
        if (tokenID.empty() || name.empty()) {
            showMessage("Invalid Input", "Token ID and Name are required", true);
            return;
        }
        
        std::string txid;
        int tokenType = token_type_combo->currentIndex();
        
        switch (tokenType) {
            case 0: // FT
                // Pass decimals as integer, not string
                txid = wallet.issueExtendedFT(tokenID, supply, name, symbol, desc, imageUrl, decimals);
                break;
            case 1: // NFT
                txid = wallet.issueExtendedNFT(tokenID, name, desc, imageUrl, 
                                               wallet.getCurrentAddress(), "");
                break;
            case 2: // SFT
                txid = wallet.issueExtendedSFT(tokenID, supply, name, symbol, desc, imageUrl, decimals);
                break;
            case 3: // NCFT
                txid = wallet.issueExtendedNCFT(tokenID, supply, name, desc, imageUrl);
                break;
        }
        
        showMessage("Token Issued",
                   QString("Token issued successfully!\nTXID: %1").arg(QString::fromStdString(txid)));
        
        // Clear the form
        token_id_edit->clear();
        token_name_edit->clear();
        token_symbol_edit->clear();
        token_supply_edit->clear();
        token_description_edit->clear();
        token_image_url_edit->clear();
        token_decimals_spin->setValue(8);
        
        // Update wallet UTXOs and refresh display
        wallet.updateLocalUTXOSetFromChain();
        refresh_tokens();
        updateBalanceDisplay();
    } catch (const std::exception &e) {
        showMessage("Error", QString::fromStdString(e.what()), true);
    }
}

void WalletGUI::transfer_token() {
    int row = tokens_table->currentRow();
    if (row < 0) return;
    
    QString tokenID = tokens_table->item(row, 0)->text();
    QString currentAmount = tokens_table->item(row, 2)->text();
    
    bool ok;
    QString recipient = QInputDialog::getText(this, "Transfer Token",
                                            "Recipient address:", QLineEdit::Normal, "", &ok);
    if (!ok || recipient.isEmpty()) return;
    
    QString amountStr = QInputDialog::getText(this, "Transfer Token",
                                             QString("Amount to transfer (available: %1):")
                                             .arg(currentAmount),
                                             QLineEdit::Normal, "1", &ok);
    if (!ok || amountStr.isEmpty()) return;
    
    try {
        std::string txid = wallet.sendToken(tokenID.toStdString(),
                                           amountStr.toULongLong(),
                                           recipient.toStdString(),
                                           wallet.getCurrentAddress());
        showMessage("Token Transferred",
                   QString("Token transferred successfully!\nTXID: %1")
                   .arg(QString::fromStdString(txid)));
        refresh_tokens();
    } catch (const std::exception &e) {
        showMessage("Error", QString::fromStdString(e.what()), true);
    }
}

void WalletGUI::refresh_tokens() {
    tokens_table->setRowCount(0);
    
    try {
        // Get token UTXOs from wallet
        const auto& tokenUTXOs = wallet.getTokenUTXOs();
        
        // Group tokens by ID to sum amounts
        std::unordered_map<std::string, std::tuple<ExtendedTokenData, uint64_t>> tokenSummary;
        
        for (const auto& [key, tokenInfo] : tokenUTXOs) {
            const auto& [txid, vout, amount, tokenData, owner] = tokenInfo;
            
            auto it = tokenSummary.find(tokenData.tokenID);
            if (it != tokenSummary.end()) {
                // Add to existing amount
                std::get<1>(it->second) += amount;
            } else {
                // New token
                tokenSummary[tokenData.tokenID] = std::make_tuple(tokenData, amount);
            }
        }
        
        // Display tokens in table
        for (const auto& [tokenID, tokenInfo] : tokenSummary) {
            const auto& [tokenData, totalAmount] = tokenInfo;
            
            int row = tokens_table->rowCount();
            tokens_table->insertRow(row);
            
            // Token ID
            tokens_table->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(tokenData.tokenID)));
            
            // Type
            tokens_table->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(tokenTypeToString(tokenData.type))));
            
            // Amount (considering decimals)
            double displayAmount = totalAmount;
            int decimals = getJsonInt(tokenData.meta.data, "decimals", 0);
            if (decimals > 0) {
                displayAmount = totalAmount / std::pow(10, decimals);
            }
            tokens_table->setItem(row, 2, new QTableWidgetItem(QString::number(displayAmount, 'f', decimals)));
            
            // Symbol
            std::string symbol = getJsonString(tokenData.meta.data, "symbol", "N/A");
            tokens_table->setItem(row, 3, new QTableWidgetItem(QString::fromStdString(symbol)));
            
            // Name
            std::string name = getJsonString(tokenData.meta.data, "name", "Unknown");
            tokens_table->setItem(row, 4, new QTableWidgetItem(QString::fromStdString(name)));
        }
        
        // Log success
        if (tokenSummary.size() > 0) {
            showMessage("Tokens Refreshed", 
                       QString("Found %1 tokens").arg(tokenSummary.size()));
        }
    } catch (const std::exception &e) {
        // Show error message
        showMessage("Error", QString("Failed to refresh tokens: %1").arg(e.what()), true);
    }
}

void WalletGUI::on_token_type_changed(int index) {
    // Enable/disable fields based on token type
    bool isNFT = (index == 1);
    token_symbol_edit->setEnabled(!isNFT);
    token_supply_edit->setEnabled(!isNFT);
    token_decimals_spin->setEnabled(!isNFT);
    
    if (isNFT) {
        token_supply_edit->setText("1");
        token_decimals_spin->setValue(0);
    }
}

void WalletGUI::inscribe_tru_script() {
    std::string data = tru_script_data_edit->toPlainText().toStdString();
    std::string owner = tru_script_owner_edit->text().toStdString();
    
    if (data.empty()) {
        showMessage("Invalid Input", "Script data cannot be empty", true);
        return;
    }
    
    if (owner.empty()) {
        owner = wallet.getCurrentAddress();
    }
    
    try {
        std::string txid = wallet.inscribeTRUScript(data, owner);
        showMessage("TRUScript Inscribed",
                   QString("TRUScript inscribed successfully!\nTXID: %1")
                   .arg(QString::fromStdString(txid)));
        refresh_tru_scripts();
    } catch (const std::exception &e) {
        showMessage("Error", QString::fromStdString(e.what()), true);
    }
}

void WalletGUI::transfer_tru_script() {
    int row = tru_scripts_table->currentRow();
    if (row < 0) return;
    
    QString txid = tru_scripts_table->item(row, 0)->text();
    
    bool ok;
    QString recipient = QInputDialog::getText(this, "Transfer TRUScript",
                                            "Recipient address:", QLineEdit::Normal, "", &ok);
    if (!ok || recipient.isEmpty()) return;
    
    try {
        std::string newTxid = wallet.transferTRUScript(txid.toStdString(), recipient.toStdString());
        showMessage("TRUScript Transferred",
                   QString("TRUScript transferred successfully!\nNew TXID: %1")
                   .arg(QString::fromStdString(newTxid)));
        refresh_tru_scripts();
    } catch (const std::exception &e) {
        showMessage("Error", QString::fromStdString(e.what()), true);
    }
}

void WalletGUI::refresh_tru_scripts() {
    tru_scripts_table->setRowCount(0);
    
    try {
        auto scripts = wallet.getTRUScripts(wallet.getCurrentAddress());
        
        for (const auto& script : scripts) {
            int row = tru_scripts_table->rowCount();
            tru_scripts_table->insertRow(row);
            
            // Set TXID
            tru_scripts_table->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(script.txid)));
            
            // Set Type - use contentType
            tru_scripts_table->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(script.contentType)));
            
            // Set Size - use sizeBytes
            tru_scripts_table->setItem(row, 2, new QTableWidgetItem(QString::number(script.sizeBytes)));
            
            // Set Data Preview
            std::string preview = script.data.substr(0, 50);
            if (script.data.length() > 50) preview += "...";
            tru_scripts_table->setItem(row, 3, new QTableWidgetItem(QString::fromStdString(preview)));
        }
    } catch (const std::exception &e) {
        // Don't ignore - show the error
        showMessage("TRUScript Error", 
                   QString("Failed to load TRUScripts: %1").arg(e.what()), 
                   true);
    }
}

void WalletGUI::save_settings() {
    QSettings settings("TRUBlockchain", "WalletGUI");
    
    settings.setValue("nodeIP", nodeIP_edit->text());
    settings.setValue("nodePort", nodePort_edit->text());
    settings.setValue("autoRefresh", auto_refresh_check->isChecked());
    settings.setValue("refreshInterval", refresh_interval_spin->value());
    
    showMessage("Settings Saved", "Settings have been saved successfully");
}

void WalletGUI::load_settings() {
    QSettings settings("TRUBlockchain", "WalletGUI");
    
    nodeIP_edit->setText(settings.value("nodeIP", "127.0.0.1").toString());
    nodePort_edit->setText(settings.value("nodePort", QString::number(tru_network::MAINNET_RPC_PORT)).toString());
    auto_refresh_check->setChecked(settings.value("autoRefresh", false).toBool());
    refresh_interval_spin->setValue(settings.value("refreshInterval", 30).toInt());
    
    if (auto_refresh_check->isChecked()) {
        refresh_timer->start(refresh_interval_spin->value() * 1000);
    }
}

void WalletGUI::auto_refresh() {
    // Add safety check
    if (!wallet.isLocalChainAvailable()) {
        return;
    }
    
    try {
        wallet.updateLocalUTXOSetFromChain();
        updateBalanceDisplay();
        updateBlockHeight();
        updateNetworkStatus();
        
        // Refresh based on current tab
        int currentTab = tabWidget->currentIndex();
        switch (currentTab) {
            case 0: // Wallet tab
                refresh_addresses();
                break;
            case 2: // Tokens tab
                refresh_tokens();
                break;
            case 3: // TRUScript tab
                refresh_tru_scripts();
                break;
            case 4: // Transactions tab
                refresh_transactions();
                break;
            default:
                break;
        }
    } catch (const std::exception& e) {
        // Log but don't crash
        qDebug() << "Auto-refresh error:" << e.what();
    }
}

void WalletGUI::updateBalanceDisplay() {
    try {
        double balance = wallet.check_balance(false);
        cached_balance = balance;
        balance_label->setText(QString("Balance: %1 TRU").arg(formatBalance(balance)));
    } catch (const std::exception &e) {
        balance_label->setText("Balance: Error");
    }
}

void WalletGUI::showMessage(const QString &title, const QString &message, bool isError) {
    if (isError) {
        QMessageBox::critical(this, title, message);
    } else {
        QMessageBox::information(this, title, message);
    }
}

QString WalletGUI::formatBalance(double balance) const {
    std::stringstream ss;
    ss << std::fixed << std::setprecision(8) << balance;
    QString result = QString::fromStdString(ss.str());
    
    // Ensure we always show 8 decimal places
    if (balance < 0.00000001) {
        return "0.00000000";
    }
    return result;
}

void WalletGUI::applyTheme(const QString &theme) {
    if (theme == "dark_futuristic") {
        setStyleSheet(WalletStyles::DARK_FUTURISTIC);
    } else if (theme == "cyberpunk_pink") {
        setStyleSheet(WalletStyles::CYBERPUNK_PINK);
    }
    currentTheme = theme;
}

void WalletGUI::loadCustomLogo() {
    // Create a futuristic TRU logo using QPainter
    QPixmap logo(200, 60);
    logo.fill(Qt::transparent);
    
    QPainter painter(&logo);
    painter.setRenderHint(QPainter::Antialiasing);
    
    // Draw futuristic text
    QFont font("Orbitron", 32, QFont::Bold);
    font.setLetterSpacing(QFont::AbsoluteSpacing, 5);
    painter.setFont(font);
    
    // Create gradient for text
    QLinearGradient gradient(0, 0, 200, 60);
    gradient.setColorAt(0, QColor(0, 212, 255));
    gradient.setColorAt(0.5, QColor(0, 255, 255));
    gradient.setColorAt(1, QColor(0, 150, 255));
    
    painter.setPen(QPen(gradient, 2));
    painter.drawText(logo.rect(), Qt::AlignCenter, "TRU");
    
    // Add glow effect
    painter.setPen(QPen(QColor(0, 212, 255, 100), 4));
    painter.drawText(logo.rect().adjusted(1, 1, 1, 1), Qt::AlignCenter, "TRU");
    
    logoLabel->setPixmap(logo);
    
    // You can also load an external image file:
    // QPixmap customLogo("path/to/your/logo.png");
    // logoLabel->setPixmap(customLogo.scaled(200, 60, Qt::KeepAspectRatio, Qt::SmoothTransformation));
}

void WalletGUI::change_theme() {
    QString theme = theme_combo->currentText();
    applyTheme(theme);
    
    QSettings settings("TRUBlockchain", "WalletGUI");
    settings.setValue("theme", theme);
}

void WalletGUI::resizeEvent(QResizeEvent* event) {
    QWidget::resizeEvent(event);  // Call parent implementation
    
    // Resize background widgets to match window size
    if (backgroundWidget) {
        backgroundWidget->setGeometry(0, 0, width(), height());
    }
    if (glowBorder) {
        glowBorder->setGeometry(0, 0, width(), height());
    }
}

void WalletGUI::updateBlockHeight() {
    try {
        // Check if local blockchain is available
        if (wallet.isLocalChainAvailable()) {
            int height = wallet.getBlockchain().getBestTipHeight();
            block_height_label->setText(QString("Block: %1").arg(height));
        } else {
            block_height_label->setText("Block: N/A (No local chain)");
        }
    } catch (const std::exception& e) {
        block_height_label->setText("Block: Error");
    }
}

void WalletGUI::updateNetworkStatus() {
    try {
        if (wallet.isLocalChainAvailable()) {
            // Get P2P node from blockchain if possible
            const Blockchain& blockchain = wallet.getBlockchain();
            
            // Check if we have any connected peers
            // You'll need to expose peer count through the wallet/blockchain interface
            int peerCount = blockchain.getConnectedPeerCount(); // You need to implement this
            
            if (peerCount > 0) {
                network_status_label->setText(QString("Network: Connected (%1 peers)").arg(peerCount));
                network_status_label->setStyleSheet("QLabel { color: green; font-weight: bold; }");
            } else {
                network_status_label->setText("Network: No peers");
                network_status_label->setStyleSheet("QLabel { color: orange; font-weight: bold; }");
            }
        } else {
            network_status_label->setText("Network: Offline");
            network_status_label->setStyleSheet("QLabel { color: red; font-weight: bold; }");
        }
    } catch (const std::exception& e) {
        network_status_label->setText("Network: Error");
        network_status_label->setStyleSheet("QLabel { color: red; font-weight: bold; }");
    }
}

void WalletGUI::setupContractsTab() {
    QWidget *contractsTab = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(contractsTab);
    
    // Contract Creation Section
    contract_creation_group = new QGroupBox("Create Smart Contract");
    QVBoxLayout *createLayout = new QVBoxLayout();
    
    // Contract type selection
    QHBoxLayout *typeLayout = new QHBoxLayout();
    typeLayout->addWidget(new QLabel("Contract Type:"));
    contract_type_combo = new QComboBox(this);
    contract_type_combo->addItems(QStringList() 
        << "Time Lock" 
        << "Hash Lock" 
        << "Oracle-Based"
        << "Stateful (Key/Value)"
        << "OP_RETURN Data"
        << "Custom Script");
    typeLayout->addWidget(contract_type_combo);
    typeLayout->addStretch();
    createLayout->addLayout(typeLayout);
    
    // Common fields
    QHBoxLayout *nameLayout = new QHBoxLayout();
    nameLayout->addWidget(new QLabel("Contract Name:"));
    contract_name_edit = new QLineEdit(this);
    contract_name_edit->setPlaceholderText("My Smart Contract");
    nameLayout->addWidget(contract_name_edit);
    createLayout->addLayout(nameLayout);
    
    // Stacked widget for contract-specific parameters
    contract_params_stack = new QStackedWidget(this);
    
    // Time Lock parameters
    QWidget *timeLockWidget = new QWidget();
    QGridLayout *timeLockLayout = new QGridLayout(timeLockWidget);
    
    timeLockLayout->addWidget(new QLabel("Lock Until (Unix timestamp):"), 0, 0);
    timelock_timestamp_edit = new QLineEdit(this);
    timelock_timestamp_edit->setPlaceholderText(QString::number(QDateTime::currentDateTime().addDays(30).toSecsSinceEpoch()));
    timeLockLayout->addWidget(timelock_timestamp_edit, 0, 1);
    
    QPushButton *datePickerBtn = new QPushButton("Pick Date", this);
    connect(datePickerBtn, &QPushButton::clicked, [this]() {
        bool ok;
        QDateTime dt = QDateTime::currentDateTime().addDays(1);
        QString dateStr = QInputDialog::getText(this, "Set Lock Date", 
            "Enter date (YYYY-MM-DD HH:MM):", QLineEdit::Normal, 
            dt.toString("yyyy-MM-dd HH:mm"), &ok);
        if (ok) {
            QDateTime selected = QDateTime::fromString(dateStr, "yyyy-MM-dd HH:mm");
            if (selected.isValid()) {
                timelock_timestamp_edit->setText(QString::number(selected.toSecsSinceEpoch()));
            }
        }
    });
    timeLockLayout->addWidget(datePickerBtn, 0, 2);
    
    timeLockLayout->addWidget(new QLabel("Recipient PubKeyHash:"), 1, 0);
    timelock_pubkeyhash_edit = new QLineEdit(this);
    timelock_pubkeyhash_edit->setPlaceholderText("20-byte hex pubkeyhash");
    timeLockLayout->addWidget(timelock_pubkeyhash_edit, 1, 1, 1, 2);
    
    timeLockLayout->addWidget(new QLabel("Lock Reason (optional):"), 2, 0);
    timelock_reason_edit = new QLineEdit(this);
    timelock_reason_edit->setPlaceholderText("Vesting, Escrow, etc.");
    timeLockLayout->addWidget(timelock_reason_edit, 2, 1, 1, 2);
    
    contract_params_stack->addWidget(timeLockWidget);
    
    // Hash Lock parameters
    QWidget *hashLockWidget = new QWidget();
    QGridLayout *hashLockLayout = new QGridLayout(hashLockWidget);
    
    hashLockLayout->addWidget(new QLabel("Preimage (secret):"), 0, 0);
    hashlock_preimage_edit = new QLineEdit(this);
    hashlock_preimage_edit->setPlaceholderText("Enter secret phrase");
    hashLockLayout->addWidget(hashlock_preimage_edit, 0, 1);
    
    QPushButton *calcHashBtn = new QPushButton("Calculate Hash", this);
    connect(calcHashBtn, &QPushButton::clicked, this, &WalletGUI::calculate_hash);
    hashLockLayout->addWidget(calcHashBtn, 0, 2);
    
    hashLockLayout->addWidget(new QLabel("Hash160:"), 1, 0);
    hashlock_hash_edit = new QLineEdit(this);
    hashlock_hash_edit->setReadOnly(true);
    hashLockLayout->addWidget(hashlock_hash_edit, 1, 1, 1, 2);
    
    contract_params_stack->addWidget(hashLockWidget);
    
    // Oracle parameters
    QWidget *oracleWidget = new QWidget();
    QGridLayout *oracleLayout = new QGridLayout(oracleWidget);
    
    oracleLayout->addWidget(new QLabel("Oracle Data Key:"), 0, 0);
    oracle_key_edit = new QLineEdit(this);
    oracle_key_edit->setPlaceholderText("price:USD, temperature:NYC, etc.");
    oracleLayout->addWidget(oracle_key_edit, 0, 1);
    
    oracleLayout->addWidget(new QLabel("Threshold Value:"), 1, 0);
    oracle_threshold_edit = new QLineEdit(this);
    oracle_threshold_edit->setPlaceholderText("1000");
    oracleLayout->addWidget(oracle_threshold_edit, 1, 1);
    
    oracleLayout->addWidget(new QLabel("Comparison:"), 2, 0);
    oracle_comparison_combo = new QComboBox(this);
    oracle_comparison_combo->addItems(QStringList() << "Greater Than (≥)" << "Less Than (≤)");
    oracleLayout->addWidget(oracle_comparison_combo, 2, 1);
    
    contract_params_stack->addWidget(oracleWidget);
    
    // Stateful parameters
    QWidget *statefulWidget = new QWidget();
    QGridLayout *statefulLayout = new QGridLayout(statefulWidget);
    
    statefulLayout->addWidget(new QLabel("State Key:"), 0, 0);
    state_key_edit = new QLineEdit(this);
    state_key_edit->setPlaceholderText("counter, balance, owner, etc.");
    statefulLayout->addWidget(state_key_edit, 0, 1);
    
    statefulLayout->addWidget(new QLabel("Initial Value:"), 1, 0);
    state_value_edit = new QLineEdit(this);
    state_value_edit->setPlaceholderText("0, address, or any value");
    statefulLayout->addWidget(state_value_edit, 1, 1);
    
    contract_params_stack->addWidget(statefulWidget);
    
    // OP_RETURN data parameters
    QWidget *opReturnWidget = new QWidget();
    QVBoxLayout *opReturnLayout = new QVBoxLayout(opReturnWidget);
    opReturnLayout->addWidget(new QLabel("Data to store (max 80 bytes):"));
    QTextEdit *opReturnData = new QTextEdit(this);
    opReturnData->setMaximumHeight(80);
    opReturnData->setPlaceholderText("Arbitrary data, memo, hash, etc.");
    opReturnLayout->addWidget(opReturnData);
    contract_params_stack->addWidget(opReturnWidget);
    
    // Custom script parameters
    QWidget *customWidget = new QWidget();
    QVBoxLayout *customLayout = new QVBoxLayout(customWidget);
    customLayout->addWidget(new QLabel("Custom Script:"));
    custom_script_edit = new QTextEdit(this);
    custom_script_edit->setPlaceholderText(
        "Enter script using opcodes:\n"
        "OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG\n"
        "OP_BLOCKTIME <time> OP_GREATERTHAN OP_VERIFY ...");
    custom_script_edit->setMaximumHeight(120);
    customLayout->addWidget(custom_script_edit);
    
    // Gas estimation
    QHBoxLayout *gasLayout = new QHBoxLayout();
    QPushButton *estimateGasBtn = new QPushButton("Estimate Gas", this);
    connect(estimateGasBtn, &QPushButton::clicked, this, &WalletGUI::estimate_contract_gas);
    QLabel *gasEstimateLabel = new QLabel("Estimated Gas: N/A");
    gasEstimateLabel->setObjectName("gasEstimateLabel");
    gasLayout->addWidget(estimateGasBtn);
    gasLayout->addWidget(gasEstimateLabel);
    gasLayout->addStretch();
    customLayout->addLayout(gasLayout);
    
    contract_params_stack->addWidget(customWidget);
    
    createLayout->addWidget(contract_params_stack);
    
    // Create button
    create_contract_button = new QPushButton("Deploy Contract", this);
    create_contract_button->setMinimumHeight(40);
    create_contract_button->setIcon(QIcon::fromTheme("document-send"));
    createLayout->addWidget(create_contract_button);
    
    contract_creation_group->setLayout(createLayout);
    layout->addWidget(contract_creation_group);
    
    // Contract Management Section
    QGroupBox *managementGroup = new QGroupBox("Deployed Contracts");
    QVBoxLayout *mgmtLayout = new QVBoxLayout();
    
    // Controls
    QHBoxLayout *controlsLayout = new QHBoxLayout();
    refresh_contracts_button = new QPushButton("Refresh", this);
    refresh_contracts_button->setIcon(QIcon::fromTheme("view-refresh"));
    execute_contract_button = new QPushButton("Execute/Redeem", this);
    execute_contract_button->setEnabled(false);
    execute_contract_button->setIcon(QIcon::fromTheme("system-run"));
    
    controlsLayout->addWidget(refresh_contracts_button);
    controlsLayout->addWidget(execute_contract_button);
    controlsLayout->addStretch();
    mgmtLayout->addLayout(controlsLayout);
    
    // Contracts table
    contracts_table = new QTableWidget(0, 6, this);
    contracts_table->setHorizontalHeaderLabels(QStringList() 
        << "Name" << "Type" << "Address" << "Status" << "Value" << "Created");
    contracts_table->horizontalHeader()->setStretchLastSection(true);
    contracts_table->setAlternatingRowColors(true);
    contracts_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    mgmtLayout->addWidget(contracts_table);
    
    // Contract details
    contract_details_text = new QTextEdit(this);
    contract_details_text->setReadOnly(true);
    contract_details_text->setMaximumHeight(150);
    contract_details_text->setPlaceholderText("Select a contract to view details...");
    mgmtLayout->addWidget(contract_details_text);
    
    managementGroup->setLayout(mgmtLayout);
    layout->addWidget(managementGroup);
    
    // Connect signals
    connect(contract_type_combo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &WalletGUI::on_contract_type_changed);
    connect(create_contract_button, &QPushButton::clicked, 
            this, &WalletGUI::create_smart_contract);
    connect(execute_contract_button, &QPushButton::clicked, 
            this, &WalletGUI::execute_contract);
    connect(refresh_contracts_button, &QPushButton::clicked, 
            this, &WalletGUI::refresh_contracts);
    connect(contracts_table, &QTableWidget::itemSelectionChanged,
            this, &WalletGUI::on_contract_selected);
    
    tabWidget->addTab(contractsTab, "Contracts");
}

void WalletGUI::on_contract_type_changed(int index) {
    contract_params_stack->setCurrentIndex(index);
    updateContractCreationUI();
}

void WalletGUI::updateContractCreationUI() {
    // Update UI based on contract type
    int type = contract_type_combo->currentIndex();
    
    // Reset all fields
    timelock_timestamp_edit->clear();
    timelock_pubkeyhash_edit->clear();
    hashlock_preimage_edit->clear();
    oracle_key_edit->clear();
    state_key_edit->clear();
    custom_script_edit->clear();
    
    // Set default values based on type
    switch (type) {
        case 0: // Time Lock
            timelock_timestamp_edit->setText(
                QString::number(QDateTime::currentDateTime().addDays(30).toSecsSinceEpoch()));
            break;
        case 1: // Hash Lock
            hashlock_preimage_edit->setText("mysecret123");
            break;
        case 2: // Oracle
            oracle_key_edit->setText("price:USD");
            oracle_threshold_edit->setText("1000");
            break;
        case 3: // Stateful
            state_key_edit->setText("counter");
            state_value_edit->setText("0");
            break;
    }
}

void WalletGUI::create_smart_contract() {
    try {
        std::string contractName = contract_name_edit->text().toStdString();
        if (contractName.empty()) {
            showMessage("Invalid Input", "Please enter a contract name", true);
            return;
        }
        
        // Generate the script based on type
        std::string scriptText = generateContractScript();
        if (scriptText.empty()) {
            showMessage("Invalid Input", "Failed to generate contract script", true);
            return;
        }
        
        // Get current pubkeyhash for the wallet
        std::string currentAddr = wallet.getCurrentAddress();
        std::string pubkeyhash = wallet.getPubKeyHashForAddress(currentAddr);
        
        // Call wallet's contract creation method
        std::string result = wallet.createSmartContract(
            contract_type_combo->currentText().toStdString(),
            contractName,
            scriptText,
            nodeIP_edit->text().toStdString(),
            nodePort_edit->text().toInt()
        );
        
        // Parse result to get contract address
        QStringList lines = QString::fromStdString(result).split('\n');
        QString contractAddr;
        for (const QString& line : lines) {
            if (line.contains("Contract Address:")) {
                contractAddr = line.split(":").last().trimmed();
                break;
            }
        }
        
        showMessage("Contract Created", 
                   QString("Smart contract deployed successfully!\n\n%1")
                   .arg(QString::fromStdString(result)));
        
        // Clear form
        contract_name_edit->clear();
        updateContractCreationUI();
        
        // Refresh contracts list
        refresh_contracts();
        
    } catch (const std::exception& e) {
        showMessage("Error", QString::fromStdString(e.what()), true);
    }
}

std::string WalletGUI::generateContractScript() {
    int type = contract_type_combo->currentIndex();
    std::string script;
    
    switch (type) {
        case 0: { // Time Lock
            uint32_t lockTime = timelock_timestamp_edit->text().toUInt();
            std::string pubkeyhash = timelock_pubkeyhash_edit->text().toStdString();
            
            if (pubkeyhash.empty()) {
                // Use current address pubkeyhash
                std::string addr = wallet.getCurrentAddress();
                pubkeyhash = wallet.getPubKeyHashForAddress(addr);
            }
            
            // Convert locktime to little-endian hex
            char timeHex[9];
            snprintf(timeHex, sizeof(timeHex), "%08x", lockTime);
            
            script = std::string(timeHex) + " OP_CHECKLOCKTIMEVERIFY OP_DROP "
                    "OP_DUP OP_HASH160 " + pubkeyhash + " OP_EQUALVERIFY OP_CHECKSIG";
            break;
        }
        
        case 1: { // Hash Lock
            std::string preimage = hashlock_preimage_edit->text().toStdString();
            if (preimage.empty()) return "";
            
            // Calculate HASH160
            std::vector<unsigned char> data(preimage.begin(), preimage.end());
            std::vector<unsigned char> hash = computeHash160(data);
            
            script = "OP_HASH160 " + bytesToHex(hash) + " OP_EQUAL";
            break;
        }
        
        case 2: { // Oracle-based
            std::string key = oracle_key_edit->text().toStdString();
            uint64_t threshold = oracle_threshold_edit->text().toULongLong();
            bool isGreaterThan = (oracle_comparison_combo->currentIndex() == 0);
            
            if (key.empty()) return "";
            
            // Get current address pubkeyhash
            std::string addr = wallet.getCurrentAddress();
            std::string pubkeyhash = wallet.getPubKeyHashForAddress(addr);
            
            // Convert key to hex
            std::vector<unsigned char> keyBytes(key.begin(), key.end());
            
            // Convert threshold to hex (8 bytes, little-endian)
            char thresholdHex[17];
            snprintf(thresholdHex, sizeof(thresholdHex), "%016" PRIx64, threshold);
            
            script = bytesToHex(keyBytes) + " OP_DATAFEED " + std::string(thresholdHex) + " " +
                    (isGreaterThan ? "OP_GREATERTHAN" : "OP_LESSTHAN") + 
                    " OP_VERIFY OP_DUP OP_HASH160 " + pubkeyhash + " OP_EQUALVERIFY OP_CHECKSIG";
            break;
        }
        
        case 3: { // Stateful
            std::string key = state_key_edit->text().toStdString();
            std::string value = state_value_edit->text().toStdString();
            
            if (key.empty() || value.empty()) return "";
            
            // Convert to hex
            std::vector<unsigned char> keyBytes(key.begin(), key.end());
            std::vector<unsigned char> valueBytes(value.begin(), value.end());
            
            script = bytesToHex(keyBytes) + " " + bytesToHex(valueBytes) + " OP_STORE OP_RETURN";
            break;
        }
        
        case 4: { // OP_RETURN
            QTextEdit* dataEdit = qobject_cast<QTextEdit*>(contract_params_stack->currentWidget()->findChild<QTextEdit*>());
            if (!dataEdit) return "";
            
            std::string data = dataEdit->toPlainText().toStdString();
            if (data.empty()) return "";
            
            std::vector<unsigned char> dataBytes(data.begin(), data.end());
            script = "OP_RETURN " + bytesToHex(dataBytes);
            break;
        }
        
        case 5: { // Custom
            script = custom_script_edit->toPlainText().toStdString();
            break;
        }
    }
    
    return script;
}

void WalletGUI::calculate_hash() {
    std::string preimage = hashlock_preimage_edit->text().toStdString();
    if (preimage.empty()) return;
    
    std::vector<unsigned char> data(preimage.begin(), preimage.end());
    std::vector<unsigned char> hash = computeHash160(data);
    
    hashlock_hash_edit->setText(QString::fromStdString(bytesToHex(hash)));
}

void WalletGUI::estimate_contract_gas() {
    try {
        std::string script = custom_script_edit->toPlainText().toStdString();
        if (script.empty()) {
            showMessage("No Script", "Please enter a script to estimate gas", true);
            return;
        }
        
        // Compile and estimate gas
        std::vector<unsigned char> scriptBytes = compileTextScript(script);
        
        // Basic gas estimation based on script complexity
        uint64_t estimatedGas = 1000; // Base gas
        estimatedGas += scriptBytes.size() * 10; // Per byte cost
        
        // Add costs for specific opcodes
        for (size_t i = 0; i < scriptBytes.size(); i++) {
            switch (scriptBytes[i]) {
                case OP_CHECKSIG:
                case OP_CHECKSIGVERIFY:
                    estimatedGas += 100;
                    break;
                case OP_SHA256:
                case OP_HASH160:
                case OP_SHA3:
                case OP_HASHBLAKE2B:
                    estimatedGas += 50;
                    break;
                case OP_STORE:
                case OP_LOAD:
                    estimatedGas += 200;
                    break;
                case OP_DATAFEED:
                case OP_EXTERNALDATA:
                    estimatedGas += 500;
                    break;
            }
        }
        
        QLabel* gasLabel = findChild<QLabel*>("gasEstimateLabel");
        if (gasLabel) {
            gasLabel->setText(QString("Estimated Gas: %1").arg(estimatedGas));
        }
        
    } catch (const std::exception& e) {
        showMessage("Estimation Error", QString::fromStdString(e.what()), true);
    }
}

void WalletGUI::refresh_contracts() {
    contracts_table->setRowCount(0);
    
    try {
        // Query contracts from wallet/blockchain
        auto contracts = wallet.getSmartContracts();
        
        // Debug: Show count
        showMessage("Debug", QString("Found %1 contracts").arg(contracts.size()));
        
        // If no contracts from wallet, try direct blockchain query for debugging
        if (contracts.empty() && wallet.isLocalChainAvailable()) {
            nlohmann::json blockchainContracts = wallet.getBlockchain().getContracts();
            showMessage("Debug", QString("Blockchain has %1 contracts")
                       .arg(blockchainContracts["contracts"].size()));
        }
        
        for (const auto& contract : contracts) {
            int row = contracts_table->rowCount();
            contracts_table->insertRow(row);
            
            contracts_table->setItem(row, 0, new QTableWidgetItem(
                QString::fromStdString(contract.name)));
            contracts_table->setItem(row, 1, new QTableWidgetItem(
                QString::fromStdString(contract.type)));
            contracts_table->setItem(row, 2, new QTableWidgetItem(
                QString::fromStdString(contract.address)));
            contracts_table->setItem(row, 3, new QTableWidgetItem(
                QString::fromStdString(contract.status)));
            contracts_table->setItem(row, 4, new QTableWidgetItem(
                QString::number(contract.value / 100000000.0, 'f', 8) + " TRU"));
            contracts_table->setItem(row, 5, new QTableWidgetItem(
                QDateTime::fromSecsSinceEpoch(contract.createdAt).toString("yyyy-MM-dd HH:mm")));
        }
        
    } catch (const std::exception& e) {
        showMessage("Refresh Error", QString::fromStdString(e.what()), true);
    }
}

void WalletGUI::on_contract_selected() {
    int row = contracts_table->currentRow();
    if (row < 0) {
        execute_contract_button->setEnabled(false);
        contract_details_text->clear();
        return;
    }
    
    execute_contract_button->setEnabled(true);
    
    QString address = contracts_table->item(row, 2)->text();
    displayContractDetails(address);
}

void WalletGUI::displayContractDetails(const QString& contractAddress) {
    try {
        auto details = wallet.getContractDetails(contractAddress.toStdString());
        
        QString detailsText = QString(
            "Contract: %1\n"
            "Type: %2\n"
            "Script: %3\n"
            "State: %4\n"
            "Executable: %5"
        ).arg(QString::fromStdString(details.name))
         .arg(QString::fromStdString(details.type))
         .arg(QString::fromStdString(details.scriptHex))
         .arg(QString::fromStdString(details.state))
         .arg(details.canExecute ? "Yes" : "No");
        
        contract_details_text->setText(detailsText);
        
    } catch (const std::exception& e) {
        contract_details_text->setText("Error loading contract details");
    }
}

void WalletGUI::execute_contract() {
    int row = contracts_table->currentRow();
    if (row < 0) return;
    
    QString contractAddr = contracts_table->item(row, 2)->text();
    QString contractType = contracts_table->item(row, 1)->text();
    
    try {
        // Different execution based on contract type
        if (contractType == "Hash Lock") {
            bool ok;
            QString preimage = QInputDialog::getText(this, "Execute Hash Lock",
                                                   "Enter preimage (secret):",
                                                   QLineEdit::Normal, "", &ok);
            if (!ok || preimage.isEmpty()) return;
            
            std::string txid = wallet.redeemHashLock(contractAddr.toStdString(), 
                                                     preimage.toStdString());
            showMessage("Contract Executed", 
                       QString("Hash lock redeemed!\nTXID: %1").arg(QString::fromStdString(txid)));
            
        } else if (contractType == "Time Lock") {
            // Check if time has passed
            std::string txid = wallet.redeemTimeLock(contractAddr.toStdString());
            showMessage("Contract Executed", 
                       QString("Time lock redeemed!\nTXID: %1").arg(QString::fromStdString(txid)));
            
        } else if (contractType == "Oracle-Based") {
            // Execute oracle-based contract
            std::string txid = wallet.executeOracleContract(contractAddr.toStdString());
            showMessage("Contract Executed", 
                       QString("Oracle contract executed!\nTXID: %1").arg(QString::fromStdString(txid)));
            
        } else {
            showMessage("Not Implemented", 
                       "Execution for this contract type is not yet implemented", true);
        }
        
        // Refresh contracts
        refresh_contracts();
        updateBalanceDisplay();
        
    } catch (const std::exception& e) {
        showMessage("Execution Error", QString::fromStdString(e.what()), true);
    }
}

void WalletGUI::handleTransactionContextMenu(const QPoint& pos) {
    QTableWidgetItem* item = transactions_table->itemAt(pos);
    if (!item || item->column() != 4) { // Only for TXID column
        return;
    }
    
    QMenu menu(this);
    QAction* copyAction = menu.addAction("Copy Full TXID");
    
    QAction* selectedAction = menu.exec(transactions_table->mapToGlobal(pos));
    if (selectedAction == copyAction) {
        QString fullTxid = item->data(Qt::UserRole).toString();
        QApplication::clipboard()->setText(fullTxid);
        showMessage("Copied", "Transaction ID copied to clipboard");
    }
}
