// walletgui.h
#ifndef WALLETGUI_H
#define WALLETGUI_H

#include <QWidget>
#include <QTabWidget>
#include <QTableWidget>
#include <QTextEdit>
#include <QComboBox>
#include <QLabel>
#include <QTimer>
#include <QGroupBox>
#include <QCheckBox>
#include <QSpinBox>
#include <QListWidget>
#include "wallet.h"
#include <QPushButton>
#include <QLineEdit>
#include <QProgressBar>
#include <QStackedWidget>
#include <QMenu>
#include <QWidget>

// Forward declarations
class AnimatedBackground;
class GlowBorder;
class DesktopPanel;
class QProcess;
class QPlainTextEdit;
class QCloseEvent;

class WalletGUI : public QWidget {
    Q_OBJECT
public:
    explicit WalletGUI(Wallet &walletRef, QWidget *parent = nullptr, int rpcPort = tru_network::MAINNET_RPC_PORT, const QByteArray& rpcToken = {});
    ~WalletGUI();

private slots:
    // Wallet Management
    void create_wallet();
    void import_private_key();
    void generate_new_address();
    void refresh_addresses();
    void copy_current_address();
    void show_qr_code();
    void backup_wallet();
    void restore_wallet();
    void updateBlockHeight();
    
    // Transactions
    void send_transaction();
    void check_balance();
    void mine();
    void refresh_transactions();
    void on_address_selection_changed();
    
    // Tokens
    void issue_token();
    void transfer_token();
    void refresh_tokens();
    void on_token_type_changed(int index);
    
    // TRUScript
    void inscribe_tru_script();
    void transfer_tru_script();
    void refresh_tru_scripts();
    
    // Settings
    void save_settings();
    void load_settings();
    void change_theme();
    
    // Auto-refresh
    void auto_refresh();
    
    // Smart Contracts
    void on_contract_type_changed(int index);
    void create_smart_contract();
    void execute_contract();
    void refresh_contracts();
    void on_contract_selected();
    void calculate_hash();
    void estimate_contract_gas();
    void handleTransactionContextMenu(const QPoint& pos);

protected:
    void resizeEvent(QResizeEvent *event) override;
    void closeEvent(QCloseEvent *event) override;

private:
    void setupUI();
    void setupMiningTab();
    void setupMultisigTab();
    void retire_token();
    bool selectWalletAddress(const QString& address);
    bool confirmAction(const QString& action, const QString& details);
    void persistSettings();
    int localRpcPort;
    QByteArray localRpcToken;
    DesktopPanel* corePanel = nullptr;
    QProcess* minerProcess = nullptr;
    QComboBox* minerKind = nullptr;
    QSpinBox* minerThreads = nullptr;
    QPlainTextEdit* minerOutput = nullptr;
    QLineEdit* contract_amount_edit = nullptr;
    QPlainTextEdit* token_extra_metadata = nullptr;
    bool closingAfterMiner = false;
    void setupWalletTab();
    void setupSendTab();
    void setupTokensTab();
    void setupTRUScriptTab();
    void setupTransactionsTab();
    void setupSettingsTab();
    void updateBalanceDisplay();
    void updateNetworkStatus();
    void showMessage(const QString &title, const QString &message, bool isError = false);
    QString formatBalance(double balance) const;
    void populateAddressCombo();
    void applyTheme(const QString &theme);
    void loadCustomLogo();
    
    void setupContractsTab();
    void updateContractCreationUI();
    std::string generateContractScript();
    void displayContractDetails(const QString& contractAddress);
    
    // Reference to wallet
    Wallet &wallet;
    
    // Main UI components
    QTabWidget *tabWidget;
    
    // Animated background
    AnimatedBackground *backgroundWidget;
    GlowBorder *glowBorder;
    
    // Logo/branding
    QLabel *logoLabel;
    
    // Wallet Tab
    QPushButton *create_wallet_button;
    QPushButton *import_key_button;
    QPushButton *generate_address_button;
    QPushButton *copy_address_button;
    QPushButton *show_qr_button;
    QPushButton *backup_button;
    QPushButton *restore_button;
    QComboBox *address_combo;
    QLabel *balance_label;
    QLabel *block_height_label;
    QTableWidget *address_table;
    
    // Send Tab
    QComboBox *from_address_combo;
    QLineEdit *recipient_edit;
    QLineEdit *amount_edit;
    QLineEdit *fee_edit;
    QPushButton *send_button;
    QLabel *available_balance_label;
    QProgressBar *send_progress;
    
    // Tokens Tab
    QComboBox *token_type_combo;
    QGroupBox *token_creation_group;
    QLineEdit *token_id_edit;
    QLineEdit *token_name_edit;
    QLineEdit *token_symbol_edit;
    QLineEdit *token_supply_edit;
    QSpinBox *token_decimals_spin;
    QTextEdit *token_description_edit;
    QLineEdit *token_image_url_edit;
    QPushButton *issue_token_button;
    QTableWidget *tokens_table;
    QPushButton *transfer_token_button;
    QPushButton *refresh_tokens_button;
    
    // TRUScript Tab
    QTextEdit *tru_script_data_edit;
    QLineEdit *tru_script_owner_edit;
    QPushButton *inscribe_button;
    QTableWidget *tru_scripts_table;
    QPushButton *transfer_script_button;
    
    // Transactions Tab
    QTableWidget *transactions_table;
    QPushButton *refresh_tx_button;
    QCheckBox *show_all_addresses_check;
    
    // Settings Tab
    QLineEdit *nodeIP_edit;
    QLineEdit *nodePort_edit;
    QCheckBox *auto_refresh_check;
    QSpinBox *refresh_interval_spin;
    QPushButton *save_settings_button;
    QComboBox *theme_combo;
    
    // Mining
    QPushButton *mine_button;
    QLabel *mining_status_label;
    QLabel *network_status_label;
    
    // Timers and state
    QTimer *refresh_timer;
    bool is_mining;
    
    // Cache
    QStringList cached_addresses;
    double cached_balance;
    
    // Current theme
    QString currentTheme;
    
    // Smart Contracts Tab
    QComboBox *contract_type_combo;
    QGroupBox *contract_creation_group;
    QStackedWidget *contract_params_stack;
    
    // Contract creation fields
    QLineEdit *contract_name_edit;
    QLineEdit *contract_address_edit;
    
    // Time Lock fields
    QLineEdit *timelock_timestamp_edit;
    QLineEdit *timelock_pubkeyhash_edit;
    QLineEdit *timelock_reason_edit;
    
    // Hash Lock fields  
    QLineEdit *hashlock_preimage_edit;
    QLineEdit *hashlock_hash_edit;
    
    // Oracle fields
    QLineEdit *oracle_key_edit;
    QLineEdit *oracle_threshold_edit;
    QComboBox *oracle_comparison_combo;
    
    // Stateful fields
    QLineEdit *state_key_edit;
    QLineEdit *state_value_edit;
    
    // Custom script
    QTextEdit *custom_script_edit;
    
    // Contract management
    QPushButton *create_contract_button;
    QPushButton *execute_contract_button;
    QPushButton *refresh_contracts_button;
    QTableWidget *contracts_table;
    QTextEdit *contract_details_text;

    // TX Search
    QLineEdit* tx_search_edit;
    QComboBox* tx_filter_combo;    
};

#endif // WALLETGUI_H
