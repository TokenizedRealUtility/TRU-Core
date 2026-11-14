#pragma once
// TRU_TOOLBOX_091_01 — presentation only. No RPC, key access or amount math.
#include "tru_toolbox_091_art.h"
#include <QPainter>
// TRU_TOOLBOX_091_01 — presentation only. No RPC, key access or amount math.
#include <QComboBox>
#include <QEvent>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPointer>
#include <QPushButton>
#include <QScrollArea>
#include <QSignalBlocker>
#include <QStandardItemModel>
#include <QTabBar>
#include <QTabWidget>
#include <QTimer>
#include <QVBoxLayout>
#include <functional>
#include <utility>
#include <vector>

namespace tru_toolbox_091 {
class MetalBackdrop final : public QWidget {
    QPixmap metal_ = tru_toolbox_092_art::texture();
protected:
    bool eventFilter(QObject* watched, QEvent* event) override {
        if (watched == parentWidget() && event->type() == QEvent::Resize) {
            setGeometry(parentWidget()->rect()); lower();
        }
        if (watched == parentWidget() && event->type() == QEvent::DynamicPropertyChange) update();
        return QWidget::eventFilter(watched, event);
    }
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.drawTiledPixmap(rect(), metal_);
        const bool light = parentWidget()->property("truTheme").toString() == "light";
        p.fillRect(rect(), light ? QColor(235, 229, 206, 185) : QColor(5, 13, 15, 110));
        p.setRenderHint(QPainter::Antialiasing);
        p.setPen(QPen(QColor(142, 112, 72), 2));
        p.drawRoundedRect(rect().adjusted(2, 2, -3, -3), 15, 15);
        for (const QPoint& point : {QPoint(9,9), QPoint(width()-10,9),
                QPoint(9,height()-10), QPoint(width()-10,height()-10)}) {
            p.setBrush(QColor(78, 66, 49)); p.drawEllipse(point, 3, 3);
        }
    }
public:
    explicit MetalBackdrop(QWidget* parent) : QWidget(parent) {
        setObjectName("toolboxMetalBackdrop");
        setAttribute(Qt::WA_TransparentForMouseEvents);
        setFocusPolicy(Qt::NoFocus);
        parent->installEventFilter(this); setGeometry(parent->rect()); lower(); show();
    }
};
inline QLabel* bronzeLogo() {
    auto* logo = new QLabel;
    logo->setObjectName("toolboxBronzeLogo");
    logo->setFixedSize(150, 60);
    logo->setPixmap(tru_toolbox_092_art::logo().scaled(300,120,Qt::KeepAspectRatio,Qt::SmoothTransformation));
    logo->setScaledContents(true);
    logo->setAccessibleName("TRU wrench emblem");
    logo->setToolTip("TRU Application Toolbox");
    return logo;
}
inline constexpr const char* releaseVersion = "0.09.1";
inline QString theme(bool light) {
    QString s = R"TB091(
        QLabel { background:transparent; }
        QWidget#toolboxNavHost { background:transparent; }
        QFrame#toolboxRail { background:#0e1a22; border:1px solid #2c4049; border-radius:14px; }
        QLabel#toolboxEyebrow { color:#99b6bd; font-size:11px; font-weight:700; }
        QLabel#toolboxHeading { color:#edf5f7; font-size:27px; font-weight:700; }
        QLabel#toolboxCopy { color:#a2b8c0; font-size:13px; }
        QLabel#toolboxBalance { color:#edf5f7; font-size:36px; font-weight:800; }
        QLabel#toolboxState { color:#64e4be; font-size:12px; font-weight:700; }
        QFrame#toolboxHero { background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #15252e,stop:1 #1c3b36); border:1px solid #3b625a; border-radius:18px; }
        QFrame#toolboxCard { background:#14232c; border:1px solid #30434f; border-radius:12px; }
        QLabel#toolboxCardTitle { color:#edf5f7; font-size:16px; font-weight:700; }
        QPushButton#toolboxNav { text-align:left; background:transparent; color:#b3c5cd; border:1px solid transparent; padding:11px 12px; border-radius:9px; font-size:13px; }
        QPushButton#toolboxNav:hover { background:#1c3337; color:#ffffff; }
        QPushButton#toolboxNav:checked { background:#23423f; border-color:#365e54; color:#69e6c2; }
        QPushButton#toolboxNav:disabled { color:#62777e; }
        QPushButton#toolboxPrimary { background:#62e3bc; color:#082b24; border:1px solid #62e3bc; border-radius:9px; padding:11px 17px; font-weight:700; }
        QPushButton#toolboxPrimary:hover { background:#85efcf; }
        QPushButton#toolboxOpen { text-align:left; background:transparent; color:#6ae5c2; border:0; padding:6px 0; }
        QPushButton:focus, QComboBox:focus { border:1px solid #64e4be; }
        QScrollArea#toolboxRailScroll { background:transparent; border:0; }
        QComboBox#toolboxCompactNav { min-height:28px; }
        QTabWidget#toolboxPages::pane { border:0; background:transparent; }
        QScrollBar:vertical { background:#102029; width:10px; margin:0; }
        QScrollBar::handle:vertical { background:#38525c; min-height:30px; border-radius:5px; }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }
        QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background:transparent; }
    )TB091";
    if (light) s += R"TB091LIGHT(
        QFrame#toolboxRail { background:#eaf1f2; border-color:#b5c9cb; }
        QLabel#toolboxEyebrow, QLabel#toolboxCopy { color:#4b6971; }
        QLabel#toolboxHeading, QLabel#toolboxCardTitle, QLabel#toolboxBalance { color:#163e40; }
        QLabel#toolboxState { color:#08735b; }
        QFrame#toolboxHero { background:#e3f4ed; border-color:#99c4b6; }
        QFrame#toolboxCard { background:#ffffff; border-color:#b7cdd0; }
        QPushButton#toolboxNav { color:#395961; }
        QPushButton#toolboxNav:hover { background:#d9e9e6; color:#163e40; }
        QPushButton#toolboxNav:checked { background:#cce9de; border-color:#83baa5; color:#075d47; }
        QPushButton#toolboxNav:disabled { color:#819598; }
        QPushButton#toolboxOpen { color:#086d54; }
        QScrollBar:vertical { background:#e4eeed; }
        QScrollBar::handle:vertical { background:#a7c2bc; }
    )TB091LIGHT";
    return s;
}

inline QLabel* label(const QString& text, const char* name, QWidget* parent = nullptr) {
    auto* result = new QLabel(text, parent);
    result->setObjectName(name);
    result->setTextFormat(Qt::PlainText);
    result->setWordWrap(true);
    return result;
}

// Leave QTabWidget's pages, indices, enabled states and callbacks intact.
// The rail and compact selector are alternate views of that same navigation.
class Shell final : public QWidget {
    QTabWidget* pages_;
    QFrame* rail_;
    QComboBox* compact_;
    std::vector<QPushButton*> buttons_;
    void sync() {
        const QSignalBlocker blocker(compact_);
        compact_->setCurrentIndex(pages_->currentIndex());
        for (int i = 0; i < pages_->count(); ++i) {
            buttons_[i]->setChecked(i == pages_->currentIndex());
            buttons_[i]->setEnabled(pages_->isTabEnabled(i));
            // QComboBox's standard item model respects disabled flags.
            if (auto* model = qobject_cast<QStandardItemModel*>(compact_->model()))
                if (auto* item = model->item(i)) item->setEnabled(pages_->isTabEnabled(i));
        }
    }
    void adapt() {
        const bool wide = width() >= 1040;
        rail_->setVisible(wide);
        compact_->setVisible(!wide);
    }
protected:
    void resizeEvent(QResizeEvent* event) override {
        QWidget::resizeEvent(event);
        adapt();
    }
public:
    explicit Shell(QTabWidget* pages, QWidget* parent = nullptr) : QWidget(parent), pages_(pages) {
        setObjectName("toolboxShell");
        auto* outer = new QHBoxLayout(this);
        outer->setContentsMargins(0, 0, 0, 0);
        outer->setSpacing(16);
        rail_ = new QFrame(this);
        rail_->setObjectName("toolboxRail");
        rail_->setFixedWidth(210);
        auto* railLayout = new QVBoxLayout(rail_);
        railLayout->setContentsMargins(10, 18, 10, 14);
        auto* eyebrow = label("WORKSPACE", "toolboxEyebrow");
        eyebrow->setMargin(8);
        railLayout->addWidget(eyebrow);
        auto* scroll = new QScrollArea;
        scroll->setObjectName("toolboxRailScroll");
        scroll->setWidgetResizable(true);
        scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        auto* nav = new QWidget;
        nav->setObjectName("toolboxNavHost");
        auto* navLayout = new QVBoxLayout(nav);
        navLayout->setContentsMargins(0, 0, 0, 0);
        navLayout->setSpacing(5);
        compact_ = new QComboBox;
        compact_->setObjectName("toolboxCompactNav");
        compact_->setAccessibleName("Toolbox workspace");
        for (int i = 0; i < pages_->count(); ++i) {
            auto* button = new QPushButton(QString(pages_->tabText(i)).replace("&", "&&"), nav);
            button->setObjectName("toolboxNav");
            button->setCheckable(true);
            button->setToolTip(pages_->tabToolTip(i));
            button->setAccessibleName(pages_->tabText(i));
            QObject::connect(button, &QPushButton::clicked, this, [this, i] {
                if (pages_->isTabEnabled(i)) pages_->setCurrentIndex(i);
                sync();
            });
            navLayout->addWidget(button);
            buttons_.push_back(button);
            compact_->addItem(pages_->tabText(i));
        }
        navLayout->addStretch();
        scroll->setWidget(nav);
        railLayout->addWidget(scroll, 1);
        railLayout->addWidget(label("TRU TOOLBOX", "toolboxEyebrow"));
        railLayout->addWidget(label("Your tools. Your keys.\nPowered by TRU.", "toolboxCopy"));
        outer->addWidget(rail_);
        auto* content = new QVBoxLayout;
        content->setSpacing(10);
        content->addWidget(compact_);
        pages_->setObjectName("toolboxPages");
        pages_->tabBar()->hide();
        content->addWidget(pages_, 1);
        outer->addLayout(content, 1);
        QObject::connect(compact_, QOverload<int>::of(&QComboBox::activated), this, [this](int i) {
            if (pages_->isTabEnabled(i)) pages_->setCurrentIndex(i);
            sync();
        });
        QObject::connect(pages_, &QTabWidget::currentChanged, this, [this](int) { sync(); });
        auto* stateTimer = new QTimer(this);
        QObject::connect(stateTimer, &QTimer::timeout, this, [this] { if (isVisible()) sync(); });
        stateTimer->start(500);
        sync();
        adapt();
    }
};

inline void openPage(QTabWidget* pages, QWidget* content, QWidget* focus = nullptr) {
    for (int i = 0; i < pages->count(); ++i) {
        auto* page = pages->widget(i);
        if (page != content && !page->isAncestorOf(content)) continue;
        if (!pages->isTabEnabled(i)) return;
        pages->setCurrentIndex(i);
        if (focus) {
            QPointer<QWidget> target(focus);
            QPointer<QScrollArea> view(qobject_cast<QScrollArea*>(page));
            QTimer::singleShot(0, pages, [target, view] {
                if (!target) return;
                if (view) view->ensureWidgetVisible(target, 20, 30);
                target->setFocus(Qt::OtherFocusReason);
            });
        }
        return;
    }
}

inline void installOverview(QWidget* overview, QTabWidget* pages, QWidget* wallet,
                            QWidget* assets, QWidget* ai, QWidget* compute, QWidget* creator) {
    auto* home = new QWidget(overview);
    home->setObjectName("toolboxHome");
    auto* layout = new QVBoxLayout(home);
    layout->setContentsMargins(0, 0, 0, 12);
    layout->setSpacing(14);
    layout->addWidget(label("YOUR WORKSPACE", "toolboxEyebrow"));
    layout->addWidget(label("Everything you need. One Toolbox.", "toolboxHeading"));
    layout->addWidget(label("Create assets, publish data, explore AI and put TRU to work.", "toolboxCopy"));
    auto* hero = new QFrame;
    hero->setObjectName("toolboxHero");
    auto* h = new QVBoxLayout(hero);
    h->setContentsMargins(24, 22, 24, 22);
    h->setSpacing(10);
    h->addWidget(label("TRU CREDITS  /  WALLET SNAPSHOT", "toolboxEyebrow"));
    auto* balance = label("— TRU", "toolboxBalance");
    balance->setTextInteractionFlags(Qt::TextSelectableByMouse);
    balance->setToolTip("Mirrors the existing wallet's last displayed safe-spendable balance. Open Credits & Vault to refresh and review activity.");
    h->addWidget(balance);
    auto* state = label("Wallet state unavailable", "toolboxState");
    h->addWidget(state);
    auto* pending = label("Pending: unavailable", "toolboxCopy");
    h->addWidget(pending);
    h->addWidget(label("1 displayed TRU credit = 1 TRU. Amounts and network fees remain in TRU.", "toolboxCopy"));
    auto* row = new QHBoxLayout;
    auto* credits = new QPushButton("Open credits && vault");
    credits->setObjectName("toolboxPrimary");
    auto* receive = new QPushButton("Receive && identity");
    row->addWidget(credits);
    row->addWidget(receive);
    row->addStretch();
    h->addLayout(row);
    QObject::connect(credits, &QPushButton::clicked, home, [pages, wallet] { openPage(pages, wallet); });
    QObject::connect(receive, &QPushButton::clicked, home, [pages, wallet] {
        openPage(pages, wallet, wallet->findChild<QWidget*>("truReceiveCard"));
    });
    layout->addWidget(hero);
    layout->addWidget(label("YOUR TOOLS", "toolboxEyebrow"));
    auto* grid = new QGridLayout;
    grid->setSpacing(12);
    int cell = 0;
    auto add = [&](const QString& title, const QString& copy, std::function<void()> action) {
        auto* card = new QFrame;
        card->setObjectName("toolboxCard");
        auto* c = new QVBoxLayout(card);
        c->setContentsMargins(16, 16, 16, 12);
        c->addWidget(label(title, "toolboxCardTitle"));
        c->addWidget(label(copy, "toolboxCopy"), 1);
        auto* open = new QPushButton("Open tool  →");
        open->setObjectName("toolboxOpen");
        open->setAccessibleName("Open " + title);
        QObject::connect(open, &QPushButton::clicked, home, [action] { action(); });
        c->addWidget(open);
        grid->addWidget(card, cell / 2, cell % 2);
        ++cell;
    };
    add("Digital assets", "Your tokens, collectibles and TRUScripts.", [pages, assets] { openPage(pages, assets); });
    add("AI & agents", "AI assets, providers and evolution provenance.", [pages, ai] { openPage(pages, ai); });
    add("Compute · AXON", "Open the existing NeroMesh customer and worker portal.", [pages, compute] { openPage(pages, compute); });
    add("Data & proof", "Create assets and publish public TRUScripts.", [pages, creator] {
        openPage(pages, creator);
        if (auto* sections = creator->findChild<QTabWidget*>("toolboxCreatorSections")) sections->setCurrentIndex(1);
    });
    add("Marketplace", "Pair your wallet through the existing approval flow.", [pages, wallet] {
        openPage(pages, wallet, wallet->findChild<QPushButton*>("toolboxMarketConnect"));
    });
    add("Quantum transactions", "Existing WOTS+ tools, backups and recovery.", [pages, wallet] {
        openPage(pages, wallet, wallet->findChild<QPushButton*>("toolboxQuantum"));
    });
    grid->setColumnStretch(0, 1);
    grid->setColumnStretch(1, 1);
    layout->addLayout(grid);
    layout->addWidget(label("NETWORK SNAPSHOT", "toolboxEyebrow"));
    if (auto* old = qobject_cast<QVBoxLayout*>(overview->layout())) old->insertWidget(0, home);
    // Presentation mirrors only. Do not query getbalance: that is the node wallet,
    // which may not be the user's independent local-key desktop wallet.
    QPointer<QLabel> sourceBalance(wallet->findChild<QLabel*>("truWalletBalanceValue"));
    QPointer<QLabel> sourceState(wallet->findChild<QLabel*>("truWalletState"));
    QPointer<QLabel> sourcePending(wallet->findChild<QLabel*>("truWalletPendingBalance"));
    auto mirror = [balance, state, pending, sourceBalance, sourceState, sourcePending] {
        balance->setText(sourceBalance ? sourceBalance->text() : "— TRU");
        state->setText(sourceState ? "LOCAL WALLET  ·  " + sourceState->text() : "Wallet state unavailable");
        pending->setText(sourcePending ? sourcePending->text() : "Pending: unavailable");
    };
    mirror();
    auto* displayTimer = new QTimer(home);
    QObject::connect(displayTimer, &QTimer::timeout, home, [home, mirror] { if (home->isVisible()) mirror(); });
    displayTimer->start(400);
}
} // namespace tru_toolbox_091
