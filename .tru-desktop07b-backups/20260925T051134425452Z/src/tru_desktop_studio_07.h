#pragma once
// TRU-DESKTOP-07A: self-custody creation studio. Header-only Qt widget:
// existing Qt5/Qt6 desktop build manifests do not need a new .cpp target.
// Write workflows require local Core and local standalone wallet signatures.
#include "desktop_rpc.h"
#include "desktop_wallet_widget.h"
#include "desktop_wallet_core.h"
#include <QComboBox>
#include <QCryptographicHash>
#include <QDateTime>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QList>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QRandomGenerator>
#include <QRegularExpression>
#include <QTabWidget>
#include <QTableWidget>
#include <QAbstractItemView>
#include <QUrl>
#include <QVBoxLayout>
#include <openssl/ripemd.h>
#include <openssl/sha.h>
#include <cstdint>
#include <limits>

class TruDesktopStudio07 final:public QWidget {
    DesktopRpc* rpc_;
    DesktopWalletWidget* wallet_;
    QComboBox *type_=nullptr,*kind_=nullptr;
    QLineEdit *tid_=nullptr,*name_=nullptr,*symbol_=nullptr,*supply_=nullptr,*desc_=nullptr,*image_=nullptr;
    QPlainTextEdit *inscription_=nullptr,*contracts_=nullptr;
    QTableWidget *contractTable_=nullptr;
    QList<QJsonObject> visibleContracts_;
    QLineEdit *contractName_=nullptr,*secret_=nullptr,*lockTime_=nullptr,*contractAmount_=nullptr;
    QLabel *notice_=nullptr;
    QPushButton *mint_=nullptr,*inscribe_=nullptr,*contractCreate_=nullptr;
    bool busy_=false;
    static constexpr std::uint64_t kFee=10000;
    static constexpr std::uint64_t kDust=546;

    static QByteArray pack(const QJsonObject& o) {
        return QJsonDocument(o).toJson(QJsonDocument::Compact);
    }
    static QString decimal(std::uint64_t value) {
        return QString::fromStdString(DesktopWalletCore::formatAmount(value));
    }
    static bool asciiSafe(const QString& value, int maxBytes=1000) {
        const QByteArray b=value.toUtf8();
        if(b.isEmpty() || b.size()>maxBytes)return false;
        for (char c:b) if(static_cast<unsigned char>(c)<32 || static_cast<unsigned char>(c)>126)return false;
        return true;
    }
    static bool digits64(const QString& text,std::uint64_t& n) {
        if(text.isEmpty() || text.contains(QRegularExpression("[^0-9]")))return false;
        bool ok=false; const auto value=text.toULongLong(&ok,10);
        if(!ok)return false;
        n=static_cast<std::uint64_t>(value);return true;
    }
    static QJsonObject output(const QString& script,std::uint64_t atoms) {
        return QJsonObject{{"scriptPubKey",script.toLower()},
                           {"amount_atoms",QString::number(static_cast<qulonglong>(atoms))}};
    }
    bool localReady(const QString& action) {
        if(busy_) {QMessageBox::warning(this,action,"An action is in progress.");return false;}
        if(!rpc_ || !rpc_->endpoint().isValid() || DesktopRpc::isRemoteEndpoint(rpc_->endpoint()) ||
           rpc_->endpoint().scheme().toLower()!="http" ||
           rpc_->endpoint().path()!="/rpc" ||
           !rpc_->endpoint().userInfo().isEmpty() || rpc_->endpoint().hasQuery() ||
           rpc_->endpoint().hasFragment()) {
            QMessageBox::warning(this,action,
                "Issuance and contract creation require your own local Core RPC at "
                "http://127.0.0.1:<port>/rpc. The public gateway and remote Core "
                "are read-only for this studio release.");
            return false;
        }
        if(!wallet_ || !wallet_->walletUnlocked()) {
            QMessageBox::warning(this,action,"Unlock the standalone wallet on the Wallet tab first.");
            return false;
        }
        const QString sender=wallet_->currentWalletAddress();
        if(sender.isEmpty() || wallet_->walletScriptForAddress(sender).isEmpty()) {
            QMessageBox::warning(this,action,"No current standalone wallet address.");
            return false;
        }
        return true;
    }
    void busy(bool yes) {
        busy_=yes;
        if(mint_)mint_->setDisabled(yes);
        if(inscribe_)inscribe_->setDisabled(yes);
        if(contractCreate_)contractCreate_->setDisabled(yes);
    }
    static QString rawError(const QString& error) {
        return error.isEmpty()?"Core returned an unexpected result.":error;
    }
    void submitPrepared(const QString& title,const QString& method,
        const QString& unsignedHex,const QJsonObject& selected,
        const QList<QJsonArray>& permissibleOrders,
        const QJsonObject& submission,
        const QString& summary,
        bool expectMetadata, QJsonObject approvedMetadata = {}) {
        QString tail,auditError;
        QJsonObject embeddedMetadata;
        bool inspected=false;
        for(const auto& expected:permissibleOrders)
            if(wallet_->inspectPreparedIntent(unsignedHex,selected,expected,kFee+kDust-1,
                                             tail,embeddedMetadata,auditError)){inspected=true;break;}
        if(!inspected) {
            busy(false);
            QMessageBox::critical(this,title,"Unsigned transaction rejected by the local "
                "wallet output/fee audit: "+auditError);
            return;
        }
        if(expectMetadata && !tail.startsWith("01")) {
            busy(false);
            QMessageBox::critical(this,title,
                "The unsigned issuance has no embedded metadata before signing. "
                "This is an incompatible older Core; update the builder first.");
            return;
        }
        if(expectMetadata && (approvedMetadata.isEmpty() || embeddedMetadata.size()!=1 ||
            embeddedMetadata.constBegin().value().toObject()!=approvedMetadata)) {
            busy(false);
            QMessageBox::critical(this,title,"Embedded token metadata is not the exact approved payload.");
            return;
        }
        if(!expectMetadata && tail!="00") {
            busy(false);
            QMessageBox::critical(this,title,"Unexpected metadata tail in prepared transaction.");
            return;
        }
        QString signedHex,txid,error;
        if(!wallet_->signPreparedTransaction(unsignedHex,QJsonArray{selected},
                                              signedHex,txid,error)) {
            busy(false);QMessageBox::critical(this,title,"Local signing failed: "+error);return;
        }
        if(expectMetadata && !embeddedMetadata.contains(txid)) {
            busy(false);
            QMessageBox::critical(this,title,"Embedded token metadata is not bound to the local txid.");
            return;
        }
        if(QMessageBox::question(this,"CONFIRM "+title,
             summary+"\n\nTXID: "+txid+
             "\nFee: 0.00010000 TRU\n\nBroadcast your locally signed transaction?",
             QMessageBox::Yes|QMessageBox::No,QMessageBox::No)!=QMessageBox::Yes) {
            busy(false);return;
        }
        QJsonObject request=submission;
        request.insert(method=="sendrawtransaction" ? "txHex" : "signedTxHex",signedHex);
        QPointer<TruDesktopStudio07> self(this);
        rpc_->call(method,pack(request),
          [self,title,txid,method](const QJsonValue& v,const QByteArray&,const QString& e){
             if(!self)return;
             self->busy(false);
             if(!e.isEmpty() || (method!="sendrawtransaction" &&
                  (!v.isObject() || !v.toObject().value("success").toBool())) ||
                  (method=="sendrawtransaction" && v.isNull())) {
                QMessageBox::warning(self,title,"Submission uncertain or rejected: "+rawError(e)+
                    "\nCheck the mempool/history before retrying; resending could duplicate the operation.");
                return;
             }
             QMessageBox::information(self,title,
                "Submitted to the connected node. Wait for confirmation.\nTXID: "+txid);
          });
    }
    void issueToken() {
        if(!localReady("Mint Token"))return;
        const QString type=type_->currentText();
        const QString tokenID=tid_->text().trimmed().toLower();
        const QString name=name_->text().trimmed(),symbol=symbol_->text().trimmed();
        const QString desc=desc_->text().trimmed(),art=image_->text().trimmed();
        std::uint64_t supply=0;
        if(!QRegularExpression("^[a-f0-9]{16}$").match(tokenID).hasMatch() ||
           !asciiSafe(name,64) || !asciiSafe(symbol,16) ||
           (!desc.isEmpty() && !asciiSafe(desc,200)) ||
           !digits64(supply_->text().trimmed(),supply) || supply==0 ||
           supply>9007199254740991ULL || (type=="NFT" && supply!=1)) {
             QMessageBox::warning(this,"Mint Token",
               "Use a 16-hex token ID, ASCII name/symbol, valid description, and "
               "an exact positive integer supply <= 2^53−1. NFT supply must be 1.");return;
        }
        if(!art.isEmpty()) {
            const QUrl url(art);
            if(!url.isValid() || url.scheme()!="https" || url.host().isEmpty() ||
               !url.userInfo().isEmpty() || art.size()>500) {
                QMessageBox::warning(this,"Artwork URL","Use an HTTPS image URL (no credentials) or leave empty.");return;
            }
        }
        const QString from=wallet_->currentWalletAddress();
        const QString ownScript=wallet_->walletScriptForAddress(from).toLower();
        const QString hash160=ownScript.mid(6,40);
        if(!ownScript.startsWith("76a914") || !ownScript.endsWith("88ac") || hash160.size()!=40){
            QMessageBox::warning(this,"Mint Token","Wallet owner script is not canonical TRU P2PKH.");return;
        }
        busy(true);
        QPointer<TruDesktopStudio07> self(this);
        wallet_->selectSafeFeeUtxo(kFee+kDust,
          [self,type,tokenID,name,symbol,desc,art,supply,from,ownScript,hash160]
          (QJsonObject utxo,QString e) {
            if(!self)return;
            if(!e.isEmpty()){self->busy(false);QMessageBox::warning(self,"Mint Token",e);return;}
            QJsonObject p{{"type",type},{"tokenID",tokenID},{"name",name},{"symbol",symbol},
              {"description",desc},{"imageUrl",art},{"decimals",(type=="NFT" || type=="NCFT")?0:8},
              {"totalSupply",static_cast<double>(supply)},
              {"senderAddress",from},{"fee",static_cast<int>(kFee)},{"utxo",utxo},
              {"metadataBeforeSigning",true}};
            self->rpc_->call("createtokentransaction",pack(p),
              [self,type,tokenID,name,symbol,supply,from,ownScript,hash160,utxo]
              (const QJsonValue& v,const QByteArray&,const QString& err) {
                if(!self)return;
                if(!err.isEmpty() || !v.isObject()) {self->busy(false);
                    QMessageBox::warning(self,"Mint Token",rawError(err));return;}
                const QJsonObject built=v.toObject();
                const QJsonObject metadata=built.value("metadata").toObject();
                const QJsonObject meta=metadata.value("meta").toObject();
                if(built.value("tokenID").toString()!=tokenID ||
                   metadata.value("tokenID").toString()!=tokenID ||
                   metadata.value("type").toString()!=type ||
                   metadata.value("owner").toString()!=from ||
                   meta.value("name").toString()!=name || meta.value("symbol").toString()!=symbol ||
                   metadata.value("amount").toString()!=QString::number(static_cast<qulonglong>(supply))) {
                    self->busy(false);QMessageBox::critical(self,"Mint Token",
                       "Core's proposed token metadata differs from your chosen identity/supply.");return;
                }
                QJsonObject canonical;
                for(auto it=meta.constBegin();it!=meta.constEnd();++it) {
                    if(it.key()=="metaHash")continue;
                    if(!it.value().isString()) {self->busy(false);
                        QMessageBox::critical(self,"Mint Token","Non-string metadata is not allowed.");return;}
                    canonical.insert(it.key(),it.value());
                }
                const QByteArray hash=QCryptographicHash::hash(
                   QJsonDocument(canonical).toJson(QJsonDocument::Compact),
                   QCryptographicHash::Sha256).toHex();
                QString amountHex=QString::number(static_cast<qulonglong>(supply),16).rightJustified(16,'0');
                const int enumValue=type=="FT"?1:type=="NFT"?2:type=="SFT"?3:4;
                const QString script=QString("6a%1%2%3%4%5")
                     .arg(enumValue,2,16,QChar('0')).arg(tokenID,amountHex,hash160,
                     QString::fromLatin1(hash));
                std::uint64_t input=0;
                if(!digits64(utxo.value("amount_atoms").toString(),input) || input<kFee+kDust){
                    self->busy(false);QMessageBox::critical(self,"Mint Token","Selected UTXO is invalid.");return;}
                QJsonArray approved{output(script,0),output(ownScript,kDust)};
                const auto change=input-kFee-kDust;
                if(change>=kDust)approved.append(output(ownScript,change));
                // CORE 07A must embed exact token metadata before local signing.
                self->submitPrepared("Mint "+type,"issuetokensigned",
                   built.value("unsignedTxHex").toString(),utxo,{approved},
                   QJsonObject{{"attachMetadata",false}},
                   QString("Issue %1 %2 (%3) to your own wallet %4.")
                      .arg(QString::number(static_cast<qulonglong>(supply)),symbol,type,from),true,metadata);
            });
          });
    }
    void inscribe() {
        if(!localReady("Inscribe TRUScript"))return;
        const QString from=wallet_->currentWalletAddress();
        const QString text=inscription_->toPlainText();
        if(text.isEmpty() || text.toUtf8().size()>1024 || text.contains(QChar(0))) {
            QMessageBox::warning(this,"Inscribe TRUScript","Text must contain 1–1024 UTF-8 bytes and no NUL.");return;
        }
        const QString ownScript=wallet_->walletScriptForAddress(from).toLower();
        if(ownScript.isEmpty())return;
        QJsonObject metadata{{"type","TRUSCRIPT"},{"data",text},
             {"owner",from},{"timestamp",static_cast<double>(QDateTime::currentSecsSinceEpoch())}};
        const QByteArray bytes=pack(metadata);
        if(bytes.size()>2048){QMessageBox::warning(this,"Inscribe TRUScript","Inscription metadata exceeds 2 KiB.");return;}
        QString push;
        if(bytes.size()<=75)push=QString::number(bytes.size(),16).rightJustified(2,'0');
        else if(bytes.size()<=255)push="4c"+QString::number(bytes.size(),16).rightJustified(2,'0');
        else push="4d"+QString::number(bytes.size()&255,16).rightJustified(2,'0')+
                            QString::number((bytes.size()>>8)&255,16).rightJustified(2,'0');
        const QString script="6a"+push+QString::fromLatin1(bytes.toHex());
        busy(true);
        QPointer<TruDesktopStudio07> self(this);
        wallet_->selectSafeFeeUtxo(kFee+kDust,[self,script,text,from,ownScript](QJsonObject utxo,QString e){
            if(!self)return;
            if(!e.isEmpty()){self->busy(false);QMessageBox::warning(self,"TRUScript",e);return;}
            std::uint64_t input=0;
            if(!digits64(utxo.value("amount_atoms").toString(),input) || input<kFee+kDust){self->busy(false);return;}
            QJsonObject outputs;
            // Legacy createrawtransaction sorts object keys; inspect both approved orders.
            outputs.insert("data",script);
            outputs.insert(from,decimal(input-kFee));
            QJsonObject p{{"inputs",QJsonArray{QJsonObject{{"txid",utxo.value("txid")},
              {"vout",utxo.value("vout")}}}},{"outputs",outputs}};
            self->rpc_->call("createrawtransaction",pack(p),
              [self,utxo,text,from,ownScript,script,input]
              (const QJsonValue& v,const QByteArray&,const QString& err){
                if(!self)return;
                const QString raw=v.toString();
                if(!err.isEmpty() || raw.isEmpty()){self->busy(false);
                   QMessageBox::warning(self,"TRUScript",rawError(err));return;}
                const QJsonObject dataOut=output(script,0);
                const QJsonObject changeOut=output(ownScript,input-kFee);
                self->submitPrepared("Inscribe TRUScript","inscribeTRUScriptSigned",raw,utxo,
                   {QJsonArray{dataOut,changeOut},QJsonArray{changeOut,dataOut}},
                   QJsonObject{{"inscriptionData",text},{"owner",from},
                   {"requireBoundOpReturn",true}},
                   QString("Inscribe %1 UTF-8 bytes owned by %2.").arg(text.toUtf8().size()).arg(from),false);
              });
        });
    }
    void refreshContracts() {
        if(!rpc_ || !rpc_->endpoint().isValid())return;
        contracts_->setPlainText("Loading authoritative getcontracts response…");
        contractTable_->setRowCount(0);
        visibleContracts_.clear();
        QPointer<TruDesktopStudio07> self(this);
        rpc_->call("getcontracts",pack({}),
          [self](const QJsonValue& v,const QByteArray&,const QString& e){
            if(!self)return;
            if(!e.isEmpty()) {self->contracts_->setPlainText("RPC: "+e);return;}
            if(!v.isObject() || !v.toObject().value("contracts").isArray()) {
                self->contracts_->setPlainText("Malformed getcontracts response");return;
            }
            const auto rows=v.toObject().value("contracts").toArray();
            self->contracts_->setPlainText(
                QString("%1 indexed contracts. Select a row to see full Core registry data.\n"
                        "Native Voting V1 create/cast and standalone lock redemption are not yet enabled.")
                    .arg(rows.size()));
            self->contractTable_->setRowCount(rows.size());
            self->visibleContracts_.clear();
            for(int i=0;i<rows.size();++i){
                const auto c=rows[i].toObject();
                self->visibleContracts_.append(c);
                const QStringList columns{
                    c.value("name").toString("Unnamed Contract"),
                    c.value("type").toString(c.value("contractType").toString("Unknown")),
                    c.value("status").toString(c.value("state").toString("Unknown")),
                    c.value("address").toString(c.value("identifier").toString()),
                    QString::number(c.value("blockHeight").toInt(-1))
                };
                for(int j=0;j<columns.size();++j){
                    auto *item=new QTableWidgetItem(columns[j]);
                    item->setFlags(Qt::ItemIsEnabled|Qt::ItemIsSelectable);
                    self->contractTable_->setItem(i,j,item);
                }
            }
            if(!rows.isEmpty())self->contractTable_->selectRow(0);
          });
    }
    void createContract() {
        if(!localReady("Create Contract"))return;
        const QString family=kind_->currentText();
        const QString name=contractName_->text().trimmed();
        const QString from=wallet_->currentWalletAddress();
        const QString ownScript=wallet_->walletScriptForAddress(from).toLower();
        const QString ownerHash=ownScript.mid(6,40);
        const QString secret=secret_->text();
        std::uint64_t amount=0;
        std::string err;
        if(!asciiSafe(name,35) || !DesktopWalletCore::parseAmount(
                 contractAmount_->text().trimmed().toStdString(),amount,&err) ||
            (family!="OP_RETURN" && amount<kDust) || (family=="OP_RETURN" && amount!=0)) {
            QMessageBox::warning(this,"Create Contract",
                "Use a 1–35-character ASCII name and a valid amount. "
                "OP_RETURN must be zero TRU; locks need at least 546 atoms.");return;
        }
        QString script,display;
        if(family=="HASH LOCK") {
            if(secret.isEmpty() || secret.toUtf8().size()>100) {
              QMessageBox::warning(this,"Hash Lock","Enter a private preimage of at most 100 UTF-8 bytes.");return;}
            const QByteArray pre=secret.toUtf8();
            const QByteArray sha=QCryptographicHash::hash(pre,QCryptographicHash::Sha256);
            unsigned char digest[RIPEMD160_DIGEST_LENGTH];
            RIPEMD160(reinterpret_cast<const unsigned char*>(sha.constData()),sha.size(),digest);
            const QString hash=QString::fromLatin1(QByteArray(reinterpret_cast<const char*>(digest),20).toHex());
            script="a914"+hash+"87";
            display="HASH160: "+hash+"\nSAVE YOUR PREIMAGE SECURELY. It is not stored by this studio.";
        } else if(family=="TIME LOCK") {
            std::uint64_t when=0;
            if(!digits64(lockTime_->text().trimmed(),when) || when<500000000ULL ||
                when>std::numeric_limits<std::uint32_t>::max() || ownerHash.size()!=40){
              QMessageBox::warning(this,"Time Lock","Use a canonical Unix timestamp between 500000000 and 4294967295.");return;}
            const auto ts=static_cast<std::uint32_t>(when);
            QString encoded;
            for(int i=0;i<4;++i)encoded+=QString::number((ts>>(i*8))&255,16).rightJustified(2,'0');
            script="04"+encoded+"b17576a914"+ownerHash+"88ac";
            display="Time-lock Unix timestamp: "+QString::number(static_cast<qulonglong>(when));
        } else if(family=="OP_RETURN") {
            const QByteArray payload=secret.toUtf8();
            if(payload.isEmpty() || payload.size()>60 || !asciiSafe(secret,60)){
                QMessageBox::warning(this,"OP_RETURN","Enter 1–60 printable ASCII bytes.");return;}
            script="6a"+QString::number(payload.size(),16).rightJustified(2,'0')+
                         QString::fromLatin1(payload.toHex());
            display="Public and permanently unspendable data output.";
        } else return;
        if(QMessageBox::warning(this,"EXPERIMENTAL: NO STANDALONE REDEMPTION",
             "The standalone wallet cannot yet redeem these contract outputs. "
             "This can permanently lock your funds. Only proceed with a disposable "
             "dust-sized amount on a test wallet. Continue?",
             QMessageBox::Yes|QMessageBox::No,QMessageBox::No)!=QMessageBox::Yes) return;
        // Do not leak the hash-lock preimage to Core or logs; only the hash goes on chain.
        secret_->clear();
        busy(true);
        QPointer<TruDesktopStudio07> self(this);
        const std::uint64_t minimum=amount>std::numeric_limits<std::uint64_t>::max()-kFee-kDust-1
            ?std::numeric_limits<std::uint64_t>::max():amount+kFee+kDust+1;
        wallet_->selectSafeFeeUtxo(minimum,
          [self,family,name,script,amount,display,from,ownScript](QJsonObject utxo,QString e){
            if(!self)return;
            if(!e.isEmpty()){self->busy(false);QMessageBox::warning(self,"Create Contract",e);return;}
            std::uint64_t input=0;
            if(!digits64(utxo.value("amount_atoms").toString(),input) || input<kFee || amount>input-kFee){
               self->busy(false);QMessageBox::critical(self,"Create Contract","Fee UTXO insufficient.");return;}
            QJsonObject p{{"type",family},{"name",name},{"scriptHex",script},
               {"senderAddress",from},{"amount",static_cast<double>(amount)},
               {"fee",static_cast<int>(kFee)},{"utxo",utxo}};
            // JSON doubles are exact only through 2^53; fail instead of rounding.
            if(amount>9007199254740991ULL){self->busy(false);
                QMessageBox::critical(self,"Create Contract","Amount exceeds exact JSON integer range.");return;}
            self->rpc_->call("createcontracttransaction",pack(p),
              [self,family,name,script,amount,display,from,ownScript,input,utxo]
              (const QJsonValue& v,const QByteArray&,const QString& err){
                 if(!self)return;
                 if(!err.isEmpty() || !v.isObject()){
                     self->busy(false);QMessageBox::warning(self,"Create Contract",rawError(err));return;}
                 const QJsonObject built=v.toObject();
                 const QByteArray note=("TRU_CONTRACT:"+name).toUtf8();
                 if(note.size()>75){self->busy(false);return;}
                 const QString marker="6a"+QString::number(note.size(),16).rightJustified(2,'0')+
                                            QString::fromLatin1(note.toHex());
                 QJsonArray outputs{output(marker,0),output(script,amount)};
                 const std::uint64_t change=input-amount-kFee;
                 if(change>kDust)outputs.append(output(ownScript,change));
                 self->submitPrepared("Create "+family,"sendrawtransaction",
                   built.value("unsignedTxHex").toString(),utxo,{outputs},
                   QJsonObject{},QString("Create %1 '%2' to %3.\n%4")
                      .arg(family,name,from,display),false);
              });
          });
    }
public:
    explicit TruDesktopStudio07(DesktopRpc* rpc,DesktopWalletWidget* wallet,QWidget* parent=nullptr)
      :QWidget(parent),rpc_(rpc),wallet_(wallet) {
        auto* root=new QVBoxLayout(this);
        auto* headline=new QLabel("TRU / CREATOR STUDIO  ·  v0.07 ALPHA");
        headline->setObjectName("truAssetTitle");root->addWidget(headline);
        notice_=new QLabel("All writes require LOCAL CORE and an unlocked STANDALONE WALLET. "
            "Keys stay inside the desktop wallet. Review each transaction before broadcast.");
        notice_->setWordWrap(true);root->addWidget(notice_);
        auto* tabs=new QTabWidget;root->addWidget(tabs,1);
        // Mint FT / NFT / SFT / NCFT
        auto* tokens=new QWidget;auto* tf=new QFormLayout(tokens);
        type_=new QComboBox;type_->addItems({"FT","NFT","SFT","NCFT"});tf->addRow("TOKEN CLASS",type_);
        tid_=new QLineEdit;auto* regen=new QPushButton("Generate 16-hex ID");
        auto* idRow=new QHBoxLayout;idRow->addWidget(tid_,1);idRow->addWidget(regen);tf->addRow("Token ID",idRow);
        QObject::connect(regen,&QPushButton::clicked,this,[this]{
          const auto bytes=QRandomGenerator::system()->generate64();
          tid_->setText(QString::number(static_cast<qulonglong>(bytes),16).rightJustified(16,'0'));
        });
        name_=new QLineEdit;name_->setMaxLength(64);tf->addRow("Name",name_);
        symbol_=new QLineEdit;symbol_->setMaxLength(16);tf->addRow("Symbol",symbol_);
        supply_=new QLineEdit("1");tf->addRow("Supply (integer units)",supply_);
        desc_=new QLineEdit;desc_->setMaxLength(200);tf->addRow("Description",desc_);
        image_=new QLineEdit;image_->setPlaceholderText("https://... (optional)");tf->addRow("HTTPS artwork URL",image_);
        mint_=new QPushButton("REVIEW & MINT TOKEN");tf->addRow(mint_);
        auto* tnote=new QLabel("NCFT/SFT issuance does not automatically delegate editing. "
            "Use the issuer authorization workflow for future artwork changes.");tnote->setWordWrap(true);tf->addRow(tnote);
        tabs->addTab(tokens,"Mint FT / NFT / SFT / NCFT");
        QObject::connect(mint_,&QPushButton::clicked,this,[this]{issueToken();});
        QObject::connect(type_,&QComboBox::currentTextChanged,this,[this](const QString& t){
            if(t=="NFT")supply_->setText("1");});
        // Inscription
        auto* scripts=new QWidget;auto* sl=new QVBoxLayout(scripts);
        auto* scriptInfo=new QLabel("TRUScript inscription is irreversible. The exact UTF-8 text is public. "
            "Only the local standalone wallet signs the selected fee UTXO.");
        scriptInfo->setWordWrap(true);sl->addWidget(scriptInfo);
        inscription_=new QPlainTextEdit;inscription_->setPlaceholderText("Text or public JSON (1–1024 bytes)");
        sl->addWidget(inscription_,1);
        inscribe_=new QPushButton("REVIEW & INSCRIBE");sl->addWidget(inscribe_);
        QObject::connect(inscribe_,&QPushButton::clicked,this,[this]{inscribe();});
        tabs->addTab(scripts,"Inscribe TRUScript");
        // Contract creation intentionally limited to canonical non-stateful families.
        auto* create=new QWidget;auto* cf=new QFormLayout(create);
        kind_=new QComboBox;kind_->addItems({"HASH LOCK","TIME LOCK","OP_RETURN"});cf->addRow("Contract family",kind_);
        contractName_=new QLineEdit;contractName_->setMaxLength(35);cf->addRow("Contract name",contractName_);
        contractAmount_=new QLineEdit("0.001");cf->addRow("Locked amount (TRU)",contractAmount_);
        secret_=new QLineEdit;secret_->setEchoMode(QLineEdit::Password);
        cf->addRow("Hash preimage / public data",secret_);
        lockTime_=new QLineEdit;lockTime_->setPlaceholderText("Unix timestamp ≥ 500000000");cf->addRow("Time-lock timestamp",lockTime_);
        auto* warning=new QLabel("Hash-lock preimages are shown only in this field and not saved. "
          "This standalone wallet cannot yet redeem a contract output: do not lock meaningful funds "
          "until the separately signed redemption builder is deployed and tested.");
        warning->setWordWrap(true);cf->addRow(warning);
        contractCreate_=new QPushButton("REVIEW & CREATE CONTRACT (EXPERIMENTAL)");
        const bool allowLocks=(qgetenv("TRU_DESKTOP_07_EXPERIMENTAL_LOCK_CREATE")=="1");
        contractCreate_->setEnabled(allowLocks);
        contractCreate_->setToolTip(allowLocks ? "Disposable test wallet only" :
            "Disabled until independent contract redemption is available. "
            "For disposable developer-only testing set "
            "TRU_DESKTOP_07_EXPERIMENTAL_LOCK_CREATE=1 before starting desktop.");
        cf->addRow(contractCreate_);
        QObject::connect(contractCreate_,&QPushButton::clicked,this,[this]{createContract();});
        tabs->addTab(create,"Hash / Time / Data Contracts");
        // Everyone can inspect all currently indexed families through getcontracts.
        auto* inspect=new QWidget;auto* il=new QVBoxLayout(inspect);
        auto* intro=new QLabel("Shows ALL indexed contract families (including Voting V1, "
           "stateful K/V, token issuer, oracle, multisig and HTLC) as reported by Core. "
           "This release does not build native Voting V1 state transactions or "
           "sign a contract-spend script. Those actions remain in the full Core CLI "
           "until independent standalone signing is implemented.");
        intro->setWordWrap(true);il->addWidget(intro);
        auto* refresh=new QPushButton("REFRESH CONTRACT VAULT");il->addWidget(refresh);
        contractTable_=new QTableWidget;
        contractTable_->setColumnCount(5);
        contractTable_->setHorizontalHeaderLabels({"CONTRACT","TYPE","STATUS","ROOT / ADDRESS","BLOCK"});
        contractTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
        contractTable_->setSelectionMode(QAbstractItemView::SingleSelection);
        contractTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        contractTable_->verticalHeader()->setVisible(false);
        contractTable_->horizontalHeader()->setStretchLastSection(false);
        contractTable_->horizontalHeader()->setSectionResizeMode(0,QHeaderView::Stretch);
        contractTable_->horizontalHeader()->setSectionResizeMode(3,QHeaderView::Stretch);
        il->addWidget(contractTable_,2);
        contracts_=new QPlainTextEdit;contracts_->setReadOnly(true);il->addWidget(contracts_,1);
        QObject::connect(contractTable_,&QTableWidget::itemSelectionChanged,this,[this]{
            const int index=contractTable_->currentRow();
            if(index<0 || index>=visibleContracts_.size())return;
            contracts_->setPlainText(QString::fromUtf8(
               QJsonDocument(visibleContracts_[index]).toJson(QJsonDocument::Indented)));
        });
        QObject::connect(refresh,&QPushButton::clicked,this,[this]{refreshContracts();});
        tabs->addTab(inspect,"All Contracts / Voting (Inspect)");
    }
};
