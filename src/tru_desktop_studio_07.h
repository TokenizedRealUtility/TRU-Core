#pragma once
// TRU-DESKTOP-07A: self-custody creation studio. Header-only Qt widget:
// existing Qt5/Qt6 desktop build manifests do not need a new .cpp target.
// Write workflows require local Core and local standalone wallet signatures.
#include "desktop_rpc.h"
#include "desktop_wallet_widget.h"
#include "desktop_wallet_core.h"
#include "contract_call_policy.h"  // strict canonical V1 creation + calldata
#include "contract_call_envelope.h"
#include <QComboBox>
#include <QCryptographicHash>
#include <QDateTime>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QGroupBox>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QList>
#include <QLineEdit>
#include <QTimer>
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
#include <vector>
#include <algorithm>

class TruDesktopStudio07 final:public QWidget {
    DesktopRpc* rpc_;
    DesktopWalletWidget* wallet_;
    QComboBox *type_=nullptr,*kind_=nullptr;
    QLineEdit *tid_=nullptr,*name_=nullptr,*symbol_=nullptr,*supply_=nullptr,*desc_=nullptr,*image_=nullptr;
    QPlainTextEdit *inscription_=nullptr,*contracts_=nullptr;
    QTableWidget *contractTable_=nullptr;
    QList<QJsonObject> visibleContracts_;
    QLineEdit *contractName_=nullptr,*secret_=nullptr,*lockTime_=nullptr,*contractAmount_=nullptr;
    QLineEdit *redeemRoot_=nullptr,*redeemSecret_=nullptr;
    QComboBox *redeemKind_=nullptr,*voteChoice_=nullptr;
    QLineEdit *proposalName_=nullptr,*proposal_=nullptr,*proposalEnd_=nullptr,*proposalAmount_=nullptr,*votingRoot_=nullptr;
    QPlainTextEdit *proposalOptions_=nullptr,*votingInfo_=nullptr;
    QPushButton *voteCreate_=nullptr,*voteRefresh_=nullptr,*voteCast_=nullptr;
    QJsonObject loadedVote_;
    QLabel *notice_=nullptr;
    QPushButton *mint_=nullptr,*inscribe_=nullptr,*contractCreate_=nullptr,*redeemBtn_=nullptr;
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
        if(redeemBtn_)redeemBtn_->setDisabled(yes);
        if(voteCreate_)voteCreate_->setDisabled(yes);
        if(voteCast_)voteCast_->setDisabled(yes);
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
                        "Native Voting V1 create/cast and canonical hash/time redemption are on separate tabs.")
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
    static std::vector<unsigned char> votingBytes(const QString& q){
        const auto b=q.toUtf8();return {b.constData(),b.constData()+b.size()};
    }
    static QString votingHex(const std::vector<unsigned char>& v){
        return QString::fromLatin1(QByteArray(reinterpret_cast<const char*>(v.data()),
            static_cast<int>(v.size())).toHex());
    }
    static std::vector<unsigned char> votingLE64(std::uint64_t n){
        std::vector<unsigned char> b(8,0);
        for(unsigned i=0;i<8;++i)b[i]=static_cast<unsigned char>((n>>(8*i))&255U);
        return b;
    }
    static QString votingInitHex(const QString& proposal,
            const QStringList& options,std::uint32_t endTime){
        tru_contract_state_init::StateInitEnvelope init;init.targetVout=1;
        init.entries.emplace_back("proposal",votingBytes(proposal));
        init.entries.emplace_back("numoptions",std::vector<unsigned char>{
            static_cast<unsigned char>(options.size())});
        init.entries.emplace_back("endtime",votingLE64(endTime));
        const auto zero=votingLE64(0);
        for(int i=0;i<options.size();++i){
            init.entries.emplace_back("option"+std::to_string(i),votingBytes(options[i]));
            init.entries.emplace_back("count"+std::to_string(i),zero);
        }
        init.entries.emplace_back("totalvotes",zero);
        std::sort(init.entries.begin(),init.entries.end(),
            [](const auto& a,const auto& b){return a.first<b.first;});
        std::string why;
        if(!tru_contract_call::IsCanonicalVotingV1InitEnvelope(init,why))
            throw std::runtime_error("invalid canonical Voting V1 init: "+why);
        std::vector<unsigned char> out;
        if(!tru_contract_state_init::BuildOpReturnScript(init,out))
            throw std::runtime_error("cannot encode TRUSTATE");
        return votingHex(out);
    }
    static QString votingUnlockHex(int choice,std::uint64_t count){
        if(choice<0 || choice>9 || count==std::numeric_limits<uint64_t>::max())
            throw std::runtime_error("invalid Voting V1 count/choice");
        std::vector<unsigned char> unlock;
        if(!tru_contract_call::BuildStatefulKvV1UnlockScript(
            "count"+std::to_string(choice),votingLE64(count+1),unlock))
            throw std::runtime_error("cannot encode canonical V1 ballot");
        return votingHex(unlock);
    }
    static QString votingCallHex(const QString& unlockHex){
        const auto raw=QByteArray::fromHex(unlockHex.toLatin1());
        const std::vector<unsigned char> unlock(raw.begin(),raw.end());
        tru_contract_call_envelope::StateCallEnvelope env;
        if(!tru_contract_call::ComputeUnlockScriptSha256(unlock,env.unlockScriptSha256))
            throw std::runtime_error("cannot hash canonical V1 ballot");
        std::vector<unsigned char> call;
        if(!tru_contract_call_envelope::BuildOpReturnScript(env,call))
            throw std::runtime_error("cannot encode TRUCALL commitment");
        return votingHex(call);
    }
    void createVotingProposal(){
        if(!localReady("Create Voting V1"))return;
        const QString name=proposalName_->text().trimmed();
        const QString title=proposal_->text().trimmed();
        const auto opts=proposalOptions_->toPlainText().split('\n',Qt::KeepEmptyParts);
        QStringList options;
        for(const auto& text:opts){const auto opt=text.trimmed();if(!opt.isEmpty())options<<opt;}
        std::uint64_t end=0,amount=0;
        std::string amountWhy;
        if(!asciiSafe(name,35) || !asciiSafe(title,200) || options.size()<2 || options.size()>10 ||
           !digits64(proposalEnd_->text().trimmed(),end) || end<=static_cast<uint64_t>(QDateTime::currentSecsSinceEpoch()) ||
           end>4294967295ULL ||
           !DesktopWalletCore::parseAmount(proposalAmount_->text().trimmed().toStdString(),amount,&amountWhy) ||
           amount<kDust || amount>9007199254740991ULL){
            QMessageBox::warning(this,"Voting V1","Use ASCII name/proposal, 2–10 options, future Unix end time and valid anchor amount.");return;}
        for(const auto& option:options)if(!asciiSafe(option,50)){
            QMessageBox::warning(this,"Voting V1","Each option must be 1–50 printable ASCII bytes.");return;}
        const QString from=wallet_->currentWalletAddress();
        const QString owner=wallet_->walletScriptForAddress(from).toLower();
        QString initHex;
        try {initHex=votingInitHex(title,options,static_cast<std::uint32_t>(end));}
        catch(const std::exception& ex){QMessageBox::warning(this,"Voting V1",ex.what());return;}
        busy(true);
        QPointer<TruDesktopStudio07> self(this);
        // Require >dust change; the exact-amount fee audit rejects dust-burn ambiguity.
        wallet_->selectSafeFeeUtxo(amount+kFee+kDust+1,
          [self,name,title,options,end,amount,from,owner,initHex](QJsonObject utxo,QString e){
            if(!self)return;
            if(!e.isEmpty()){self->busy(false);QMessageBox::warning(self,"Voting V1",e);return;}
            std::uint64_t in=0;
            if(!digits64(utxo.value("amount_atoms").toString(),in) || in<amount+kFee){
                self->busy(false);QMessageBox::warning(self,"Voting V1","Insufficient fee UTXO");return;}
            QJsonArray choices;for(const auto& opt:options)choices.append(opt);
            QJsonObject p{{"name",name},{"proposal",title},{"options",choices},
                {"endTime",static_cast<double>(end)},
                {"amount_atoms",QString::number(static_cast<qulonglong>(amount))},
                {"senderAddress",from},{"utxo",utxo}};
            self->rpc_->call("preparevotingv1create07b",pack(p),
              [self,name,title,options,amount,in,owner,initHex,utxo]
              (const QJsonValue& v,const QByteArray&,const QString& err){
                if(!self)return;
                if(!err.isEmpty() || !v.isObject()){
                    self->busy(false);QMessageBox::warning(self,"Voting V1",rawError(err));return;}
                const QJsonObject built=v.toObject();
                if(built.value("initScriptHex").toString()!=initHex){
                    self->busy(false);QMessageBox::critical(self,"Voting V1","Core returned unexpected TRUSTATE init");return;}
                const auto note=("TRU_CONTRACT:"+name).toUtf8();
                if(note.size()>75){self->busy(false);return;}
                const QString marker="6a"+QString::number(note.size(),16).rightJustified(2,'0')+
                                     QString::fromLatin1(note.toHex());
                QJsonArray outputs{output(marker,0),output("f751",amount),output(initHex,0)};
                const auto change=in-amount-kFee;
                if(change>kDust)outputs.append(output(owner,change));
                if(built.value("anchor_atoms").toString()!=QString::number(static_cast<qulonglong>(amount))){
                    self->busy(false);QMessageBox::critical(self,"Voting V1","Wrong anchor amount");return;}
                self->submitPrepared("Create Voting V1","sendrawtransaction",
                    built.value("unsignedTxHex").toString(),utxo,{outputs},QJsonObject{},
                    QString("Proposal: %1\nOptions: %2\nVoting root after confirmation: TXID:1\n"
                        "Creates canonical f751 + TRUSTATE anchor. One vote per address, not per person.")
                        .arg(title,options.join(" | ")),false);
              });
          });
    }
    void refreshVoting(){
        if(!rpc_ || !rpc_->endpoint().isValid())return;
        const QString root=votingRoot_->text().trimmed();
        if(!QRegularExpression("^[0-9a-f]{64}:[0-9]{1,10}$").match(root).hasMatch()){
            QMessageBox::warning(this,"Voting V1","Provide a confirmed root txid:1");return;}
        votingInfo_->setPlainText("Loading confirmed Voting V1 state…");
        loadedVote_={};voteChoice_->clear();
        QPointer<TruDesktopStudio07> self(this);
        const auto voter=wallet_->currentWalletAddress();
        QJsonObject p{{"root",root}};
        if(!voter.isEmpty())p.insert("voterAddress",voter);
        rpc_->call("getvotingv1snapshot07b",pack(p),
          [self,root](const QJsonValue& v,const QByteArray&,const QString& err){
            if(!self)return;
            if(!err.isEmpty() || !v.isObject()){
                self->votingInfo_->setPlainText(rawError(err));return;}
            const auto snap=v.toObject();
            if(snap.value("root").toString()!=root || !snap.value("options").isArray() ||
               !snap.value("counts").isArray() ||
                snap.value("options").toArray().size()!=snap.value("counts").toArray().size()){
                self->votingInfo_->setPlainText("Malformed confirmed Voting V1 snapshot");return;}
            self->loadedVote_=snap;
            QStringList lines{"Proposal: "+snap.value("proposal").toString(),
              "Root: "+root,"Live anchor: "+snap.value("live").toString(),
              "Voting ends (Unix): "+snap.value("endTime").toString(),
              "Total votes: "+snap.value("totalVotes").toString(),
              "This address voted: "+QString(snap.value("alreadyVoted").toBool(false)?"YES":"NO"),"\nChoices:"};
            const auto opts=snap.value("options").toArray(),counts=snap.value("counts").toArray();
            for(int i=0;i<opts.size();++i){
                lines<<QString("%1) %2 — %3 vote(s)").arg(i).arg(opts[i].toString(),counts[i].toString());
                self->voteChoice_->addItem(QString("%1 — %2").arg(i).arg(opts[i].toString()),i);
            }
            self->votingInfo_->setPlainText(lines.join("\n"));
          });
    }
    void castVotingBallot(){
        if(!localReady("Cast Voting V1 ballot"))return;
        const QString root=votingRoot_->text().trimmed();
        const auto snapshot=loadedVote_;
        bool choiceOk=false;
        const int choice=voteChoice_->currentData().toInt(&choiceOk);
        if(snapshot.isEmpty() || snapshot.value("root").toString()!=root ||
           snapshot.value("alreadyVoted").toBool(true) || !choiceOk || choice<0 ||
           choice>=snapshot.value("counts").toArray().size()){
            QMessageBox::warning(this,"Voting V1","Refresh the confirmed vote. Already-voted addresses cannot vote twice.");return;}
        std::uint64_t end=0,current=0,anchor=0;
        if(!digits64(snapshot.value("endTime").toString(),end) ||
           end<=static_cast<uint64_t>(QDateTime::currentSecsSinceEpoch()) ||
           !digits64(snapshot.value("counts").toArray()[choice].toString(),current) ||
           !digits64(snapshot.value("anchor_atoms").toString(),anchor)){
            QMessageBox::warning(this,"Voting V1","Invalid or expired confirmed voting state");return;}
        QString unlock,call;
        try {unlock=votingUnlockHex(choice,current);call=votingCallHex(unlock);}
        catch(const std::exception& ex){QMessageBox::warning(this,"Voting V1",ex.what());return;}
        const auto addr=wallet_->currentWalletAddress();
        busy(true);QPointer<TruDesktopStudio07> self(this);
        wallet_->selectSafeFeeUtxo(kFee+kDust,
          [self,root,choice,addr,anchor,snapshot,unlock,call]
          (QJsonObject utxo,QString e){
            if(!self)return;
            if(!e.isEmpty()){self->busy(false);QMessageBox::warning(self,"Voting V1",e);return;}
            QJsonObject p{{"root",root},{"choice",choice},{"senderAddress",addr},{"utxo",utxo}};
            self->rpc_->call("preparevotingv1ballot07b",pack(p),
              [self,root,choice,addr,anchor,snapshot,unlock,call,utxo]
              (const QJsonValue& v,const QByteArray&,const QString& err){
                if(!self)return;
                if(!err.isEmpty() || !v.isObject()){
                    self->busy(false);QMessageBox::warning(self,"Voting V1",rawError(err));return;}
                const auto b=v.toObject();
                if(b.value("root").toString()!=root ||
                   b.value("live").toString()!=snapshot.value("live").toString() ||
                   b.value("unlockScriptHex").toString()!=unlock ||
                   b.value("callScriptHex").toString()!=call ||
                   b.value("anchorScriptHex").toString()!="f751" ||
                   b.value("anchor_atoms").toString()!=snapshot.value("anchor_atoms").toString() ||
                   b.value("choice").toInt(-1)!=choice ||
                   b.value("previous_count").toString()!=snapshot.value("counts").toArray()[choice].toString()){
                    self->busy(false);QMessageBox::critical(self,"Voting V1","Confirmed snapshot changed or ballot differs; refresh and try again");return;}
                QString signedHex,txid,error;
                if(!self->wallet_->signVotingV1Ballot(
                    b.value("unsignedTxHex").toString(),utxo,
                    snapshot.value("live").toString(),
                    snapshot.value("anchor_atoms").toString(),unlock,call,
                    signedHex,txid,error)){
                    self->busy(false);QMessageBox::warning(self,"Voting V1",error);return;}
                if(QMessageBox::question(self,"CONFIRM VOTE",
                    QString("Proposal: %1\nChoice: %2\nVoter: %3\nVoting root: %4\nFee: 10000 atoms\nTXID: %5\n\n"
                      "Cast one irreversible vote from your standalone wallet?")
                      .arg(snapshot.value("proposal").toString(),
                           snapshot.value("options").toArray()[choice].toString(),
                           addr,root,txid),
                    QMessageBox::Yes|QMessageBox::No,QMessageBox::No)!=QMessageBox::Yes){
                    self->busy(false);return;}
                self->rpc_->call("sendrawtransaction",pack(QJsonObject{{"txHex",signedHex}}),
                  [self,txid](const QJsonValue& r,const QByteArray&,const QString& err2){
                    if(!self)return;self->busy(false);self->loadedVote_={};
                    if(!err2.isEmpty() || r.isNull())
                        QMessageBox::warning(self,"Vote submission uncertain",
                          rawError(err2)+"\nCheck the mempool before retrying: "+txid);
                    else QMessageBox::information(self,"Vote submitted",
                        "Await confirmation before refreshing results. TXID: "+txid);
                  });
              });
          });
    }

    // 07B: redeem using THIS standalone wallet, never Core's private keys.
    void redeemContract() {
        if(!localReady("Redeem Contract"))return;
        const QString root=redeemRoot_->text().trimmed();
        const QRegularExpression canonical("^([0-9a-f]{64}):([0-9]{1,10})$");
        const auto match=canonical.match(root);
        if(!match.hasMatch()) {QMessageBox::warning(this,"Redeem","Use canonical lowercase txid:vout");return;}
        bool voutOk=false;
        const auto n=match.captured(2).toULongLong(&voutOk);
        if(!voutOk || n>static_cast<qulonglong>(std::numeric_limits<int>::max())){QMessageBox::warning(this,"Redeem","vout overflow");return;}
        const QString family=redeemKind_->currentText();
        QString preimage=redeemSecret_->text();
        redeemSecret_->clear();
        if(family=="HASH LOCK" && (preimage.isEmpty() || preimage.toUtf8().size()>100)){
            QMessageBox::warning(this,"Redeem","Enter the 1–100-byte private preimage.");return;}
        if(family=="TIME LOCK" && !preimage.isEmpty()){
            QMessageBox::warning(this,"Redeem","Time Lock redemption never needs a preimage.");return;}
        const QString destination=wallet_->currentWalletAddress();
        if(destination.isEmpty()){QMessageBox::warning(this,"Redeem","Wallet destination is missing");return;}
        busy(true);
        QPointer<TruDesktopStudio07> self(this);
        rpc_->call("getcontractoutpoint07b",pack(QJsonObject{
           {"txid",match.captured(1)},{"vout",static_cast<int>(n)}}),
          [self,family,preimage,destination,root]
          (const QJsonValue& v,const QByteArray&,const QString& e){
            if(!self)return;
            if(!e.isEmpty() || !v.isObject()){
                self->busy(false);QMessageBox::warning(self,"Redeem",rawError(e));return;}
            const QJsonObject confirmed=v.toObject();
            if(confirmed.value("txid").toString()+":"+
              QString::number(confirmed.value("vout").toInt(-1))!=root){
                self->busy(false);QMessageBox::critical(self,"Redeem","Core returned another outpoint");return;}
            const QString amount=confirmed.value("amount_atoms").toString();
            QString signedHex,txid,error;
            if(!self->wallet_->signContractRedemption(confirmed,family,preimage,
                 destination,signedHex,txid,error)){
                self->busy(false);QMessageBox::warning(self,"Redeem",error);return;}
            if(QMessageBox::question(self,"CONFIRM REDEMPTION",
                "Contract: "+root+"\nType: "+family+"\nInput: "+amount+
                " atoms\nNetwork fee: 10000 atoms\nRedeem to: "+destination+
                "\n\nTXID: "+txid+"\n\nBroadcast signed redemption?",
                QMessageBox::Yes|QMessageBox::No,QMessageBox::No)!=QMessageBox::Yes){
                self->busy(false);return;}
            self->rpc_->call("sendrawtransaction",pack(QJsonObject{{"txHex",signedHex}}),
             [self,txid](const QJsonValue& result,const QByteArray&,const QString& error){
                if(!self)return;self->busy(false);
                if(!error.isEmpty() || result.isNull())
                    QMessageBox::warning(self,"Redemption uncertain",
                        rawError(error)+"\nCheck txid/mempool before retrying: "+txid);
                else QMessageBox::information(self,"Redemption submitted",
                    "Wait for confirmation. TXID: "+txid);
             });
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
        if(QMessageBox::warning(this,"07B BETA — UNVERIFIED LIVE REDEMPTION",
             "Canonical standalone hash/time redemption now has a local signer, "
             "but live chain success has not been verified. Lost hash preimages "
             "or time-lock signing keys can permanently lock funds. "
             "Only proceed with a disposable wallet and dust-sized test amount. Continue?",
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
        auto* headline=new QLabel("TRU / CREATOR STUDIO  ·  v0.07B TEST");
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
        // Contract creation: canonical non-stateful families only. Voting V1 below.
        auto* create=new QWidget;auto* cf=new QFormLayout(create);
        kind_=new QComboBox;kind_->addItems({"HASH LOCK","TIME LOCK","OP_RETURN"});cf->addRow("Contract family",kind_);
        contractName_=new QLineEdit;contractName_->setMaxLength(35);cf->addRow("Contract name",contractName_);
        contractAmount_=new QLineEdit("0.001");cf->addRow("Locked amount (TRU)",contractAmount_);
        secret_=new QLineEdit;secret_->setEchoMode(QLineEdit::Password);
        cf->addRow("Hash preimage / public data",secret_);
        lockTime_=new QLineEdit;lockTime_->setPlaceholderText("Unix timestamp ≥ 500000000");cf->addRow("Time-lock timestamp",lockTime_);
        auto* warning=new QLabel("Hash-lock preimages are shown only in this field and not saved. "
          "07B can sign canonical hash/time redemption locally. Both "
          "creation and redemption are TEST-ONLY until validated end-to-end.");
        warning->setWordWrap(true);cf->addRow(warning);
        contractCreate_=new QPushButton("REVIEW & CREATE CONTRACT (EXPERIMENTAL)");
        const bool allowLocks=(qgetenv("TRU_DESKTOP_07_EXPERIMENTAL_LOCK_CREATE")=="1");
        contractCreate_->setEnabled(allowLocks);
        contractCreate_->setToolTip(allowLocks ? "Disposable test wallet only" :
            "Disabled until operator explicitly enables 07B beta. "
            "For disposable developer-only testing set "
            "TRU_DESKTOP_07_EXPERIMENTAL_LOCK_CREATE=1 before starting desktop.");
        cf->addRow(contractCreate_);
        QObject::connect(contractCreate_,&QPushButton::clicked,this,[this]{createContract();});
        tabs->addTab(create,"Hash / Time / Data Contracts");
        // The lock outputs are standard Core V1 scripts. The only wallet spend
        // path exposed here is strict canonical hash/time redemption.
        auto* redeemPage=new QWidget;
        auto* rf=new QFormLayout(redeemPage);
        redeemKind_=new QComboBox;redeemKind_->addItems({"HASH LOCK","TIME LOCK"});
        rf->addRow("Redemption family",redeemKind_);
        redeemRoot_=new QLineEdit;redeemRoot_->setPlaceholderText("64hex-txid:1");
        rf->addRow("Confirmed output",redeemRoot_);
        redeemSecret_=new QLineEdit;redeemSecret_->setEchoMode(QLineEdit::Password);
        rf->addRow("Private preimage (hash only)",redeemSecret_);
        auto* redeemNote=new QLabel(
            "Local Core supplies the unspent output and parent-chain MTP. "
            "The standalone wallet checks the exact locking script, verifies "
            "the hash/preimage or owned CLTV key, then signs locally. "
            "A hash-lock preimage is published on redemption: anyone who learns "
            "it before confirmation may race to redeem to another address. "
            "Only redeem to your own address during testing.");
        redeemNote->setWordWrap(true);rf->addRow(redeemNote);
        redeemBtn_=new QPushButton("VERIFY, SIGN LOCALLY & REDEEM");rf->addRow(redeemBtn_);
        QObject::connect(redeemBtn_,&QPushButton::clicked,this,[this]{redeemContract();});
        tabs->addTab(redeemPage,"Unlock / Redeem");
        // Everyone can inspect all currently indexed families through getcontracts.
        auto* inspect=new QWidget;auto* il=new QVBoxLayout(inspect);
        auto* intro=new QLabel("Shows ALL indexed contract families (including Voting V1, "
           "stateful K/V, token issuer, oracle, multisig and HTLC) as reported by Core. "
           "Native Voting V1 create/cast and canonical Hash/Time redemption "
           "are available on their dedicated beta tabs. Other stateful families "
           "are inspect-only until dedicated standalone signing is implemented.");
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
        // Native Voting V1 creation and signed ballot voting (not token-gated).
        auto* vp=new QWidget;auto* vv=new QVBoxLayout(vp);
        auto* vCreate=new QGroupBox("CREATE A NATIVE VOTING V1 PROPOSAL");
        auto* vc=new QFormLayout(vCreate);
        proposalName_=new QLineEdit;proposalName_->setMaxLength(35);
        vc->addRow("Contract name (ASCII)",proposalName_);
        proposal_=new QLineEdit;proposal_->setMaxLength(200);
        vc->addRow("Question (ASCII)",proposal_);
        proposalOptions_=new QPlainTextEdit;
        proposalOptions_->setPlaceholderText("One option per line, 2–10 options (50 bytes each)");
        proposalOptions_->setMaximumHeight(110);
        vc->addRow("Options",proposalOptions_);
        proposalEnd_=new QLineEdit;
        proposalEnd_->setPlaceholderText("Unix timestamp in the future");
        vc->addRow("Voting deadline",proposalEnd_);
        proposalAmount_=new QLineEdit("0.001");
        vc->addRow("Anchor amount TRU",proposalAmount_);
        voteCreate_=new QPushButton("REVIEW & CREATE VOTING V1");
        vc->addRow(voteCreate_);
        QObject::connect(voteCreate_,&QPushButton::clicked,this,[this]{createVotingProposal();});
        vv->addWidget(vCreate);
        auto* vCast=new QGroupBox("VIEW RESULTS / CAST ONE SIGNED VOTE");
        auto* vf=new QFormLayout(vCast);
        votingRoot_=new QLineEdit;
        votingRoot_->setPlaceholderText("Confirmed creation txid:1");
        vf->addRow("Voting root",votingRoot_);
        voteRefresh_=new QPushButton("LOAD CONFIRMED VOTE & RESULTS");
        vf->addRow(voteRefresh_);
        votingInfo_=new QPlainTextEdit;votingInfo_->setReadOnly(true);
        votingInfo_->setMaximumHeight(180);
        vf->addRow(votingInfo_);
        voteChoice_=new QComboBox;
        vf->addRow("Choice",voteChoice_);
        voteCast_=new QPushButton("REVIEW, SIGN & CAST BALLOT");
        vf->addRow(voteCast_);
        QObject::connect(voteRefresh_,&QPushButton::clicked,this,[this]{refreshVoting();});
        QObject::connect(voteCast_,&QPushButton::clicked,this,[this]{castVotingBallot();});
        auto* vDisclaimer=new QLabel("Voting V1 is one vote per P2PKH address; it is NOT RANDY-token-gated. "
          "Your wallet signs the fee input locally; votes spend/recreate the confirmed f751 live anchor. "
          "Two voters targeting the same live anchor can race; refresh after each confirmed ballot.");
        vDisclaimer->setWordWrap(true);
        vv->addWidget(vCast);vv->addWidget(vDisclaimer);
        tabs->addTab(vp,"Voting V1");
    }
};
