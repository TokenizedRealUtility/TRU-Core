#pragma once
#include "magic_secret_v2.h"
#include "desktop_rpc.h"
#include "desktop_wallet_widget.h"
#include <QCheckBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPointer>
#include <QProgressBar>
#include <QPushButton>
#include <QSpinBox>
#include <QTimer>
#include <QVBoxLayout>
#include <atomic>
#include <memory>
#include <mutex>
#include <thread>

// Header-only so existing standalone and embedded desktop targets need no source-list edits.
class TruMagicSecretWidgetV2 final:public QWidget {
 struct Job {std::atomic<bool> cancel{false},done{false};std::mutex mutex;tru_magic_v2::Progress progress{0,0,"",false};std::string result,error;bool creating=false;};
 DesktopRpc* rpc_;DesktopWalletWidget* wallet_;
 QPlainTextEdit *text_,*output_;QLineEdit *code_,*txid_;QSpinBox *bits_,*vout_;
 QLabel *status_,*work_;QProgressBar* bar_;QCheckBox *saved_,*reveal_;
 QPushButton *create_,*publish_,*open_,*cancel_,*clear_;
 QTimer timer_;std::thread thread_;std::shared_ptr<Job> job_;QString ready_,chainState_;bool busy_=false;
 static QByteArray pack(const QJsonObject& o){return QJsonDocument(o).toJson(QJsonDocument::Compact);}
 static QJsonObject out(const QString& script,quint64 atoms){return {{"scriptPubKey",script},{"amount_atoms",QString::number(atoms)}};}
 void busy(bool value){busy_=value;create_->setDisabled(value);open_->setDisabled(value);clear_->setDisabled(value);text_->setDisabled(value);code_->setDisabled(value);bits_->setDisabled(value);txid_->setDisabled(value);vout_->setDisabled(value);publish_->setEnabled(!value&&!ready_.isEmpty()&&saved_->isChecked());cancel_->setEnabled(value&&bool(job_));bar_->setRange(0,value?0:1);bar_->setValue(value?0:1);}
 void invalidate(){ready_.clear();saved_->setChecked(false);publish_->setEnabled(false);}
 void failure(const QString& error){busy(false);status_->setText(error);}
 void startWork(bool creating,const QString& secret,const QString& code,unsigned bits,const QString& script={}){
  if(thread_.joinable())thread_.join();job_=std::make_shared<Job>();job_->creating=creating;auto j=job_;busy(true);work_->setText("Starting local SHA-256 work…");
  thread_=std::thread([j,creating,secret,code,bits,script]{
   try{auto report=[j](const tru_magic_v2::Progress& p){std::lock_guard<std::mutex> lock(j->mutex);j->progress=p;return !j->cancel.load();};
    std::string result;if(creating)result=tru_magic_v2::script(tru_magic_v2::seal(secret.toUtf8().toStdString(),code.toStdString(),bits,report));else result=tru_magic_v2::open(tru_magic_v2::fromScript(script.toStdString()),code.toStdString(),report);
    std::lock_guard<std::mutex> lock(j->mutex);j->result=result;
   }catch(const std::exception& e){std::lock_guard<std::mutex> lock(j->mutex);j->error=e.what();}j->done.store(true);
  });timer_.start(80);
 }
 void poll(){
  auto j=job_;if(!j)return;tru_magic_v2::Progress p;{std::lock_guard<std::mutex> lock(j->mutex);p=j->progress;}
  work_->setText(QString("%1 attempts  ·  %2 H/s  ·  %3 seconds\n%4")
   .arg(qulonglong(p.attempts)).arg(p.seconds>0?qulonglong(p.attempts/p.seconds):0).arg(p.seconds,0,'f',1).arg(QString::fromStdString(p.digest)));
  if(!j->done.load())return;timer_.stop();thread_.join();job_.reset();busy(false);
  if(!j->error.empty()){failure(QString::fromStdString(j->error));return;}
  if(j->creating){ready_=QString::fromStdString(j->result);status_->setText("Encrypted locally. Reveal and save the code, then confirm the fee to publish.");}
  else{output_->setPlainText(QString::fromUtf8(j->result.data(),int(j->result.size())));status_->setText(chainState_+"\nSecret authenticated and unlocked locally.");}
  busy(false);
 }
 void createSecret(){
  invalidate();chainState_.clear();output_->clear();try{code_->setText(QString::fromStdString(tru_magic_v2::newCode()));startWork(true,text_->toPlainText(),code_->text(),unsigned(bits_->value()));}catch(const std::exception& e){failure(e.what());}
 }
 void readSecret(){
  invalidate();chainState_.clear();status_->clear();output_->clear();const QString id=txid_->text().trimmed().toLower(),code=code_->text().trimmed();const int outputIndex=vout_->value();
  try{tru_magic_v2::codeBytes(code.toStdString());if(id.size()!=64||id.toStdString().find_first_not_of("0123456789abcdef")!=std::string::npos)throw std::runtime_error("Enter a 64-character transaction ID");}catch(const std::exception& e){failure(e.what());return;}
  busy(true);QPointer<TruMagicSecretWidgetV2> self(this);
  rpc_->call("getmagicsecret",pack({{"txid",id}}),[self,code,outputIndex](const QJsonValue& v,const QByteArray&,const QString& e){
   if(!self)return;if(!e.isEmpty()){self->failure(e);return;}auto o=v.toObject();
   self->chainState_=QString("Chain state: %1 · %2 confirmations%3").arg(o.value("location").toString()).arg(o.value("confirmations").toInt()).arg(o.value("conflicted").toBool()?" · CONFLICTED":"");self->status_->setText(self->chainState_);
   for(auto value:o.value("entries").toArray()){auto entry=value.toObject();if(entry.value("vout").toInt(-1)==outputIndex){self->startWork(false,{},code,0,entry.value("scriptHex").toString());return;}}
   self->failure("No V2 secret at that output index.");
  });
 }
 void publish(){
  if(ready_.isEmpty()||!saved_->isChecked())return;
  if(!wallet_->walletUnlocked()){failure("Unlock your standalone wallet on the Wallet tab first.");return;}
  const QString script=ready_;
  busy(true);QPointer<TruMagicSecretWidgetV2> self(this);
  wallet_->selectSafeFeeUtxo(10546,[self,script](QJsonObject selected,QString error){
   if(!self)return;if(!error.isEmpty()){self->failure(error);return;}
   const QString own=selected.value("scriptPubKey").toString().toLower();QString address;
   for(const auto& a:self->wallet_->walletAddresses())if(self->wallet_->walletScriptForAddress(a).toLower()==own){address=a;break;}
   if(address.isEmpty()){self->failure("Selected input is not owned by this wallet");return;}
   bool ok=false;quint64 amount=selected.value("amount_atoms").toString().toULongLong(&ok);
   if(!ok||amount<10546){self->failure("Invalid fee input amount");return;}
   self->rpc_->call("preparemagicsecret",pack({{"address",address},{"scriptHex",script},{"txid",selected.value("txid")},{"vout",selected.value("vout")}}),
    [self,selected,script,own,amount](const QJsonValue& v,const QByteArray&,const QString& e){
     if(!self)return;if(!e.isEmpty()){self->failure(e);return;}
     const QString raw=v.toObject().value("unsignedTxHex").toString();QString tail,error;QJsonObject metadata;
     QJsonArray outputs{out(script,0),out(own,amount-10000)};
     if(!self->wallet_->inspectPreparedIntent(raw,selected,outputs,10000,tail,metadata,error)||tail!="00"){self->failure("Local output/fee audit rejected the transaction: "+error);return;}
     if(QMessageBox::question(self,"Publish encrypted secret","Code saved privately?\nFee: 0.00010000 TRU\nPublish this encrypted message permanently?",QMessageBox::Yes|QMessageBox::No,QMessageBox::No)!=QMessageBox::Yes){self->busy(false);return;}
     QString signedHex,id;
     if(!self->wallet_->signPreparedTransaction(raw,QJsonArray{selected},signedHex,id,error)){self->failure(error);return;}
     self->txid_->setText(id);self->vout_->setValue(0);
     // Disable repeat publication even if the transport loses the response.
     self->invalidate();
     self->rpc_->call("sendrawtransaction",pack({{"txHex",signedHex}}),[self,id](const QJsonValue&,const QByteArray&,const QString& e){if(!self)return;self->busy(false);self->status_->setText(e.isEmpty()?"Submitted; awaiting confirmation. Share the transaction ID and code privately.":"Submission uncertain or rejected. Check transaction "+id+" before retrying. "+e);});
    });
  });
 }
public:
 TruMagicSecretWidgetV2(DesktopRpc* rpc,DesktopWalletWidget* wallet,QWidget* parent=nullptr):QWidget(parent),rpc_(rpc),wallet_(wallet){
  auto* layout=new QVBoxLayout(this);auto* title=new QLabel("MAGICLOCK V2 · Private secrets / visible work",this);layout->addWidget(title);
  auto* help=new QLabel("Create an encrypted on-chain message. Share its transaction ID and unlock code privately.\nAnyone with the code can pass it on. Opening spends no coins; publishing costs 0.00010000 TRU.",this);help->setWordWrap(true);layout->addWidget(help);
  auto* form=new QFormLayout;text_=new QPlainTextEdit(this);text_->setPlaceholderText("Secret text · maximum 200 UTF-8 bytes");text_->setMaximumHeight(95);form->addRow("Create secret",text_);
  bits_=new QSpinBox(this);bits_->setRange(12,20);bits_->setValue(18);form->addRow("Work bits",bits_);
  code_=new QLineEdit(this);code_->setEchoMode(QLineEdit::Password);code_->setMaxLength(70);code_->setPlaceholderText("TRUM2-… creator-issued code");form->addRow("Unlock code",code_);
  reveal_=new QCheckBox("Reveal code to save or share privately",this);form->addRow(reveal_);connect(reveal_,&QCheckBox::toggled,this,[this](bool yes){code_->setEchoMode(yes?QLineEdit::Normal:QLineEdit::Password);});
  txid_=new QLineEdit(this);txid_->setMaxLength(64);form->addRow("Transaction ID",txid_);vout_=new QSpinBox(this);vout_->setRange(0,1000000);form->addRow("Output index",vout_);layout->addLayout(form);
  saved_=new QCheckBox("I have saved the unlock code privately. It cannot be recovered.",this);layout->addWidget(saved_);
  auto* buttons=new QHBoxLayout;create_=new QPushButton("Grind & encrypt",this);publish_=new QPushButton("Publish secret",this);open_=new QPushButton("Grind & unlock",this);cancel_=new QPushButton("Cancel work",this);clear_=new QPushButton("Clear secrets",this);for(auto b:{create_,publish_,open_,cancel_,clear_})buttons->addWidget(b);layout->addLayout(buttons);
  bar_=new QProgressBar(this);bar_->setTextVisible(false);layout->addWidget(bar_);work_=new QLabel("Ready · actual attempts and hash rate appear here",this);work_->setWordWrap(true);work_->setTextInteractionFlags(Qt::TextSelectableByMouse);layout->addWidget(work_);
  status_=new QLabel(this);status_->setWordWrap(true);layout->addWidget(status_);output_=new QPlainTextEdit(this);output_->setReadOnly(true);output_->setPlaceholderText("Unlocked message appears here");layout->addWidget(output_);
  connect(create_,&QPushButton::clicked,this,[this]{createSecret();});connect(open_,&QPushButton::clicked,this,[this]{readSecret();});connect(publish_,&QPushButton::clicked,this,[this]{publish();});connect(cancel_,&QPushButton::clicked,this,[this]{if(job_)job_->cancel.store(true);});
  connect(clear_,&QPushButton::clicked,this,[this]{invalidate();text_->clear();code_->clear();output_->clear();status_->clear();});connect(code_,&QLineEdit::textEdited,this,[this]{invalidate();});connect(text_,&QPlainTextEdit::textChanged,this,[this]{if(!busy_)invalidate();});connect(saved_,&QCheckBox::toggled,this,[this]{busy(busy_);});connect(&timer_,&QTimer::timeout,this,[this]{poll();});busy(false);
 }
 ~TruMagicSecretWidgetV2() override {if(job_)job_->cancel.store(true);if(thread_.joinable())thread_.join();}
};
