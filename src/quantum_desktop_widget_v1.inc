void DesktopWalletWidget::quantumTransactions(){
 if(!wallet_.isUnlocked()){QMessageBox::warning(this,"Quantum Transactions","Unlock your desktop wallet first.");return;}
 bool ok=false;const QString mode=QInputDialog::getItem(this,"Quantum Transactions","Separate WOTS+ workflow (TRU only):",{"Receive","Fund quantum output","Quantum Send","Exit Quantum Protection","List quantum keys","Backup Quantum State","Retry saved transaction"},0,false,&ok);if(!ok)return;
 auto show=[this](const QString& text){QDialog d(this);d.setWindowTitle("Quantum Transactions");auto* layout=new QVBoxLayout(&d);auto* view=new QPlainTextEdit(text);view->setReadOnly(true);layout->addWidget(view);auto* close=new QPushButton("Close");layout->addWidget(close);connect(close,&QPushButton::clicked,&d,&QDialog::accept);d.resize(760,480);d.exec();};
 auto submit=[this,show](const std::string& raw){
  show("Signed transaction (saved for WOTS inputs):\n"+QString::fromStdString(raw));
  if(QMessageBox::question(this,"Quantum Transactions","Broadcast this signed transaction now?")!=QMessageBox::Yes)return;
  nlohmann::json p={{"txHex",raw}};
  rpc_->call("sendquantumtransaction",QByteArray::fromStdString(p.dump()),[this,show](const QJsonValue&,const QByteArray& raw,const QString& error){if(!error.isEmpty())QMessageBox::warning(this,"Quantum submission",error+"\nKeep the saved transaction. Never reuse its WOTS key for a different transaction.");else show(QString::fromUtf8(raw));});
 };
 try {
  const auto path=walletPath_.toStdString();
  if(mode=="Backup Quantum State"){
   auto dest=QFileDialog::getSaveFileName(this,"Back up current quantum state",walletPath_+".pq01.backup");if(dest.isEmpty())return;
   wallet_.quantumBackup(path,dest.toStdString());show("Encrypted quantum state backed up. Also retain the ordinary wallet backup. Refresh this state backup after EVERY quantum key creation or signature. Never restore an old copy or run cloned copies.");return;
  }
  if(mode=="Receive"){
   if(QMessageBox::warning(this,"Quantum recovery","Use each descriptor for ONE payment only. Your normal recovery code does not recover this sidecar. Back up the wallet and its .pq01 companion together. Never restore an older companion or run cloned copies. Continue?",QMessageBox::Yes|QMessageBox::No)!=QMessageBox::Yes)return;
   show(QString::fromStdString(wallet_.quantumReceive(path).dump(2)));return;
  }
  if(mode=="List quantum keys"){show(QString::fromStdString(wallet_.quantumList(path).dump(2)));return;}
  std::string source;
  if(mode!="Fund quantum output"){
   auto s=QInputDialog::getText(this,"Quantum source","Your source truq1: descriptor:",QLineEdit::Normal,{},&ok);if(!ok)return;source=s.toStdString();
  }
  if(mode=="Retry saved transaction"){submit(wallet_.quantumRetry(path,source));return;}
  const bool funding=mode=="Fund quantum output",exit=mode=="Exit Quantum Protection";
  auto txid=QInputDialog::getText(this,mode,"Confirmed source transaction ID:",QLineEdit::Normal,{},&ok);if(!ok)return;
  auto vout=QInputDialog::getInt(this,mode,"Source output index:",0,0,2147483647,1,&ok);if(!ok)return;
  auto destination=QInputDialog::getText(this,mode,exit?"Ordinary TRU destination (quantum protection ends):":"Fresh recipient truq1: descriptor (ONE payment only):",QLineEdit::Normal,{},&ok);if(!ok)return;
  auto feeText=QInputDialog::getText(this,mode,"Fee in TRU (whole selected output minus fee will be sent):",QLineEdit::Normal,"0.00010000",&ok);if(!ok)return;
  uint64_t fee=0;std::string error;if(!DesktopWalletCore::parseAmount(feeText.toStdString(),fee,&error))throw std::runtime_error(error);
  nlohmann::json p={{"txid",txid.toStdString()},{"vout",static_cast<uint32_t>(vout)}};
  rpc_->call("getquantuminput",QByteArray::fromStdString(p.dump()),[this,path,source,destination,fee,funding,exit,txid,vout,submit](const QJsonValue&,const QByteArray& raw,const QString& error){
   try{
    if(!error.isEmpty())throw std::runtime_error(error.toStdString());
    const auto response=nlohmann::json::parse(raw.constData(),raw.constData()+raw.size());const auto& r=response.at("result");
    DesktopWalletUtxo u;u.txid=r.at("txid");u.vout=r.at("vout");u.amountAtoms=r.at("amount_atoms");u.scriptPubKey=r.at("scriptPubKey");
    if(u.txid!=txid.toStdString()||u.vout!=static_cast<uint32_t>(vout))throw std::runtime_error("Core returned a different outpoint");
    if(funding){bool found=false;for(uint32_t i=0;i<wallet_.addressCount();++i)if(wallet_.scriptForAddress(wallet_.address(i))==u.scriptPubKey){u.keyIndex=i;found=true;break;}if(!found)throw std::runtime_error("This ordinary input does not belong to your desktop wallet");}
    if(fee>=u.amountAtoms)throw std::runtime_error("Fee exceeds input value");
    const auto amount=QString::fromStdString(DesktopWalletCore::formatAmount(u.amountAtoms-fee));
    const auto question="Send "+amount+" TRU to\n"+destination+"\nFee: "+QString::fromStdString(DesktopWalletCore::formatAmount(fee))+" TRU\nWhole selected output will be spent. No change output."+(exit?"\nDestination will NOT be quantum protected.":"");
    if(QMessageBox::question(this,"Confirm Quantum Transaction",question)!=QMessageBox::Yes)return;
    auto signedTx=wallet_.quantumSign(path,u,source,destination.toStdString(),fee,r.at("candidate_height"),funding,exit);submit(signedTx.rawHex);
   }catch(const std::exception& e){QMessageBox::critical(this,"Quantum Transactions",e.what());}
  });
 }catch(const std::exception& e){QMessageBox::critical(this,"Quantum Transactions",e.what());}
}
