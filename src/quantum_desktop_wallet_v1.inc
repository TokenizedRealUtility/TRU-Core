void DesktopWalletCore::quantumBackup(const std::string& path,const std::string& backup){if(!unlocked_)throw std::runtime_error("Wallet is locked");tru_quantum::Store store(path+".pq01",seed_);store.backupTo(backup);}
nlohmann::json DesktopWalletCore::quantumReceive(const std::string& path){if(!unlocked_)throw std::runtime_error("Wallet is locked");tru_quantum::Store store(path+".pq01",seed_,true);return store.receive();}
nlohmann::json DesktopWalletCore::quantumList(const std::string& path){if(!unlocked_)throw std::runtime_error("Wallet is locked");tru_quantum::Store store(path+".pq01",seed_);return store.list();}
std::string DesktopWalletCore::quantumRetry(const std::string& path,const std::string& source){if(!unlocked_)throw std::runtime_error("Wallet is locked");tru_quantum::Store store(path+".pq01",seed_);return store.saved(source);}
DesktopWalletSignedTx DesktopWalletCore::quantumSign(const std::string& path,const DesktopWalletUtxo& u,const std::string& source,const std::string& destination,std::uint64_t fee,std::uint32_t height,bool funding,bool exit){
 if(!unlocked_)throw std::runtime_error("Wallet is locked");
 if(!tru09::active(height,tru09::WOTS_HEIGHT))throw std::runtime_error("PQ01 is not active; do not fund or spend protected outputs yet");
 if(tru_quantum::unhex(u.txid).size()!=32||!u.amountAtoms||u.amountAtoms>tru_limits::MAX_MONEY||fee<10000||fee>=u.amountAtoms||u.amountAtoms-fee<546)throw std::runtime_error("Invalid input/fee; minimum fee 10000 atoms");
 Tx tx;TxInput in;in.txid=u.txid;in.vout=u.vout;tx.vin.push_back(in);
 tru_quantum::Bytes out;if(exit){if(funding||!validateAddress(destination))throw std::runtime_error("Invalid Exit Quantum Protection destination");out=p2pkhScript(destination);}else out=tru_quantum::script(destination);
 tx.vout.push_back({u.amountAtoms-fee,out});
 auto previous=tru_quantum::unhex(u.scriptPubKey);
 std::string raw;
 if(funding){
  if(u.keyIndex>=nextIndex_||u.scriptPubKey!=scriptForAddress(address(u.keyIndex)))throw std::runtime_error("Funding requires a local ordinary P2PKH input");
  auto digest=canonicalSigHash(tx,0,previous);tru_quantum::Secret priv{derivePrivate(u.keyIndex)};auto sig=strictDerLowSSign(priv.bytes,digest);sig.push_back(1);pushData(tx.vin[0].scriptSig,sig);pushData(tx.vin[0].scriptSig,compressedPublic(priv.bytes));raw=toHex(serializeTx(tx));
 }else{
  if(previous!=tru_quantum::script(source)||destination==source)throw std::runtime_error("Source mismatch or reused quantum destination");
  auto digest=canonicalSigHash(tx,0,previous);auto unsignedHex=toHex(serializeTx(tx));
  tx.vin[0].scriptSig=tru_quantum::Bytes(2147,0);if(fee<serializeTx(tx).size()*tru_limits::MIN_RELAY_FEE_SAT_PER_BYTE)throw std::runtime_error("Fee below WOTS relay policy");tx.vin[0].scriptSig.clear();
  tru_quantum::Store store(path+".pq01",seed_);
  raw=store.sign(source,tru_quantum::Bytes(digest.begin(),digest.end()),unsignedHex,[&](const tru_quantum::Bytes& sig){tx.vin[0].scriptSig={0x4d,0x60,0x08};tx.vin[0].scriptSig.insert(tx.vin[0].scriptSig.end(),sig.begin(),sig.end());return toHex(serializeTx(tx));});
 }
 Tx idTx=tx;for(auto& in:idTx.vin)in.scriptSig.clear();auto ser=serializeTx(idTx);auto hash=doubleSha(ser.data(),ser.size());
 DesktopWalletSignedTx r;r.txid=toHex(hash.data(),hash.size());r.rawHex=raw;r.inputAtoms=u.amountAtoms;r.sendAtoms=u.amountAtoms-fee;r.feeAtoms=fee;return r;
}
