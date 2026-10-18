// Separate entry point: legacy wallet send functions are not modified.
nlohmann::json Wallet::quantumTransaction(const std::string& action,const nlohmann::json& p) {
 requirePrivateAccess("Quantum Transactions");
 const auto& seed=getWalletSecurityMode()==WalletSecurityModeV1::ENCRYPTED_UNLOCKED?walletSecurityController_->unlockedSeed():masterSeed;
 const std::string path=walletFilePath+".pq01";
 if(action=="receive"){tru_quantum::Store store(path,seed,true);return store.receive();}
 tru_quantum::Store store(path,seed);
 if(action=="list")return store.list();
 if(action=="retry")return {{"rawHex",store.saved(p.at("source"))},{"signed",true}};
 if(action!="fund"&&action!="send"&&action!="exit")throw std::runtime_error("Quantum action must be receive, list, fund, send, exit or retry");
 if(!isLocalChain||!blockchainPtr)throw std::runtime_error("Quantum signing requires local chain");
 auto u=tru_quantum::input(*blockchainPtr,p);
 if(isSwapPreparedFundingInputReserved(blockchainPtr->getStorage(),u.txid,u.vout))throw std::runtime_error("Input reserved by another wallet operation");
 auto fee=tru_quantum::integer(p,"fee_atoms");if(fee<10000||fee>=u.amount||u.amount-fee<546)throw std::runtime_error("Fee must be >=10000 atoms and leave a nondust output");
 const auto destination=p.at("destination").get<std::string>();std::string output;
 if(action=="exit"){
  if(!p.value("confirm_exit",false))throw std::runtime_error("Exit requires confirm_exit=true; destination loses quantum protection");
  output=createP2PKHScriptHexFromAddress(destination);if(output.size()!=50)throw std::runtime_error("Invalid ordinary destination");
 }else output=tru_quantum::hex(tru_quantum::script(destination));
 Transaction tx(false);tx.version=1;tx.lockTime=0;tx.vin.emplace_back(u.txid,u.vout);tx.vout.emplace_back(u.amount-fee,output);
 std::string raw;
 if(action=="fund"){
  bool owned=false;for(const auto& address:getAllAddresses())if(u.scriptPubKey==createP2PKHScriptHexFromAddress(address)){owned=true;break;}
  if(!owned||u.scriptPubKey.size()!=50)throw std::runtime_error("Funding requires a wallet-owned ordinary P2PKH input");
  if(fee<estimateWalletPolicyFee(tx))throw std::runtime_error("Fee below wallet policy");
  if(!signTransaction(tx))throw std::runtime_error("Quantum funding ECDSA signature failed");raw=tru_quantum::hex(tx.serializeBinary());
 }else{
  const auto source=p.at("source").get<std::string>();if(u.scriptPubKey!=tru_quantum::hex(tru_quantum::script(source)))throw std::runtime_error("Input does not match quantum source");
  if(destination==source)throw std::runtime_error("Never send change or funds back to a used WOTS key");
  auto previous=tru_quantum::unhex(u.scriptPubKey);auto digest=tx.getSigHash(0,previous);auto unsignedHex=tru_quantum::hex(tx.serializeBinary());
  tx.vin[0].scriptSig=tru_quantum::Bytes(2147,0);if(fee<estimateWalletPolicyFee(tx))throw std::runtime_error("Fee below WOTS transaction policy");tx.vin[0].scriptSig.clear();
  raw=store.sign(source,digest,unsignedHex,[&](const tru_quantum::Bytes& sig){tx.vin[0].scriptSig={0x4d,0x60,0x08};tx.vin[0].scriptSig.insert(tx.vin[0].scriptSig.end(),sig.begin(),sig.end());return tru_quantum::hex(tx.serializeBinary());});
 }
 return {{"rawHex",raw},{"input_atoms",u.amount},{"send_atoms",u.amount-fee},{"fee_atoms",fee},{"signed",true},{"broadcast",false},{"note","Whole selected output is spent; no reused-key change. Submit with sendquantumtransaction."}};
}
