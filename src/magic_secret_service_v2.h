#pragma once
#include "magic_secret_v2.h"
#include "blockchain.h"
#include "wallet.h"
#include "mempool.h"
#include "address_helpers.h"
#include "tru_swap_prepared_funding_guard.h"
#include "tru_limits.h"
#include "globals.h"
#include <mutex>

namespace tru_magic_service_v2 {
using json=nlohmann::json;
constexpr uint64_t FEE=10000, DUST=546;
inline void fields(const json& p,std::initializer_list<const char*> allowed){
 tru_magic_v2::require(p.is_object(),"Object parameters required");
 for(auto it=p.begin();it!=p.end();++it){bool yes=false;for(auto key:allowed)if(it.key()==key)yes=true;tru_magic_v2::require(yes,"Unexpected parameter; never send a secret or unlock code to RPC");}
}
inline bool txidOK(const std::string& s){return s.size()==64&&s.find_first_not_of("0123456789abcdef")==std::string::npos;}
inline bool safeFunding(Blockchain& chain,const UTXO& u,const std::string& address){
 if(!chain.mempool||!chain.getStorage()||u.amount<FEE+DUST||u.amount>tru_limits::MAX_MONEY)return false;
 if(u.scriptPubKey!=createP2PKHScriptHexFromAddress(address))return false;
 if(chain.mempool->isUTXOSpentInMempool(u.txid,u.vout))return false;
 if(chain.getStorage()->exists("tokenUTXO:"+u.txid+":"+std::to_string(u.vout)))return false;
 std::string reservation;
 if(chain.getStorage()->getWithDataChecksum(tru_swap_prepared_funding::inputKey(u.txid,u.vout),reservation))return false;
 const int tip=chain.getBestTipHeight();
 if(u.isCoinbase&&(tip<0||uint64_t(tip)+1<u.createdAtHeight+uint64_t(COINBASE_MATURITY)))return false;
 KnownTransactionStatus status;
 if(!chain.getKnownTransactionStatus(u.txid,status)||status.location!="ACTIVE"||status.conflicted)return false;
 if(u.vout>=status.transaction.vout.size())return false;
 const auto& previous=status.transaction.vout[u.vout];
 if(previous.amount!=u.amount||previous.scriptPubKey!=u.scriptPubKey)return false;
 // Conservatively avoid asset/control transactions, even if an asset index is incomplete.
 if(!status.transaction.tokenMetadata.empty())return false;
 for(const auto& out:status.transaction.vout){
  if(out.scriptPubKey.rfind("6a",0)==0){
   try{tru_magic_v2::fromScript(out.scriptPubKey);}catch(...){return false;}
  }
 }
 return true;
}
struct Prepared{Transaction tx;UTXO input;};
inline Prepared prepare(Blockchain& chain,const json& p){
 fields(p,{"address","scriptHex","txid","vout"});
 const auto address=p.at("address").get<std::string>();
 tru_magic_v2::require(address.size()<=128&&chain.isValidAddress(address),"Invalid funding address");
 const auto sh=p.at("scriptHex").get<std::string>();tru_magic_v2::fromScript(sh);
 const std::string canonical=tru_magic_v2::script(tru_magic_v2::fromScript(sh));
 UTXO selected;bool found=false;
 std::lock_guard<std::recursive_mutex> guard(tru_swap_prepared_funding::mutex());
 if(p.contains("txid")||p.contains("vout")){
  const auto id=p.at("txid").get<std::string>();
  tru_magic_v2::require(txidOK(id)&&p.at("vout").is_number_unsigned()&&p.at("vout").get<uint64_t>()<=UINT32_MAX,"Invalid funding outpoint");
  found=chain.utxoSet.getUTXO(id,p.at("vout").get<uint32_t>(),selected)&&safeFunding(chain,selected,address);
 }else{
  auto candidates=chain.utxoSet.getUTXOsForAddress(address);
  // Bound expensive parent checks. Caller may select an explicit outpoint instead.
  size_t checked=0;for(const auto& u:candidates){if(++checked>16)break;if(safeFunding(chain,u,address)&&(!found||u.amount<selected.amount)){selected=u;found=true;break;}}
 }
 tru_magic_v2::require(found,"No safe confirmed fee UTXO; fund a fresh standard address with at least 0.00010546 TRU");
 Transaction tx(false);tx.vin.emplace_back(selected.txid,selected.vout);
 tx.vout.emplace_back(0,canonical);tx.vout.emplace_back(selected.amount-FEE,selected.scriptPubKey);tx.computeTxId();
 return {tx,selected};
}
inline json preparedJson(const Prepared& p){return {{"unsignedTxHex",tru_magic_v2::hex(p.tx.serializeBinary())},{"fee_atoms",std::to_string(FEE)},
 {"signingInput",{{"txid",p.input.txid},{"vout",p.input.vout},{"amount_atoms",std::to_string(p.input.amount)},{"scriptPubKey",p.input.scriptPubKey}}}};}
inline json get(Blockchain& chain,const json& p){
 fields(p,{"txid"});const auto id=p.at("txid").get<std::string>();tru_magic_v2::require(txidOK(id),"Expected lowercase 64-character transaction ID");
 KnownTransactionStatus status;
 tru_magic_v2::require(chain.getKnownTransactionStatus(id,status)&&status.found,"Transaction not found on connected node");
 json entries=json::array();
 for(size_t i=0;i<status.transaction.vout.size();++i){const auto& out=status.transaction.vout[i];if(out.amount!=0)continue;try{auto e=tru_magic_v2::parse(tru_magic_v2::fromScript(out.scriptPubKey));entries.push_back({{"vout",i},{"scriptHex",out.scriptPubKey},{"bits",e.bits}});}catch(...) {}}
 tru_magic_v2::require(!entries.empty(),"No MagicLock V2 secret in this transaction (legacy secrets use a different format)");
 return {{"txid",id},{"location",status.location},{"conflicted",status.conflicted},{"height",status.blockHeight},
 {"confirmations",status.location=="ACTIVE"?std::max(0,status.tipHeight-status.blockHeight+1):0},{"entries",entries}};
}
inline json publish(Blockchain& chain,Wallet& wallet,const json& p){
 fields(p,{"scriptHex"});wallet.requirePrivateAccess("publishmagicsecret");
 tru_magic_v2::require(wallet.isLocalChainAvailable(),"A local Core wallet is required");
 // Serialize this feature's funding/sign/accept path; mempool remains the final race arbiter.
 static std::mutex mutex;std::lock_guard<std::mutex> lock(mutex);
 std::lock_guard<std::recursive_mutex> fundingGuard(tru_swap_prepared_funding::mutex());
 auto built=prepare(chain,{{"address",wallet.getCurrentAddress()},{"scriptHex",p.at("scriptHex")}});
 tru_magic_v2::require(wallet.signTransaction(built.tx),"Local wallet signing failed");built.tx.computeTxId();
 auto accepted=chain.mempool->addTransaction(built.tx);
 tru_magic_v2::require(accepted==MempoolAddStatus::SUCCESS,"Transaction not accepted; inspect mempool before retrying");
 // Acceptance is definitive locally even if a later relay attempt fails.
 try{chain.broadcastTransaction(built.tx);}catch(...){}
 return {{"txid",built.tx.txid},{"fee_atoms",std::to_string(FEE)},{"location","MEMPOOL"}};
}
} // namespace tru_magic_service_v2
