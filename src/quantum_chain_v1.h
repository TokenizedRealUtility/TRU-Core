#pragma once
#include "quantum_wallet_v1.h"
#include "consensus09_activation.h"
#include "blockchain.h"
#include "mempool.h"
#include "tru_limits.h"
#include "tru_swap_prepared_funding_guard.h"
#include <climits>
namespace tru_quantum {
inline uint32_t activeHeight(Blockchain& chain){int tip=chain.getBestTipHeight();if(tip<0||tip==INT_MAX||!tru09::active(static_cast<uint32_t>(tip)+1,tru09::WOTS_HEIGHT))throw std::runtime_error("PQ01 is not active; quantum funding and spending are disabled");return static_cast<uint32_t>(tip)+1;}
inline uint64_t integer(const Json& p,const char* key){const auto& j=p.at(key);if(!j.is_number_unsigned())throw std::runtime_error(std::string(key)+" must be an unsigned integer");return j.get<uint64_t>();}
inline UTXO input(Blockchain& chain,const Json& p){auto h=activeHeight(chain);auto id=p.at("txid").get<std::string>();auto v=integer(p,"vout");if(unhex(id).size()!=32||v>UINT32_MAX)throw std::runtime_error("Invalid outpoint");UTXO u{};Transaction parent;
 if(!chain.utxoSet.getUTXO(id,static_cast<uint32_t>(v),u)||!chain.getTransaction(id,parent)||v>=parent.vout.size()||parent.vout[v].amount!=u.amount||parent.vout[v].scriptPubKey!=u.scriptPubKey)throw std::runtime_error("Input must be confirmed and unspent");
 if(!chain.mempool||chain.mempool->isUTXOSpentInMempool(id,static_cast<uint32_t>(v)))throw std::runtime_error("Input unavailable or spent in mempool");
 if(u.isCoinbase&&(h<=u.createdAtHeight||h-u.createdAtHeight<COINBASE_MATURITY))throw std::runtime_error("Input is an immature coinbase");
 auto* db=chain.getStorage();if(!db||db->exists("tokenUTXO:"+id+":"+std::to_string(v)))throw std::runtime_error("Token/control inputs are not supported by Quantum Send");
 std::string reserved;if(db->getWithDataChecksum(tru_swap_prepared_funding::inputKey(id,static_cast<uint32_t>(v)),reserved))throw std::runtime_error("Input reserved by another wallet operation");
 if(!u.amount||u.amount>tru_limits::MAX_MONEY)throw std::runtime_error("Invalid input amount");return u;
}
inline Json inputJson(Blockchain& chain,const Json& p){auto u=input(chain,p);return {{"txid",u.txid},{"vout",u.vout},{"amount_atoms",u.amount},{"scriptPubKey",u.scriptPubKey},{"candidate_height",activeHeight(chain)}};}
}
