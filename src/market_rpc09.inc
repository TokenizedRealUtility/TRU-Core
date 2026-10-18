// Included by rpc_server.cpp after makeResult/makeError and all core helpers.
static json consensusInfo09(Blockchain& chain,int id) {
    const int tip=chain.getBestTipHeight();const uint32_t h=tip<0?0:static_cast<uint32_t>(tip)+1;
    return makeResult(id,json{{"core_version",tru_version::compiledCoreVersion()},{"release_status","mainnet-0.08.5"},{"activation_height",tru09::ACTIVATION_HEIGHT==tru09::NEVER?json(nullptr):json(tru09::ACTIVATION_HEIGHT)},
        {"candidate_height",h},{"active",tru09::active(h)},
        {"opcodes",{{"OP_CHECKWOTSVERIFY","0xbb"},{"OP_MARKETVERIFY","0xbc"},{"OP_SIZE","0x82"}}},
        {"wots",{{"version",1},{"algorithm","WOTS+ SHA2 n32 w16 len67 L-tree"},{"signature_bytes",2144},{"gas",tru09::WOTS_GAS},{"sigop_cost",tru09::WOTS_SIGOPS}}},
        {"market",{{"version",1},{"token_id_bytes",8},{"supports",{"TRU","FT","SFT","NFT","NCFT"}},{"partial_fills",true},{"refund","seller signature at/after expiry"}}}});
}
static json buildMarket09(Blockchain& chain,const json& p,int id) {
    try {
        const int tip=chain.getBestTipHeight();if(tip<0||tip==INT_MAX)return makeError(-32000,"No usable active tip");
        const uint32_t height=static_cast<uint32_t>(tip)+1;
        if(!tru09::active(height,tru09::MARKET_HEIGHT))return makeError(-32000,"CONSENSUS09 is not activated; protected outputs must not be funded");
        auto u64=[](const json& j)->uint64_t{if(!j.is_number_unsigned())throw std::runtime_error("Amounts must be unsigned JSON integers in raw units/atoms");return j.get<uint64_t>();};
        const auto action=p.at("action").get<std::string>();
        if(action!="lock"&&action!="fill"&&action!="refund")throw std::runtime_error("action must be lock, fill or refund");
        const auto& inputs=p.at("inputs");if(!inputs.is_array()||inputs.empty()||inputs.size()>tru_limits::MAX_TX_INPUTS)throw std::runtime_error("Invalid explicit input list");
        Transaction tx;std::vector<Transaction> parents;uint64_t incoming=0;std::unordered_set<std::string> seen;
        for(const auto& in:inputs){const std::string txid=in.at("txid").get<std::string>();const uint64_t v=u64(in.at("vout"));
            if(txid.size()!=64||v>INT_MAX||!seen.insert(txid+":"+std::to_string(v)).second)throw std::runtime_error("Invalid/duplicate input");
            UTXO live;Transaction parent;
            if(!chain.utxoSet.getUTXO(txid,static_cast<uint32_t>(v),live)||!chain.getTransaction(txid,parent)||v>=parent.vout.size()||live.amount!=parent.vout[v].amount||live.scriptPubKey!=parent.vout[v].scriptPubKey)throw std::runtime_error("Input must be confirmed and unspent");
            if(live.amount>tru_limits::MAX_MONEY||incoming>tru_limits::MAX_MONEY-live.amount)throw std::runtime_error("Input amount overflow");incoming+=live.amount;
            tx.vin.emplace_back(txid,static_cast<uint32_t>(v));parents.push_back(std::move(parent));
        }
        const uint64_t fee=u64(p.at("fee_atoms"));if(!fee||fee>tru_limits::MAX_MONEY)throw std::runtime_error("Invalid fee_atoms");
        tru_market09::Terms t;tru_market09::Token offered;
        if(!tru_market09::branch(parents[0],static_cast<size_t>(tx.vin[0].vout),offered))throw std::runtime_error("First input must be a canonical token control");
        auto pair=[&](const tru_market09::Token& tok,const std::string& control=std::string()){
            tx.vout.emplace_back(0,tru_market09::data(tok));tx.vout.emplace_back(1,control.empty()?tru_market09::pay(tok.owner):control);
        };
        std::string changeOwner;
        if(action=="lock") {
            if(parents[0].vout[tx.vin[0].vout].scriptPubKey!=tru_market09::pay(offered.owner))throw std::runtime_error("Seller input must be unlocked P2PKH");
            t.offered=offered.asset;t.seller=offered.owner;t.quantity=u64(p.at("quantity_units"));t.price=u64(p.at("price_units_per_lot"));t.lot=u64(p.at("lot_units"));
            const auto expiry=u64(p.at("expiry_height"));if(expiry>UINT32_MAX)throw std::runtime_error("Expiry overflow");t.expiry=static_cast<uint32_t>(expiry);
            const auto& w=p.at("wanted");const auto type=u64(w.at("type"));if(type>4)throw std::runtime_error("Unknown wanted asset type");t.wanted.type=static_cast<unsigned>(type);
            t.wanted.id=w.at("token_id").get<std::string>();t.wanted.meta=w.at("meta_hash").get<std::string>();
            if(!tru_market09::valid(t)||t.quantity>offered.amount||height>=t.expiry)throw std::runtime_error("Invalid lock terms");
            pair({t.offered,t.seller,t.quantity},tru_market09::script(t));
            if(t.quantity<offered.amount)pair({t.offered,t.seller,offered.amount-t.quantity});changeOwner=t.seller;
        } else {
            if(!tru_market09::parseLock(parents[0].vout[tx.vin[0].vout].scriptPubKey,t))throw std::runtime_error("First input must be a MARKET-V1 lock");
            if(action=="fill"){
                const uint64_t q=u64(p.at("quantity_units"));const auto buyer=p.at("buyer_hash160").get<std::string>();std::vector<unsigned char> b;
                if(buyer.size()!=40||!tru_market09::unhex(buyer,b)||!q||q>t.quantity||q%t.lot||height>=t.expiry)throw std::runtime_error("Invalid fill");
                auto& ss=tx.vin[0].scriptSig;ss={1,1,8};tru_market09::put(ss,q,8);ss.push_back(20);ss.insert(ss.end(),b.begin(),b.end());
                pair({t.offered,buyer,q});const uint64_t due=q/t.lot*t.price;
                if(!t.wanted.type)tx.vout.emplace_back(due,tru_market09::pay(t.seller));else pair({t.wanted,t.seller,due});
                if(q<t.quantity){auto rest=t;rest.quantity-=q;pair({t.offered,t.seller,rest.quantity},tru_market09::script(rest));}
                if(t.wanted.type){uint64_t have=0;for(size_t i=1;i<parents.size();++i){tru_market09::Token tok;if(tru_market09::branch(parents[i],tx.vin[i].vout,tok)){if(!(tok.asset==t.wanted)||!tru_market09::add(have,tok.amount))throw std::runtime_error("Invalid payment inputs");}}
                    if(have<due)throw std::runtime_error("Payment token quantity is insufficient");if(have>due)pair({t.wanted,buyer,have-due});}
                changeOwner=buyer;
            }else{
                if(height<t.expiry)throw std::runtime_error("Refund not mature");pair({t.offered,t.seller,t.quantity});changeOwner=t.seller;
                // Shape-only placeholder replaced by signrawtransactionwithkey.
                tx.vin[0].scriptSig={1,2,9,0,0,0,0,0,0,0,0,1,33,2};tx.vin[0].scriptSig.resize(46,0);
            }
        }
        uint64_t outgoing=0;for(const auto& out:tx.vout)if(!tru_market09::add(outgoing,out.amount))throw std::runtime_error("Output overflow");
        if(outgoing>incoming||fee>incoming-outgoing)throw std::runtime_error("TRU inputs do not cover outputs and fee");const uint64_t change=incoming-outgoing-fee;
        if(change && change<tru_limits::MIN_OUTPUT_DUST_ATOMS)throw std::runtime_error("TRU change is below dust; adjust the explicit fee or inputs");
        if(change)tx.vout.emplace_back(change,tru_market09::pay(changeOwner));
        tx.computeTxId();if(!chain.validateConsensus09Transaction(tx,height))throw std::runtime_error("Consensus09 structural/ownership gate failed");
        return makeResult(id,json{{"txHex",hexEncode(tx.serializeBinary())},{"txid",tx.txid},{"signed",false},{"broadcast",false},{"fee_atoms",fee},{"candidate_height",height},{"lock_script",tru_market09::script(t)}});
    }catch(const std::exception& e){return makeError(-32602,e.what());}
}
