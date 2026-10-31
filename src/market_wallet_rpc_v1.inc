// Application signing only. Consensus rules and activation are unchanged.
static json marketWalletSignV1(Blockchain& chain,Wallet& wallet,const json& p,int id){
    try {
        if(!p.is_object() || p.size()!=4 || p.at("confirm")!="SIGN")throw std::runtime_error("Expected request, address, unsigned_hex and confirm=SIGN");
        wallet.requirePrivateAccess("Market transaction approval");
        const auto address=p.at("address").get<std::string>();
        if(!chain.isValidAddress(address))throw std::runtime_error("Invalid approval address");
        const auto& request=p.at("request");
        if(request.at("inputs").size()>32)throw std::runtime_error("At most 32 inputs per market approval");
        const auto action=request.at("action").get<std::string>();
        const auto built=buildMarket09(chain,request,id);
        if(built.contains("error"))return built;
        const auto raw=built.at("result").at("txHex").get<std::string>();
        if(raw!=p.at("unsigned_hex").get<std::string>())throw std::runtime_error("Approved bytes changed; obtain a fresh review");
        auto tx=Transaction::deserializeBinary(hexDecode(raw));
        const auto ownerScript=createP2PKHScriptHexFromAddress(address);
        if(action=="fill" && tru_market09::pay(request.at("buyer_hash160").get<std::string>())!=ownerScript)throw std::runtime_error("Buyer address mismatch");
        // All paid inputs belong to the explicitly approved address. Only the
        // covenant's permissionless fill input is exempt from wallet ownership.
        for(size_t i=0;i<tx.vin.size();++i){
            UTXO u;if(!chain.utxoSet.getUTXO(tx.vin[i].txid,tx.vin[i].vout,u))throw std::runtime_error("Input no longer unspent");
            if(!chain.mempool || chain.mempool->isUTXOSpentInMempool(u.txid,u.vout))throw std::runtime_error("Input already pending");
            std::string reservation;
            if(!chain.getStorage() || chain.getStorage()->getWithDataChecksum(tru_swap_prepared_funding::inputKey(u.txid,u.vout),reservation))throw std::runtime_error("Input reserved for another operation");
            if(i==0 && action=="fill")continue;
            tru_market09::Terms terms;
            const auto signingScript=(i==0 && action=="refund" && tru_market09::parseLock(u.scriptPubKey,terms))?tru_market09::pay(terms.seller):u.scriptPubKey;
            if(signingScript!=ownerScript)throw std::runtime_error("Input is not controlled by approval address");
        }
        // Private material remains inside Core. Reuse the existing canonical
        // MARKET-V1 aware signer, including its refund signature handling.
        const auto key=wallet.getPrivateKeyForAddress(address);
        auto signedResult=handleSignRawTransactionWithKey(chain,{{"txHex",raw},{"privKeys",json::array({key})}},id);
        if(signedResult.contains("result"))signedResult["result"]["broadcast"]=false;
        return signedResult;
    }catch(const std::exception& e){return makeError(-32080,e.what());}
}
