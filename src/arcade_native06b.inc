// TRU Arcade Native 06B: privileged local-only RPC with browser P-256 approval.
// NOT a consensus change. All funding outputs return to the authorized wallet address.
// Signing is disabled unless an exact browser public key and address are configured.
namespace tru_arcade_native06b {
static std::mutex publishMutex;
static void require(bool valid, const char* msg) {if(!valid)throw std::runtime_error(msg);}
static std::string digest(const std::string& msg) {
    unsigned char out[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(msg.data()),msg.size(),out);
    return bytesToHex(std::vector<unsigned char>(out,out+sizeof(out)));
}
static std::string configPath() {
#ifdef __linux__
    std::error_code error;
    auto exe=std::filesystem::read_symlink("/proc/self/exe",error);
    require(!error,"Cannot locate running Core executable");
    return (exe.parent_path()/"tru.conf").string();
#else
    throw std::runtime_error("Arcade 06B supports explicitly reviewed Linux Core builds only");
#endif
}
struct Policy { std::string address,pub;uint64_t cap,daily; };
static Policy policy() {
    auto path=configPath();
    require(std::filesystem::is_regular_file(path) && !std::filesystem::is_symlink(path),"Configuration must be regular file");
    ConfigReader conf(path);
    require(conf.getValue("network","TRU_ARCADE_PUBLISH_ENABLE")=="1","Arcade publication is disabled");
    const auto address=conf.getValue("network","TRU_ARCADE_PUBLISH_ADDRESS");
    const auto pub=conf.getValue("network","TRU_ARCADE_PUBLISH_APPROVER_SPKI_HEX");
    const auto fee=conf.getValue("network","TRU_ARCADE_PUBLISH_MAX_FEE_ATOMS");
    const auto dailyValue=conf.getValue("network","TRU_ARCADE_PUBLISH_DAILY_FEE_BUDGET_ATOMS");
    require(address.size()>=20 && address.size()<=128 && pub.size()>=130 && pub.size()<=512 && isHex(pub),"Arcade enrollment is incomplete");
    require(!fee.empty() && fee.size()<=7 && std::all_of(fee.begin(),fee.end(),[](char c){return c>='0'&&c<='9';}),"Invalid Arcade fee cap");
    auto cap=std::stoull(fee);
    require(cap>=10000 && cap<=1000000,"Arcade fee cap out of allowed range");
    require(!dailyValue.empty() && dailyValue.size()<=9 && std::all_of(dailyValue.begin(),dailyValue.end(),[](char c){return c>='0'&&c<='9';}),"Invalid daily budget");
    const auto daily=std::stoull(dailyValue);
    require(daily>=cap && daily<=100000000ULL,"Daily fee budget exceeds safe limits");
    return {address,pub,cap,daily};
}
static void verifyP256(const std::string& spkiHex,const std::string& msg,const std::string& sigHex) {
    require(sigHex.size()==128 && isHex(sigHex),"Expected raw 64-byte P-256 signature");
    const auto key=hexDecode(spkiHex), raw=hexDecode(sigHex);
    const unsigned char* cursor=key.data();
    std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)> pub(d2i_PUBKEY(nullptr,&cursor,static_cast<long>(key.size())),EVP_PKEY_free);
    require(pub && cursor==key.data()+key.size() && EVP_PKEY_base_id(pub.get())==EVP_PKEY_EC,"Bad or unsupported enrolled public key");
    // Only NIST P-256, not an attacker-supplied curve.
    const EC_KEY* ec=EVP_PKEY_get0_EC_KEY(pub.get());
    require(ec && EC_GROUP_get_curve_name(EC_KEY_get0_group(ec))==NID_X9_62_prime256v1,"Signer must use P-256");
    std::unique_ptr<ECDSA_SIG,decltype(&ECDSA_SIG_free)> sig(ECDSA_SIG_new(),ECDSA_SIG_free);
    require(sig!=nullptr,"Signature allocation failed");
    BIGNUM* r=BN_bin2bn(raw.data(),32,nullptr);BIGNUM* s=BN_bin2bn(raw.data()+32,32,nullptr);
    if(!r || !s || ECDSA_SIG_set0(sig.get(),r,s)!=1){BN_free(r);BN_free(s);throw std::runtime_error("Bad signature scalar");}
    const int derLen=i2d_ECDSA_SIG(sig.get(),nullptr);require(derLen>0 && derLen<100,"Invalid DER signature length");
    std::vector<unsigned char> der(static_cast<size_t>(derLen));unsigned char* out=der.data();
    require(i2d_ECDSA_SIG(sig.get(),&out)==derLen,"Signature encode failed");
    std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(),EVP_MD_CTX_free);
    require(ctx && EVP_DigestVerifyInit(ctx.get(),nullptr,EVP_sha256(),nullptr,pub.get())==1,"Verification init failed");
    require(EVP_DigestVerify(ctx.get(),der.data(),der.size(),reinterpret_cast<const unsigned char*>(msg.data()),msg.size())==1,"Browser approval signature rejected");
}
static std::string message(const json& plan,const std::string& address,const std::string& nonce,std::int64_t expiry) {
    return "TRU_ARCADE06B_V1\n"+address+"\n"+digest(plan.dump())+"\n"+nonce+"\n"+std::to_string(expiry);
}
static json run(Blockchain& chain,Wallet& wallet,const json& p,int id,const std::string& peer) {
    try {
        require(rpcLocalPeer(peer),"Native Arcade signer requires loopback RPC");
        const auto cfg=policy();
        require(chain.isValidAddress(cfg.address),"Invalid authorized wallet address");
        const auto addresses=wallet.getAddresses();
        require(std::find(addresses.begin(),addresses.end(),cfg.address)!=addresses.end(),"Arcade address not held by Core wallet");
        require(p.is_object() && p.contains("action") && p.at("action").is_string(),"Malformed publishing request");
        const auto action=p.at("action").get<std::string>();
        if(action=="quote") {
            require(p.size()==4 && p.contains("address") && p.contains("op_return_script_hex") && p.contains("nonce"),"Unexpected quote parameters");
            require(p.at("address")==cfg.address,"Wallet address not enrolled");
            const auto script=p.at("op_return_script_hex").get<std::string>();
            require(script.size()>=82 && script.size()<=154 && isHex(script),"Invalid achievement script");
            const auto nonce=p.at("nonce").get<std::string>();
            require(nonce.size()==32 && isHex(nonce),"Invalid quote nonce");
            // Select one confirmed, ordinary P2PKH coin belonging to the enrolled address.
            // Never permit Marketplace to choose a third-party or token UTXO.
            json inputs=json::array();
            for(const auto& coin:tru_utxo_tools_v1::scanEnrolledAddress(chain,wallet,cfg.address)) {
                if(coin.address==cfg.address && coin.excluded.empty() && coin.u.amount>cfg.cap+tru_limits::MIN_OUTPUT_DUST_ATOMS) {
                    inputs.push_back({{"txid",coin.u.txid},{"vout",coin.u.vout}});break;
                }
            }
            require(!inputs.empty(),"No suitable confirmed ordinary TRU coin for enrolled wallet");
            const json req={{"action","prepare"},{"mode","anchor"},{"address",cfg.address},
               {"op_return_script_hex",script},{"max_fee",tru_amount::formatNumeric(cfg.cap)},{"inputs",inputs}};
            const auto result=tru_utxo_tools_v1::run(chain,wallet,req,id,peer);
            if(result.contains("error"))return result;
            auto plan=result.at("result");
            require(plan.at("fee_atoms").get<uint64_t>()<=cfg.cap,"Fee exceeds configured cap");
            require(plan.at("outputs_count")==2,"Unexpected output count");
            // A quote is not an authorization and carries no private keys.
            return makeResult(id,json{{"plan",plan},{"max_fee_atoms",cfg.cap},{"address",cfg.address}});
        }
        require(action=="publish","Unknown Arcade publishing action");
        require(p.size()==7 && p.contains("address") && p.contains("plan") && p.contains("nonce") && p.contains("expiry") && p.contains("signature") && p.contains("confirm"),"Unexpected publishing fields");
        require(p.at("address")==cfg.address && p.at("confirm")=="PUBLISH","Explicit approval required");
        const std::string nonce=p.at("nonce").get<std::string>();
        require(nonce.size()==32 && isHex(nonce),"Bad nonce");
        require(p.at("expiry").is_number_integer(),"Invalid approval expiry");
        const auto expiry=p.at("expiry").get<int64_t>();
        const auto now=static_cast<int64_t>(std::time(nullptr));
        require(expiry>now && expiry<=now+120,"Approval expired or too far ahead");
        const auto& plan=p.at("plan");
        require(plan.is_object() && plan.contains("request") && plan.contains("fee_atoms"),"Missing exact reviewed plan");
        require(plan.at("fee_atoms").is_number_unsigned() && plan.at("fee_atoms").get<uint64_t>()<=cfg.cap,"Fee cap exceeded");
        const auto& request=plan.at("request");
        require(request.is_object() && request.value("mode",std::string())=="anchor" && request.value("address",std::string())==cfg.address,"Wrong transaction mode/address");
        require(request.at("max_fee")==tru_amount::formatNumeric(cfg.cap),"Fee ceiling changed");
        require(request.at("inputs").is_array() && request.at("inputs").size()==1,"Exactly one funding input required");
        require(plan.at("outputs_count")==2,"Exactly OP_RETURN and self-change required");
        const auto& outputs=plan.at("outputs");
        require(outputs.is_array() && outputs.size()==2 && outputs.at(0).value("type",std::string())=="arcade_op_return" && outputs.at(0).at("amount_atoms")==0 && outputs.at(1).at("address")==cfg.address,"Invalid outputs");
        const auto script=request.at("op_return_script_hex").get<std::string>();
        require(outputs.at(0).at("script_hex")==script && script.size()<=154,"Script mismatch");
        verifyP256(cfg.pub,message(plan,cfg.address,nonce,expiry),p.at("signature").get<std::string>());
        std::lock_guard<std::mutex> guard(publishMutex);
        auto storage=chain.getStorage();require(storage!=nullptr,"Core storage not available");
        const auto replay="arcade06b:nonce:"+digest(cfg.address+":"+nonce);
        require(!storage->exists(replay),"Approval already used");
        // Persist one-time nonce before attempting spend. Failure fails closed;
        // rejected broadcasts may require preparing another approval.
        require(storage->putWithDataChecksum(replay,std::to_string(now)),"Cannot persist used authorization");
        const auto budgetKey="arcade06b:budget:"+digest(cfg.address)+":"+std::to_string(now/86400);
        std::string budgetText;uint64_t already=0;
        const bool budgetExists=storage->exists(budgetKey);
        if(budgetExists) {
            require(storage->getWithDataChecksum(budgetKey,budgetText),"Budget journal is corrupt");
            require(!budgetText.empty() && budgetText.size()<=12 && std::all_of(budgetText.begin(),budgetText.end(),[](char c){return c>='0'&&c<='9';}),"Invalid budget journal");
            already=std::stoull(budgetText);
        }
        const auto fee=plan.at("fee_atoms").get<uint64_t>();
        require(already<=cfg.daily && fee<=cfg.daily-already,"Daily wallet fee budget exhausted");
        require(storage->putWithDataChecksum(budgetKey,std::to_string(already+fee)),"Cannot persist daily fee reservation");
        const auto result=tru_utxo_tools_v1::run(chain,wallet,json{{"action","submit"},{"plan",plan},{"confirm","SUBMIT"}},id,peer,true);
        return result;
    } catch(const std::exception& e) {return makeError(-32166,std::string("Arcade 06B: ")+e.what());}
}
} // namespace tru_arcade_native06b
