// Included once at the end of blockchain.cpp; no consensus call sites.
nlohmann::json Blockchain::getDataProviderChainV1() const {
    using namespace tru_data_provider_v1;
    const auto meta=metadata();json out;
    {
        std::shared_lock<std::shared_mutex> lock(mtx);
        const auto h=bestTipHeight.load();uint64_t timestamp=0;
        if(h>0&&!chain.empty())timestamp=chain.back().header.timestamp;
        out={{"schema","TRU-CHAIN-V1"},{"name","Tokenized Real Utility"},{"ticker","TRU"},{"network","mainnet"},{"height",h},{"best_block_hash",bestTipHash},{"tip_timestamp",timestamp},
          {"decimals",8},{"consensus","Proof of Work"},{"pow_algorithm","SHA256d-21E8"},
          {"pow_description","80-byte header; double SHA-256; add 0x21E8 modulo 2^32 to final big-endian hash word; compare as little-endian target integer"},
          {"target_block_time_seconds",DIFFICULTY_TARGET_SPACING},{"genesis_height",1},{"genesis_hash",std::string(tru_network::GENESIS_BLOCK_HASH)},
          {"genesis_timestamp",tru_network::GENESIS_TIMESTAMP},{"mainnet_launch_date",meta["mainnet_launch_date"]},
          {"address_format",{{"encoding","Base58Check"},{"p2pkh_version",65},{"p2pkh_prefix","T"},{"hash","HASH160"},{"checksum","first 4 bytes of double SHA-256"}}},
          {"issuance",{{"initial_subsidy_atoms","5000000000"},{"halving_interval_blocks",210000},{"first_reward_height",1},{"halving_formula","50 TRU >> floor((height - 1) / 210000), with integer atom rounding"},{"schedule_max_atoms",std::to_string(scheduled(UINT64_MAX))},{"coinbase_maturity_blocks",COINBASE_MATURITY}}},
          {"core_version",tru_version::coreReleaseVersion()}};
    }
    out["links"]={{"website",meta["website"]},{"source",meta["source"]},{"wallet_downloads",meta["wallet_downloads"]},{"logo_png",meta["logo_png"]}};
    return out;
}
nlohmann::json Blockchain::getDataProviderHealthV1() const {
    auto info=getDataProviderChainV1();const auto now=static_cast<uint64_t>(std::time(nullptr));const auto ts=info["tip_timestamp"].get<uint64_t>();
    const auto peers=node.getActivePeerCount();const bool fresh=ts>0&&ts<=now+7200&&now<=ts+1200;
    return {{"schema","TRU-HEALTH-V1"},{"status",fresh&&peers>0?"ok":"degraded"},{"rpc_available",true},{"height",info["height"]},{"best_block_hash",info["best_block_hash"]},{"tip_timestamp",ts},{"tip_age_seconds",now>=ts?nlohmann::json(now-ts):nlohmann::json(nullptr)},{"connected_peers",peers},{"tip_fresh",fresh},{"synced",nullptr},{"sync_note","Local freshness and peer connectivity are health signals, not proof of agreement with the entire network"},{"timestamp",now}};
}
nlohmann::json Blockchain::getDataProviderSupplyV1() const {
    using namespace tru_data_provider_v1;
    // One result per tip, at most one scan per 30 seconds. Cache identity uses
    // block HASH as well as height, so a same-height reorg invalidates it.
    struct Cache {std::mutex mutex;const Blockchain* owner=nullptr;std::string hash;int height=-1;json value;std::chrono::steady_clock::time_point last{};};
    static Cache cache;std::lock_guard<std::mutex> guard(cache.mutex);
    std::shared_lock<std::shared_mutex> chainGuard(mtx);const auto h=bestTipHeight.load();
    if(h<1||bestTipHash.empty())throw std::runtime_error("chain is not ready");
    const auto now=std::chrono::steady_clock::now();
    if(cache.owner==this&&cache.hash==bestTipHash&&cache.height==h&&!cache.value.is_null())return cache.value;
    if(cache.owner==this&&cache.last.time_since_epoch().count()!=0&&now-cache.last<std::chrono::seconds(30))throw std::runtime_error("supply snapshot refresh pending");
    cache.owner=this;cache.last=now;
    // Chain shared lock prevents concurrent publication/apply during this
    // bounded, read-only database scan. No writes or wallet calls occur here.
    auto result=utxoSet.getDataProviderSupplyV1(static_cast<uint64_t>(h));
    result["best_block_hash"]=bestTipHash;result["timestamp"]=static_cast<uint64_t>(std::time(nullptr));
    cache.value=result;cache.hash=bestTipHash;cache.height=h;return result;
}
