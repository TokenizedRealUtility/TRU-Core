#include "vah_sensor_batch_anchor.h"
#include "leveldb_storage.h"
#include <cassert>
#include <filesystem>
#include <iostream>
#include <unistd.h>

static VAHSensorBatchAccumulator::StoredBatch sample(){
    VAHSensorBatchAccumulator::StoredBatch s; s.feed_index=1;
    s.batch.token_id="0123456789abcdef"; s.batch.token_type="SFT"; s.batch.epoch=7;
    s.batch.writer_id=std::string(64,'a'); s.batch.previous_batch_hash=std::string(64,'0');
    s.batch.merkle_root=std::string(64,'b'); s.batch.batch_hash=std::string(64,'c');
    for(uint64_t i=1;i<=3;i++){ VAHSensorBatch::Event e; e.sequence=i; s.batch.events.push_back(e); }
    return s;
}
int main(){
    auto s=sample(); auto a=VAHSensorBatchAnchor::canonicalAnchorForStoredBatch(s); auto enc=VAHSensorBatchAnchor::encodeAnchor(a);
    VAHSensorBatchAnchor::Anchor p; std::string r;
    assert(VAHSensorBatchAnchor::parseAnchor(enc,p,r)==VAHSensorBatchAnchor::ParseStatus::Valid);
    // Current V1 fields are <=64 bytes, so OP_PUSHDATA1 is never canonical. A forced PUSHDATA1 marker encoding must not verify.
    std::string noncanonicalPush="6a4c"+enc.substr(2); VAHSensorBatchAnchor::Anchor np; std::string nr; assert(VAHSensorBatchAnchor::parseAnchor(noncanonicalPush,np,nr)!=VAHSensorBatchAnchor::ParseStatus::Valid);
    std::vector<VAHSensorBatchAnchor::OutputSnapshot> outs={{0,enc},{1,"76a914"}};
    assert(VAHSensorBatchAnchor::verifyPreparedAnchorOutputs(outs,s,&r)); outs[0].amount=1; assert(!VAHSensorBatchAnchor::verifyPreparedAnchorOutputs(outs,s,&r)); outs[0].amount=0;
    // Public bool/reason verifier must contain canonicalization exceptions.
    auto empty=s; empty.batch.events.clear(); r.clear(); assert(!VAHSensorBatchAnchor::verifyPreparedAnchorOutputs(outs,empty,&r)); assert(!r.empty());
    VAHReconciliation::CanonicalView v{102,std::string(64,'f')};
    VAHSensorBatchAnchor::BlockSnapshot b1{std::string(64,'d'),std::string(64,'e'),101,{}};
    VAHSensorBatchAnchor::TxSnapshot tx{std::string(64,'1'),{{0,enc}}};
    VAHSensorBatchAnchor::BlockSnapshot b2{std::string(64,'f'),std::string(64,'d'),102,{tx}};
    assert(VAHSensorBatchAnchor::confirmSnapshot(s,std::string(64,'1'),v,{b1,b2},&r));
    assert(!VAHSensorBatchAnchor::confirmSnapshot(s,std::string(64,'2'),v,{b1,b2},&r));

    const std::string path="/tmp/truq-vah04c1-anchor-"+std::to_string((long long)getpid()); std::filesystem::remove_all(path);
    {
        LevelDBStorage db(path);
        const std::string txid(64,'1'), ser="signed|prepared|transaction";
        assert(VAHSensorBatchAnchor::persistPreparedWatch(db,s,txid,ser,&r));
        VAHSensorBatchAnchor::DurableAnchorState st; assert(VAHSensorBatchAnchor::loadPreparedWatch(db,s,st,&r));
        assert(st.txid==txid && st.batch_hash==s.batch.batch_hash);
        assert(VAHSensorBatchAnchor::persistPreparedWatch(db,s,txid,ser,&r)); // exact replay
        assert(!VAHSensorBatchAnchor::persistPreparedWatch(db,s,std::string(64,'2'),ser,&r)); // conflict
    }
    {
        LevelDBStorage db(path); VAHSensorBatchAnchor::DurableAnchorState st; assert(VAHSensorBatchAnchor::loadPreparedWatch(db,s,st,&r));
        std::string raw; bool found=false; const std::string fk="contract:"+VAHSensorBatchAnchor::watchKey(s); assert(db.getRaw(fk,raw,found)&&found);
        auto bar=raw.find('|'); assert(bar!=std::string::npos); std::string data=raw.substr(bar+1); data.replace(data.find("txid=")+5,1,"2");
        // generic put creates legacy single-SHA wrapper; strict sensor watch must refuse it and must not upgrade on read
        assert(db.put(fk,data)); std::string out; assert(!db.getContract(VAHSensorBatchAnchor::watchKey(s),out));
        std::string raw2; bool found2=false; assert(db.getRaw(fk,raw2,found2)&&found2); assert(raw2!=raw); // corrupted test value remains, no laundering rewrite
        assert(db.put("contract:TOKEN:VAH_AUTH:0123456789abcdef:head","TRU_VAH_AUTH_HEAD_V1|1|"+std::string(64,'a')));
        assert(!db.getContract("TOKEN:VAH_AUTH:0123456789abcdef:head",out)); // VAH_AUTH now strict
        assert(db.put("contract:LEGACY:compat","legacy-value")); assert(db.getContract("LEGACY:compat",out)&&out=="legacy-value"); // non-VAH legacy still accepted
    }
    std::filesystem::remove_all(path);
    std::cout<<"TRU_VAH_04C1_TXID_CRASH_SAFE_ANCHOR_STRICT_AUTH_MATRIX=PASS\n";
}
