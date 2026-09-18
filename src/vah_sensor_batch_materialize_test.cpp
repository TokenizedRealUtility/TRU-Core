#include "vah_sensor_batch_materialize.h"
#include "crypto_ecdsa.h"
#include "leveldb_storage.h"
#include "vah_authorization.h"
#include <cassert>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>
namespace fs=std::filesystem;
namespace {
std::string hexLower(const std::vector<unsigned char>&b){static const char H[]="0123456789abcdef";std::string o;for(auto x:b){o.push_back(H[x>>4]);o.push_back(H[x&15]);}return o;}
VAHAuthorization::AuthorizationRecord auth(const std::string&t,const ECDSAKey&s,const ECDSAKey&r,const std::string&rp){VAHAuthorization::AuthorizationRecord x;x.sequence=1;x.effective_epoch=1;x.action=VAHAuthorization::Action::AUTHORIZE;x.token_id=t;x.writer_pubkey_hex=hexLower(s.getCompressedSec1());x.writer_class="sensor";x.capabilities={"SENSOR_MEASUREMENT"};x.previous_record_hash=std::string(64,'0');x.authorization_root_pubkey_hex=rp;std::string q;assert(VAHAuthorization::signAuthorizationRecord(x,r,&q));return x;}
VAHSensorBatch::Batch batch(const std::string&t,const ECDSAKey&s,uint64_t ep,const std::string&prev,uint64_t fs,uint64_t tm,char nib){VAHSensorBatch::Batch b;b.token_id=t;b.token_type="SFT";b.epoch=ep;b.previous_batch_hash=prev;for(size_t i=0;i<3;i++)b.events.push_back({fs+i,tm+i*1000,"sentiment_score",std::string(63,nib)+char('1'+i)});std::string q;assert(VAHSensorBatch::signBatch(b,s,&q));return b;}
std::string tp(const std::string&t){return "/tmp/truq-vah04d-"+t+"-"+std::to_string(::getpid());}
void rm(const std::string&p){std::error_code e;fs::remove_all(p,e);}
VAHSensorBatchMaterialize::ChainProof proof(const VAHSensorBatchAccumulator::StoredBatch&s,const std::string&tx,uint64_t h,uint64_t ix){VAHSensorBatchMaterialize::ChainProof p;p.anchor=VAHSensorBatchAnchor::canonicalAnchorForStoredBatch(s);p.txid=tx;p.block_height=h;p.block_hash=std::string(64,h==120?'a':'b');p.tx_index=ix;p.finalized_height=150;p.finalized_block_hash=std::string(64,'f');return p;}
VAHSensorBatchMaterialize::Identity id(const VAHSensorBatchAccumulator::StoredBatch&s){return {s.batch.token_id,s.batch.writer_id,s.batch.batch_hash,s.batch.events.front().sequence};}
}
int main(){const std::string token="2df1363f156c50b8";ECDSAKey root=ECDSAKey::generate(),sensor=ECDSAKey::generate();std::string rp=hexLower(root.getCompressedSec1());std::vector<VAHAuthorization::AuthorizationRecord> hist={auth(token,sensor,root,rp)};std::string reason;auto b1=batch(token,sensor,7,std::string(64,'0'),1,1700000000000ULL,'a');auto b2=batch(token,sensor,7,b1.batch_hash,4,1700000004000ULL,'b');
const std::string path=tp("core");rm(path);{
 LevelDBStorage db(path);assert(VAHSensorBatchAccumulator::appendBatch(db,b1,hist,rp,&reason));assert(VAHSensorBatchAccumulator::appendBatch(db,b2,hist,rp,&reason));VAHSensorBatchAccumulator::StoredBatch s1,s2;assert(VAHSensorBatchAccumulator::loadStoredBatch(db,token,b1.writer_id,1,b1.batch_hash,hist,rp,s1,&reason));assert(VAHSensorBatchAccumulator::loadStoredBatch(db,token,b2.writer_id,4,b2.batch_hash,hist,rp,s2,&reason));
 auto p1=proof(s1,std::string(64,'1'),120,1),p2=proof(s2,std::string(64,'2'),120,2);assert(VAHSensorBatchMaterialize::materializeConfirmed(db,id(s1),p1,hist,rp,&reason)==VAHSensorBatchMaterialize::Outcome::Materialized);assert(VAHSensorBatchMaterialize::materializeConfirmed(db,id(s2),p2,hist,rp,&reason)==VAHSensorBatchMaterialize::Outcome::Materialized);assert(VAHSensorBatchMaterialize::materializeConfirmed(db,id(s1),p1,hist,rp,&reason)==VAHSensorBatchMaterialize::Outcome::Idempotent);
 std::string ev;assert(db.getContract(VAHSensorBatchMaterialize::eventKey(id(s1),1),ev));assert(ev.find("sequence=1\n")!=std::string::npos);assert(db.getContract(VAHSensorBatchMaterialize::eventKey(id(s2),6),ev));assert(ev.find("sequence=6\n")!=std::string::npos);
 // Confirmed chain proof survives while exact local batch becomes unreadable: recovery-required, no silent repair.
 // accumulatedBatchKey() returns the fully-qualified LevelDB key including the contract: prefix.
 const std::string fullyQualifiedBatchKey=VAHSensorBatchAccumulator::accumulatedBatchKey(token,b1.writer_id,1,b1.batch_hash);assert(fullyQualifiedBatchKey.rfind("contract:TOKEN:VAH_SENSOR_BATCH:",0)==0);assert(db.put(fullyQualifiedBatchKey,"corrupt-local-batch"));auto o=VAHSensorBatchMaterialize::materializeConfirmed(db,id(s1),p1,hist,rp,&reason);assert(o==VAHSensorBatchMaterialize::Outcome::RecoveryRequired);assert(reason.find("CHAIN_CONFIRMED_LOCAL_BATCH_UNREADABLE")!=std::string::npos);std::string rec;assert(db.getContract(VAHSensorBatchMaterialize::recoveryKey(id(s1)),rec));assert(rec.find("RECOVERY_REQUIRED")!=std::string::npos);
 // Recovery namespace itself is strict and cannot be legacy-laundered.
 assert(db.put("contract:"+VAHSensorBatchMaterialize::recoveryKey(id(s1)),rec));std::string bad;assert(!db.getContract(VAHSensorBatchMaterialize::recoveryKey(id(s1)),bad));
 }
 rm(path);
 // Proof parser is canonical and round-trips.
 VAHSensorBatchAccumulator::StoredBatch fake;fake.feed_index=1;fake.batch=b1;auto pp=proof(fake,std::string(64,'3'),125,0);auto txt=VAHSensorBatchMaterialize::serializeProof(pp);VAHSensorBatchMaterialize::ChainProof out;assert(VAHSensorBatchMaterialize::parseProof(txt,out,&reason));assert(VAHSensorBatchMaterialize::serializeProof(out)==txt);
 std::cout<<"TRU_VAH_04D_CONFIRMED_BATCH_RECOVERY_EVENT_CHECKPOINT_MATRIX=PASS\n";return 0;}
