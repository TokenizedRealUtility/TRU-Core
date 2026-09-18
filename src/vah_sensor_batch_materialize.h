#pragma once
#ifndef VAH_SENSOR_BATCH_MATERIALIZE_H
#define VAH_SENSOR_BATCH_MATERIALIZE_H
#include "vah_sensor_batch_anchor.h"
#include <cstdint>
#include <string>
#include <vector>
class Blockchain; class LevelDBStorage;
namespace VAHSensorBatchMaterialize {
constexpr const char* CONFIRMED_MAGIC="TRU_VAH_SENSOR_CONFIRMED_V1";
constexpr const char* RECOVERY_MAGIC="TRU_VAH_SENSOR_RECOVERY_REQUIRED_V1";
constexpr const char* CHECKPOINT_MAGIC="TRU_VAH_SENSOR_CHECKPOINT_V1";
constexpr const char* EVENT_MAGIC="TRU_VAH_SENSOR_EVENT_MATERIALIZED_V1";
struct Identity { std::string token_id,writer_id,batch_hash; std::uint64_t first_sequence{0}; };
struct ChainProof { VAHSensorBatchAnchor::Anchor anchor; std::string txid,block_hash; std::uint64_t block_height{0},tx_index{0},finalized_height{0}; std::string finalized_block_hash; };
enum class Outcome { Materialized, Idempotent, RecoveryRequired, Rejected };
std::string confirmedKey(const Identity&);
std::string recoveryKey(const Identity&);
std::string checkpointKey(const Identity&);
std::string eventKey(const Identity&,std::uint64_t sequence);
std::string serializeProof(const ChainProof&);
bool persistRecoveryRequired(LevelDBStorage&,const Identity&,const std::string& reasonCode,const std::string& expectedTxid,const VAHReconciliation::CanonicalView&,std::string* reason=nullptr);
bool parseProof(const std::string&,ChainProof&,std::string* reason=nullptr);
Outcome materializeConfirmed(LevelDBStorage&,const Identity&,const ChainProof&,const std::vector<VAHAuthorization::AuthorizationRecord>&,const std::string&,std::string* reason=nullptr);
Outcome diagnoseAndMaterialize(const Blockchain&,LevelDBStorage&,const Identity&,const std::vector<VAHAuthorization::AuthorizationRecord>&,const std::string&,const VAHReconciliation::CanonicalView&,std::uint64_t firstHeight,std::string* reason=nullptr);
}
#endif
