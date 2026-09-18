#pragma once
#ifndef VAH_SENSOR_BATCH_ANCHOR_H
#define VAH_SENSOR_BATCH_ANCHOR_H
#include "vah_sensor_batch_accumulator.h"
#include "vah_reconciliation.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
class Blockchain; class LevelDBStorage; class Transaction;
namespace VAHSensorBatchAnchor {
constexpr std::size_t MAX_ANCHOR_TRANSACTION_OUTPUTS=64U;
constexpr const char* SENSOR_BATCH_MARKER="TRU_SENSOR_BATCH_V1";
constexpr const char* PREPARED_MAGIC="TRU_VAH_SENSOR_ANCHOR_PREPARED_V1";
constexpr const char* WATCH_MAGIC="TRU_VAH_SENSOR_ANCHOR_WATCH_V1";
constexpr std::size_t MAX_PREPARED_TX_BYTES=262144U;
struct Anchor { std::string token_id,token_type; std::uint64_t epoch{0},first_sequence{0},last_sequence{0},event_count{0}; std::string writer_id,previous_batch_hash,merkle_root,batch_hash; };
enum class ParseStatus { NotSensorBatchAnchor, Valid, Malformed };
struct OutputSnapshot { std::uint64_t amount{0}; std::string scriptPubKey; };
struct TxSnapshot { std::string txid; std::vector<OutputSnapshot> outputs; };
struct BlockSnapshot { std::string blockHash,previousBlockHash; std::uint64_t height{0}; std::vector<TxSnapshot> transactions; };
struct DurableAnchorState { std::string token_id,writer_id,batch_hash,merkle_root,txid,tx_serialized_hex; std::uint64_t first_sequence{0},last_sequence{0}; };
Anchor canonicalAnchorForStoredBatch(const VAHSensorBatchAccumulator::StoredBatch& stored);
std::string encodeAnchor(const Anchor& a);
ParseStatus parseAnchor(const std::string& scriptHex, Anchor& out, std::string& reason);
bool verifyPreparedAnchorOutputs(const std::vector<OutputSnapshot>& outputs,const VAHSensorBatchAccumulator::StoredBatch& stored,std::string* reason=nullptr);
std::string preparedKey(const VAHSensorBatchAccumulator::StoredBatch& stored);
std::string watchKey(const VAHSensorBatchAccumulator::StoredBatch& stored);
bool persistPreparedWatch(LevelDBStorage&,const VAHSensorBatchAccumulator::StoredBatch&,const std::string& txid,const std::string& txSerialized,std::string* reason=nullptr);
bool loadPreparedWatch(LevelDBStorage&,const VAHSensorBatchAccumulator::StoredBatch&,DurableAnchorState& out,std::string* reason=nullptr);
bool confirmSnapshot(const VAHSensorBatchAccumulator::StoredBatch& stored,const std::string& expectedTxid,const VAHReconciliation::CanonicalView& view,const std::vector<BlockSnapshot>& blocks,std::string* reason=nullptr);
bool submitPreparedAnchor(Blockchain&,LevelDBStorage&,const VAHSensorBatchAccumulator::StoredBatch&,const std::vector<VAHAuthorization::AuthorizationRecord>&,const std::string&,const Transaction&,std::string* reason=nullptr);
bool recoverPreparedAnchor(Blockchain&,LevelDBStorage&,const VAHSensorBatchAccumulator::StoredBatch&,const std::vector<VAHAuthorization::AuthorizationRecord>&,const std::string&,std::string* reason=nullptr);
bool confirmPreparedAnchor(const Blockchain&,LevelDBStorage&,const VAHSensorBatchAccumulator::StoredBatch&,const std::vector<VAHAuthorization::AuthorizationRecord>&,const std::string&,const Transaction&,const VAHReconciliation::CanonicalView&,std::uint64_t firstHeight,std::string* reason=nullptr);
}
#endif
