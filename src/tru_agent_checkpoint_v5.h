// TRU Core 0.07.8: deterministic issuer-approved checkpoint evolution, not consensus.
#pragma once
#include <nlohmann/json.hpp>
#include <openssl/sha.h>
#include <limits>
#include <stdexcept>
#include <string>
namespace tru_checkpoint_v5 {
using json=nlohmann::json;
inline std::string hash(const std::string& s) {
 unsigned char d[32]; SHA256(reinterpret_cast<const unsigned char*>(s.data()),s.size(),d);
 static const char*h="0123456789abcdef"; std::string out;
 for(auto b:d){out+=h[b>>4];out+=h[b&15];} return out;
}
inline bool hex(const std::string&s,size_t n){return s.size()==n && s.find_first_not_of("0123456789abcdef")==std::string::npos;}
inline void require(bool b,const char*m){if(!b)throw std::runtime_error(m);}
inline void descriptor(const json& d){
 require(d.is_object() && d.size()==7,"Checkpoint request must contain exactly seven public fields");
 require(d.at("schema")=="TRU_AGENT_CHECKPOINT_REQUEST_V1","Wrong checkpoint request schema");
 require(hex(d.at("token_id").get<std::string>(),16),"Invalid checkpoint token ID");
 for(const char* k:{"checkpoint_sha256","manifest_sha256"})require(hex(d.at(k).get<std::string>(),64),"Invalid checkpoint hash");
 require(d.at("memory_revision").is_number_unsigned() && d.at("memory_revision").get<uint64_t>()>0,"Invalid memory revision");
 require(d.at("checkpoint_bytes").is_number_unsigned() && d.at("checkpoint_bytes").get<uint64_t>()>0 && d.at("checkpoint_bytes").get<uint64_t>()<=1048576,"Invalid checkpoint length");
 require(d.at("scope")=="explicit_memories_only","Unsupported checkpoint scope");
}
inline json assemble(const json& parent,const json& d,uint64_t epoch,uint64_t timestamp){
 descriptor(d);
 if(parent.contains("agent_checkpoint")){
  auto old=json::parse(parent.at("agent_checkpoint").get<std::string>());descriptor(old);
  require(old.at("checkpoint_sha256")!=d.at("checkpoint_sha256"),"Checkpoint already committed");
  // Revision is scoped to this identity's runtime. New/reset databases need an explicit migration.
  require(d.at("memory_revision").get<uint64_t>()>old.at("memory_revision").get<uint64_t>(),"Checkpoint revision must advance");
 }
 json m=parent;m["agent_checkpoint"]=d.dump();m["evolution_epoch"]=std::to_string(epoch);
 m["last_evolution"]="unix:"+std::to_string(timestamp)+";epoch:"+std::to_string(epoch);return m;
}
inline std::string requestHash(const std::string& token,const std::string& parentHash,const json& d){
 return hash(json{{"domain","TRU_AGENT_CHECKPOINT_V5"},{"token_id",token},{"parent_hash",parentHash},{"checkpoint",d}}.dump());
}
inline bool valid(const json&r,const json& parent){try{
 const auto&d=r.at("checkpoint");descriptor(d);
 require(r.at("record_format_version")==5 && r.at("type")=="NCFT" && r.at("writer_type")=="agent_checkpoint","Wrong record kind");
 require(r.at("provider")=="checkpoint" && r.at("provider_version")=="tru-agent-checkpoint-v1" && r.at("model_id")=="","Wrong checkpoint provenance");
 require(r.at("tokenID")==d.at("token_id") && r.at("trigger")=="agent_memory_checkpoint","Wrong checkpoint identity");
 require(r.at("input_metadata")==parent && r.at("input_metadata_hash")==hash(parent.dump()) && r.at("previous_metadata_hash")==hash(parent.dump()),"Wrong parent hash");
 auto before=r.at("epoch_before").get<uint64_t>(),epoch=r.at("epoch_after").get<uint64_t>(),ts=r.at("timestamp").get<uint64_t>();
 require(before<std::numeric_limits<uint64_t>::max() && epoch==before+1 && ts>0,"Wrong epoch/time");
 require(parent.at("evolution_epoch")==std::to_string(before),"Wrong parent epoch");
 json expected=assemble(parent,d,epoch,ts);
 require(r.at("metadata")==expected && r.at("new_metadata_hash")==hash(expected.dump()),"Wrong exact checkpoint transition");
 require(r.at("updated_fields")==json{{"agent_checkpoint",d.dump()}},"Wrong checkpoint updates");
 require(r.at("request_hash")==requestHash(r.at("tokenID"),hash(parent.dump()),d),"Wrong checkpoint request hash");
 return true;
}catch(...){return false;}}
}
