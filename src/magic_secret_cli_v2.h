#pragma once
#include "magic_secret_service_v2.h"
#include "magic_secret_receipt_v2.h"
#include <iostream>
#include <iomanip>

namespace tru_magic_cli_v2 {
using Ask=std::function<std::string(const std::string&)>;
using Say=std::function<void(const std::string&)>;
inline void run(Blockchain& chain,Wallet& wallet,Ask ask,Say say,tru_magic_v2::Report report){
 const auto action=ask("Magic Secret: create or open? ");
 if(action=="create"){
  const auto text=ask("Secret text (1..200 UTF-8 bytes): ");
  const auto code=tru_magic_v2::newCode();
  auto payload=tru_magic_v2::seal(text,code,tru_magic_v2::DEFAULT_BITS,report);
  say(tru_magic_receipt_v2::ready(code));
  if(ask("Code saved? Publish for 0.00010000 TRU? Type PUBLISH: ")!="PUBLISH"){say("Cancelled; nothing published.");return;}
  auto result=tru_magic_service_v2::publish(chain,wallet,{{"scriptHex",tru_magic_v2::script(payload)}});
  say(tru_magic_receipt_v2::published(result.at("txid").get<std::string>(),code));
 }else if(action=="open"){
  auto id=ask("Secret transaction ID: ");
  auto result=tru_magic_service_v2::get(chain,{{"txid",id}});
  say("State: "+result.at("location").get<std::string>()+"; confirmations: "+std::to_string(result.at("confirmations").get<int>()));
  auto entries=result.at("entries");auto entry=entries.at(0);
  if(entries.size()>1){const auto wanted=ask("Output index: ");bool found=false;for(auto e:entries)if(std::to_string(e.at("vout").get<unsigned>())==wanted){entry=e;found=true;}tru_magic_v2::require(found,"Output not found");}
  auto code=ask("Creator-issued unlock code (visible here): ");
  auto text=tru_magic_v2::open(tru_magic_v2::fromScript(entry.at("scriptHex").get<std::string>()),code,report);
  for(char& c:text)if(static_cast<unsigned char>(c)<32&&c!='\n'&&c!='\t')c='?';
  say("\nUNLOCKED SECRET:\n"+text);
 }else say("Choose create or open.");
}
}
