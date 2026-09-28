#pragma once
#include <string>

namespace tru_magic_receipt_v2 {
inline std::string ready(const std::string& code) {
    return "MAGIC SECRET READY - NOT PUBLISHED YET\n"
           "SAVE THIS UNLOCK CODE PRIVATELY:\n" + code +
           "\nSave the code, then type PUBLISH at the prompt.";
}
inline std::string published(const std::string& txid, const std::string& code) {
    return "MAGIC SECRET SUBMITTED - AWAITING CONFIRMATION\n"
           "TRANSACTION ID:\n" + txid +
           "\nOUTPUT INDEX: 0\nUNLOCK CODE:\n" + code +
           "\nShare BOTH the transaction ID and code privately.\n"
           "Web wallet: MagicLock V2 > enter both > Grind & unlock.";
}
}
