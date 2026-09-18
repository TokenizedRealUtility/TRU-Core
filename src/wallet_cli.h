#ifndef WALLET_CLI_H
#define WALLET_CLI_H

#include <string>
#include "blockchain.h"
#include "wallet.h"

std::string formatTokenTable(const Wallet &wallet,const std::string &nodeIP,int nodePort);

double computeUnconfirmedBalance(const Blockchain &blockchain, const std::string &address);

void addAddress(const std::string& addr);

#endif // WALLET_CLI_H
