#ifndef RPC_SERVER_H
#define RPC_SERVER_H

#include <string>
#include "blockchain.h"
#include "wallet.h" // Include wallet.h for Wallet type
#include "p2p.h"

extern httplib::Server g_rpcServer;

nlohmann::json handleInteractWithAIToken(Blockchain& chain,
                                         const nlohmann::json& request,
                                         int id);

nlohmann::json handleGetAIResponse(Blockchain& chain,
                                   const nlohmann::json& request,
                                   int id);

//void startRPCServer(Blockchain &blockchain, Wallet &wallet, int port, const std::string &bindIP);
void startRPCServer(Blockchain &chain, Wallet &wallet, P2PNode &node, int port, const std::string &bindIP, int maxConnections, const std::string &rpcAuthToken);

#endif
