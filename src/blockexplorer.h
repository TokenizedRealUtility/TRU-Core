#ifndef BLOCKEXPLORER_H
#define BLOCKEXPLORER_H

#include <httplib.h>
#include "blockchain.h"
#include "logging.h"
#include <nlohmann/json.hpp>

class BlockExplorer {
public:
    explicit BlockExplorer(Blockchain* blockchain);
    void startServer(int port);

private:
    Blockchain* blockchain_;

 
    void handleStats(const httplib::Request&, httplib::Response&);
    void handleBlocks(const httplib::Request&, httplib::Response&);
    void handleBlockByHash(const httplib::Request&, httplib::Response&);
    void handleAddresses(const httplib::Request&, httplib::Response&);
    void handleTransactions(const httplib::Request&, httplib::Response&);
    void handleAddressDetails(const httplib::Request&, httplib::Response&);
    void handleTransactionDetails(const httplib::Request&, httplib::Response&);
    void handleTokens(const httplib::Request&, httplib::Response&);
    void handleContracts(const httplib::Request&, httplib::Response&);
    void handleMiners(const httplib::Request&, httplib::Response&);
};

#endif // BLOCKEXPLORER_H
