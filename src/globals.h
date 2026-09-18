#ifndef GLOBALS_H
#define GLOBALS_H

#include <mutex>
#include "config_reader.h"

extern ConfigReader config;

extern std::mutex gConsoleMutex;

// Consensus: number of confirmations before a coinbase output may be spent.
// Single source of truth shared by blockchain.cpp (validateBlock) and
// mempool.cpp (validateTransaction/isTransactionValidUnchecked) so the two
// can never disagree.
static const int COINBASE_MATURITY = 100;

#endif // GLOBALS_H
