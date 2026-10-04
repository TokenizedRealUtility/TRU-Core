#pragma once

#include <mutex>

// AXON UX-03B: one process-wide funding critical section shared by the CLI
// and loopback RPC handoff paths. This prevents two local UI paths from
// creating a second HTLC pair concurrently.
inline std::mutex g_truAxonWalletHandoffFundingMutex;
