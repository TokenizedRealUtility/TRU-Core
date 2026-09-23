// CORE-MINER-HARDEN-01. Snapshot mirror of validateBlock except PoW.
// tests verify parity; update this local assembly mirror when consensus validation changes.
bool Blockchain::checkMiningTemplate(const Block& block) {
    // CORE-MINER-HARDEN-01: local assembly only, never an acceptance API.
    // Hold the existing submission-order lock so UTXOs/state stay on this tip.
    std::unique_lock<std::mutex> submissionLock(miningSubmitMutex, std::try_to_lock);
    if (!submissionLock.owns_lock()) throw std::runtime_error("template preflight busy; retry");
    std::string tip; int tipHeight = 0;
    getBestTipSnapshot(tip, tipHeight);
    if (block.header.prevHash != tip || block.height != static_cast<uint64_t>(tipHeight) + 1)
        throw std::runtime_error("template parent changed; retry");

    Logger::log("[checkMiningTemplate] Starting validation for block: " + block.blockHash + ", height: " + std::to_string(block.height));

    // Step 1: Validate block structure
    if (block.transactions.empty()) {
        Logger::log("[checkMiningTemplate] ERROR: Block has no transactions");
        return false;
    }
    if (block.blockHash.empty() || block.blockHash.size() != 64 || !isValidHex(block.blockHash)) {
        Logger::log("[checkMiningTemplate] ERROR: Invalid block hash: " + block.blockHash);
        return false;
    }
    if (block.header.prevHash.size() != 64 || !isValidHex(block.header.prevHash)) {
        Logger::log("[checkMiningTemplate] ERROR: Invalid prevHash: " + block.header.prevHash);
        return false;
    }

    // enforce cheap byte/count limits before expensive
    // txid recomputation, BIP30 UTXO lookups, Merkle work, or script execution.
    size_t serializedBlockSize = 0;
    try {
        serializedBlockSize = block.serialize().size();
    } catch (const std::exception& e) {
        Logger::log(std::string("[checkMiningTemplate] ERROR: block serialization failed: ") + e.what());
        return false;
    } catch (...) {
        Logger::log("[checkMiningTemplate] ERROR: block serialization failed");
        return false;
    }
    if (serializedBlockSize > MAX_BLOCK_BYTES) {
        Logger::log("[checkMiningTemplate] ERROR: Block size (" +
                    std::to_string(serializedBlockSize) +
                    " bytes) exceeds limit (" + std::to_string(MAX_BLOCK_BYTES) + ")");
        return false;
    }

    size_t blockInputCount = 0;
    size_t blockOutputCount = 0;
    size_t blockStateInitBytes = 0;
    for (const auto& tx : block.transactions) {
        if (!validateTxResourceShape(
                tx, blockInputCount, blockOutputCount, blockStateInitBytes,
                true, "[checkMiningTemplate]")) {
            return false;
        }
    }

    // Step 2: Verify block hash
    std::string computedHash = block.computeHash();
    if (computedHash != block.blockHash) {
        Logger::log("[checkMiningTemplate] ERROR: Hash mismatch: computed=" + computedHash + ", expected=" + block.blockHash);
        return false;
    }

    // Unsolved local template: PoW is checked only by the unchanged acceptance path.

    // Step 4: Check previous block hash and height
    std::string prevHash = block.header.prevHash;
    {
        std::shared_lock<std::shared_mutex> lock(mtx);
        if (prevHash == std::string(64, '0')) {
            if (block.height != 1) {
                Logger::log("[checkMiningTemplate] ERROR: Genesis block must have height 1, got " + std::to_string(block.height));
                return false;
            }
        } else {
            auto it = blockIndex.find(prevHash);
            if (it == blockIndex.end()) {
                Logger::log("[checkMiningTemplate] ERROR: Previous block not found: " + prevHash);
                return false;
            }
            int expectedHeight = it->second.height + 1;
            if (block.height != expectedHeight) {
                Logger::log("[checkMiningTemplate] ERROR: Height mismatch: expected=" + std::to_string(expectedHeight) +
                            ", got=" + std::to_string(block.height));
                return false;
            }
        }
    }

    // Step 5: Validate timestamp
    //auto now = std::chrono::system_clock::now().time_since_epoch();
    //uint32_t currentTime = std::chrono::duration_cast<std::chrono::seconds>(now).count();
    //if (block.header.timestamp > currentTime + 7200) {
    //    Logger::log("[checkMiningTemplate] ERROR: Timestamp too far in the future: " + std::to_string(block.header.timestamp));
    //    return false;
    //}
    //if (block.height > bestTipHeight) {
    //    if (block.header.timestamp < currentTime - 86400) {
    //        Logger::log("[checkMiningTemplate] ERROR: Timestamp too old: " + std::to_string(block.header.timestamp));
    //        return false;
    //    }
    //}

    auto now = std::chrono::system_clock::now().time_since_epoch();
    uint32_t currentTime = std::chrono::duration_cast<std::chrono::seconds>(now).count();

    // Check not too far in future (2 hours)
    if (block.header.timestamp > currentTime + 7200) {
        Logger::log("[checkMiningTemplate] ERROR: Timestamp too far in future");
        return false;
    }

    // TRU Security Patch 07 + Smart Contract Patch 20 v2:
    // derive the candidate-parent MTP ONCE and use that exact value both for
    // header validation and every CLTV script executed in this block.
    uint32_t candidateParentMtp = 0;
    try {
        candidateParentMtp = getMedianTimePast(
            block.header.prevHash, static_cast<int>(block.height));
        if (block.header.timestamp <= candidateParentMtp) {
            Logger::log("[checkMiningTemplate] ERROR: Timestamp not greater than candidate-parent MTP");
            return false;
        }
    } catch (const std::exception& e) {
        Logger::log(std::string("[checkMiningTemplate] ERROR: candidate ancestry/MTP failure: ") + e.what());
        return false;
    }

    //
    // Never trust a transaction ID supplied by a peer or deserializer.  The
    // Merkle root below is built from tx.txid, so every claimed ID must first
    // be proven to match TRU's canonical computeTxId() result for the actual
    // transaction contents.
    //
    // Work on a copy because computeTxId() mutates txid and temporarily clears
    // fields while hashing.  validateBlock() must not modify the received block.
    std::unordered_set<std::string> blockTxids;
    blockTxids.reserve(block.transactions.size());

    for (size_t txIndex = 0; txIndex < block.transactions.size(); ++txIndex)
    {
        const Transaction &receivedTx = block.transactions[txIndex];

        if (receivedTx.txid.empty() || receivedTx.txid.size() != 64 || !isValidHex(receivedTx.txid))
        {
            Logger::log("[checkMiningTemplate] ERROR: Invalid transaction ID encoding at index " +
                        std::to_string(txIndex));
            return false;
        }

        Transaction recomputedTx = receivedTx;
        const std::string claimedTxid = receivedTx.txid;
        recomputedTx.computeTxId();

        if (recomputedTx.txid != claimedTxid)
        {
            Logger::log("[checkMiningTemplate] ERROR: Transaction ID/content mismatch at index " +
                        std::to_string(txIndex) + ": claimed=" + claimedTxid +
                        ", computed=" + recomputedTx.txid);
            return false;
        }

        // CVE-2012-2459 class defense: the merkle tree must not hide duplicates.
        if (!blockTxids.insert(claimedTxid).second)
        {
            Logger::log(
                "[checkMiningTemplate] ERROR: Duplicate transaction ID in block: " +
                claimedTxid);
            return false;
        }

        // BIP30-style live-UTXO collision protection.
        for (size_t outIndex = 0; outIndex < receivedTx.vout.size(); ++outIndex)
        {
            if (outIndex > static_cast<size_t>(
                    std::numeric_limits<uint32_t>::max()))
            {
                Logger::log(
                    "[checkMiningTemplate] ERROR: Output index exceeds uint32 range");
                return false;
            }

            UTXO existing;
            if (utxoSet.getUTXO(
                    claimedTxid,
                    static_cast<uint32_t>(outIndex),
                    existing))
            {
                Logger::log(
                    "[checkMiningTemplate] ERROR: BIP30-style UTXO collision: " +
                    claimedTxid + ":" + std::to_string(outIndex));
                return false;
            }
        }
    }

    // Step 6: Verify Merkle root
    std::string computedMerkleRoot = computeMerkleRoot(block.transactions);
    if (computedMerkleRoot != block.header.merkleRoot) {
        Logger::log("[checkMiningTemplate] ERROR: Merkle root mismatch: computed=" + computedMerkleRoot +
                    ", expected=" + block.header.merkleRoot);
        return false;
    }

    // Step 7: Validate coinbase transaction
    if (!block.transactions[0].isCoinbase) {
        Logger::log("[checkMiningTemplate] ERROR: First transaction is not a coinbase");
        return false;
    }
    // FIX(crash): short-circuit deref of vout[0] on an empty coinbase.
    if (block.transactions[0].vout.empty()) {
        Logger::log("[checkMiningTemplate] ERROR: Coinbase has no outputs");
        return false;
    }

    // every non-genesis coinbase must commit to the
    // candidate block height in its scriptSig. Coinbase scriptSig IS included
    // in TRU's coinbase txid, so this commitment is merkle-covered today.
    if (block.height > 1) {
        uint64_t committedHeight = 0;
        if (!extractCommittedCoinbaseHeight(
                block.transactions[0], committedHeight) ||
            committedHeight != block.height) {
            Logger::log(
                "[checkMiningTemplate] ERROR: Coinbase height commitment mismatch: "
                "block=" + std::to_string(block.height) +
                " committed=" + std::to_string(committedHeight));
            return false;
        }
    }
    // the coinbase amount is NOT validated here any more.
    //
    // The old test was:
    //     if (block.transactions[0].vout[0].amount > calculateSubsidy(height))
    //         reject;
    //
    // At this point in validateBlock the block's transaction fees have not
    // been summed yet (that happens in Step 8), so the coinbase was being
    // compared against the bare subsidy.  getblocktemplate advertises
    // coinbasevalue = subsidy + fees, so every block that carried even one
    // fee-paying transaction was rejected with:
    //
    //     "Invalid coinbase output amount: got=5000010000, expected<=5000000000"
    //
    // That halted block production entirely for as long as the mempool was
    // non-empty: the miner re-included the same transaction in every
    // template and every solved block was thrown away.
    //
    // Step 8b below performs the correct check once totalFees is known:
    //     coinbaseValue <= subsidy + totalFees
    // It also sums ALL coinbase outputs rather than only vout[0], so it is
    // strictly the more complete test.  Do not reintroduce a subsidy-only
    // comparison here.

    // Step 8: Validate all transactions
    std::unordered_set<std::string> spentUTXOs;
    uint64_t totalFees = 0;
    uint64_t blockScriptOps = 0;
    uint64_t blockSigOps = 0;
    uint64_t blockGasUsed = 0;
    std::unordered_set<std::string> touchedStateRoots;
    for (size_t i = 0; i < block.transactions.size(); ++i)
    {
        const Transaction &tx = block.transactions[i];
        Logger::log("[checkMiningTemplate] Validating transaction " + std::to_string(i) + ": " + tx.txid);

        if (i == 0)
        {
            // coinbase tx is handled later for value checks
            continue;
        }

        if (tx.isCoinbase)
        {
            Logger::log("[checkMiningTemplate] ERROR: Multiple coinbase transactions detected");
            return false;
        }

        uint64_t inSum = 0, outSum = 0;
        uint64_t txScriptOps = 0;
        uint64_t txSigOps = 0;
        uint64_t txGasUsed = 0;
        bool sawStatefulCallInput = false;

        // retain creation classification while validating
        // inputs so consensus can bind the new root to its sole P2PKH creator.
        const auto stateCreation =
            tru_contract_call::ValidateStatefulCreationShape(tx);
        if (!stateCreation.valid) {
            Logger::log(
                "[checkMiningTemplate] ERROR: stateful creation classification diverged: " +
                stateCreation.reason);
            return false;
        }

        // Inputs
        for (size_t j = 0; j < tx.vin.size(); ++j)
        {
            const TxIn &vin = tx.vin[j];
            const std::string utxoKey = vin.txid + ":" + std::to_string(vin.vout);

            if (spentUTXOs.count(utxoKey))
            {
                Logger::log("[checkMiningTemplate] ERROR: Double-spend detected for UTXO: " + utxoKey);
                return false;
            }

            UTXO utxo;
            if (!utxoSet.getUTXO(vin.txid, vin.vout, utxo))
            {
                Logger::log("[checkMiningTemplate] ERROR: Missing UTXO for input: " + utxoKey);
                return false;
            }

            if (stateCreation.hasCreation && j == 0) {
                std::string creatorHash160;
                if (!tru_contract_call::ExtractCanonicalP2PKHHash160Hex(
                        utxo.scriptPubKey, creatorHash160)) {
                    Logger::log(
                        "[checkMiningTemplate] ERROR: stateful V1 creator input must be standard P2PKH");
                    return false;
                }
            }

            // Enforce coinbase maturity at consensus
            if (utxo.isCoinbase)
            {
                if (block.height <= utxo.createdAtHeight ||
                    (block.height - utxo.createdAtHeight) < COINBASE_MATURITY)
                {
                    Logger::log("[checkMiningTemplate] ERROR: Spending immature coinbase: " + utxoKey);
                    return false;
                }
            }

            //
            // Consensus monetary arithmetic must never rely on uint64_t wraparound.
            // Bound every referenced UTXO and accumulate the input value with an
            // explicit MAX_MONEY check.
            if (utxo.amount > MAX_MONEY)
            {
                Logger::log("[checkMiningTemplate] ERROR: Input UTXO exceeds MAX_MONEY: " + utxoKey);
                return false;
            }
            if (inSum > MAX_MONEY - utxo.amount)
            {
                Logger::log("[checkMiningTemplate] ERROR: Input sum exceeds MAX_MONEY: " + tx.txid);
                return false;
            }
            inSum += utxo.amount;

            // Script verification.
            std::vector<unsigned char> scriptPubKeyBytes;
            try {
                scriptPubKeyBytes = hexDecode(utxo.scriptPubKey);
            } catch (const std::exception& e) {
                Logger::log(std::string("[checkMiningTemplate] ERROR: Invalid scriptPubKey encoding for UTXO: ") +
                            utxoKey + ": " + e.what());
                return false;
            }
            if (scriptPubKeyBytes.empty() ||
                scriptPubKeyBytes.size() > tru_limits::MAX_SCRIPT_BYTES ||
                vin.scriptSig.size() > tru_limits::MAX_SCRIPT_BYTES)
            {
                Logger::log("[checkMiningTemplate] ERROR: Script byte limit exceeded for UTXO: " + utxoKey);
                return false;
            }

            // leading OP_RETURN outputs are unspendable.
            // Data-carrier outputs must never be made spendable by attacker-controlled
            // scriptSig stack contents or by OP_RETURN's interpreter termination behavior.
            // This rule is based only on the locking-script prefix and therefore applies
            // identically to push-prefixed and legacy/raw OP_RETURN payload encodings.
            if (scriptPubKeyBytes.front() == static_cast<unsigned char>(OP_RETURN))
            {
                Logger::log("[checkMiningTemplate] ERROR: Attempt to spend unspendable OP_RETURN UTXO: " + utxoKey);
                return false;
            }

            ScriptResourceMetrics unlockMetrics, lockMetrics;
            if (!AnalyzeScriptResources(vin.scriptSig, unlockMetrics) ||
                !AnalyzeScriptResources(scriptPubKeyBytes, lockMetrics) ||
                !addScriptMetricsChecked(
                    unlockMetrics, lockMetrics,
                    txScriptOps, txSigOps, blockScriptOps, blockSigOps)) {
                Logger::log("[checkMiningTemplate] ERROR: script/sigop budget exceeded for input: " + utxoKey);
                return false;
            }

            // owner-authorized Stateful K/V
            // continuation execution. State is loaded from the stable confirmed
            // root and executed on a disposable scratch copy during validation.
            const auto statefulScan =
                tru_contract_call::ScanStatefulContractScript(scriptPubKeyBytes);
            if (!statefulScan.valid) {
                Logger::log("[checkMiningTemplate] ERROR: malformed stateful-script scan for input: " + utxoKey);
                return false;
            }
            if (statefulScan.usesStateDomain) {
                const auto callShape =
                    tru_contract_call::ValidateStatefulCallShape(
                        tx, j, utxo.scriptPubKey, utxo.amount);
                if (!callShape.valid) {
                    Logger::log(
                        "[checkMiningTemplate] ERROR: invalid state-anchor call shape for " +
                        utxoKey + ": " + callShape.reason);
                    return false;
                }

                const std::string current =
                    tru_contract_state::BuildCanonicalContractOutpoint(
                        vin.txid, static_cast<uint32_t>(vin.vout));
                tru_contract_state_runtime::ConfirmedStateDomainSnapshot snapshot;
                std::string stateReason;
                if (current.empty() ||
                    !tru_contract_state_runtime::LoadConfirmedStateDomain(
                        dbStorage, current, snapshot, stateReason)) {
                    Logger::log(
                        "[checkMiningTemplate] ERROR: confirmed state-domain load failed for " +
                        utxoKey + ": " + stateReason);
                    return false;
                }
                if (!touchedStateRoots.insert(snapshot.root).second) {
                    Logger::log(
                        "[checkMiningTemplate] ERROR: more than one Stateful K/V call for root in one block: " +
                        snapshot.root);
                    return false;
                }

                const TxIn& callerVin = tx.vin[callShape.callerInputIndex];
                UTXO callerUtxo;
                if (!utxoSet.getUTXO(callerVin.txid, callerVin.vout, callerUtxo)) {
                    Logger::log(
                        "[checkMiningTemplate] ERROR: missing caller funding UTXO for stateful call: " +
                        callerVin.txid + ":" + std::to_string(callerVin.vout));
                    return false;
                }
                std::string callerHash160;
                if (!tru_contract_call::ExtractCanonicalP2PKHHash160Hex(
                        callerUtxo.scriptPubKey, callerHash160)) {
                    Logger::log(
                        "[checkMiningTemplate] ERROR: stateful V1 caller input must be standard P2PKH");
                    return false;
                }
                const std::string callerAddress =
                    extractAddressFromScriptPubKey(
                        callerUtxo.scriptPubKey, callerVin.txid,
                        static_cast<uint32_t>(callerVin.vout), this);
                if (callerAddress.empty()) {
                    Logger::log(
                        "[checkMiningTemplate] ERROR: unable to derive stateful caller address");
                    return false;
                }

                if (txGasUsed >= tru_limits::MAX_TX_SCRIPT_GAS ||
                    blockGasUsed >= tru_limits::MAX_BLOCK_SCRIPT_GAS) {
                    Logger::log("[checkMiningTemplate] ERROR: transaction/block gas budget exhausted");
                    return false;
                }
                const uint64_t inputGasLimit = std::min({
                    tru_limits::MAX_SCRIPT_GAS_PER_INPUT,
                    tru_limits::MAX_TX_SCRIPT_GAS - txGasUsed,
                    tru_limits::MAX_BLOCK_SCRIPT_GAS - blockGasUsed});
                if (inputGasLimit == 0) return false;

                uint64_t stateCallGasUsed = 0;
                std::string stateCallLabel;
                if (snapshot.family.empty()) {
                    if (callerHash160 != snapshot.ownerHash160) {
                        Logger::log(
                            "[checkMiningTemplate] ERROR: unauthorized Stateful K/V V1 caller for root " +
                            snapshot.root);
                        return false;
                    }

                    tru_contract_state_runtime::KvCallExecutionResult execResult;
                    if (!tru_contract_state_runtime::ExecuteStatefulKvV1Call(
                            tx, callShape, scriptPubKeyBytes, snapshot, callerAddress,
                            block.header.timestamp, static_cast<uint32_t>(block.height),
                            inputGasLimit, this, execResult, stateReason)) {
                        Logger::log(
                            "[checkMiningTemplate] ERROR: Stateful K/V V1 scratch execution failed: " +
                            stateReason);
                        return false;
                    }
                    stateCallGasUsed = execResult.gasUsed;
                    stateCallLabel = "Stateful K/V V1";
                } else if (snapshot.family == "voting_v1") {
                    tru_contract_state_runtime::VotingCallExecutionResult execResult;
                    if (!tru_contract_state_runtime::ExecuteVotingV1Call(
                            tx, callShape, scriptPubKeyBytes, snapshot,
                            callerHash160, callerAddress,
                            block.header.timestamp, static_cast<uint32_t>(block.height),
                            inputGasLimit, this, execResult, stateReason)) {
                        Logger::log(
                            "[checkMiningTemplate] ERROR: Voting V1 scratch execution failed: " +
                            stateReason);
                        return false;
                    }
                    stateCallGasUsed = execResult.gasUsed;
                    stateCallLabel = "Voting V1";
                } else if (snapshot.family == "token_issuer_v1") {
                    tru_contract_state_runtime::TokenIssuerCallExecutionResult execResult;
                    if (!tru_contract_state_runtime::ExecuteTokenIssuerV1Call(
                            tx, callShape, scriptPubKeyBytes, snapshot,
                            callerHash160, callerAddress,
                            block.header.timestamp, static_cast<uint32_t>(block.height),
                            inputGasLimit, this, execResult, stateReason)) {
                        Logger::log(
                            "[checkMiningTemplate] ERROR: Token Issuer V1 scratch execution failed: " +
                            stateReason);
                        return false;
                    }
                    stateCallGasUsed = execResult.gasUsed;
                    stateCallLabel = "Token Issuer V1";
                } else {
                    Logger::log(
                        "[checkMiningTemplate] ERROR: unsupported confirmed stateful family");
                    return false;
                }

                if (stateCallGasUsed >
                        tru_limits::MAX_TX_SCRIPT_GAS - txGasUsed ||
                    stateCallGasUsed >
                        tru_limits::MAX_BLOCK_SCRIPT_GAS - blockGasUsed) {
                    Logger::log(
                        "[checkMiningTemplate] ERROR: stateful V1 gas accounting breach");
                    return false;
                }
                txGasUsed += stateCallGasUsed;
                blockGasUsed += stateCallGasUsed;
                sawStatefulCallInput = true;
                spentUTXOs.insert(utxoKey);

                Logger::log(
                    "[checkMiningTemplate] " + stateCallLabel +
                    " call validated: root=" +
                    snapshot.root + " current=" + current +
                    " continuationVout=" +
                    std::to_string(callShape.continuationVout) +
                    " callValue=" + std::to_string(callShape.callValue) +
                    " key=" + callShape.logicalKey +
                    " callerHash160=" + callerHash160);
                continue;
            }

            if (txGasUsed >= tru_limits::MAX_TX_SCRIPT_GAS ||
                blockGasUsed >= tru_limits::MAX_BLOCK_SCRIPT_GAS) {
                Logger::log("[checkMiningTemplate] ERROR: transaction/block gas budget exhausted");
                return false;
            }
            const uint64_t inputGasLimit = std::min({
                tru_limits::MAX_SCRIPT_GAS_PER_INPUT,
                tru_limits::MAX_TX_SCRIPT_GAS - txGasUsed,
                tru_limits::MAX_BLOCK_SCRIPT_GAS - blockGasUsed});
            if (inputGasLimit == 0) return false;

            // consensus context is built from
            // explicit block/input data. OP_BLOCKTIME now uses the candidate
            // block header timestamp, never the validator node's wall clock.
            const std::vector<unsigned char> inputSighash =
                computeSighash(tx, j, scriptPubKeyBytes);
            const std::string inputSender =
                extractAddressFromScriptPubKey(
                    utxo.scriptPubKey, vin.txid, vin.vout, this);
            const std::string contractIdentity =
                BuildContractIdentity(vin.txid, vin.vout);
            if (contractIdentity.empty()) {
                Logger::log("[checkMiningTemplate] ERROR: Cannot derive contract identity for input: " + utxoKey);
                return false;
            }

            // state is scoped by the locking UTXO
            // identity, never by owner/caller. Validation works on a local copy;
            // Patch 14D will define atomic persistence/rollback of successful writes.
            std::unordered_map<std::string, std::vector<unsigned char>> scratchState;
            {
                // NOTE: do NOT lock `mtx` here — validateBlock may already run
                // with `mtx` held by a caller, and re-locking a non-recursive
                // shared_mutex self-deadlocks. Read is best-effort for validation.
                auto csIt = contractStates.find(contractIdentity);
                if (csIt != contractStates.end()) scratchState = csIt->second;
            }

            ScriptExecutionContextSpec ctxSpec;
            ctxSpec.gasLimit = inputGasLimit;
            ctxSpec.tx = &tx;
            ctxSpec.blockTime = block.header.timestamp;
            ctxSpec.medianTimePast = candidateParentMtp;
            ctxSpec.inputIndex = j;
            ctxSpec.scriptPubKey = &scriptPubKeyBytes;
            ctxSpec.sighash = inputSighash;
            ctxSpec.chainCtx = this;
            ctxSpec.execHeight = static_cast<uint32_t>(block.height);
            ctxSpec.sender = inputSender;
            ctxSpec.state = &scratchState;
            ctxSpec.contractAddress = contractIdentity;
            // outputIndex intentionally remains unset until 14E.
            ScriptExecutionContext ctx = BuildScriptExecutionContext(ctxSpec);

            try
            {
                if (!VerifyScripts(vin.scriptSig, scriptPubKeyBytes, ctx))
                {
                    Logger::log("[checkMiningTemplate] ERROR: Script verification failed for input: " + utxoKey);
                    return false;
                }
            }
            catch (const std::exception &e)
            {
                Logger::log(std::string("[checkMiningTemplate] ERROR: Script execution exception for input ") + utxoKey + ": " + e.what());
                return false;
            }

            if (ctx.gasUsed > inputGasLimit ||
                ctx.gasUsed > tru_limits::MAX_TX_SCRIPT_GAS - txGasUsed ||
                ctx.gasUsed > tru_limits::MAX_BLOCK_SCRIPT_GAS - blockGasUsed) {
                Logger::log("[checkMiningTemplate] ERROR: script gas accounting overflow/budget breach");
                return false;
            }
            txGasUsed += ctx.gasUsed;
            blockGasUsed += ctx.gasUsed;

            // Mark spent after successful verification
            spentUTXOs.insert(utxoKey);
        }

        if (stateCreation.hasCallCandidate != sawStatefulCallInput) {
            Logger::log(
                "[checkMiningTemplate] ERROR: stateful call envelope/input parity failure for tx " +
                tx.txid);
            return false;
        }

        // Outputs
        // FIX(overflow): bound each output to MAX_MONEY and use checked
        // accumulation so two huge uint64 outputs can't wrap past inSum.
        for (const auto &vout : tx.vout)
        {
            if (vout.amount > MAX_MONEY)
            {
                Logger::log("[checkMiningTemplate] ERROR: Output exceeds MAX_MONEY: " + tx.txid);
                return false;
            }
            if (outSum > MAX_MONEY - vout.amount)
            {
                Logger::log("[checkMiningTemplate] ERROR: Output sum overflow: " + tx.txid);
                return false;
            }
            outSum += vout.amount;
        }

        if (outSum > inSum)
        {
            Logger::log("[checkMiningTemplate] ERROR: Transaction creates money (out > in): " + tx.txid);
            return false;
        }

        //
        // Fee arithmetic is consensus-critical. Keep the per-transaction fee
        // and the running block fee total bounded so neither can wrap.
        const uint64_t txFee = inSum - outSum;
        if (txFee > MAX_MONEY)
        {
            Logger::log("[checkMiningTemplate] ERROR: Transaction fee exceeds MAX_MONEY: " + tx.txid);
            return false;
        }
        if (totalFees > MAX_MONEY - txFee)
        {
            Logger::log("[checkMiningTemplate] ERROR: Total block fees exceed MAX_MONEY");
            return false;
        }
        totalFees += txFee;
    }

    // ---- Step 8b: Enforce coinbase value <= subsidy + totalFees ----
    //
    // The coinbase transaction was intentionally skipped by the regular
    // transaction-output loop above, so it needs the SAME MAX_MONEY bounds
    // and checked accumulation here. Without this, multiple huge uint64_t
    // outputs can wrap coinbaseValue and bypass the subsidy+fees limit.
    uint64_t coinbaseValue = 0;
    for (const auto &vout : block.transactions[0].vout)
    {
        if (vout.amount > MAX_MONEY)
        {
            Logger::log("[checkMiningTemplate] ERROR: Coinbase output exceeds MAX_MONEY");
            return false;
        }
        if (coinbaseValue > MAX_MONEY - vout.amount)
        {
            Logger::log("[checkMiningTemplate] ERROR: Coinbase output sum exceeds MAX_MONEY");
            return false;
        }
        coinbaseValue += vout.amount;
    }

    const uint64_t subsidy = calculateSubsidy(block.height);
    if (subsidy > MAX_MONEY)
    {
        Logger::log("[checkMiningTemplate] ERROR: Calculated subsidy exceeds MAX_MONEY");
        return false;
    }
    if (totalFees > MAX_MONEY - subsidy)
    {
        Logger::log("[checkMiningTemplate] ERROR: Subsidy + fees exceeds MAX_MONEY");
        return false;
    }

    const uint64_t maxCoinbaseValue = subsidy + totalFees;
    if (coinbaseValue > maxCoinbaseValue)
    {
        Logger::log("[checkMiningTemplate] ERROR: Coinbase pays too much: coinbase=" +
                    std::to_string(coinbaseValue) + " subsidy=" + std::to_string(subsidy) +
                    " fees=" + std::to_string(totalFees));
        return false;
    }

    // Step 9: block byte size was checked before expensive validation work.
    // Keep the variable live here as a defensive invariant/documentation point.
    if (serializedBlockSize > MAX_BLOCK_BYTES) {
        Logger::log("[checkMiningTemplate] ERROR: block size invariant violated");
        return false;
    }

    // Step 10: Validate difficulty bits on EVERY block.
    // FIX(consensus): previously only retarget-height blocks were checked, so at
    // any other height an attacker could set trivial `bits` and mine for free.
    if (block.height > 1) {
        try {
            // difficulty is anchored to THIS block's parent.
            std::string expectedBits =
                calculateExpectedBits(block.header.prevHash, block.height);
            uint32_t exp = std::stoul(expectedBits, nullptr, 16);
            if (block.header.bits != exp) {
                Logger::log("[checkMiningTemplate] ERROR: Invalid difficulty bits: expected=" +
                            expectedBits + ", got=" + std::to_string(block.header.bits));
                return false;
            }
        } catch (const std::exception& e) {
            Logger::log(std::string("[checkMiningTemplate] ERROR: bad expected bits: ") + e.what());
            return false;
        }
    }

    Logger::log("[checkMiningTemplate] Block validated successfully: " + block.blockHash);
    return true;
}

