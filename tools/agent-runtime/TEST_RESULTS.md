# TRU-AGENT-03 validation

## Passed in the build workspace

- Existing Python runtime suite: 12 tests.
- Existing manual anchor/receipt suite: 5 tests.
- New adapter/scheduler suite: 12 tests covering all six adapter request/response formats, old Nemotron config, required remote opt-in, remote HTTP refusal, missing credentials, provider error responses, disabled/expired policy, unchanged memory, wrong manifest, request privacy/HMAC binding, interrupted handoff recovery, pending responses, and confirmed receipt advancement.
- Focused C++ policy tests: finite lifetime and daily budgets, minimum interval, expiry, disablement, backwards clock, invalid integer types, wrong network/fee cap, and HMAC mutation/wrong credential rejection.
- Python and C++ HMAC serialization agree on the same test vector.
- Linked C++ atomic storage test using actual modified TokenEvolutionEngine, actual ContractStorage/LevelDB, actual ECDSA signing/verification, and existing fault hooks: pre-write failure leaves neither epoch nor allowance; failure after synced write leaves epoch, queue and allowance together; replay after ambiguous success is refused; wrong expected allowance is refused; concurrent duplicate commits produce exactly one winner.
- C++17 syntax checks passed for modified ai_oracle_service.cpp and token_evolution.cpp in both NEW_TRU and TRU_Core profiles.
- Exact-source installers tested on reconstructed Agent02 baselines for both profiles: read-only check, apply, already-installed behavior, drift refusal, and byte-exact rollback.
- Python modules compile; 41 shell examples in package documentation pass `bash -n` syntax checks.

## Not established by these tests

No full linked Core application build was completed in this environment. main.cpp compilation is blocked by the environment's missing wally_address.h. The configuration helper is compiled by the policy/header and oracle checks, but a successful production build and restart remain required on the deployment machine.

The new automatic worker has not been exercised against a live node/wallet, and no live automatic fee was spent here. The prior successful manual checkpoint test does not count as a live test of this new code. The linked fault test exercises actual persistence/crypto but is not a complete oracle worker/network integration test.

Provider payloads were tested offline; no paid API calls, real Claude/Grok/OpenAI requests, or real Ollama inference were made. Choose an available text model and run one supervised inference check per configured provider. Native provider-specific tool use, multimodal content, streaming, and arbitrary custom API protocols are outside this text adapter implementation.

Wallet-locked deferral, policy revocation, missing/reorganized prior anchors, insufficient funding, full queue conditions, and restart recovery need supervised deployment acceptance checks as appropriate. Confirmation checks use the configured Core chain view; receipts are not independent light-client proofs.

Automatic approval is disabled by default. Installation does not edit tru.conf, grant a policy, unlock a wallet, start a watcher/service, or transmit any checkpoint.
