# RC2 candidate verification

2026-09-22: full isolated `cargo test --workspace --locked -- --test-threads=1`
passed all 104 tests with zero skip messages. Pinned Foundry 1.7.1 deployed the
copied canonical contracts to fresh local Anvil nodes. Previously skipped paths
ran: contract state reads, continuous two-proof mining, wallet submission/restart,
and exact signed-transaction recovery after a lost RPC reply.

The submission test now funds the newly generated encrypted wallet with an actual
local ETH transfer and checks its receipt and balance. It verifies fee refusal,
wrong-chain refusal, NFT ownership and a second mint after process restart.
The changed funding test also passed separately. Python launcher checks: 9 passed.

These are local-chain tests, not public-testnet or packaged-release acceptance.
Profiles remain disabled. No public funds or existing browser nodes were used.
Source import provenance is in source-snapshot.json; the subsequent funding test
change is recorded in git. Local raw logs and contract snapshot hashes are saved
under outputs/public-miner-full-test-20260922 in the parent workspace.
