# CLI automatic seed refresh acceptance

`mine --submit` now handles an expired challenge with one zero-value refresh transaction and exits as `seedRefreshed`. `mine --submit --loop` refreshes, waits for the new seed and resumes proof search. Read-only status and mining without submission authorization do not spend.

The core and chain are verified; expired challenge ID and seed block are read at one snapshot, simulated and checked again after wallet unlock immediately before signing. A competing refresh observed before signing prevents a send. A race after signing may still revert and consume bounded gas. No contract, cap, difficulty or mining-power rule changed.

Refreshes use the existing padded estimate and per-transaction fee ceiling. They share the exclusive owner-only durable journal with proofs. Journal v2 identifies refreshes; legacy v1 proof recovery remains supported. An unresolved send stops new signing. Recovery reconciles the original signed hash; absent a receipt, changed seed identity refuses stale rebroadcast and retains evidence. Successful refresh receipts require the exact SeedRefreshed identity, matching transaction fields and canonical block hash. Refresh fees count toward the displayed fee total but refreshes never count as accepted proofs or NFTs.

## Verification

- 115 optimized Rust tests passed against the canonical checkout, with real local contracts and no skips.
- Real local loop: one refresh, followed by two NFT mints and correct ownership/account-nonce/fee accounting.
- Real local lost-reply refresh: same journaled transaction recovered, no extra account nonce, zero NFT mint count.
- Real local competing refresh after gas estimation: CLI sends zero transactions.
- Fee ceiling refusal sends nothing; receipt identity/removed/missing event rejection; v1/v2 journal compatibility and malformed refresh calldata rejection.
- Strict clippy all targets passed. 15 launcher/package tests passed. Documentation site checks passed (14 pages, 661 references).

Initial test runs exposed asynchronous Anvil indexing and a test harness bulk-mining race. The client now waits boundedly for transaction inclusion fields before applying unchanged exact checks. Lost-reply tests wait for the exact journaled receipt, and the loop test advances four parent blocks (the contract seed delay is three) rather than an uncontrolled 128-block burst. The original requirement of exactly one refresh and two accepted NFTs is unchanged. Failed run logs remain in the VPS job directory.

No public-chain transactions were sent and no existing miners were replaced. Artifact builds and publication are separate release steps. This change does not fix browser mining-power search.
