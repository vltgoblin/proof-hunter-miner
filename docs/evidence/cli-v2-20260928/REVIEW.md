# CLI v0.3.0 acceptance: mining on the upgraded system

v0.3.0 mines on the mining system upgraded on 28 Sep 2026. It reads the mining core's
current module; on the upgraded system every proof goes through the mining router, sent
by the mining wallet, and the Hunter NFT is delivered to that wallet in the same
transaction. A wallet must hold its own stake (1M HUNTER tokens, staked in the app). The
CLI checks the stake before unlocking the keystore and submits a proof only when the chain
says it would be accepted for the wallet right now. An expired round is refreshed only once
the network allows the next round. Any other module keeps v0.2.3 behaviour; a pause module
prints the pause notice.

## Verification

- Mainnet fork end to end (`tests/mainnet_fork.rs`, opt-in with `BPROOF_FORK_RPC_URL`):
  one local Anvil fork of Robinhood Chain mainnet, real release binary, real deployed
  contracts. An unstaked wallet got the stake instruction (exit 4) in one-shot and `--loop`
  mode and sent no transaction. A wallet staked 1M HUNTER tokens through the real
  deposit/assign calls. With the round expired but the next one not yet allowed, the CLI
  sent nothing. Once allowed, `--loop` refreshed the round, then claimed through the router;
  a second round was refreshed and claimed in one-shot mode. Both Hunter NFTs are owned by
  the CLI wallet; both transactions go from the wallet to the router. Fork-only cheats: the
  core target was made easy, the round start time was moved, and the wallet was made the
  only stake so the run is deterministic.
- Scripted-node tests (`tests/hunt_gating.rs`): not staked, not yet allowed to refresh,
  refresh once allowed, staked-but-not-this-round (every refusal reason, one-shot and loop),
  eligible claim with a bound nonce and in-range digest, pause notice, and a router other
  than the pinned one. Each proves exactly what was or was not broadcast.
- Unit tests: nonce prefix, router digest, digest ranges against all 64 contract vectors
  (`tests/fixtures/hunt-tier-vectors.json`, byte-identical to the contract copy), submission
  gating, refresh timing, stake gate and message wording, journal v3 round trip and tamper
  refusal, receipt delivery checks.
- The existing suite, including the live local-contract Anvil tests, passed on Rust 1.90.0;
  clippy (all targets) is clean on 1.90.0. 20 launcher/package tests passed.

No public-chain transaction was sent. The fork ran on 127.0.0.1 only and was stopped after
each run.
