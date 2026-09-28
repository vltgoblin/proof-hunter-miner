# Changelog

## v0.3.0 (28 Sep 2026)

Mines on the mining system upgraded on 28 Sep 2026; v0.2.3 cannot. Full notes:
[docs/releases/v0.3.0.md](docs/releases/v0.3.0.md).

- Proofs go through the mining router from the mining wallet; the Hunter NFT is
  delivered to the wallet in the same transaction and verified in the receipt.
- A wallet must be staked (1M HUNTER tokens, staked in the app). The stake is checked
  before the keystore is unlocked; an unstaked wallet sends nothing and exits with code 4
  and a plain instruction.
- A proof is submitted only when the chain says it would be accepted for this wallet now.
- Expired rounds are refreshed only once the network allows the next round.
- `--loop` sends occasional network upkeep transactions while the wallet is staked
  (simulated first, random delay, within `--max-fee`, never during a claim);
  `--no-upkeep` turns them off. Events `upkeepSent`, `upkeepSkipped`, `upkeepRecovered`,
  `submissionPending`.
- On-chain pause notice (one-shot exit code 4; `--loop` waits).
- New exit code 4, loop events `notStaked`, `stakePending`, `miningPaused`, and
  `message` fields.
- `--router` pins the router from the release profile; the launcher and mainnet profile
  pin the stake module and router bytecode.
- Version 3 pending journals for router submissions (versions 1 and 2 still readable).
- Fix: bare keystore file names no longer fail to sync the journal directory.
- Fix: a stop between two search batches no longer reports a spurious failure.
- `proof-core` 0.1.1 adds `search_nonce_above` (a search with an exclusive lower bound).

## Earlier releases

v0.2.3 and earlier: see the
[GitHub releases](https://github.com/vltgoblin/proof-hunter-miner/releases).
