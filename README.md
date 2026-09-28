# Proof Hunters CLI

The live `bproof` reader and submitter target `HunterMiningCore`: each accepted
proof mints one NFT. Mining does not pay liquid HUNTER, and token activation or
backing is a separate operation. `status --json` reports `settlementMode: nftOnly`
and `nftsMintedEver`; successful submissions include `nftTokenId`.

Build from the repository root:

```sh
cargo build --release
target/release/bproof --help
target/release/bproof wallet new --help
```

Create a dedicated encrypted mining wallet using `wallet new`. Keep the recovery
file private. The CLI signs with that wallet, not the browser's MetaMask account.
Phase 1 is live on Robinhood mainnet (4663). Use the verified settings in
[the setup guide](docs/getting-started.md); do not use RC1/RC2 fixtures.

```sh
target/release/bproof status \
  --rpc-url "$RPC_URL" --chain-id "$CHAIN_ID" --mining-core "$MINING_CORE" --json

target/release/bproof mine --submit \
  --rpc-url "$RPC_URL" --chain-id "$CHAIN_ID" --mining-core "$MINING_CORE" \
  --basket "$BASKET" --keystore ./miner-wallet.json \
  --max-fee "$MAX_TOTAL_FEE_WEI" --json
```

`--max-fee` is the maximum total gas exposure in **wei**, not a gas price.
The default gas margin is 100% above `eth_estimateGas`; the full padded exposure
must fit the explicit ceiling. It is a buffer, not a guarantee of successful
execution. A reverted transaction can still spend gas. Add `--loop` for continuous
mining; Ctrl-C stops it. A restart after confirmed completion reads the chain's
account nonce and restores the same encrypted wallet.

Receipt acceptance requires the current core's `ProofAccepted` and exactly one
matching `ProofNftMinted` event, consistent with the transaction, miner, challenge,
proof digest and requested basket; a router submission must also deliver the Hunter
NFT to the mining wallet in the same transaction. RPC data remains a trust source.

Before broadcast, the CLI writes an owner-only durable journal beside the
keystore containing the exact signed transaction and the public verification
context. If the process crashes or an RPC reply is lost, the next invocation
reconciles or rebroadcasts those same signed bytes and verifies the canonical
receipt before allowing a new transaction. Corrupt, overly permissive, or
inconsistent journal state fails closed. Never delete a pending journal merely
to bypass this guard; reconcile its transaction first.

A wallet must be staked to mine. Stake **1M HUNTER tokens** to the CLI wallet's
address in the app (app.proofhunter.fun/app/mine); `bproof wallet address` prints
it. The CLI never stakes, approves or assigns tokens. Before it unlocks the keystore
or sends anything, `mine --submit` checks the wallet's stake; an unstaked wallet
stops with exit code 4 and a plain instruction:

```text
Not staked: Stake 1M HUNTER tokens to this wallet in the app: app.proofhunter.fun/app/mine (your CLI wallet address: 0x…).
```

The CLI reads the current mining contracts from the core and submits proofs through
the mining router, sent by the mining wallet itself. `--router` pins the router
address from the release profile (the launcher passes it). A proof is submitted only
when the chain says it would be accepted for this wallet right now; otherwise the
CLI keeps mining and sends nothing. Exit code 4 means nothing was sent: `status` is
`notStaked`, `stakePending`, `waiting` or `paused`. If mining is paused on chain the
CLI prints the pause notice; `--loop` waits and resumes by itself. The old HUNTER
boost (MiningPowerCustody) is withdraw-only and no longer affects mining.
While the wallet is staked, `--loop` also sends occasional network upkeep
transactions, as the app does: each is simulated first, sent after a short random
delay, stays within `--max-fee`, and never while a proof is being submitted. They
are logged as `upkeepSent` (with `kind`) or a neutral `upkeepSkipped`, and never stop
mining. `--no-upkeep` turns them off. One-shot runs, including the launcher, never
send them.
`schedule` and `--state-file` remain legacy offline calculation tools; their token
schedule is not the current live settlement model.

See [wallet funding and gas limits](docs/getting-started.md) for the setup flow.

## Network profiles and AI agents

The network launcher in [distribution](distribution/README.md) defaults to testnet.
The mainnet protocol is live and its public addresses/runtime hashes are recorded
in the mainnet profile. Source profile templates stay disabled. The v0.3.0 release bundles contain a
matching binary and a mainnet profile pinned to that binary. Testnet stays disabled.
Mainnet mining through a released launcher requires explicit confirmation.

```sh
python3 distribution/proof-hunters --network testnet profile
python3 -m unittest discover -s distribution -p 'test_*.py'
cargo test --workspace --locked
```

Install the public [Proof Hunters Agent Skills](https://github.com/vltgoblin/proof-hunters-skills):

```sh
npx skills add vltgoblin/proof-hunters-skills --skill proof-hunters-mining
```

It uses verified v0.3.0 bundles, bounded mining calls, explicit gas budgets,
stake checks, and automatic seed refresh. Start with a read-only status
check. Installing the skill does not authorize transactions. A matching copy is
included at [agent-skills/proof-hunters-mining](agent-skills/proof-hunters-mining/SKILL.md).

## Release status

**Mainnet: live on Robinhood Chain (4663).** [Download v0.3.0](https://github.com/vltgoblin/proof-hunter-miner/releases/tag/v0.3.0) for the mining system upgraded on 28 Sep 2026; see the [changelog](CHANGELOG.md).
Verify download checksums and build attestations before use. **v0.2.3 cannot mine since
the upgrade**, and **v0.1.0 is legacy**; do not use either for mainnet NFT mining.

Each `proof-hunters-<system>.zip` includes the binary, Python 3.9+ launcher and
mainnet configuration. The raw `bproof-*` files are also available for users who
supply the explicit network options themselves. Read [the setup guide](docs/getting-started.md).

The approximately month-long collection model is a population scenario, not a
promise about one miner or the completion date.

Standalone Rust checks skip production-contract integration tests when the
monorepo contracts are absent. Those tests must also pass in the canonical
bonded-proof checkout with pinned Foundry 1.7.1 before release acceptance.
See [source provenance](docs/source-snapshot.json) and
[release verification](docs/verifying-a-release.md).

[Website](https://proofhunter.fun) · [App](https://app.proofhunter.fun) ·
[Documentation](https://doc.proofhunter.fun)

## Performance and fair mining

Workers search disjoint nonce ranges in 16,384-attempt batches. The native search
caches the fixed proof prefix, then hashes each nonce against the same canonical
Keccak and target rules. The optimization does not change difficulty, NFT supply,
challenge timing or HUNTER rules. Shared proof-vector tests protect compatibility
with browser proofs. Stronger hardware can search more nonces; equal rules do not
promise equal wins per device. The browser remains a valid mining path.

[An early signal](DISCOVER.md)

## Automatic seed refresh

An expired round is refreshed automatically when `mine --submit` is authorized and the
network allows the next round; until then the CLI waits and sends nothing. A one-shot
run sends only the refresh, reports `seedRefreshed`, and exits; invoke it again after
the seed becomes readable to mine. With `--loop`, the miner waits for the new seed and
resumes itself. Read-only commands never refresh or spend.
The refresh uses the same per-transaction `--max-fee` ceiling, has zero ETH value,
and mints no NFT. Another miner can win the refresh race; a reverted transaction
can still cost gas. Refresh fees are included in the loop's total fees.

An unresolved refresh is journaled before broadcast and reconciled on restart.
If the seed changed and no receipt is available, recovery refuses to rebroadcast
stale refresh bytes and keeps the journal for investigation. Never clear it to
force another transaction. v0.3.0 writes version 3 journals for router submissions;
version 1 and 2 journals remain readable. Do not downgrade while a journal is pending.
