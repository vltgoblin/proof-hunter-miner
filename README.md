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
proof digest and requested basket. RPC data remains a trust source.

Before broadcast, the CLI writes an owner-only durable journal beside the
keystore containing the exact signed transaction and the public verification
context. If the process crashes or an RPC reply is lost, the next invocation
reconciles or rebroadcasts those same signed bytes and verifies the canonical
receipt before allowing a new transaction. Corrupt, overly permissive, or
inconsistent journal state fails closed. Never delete a pending journal merely
to bypass this guard; reconcile its transaction first.

The search uses the core's base target. It does not yet search Mining Power's boosted
effective target for HUNTER assigned to a mining wallet. `schedule` and `--state-file` remain legacy offline
calculation tools; their token schedule is not the current live settlement model.

See [wallet funding and gas limits](docs/getting-started.md) for the setup flow.

## Network profiles and AI agents

The network launcher in [distribution](distribution/README.md) defaults to testnet.
The mainnet protocol is live and its public addresses/runtime hashes are recorded
in the mainnet profile. Source profile templates stay disabled. The v0.2.0 release bundles contain a
matching binary and a mainnet profile pinned to that binary. Testnet stays disabled.
Mainnet mining through a released launcher requires explicit confirmation.

```sh
python3 distribution/proof-hunters --network testnet profile
python3 -m unittest discover -s distribution -p 'test_*.py'
cargo test --workspace --locked
```

Install [the mining skill](agent-skills/proof-hunters-mining/SKILL.md) in your
agent's skill directory. It uses bounded mining calls and an explicit gas ceiling.

## Release status

**Mainnet: live on Robinhood Chain (4663).** Download the current **v0.2.0**
package from [Releases](https://github.com/vltgoblin/proof-hunter-miner/releases/tag/v0.2.0)
and verify its checksum and build attestation before use. The older **v0.1.0 is
legacy** and must not be used for mainnet NFT mining. If v0.2.0 is not available,
build the current source; never substitute a v0.1.0 binary.

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
