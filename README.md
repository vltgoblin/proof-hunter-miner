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
Use an approved deployment's chain ID, core and admitted basket addresses. Do not
copy addresses from test fixtures into a public deployment.

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

The search uses the core's base target. It does not optimize mining for an attached
NFT's boosted effective target. `schedule` and `--state-file` remain legacy offline
calculation tools; their token schedule is not the current live settlement model.

See [wallet funding and gas limits](docs/getting-started.md) for the setup flow.

## Network profiles and AI agents

The network launcher in [distribution](distribution/README.md) defaults to testnet.
Both profiles are disabled pending acceptance. Mainnet uses its own verified
configuration and explicit confirmation; it never inherits testnet addresses.

```sh
python3 distribution/proof-hunters --network testnet profile
python3 -m unittest discover -s distribution -p 'test_*.py'
cargo test --workspace --locked
```

Install [the mining skill](agent-skills/proof-hunters-mining/SKILL.md) in your
agent's skill directory. It uses bounded mining calls and an explicit gas ceiling.

## Release status

This source update is an RC2 candidate. The existing **v0.1.0 release is legacy**
and is not the NFT-only RC2 miner. Do not use its old contract addresses for RC2.
No accepted RC2 binary or active network profile is supplied by this change.
The approximate 30-day collection model is a calibration target, not a promise
about an individual miner or completion date.

Standalone Rust checks skip production-contract integration tests when the
monorepo contracts are absent. Those tests must also pass in the canonical
bonded-proof checkout with pinned Foundry 1.7.1 before release acceptance.
See [source provenance](docs/source-snapshot.json) and
[release verification](docs/verifying-a-release.md).

[Website](https://proofhunter.fun) · [App](https://app.proofhunter.fun) ·
[Documentation](https://doc.proofhunter.fun)
