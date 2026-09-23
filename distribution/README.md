# Proof Hunters network launcher

Requires Python 3.9+ and the native `bproof` binary included in the release bundle.
Mainnet is live on chain 4663. The v0.2.0 bundles pin each platform binary and the
deployed contract bytecode. Source templates remain disabled; testnet is disabled.

## Commands

```sh
./proof-hunters --network mainnet profile
./proof-hunters --network mainnet status
./proof-hunters --network mainnet mine --confirm-mainnet --keystore ./mainnet-wallet.json --max-fee-wei 100000000000000 --max-attempts 1000000
```

The fee above is a syntax example, not a recommended budget. The limit is per
transaction. Each call submits at most one proof, never an unbounded mining loop.
Use `bproof wallet new --help` to create a dedicated encrypted wallet. Never put
private keys or passphrases in profiles or command arguments. Do not delete a
pending transaction journal to retry a transfer.

## Mainnet protocol is live; package activation remains separate

`profiles/mainnet.json` records chain 4663, the live mining core, admitted NVDA
basket and SHA-256 hashes of decoded runtime bytecode. Its `ready` flag stays
false and `binarySha256` stays empty until a matching current binary is packaged
and verified. This is a CLI distribution limit, not a mainnet launch gate.
The old v0.1.0 binary must not be used to fill this gap.

For each released OS/architecture, package the matching `bproof` binary with its
own profile/checksum and publish build provenance. Confirm local-contract tests
and read-only mainnet status against the exact source. Any mainnet submission
still needs the user's explicit spending authorization and `--confirm-mainnet`.
Do not edit `ready` or use a guessed checksum to bypass a missing release.

Use `--network mainnet` for this deployment; the default remains testnet to
avoid silently changing an existing command's spending network. There is no
RPC fallback or automatic testnet-to-mainnet switch. Profiles are configuration,
not signatures or independent chain proofs. Use separate wallet journals per network.

## Agent skill

The repository's `agent-skills/proof-hunters-mining/SKILL.md` is model-neutral.
Install the directory in the skill location used by your agent. It invokes this
launcher, not the older private `hunter-operator` package, and does not require
an Anthropic API key. An agent skill is instructions, not a key-isolation sandbox.

## Verification

`python3 -m unittest discover -s distribution -p 'test_*.py'`

Tests use dummy binaries and mocked RPC. They do not establish native miner or
public-chain acceptance. Source templates remain disabled; `package_release.py` creates a separate mainnet profile bound to the bundled binary.
