# Mainnet wallet and mining setup

## Choose the available mining path

The [browser miner](https://app.proofhunter.fun/app/mine) and mainnet protocol are live.
Use the **v0.3.0** CLI release or current reviewed source. Mining was upgraded on
28 Sep 2026; **v0.2.3 cannot mine** on the upgraded system and **v0.1.0 is legacy**.

## Download a release bundle

Get `proof-hunters-<system>.zip` and `SHA256SUMS` from
[the v0.3.0 release](https://github.com/vltgoblin/proof-hunter-miner/releases/tag/v0.3.0).
Choose `linux-x86_64`, `linux-aarch64`, `macos-aarch64`, `macos-x86_64` or
`windows-x86_64`. Follow [release verification](verifying-a-release.md) before
extracting or running it. Python 3.9+ is required for the launcher.

Inside the extracted `proof-hunters` folder:

```sh
python3 proof-hunters --network mainnet profile
python3 proof-hunters --network mainnet status
```

These commands do not spend funds. On macOS/Linux, run `chmod 755 bproof` if your
ZIP extractor did not preserve the executable bit. Windows mining requires WSL2 with the Linux package; store the wallet in the Linux
home directory. Native `bproof.exe` supports read-only commands and cannot create
or unlock mining wallets. A source profile is intentionally
disabled; the release package pins its matching binary checksum.

## Build and inspect

If you prefer building from source, clone this repository and use its pinned Rust toolchain. The native examples below use the source-build path; bundle users substitute `./bproof` (or `bproof.exe` on Windows):

```sh
cargo build --release --locked --bin bproof
./target/release/bproof --help
```

Set the verified public configuration:

```sh
export RPC_URL=https://rpc.mainnet.chain.robinhood.com
export CHAIN_ID=4663
export MINING_CORE=0xf213854c6d5d4334d23d452574556bd53ca24c2c
export BASKET=0xd0601CE157Db5bdC3162BbaC2a2C8aF5320D9EEC
export ROUTER=0x724b77b12b63217b5379c31a713017404175bac7
./target/release/bproof status --rpc-url "$RPC_URL" --chain-id "$CHAIN_ID" --mining-core "$MINING_CORE" --json
```

Status is read-only and needs no wallet. Compare these settings with the [mainnet manifest](https://app.proofhunter.fun/release.json).

## Create and fund a dedicated wallet

```sh
./target/release/bproof wallet new --keystore ./mainnet-miner.json --recovery-out ./mainnet-recovery.txt
./target/release/bproof wallet address --keystore ./mainnet-miner.json --json
```

Choose the passphrase locally. Keep the recovery file private and offline. Send a deliberately limited amount of **mainnet ETH** from MetaMask to the printed mining address. The CLI signs with this wallet, and accepted proofs mint Hunter NFTs to it. HUNTER tokens, USDG and NVDA are not gas.

## Stake to the CLI wallet

A wallet must be staked to mine. In the app at
[app.proofhunter.fun/app/mine](https://app.proofhunter.fun/app/mine), stake **1M HUNTER
tokens** to the exact address printed by `bproof wallet address`. The CLI never stakes,
approves or moves tokens for you. Stake can be withdrawn 3 days after it is added.

The CLI checks the stake before it unlocks the wallet or sends anything. If the wallet
is not staked it sends nothing, exits with code 4 and says:

```text
Not staked: Stake 1M HUNTER tokens to this wallet in the app: app.proofhunter.fun/app/mine (your CLI wallet address: 0x…).
```

New stake becomes active shortly after it lands; until then the CLI keeps mining and
says `Your stake becomes active soon. Mining continues.`

## Authorise one bounded search

This is a transaction-capable command. Choose a per-transaction fee ceiling before running it:

```sh
export MAX_TOTAL_FEE_WEI=100000000000000
./target/release/bproof mine --submit --rpc-url "$RPC_URL" --chain-id "$CHAIN_ID" --mining-core "$MINING_CORE" --basket "$BASKET" --router "$ROUTER" --keystore ./mainnet-miner.json --max-fee "$MAX_TOTAL_FEE_WEI" --max-attempts 1000000 --threads 2 --json
```

The example ceiling is 0.0001 ETH, not a recommended budget. `--max-fee` caps total gas exposure for **one transaction**, not gas price or cumulative session spending. The release launcher calls this option `--max-fee-wei`. A search may finish without finding a proof.

The CLI submits a proof only when the network would accept it from this wallet right
now, so it does not pay gas for a proof that would be refused. Another miner can still
win first, and a reverted transaction can still cost gas. A run that ends without
sending anything exits with code 4 and a plain `status`: `notStaked`, `stakePending`,
`waiting` or `paused`. `--router` pins the mining router from the release profile; the
CLI refuses to mine if the core reports a different one. Without it, the CLI reads the
router from the core.

The native `--loop` option has no total-run spending cap. Do not treat the per-transaction limit as a run-wide budget. Preserve pending journals after crashes or uncertain RPC replies so the CLI can reconcile the exact signed transaction.

## Agents and the old HUNTER boost

The old HUNTER boost (MiningPowerCustody) is withdraw-only since the 27 Sep 2026 pause:
HUNTER tokens assigned there no longer affect mining. Withdraw them from the app at any time.

An agent needs an explicitly selected network, a bounded run count and a spending limit. Never paste a private key, passphrase or recovery phrase into chat. The agent skill is operating guidance, not an isolation boundary or evidence of a released binary.

## Use the packaged launcher for a bounded submission

After creating and funding your dedicated wallet, explicitly authorize a mainnet
submission and set your own fee ceiling:

```sh
python3 proof-hunters --network mainnet mine --confirm-mainnet --keystore ./mainnet-miner.json --max-fee-wei 100000000000000 --max-attempts 1000000 --threads 2
```

This performs at most one proof submission. The fee is an example, not a recommended
spend. It never silently switches networks. A failed proof search can return no NFT.

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

## If mining is paused

If mining is paused on chain, the CLI prints the pause notice and when it ends. A
one-shot run exits with code 4; `--loop` waits and resumes by itself.
