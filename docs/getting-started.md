# Mainnet wallet and mining setup

## Choose the available mining path

The [browser miner](https://app.proofhunter.fun/app/mine) and mainnet protocol are live.
Use the **v0.2.3** CLI release or current reviewed source. **v0.1.0 is legacy** and
must not be used for NFT mining.

## Download a release bundle

Get `proof-hunters-<system>.zip` and `SHA256SUMS` from
[the v0.2.3 release](https://github.com/vltgoblin/proof-hunter-miner/releases/tag/v0.2.3).
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
./target/release/bproof status --rpc-url "$RPC_URL" --chain-id "$CHAIN_ID" --mining-core "$MINING_CORE" --json
```

Status is read-only and needs no wallet. Compare these settings with the [mainnet manifest](https://app.proofhunter.fun/release.json).

## Create and fund a dedicated wallet

```sh
./target/release/bproof wallet new --keystore ./mainnet-miner.json --recovery-out ./mainnet-recovery.txt
./target/release/bproof wallet address --keystore ./mainnet-miner.json --json
```

Choose the passphrase locally. Keep the recovery file private and offline. Send a deliberately limited amount of **mainnet ETH** from MetaMask to the printed mining address. The CLI signs with this wallet, and accepted proofs mint NFTs to it. HUNTER, USDG and NVDA are not gas, and holding them is not required to start base mining.

## Authorise one bounded search

This is a transaction-capable command. Choose a per-transaction fee ceiling before running it:

```sh
export MAX_TOTAL_FEE_WEI=100000000000000
./target/release/bproof mine --submit --rpc-url "$RPC_URL" --chain-id "$CHAIN_ID" --mining-core "$MINING_CORE" --basket "$BASKET" --keystore ./mainnet-miner.json --max-fee "$MAX_TOTAL_FEE_WEI" --max-attempts 1000000 --threads 2 --json
```

The example ceiling is 0.0001 ETH, not a recommended budget. `--max-fee` caps total gas exposure for **one transaction**, not gas price or cumulative session spending. The release launcher calls this option `--max-fee-wei`. A search may finish without finding a proof.

The native `--loop` option has no total-run spending cap. Do not treat the per-transaction limit as a run-wide budget. Preserve pending journals after crashes or uncertain RPC replies so the CLI can reconcile the exact signed transaction.

## Mining Power and agents

The CLI automatically uses Mining Power assigned to its mining wallet. HUNTER must be deposited in MiningPowerCustody and assigned to the exact address printed by `bproof wallet address`. The app’s current assignment shortcut selects its browser mining wallet; it cannot target a different CLI wallet. New assignments apply from the next challenge; loose balances do not count. No assignment means 1x. Continuous `searchStarted` events report `baseTarget`, effective `target`, and `powerMultiplierWad` (1e18 = 1x). The CLI does not sign token approvals, deposits or assignments.

An agent needs an explicitly selected network, a bounded run count and a spending limit. Never paste a private key, passphrase or recovery phrase into chat. The agent skill is operating guidance, not an isolation boundary or evidence of a released binary.

## Use the packaged launcher for a bounded submission

After creating and funding your dedicated wallet, explicitly authorize a mainnet
submission and set your own fee ceiling:

```sh
python3 proof-hunters --network mainnet mine --confirm-mainnet --keystore ./mainnet-miner.json --max-fee-wei 100000000000000 --max-attempts 1000000 --threads 2
```

This performs at most one proof submission. The fee is an example, not a recommended
spend. It never silently switches networks. A failed proof search can return no NFT.

## Assign power to a CLI wallet

Check the CLI wallet address first. Using your funding wallet and a contract interface
that lets you choose the mining recipient, the contract sequence is:

1. Approve the verified MiningPowerCustody address to spend the exact HUNTER amount.
2. Call `deposit(amount)` on that custody from the funding wallet.
3. Call `assign(cliMiningWallet, amount)` from the same funding wallet.

Use raw token units (HUNTER has 18 decimals). Read the custody address from the
verified core's `miningPower()` and verify its `HUNTER()` matches the canonical
token before approving. Keep the funding wallet distinct from the mining wallet.
The existing app button targets the browser wallet, so do not use it for a
different CLI address. The CLI itself does not sign these custody transactions.
Once assigned and eligible, `mine` uses the boost automatically.

## Automatic seed refresh

Expired seeds are refreshed automatically when `mine --submit` is authorized.
A one-shot run sends only the refresh, reports `seedRefreshed`, and exits; invoke
it again after the seed becomes readable to mine. With `--loop`, the miner waits
for the new seed and resumes itself. Read-only commands never refresh or spend.
The refresh uses the same per-transaction `--max-fee` ceiling, has zero ETH value,
and mints no NFT. Another miner can win the refresh race; a reverted transaction
can still cost gas. Refresh fees are included in the loop's total fees.

An unresolved refresh is journaled before broadcast and reconciled on restart.
If the seed changed and no receipt is available, recovery refuses to rebroadcast
stale refresh bytes and keeps the journal for investigation. Never clear it to
force another transaction. Version 2 journals support proof and refresh calls;
existing version 1 proof journals remain readable.
