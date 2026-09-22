# Set up and fund your miner

RC2 is a candidate. Wait for an accepted release and enabled testnet profile before
sending funds for this release. Old v0.1.0 binaries target the previous model.

## 1. Create a mining wallet

From the verified release directory:

```sh
./bproof wallet new --keystore ./testnet-wallet.json --recovery-out ./testnet-recovery.txt
./bproof wallet address --keystore ./testnet-wallet.json --json
```

Enter your passphrase locally. Keep the recovery file offline and private. The
address is public; do not share the keystore, passphrase, or recovery words.

## 2. Transfer test ETH

In MetaMask, select Robinhood Chain Testnet (chain 46630). Send test ETH to the
address printed above. Check the full destination and network before confirming.
Wait for the transfer receipt. The CLI does not pull funds from MetaMask or need
an allowance. The selected basket is proof configuration, not the gas currency;
you do not need to transfer basket tokens merely to pay mining gas.

Use your wallet or the network explorer to check that the mining address received
the ETH. The CLI currently has no dedicated funding or balance command.

## 3. Set the fee ceiling and mine

```sh
./proof-hunters --network testnet status
./proof-hunters --network testnet mine --keystore ./testnet-wallet.json --max-fee-wei 100000000000000 --max-attempts 1000000
```

This example ceiling is 0.0001 ETH per transaction, not a recommended amount.
The miner estimates gas and refuses a submission if the padded exposure exceeds
the ceiling. Network gas is paid even if a transaction reverts. This is not a
protocol reward setting, mining difficulty control, or total session budget.
Each launcher call submits at most one proof. Set an explicit total spending
budget before repeating calls; the native CLI's `--loop` has no total-run cap.

An accepted proof creates an NFT; it does not pay liquid HUNTER tokens. Verify
the reported transaction and NFT ownership. A search that finds no proof is not
a failed transfer. Keep any pending transaction journal intact for recovery.

## Mainnet later

Use a separately approved mainnet release/profile and wallet. Select
`--network mainnet` and explicitly add `--confirm-mainnet` for mining. Never
replace testnet addresses manually or assume testnet ETH works on mainnet.
