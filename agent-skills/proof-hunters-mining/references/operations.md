# Setup and operations

## Verify the release

Use the platform ZIP from [v0.2.3](https://github.com/vltgoblin/proof-hunter-miner/releases/tag/v0.2.3), which contains `bproof`, the Python launcher, and matching profiles. Verify the ZIP against the release's `SHA256SUMS` **and** its GitHub build attestation before running it:

```sh
gh attestation verify /absolute/path/to/downloaded.zip --repo vltgoblin/proof-hunter-miner
```

Follow the CLI's [release verification guide](https://github.com/vltgoblin/proof-hunter-miner/blob/main/docs/verifying-a-release.md), including expected tag/workflow identity. A checksum alone does not authenticate a download. Do not silently switch to a newer release without reviewing interface changes. Do not use v0.1.0 for mainnet.

Python 3.9+ is required. Mining runs on Linux/macOS. On Windows, use WSL2 with the Linux package and keep the keystore in the Linux home directory; native Windows wallet unlocking is unsupported. If ZIP extraction removed the verified binary's executable bit, restore it with `chmod 755 /absolute/path/to/release/bproof`.

`RELEASE_DIR` below means the extracted directory containing `proof-hunters`, `bproof`, and `profiles/`; it is not the skill directory. Set it to the verified absolute path. These commands do not require rebuilding Rust.

## Read-only checks

```sh
python3 "$RELEASE_DIR/proof-hunters" --network mainnet profile
python3 "$RELEASE_DIR/proof-hunters" --network mainnet status
```

`profile` displays configuration. `status` checks the binary checksum, RPC chain ID, and deployed core/basket runtime hashes before querying mining state. These checks rely on an authentic release and trusted RPC; they are not an independent chain proof. Public configuration is also available at [release.json](https://app.proofhunter.fun/release.json). Never copy testnet/RC fixtures into a mainnet profile.

An expired or not-yet-readable seed can produce `challenge unavailable` with exit code 2. It is not a confirmed mint or an authorization to spend. Check the actual error before diagnosing the network as disabled.

## Wallet preparation

A human can create a fresh dedicated wallet from their local terminal:

```sh
"$RELEASE_DIR/bproof" wallet new --keystore /private/path/miner-wallet.json --recovery-out /private/path/miner-recovery.txt
```

They choose and enter the passphrase at the hidden prompt and preserve the recovery file privately. Never overwrite an existing wallet. Do not open either recovery or passphrase files in agent tools. Fund the public mining address with ETH on the selected network only under the user's transfer authorization. Do not assume a browser wallet is present on a VPS or that backing it up in one browser backs up the CLI wallet.

## One bounded mainnet call

The variables below are placeholders for **explicitly authorized** values, not suggested budgets. `KEYSTORE_PATH` and any passphrase path must refer to the user's existing dedicated CLI wallet. `MAX_FEE_WEI` is a positive integer in wei; `MAX_ATTEMPTS` and `THREADS` are positive integers.

```sh
python3 "$RELEASE_DIR/proof-hunters" --network mainnet mine \
  --confirm-mainnet \
  --keystore "$KEYSTORE_PATH" \
  --max-fee-wei "$MAX_FEE_WEI" \
  --max-attempts "$MAX_ATTEMPTS" \
  --threads "$THREADS"
```

An authorized unattended call may append `--passphrase-file "$PASSPHRASE_FILE_PATH"`; pass only the path, never its contents. The launcher performs profile checks and submits at most one transaction per ordinary call: either a proof or an expired-seed refresh. `--max-attempts` limits hashing, not gas. Recovery may reconcile an earlier journaled transaction before a new attempt, so treat unresolved outcomes separately and never assume a retry is free or safe to bypass.

Read both JSON and exit status. Exit 0 alone does not prove a mint: `seedRefreshed` has `proofClassification: seedRefresh` and `nftTokenId: null`. Exit 1 can mean exhausted search, 2 can mean an error/unavailable challenge, and 3 can mean fee refusal. Inspect the actual output. Do not invent balances, hash rates, proof IDs, transaction hashes, or confirmations.

For repeated calls, keep a run ledger with authorized ceilings, calls used, confirmed results, and unresolved transactions. Reserve the full fee ceiling per new call; never exceed the authorized total. Stop on unknown submission, lost RPC replies, or journal failure. Do not start another call just because a process timed out. Rerunning the same CLI/wallet for recovery must preserve the journal and original transaction identity.

## HUNTER power and seed refresh

v0.2.3 reads assigned mining power automatically. A failed power read stops search instead of silently substituting base power. The exact CLI mining address must receive the assignment; holding HUNTER in MetaMask is insufficient. Base power still permits mining without a lock. Locking, allowances, and assignment are separate transactions requiring their own authorization and verified custody configuration. This skill does not construct those transactions.

A one-shot expired-seed refresh uses the same gas ceiling, carries zero ETH value, and exits without an NFT. Another miner may refresh first; a reverted refresh can cost gas. After confirmation, wait for the new seed to become readable and use a later authorized bounded call. Read-only status never refreshes. Preserve pending journals across restarts; never downgrade a v2 refresh journal or erase it to force progress.
