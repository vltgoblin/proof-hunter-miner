---
name: proof-hunters-mining
description: Operate the Proof Hunters profile-bound CLI to inspect mining status or submit a bounded NFT mining attempt on an explicitly authorized network.
---

Use the release's `proof-hunters` launcher and its matching `bproof` binary. First locate the installed release directory; use absolute paths. Python 3.9+ is required. This skill provides instructions, not an isolated execution sandbox.

1. Run `./proof-hunters --network testnet profile`. A profile with `ready: false` means stop; do not edit it to bypass acceptance or borrow RC1/local fixture addresses.
2. Run `./proof-hunters --network testnet status`. The launcher checks the binary checksum, RPC chain ID, and deployed core/basket bytecode. These checks assume an authentic release and trusted RPC; they are not a signature or an independent chain proof.
3. Use the user's dedicated encrypted mining wallet. Wallet creation uses `./bproof wallet new --keystore PATH --recovery-out PATH` and a local hidden passphrase prompt. Never read recovery words, private keys or passphrase-file contents into model context. The human chooses and enters the passphrase. Do not upload wallet files.
4. For authorized mining use `./proof-hunters --network testnet mine --keystore PATH --max-fee-wei AMOUNT --max-attempts COUNT`. An owner-only passphrase file may be supplied by path with `--passphrase-file`; never read it. The ceiling is per transaction, in wei, not a session budget. Each call submits at most one proof; exhaustion is a normal outcome. Do not wrap calls in an unattended loop or automatically replenish gas without an explicit total-spend and run-count limit from the user.
5. Report actual JSON output: searching, exhausted, fee refused, pending, confirmed NFT ID, or failure. Searching is not a mint. Mining creates a Hunter NFT, not HUNTER tokens. The `schedule` command is legacy and must not be used to estimate live rewards.
6. If submission is unresolved, retain the keystore's durable journal. Retry through the same CLI and wallet so it reconciles the signed transaction; never delete the journal, guess a matching transaction, or create a fresh wallet to bypass it. Ctrl-C stops the foreground process. A stopped process may still have a submitted transaction.

## Mainnet transition
Use `--network mainnet` only after the user explicitly selects mainnet and a released, verified mainnet profile exists. Mining also requires `--confirm-mainnet`. Separate network keystores/journals are recommended. Testnet authorization does not authorize mainnet spending. Profiles are public release configuration, never credentials; do not invent mainnet addresses or copy testnet addresses. Keep reporting mainnet as unavailable while its profile is disabled.
