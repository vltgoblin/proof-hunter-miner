# Proof Hunters network launcher

Release candidate tooling, not a cleared public miner. Requires Python 3.9+ and
a matching native `bproof` binary. Both shipped profiles are disabled until their
network acceptance completes. This wrapper leaves the core miner unchanged.

## Commands

```sh
./proof-hunters --network testnet profile
./proof-hunters --network testnet status
./proof-hunters --network testnet mine --keystore ./testnet-wallet.json --max-fee-wei 100000000000000 --max-attempts 1000000
```

The fee above is a syntax example, not a recommended budget. The limit is per
transaction. Each call submits at most one proof, never an unbounded mining loop.
Use `bproof wallet new --help` to create a dedicated encrypted wallet. Never put
private keys or passphrases in profiles or command arguments. Do not delete a
pending transaction journal to retry a transfer.

## Release activation

1. Freeze and test the exact RC2 source and native binary in the main release
   workstream. Complete the controlled testnet deployment and required pilot.
2. Populate `profiles/testnet.json` from the accepted deployment: chain ID, public
   HTTPS RPC, mining core, basket, and SHA-256 hashes of their raw runtime bytecode.
   Hash decoded bytes, not the hexadecimal text.
3. Package the matching native binary as `bproof`. Its SHA-256 must equal
   `binarySha256`. Publish separate packages and checksums per operating system
   and architecture. Set `ready: true` only after acceptance; remove the blocker
   reason. The profile is public configuration, not an authenticity signature.
4. Run launcher status and one owner-authorized bounded proof; verify the NFT's
   canonical receipt and ownership. Then publish the accepted release/checksums
   and update the public download page. Do not label candidate archives as ready.

## Mainnet later

Keep the same command interface, selecting `--network mainnet`. Populate the
separate mainnet profile from its own accepted deployment and code hashes, never
from the testnet profile. Mainnet mining additionally requires
`--confirm-mainnet`. Use a separately funded wallet/journal. There is no automatic
RPC fallback or testnet-to-mainnet switch. A missing/unapproved profile refuses
before any wallet is opened. A user editing a profile can change these checks;
the launcher is not a substitute for trusting the release distributor and RPC.

## Agent skill

The repository's `agent-skills/proof-hunters-mining/SKILL.md` is model-neutral.
Install the directory in the skill location used by your agent. It invokes this
launcher, not the older private `hunter-operator` package, and does not require
an Anthropic API key. An agent skill is instructions, not a key-isolation sandbox.

## Verification

`python3 -m unittest discover -s distribution -p 'test_*.py'`

Tests use dummy binaries and mocked RPC. They do not establish native miner or
public-chain acceptance. Public profiles intentionally remain disabled.
