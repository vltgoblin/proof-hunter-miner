# CLI Mining Power acceptance — 2026-09-23

Version: v0.2.2 candidate. No production contract changes or public-chain transactions.

Live `mine`, `mine --submit`, continuous mining, and `submit` now read the
core-selected Mining Power module and the exact challenge/mining-wallet
multiplier at the same RPC block as the challenge. Arithmetic matches the
core's integer rounding, multiplier clamp and MAX_TARGET saturation. NFT
classification includes the bonus window. No module means base power;
failed/malformed power reads fail closed. Continuous search events expose
baseTarget, target and powerMultiplierWad. `status` without a miner remains
base network state, not a wallet power preview.

## Evidence

- Canonical workspace release tests: 110 passed; no failed, ignored or skipped live checks.
- Real local production-contract composition: create mining wallet, activate fixture
  token/custody, deposit and assign. Open challenge stays 1x; next challenge reads
  2x. Another unassigned wallet stays 1x. CLI finds a contract-derived digest
  above the base target, classifies it as an NFT, submits it, and verifies
  the resulting NFT ownership. Existing continuous two-proof test also passes.
- Unit tests: full uint256 arithmetic, fractional multiplier, saturation rounding,
  3x clamp, same-block module reads, malformed word/RPC failure refusal.
- Launcher and packaging tests: 15 passed.
- Strict clippy: see attached log.

The original debug-profile loop test had a five-second event timeout after
`started`; the optimized release-profile full suite passes without loosening
its assertions or timeouts. Preserve that distinction: release acceptance is
against the optimized binary. A separate fixture race read a funding receipt
before it existed; the harness now polls its exact local transaction hash and
still requires successful receipt status. No production guard was changed.

## User flow and boundaries

Use the app to lock/assign HUNTER to the CLI wallet address. This release consumes
existing assigned power; it does not create token approvals/deposits/assignments.
New assignments take effect from the next challenge. Loose balances do not count.
Native Windows remains read-only; Windows mining requires WSL2/Linux wallet storage.
No live user miner was stopped or replaced. Browser optimization is separate.
GitHub build/publication and installed user binaries require separate verification.
