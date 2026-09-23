# Mainnet CLI release review — 2026-09-23

- PR #4 was merged; its 16,384-attempt worker batches are retained.
- v0.2.0 adds cached Keccak proof prefixes. The unchanged reference proof_digest remains the oracle; regression tests compare 8,192 nonce/domain combinations, including uint64/128/256 rollover.
- Raw offline single-thread VPS samples are in prefix-benchmark.txt. Six rounds alternate reference/cached order, 500,000 attempts per sample. Checksums agree. These are host-specific microbenchmarks, not live win rates or population calibration.
- Launcher bundles bind their actual platform binary checksum and live mainnet contract code hashes. Source templates remain disabled; testnet is not enabled. The launcher requires explicit mainnet submission confirmation and a per-transaction fee ceiling.
- Mining rules and contracts are unchanged: no client identity preference, no supply or difficulty adjustment. Compute throughput differs by hardware. Native Mining Power boost support remains a documented limitation.
- Repository history scan found two checksum false positives in docs/source-snapshot.json, both on the SHA-256 of keystore.rs. No credential was found. Scanned GitHub issue bodies and issue comments had no findings. This is a bounded exposure review, not a security audit.
- Native unit tests and clippy passed. Launcher/package tests passed (14). Canonical contract-backed acceptance and release asset verification are recorded separately before publication.
