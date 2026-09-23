# Verify a miner release

**Mainnet:** chain 4663. Use v0.2.1 for NFT mining; v0.1.0 is legacy.
Download from the exact release tag and verify the files below before execution.
If that release is not published yet, use a reviewed source build instead.

The binary release workflow produces five `bproof` binaries, five matching `proof-hunters-<system>.zip` launcher bundles and a `SHA256SUMS` file:

| System | Release file |
|---|---|
| macOS on Apple silicon | `bproof-macos-aarch64` |
| macOS on Intel | `bproof-macos-x86_64` |
| Linux on x86-64 | `bproof-linux-x86_64` |
| Linux on ARM64 | `bproof-linux-aarch64` |
| Windows on x86-64 | `bproof-windows-x86_64.exe` |

Download the file for your system and `SHA256SUMS` from the
[GitHub Releases page](https://github.com/vltgoblin/proof-hunter-miner/releases).
Replace `vX.Y.Z` below with the release tag that you want. You can also download
both files with GitHub CLI:

```sh
gh release download vX.Y.Z \
  --repo vltgoblin/proof-hunter-miner \
  --pattern bproof-macos-aarch64 \
  --pattern SHA256SUMS
```

The same checks apply to each ZIP bundle: substitute its exact filename in the
commands below. Bundles contain a profile with the SHA-256 of their own binary;
profiles from different platforms are not interchangeable.

## Verify the build provenance

GitHub Actions signs each release file with a short-lived Sigstore identity. No
project signing key or stored signing secret is involved. Install and sign in to
[GitHub CLI](https://cli.github.com/), then run:

```sh
gh attestation verify bproof-macos-aarch64 \
  --repo vltgoblin/proof-hunter-miner
```

Change the file name for your system. A pass prints `Verification succeeded`
with a check mark and identifies `vltgoblin/proof-hunter-miner` as the source
repository. It also reports the signing workflow. A non-zero exit status or a
verification error is a failure. Do not run that file.

For a stricter check, require this repository's release workflow as the signer:

```sh
gh attestation verify bproof-macos-aarch64 \
  --repo vltgoblin/proof-hunter-miner \
  --signer-workflow vltgoblin/proof-hunter-miner/.github/workflows/release.yml
```

This verification proves that the file's SHA-256 digest was produced by the
public release workflow from the commit named in the attestation.

## Check SHA256SUMS

The checksum is a quick way to detect an incomplete or changed download. On
macOS or Linux, run this command from the directory that contains both files:

```sh
grep '  bproof-macos-aarch64$' SHA256SUMS | shasum -a 256 -c -
```

A pass prints `bproof-macos-aarch64: OK`. You can also calculate the digest and
compare it with the matching line in `SHA256SUMS`:

```sh
shasum -a 256 bproof-macos-aarch64
grep '  bproof-macos-aarch64$' SHA256SUMS
```

On Windows PowerShell:

```powershell
$file = "bproof-windows-x86_64.exe"
$expected = ((Select-String -Path SHA256SUMS -Pattern "  $file$").Line -split "\s+")[0]
$actual = (Get-FileHash $file -Algorithm SHA256).Hash.ToLowerInvariant()
$actual -eq $expected
```

A pass prints `True`. A matching checksum only proves that the file matches the
release manifest. The attestation check also proves which repository and
workflow produced it.

After both checks pass, macOS and Linux users can make the downloaded file
executable:

```sh
chmod 0755 bproof-macos-aarch64
```

## Inspect embedded dependencies

The release workflow builds with `cargo-auditable`, so every binary contains its
exact Rust dependency tree. Install the pinned scanner and inspect the binary:

```sh
cargo install cargo-audit --version '=0.22.2' --locked
cargo audit bin ./bproof-macos-aarch64
```

The command lists embedded dependencies and checks them against the current
RustSec advisory database.

## Build from source

For the trust-nothing path, inspect the tagged source and build it yourself:

```sh
git clone --branch vX.Y.Z --depth 1 \
  https://github.com/vltgoblin/proof-hunter-miner.git
cd proof-hunter-miner
cargo build --release --locked --bin bproof
```

`--locked` makes Cargo use the committed `Cargo.lock`. The repository also pins
the Rust toolchain in `rust-toolchain.toml`.

The published files contain extra dependency metadata, so a plain `cargo build`
is not a byte-for-byte equivalent of the release build. To reproduce the release
command, install the same `cargo-auditable` version and use the target triple for
your system:

```sh
cargo install cargo-auditable --version '=0.7.5' --locked
cargo auditable build --release --locked \
  --target aarch64-apple-darwin \
  --bin bproof
shasum -a 256 target/aarch64-apple-darwin/release/bproof
shasum -a 256 ../bproof-macos-aarch64
```

Change the target and file name using the table above. A byte-for-byte match is
useful when it occurs, but it is not guaranteed across different operating
system images and linkers. The provenance attestation is the authoritative link
between the published binary and its public source commit.
