//! Wallet-bound Keccak proof rules from the accepted Secure Mining Design.
//!
//! Field order and target comparison come from
//! `docs/product/bonded-proof/secure-mining-design-v0.1.md`. The canonical type
//! strings, typehashes, and proof version are frozen in section 8.2 of
//! `docs/product/bonded-proof/contract-rulebook-v0.1.md`.

use sha3::{Digest as _, Keccak256};

const ABI_WORD_BYTES: usize = 32;
const PREIMAGE_WORDS: usize = 8;

/// The byte length of either canonical ABI-encoded preimage.
pub const PREIMAGE_BYTES: usize = ABI_WORD_BYTES * PREIMAGE_WORDS;

/// The canonical proof type string recorded in the contract rulebook.
pub const PROOF_TYPE_STRING: &str = "BondedProofV1(uint256 chainId,address miningCore,uint256 proofVersion,uint256 challengeId,bytes32 challenge,address miner,uint256 nonce)";

/// The canonical challenge type string recorded in the contract rulebook.
pub const CHALLENGE_TYPE_STRING: &str = "BondedChallengeV1(uint256 chainId,address miningCore,uint256 proofVersion,uint256 challengeId,bytes32 previousAcceptedDigest,uint256 seedParentBlock,bytes32 seedBlockhash)";

/// A Solidity `uint256` represented as one big-endian ABI word.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Uint256([u8; ABI_WORD_BYTES]);

impl Uint256 {
    /// Zero as a Solidity `uint256`.
    pub const ZERO: Self = Self([0; ABI_WORD_BYTES]);

    /// One as a Solidity `uint256`.
    pub const ONE: Self = Self([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ]);

    /// Creates a `uint256` from its full big-endian representation.
    #[must_use]
    pub const fn from_be_bytes(bytes: [u8; ABI_WORD_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the full big-endian representation.
    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; ABI_WORD_BYTES] {
        self.0
    }

    /// Adds two words modulo 2^256.
    #[must_use]
    pub const fn wrapping_add(self, rhs: Self) -> Self {
        let mut result = [0; ABI_WORD_BYTES];
        let mut carry = 0_u16;
        let mut index = ABI_WORD_BYTES;

        while index > 0 {
            index -= 1;
            let sum = self.0[index] as u16 + rhs.0[index] as u16 + carry;
            result[index] = sum as u8;
            carry = sum >> 8;
        }

        Self(result)
    }
}

impl From<u64> for Uint256 {
    fn from(value: u64) -> Self {
        let mut bytes = [0; ABI_WORD_BYTES];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Self(bytes)
    }
}

impl From<u128> for Uint256 {
    fn from(value: u128) -> Self {
        let mut bytes = [0; ABI_WORD_BYTES];
        bytes[16..].copy_from_slice(&value.to_be_bytes());
        Self(bytes)
    }
}

/// A Solidity address in its canonical 20-byte representation.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Address([u8; 20]);

impl Address {
    /// Creates an address from its canonical 20 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical 20-byte representation.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 20] {
        self.0
    }
}

/// A Keccak-256 digest or another canonical Solidity `bytes32` value.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Digest([u8; ABI_WORD_BYTES]);

impl Digest {
    /// The all-zero digest.
    pub const ZERO: Self = Self([0; ABI_WORD_BYTES]);

    /// Creates a digest from its canonical bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ABI_WORD_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical digest bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; ABI_WORD_BYTES] {
        self.0
    }
}

/// A 256-bit unsigned proof target in big-endian numeric order.
///
/// This type models a target but deliberately defines no minimum, maximum, or
/// genesis value. Those values belong to the deployment configuration.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Target([u8; ABI_WORD_BYTES]);

impl Target {
    /// Creates a target from its full big-endian representation.
    #[must_use]
    pub const fn from_be_bytes(bytes: [u8; ABI_WORD_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the full big-endian representation.
    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; ABI_WORD_BYTES] {
        self.0
    }
}

/// The decided immutable proof version.
pub const PROOF_VERSION: Uint256 = Uint256::ONE;

/// Keccak-256 of [`PROOF_TYPE_STRING`], as recorded in the rulebook.
pub const PROOF_TYPEHASH: Digest = Digest::from_bytes([
    0xdf, 0x48, 0x04, 0x9c, 0x80, 0x32, 0xf0, 0x61, 0xc4, 0x7a, 0x9b, 0x74, 0xb3, 0xf5, 0x45, 0x16,
    0xba, 0x0b, 0x83, 0x39, 0x56, 0x0b, 0xd2, 0x3c, 0x99, 0xb0, 0xc5, 0xd4, 0x50, 0x61, 0x39, 0x3a,
]);

/// Keccak-256 of [`CHALLENGE_TYPE_STRING`], as recorded in the rulebook.
pub const CHALLENGE_TYPEHASH: Digest = Digest::from_bytes([
    0xe0, 0xe8, 0x2b, 0x0a, 0x91, 0x88, 0x73, 0x86, 0xe1, 0x6d, 0x42, 0x09, 0x17, 0x0f, 0x8f, 0x80,
    0x21, 0x63, 0x18, 0xfc, 0x95, 0xf9, 0x02, 0xa4, 0xa5, 0xab, 0x3f, 0x18, 0xcf, 0x5b, 0x0c, 0x5b,
]);

/// Inputs to the canonical challenge derivation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChallengeInputs {
    pub chain_id: Uint256,
    pub mining_core: Address,
    pub challenge_id: Uint256,
    pub previous_accepted_digest: Digest,
    pub seed_parent_block: Uint256,
    pub seed_blockhash: Digest,
}

/// Inputs to the canonical wallet-bound proof digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofInputs {
    pub chain_id: Uint256,
    pub mining_core: Address,
    pub challenge_id: Uint256,
    pub challenge: Digest,
    pub miner: Address,
    pub nonce: Uint256,
}

/// Computes legacy Ethereum Keccak-256, not FIPS SHA3-256.
#[must_use]
pub fn keccak256(input: &[u8]) -> Digest {
    let hash = Keccak256::digest(input);
    let mut bytes = [0; ABI_WORD_BYTES];
    bytes.copy_from_slice(&hash);
    Digest(bytes)
}

/// Returns the exact `abi.encode` preimage for a challenge.
#[must_use]
pub fn challenge_preimage(inputs: &ChallengeInputs) -> [u8; PREIMAGE_BYTES] {
    let mut preimage = [0; PREIMAGE_BYTES];
    let mining_core = address_word(inputs.mining_core);

    write_word(&mut preimage, 0, CHALLENGE_TYPEHASH.0);
    write_word(&mut preimage, 1, inputs.chain_id.0);
    write_word(&mut preimage, 2, mining_core);
    write_word(&mut preimage, 3, PROOF_VERSION.0);
    write_word(&mut preimage, 4, inputs.challenge_id.0);
    write_word(&mut preimage, 5, inputs.previous_accepted_digest.0);
    write_word(&mut preimage, 6, inputs.seed_parent_block.0);
    write_word(&mut preimage, 7, inputs.seed_blockhash.0);
    preimage
}

/// Derives the active challenge from the canonical challenge inputs.
#[must_use]
pub fn derive_challenge(inputs: &ChallengeInputs) -> Digest {
    keccak256(&challenge_preimage(inputs))
}

/// Returns the exact `abi.encode` preimage for a wallet-bound proof.
#[must_use]
pub fn proof_preimage(inputs: &ProofInputs) -> [u8; PREIMAGE_BYTES] {
    let mut preimage = [0; PREIMAGE_BYTES];
    let mining_core = address_word(inputs.mining_core);
    let miner = address_word(inputs.miner);

    write_word(&mut preimage, 0, PROOF_TYPEHASH.0);
    write_word(&mut preimage, 1, inputs.chain_id.0);
    write_word(&mut preimage, 2, mining_core);
    write_word(&mut preimage, 3, PROOF_VERSION.0);
    write_word(&mut preimage, 4, inputs.challenge_id.0);
    write_word(&mut preimage, 5, inputs.challenge.0);
    write_word(&mut preimage, 6, miner);
    write_word(&mut preimage, 7, inputs.nonce.0);
    preimage
}

/// Derives the wallet-bound proof digest from the canonical proof inputs.
#[must_use]
pub fn proof_digest(inputs: &ProofInputs) -> Digest {
    keccak256(&proof_preimage(inputs))
}

/// Reuses the fixed 224-byte proof prefix across nonce attempts.
///
/// This is the same Keccak computation as `proof_digest`: the cached state
/// includes the complete first absorption block and the buffered prefix tail.
/// Only the final ABI word (nonce) varies; no domain or target rule changes.
#[derive(Clone)]
pub struct PreparedProof {
    prefix: Keccak256,
}

impl PreparedProof {
    #[must_use]
    pub fn new(inputs: &ProofInputs) -> Self {
        let preimage = proof_preimage(inputs);
        let mut prefix = Keccak256::new();
        prefix.update(&preimage[..PREIMAGE_BYTES - ABI_WORD_BYTES]);
        Self { prefix }
    }

    #[must_use]
    pub fn digest(&self, nonce: Uint256) -> Digest {
        let mut hasher = self.prefix.clone();
        hasher.update(nonce.to_be_bytes());
        let hash = hasher.finalize();
        let mut bytes = [0; ABI_WORD_BYTES];
        bytes.copy_from_slice(&hash);
        Digest(bytes)
    }
}

/// Returns whether the digest satisfies the inclusive proof target.
#[must_use]
pub fn meets_target(digest: Digest, target: Target) -> bool {
    digest.0 <= target.0
}

/// Derives the challenge and wallet-bound digest, then checks the target.
#[must_use]
pub fn check_proof(
    challenge_inputs: &ChallengeInputs,
    miner: Address,
    nonce: Uint256,
    target: Target,
) -> bool {
    let proof_inputs = ProofInputs {
        chain_id: challenge_inputs.chain_id,
        mining_core: challenge_inputs.mining_core,
        challenge_id: challenge_inputs.challenge_id,
        challenge: derive_challenge(challenge_inputs),
        miner,
        nonce,
    };

    meets_target(proof_digest(&proof_inputs), target)
}

fn address_word(address: Address) -> [u8; ABI_WORD_BYTES] {
    let mut word = [0; ABI_WORD_BYTES];
    word[12..].copy_from_slice(&address.0);
    word
}

fn write_word(preimage: &mut [u8; PREIMAGE_BYTES], index: usize, word: [u8; ABI_WORD_BYTES]) {
    let start = index * ABI_WORD_BYTES;
    preimage[start..start + ABI_WORD_BYTES].copy_from_slice(&word);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorded_typehashes_recompute_from_the_canonical_strings() {
        assert_eq!(direct_keccak(PROOF_TYPE_STRING.as_bytes()), PROOF_TYPEHASH);
        assert_eq!(
            direct_keccak(CHALLENGE_TYPE_STRING.as_bytes()),
            CHALLENGE_TYPEHASH
        );
    }

    #[test]
    fn challenge_matches_independent_abi_encoding_and_is_deterministic() {
        let inputs = challenge_fixture();
        let expected = manual_challenge_digest(&inputs);

        assert_eq!(derive_challenge(&inputs), expected);
        assert_eq!(derive_challenge(&inputs), expected);
    }

    #[test]
    fn two_full_proof_vectors_match_independent_abi_encoding() {
        let challenge_inputs = challenge_fixture();
        let challenge = manual_challenge_digest(&challenge_inputs);
        let vectors = [
            (Address::from_bytes([0x11; 20]), Uint256::from(7_u64)),
            (
                Address::from_bytes([
                    0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                ]),
                Uint256::from_be_bytes([0xff; ABI_WORD_BYTES]),
            ),
        ];

        for (miner, nonce) in vectors {
            let proof_inputs = ProofInputs {
                chain_id: challenge_inputs.chain_id,
                mining_core: challenge_inputs.mining_core,
                challenge_id: challenge_inputs.challenge_id,
                challenge,
                miner,
                nonce,
            };
            let expected = manual_proof_digest(&proof_inputs);

            assert_eq!(proof_digest(&proof_inputs), expected);
            assert!(check_proof(
                &challenge_inputs,
                miner,
                nonce,
                Target::from_be_bytes(expected.to_bytes())
            ));
        }
    }

    #[test]
    fn a_nonce_valid_for_one_wallet_fails_for_another_wallet() {
        let challenge_inputs = challenge_fixture();
        let nonce = Uint256::from(42_u64);
        let first_wallet = Address::from_bytes([0x11; 20]);
        let second_wallet = Address::from_bytes([0x22; 20]);
        let first_digest = digest_for(&challenge_inputs, first_wallet, nonce);
        let second_digest = digest_for(&challenge_inputs, second_wallet, nonce);
        assert_ne!(first_digest, second_digest);

        let (wallet_a, wallet_b, wallet_a_digest) = if first_digest < second_digest {
            (first_wallet, second_wallet, first_digest)
        } else {
            (second_wallet, first_wallet, second_digest)
        };
        let target = Target::from_be_bytes(wallet_a_digest.to_bytes());

        assert!(check_proof(&challenge_inputs, wallet_a, nonce, target));
        assert!(!check_proof(&challenge_inputs, wallet_b, nonce, target));
    }

    #[test]
    fn target_comparison_is_inclusive_at_equality() {
        let digest = Digest::from_bytes([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]);

        // Secure Mining Design lines 111-115 require uint256(digest) <= target.
        assert!(meets_target(
            digest,
            Target::from_be_bytes(digest.to_bytes())
        ));

        let mut lower_target = digest.to_bytes();
        lower_target[31] -= 1;
        assert!(!meets_target(digest, Target::from_be_bytes(lower_target)));
    }

    #[test]
    fn uint256_wrapping_add_handles_plain_carry_chain_and_wrap() {
        assert_eq!(
            Uint256::from(7_u64).wrapping_add(Uint256::from(5_u64)),
            Uint256::from(12_u64)
        );

        let mut carry_input = [0_u8; ABI_WORD_BYTES];
        carry_input[29] = 0x7f;
        carry_input[30] = 0xff;
        carry_input[31] = 0xff;
        let mut carry_expected = [0_u8; ABI_WORD_BYTES];
        carry_expected[29] = 0x80;
        assert_eq!(
            Uint256::from_be_bytes(carry_input).wrapping_add(Uint256::ONE),
            Uint256::from_be_bytes(carry_expected)
        );

        assert_eq!(
            Uint256::from_be_bytes([0xff; ABI_WORD_BYTES]).wrapping_add(Uint256::ONE),
            Uint256::ZERO
        );
    }

    fn challenge_fixture() -> ChallengeInputs {
        ChallengeInputs {
            chain_id: Uint256::from(4663_u64),
            mining_core: Address::from_bytes([
                0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
                0xf0, 0x01, 0x12, 0x23, 0x34, 0x45,
            ]),
            challenge_id: Uint256::from(19_u64),
            previous_accepted_digest: Digest::from_bytes([0xa5; ABI_WORD_BYTES]),
            seed_parent_block: Uint256::from(22_345_678_u64),
            seed_blockhash: Digest::from_bytes([0x5a; ABI_WORD_BYTES]),
        }
    }

    fn digest_for(challenge_inputs: &ChallengeInputs, miner: Address, nonce: Uint256) -> Digest {
        proof_digest(&ProofInputs {
            chain_id: challenge_inputs.chain_id,
            mining_core: challenge_inputs.mining_core,
            challenge_id: challenge_inputs.challenge_id,
            challenge: derive_challenge(challenge_inputs),
            miner,
            nonce,
        })
    }

    fn manual_challenge_digest(inputs: &ChallengeInputs) -> Digest {
        let mut encoded = Vec::with_capacity(PREIMAGE_BYTES);
        encoded.extend_from_slice(&CHALLENGE_TYPEHASH.to_bytes());
        encoded.extend_from_slice(&inputs.chain_id.to_be_bytes());
        append_address_word(&mut encoded, inputs.mining_core);
        encoded.extend_from_slice(&PROOF_VERSION.to_be_bytes());
        encoded.extend_from_slice(&inputs.challenge_id.to_be_bytes());
        encoded.extend_from_slice(&inputs.previous_accepted_digest.to_bytes());
        encoded.extend_from_slice(&inputs.seed_parent_block.to_be_bytes());
        encoded.extend_from_slice(&inputs.seed_blockhash.to_bytes());
        assert_eq!(encoded.len(), PREIMAGE_BYTES);
        direct_keccak(&encoded)
    }

    fn manual_proof_digest(inputs: &ProofInputs) -> Digest {
        let mut encoded = Vec::with_capacity(PREIMAGE_BYTES);
        encoded.extend_from_slice(&PROOF_TYPEHASH.to_bytes());
        encoded.extend_from_slice(&inputs.chain_id.to_be_bytes());
        append_address_word(&mut encoded, inputs.mining_core);
        encoded.extend_from_slice(&PROOF_VERSION.to_be_bytes());
        encoded.extend_from_slice(&inputs.challenge_id.to_be_bytes());
        encoded.extend_from_slice(&inputs.challenge.to_bytes());
        append_address_word(&mut encoded, inputs.miner);
        encoded.extend_from_slice(&inputs.nonce.to_be_bytes());
        assert_eq!(encoded.len(), PREIMAGE_BYTES);
        direct_keccak(&encoded)
    }

    fn append_address_word(encoded: &mut Vec<u8>, address: Address) {
        encoded.extend_from_slice(&[0; 12]);
        encoded.extend_from_slice(&address.to_bytes());
    }

    fn direct_keccak(input: &[u8]) -> Digest {
        let hash = sha3::Keccak256::digest(input);
        let mut bytes = [0; ABI_WORD_BYTES];
        bytes.copy_from_slice(&hash);
        Digest::from_bytes(bytes)
    }
}
