//! Deterministic, synchronous nonce search over wallet-bound proofs.

use crate::{
    Address, ChallengeInputs, Digest, PreparedProof, ProofInputs, Target, Uint256,
    derive_challenge, meets_target,
};

/// The result of one bounded nonce search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchResult {
    /// The first acceptable digest in the requested nonce sequence.
    Found {
        nonce: Uint256,
        digest: Digest,
        attempts: u64,
    },
    /// Every allowed attempt was made without finding an acceptable digest.
    Exhausted { attempts: u64 },
}

/// Searches one deterministic nonce sequence for the first acceptable proof.
///
/// The challenge is derived once. Nonces then advance by `step` with wrapping
/// `uint256` addition. A zero budget performs no hashes.
#[must_use]
pub fn search_nonce(
    challenge_inputs: ChallengeInputs,
    miner: Address,
    target: Target,
    start_nonce: Uint256,
    step: Uint256,
    attempt_budget: u64,
) -> SearchResult {
    let challenge = derive_challenge(&challenge_inputs);
    let prepared = PreparedProof::new(&ProofInputs {
        chain_id: challenge_inputs.chain_id,
        mining_core: challenge_inputs.mining_core,
        challenge_id: challenge_inputs.challenge_id,
        challenge,
        miner,
        nonce: start_nonce,
    });
    let mut nonce = start_nonce;

    for attempt in 0..attempt_budget {
        let digest = prepared.digest(nonce);

        if meets_target(digest, target) {
            return SearchResult::Found {
                nonce,
                digest,
                attempts: attempt + 1,
            };
        }

        nonce = nonce.wrapping_add(step);
    }

    SearchResult::Exhausted {
        attempts: attempt_budget,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::proof_digest;

    #[test]
    fn engine_finds_the_first_known_nonce_with_an_exact_attempt_count() {
        let challenge_inputs = challenge_fixture();
        let miner = Address::from_bytes([0x11; 20]);
        let known_nonce = 13_u64;
        let target_digest = digest_for(&challenge_inputs, miner, known_nonce);

        for earlier_nonce in 0..known_nonce {
            assert!(
                digest_for(&challenge_inputs, miner, earlier_nonce) > target_digest,
                "fixture must reject nonce {earlier_nonce}"
            );
        }

        assert_eq!(
            search_nonce(
                challenge_inputs,
                miner,
                Target::from_be_bytes(target_digest.to_bytes()),
                Uint256::ZERO,
                Uint256::ONE,
                known_nonce + 1,
            ),
            SearchResult::Found {
                nonce: Uint256::from(known_nonce),
                digest: target_digest,
                attempts: known_nonce + 1,
            }
        );
    }

    #[test]
    fn engine_exhausts_the_exact_budget_for_an_impossible_target() {
        assert_eq!(
            search_nonce(
                challenge_fixture(),
                Address::from_bytes([0x11; 20]),
                Target::from_be_bytes([0; 32]),
                Uint256::ZERO,
                Uint256::ONE,
                100,
            ),
            SearchResult::Exhausted { attempts: 100 }
        );
    }

    #[test]
    fn four_stride_sequences_cover_exactly_the_first_hundred_nonces() {
        let challenge_inputs = challenge_fixture();
        let miner = Address::from_bytes([0x11; 20]);
        let step = Uint256::from(4_u64);
        let mut covered = BTreeSet::new();

        for start in 0_u64..4 {
            assert_eq!(
                search_nonce(
                    challenge_inputs,
                    miner,
                    Target::from_be_bytes([0; 32]),
                    Uint256::from(start),
                    step,
                    25,
                ),
                SearchResult::Exhausted { attempts: 25 }
            );

            let mut nonce = Uint256::from(start);
            for _ in 0..25 {
                assert!(covered.insert(nonce));
                nonce = nonce.wrapping_add(step);
            }
        }

        assert_eq!(
            covered,
            (0_u64..100).map(Uint256::from).collect::<BTreeSet<_>>()
        );
    }

    fn challenge_fixture() -> ChallengeInputs {
        ChallengeInputs {
            chain_id: Uint256::from(4_663_u64),
            mining_core: Address::from_bytes([0x22; 20]),
            challenge_id: Uint256::from(19_u64),
            previous_accepted_digest: Digest::from_bytes([0xa5; 32]),
            seed_parent_block: Uint256::from(22_345_678_u64),
            seed_blockhash: Digest::from_bytes([0x5a; 32]),
        }
    }

    fn digest_for(challenge_inputs: &ChallengeInputs, miner: Address, nonce: u64) -> Digest {
        proof_digest(&ProofInputs {
            chain_id: challenge_inputs.chain_id,
            mining_core: challenge_inputs.mining_core,
            challenge_id: challenge_inputs.challenge_id,
            challenge: derive_challenge(challenge_inputs),
            miner,
            nonce: Uint256::from(nonce),
        })
    }
}
