#![forbid(unsafe_code)]

//! Pure integer arithmetic for the decided Bonded Proof mining economics.
//!
//! The reward schedule is package D2 from
//! `docs/product/bonded-proof/economics/ticket-05-options-v0.1.md`, confirmed
//! as decided in
//! `docs/product/bonded-proof/economics/ticket-16-numbers-v0.1.md`. The Core
//! Reserve rule locks the whole reward inside a minted Hunter.

pub mod proof;
pub mod schedule;
pub mod search;

pub use proof::{
    Address, CHALLENGE_TYPE_STRING, CHALLENGE_TYPEHASH, ChallengeInputs, Digest, PREIMAGE_BYTES,
    PROOF_TYPE_STRING, PROOF_TYPEHASH, PROOF_VERSION, PreparedProof, ProofInputs, Target, Uint256,
    challenge_preimage, check_proof, derive_challenge, keccak256, meets_target, proof_digest,
    proof_preimage,
};
pub use schedule::{
    FINAL_DIVISOR, MAX_MINTED_EVER, MIN_REWARD, OPENING_DIVISOR, RAMP_PROOFS, RewardSchedule,
    TOKEN_WEI, divisor_at, reserve_for, reward_at,
};
pub use search::{SearchResult, search_nonce};
