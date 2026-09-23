//! Offline single-thread comparison; never connects to a chain or wallet.
use proof_core::{Address, Digest, PreparedProof, ProofInputs, Uint256, proof_digest};
use std::{hint::black_box, time::Instant};
fn main() {
    let mut inputs = ProofInputs {
        chain_id: Uint256::from(4663_u64),
        mining_core: Address::from_bytes([0x22; 20]),
        challenge_id: Uint256::from(7_u64),
        challenge: Digest::from_bytes([0xa5; 32]),
        miner: Address::from_bytes([0x11; 20]),
        nonce: Uint256::ZERO,
    };
    let prepared = PreparedProof::new(&inputs);
    let attempts = 500_000_u64;
    for round in 0..6 {
        for cached in if round % 2 == 0 {
            [false, true]
        } else {
            [true, false]
        } {
            let start = Instant::now();
            let mut checksum = [0_u8; 32];
            for nonce in 0..attempts {
                inputs.nonce = Uint256::from(black_box(nonce));
                let digest = black_box(if cached {
                    prepared.digest(inputs.nonce)
                } else {
                    proof_digest(&inputs)
                });
                for (acc, byte) in checksum.iter_mut().zip(digest.to_bytes()) {
                    *acc ^= byte;
                }
            }
            let seconds = start.elapsed().as_secs_f64();
            println!(
                "round={round} cached={cached} attempts={attempts} seconds={seconds:.6} hashes_per_second={:.0} checksum={checksum:02x?}",
                attempts as f64 / seconds
            );
        }
    }
}
