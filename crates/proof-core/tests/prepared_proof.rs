use proof_core::{Address, Digest, PreparedProof, ProofInputs, Uint256, proof_digest};

#[test]
fn prepared_hash_matches_reference_across_domains_and_nonce_boundaries() {
    for domain in 0..32_u64 {
        let mut inputs = ProofInputs {
            chain_id: Uint256::from(4663 + domain),
            mining_core: Address::from_bytes([domain as u8; 20]),
            challenge_id: Uint256::from(domain),
            challenge: Digest::from_bytes([(domain * 7) as u8; 32]),
            miner: Address::from_bytes([(domain * 3) as u8; 20]),
            nonce: Uint256::from(123_u64),
        };
        let prepared = PreparedProof::new(&inputs);
        for seed in [
            Uint256::ZERO,
            Uint256::from(u64::MAX),
            Uint256::from(u128::MAX),
            Uint256::from_be_bytes([255; 32]),
        ] {
            let mut nonce = seed;
            for _ in 0..64 {
                inputs.nonce = nonce;
                assert_eq!(prepared.digest(nonce), proof_digest(&inputs));
                // Repeated calls must not mutate the cached prefix.
                assert_eq!(prepared.digest(nonce), prepared.clone().digest(nonce));
                nonce = nonce.wrapping_add(Uint256::ONE);
            }
        }
    }
}
