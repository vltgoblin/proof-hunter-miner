//! Minimal EIP-1559 transaction construction for one HunterMiningCore proof submission.

use std::fmt;

use proof_core::{Address, Digest, Uint256, keccak256};

use crate::keystore::UnlockedWallet;

const EIP_1559_TYPE: u8 = 0x02;
const SUBMIT_PROOF_SIGNATURE: &str = "submitProof(uint256,uint256,uint256,address)";
const REDACTED: &str = "[REDACTED]";

/// The unsigned fields of one EIP-1559 transaction.
pub struct Eip1559Transaction {
    pub chain_id: Uint256,
    pub account_nonce: Uint256,
    pub max_priority_fee_per_gas: Uint256,
    pub max_fee_per_gas: Uint256,
    pub gas_limit: Uint256,
    pub to: Address,
    pub data: Vec<u8>,
}

impl fmt::Debug for Eip1559Transaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Eip1559Transaction")
            .field("chain_id", &self.chain_id)
            .field("account_nonce", &self.account_nonce)
            .field("max_priority_fee_per_gas", &self.max_priority_fee_per_gas)
            .field("max_fee_per_gas", &self.max_fee_per_gas)
            .field("gas_limit", &self.gas_limit)
            .field("to", &self.to)
            .field("data", &self.data)
            .finish()
    }
}

/// A signed transaction ready for `eth_sendRawTransaction`.
pub struct SignedTransaction {
    raw_bytes: Vec<u8>,
    transaction_hash: Digest,
}

impl SignedTransaction {
    #[must_use]
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw_bytes
    }

    #[must_use]
    pub const fn transaction_hash(&self) -> Digest {
        self.transaction_hash
    }
}

impl fmt::Debug for SignedTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedTransaction")
            .field("raw_bytes", &REDACTED)
            .field("transaction_hash", &self.transaction_hash)
            .finish()
    }
}

/// Encodes the exact calldata for `HunterMiningCore.submitProof`.
#[must_use]
pub fn submit_proof_call_data(
    expected_challenge_id: Uint256,
    expected_seed_parent_block: Uint256,
    mining_nonce: Uint256,
    basket: Address,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 32 * 4);
    data.extend_from_slice(&keccak256(SUBMIT_PROOF_SIGNATURE.as_bytes()).to_bytes()[..4]);
    data.extend_from_slice(&expected_challenge_id.to_be_bytes());
    data.extend_from_slice(&expected_seed_parent_block.to_be_bytes());
    data.extend_from_slice(&mining_nonce.to_be_bytes());
    let mut basket_word = [0_u8; 32];
    basket_word[12..].copy_from_slice(&basket.to_bytes());
    data.extend_from_slice(&basket_word);
    data
}

/// Signs one EIP-1559 transaction without exposing the wallet key.
pub fn sign_eip1559_transaction(
    wallet: &UnlockedWallet,
    transaction: &Eip1559Transaction,
) -> Result<SignedTransaction, String> {
    let signing_payload = typed_payload(unsigned_fields(transaction));
    let signing_digest = keccak256(&signing_payload).to_bytes();
    let (signature, y_parity) = wallet.sign_digest(&signing_digest)?;

    let mut fields = unsigned_fields(transaction);
    fields.extend([
        rlp_integer(&[y_parity]),
        rlp_integer(&signature[..32]),
        rlp_integer(&signature[32..]),
    ]);
    let raw_bytes = typed_payload(fields);
    let transaction_hash = keccak256(&raw_bytes);
    Ok(SignedTransaction {
        raw_bytes,
        transaction_hash,
    })
}

fn unsigned_fields(transaction: &Eip1559Transaction) -> Vec<Vec<u8>> {
    vec![
        rlp_integer(&transaction.chain_id.to_be_bytes()),
        rlp_integer(&transaction.account_nonce.to_be_bytes()),
        rlp_integer(&transaction.max_priority_fee_per_gas.to_be_bytes()),
        rlp_integer(&transaction.max_fee_per_gas.to_be_bytes()),
        rlp_integer(&transaction.gas_limit.to_be_bytes()),
        rlp_bytes(&transaction.to.to_bytes()),
        rlp_integer(&[]),
        rlp_bytes(&transaction.data),
        rlp_list(&[]),
    ]
}

fn typed_payload(fields: Vec<Vec<u8>>) -> Vec<u8> {
    let encoded = rlp_list(&fields);
    let mut payload = Vec::with_capacity(1 + encoded.len());
    payload.push(EIP_1559_TYPE);
    payload.extend_from_slice(&encoded);
    payload
}

fn rlp_integer(bytes: &[u8]) -> Vec<u8> {
    let first_nonzero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    rlp_bytes(&bytes[first_nonzero..])
}

fn rlp_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        return vec![bytes[0]];
    }
    let mut encoded = rlp_length(bytes.len(), 0x80);
    encoded.extend_from_slice(bytes);
    encoded
}

fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload_length = items.iter().map(Vec::len).sum();
    let mut encoded = rlp_length(payload_length, 0xc0);
    for item in items {
        encoded.extend_from_slice(item);
    }
    encoded
}

fn rlp_length(length: usize, offset: u8) -> Vec<u8> {
    if length < 56 {
        return vec![offset + length as u8];
    }

    let full = length.to_be_bytes();
    let first_nonzero = full
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(full.len());
    let length_bytes = &full[first_nonzero..];
    let mut encoded = Vec::with_capacity(1 + length_bytes.len());
    encoded.push(offset + 55 + length_bytes.len() as u8);
    encoded.extend_from_slice(length_bytes);
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submit_proof_calldata_has_the_recorded_selector_and_four_words() {
        let basket = Address::from_bytes([0x44; 20]);
        let data = submit_proof_call_data(
            Uint256::from(7_u64),
            Uint256::from(11_u64),
            Uint256::from(13_u64),
            basket,
        );

        assert_eq!(data.len(), 132);
        assert_eq!(
            &data[..4],
            &keccak256(SUBMIT_PROOF_SIGNATURE.as_bytes()).to_bytes()[..4]
        );
        assert_eq!(&data[4..36], &Uint256::from(7_u64).to_be_bytes());
        assert_eq!(&data[36..68], &Uint256::from(11_u64).to_be_bytes());
        assert_eq!(&data[68..100], &Uint256::from(13_u64).to_be_bytes());
        let mut basket_word = [0_u8; 32];
        basket_word[12..].copy_from_slice(&basket.to_bytes());
        assert_eq!(&data[100..132], &basket_word);
    }

    #[test]
    fn rlp_uses_canonical_integer_and_length_encodings() {
        assert_eq!(rlp_integer(&[0]), vec![0x80]);
        assert_eq!(rlp_integer(&[0, 0x7f]), vec![0x7f]);
        assert_eq!(rlp_integer(&[0x80]), vec![0x81, 0x80]);
        assert_eq!(rlp_bytes(&[0x11; 56])[..2], [0xb8, 56]);
        assert_eq!(rlp_list(&[]), vec![0xc0]);
    }

    #[test]
    fn chain_id_is_inside_the_typed_signing_payload() {
        let transaction = |chain_id: u64| Eip1559Transaction {
            chain_id: Uint256::from(chain_id),
            account_nonce: Uint256::from(4_u64),
            max_priority_fee_per_gas: Uint256::from(2_u64),
            max_fee_per_gas: Uint256::from(20_u64),
            gas_limit: Uint256::from(30_000_u64),
            to: Address::from_bytes([0x22; 20]),
            data: vec![0xaa; 100],
        };

        let first = typed_payload(unsigned_fields(&transaction(1)));
        let second = typed_payload(unsigned_fields(&transaction(31_337)));
        assert_ne!(first, second);
        assert_ne!(keccak256(&first), keccak256(&second));
    }
}
