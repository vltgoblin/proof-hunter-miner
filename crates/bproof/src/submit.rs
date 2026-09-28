//! Live JSON-RPC preparation and single-shot submission of one proof.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use bproof::keystore::UnlockedWallet;
use bproof::transaction::{Eip1559Transaction, sign_eip1559_transaction, submit_proof_call_data};
use proof_core::{
    Address, Digest, ProofInputs, Uint256, derive_challenge, keccak256, proof_digest,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::chain::RpcChainReader;
use crate::parse::{
    hex_string, parse_address, parse_decimal_uint256, parse_digest, parse_hex_bytes,
    parse_hex_quantity_uint256, parse_u64, parse_u128, parse_uint256_word, uint256_to_decimal,
};
use crate::upkeep::UpkeepKind;

pub const FEE_REFUSAL_EXIT_CODE: u8 = 3;
pub const SUBMISSION_WARNING: &str = "Another miner may consume this challenge before inclusion, and this transaction may fail. Receipt success is accepted only after transaction and event consistency checks; the configured RPC can still withhold or delay data and remains a trust source.";
pub const PROOF_HUNTER_FEE_WARNING: &str = "Every accepted HunterMiningCore proof mints one NFT and pays no liquid HUNTER. Token activation and backing are separate from mining; no backing amount is promised. --max-fee must cover the estimated mint transaction or submission is refused.";

// NFT composition can use more gas at inclusion than the RPC estimate.
// The explicit total fee ceiling still bounds the padded exposure.
const DEFAULT_GAS_MARGIN_PERCENT: u64 = 100;
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(60);
const RECEIPT_POLL_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeeOptions {
    pub fee_ceiling_wei: u128,
    pub base_fee_per_gas_override_wei: Option<u128>,
    pub priority_fee_per_gas_override_wei: Option<u128>,
    pub gas_margin_percent: u64,
}

impl FeeOptions {
    #[must_use]
    pub const fn default_gas_margin_percent() -> u64 {
        DEFAULT_GAS_MARGIN_PERCENT
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeeQuote {
    pub base_fee_per_gas_wei: u128,
    pub priority_fee_per_gas_wei: u128,
    pub max_fee_per_gas_wei: u128,
    pub estimated_gas: u64,
    pub gas_margin_percent: u64,
    pub gas_limit: u64,
    pub maximum_exposure_wei: u128,
    pub fee_ceiling_wei: u128,
}

/// A Mining v2 claim: the proof goes through the router, which forwards the Hunter NFT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimRoute {
    pub router: Address,
    pub nft: Address,
}

pub struct PreparedSubmission {
    seed_refresh: bool,
    pub mining_nonce: Uint256,
    pub account_nonce: Uint256,
    pub fee_quote: FeeQuote,
    /// The signing wallet (the hunter for a claim).
    miner: Address,
    /// The mining core, which emits the proof events.
    core: Address,
    claim: Option<ClaimRoute>,
    /// Network upkeep (`easeDifficulty()` or `fixDraw()`): no proof, no NFT.
    upkeep: Option<UpkeepKind>,
    challenge_id: Uint256,
    seed_parent_block: Uint256,
    challenge: Digest,
    expected_digest: Digest,
    basket: Address,
    transaction: Eip1559Transaction,
}

impl std::fmt::Debug for PreparedSubmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedSubmission")
            .field("mining_nonce", &self.mining_nonce)
            .field("account_nonce", &self.account_nonce)
            .field("fee_quote", &self.fee_quote)
            .field("miner", &self.miner)
            .field("core", &self.core)
            .field("claim", &self.claim)
            .field("upkeep", &self.upkeep)
            .field("challenge_id", &self.challenge_id)
            .field("seed_parent_block", &self.seed_parent_block)
            .field("challenge", &self.challenge)
            .field("expected_digest", &self.expected_digest)
            .field("transaction", &self.transaction)
            .finish()
    }
}

#[derive(Debug)]
pub enum PreparationOutcome {
    Ready(Box<PreparedSubmission>),
    SimulationRejected { reason: String },
    FeeRefused(FeeQuote),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MinedSubmission {
    pub seed_refresh: bool,
    /// A Mining v2 router claim (the proof path of the upgraded system).
    pub claimed: bool,
    pub upkeep: Option<UpkeepKind>,
    pub transaction_hash: Digest,
    pub mining_nonce: Uint256,
    pub account_nonce: Uint256,
    pub fee_quote: FeeQuote,
    pub fee_paid_wei: u128,
    pub succeeded: bool,
    pub proof_nft_minted: bool,
    pub nft_token_id: Option<Uint256>,
}

#[derive(Debug)]
pub struct RecoveredSubmission {
    pub mined: MinedSubmission,
    pub miner: Address,
    pub proof_classification: String,
    pub classification_reason: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PendingSubmissionDocument {
    #[serde(default)]
    seed_refresh: bool,
    /// Version 3: the mining core (the transaction may go to its router).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    core: Option<String>,
    /// Version 3 claims: the router the transaction calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    router: Option<String>,
    /// Version 3 claims: the Hunter NFT the router forwards.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hunter_nft: Option<String>,
    /// Version 3 network upkeep: `ease` or `lock`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    upkeep: Option<String>,
    version: u8,
    transaction_hash: String,
    raw_transaction: String,
    mining_nonce: String,
    account_nonce: String,
    miner: String,
    challenge_id: String,
    seed_parent_block: String,
    challenge: String,
    expected_digest: String,
    basket: String,
    chain_id: String,
    max_priority_fee_per_gas: String,
    max_fee_per_gas: String,
    gas_limit: String,
    to: String,
    data: String,
    base_fee_per_gas_wei: String,
    priority_fee_per_gas_wei: String,
    estimated_gas: String,
    gas_margin_percent: String,
    maximum_exposure_wei: String,
    fee_ceiling_wei: String,
    proof_classification: String,
    classification_reason: Option<String>,
}

const PENDING_SUBMISSION_VERSION: u8 = 2;
/// Written for router claims and network upkeep only, so v1-path journals stay
/// readable by older releases.
const PENDING_CLAIM_VERSION: u8 = 3;

pub fn prepare_submission(
    reader: &RpcChainReader,
    challenge_inputs: proof_core::ChallengeInputs,
    miner: Address,
    mining_nonce: Uint256,
    basket: Address,
    fee_options: FeeOptions,
) -> Result<PreparationOutcome, String> {
    let challenge = derive_challenge(&challenge_inputs);
    let expected_digest = proof_digest(&ProofInputs {
        chain_id: challenge_inputs.chain_id,
        mining_core: challenge_inputs.mining_core,
        challenge_id: challenge_inputs.challenge_id,
        challenge,
        miner,
        nonce: mining_nonce,
    });
    let call_data = submit_proof_call_data(
        challenge_inputs.challenge_id,
        challenge_inputs.seed_parent_block,
        mining_nonce,
        basket,
    );
    let mut outcome = prepare_call(
        reader,
        challenge_inputs.chain_id,
        challenge_inputs.mining_core,
        miner,
        call_data,
        fee_options,
    )?;
    if let PreparationOutcome::Ready(prepared) = &mut outcome {
        prepared.mining_nonce = mining_nonce;
        prepared.challenge_id = challenge_inputs.challenge_id;
        prepared.seed_parent_block = challenge_inputs.seed_parent_block;
        prepared.challenge = challenge;
        prepared.expected_digest = expected_digest;
        prepared.basket = basket;
    }
    Ok(outcome)
}

/// Prepares `HuntRouter.claim(hunter, nonce, basket)`, sent by the hunter itself.
/// The digest is the core's digest with the router as miner; the nonce must be bound.
pub fn prepare_claim(
    reader: &RpcChainReader,
    challenge_inputs: proof_core::ChallengeInputs,
    hunter: Address,
    route: ClaimRoute,
    mining_nonce: Uint256,
    basket: Address,
    fee_options: FeeOptions,
) -> Result<PreparationOutcome, String> {
    if !crate::hunt::is_bound_nonce(mining_nonce, hunter) {
        return Ok(PreparationOutcome::SimulationRejected {
            reason: "mining nonce is not bound to this wallet".to_owned(),
        });
    }
    let challenge = derive_challenge(&challenge_inputs);
    let expected_digest = crate::hunt::router_digest(&challenge_inputs, route.router, mining_nonce);
    let call_data = crate::hunt::claim_call_data(hunter, mining_nonce, basket);
    let mut outcome = prepare_call(
        reader,
        challenge_inputs.chain_id,
        route.router,
        hunter,
        call_data,
        fee_options,
    )?;
    if let PreparationOutcome::Ready(prepared) = &mut outcome {
        prepared.core = challenge_inputs.mining_core;
        prepared.claim = Some(route);
        prepared.mining_nonce = mining_nonce;
        prepared.challenge_id = challenge_inputs.challenge_id;
        prepared.seed_parent_block = challenge_inputs.seed_parent_block;
        prepared.challenge = challenge;
        prepared.expected_digest = expected_digest;
        prepared.basket = basket;
    }
    Ok(outcome)
}

/// Prepares one network upkeep call from `wallet`: `easeDifficulty()` on the core or
/// `fixDraw()` on the router. The existing simulation, gas estimate and fee ceiling apply.
pub fn prepare_upkeep(
    reader: &RpcChainReader,
    wallet: Address,
    kind: UpkeepKind,
    router: Address,
    fee_options: FeeOptions,
) -> Result<PreparationOutcome, String> {
    let (chain_id, core) = reader.deployment();
    let to = match kind {
        UpkeepKind::Ease => core,
        UpkeepKind::Lock => router,
    };
    let mut outcome = prepare_call(reader, chain_id, to, wallet, kind.call_data(), fee_options)?;
    if let PreparationOutcome::Ready(prepared) = &mut outcome {
        prepared.core = core;
        prepared.upkeep = Some(kind);
    }
    Ok(outcome)
}

pub fn prepare_seed_refresh(
    reader: &RpcChainReader,
    chain_id: Uint256,
    core: Address,
    miner: Address,
    expired: (Uint256, Uint256),
    fee_options: FeeOptions,
) -> Result<PreparationOutcome, String> {
    if !reader.matches_deployment(chain_id, core) || reader.expired_seed()? != Some(expired) {
        return Ok(PreparationOutcome::SimulationRejected {
            reason: "expired seed changed before refresh preparation".to_owned(),
        });
    }
    let mut outcome = prepare_call(
        reader,
        chain_id,
        core,
        miner,
        refresh_call_data(),
        fee_options,
    )?;
    if let PreparationOutcome::Ready(prepared) = &mut outcome {
        prepared.seed_refresh = true;
        prepared.challenge_id = expired.0;
        prepared.seed_parent_block = expired.1;
    }
    Ok(outcome)
}

fn refresh_call_data() -> Vec<u8> {
    keccak256(b"refreshExpiredSeed()").to_bytes()[..4].to_vec()
}

fn prepare_call(
    reader: &RpcChainReader,
    chain_id: Uint256,
    to: Address,
    miner: Address,
    call_data: Vec<u8>,
    fee_options: FeeOptions,
) -> Result<PreparationOutcome, String> {
    let call = transaction_call(miner, to, &call_data);

    if let Err(error) = reader.rpc_result(
        "proof simulation",
        "eth_call",
        json!([call.clone(), "latest"]),
    ) {
        if error.contains("JSON-RPC proof simulation failed with error") {
            return Ok(PreparationOutcome::SimulationRejected {
                reason: disambiguate_mining_nonce(&error),
            });
        }
        return Err(error);
    }

    let estimated_gas_text =
        reader.string_result("proof gas estimate", "eth_estimateGas", json!([call]))?;
    let estimated_gas = uint256_to_u64(
        parse_hex_quantity_uint256(&estimated_gas_text, "eth_estimateGas result")?,
        "eth_estimateGas result",
    )?;
    let base_fee_per_gas_wei = match fee_options.base_fee_per_gas_override_wei {
        Some(value) => value,
        None => read_base_fee_per_gas(reader)?,
    };
    let priority_fee_per_gas_wei = match fee_options.priority_fee_per_gas_override_wei {
        Some(value) => value,
        None => read_priority_fee_per_gas(reader)?,
    };
    let fee_quote = fee_quote(
        base_fee_per_gas_wei,
        priority_fee_per_gas_wei,
        estimated_gas,
        fee_options.gas_margin_percent,
        fee_options.fee_ceiling_wei,
    )?;
    if fee_quote.maximum_exposure_wei > fee_quote.fee_ceiling_wei {
        return Ok(PreparationOutcome::FeeRefused(fee_quote));
    }

    let account_nonce_text = reader.string_result(
        "miner account transaction count",
        "eth_getTransactionCount",
        json!([hex_string(&miner.to_bytes()), "pending"]),
    )?;
    let account_nonce = parse_hex_quantity_uint256(
        &account_nonce_text,
        "eth_getTransactionCount result for account nonce",
    )?;
    let transaction = Eip1559Transaction {
        chain_id,
        account_nonce,
        max_priority_fee_per_gas: Uint256::from(priority_fee_per_gas_wei),
        max_fee_per_gas: Uint256::from(fee_quote.max_fee_per_gas_wei),
        gas_limit: Uint256::from(fee_quote.gas_limit),
        to,
        data: call_data,
    };

    Ok(PreparationOutcome::Ready(Box::new(PreparedSubmission {
        seed_refresh: false,
        mining_nonce: Uint256::ZERO,
        account_nonce,
        fee_quote,
        miner,
        core: to,
        claim: None,
        upkeep: None,
        challenge_id: Uint256::ZERO,
        seed_parent_block: Uint256::ZERO,
        challenge: Digest::from_bytes([0; 32]),
        expected_digest: Digest::from_bytes([0; 32]),
        basket: Address::from_bytes([0; 20]),
        transaction,
    })))
}

#[must_use]
pub fn pending_submission_path(keystore: &Path) -> PathBuf {
    let mut name = keystore
        .file_name()
        .map(|value| value.to_os_string())
        .unwrap_or_else(|| "wallet".into());
    name.push(".pending-submission.json");
    keystore.with_file_name(name)
}

pub fn recover_pending_submission(
    reader: &RpcChainReader,
    keystore: &Path,
) -> Result<Option<RecoveredSubmission>, String> {
    let journal_path = pending_submission_path(keystore);
    if !journal_path.exists() {
        return Ok(None);
    }
    let document = read_pending_document(&journal_path)?;
    let (expected_hash, raw_transaction, prepared) = document.to_prepared()?;
    if !reader.matches_deployment(prepared.transaction.chain_id, prepared.core) {
        return Err(
            "pending transaction belongs to a different deployment; journal retained".to_owned(),
        );
    }
    reader.verify_identity()?;
    if keccak256(&raw_transaction) != expected_hash {
        return Err(format!(
            "pending submission journal {} does not match its signed transaction hash; refusing to send or replace it",
            journal_path.display()
        ));
    }

    let hash_text = hex_string(&expected_hash.to_bytes());
    let existing = reader.rpc_result(
        "pending proof transaction receipt",
        "eth_getTransactionReceipt",
        json!([&hash_text]),
    )?;
    let receipt = if existing.is_null() {
        if prepared.seed_refresh {
            require_current_expired_seed(reader, &prepared)?;
        }
        // Re-broadcasting the exact signed bytes is idempotent. Any RPC error
        // remains ambiguous, so receipt lookup below is still authoritative.
        let _ = reader.string_result(
            "pending signed proof rebroadcast",
            "eth_sendRawTransaction",
            json!([hex_string(&raw_transaction)]),
        );
        wait_for_receipt(reader, expected_hash, &prepared)?
    } else {
        parse_receipt(&existing, expected_hash, &prepared)?
    };
    verify_mined_transaction(reader, expected_hash, &receipt, &prepared)?;
    let mined = mined_submission(expected_hash, &receipt, &prepared)?;
    clear_pending_document(&journal_path)?;
    Ok(Some(RecoveredSubmission {
        mined,
        miner: prepared.miner,
        proof_classification: document.proof_classification,
        classification_reason: document.classification_reason,
    }))
}

pub fn send_prepared_submission(
    reader: &RpcChainReader,
    wallet: &UnlockedWallet,
    prepared: PreparedSubmission,
    keystore: &Path,
    proof_classification: &str,
    classification_reason: Option<&str>,
) -> Result<MinedSubmission, String> {
    if parse_address(wallet.address(), "unlocked wallet address")? != prepared.miner {
        return Err("unlocked wallet does not match the prepared proof miner".to_owned());
    }
    if prepared.seed_refresh {
        require_current_expired_seed(reader, &prepared)?;
    }
    let signed = sign_eip1559_transaction(wallet, &prepared.transaction)?;
    let expected_transaction_hash = signed.transaction_hash();
    let raw_transaction = hex_string(signed.raw_bytes());
    let journal_path = pending_submission_path(keystore);
    let journal = PendingSubmissionDocument::from_prepared(
        expected_transaction_hash,
        &raw_transaction,
        &prepared,
        proof_classification,
        classification_reason,
    );
    persist_pending_document(&journal_path, &journal)?;
    let outcome = (|| -> Result<MinedSubmission, String> {
        let sent_hash_text = reader
            .string_result(
                "signed proof submission",
                "eth_sendRawTransaction",
                json!([raw_transaction]),
            )
            .map_err(|error| disambiguate_account_nonce(&error))?;
        let sent_hash = parse_digest(&sent_hash_text, "eth_sendRawTransaction transaction hash")?;
        if sent_hash != expected_transaction_hash {
            return Err(format!(
                "eth_sendRawTransaction returned transaction hash {}, but the signed transaction hash is {}",
                hex_string(&sent_hash.to_bytes()),
                hex_string(&expected_transaction_hash.to_bytes())
            ));
        }

        let receipt = wait_for_receipt(reader, sent_hash, &prepared)?;
        verify_mined_transaction(reader, sent_hash, &receipt, &prepared)?;
        mined_submission(sent_hash, &receipt, &prepared)
    })();
    match outcome {
        Ok(mined) => {
            clear_pending_document(&journal_path)?;
            Ok(mined)
        }
        Err(error) => Err(format!(
            "submission outcome unresolved for signed transaction {}; durable recovery journal retained at {}; rerun with the same keystore to reconcile the exact signed transaction before any new proof is sent: {error}",
            hex_string(&expected_transaction_hash.to_bytes()),
            journal_path.display()
        )),
    }
}

impl PendingSubmissionDocument {
    fn from_prepared(
        transaction_hash: Digest,
        raw_transaction: &str,
        prepared: &PreparedSubmission,
        proof_classification: &str,
        classification_reason: Option<&str>,
    ) -> Self {
        let fee = prepared.fee_quote;
        let tx = &prepared.transaction;
        let v3 = prepared.claim.is_some() || prepared.upkeep.is_some();
        Self {
            seed_refresh: prepared.seed_refresh,
            core: v3.then(|| hex_string(&prepared.core.to_bytes())),
            router: match (prepared.claim, prepared.upkeep) {
                (Some(route), _) => Some(hex_string(&route.router.to_bytes())),
                (None, Some(UpkeepKind::Lock)) => Some(hex_string(&tx.to.to_bytes())),
                _ => None,
            },
            hunter_nft: prepared
                .claim
                .map(|route| hex_string(&route.nft.to_bytes())),
            upkeep: prepared.upkeep.map(|kind| kind.name().to_owned()),
            version: if v3 {
                PENDING_CLAIM_VERSION
            } else {
                PENDING_SUBMISSION_VERSION
            },
            transaction_hash: hex_string(&transaction_hash.to_bytes()),
            raw_transaction: raw_transaction.to_owned(),
            mining_nonce: uint256_to_decimal(prepared.mining_nonce),
            account_nonce: uint256_to_decimal(prepared.account_nonce),
            miner: hex_string(&prepared.miner.to_bytes()),
            challenge_id: uint256_to_decimal(prepared.challenge_id),
            seed_parent_block: uint256_to_decimal(prepared.seed_parent_block),
            challenge: hex_string(&prepared.challenge.to_bytes()),
            expected_digest: hex_string(&prepared.expected_digest.to_bytes()),
            basket: hex_string(&prepared.basket.to_bytes()),
            chain_id: uint256_to_decimal(tx.chain_id),
            max_priority_fee_per_gas: uint256_to_decimal(tx.max_priority_fee_per_gas),
            max_fee_per_gas: uint256_to_decimal(tx.max_fee_per_gas),
            gas_limit: uint256_to_decimal(tx.gas_limit),
            to: hex_string(&tx.to.to_bytes()),
            data: hex_string(&tx.data),
            base_fee_per_gas_wei: fee.base_fee_per_gas_wei.to_string(),
            priority_fee_per_gas_wei: fee.priority_fee_per_gas_wei.to_string(),
            estimated_gas: fee.estimated_gas.to_string(),
            gas_margin_percent: fee.gas_margin_percent.to_string(),
            maximum_exposure_wei: fee.maximum_exposure_wei.to_string(),
            fee_ceiling_wei: fee.fee_ceiling_wei.to_string(),
            proof_classification: proof_classification.to_owned(),
            classification_reason: classification_reason.map(str::to_owned),
        }
    }

    fn to_prepared(&self) -> Result<(Digest, Vec<u8>, PreparedSubmission), String> {
        if !(1..=PENDING_CLAIM_VERSION).contains(&self.version) {
            return Err(format!(
                "unsupported pending submission journal version {}",
                self.version
            ));
        }
        if self.version == 1 && self.seed_refresh {
            return Err("legacy proof journal cannot describe a seed refresh".to_owned());
        }
        let v3_fields = [&self.core, &self.router, &self.hunter_nft, &self.upkeep];
        if self.version < PENDING_CLAIM_VERSION && v3_fields.iter().any(|field| field.is_some()) {
            return Err(
                "pending submission journal has claim fields in an older version".to_owned(),
            );
        }
        let upkeep = self
            .upkeep
            .as_deref()
            .map(UpkeepKind::from_name)
            .transpose()?;
        if self.version == PENDING_CLAIM_VERSION {
            let complete = match upkeep {
                None => self.router.is_some() && self.hunter_nft.is_some(),
                Some(UpkeepKind::Ease) => self.router.is_none() && self.hunter_nft.is_none(),
                Some(UpkeepKind::Lock) => self.router.is_some() && self.hunter_nft.is_none(),
            };
            if self.core.is_none() || !complete || self.seed_refresh {
                return Err("pending claim journal is missing its core, router or NFT".to_owned());
            }
        }
        let transaction_hash = parse_digest(&self.transaction_hash, "journal transactionHash")?;
        let raw_transaction = parse_hex_bytes(&self.raw_transaction, "journal rawTransaction")?;
        let claim = match (&self.router, &self.hunter_nft) {
            (Some(router), Some(nft)) if upkeep.is_none() => Some(ClaimRoute {
                router: parse_address(router, "journal router")?,
                nft: parse_address(nft, "journal hunterNft")?,
            }),
            _ => None,
        };
        let to = parse_address(&self.to, "journal to")?;
        let core = match &self.core {
            Some(core) => parse_address(core, "journal core")?,
            None => to,
        };
        let fee_quote = FeeQuote {
            base_fee_per_gas_wei: parse_u128(
                &self.base_fee_per_gas_wei,
                "journal baseFeePerGasWei",
            )?,
            priority_fee_per_gas_wei: parse_u128(
                &self.priority_fee_per_gas_wei,
                "journal priorityFeePerGasWei",
            )?,
            max_fee_per_gas_wei: parse_u128(&self.max_fee_per_gas, "journal maxFeePerGas")?,
            estimated_gas: parse_u64(&self.estimated_gas, "journal estimatedGas")?,
            gas_margin_percent: parse_u64(&self.gas_margin_percent, "journal gasMarginPercent")?,
            gas_limit: parse_u64(&self.gas_limit, "journal gasLimit")?,
            maximum_exposure_wei: parse_u128(
                &self.maximum_exposure_wei,
                "journal maximumExposureWei",
            )?,
            fee_ceiling_wei: parse_u128(&self.fee_ceiling_wei, "journal feeCeilingWei")?,
        };
        let prepared = PreparedSubmission {
            seed_refresh: self.seed_refresh,
            mining_nonce: parse_decimal_uint256(&self.mining_nonce, "journal miningNonce")?,
            account_nonce: parse_decimal_uint256(&self.account_nonce, "journal accountNonce")?,
            fee_quote,
            miner: parse_address(&self.miner, "journal miner")?,
            core,
            claim,
            upkeep,
            challenge_id: parse_decimal_uint256(&self.challenge_id, "journal challengeId")?,
            seed_parent_block: parse_decimal_uint256(
                &self.seed_parent_block,
                "journal seedParentBlock",
            )?,
            challenge: parse_digest(&self.challenge, "journal challenge")?,
            expected_digest: parse_digest(&self.expected_digest, "journal expectedDigest")?,
            basket: parse_address(&self.basket, "journal basket")?,
            transaction: Eip1559Transaction {
                chain_id: parse_decimal_uint256(&self.chain_id, "journal chainId")?,
                account_nonce: parse_decimal_uint256(&self.account_nonce, "journal accountNonce")?,
                max_priority_fee_per_gas: parse_decimal_uint256(
                    &self.max_priority_fee_per_gas,
                    "journal maxPriorityFeePerGas",
                )?,
                max_fee_per_gas: parse_decimal_uint256(
                    &self.max_fee_per_gas,
                    "journal maxFeePerGas",
                )?,
                gas_limit: parse_decimal_uint256(&self.gas_limit, "journal gasLimit")?,
                to,
                data: parse_hex_bytes(&self.data, "journal data")?,
            },
        };
        if prepared.seed_refresh && prepared.transaction.data != refresh_call_data() {
            return Err("refresh journal has invalid calldata".to_owned());
        }
        if let Some(route) = prepared.claim {
            validate_claim_journal(&prepared, route)?;
        }
        if let Some(kind) = prepared.upkeep {
            let expected_to = match kind {
                UpkeepKind::Ease => prepared.core,
                UpkeepKind::Lock => match &self.router {
                    Some(router) => parse_address(router, "journal router")?,
                    None => return Err("upkeep journal is missing its router".to_owned()),
                },
            };
            if prepared.transaction.data != kind.call_data()
                || prepared.transaction.to != expected_to
            {
                return Err("upkeep journal has invalid calldata".to_owned());
            }
        }
        if prepared.transaction.account_nonce != prepared.account_nonce {
            return Err(
                "pending submission journal contains inconsistent account nonces".to_owned(),
            );
        }
        if prepared.transaction.max_fee_per_gas != Uint256::from(fee_quote.max_fee_per_gas_wei)
            || prepared.transaction.max_priority_fee_per_gas
                != Uint256::from(fee_quote.priority_fee_per_gas_wei)
            || prepared.transaction.gas_limit != Uint256::from(fee_quote.gas_limit)
        {
            return Err("pending submission journal contains inconsistent fee fields".to_owned());
        }
        let expected_gas_limit =
            padded_gas_limit(fee_quote.estimated_gas, fee_quote.gas_margin_percent)?;
        let expected_exposure = u128::from(fee_quote.gas_limit)
            .checked_mul(fee_quote.max_fee_per_gas_wei)
            .ok_or_else(|| {
                "pending submission journal fee exposure exceeds the u128 range".to_owned()
            })?;
        if expected_gas_limit != fee_quote.gas_limit
            || expected_exposure != fee_quote.maximum_exposure_wei
            || fee_quote.maximum_exposure_wei > fee_quote.fee_ceiling_wei
        {
            return Err(
                "pending submission journal contains an inconsistent or unauthorised fee exposure"
                    .to_owned(),
            );
        }
        Ok((transaction_hash, raw_transaction, prepared))
    }
}

fn mined_submission(
    transaction_hash: Digest,
    receipt: &TransactionReceipt,
    prepared: &PreparedSubmission,
) -> Result<MinedSubmission, String> {
    let fee_paid_wei = receipt
        .gas_used
        .checked_mul(receipt.effective_gas_price_wei)
        .ok_or_else(|| "actual transaction fee exceeds the supported u128 range".to_owned())?;
    if fee_paid_wei > prepared.fee_quote.maximum_exposure_wei {
        return Err(format!(
            "actual transaction fee {fee_paid_wei} wei exceeds the authorised maximum exposure {} wei",
            prepared.fee_quote.maximum_exposure_wei
        ));
    }
    Ok(MinedSubmission {
        seed_refresh: prepared.seed_refresh,
        claimed: prepared.claim.is_some(),
        upkeep: prepared.upkeep,
        transaction_hash,
        mining_nonce: prepared.mining_nonce,
        account_nonce: prepared.account_nonce,
        fee_quote: prepared.fee_quote,
        fee_paid_wei,
        succeeded: receipt.succeeded,
        proof_nft_minted: receipt.proof_nft_minted,
        nft_token_id: receipt.nft_token_id,
    })
}

fn persist_pending_document(
    path: &Path,
    document: &PendingSubmissionDocument,
) -> Result<(), String> {
    if path.exists() {
        return Err(format!(
            "pending submission journal {} already exists; reconcile it before signing a new transaction",
            path.display()
        ));
    }
    let parent = journal_directory(path);
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "pending submission journal path is not valid UTF-8".to_owned())?;
    let temporary = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
    let encoded = serde_json::to_vec_pretty(document)
        .map_err(|error| format!("failed to encode pending submission journal: {error}"))?;
    let write_result = (|| -> Result<(), String> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary).map_err(|error| {
            format!(
                "failed to create pending submission journal {}: {error}",
                temporary.display()
            )
        })?;
        file.write_all(&encoded).map_err(|error| {
            format!(
                "failed to write pending submission journal {}: {error}",
                temporary.display()
            )
        })?;
        file.write_all(b"\n")
            .map_err(|error| format!("failed to finish pending submission journal: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("failed to sync pending submission journal: {error}"))?;
        fs::hard_link(&temporary, path).map_err(|error| {
            format!(
                "failed to publish pending submission journal {} without overwriting existing state: {error}",
                path.display()
            )
        })?;
        sync_directory(parent)?;
        Ok(())
    })();
    let _ = fs::remove_file(&temporary);
    write_result
}

fn read_pending_document(path: &Path) -> Result<PendingSubmissionDocument, String> {
    let mut file = open_owner_only(path)?;
    let mut encoded = Vec::new();
    file.read_to_end(&mut encoded).map_err(|error| {
        format!(
            "failed to read pending submission journal {}: {error}",
            path.display()
        )
    })?;
    serde_json::from_slice(&encoded).map_err(|error| {
        format!(
            "pending submission journal {} is invalid; refusing to send a replacement transaction: {error}",
            path.display()
        )
    })
}

fn clear_pending_document(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => sync_directory(journal_directory(path)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "transaction resolved but failed to remove pending submission journal {}: {error}",
            path.display()
        )),
    }
}

fn open_owner_only(path: &Path) -> Result<File, String> {
    #[cfg(unix)]
    let file: File = {
        use rustix::fs::{Mode, OFlags, open};

        open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| {
            format!(
                "failed to securely open pending submission journal {}: {error}",
                path.display()
            )
        })?
    };
    #[cfg(not(unix))]
    let file = OpenOptions::new().read(true).open(path).map_err(|error| {
        format!(
            "failed to open pending submission journal {}: {error}",
            path.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = file.metadata().map_err(|error| {
            format!(
                "failed to inspect pending submission journal {}: {error}",
                path.display()
            )
        })?;
        if !metadata.is_file() {
            return Err("pending submission journal must be a regular file".to_owned());
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "pending submission journal {} must be owner-only (mode 0600)",
                path.display()
            ));
        }
        if metadata.uid() != rustix::process::getuid().as_raw() {
            return Err(format!(
                "pending submission journal {} is not owned by the current user",
                path.display()
            ));
        }
    }
    Ok(file)
}

/// The directory holding a journal; a bare file name (an empty parent) means the current one.
fn journal_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            format!(
                "failed to sync journal directory {}: {error}",
                path.display()
            )
        })
}

fn transaction_call(from: Address, to: Address, data: &[u8]) -> Value {
    json!({
        "from": hex_string(&from.to_bytes()),
        "to": hex_string(&to.to_bytes()),
        "data": hex_string(data),
    })
}

fn read_base_fee_per_gas(reader: &RpcChainReader) -> Result<u128, String> {
    let block = reader.rpc_result(
        "latest block base fee",
        "eth_getBlockByNumber",
        json!(["latest", false]),
    )?;
    let base_fee = block
        .as_object()
        .and_then(|fields| fields.get("baseFeePerGas"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            "latest block has no baseFeePerGas; use --base-fee-per-gas to provide raw wei"
                .to_owned()
        })?;
    uint256_to_u128(
        parse_hex_quantity_uint256(base_fee, "latest block baseFeePerGas")?,
        "latest block baseFeePerGas",
    )
}

fn read_priority_fee_per_gas(reader: &RpcChainReader) -> Result<u128, String> {
    let priority_fee = reader
        .string_result(
            "priority fee quote",
            "eth_maxPriorityFeePerGas",
            json!([]),
        )
        .map_err(|error| {
            format!(
                "{error}; use --priority-fee-per-gas to provide the tip in raw wei when the node does not offer eth_maxPriorityFeePerGas"
            )
        })?;
    uint256_to_u128(
        parse_hex_quantity_uint256(&priority_fee, "eth_maxPriorityFeePerGas result")?,
        "eth_maxPriorityFeePerGas result",
    )
}

fn fee_quote(
    base_fee_per_gas_wei: u128,
    priority_fee_per_gas_wei: u128,
    estimated_gas: u64,
    gas_margin_percent: u64,
    fee_ceiling_wei: u128,
) -> Result<FeeQuote, String> {
    // The doubled base fee is the recorded liveness policy. The total-exposure
    // comparison below, not this multiplier, is the operator's safety boundary.
    let max_fee_per_gas_wei = base_fee_per_gas_wei
        .checked_mul(2)
        .and_then(|value| value.checked_add(priority_fee_per_gas_wei))
        .ok_or_else(|| "base fee times two plus priority fee exceeds the u128 range".to_owned())?;
    let gas_limit = padded_gas_limit(estimated_gas, gas_margin_percent)?;
    let maximum_exposure_wei = u128::from(gas_limit)
        .checked_mul(max_fee_per_gas_wei)
        .ok_or_else(|| "maximum transaction exposure exceeds the u128 range".to_owned())?;
    Ok(FeeQuote {
        base_fee_per_gas_wei,
        priority_fee_per_gas_wei,
        max_fee_per_gas_wei,
        estimated_gas,
        gas_margin_percent,
        gas_limit,
        maximum_exposure_wei,
        fee_ceiling_wei,
    })
}

fn padded_gas_limit(estimated_gas: u64, gas_margin_percent: u64) -> Result<u64, String> {
    // Round up so the recorded margin is never weakened by integer division.
    let multiplier = 100_u128
        .checked_add(u128::from(gas_margin_percent))
        .ok_or_else(|| "--gas-margin-percent is too large".to_owned())?;
    let padded = u128::from(estimated_gas)
        .checked_mul(multiplier)
        .and_then(|value| value.checked_add(99))
        .map(|value| value / 100)
        .ok_or_else(|| "padded gas limit exceeds the supported range".to_owned())?;
    u64::try_from(padded).map_err(|_| "padded gas limit exceeds the u64 range".to_owned())
}

#[derive(Debug)]
struct TransactionReceipt {
    succeeded: bool,
    gas_used: u128,
    effective_gas_price_wei: u128,
    proof_nft_minted: bool,
    nft_token_id: Option<Uint256>,
    block_hash: Digest,
    block_number: Uint256,
}

fn wait_for_receipt(
    reader: &RpcChainReader,
    transaction_hash: Digest,
    prepared: &PreparedSubmission,
) -> Result<TransactionReceipt, String> {
    let transaction_hash_text = hex_string(&transaction_hash.to_bytes());
    let deadline = Instant::now() + RECEIPT_TIMEOUT;
    loop {
        let value = reader.rpc_result(
            "proof transaction receipt",
            "eth_getTransactionReceipt",
            json!([&transaction_hash_text]),
        )?;
        if !value.is_null() {
            return parse_receipt(&value, transaction_hash, prepared);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for proof transaction receipt {transaction_hash_text}"
            ));
        }
        thread::sleep(RECEIPT_POLL_INTERVAL);
    }
}

fn parse_receipt(
    value: &Value,
    transaction_hash: Digest,
    prepared: &PreparedSubmission,
) -> Result<TransactionReceipt, String> {
    let fields = value
        .as_object()
        .ok_or_else(|| "proof transaction receipt must be an object".to_owned())?;
    require_digest_field(fields, "transactionHash", "receipt", transaction_hash)?;
    require_address_field(fields, "from", "receipt", prepared.miner)?;
    require_address_field(fields, "to", "receipt", prepared.transaction.to)?;
    let block_hash = digest_field(fields, "blockHash", "receipt")?;
    let block_number = quantity_field(fields, "blockNumber", "receipt")?;
    let status = receipt_quantity(fields, "status")?;
    if status != Uint256::ZERO && status != Uint256::ONE {
        return Err("proof transaction receipt status must be 0x0 or 0x1".to_owned());
    }
    let gas_used = uint256_to_u128(receipt_quantity(fields, "gasUsed")?, "receipt gasUsed")?;
    let effective_gas_price_wei = uint256_to_u128(
        receipt_quantity(fields, "effectiveGasPrice")?,
        "receipt effectiveGasPrice",
    )?;
    let logs = fields
        .get("logs")
        .and_then(Value::as_array)
        .ok_or_else(|| "proof transaction receipt is missing `logs`".to_owned())?;
    let succeeded = status == Uint256::ONE;
    let proof = !prepared.seed_refresh && prepared.upkeep.is_none();
    if succeeded && proof {
        verify_proof_accepted_event(logs, transaction_hash, block_hash, block_number, prepared)?;
    }
    let nft_token_id =
        verify_proof_nft_event(logs, transaction_hash, block_hash, block_number, prepared)?;
    let proof_nft_minted = nft_token_id.is_some();
    if let Some(route) = prepared.claim {
        verify_claim_delivery(
            logs,
            transaction_hash,
            block_hash,
            block_number,
            prepared,
            route,
            nft_token_id,
        )?;
    }
    if prepared.seed_refresh {
        verify_seed_refreshed_event(
            logs,
            transaction_hash,
            block_hash,
            block_number,
            prepared,
            succeeded,
        )?;
        if proof_nft_minted {
            return Err("seed refresh must not mint an NFT".to_owned());
        }
    } else if let Some(kind) = prepared.upkeep {
        if proof_nft_minted {
            return Err("network upkeep must not mint an NFT".to_owned());
        }
        verify_upkeep_event(
            logs,
            transaction_hash,
            block_hash,
            block_number,
            prepared,
            kind,
            succeeded,
        )?;
    } else if succeeded != proof_nft_minted {
        return Err("HunterMiningCore success requires exactly one NFT mint; reverted receipts must not mint".to_owned());
    }
    Ok(TransactionReceipt {
        succeeded,
        gas_used,
        effective_gas_price_wei,
        proof_nft_minted,
        nft_token_id,
        block_hash,
        block_number,
    })
}

fn verify_mined_transaction(
    reader: &RpcChainReader,
    transaction_hash: Digest,
    receipt: &TransactionReceipt,
    prepared: &PreparedSubmission,
) -> Result<(), String> {
    let transaction_hash_text = hex_string(&transaction_hash.to_bytes());
    let deadline = Instant::now() + RECEIPT_TIMEOUT;
    let value = loop {
        let value = reader.rpc_result(
            "mined proof transaction",
            "eth_getTransactionByHash",
            json!([&transaction_hash_text]),
        )?;
        // A receipt can become visible before the transaction index catches up.
        // Wait for inclusion fields, then retain every exact transaction check below.
        if value.get("blockHash").is_some_and(|v| !v.is_null()) {
            break value;
        }
        if Instant::now() >= deadline {
            return Err(
                "mined transaction inclusion fields unavailable; journal retained".to_owned(),
            );
        }
        thread::sleep(RECEIPT_POLL_INTERVAL);
    };
    let fields = value
        .as_object()
        .ok_or_else(|| "mined proof transaction must be an object".to_owned())?;

    require_digest_field(fields, "hash", "mined transaction", transaction_hash)?;
    require_address_field(fields, "from", "mined transaction", prepared.miner)?;
    require_address_field(fields, "to", "mined transaction", prepared.transaction.to)?;
    require_digest_field(fields, "blockHash", "mined transaction", receipt.block_hash)?;
    require_quantity_field(
        fields,
        "blockNumber",
        "mined transaction",
        receipt.block_number,
    )?;
    require_quantity_field(
        fields,
        "chainId",
        "mined transaction",
        prepared.transaction.chain_id,
    )?;
    require_quantity_field(
        fields,
        "nonce",
        "mined transaction",
        prepared.transaction.account_nonce,
    )?;
    require_quantity_field(
        fields,
        "gas",
        "mined transaction",
        prepared.transaction.gas_limit,
    )?;
    require_quantity_field(
        fields,
        "maxFeePerGas",
        "mined transaction",
        prepared.transaction.max_fee_per_gas,
    )?;
    require_quantity_field(
        fields,
        "maxPriorityFeePerGas",
        "mined transaction",
        prepared.transaction.max_priority_fee_per_gas,
    )?;
    require_quantity_field(fields, "value", "mined transaction", Uint256::ZERO)?;
    require_quantity_field(fields, "type", "mined transaction", Uint256::from(2_u64))?;
    require_hex_bytes_field(
        fields,
        "input",
        "mined transaction",
        &prepared.transaction.data,
    )?;

    if prepared.seed_refresh || prepared.upkeep.is_some() {
        let block = reader.rpc_result(
            "canonical refresh block",
            "eth_getBlockByNumber",
            json!([
                format!(
                    "0x{:x}",
                    uint256_to_u128(receipt.block_number, "receipt block number")?
                ),
                false
            ]),
        )?;
        let block = block
            .as_object()
            .ok_or("canonical refresh block unavailable; journal retained")?;
        require_digest_field(block, "hash", "canonical refresh block", receipt.block_hash)?;
    }

    // These bindings reject an internally inconsistent RPC account. One endpoint
    // can still fabricate a fully self-consistent chain view or withhold/delay data;
    // stronger unattended assurance requires agreement from an independent endpoint.
    Ok(())
}

fn require_current_expired_seed(
    reader: &RpcChainReader,
    prepared: &PreparedSubmission,
) -> Result<(), String> {
    if !reader.matches_deployment(prepared.transaction.chain_id, prepared.transaction.to)
        || reader.expired_seed()? != Some((prepared.challenge_id, prepared.seed_parent_block))
    {
        return Err(
            "expired seed changed; refusing a stale refresh (any pending journal is retained)"
                .to_owned(),
        );
    }
    Ok(())
}

/// A successful upkeep receipt carries exactly its own event: `DifficultyEased` from the
/// core naming this wallet, or `DrawFixed` from the router. A reverted one carries none.
fn verify_upkeep_event(
    logs: &[Value],
    hash: Digest,
    block_hash: Digest,
    block_number: Uint256,
    prepared: &PreparedSubmission,
    kind: UpkeepKind,
    succeeded: bool,
) -> Result<(), String> {
    let (signature, name, topics) = match kind {
        UpkeepKind::Ease => (
            event_signature(b"DifficultyEased(address,uint256,uint256,uint256)"),
            "upkeep ease event",
            2,
        ),
        UpkeepKind::Lock => (
            event_signature(b"DrawFixed(uint256,uint8,uint256)"),
            "upkeep lock event",
            2,
        ),
    };
    let events = event_candidates(logs, signature)?;
    if events.len() != usize::from(succeeded) {
        return Err("upkeep receipt has an inconsistent event count".to_owned());
    }
    if !succeeded {
        return Ok(());
    }
    let fields = event_fields(
        events[0],
        name,
        hash,
        block_hash,
        block_number,
        prepared.transaction.to,
    )?;
    let topics = event_topics(fields, name, topics)?;
    if kind == UpkeepKind::Ease {
        require_topic_address(topics, 1, "upkeep ease caller", prepared.miner)?;
    }
    Ok(())
}

fn verify_seed_refreshed_event(
    logs: &[Value],
    hash: Digest,
    block_hash: Digest,
    block_number: Uint256,
    prepared: &PreparedSubmission,
    succeeded: bool,
) -> Result<(), String> {
    let events = event_candidates(
        logs,
        event_signature(b"SeedRefreshed(uint256,uint256,uint256,uint256)"),
    )?;
    if events.len() != usize::from(succeeded) {
        return Err("refresh receipt has an inconsistent SeedRefreshed event count".to_owned());
    }
    if !succeeded {
        return Ok(());
    }
    let fields = event_fields(
        events[0],
        "SeedRefreshed",
        hash,
        block_hash,
        block_number,
        prepared.transaction.to,
    )?;
    let topics = event_topics(fields, "SeedRefreshed", 3)?;
    require_topic_uint256(topics, 1, "expired challenge", prepared.challenge_id)?;
    let next = prepared.challenge_id.wrapping_add(Uint256::ONE);
    if next == Uint256::ZERO {
        return Err("refresh challenge ID overflow".to_owned());
    }
    require_topic_uint256(topics, 2, "new challenge", next)?;
    let words = event_data_words(fields, "SeedRefreshed", 2)?;
    require_word_uint256(&words, 0, "expired seed", prepared.seed_parent_block)?;
    if parse_uint256_word(&words[1], "new seed")? <= prepared.seed_parent_block {
        return Err("refresh event did not advance the seed".to_owned());
    }
    Ok(())
}

fn verify_proof_accepted_event(
    logs: &[Value],
    transaction_hash: Digest,
    block_hash: Digest,
    block_number: Uint256,
    prepared: &PreparedSubmission,
) -> Result<(), String> {
    let signature = event_signature(
        b"ProofAccepted(address,uint256,bytes32,uint256,bytes32,uint256,uint256,uint256,uint256,uint256,bool)",
    );
    let candidates = event_candidates(logs, signature)?;
    if candidates.len() != 1 {
        return Err(format!(
            "successful proof receipt must contain exactly one ProofAccepted event; found {}",
            candidates.len()
        ));
    }
    let fields = event_fields(
        candidates[0],
        "ProofAccepted",
        transaction_hash,
        block_hash,
        block_number,
        prepared.core,
    )?;
    let topics = event_topics(fields, "ProofAccepted", 4)?;
    require_topic_address(topics, 1, "ProofAccepted miner", prepared.proof_miner())?;
    require_topic_uint256(
        topics,
        2,
        "ProofAccepted challengeId",
        prepared.challenge_id,
    )?;
    require_topic_digest(topics, 3, "ProofAccepted digest", prepared.expected_digest)?;
    let words = event_data_words(fields, "ProofAccepted", 8)?;
    require_word_uint256(
        &words,
        0,
        "ProofAccepted seedParentBlock",
        prepared.seed_parent_block,
    )?;
    require_word_digest(&words, 1, "ProofAccepted challenge", prepared.challenge)?;
    require_word_uint256(
        &words,
        2,
        "ProofAccepted mining nonce",
        prepared.mining_nonce,
    )
}

fn verify_proof_nft_event(
    logs: &[Value],
    transaction_hash: Digest,
    block_hash: Digest,
    block_number: Uint256,
    prepared: &PreparedSubmission,
) -> Result<Option<Uint256>, String> {
    let signature =
        event_signature(b"ProofNftMinted(address,uint256,uint256,bytes32,uint8,address)");
    let candidates = event_candidates(logs, signature)?;
    if candidates.is_empty() {
        return Ok(None);
    }
    if candidates.len() != 1 {
        return Err(format!(
            "proof receipt must contain at most one ProofNftMinted event; found {}",
            candidates.len()
        ));
    }
    let fields = event_fields(
        candidates[0],
        "ProofNftMinted",
        transaction_hash,
        block_hash,
        block_number,
        prepared.core,
    )?;
    let topics = event_topics(fields, "ProofNftMinted", 4)?;
    require_topic_address(topics, 1, "ProofNftMinted miner", prepared.proof_miner())?;
    require_topic_uint256(
        topics,
        3,
        "ProofNftMinted challengeId",
        prepared.challenge_id,
    )?;
    let words = event_data_words(fields, "ProofNftMinted", 3)?;
    require_word_digest(&words, 0, "ProofNftMinted digest", prepared.expected_digest)?;
    let mut basket_word = [0_u8; 32];
    basket_word[12..].copy_from_slice(&prepared.basket.to_bytes());
    require_word_uint256(
        &words,
        2,
        "ProofNftMinted basket",
        Uint256::from_be_bytes(basket_word),
    )?;
    let tier = parse_uint256_word(&words[1], "ProofNftMinted tier")?;
    if tier < Uint256::ONE || tier > Uint256::from(4_u64) {
        return Err("ProofNftMinted tier is outside the NFT tier range".to_owned());
    }
    let token_id = parse_uint256_word(
        topics[2].as_str().ok_or("NFT token ID must be a word")?,
        "NFT token ID",
    )?;
    if token_id == Uint256::ZERO {
        return Err("ProofNftMinted token ID must be nonzero".to_owned());
    }
    Ok(Some(token_id))
}

impl PreparedSubmission {
    /// The address the core records as miner: the router for a claim, else the signer.
    fn proof_miner(&self) -> Address {
        self.claim.map_or(self.miner, |route| route.router)
    }
}

/// A claim journal must describe exactly one bound claim to its router, whose
/// digest (router as miner) matches the one recorded before signing.
fn validate_claim_journal(prepared: &PreparedSubmission, route: ClaimRoute) -> Result<(), String> {
    let Some((hunter, nonce, basket)) =
        crate::hunt::decode_claim_call_data(&prepared.transaction.data)
    else {
        return Err("claim journal has invalid calldata".to_owned());
    };
    if prepared.transaction.to != route.router
        || hunter != prepared.miner
        || nonce != prepared.mining_nonce
        || basket != prepared.basket
        || !crate::hunt::is_bound_nonce(nonce, hunter)
    {
        return Err("claim journal calldata does not match its recorded claim".to_owned());
    }
    let digest = proof_digest(&ProofInputs {
        chain_id: prepared.transaction.chain_id,
        mining_core: prepared.core,
        challenge_id: prepared.challenge_id,
        challenge: prepared.challenge,
        miner: route.router,
        nonce,
    });
    if digest != prepared.expected_digest {
        return Err("claim journal digest does not match its recorded claim".to_owned());
    }
    Ok(())
}

/// A successful claim must hand the minted Hunter NFT to the hunter: exactly one
/// `HunterClaimed` from the router and one NFT transfer from the router to the hunter.
fn verify_claim_delivery(
    logs: &[Value],
    transaction_hash: Digest,
    block_hash: Digest,
    block_number: Uint256,
    prepared: &PreparedSubmission,
    route: ClaimRoute,
    minted: Option<Uint256>,
) -> Result<(), String> {
    let claimed = event_candidates(
        logs,
        event_signature(b"HunterClaimed(address,uint256,uint8,uint256)"),
    )?;
    let transfers = event_candidates(logs, event_signature(b"Transfer(address,address,uint256)"))?;
    let Some(token_id) = minted else {
        if claimed.is_empty() {
            return Ok(());
        }
        return Err("claim receipt reports a delivery without a mint".to_owned());
    };
    if claimed.len() != 1 {
        return Err(format!(
            "successful claim receipt must contain exactly one HunterClaimed event; found {}",
            claimed.len()
        ));
    }
    let fields = event_fields(
        claimed[0],
        "HunterClaimed",
        transaction_hash,
        block_hash,
        block_number,
        route.router,
    )?;
    let topics = event_topics(fields, "HunterClaimed", 3)?;
    require_topic_address(topics, 1, "HunterClaimed hunter", prepared.miner)?;
    require_topic_uint256(topics, 2, "HunterClaimed tokenId", token_id)?;
    let words = event_data_words(fields, "HunterClaimed", 2)?;
    require_word_uint256(
        &words,
        1,
        "HunterClaimed challengeId",
        prepared.challenge_id,
    )?;

    let mut delivered = 0;
    for log in transfers {
        let Some(address) = log.get("address").and_then(Value::as_str) else {
            continue;
        };
        if parse_address(address, "Transfer emitter")? != route.nft {
            continue;
        }
        let fields = event_fields(
            log,
            "Transfer",
            transaction_hash,
            block_hash,
            block_number,
            route.nft,
        )?;
        let topics = event_topics(fields, "Transfer", 4)?;
        if topic_word(topics, 1, "Transfer from")?.to_be_bytes()
            == crate::hunt::address_word(route.router)
        {
            require_topic_address(topics, 2, "Transfer to", prepared.miner)?;
            require_topic_uint256(topics, 3, "Transfer tokenId", token_id)?;
            delivered += 1;
        }
    }
    if delivered != 1 {
        return Err(format!(
            "successful claim receipt must move the Hunter NFT from the router to the wallet exactly once; found {delivered}"
        ));
    }
    Ok(())
}

fn event_candidates(logs: &[Value], signature: Digest) -> Result<Vec<&Value>, String> {
    let signature = hex_string(&signature.to_bytes());
    logs.iter()
        .filter_map(|log| {
            let fields = match log.as_object() {
                Some(fields) => fields,
                None => return Some(Err("proof receipt log must be an object".to_owned())),
            };
            let first_topic = fields
                .get("topics")
                .and_then(Value::as_array)
                .and_then(|topics| topics.first())
                .and_then(Value::as_str);
            match first_topic {
                Some(topic) if topic.eq_ignore_ascii_case(&signature) => Some(Ok(log)),
                _ => None,
            }
        })
        .collect()
}

fn event_fields<'a>(
    log: &'a Value,
    event: &str,
    transaction_hash: Digest,
    block_hash: Digest,
    block_number: Uint256,
    emitter: Address,
) -> Result<&'a serde_json::Map<String, Value>, String> {
    let fields = log
        .as_object()
        .ok_or_else(|| format!("{event} log must be an object"))?;
    require_address_field(fields, "address", event, emitter)?;
    require_digest_field(fields, "transactionHash", event, transaction_hash)?;
    require_digest_field(fields, "blockHash", event, block_hash)?;
    require_quantity_field(fields, "blockNumber", event, block_number)?;
    match fields.get("removed").and_then(Value::as_bool) {
        Some(false) => {}
        _ => return Err(format!("{event} log must have `removed` set to false")),
    }
    Ok(fields)
}

fn event_topics<'a>(
    fields: &'a serde_json::Map<String, Value>,
    event: &str,
    expected_len: usize,
) -> Result<&'a [Value], String> {
    let topics = fields
        .get("topics")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{event} log is missing `topics`"))?;
    if topics.len() != expected_len {
        return Err(format!(
            "{event} log must have exactly {expected_len} topics"
        ));
    }
    Ok(topics)
}

fn event_data_words(
    fields: &serde_json::Map<String, Value>,
    event: &str,
    expected_words: usize,
) -> Result<Vec<String>, String> {
    let data = fields
        .get("data")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{event} log is missing `data`"))?;
    let hex = data
        .strip_prefix("0x")
        .ok_or_else(|| format!("{event} data must be 0x-prefixed"))?;
    if hex.len() != expected_words * 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "{event} data must contain exactly {expected_words} ABI words"
        ));
    }
    Ok(hex
        .as_bytes()
        .chunks_exact(64)
        .map(|word| format!("0x{}", std::str::from_utf8(word).expect("hex is ASCII")))
        .collect())
}

fn require_topic_address(
    topics: &[Value],
    index: usize,
    name: &str,
    expected: Address,
) -> Result<(), String> {
    let word = topic_word(topics, index, name)?.to_be_bytes();
    let mut expected_word = [0_u8; 32];
    expected_word[12..].copy_from_slice(&expected.to_bytes());
    if word != expected_word {
        return Err(format!("{name} does not match the prepared proof"));
    }
    Ok(())
}

fn require_topic_uint256(
    topics: &[Value],
    index: usize,
    name: &str,
    expected: Uint256,
) -> Result<(), String> {
    if topic_word(topics, index, name)? != expected {
        return Err(format!("{name} does not match the prepared proof"));
    }
    Ok(())
}

fn require_topic_digest(
    topics: &[Value],
    index: usize,
    name: &str,
    expected: Digest,
) -> Result<(), String> {
    let actual = topics
        .get(index)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{name} must be a 32-byte topic"))?;
    if parse_digest(actual, name)? != expected {
        return Err(format!("{name} does not match the prepared proof"));
    }
    Ok(())
}

fn topic_word(topics: &[Value], index: usize, name: &str) -> Result<Uint256, String> {
    let value = topics
        .get(index)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{name} must be a 32-byte topic"))?;
    parse_uint256_word(value, name)
}

fn require_word_uint256(
    words: &[String],
    index: usize,
    name: &str,
    expected: Uint256,
) -> Result<(), String> {
    if parse_uint256_word(&words[index], name)? != expected {
        return Err(format!("{name} does not match the prepared proof"));
    }
    Ok(())
}

fn require_word_digest(
    words: &[String],
    index: usize,
    name: &str,
    expected: Digest,
) -> Result<(), String> {
    if parse_digest(&words[index], name)? != expected {
        return Err(format!("{name} does not match the prepared proof"));
    }
    Ok(())
}

fn event_signature(signature: &[u8]) -> Digest {
    keccak256(signature)
}

fn require_digest_field(
    fields: &serde_json::Map<String, Value>,
    name: &str,
    context: &str,
    expected: Digest,
) -> Result<(), String> {
    if digest_field(fields, name, context)? != expected {
        return Err(format!(
            "{context} `{name}` does not match the locally signed transaction"
        ));
    }
    Ok(())
}

fn digest_field(
    fields: &serde_json::Map<String, Value>,
    name: &str,
    context: &str,
) -> Result<Digest, String> {
    let value = fields
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{context} is missing `{name}`"))?;
    parse_digest(value, &format!("{context} {name}"))
}

fn require_address_field(
    fields: &serde_json::Map<String, Value>,
    name: &str,
    context: &str,
    expected: Address,
) -> Result<(), String> {
    let value = fields
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{context} is missing `{name}`"))?;
    if parse_address(value, &format!("{context} {name}"))? != expected {
        return Err(format!(
            "{context} `{name}` does not match the prepared proof"
        ));
    }
    Ok(())
}

fn require_quantity_field(
    fields: &serde_json::Map<String, Value>,
    name: &str,
    context: &str,
    expected: Uint256,
) -> Result<(), String> {
    if quantity_field(fields, name, context)? != expected {
        return Err(format!(
            "{context} `{name}` does not match the locally signed transaction"
        ));
    }
    Ok(())
}

fn quantity_field(
    fields: &serde_json::Map<String, Value>,
    name: &str,
    context: &str,
) -> Result<Uint256, String> {
    let value = fields
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{context} is missing `{name}`"))?;
    parse_hex_quantity_uint256(value, &format!("{context} {name}"))
}

fn require_hex_bytes_field(
    fields: &serde_json::Map<String, Value>,
    name: &str,
    context: &str,
    expected: &[u8],
) -> Result<(), String> {
    let value = fields
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{context} is missing `{name}`"))?;
    if !value.eq_ignore_ascii_case(&hex_string(expected)) {
        return Err(format!(
            "{context} `{name}` does not match the locally signed transaction"
        ));
    }
    Ok(())
}

fn receipt_quantity(
    fields: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<Uint256, String> {
    let value = fields
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("proof transaction receipt is missing `{name}`"))?;
    parse_hex_quantity_uint256(value, &format!("receipt {name}"))
}

fn uint256_to_u128(value: Uint256, name: &str) -> Result<u128, String> {
    let bytes = value.to_be_bytes();
    if bytes[..16].iter().any(|byte| *byte != 0) {
        return Err(format!("{name} exceeds the supported u128 range"));
    }
    let mut lower = [0_u8; 16];
    lower.copy_from_slice(&bytes[16..]);
    Ok(u128::from_be_bytes(lower))
}

fn uint256_to_u64(value: Uint256, name: &str) -> Result<u64, String> {
    let bytes = value.to_be_bytes();
    if bytes[..24].iter().any(|byte| *byte != 0) {
        return Err(format!("{name} exceeds the supported u64 range"));
    }
    let mut lower = [0_u8; 8];
    lower.copy_from_slice(&bytes[24..]);
    Ok(u64::from_be_bytes(lower))
}

fn disambiguate_mining_nonce(error: &str) -> String {
    error
        .replace("Nonce", "__MINING_NONCE__")
        .replace("nonce", "mining nonce")
        .replace("__MINING_NONCE__", "Mining nonce")
}

fn disambiguate_account_nonce(error: &str) -> String {
    error
        .replace("Nonce", "__ACCOUNT_NONCE__")
        .replace("nonce", "account nonce")
        .replace("__ACCOUNT_NONCE__", "Account nonce")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    use proof_core::{ChallengeInputs, Target, derive_challenge};

    use super::*;

    #[test]
    fn pending_submission_journal_round_trips_and_refuses_overwrite() {
        let directory = std::env::temp_dir().join(format!(
            "bproof-pending-journal-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let path = directory.join("wallet.json.pending-submission.json");
        let prepared = prepared_fixture();
        let raw = vec![0x02, 0x01, 0x02, 0x03];
        let hash = keccak256(&raw);
        let document = PendingSubmissionDocument::from_prepared(
            hash,
            &hex_string(&raw),
            &prepared,
            "proofHunter",
            Some("test classification"),
        );

        persist_pending_document(&path, &document).unwrap();
        let metadata = fs::metadata(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        }
        let stored = read_pending_document(&path).unwrap();
        let (stored_hash, stored_raw, stored_prepared) = stored.to_prepared().unwrap();
        assert_eq!(stored_hash, hash);
        assert_eq!(stored_raw, raw);
        assert_eq!(stored_prepared.miner, prepared.miner);
        assert_eq!(stored_prepared.transaction.data, prepared.transaction.data);
        assert!(persist_pending_document(&path, &document).is_err());
        clear_pending_document(&path).unwrap();
        assert!(!path.exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_bare_keystore_file_name_journals_in_the_current_directory() {
        let path = pending_submission_path(Path::new("wallet.json"));
        assert_eq!(path, PathBuf::from("wallet.json.pending-submission.json"));
        assert_eq!(journal_directory(&path), Path::new("."));
        assert_eq!(
            journal_directory(Path::new("dir/wallet.json.pending-submission.json")),
            Path::new("dir")
        );
    }

    #[cfg(unix)]
    #[test]
    fn pending_submission_journal_fails_closed_on_open_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory =
            std::env::temp_dir().join(format!("bproof-pending-permissions-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let path = directory.join("pending.json");
        fs::write(&path, b"{}\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let error = read_pending_document(&path).unwrap_err();
        assert!(error.contains("owner-only"), "error: {error}");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn pending_submission_journal_rejects_tampered_fee_authority() {
        let prepared = prepared_fixture();
        let raw = vec![0x02, 0x01, 0x02, 0x03];
        let mut document = PendingSubmissionDocument::from_prepared(
            keccak256(&raw),
            &hex_string(&raw),
            &prepared,
            "proofHunter",
            None,
        );

        document.priority_fee_per_gas_wei = "2".to_owned();
        let error = document.to_prepared().unwrap_err();
        assert!(error.contains("inconsistent fee fields"), "error: {error}");

        let mut document = PendingSubmissionDocument::from_prepared(
            keccak256(&raw),
            &hex_string(&raw),
            &prepared,
            "proofHunter",
            None,
        );
        document.maximum_exposure_wei = "1".to_owned();
        let error = document.to_prepared().unwrap_err();
        assert!(error.contains("fee exposure"), "error: {error}");
    }

    #[cfg(unix)]
    #[test]
    fn pending_submission_journal_refuses_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory =
            std::env::temp_dir().join(format!("bproof-pending-symlink-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let target = directory.join("target.json");
        let link = directory.join("pending.json");
        fs::write(&target, b"{}\n").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &link).unwrap();
        let error = read_pending_document(&link).unwrap_err();
        assert!(error.contains("securely open"), "error: {error}");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn recorded_fee_formula_and_margin_bound_total_exposure() {
        let quote = fee_quote(10, 3, 21_001, 25, 1_000_000).unwrap();
        assert_eq!(quote.max_fee_per_gas_wei, 23);
        assert_eq!(quote.gas_limit, 26_252);
        assert_eq!(quote.maximum_exposure_wei, 603_796);
    }

    #[test]
    fn fee_ceiling_is_compared_to_maximum_exposure_inclusively() {
        let exact = fee_quote(10, 3, 100, 25, 2_875).unwrap();
        assert_eq!(exact.maximum_exposure_wei, exact.fee_ceiling_wei);
        assert!(exact.maximum_exposure_wei <= exact.fee_ceiling_wei);

        let below = fee_quote(10, 3, 100, 25, 2_874).unwrap();
        assert!(below.maximum_exposure_wei > below.fee_ceiling_wei);
    }

    #[test]
    fn error_disambiguation_never_leaves_a_plain_transaction_count_name() {
        let error = disambiguate_account_nonce("nonce too low; Nonce already used");
        assert_eq!(error, "account nonce too low; Account nonce already used");
    }

    #[test]
    fn successful_receipt_requires_the_exact_locally_prepared_proof_event() {
        let prepared = prepared_fixture();
        let transaction_hash = Digest::from_bytes([0x77; 32]);
        let block_hash = Digest::from_bytes([0x88; 32]);
        let block_number = Uint256::from(21_u64);
        let mut receipt_value = json!({
            "transactionHash": hex_string(&transaction_hash.to_bytes()),
            "from": hex_string(&prepared.miner.to_bytes()),
            "to": hex_string(&prepared.transaction.to.to_bytes()),
            "blockHash": hex_string(&block_hash.to_bytes()),
            "blockNumber": "0x15",
            "status": "0x1",
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x2",
            "logs": [{
                "address": hex_string(&prepared.transaction.to.to_bytes()),
                "transactionHash": hex_string(&transaction_hash.to_bytes()),
                "blockHash": hex_string(&block_hash.to_bytes()),
                "blockNumber": "0x15",
                "removed": false,
                "topics": [
                    hex_string(&event_signature(b"ProofAccepted(address,uint256,bytes32,uint256,bytes32,uint256,uint256,uint256,uint256,uint256,bool)").to_bytes()),
                    address_topic(prepared.miner),
                    hex_string(&prepared.challenge_id.to_be_bytes()),
                    hex_string(&prepared.expected_digest.to_bytes()),
                ],
                "data": abi_data(&[
                    prepared.seed_parent_block.to_be_bytes(),
                    prepared.challenge.to_bytes(),
                    prepared.mining_nonce.to_be_bytes(),
                    Uint256::from(100_u64).to_be_bytes(),
                    Uint256::from(2_u64).to_be_bytes(),
                    Uint256::from(22_u64).to_be_bytes(),
                    Uint256::from(90_u64).to_be_bytes(),
                    Uint256::ZERO.to_be_bytes(),
                ]),
            }],
        });
        let mut mint = receipt_value["logs"][0].clone();
        mint["topics"] = json!([
            hex_string(
                &event_signature(b"ProofNftMinted(address,uint256,uint256,bytes32,uint8,address)")
                    .to_bytes()
            ),
            address_topic(prepared.miner),
            hex_string(&Uint256::ONE.to_be_bytes()),
            hex_string(&prepared.challenge_id.to_be_bytes()),
        ]);
        let mut basket_word = [0_u8; 32];
        basket_word[12..].copy_from_slice(&prepared.basket.to_bytes());
        mint["data"] = json!(abi_data(&[
            prepared.expected_digest.to_bytes(),
            Uint256::ONE.to_be_bytes(),
            basket_word
        ]));
        receipt_value["logs"].as_array_mut().unwrap().push(mint);
        let mut no_mint = receipt_value.clone();
        no_mint["logs"].as_array_mut().unwrap().pop();
        assert!(parse_receipt(&no_mint, transaction_hash, &prepared).is_err());
        let mut wrong_basket = receipt_value.clone();
        wrong_basket["logs"][1]["data"] = json!(abi_data(&[
            prepared.expected_digest.to_bytes(),
            Uint256::ONE.to_be_bytes(),
            [0; 32]
        ]));
        assert!(
            parse_receipt(&wrong_basket, transaction_hash, &prepared)
                .unwrap_err()
                .contains("basket")
        );
        let mut duplicate = receipt_value.clone();
        duplicate["logs"]
            .as_array_mut()
            .unwrap()
            .push(receipt_value["logs"][1].clone());
        assert!(parse_receipt(&duplicate, transaction_hash, &prepared).is_err());
        let receipt = parse_receipt(&receipt_value, transaction_hash, &prepared).unwrap();
        assert!(receipt.succeeded);
        assert!(receipt.proof_nft_minted);
        assert_eq!(receipt.block_hash, block_hash);
        assert_eq!(receipt.block_number, block_number);

        let mut forged = receipt_value;
        forged["logs"][0]["topics"][3] = json!(hex_string(&[0x99; 32]));
        let error = parse_receipt(&forged, transaction_hash, &prepared)
            .expect_err("a different proof digest must not be accepted");
        assert!(error.contains("ProofAccepted digest"), "error: {error}");
    }

    #[test]
    fn refresh_event_must_match_identity_and_never_count_as_a_proof() {
        let mut prepared = prepared_fixture();
        prepared.seed_refresh = true;
        prepared.transaction.data = refresh_call_data();
        let hash = Digest::from_bytes([0x77; 32]);
        let block_hash = Digest::from_bytes([0x88; 32]);
        let event = json!({
            "address":hex_string(&prepared.transaction.to.to_bytes()),
            "transactionHash":hex_string(&hash.to_bytes()), "blockHash":hex_string(&block_hash.to_bytes()),
            "blockNumber":"0x15", "removed":false,
            "topics":[hex_string(&event_signature(b"SeedRefreshed(uint256,uint256,uint256,uint256)").to_bytes()),
                hex_string(&prepared.challenge_id.to_be_bytes()),hex_string(&prepared.challenge_id.wrapping_add(Uint256::ONE).to_be_bytes())],
            "data":abi_data(&[prepared.seed_parent_block.to_be_bytes(), prepared.seed_parent_block.wrapping_add(Uint256::from(300_u64)).to_be_bytes()]),
        });
        let mut value = json!({"transactionHash":hex_string(&hash.to_bytes()), "from":hex_string(&prepared.miner.to_bytes()),
            "to":hex_string(&prepared.transaction.to.to_bytes()), "blockHash":hex_string(&block_hash.to_bytes()), "blockNumber":"0x15",
            "status":"0x1", "gasUsed":"0x5208", "effectiveGasPrice":"0x2", "logs":[event]});
        let receipt = parse_receipt(&value, hash, &prepared).unwrap();
        assert!(receipt.succeeded);
        assert!(!receipt.proof_nft_minted);
        let original = value.clone();
        value["logs"][0]["topics"][1] = json!(hex_string(&Uint256::ZERO.to_be_bytes()));
        assert!(parse_receipt(&value, hash, &prepared).is_err());
        value = original.clone();
        value["logs"][0]["removed"] = json!(true);
        assert!(parse_receipt(&value, hash, &prepared).is_err());
        value = original.clone();
        value["logs"][0]["address"] = json!(hex_string(&[0x99; 20]));
        assert!(parse_receipt(&value, hash, &prepared).is_err());
        value = original.clone();
        value["logs"] = json!([]);
        assert!(parse_receipt(&value, hash, &prepared).is_err());
        value["status"] = json!("0x0");
        assert!(!parse_receipt(&value, hash, &prepared).unwrap().succeeded);
        value = original;
        value["status"] = json!("0x0");
        assert!(parse_receipt(&value, hash, &prepared).is_err());
    }

    #[test]
    fn refresh_journal_round_trip_and_legacy_proof_compatibility() {
        let mut prepared = prepared_fixture();
        prepared.seed_refresh = true;
        prepared.transaction.data = refresh_call_data();
        let mut doc = PendingSubmissionDocument::from_prepared(
            Digest::ZERO,
            "0x02",
            &prepared,
            "seedRefresh",
            None,
        );
        assert!(doc.to_prepared().unwrap().2.seed_refresh);
        doc.data = "0x12345678".to_owned();
        assert!(doc.to_prepared().unwrap_err().contains("calldata"));
        doc.seed_refresh = false;
        doc.version = 1;
        let mut legacy = serde_json::to_value(doc).unwrap();
        legacy.as_object_mut().unwrap().remove("seedRefresh");
        let legacy: PendingSubmissionDocument = serde_json::from_value(legacy).unwrap();
        assert!(!legacy.to_prepared().unwrap().2.seed_refresh);
    }

    fn prepared_fixture() -> PreparedSubmission {
        let miner = Address::from_bytes([0x11; 20]);
        let mining_core = Address::from_bytes([0x22; 20]);
        let challenge_id = Uint256::ONE;
        let seed_parent_block = Uint256::from(1_003_u64);
        let challenge = Digest::from_bytes([0x33; 32]);
        let mining_nonce = Uint256::from(9_u64);
        let expected_digest = proof_digest(&ProofInputs {
            chain_id: Uint256::from(31_337_u64),
            mining_core,
            challenge_id,
            challenge,
            miner,
            nonce: mining_nonce,
        });
        PreparedSubmission {
            seed_refresh: false,
            mining_nonce,
            account_nonce: Uint256::ZERO,
            fee_quote: fee_quote(1, 1, 21_000, 25, u128::MAX).unwrap(),
            miner,
            core: mining_core,
            claim: None,
            upkeep: None,
            challenge_id,
            seed_parent_block,
            challenge,
            expected_digest,
            basket: Address::from_bytes([0x55; 20]),
            transaction: Eip1559Transaction {
                chain_id: Uint256::from(31_337_u64),
                account_nonce: Uint256::ZERO,
                max_priority_fee_per_gas: Uint256::ONE,
                max_fee_per_gas: Uint256::from(3_u64),
                gas_limit: Uint256::from(26_250_u64),
                to: mining_core,
                data: submit_proof_call_data(
                    challenge_id,
                    seed_parent_block,
                    mining_nonce,
                    Address::from_bytes([0x55; 20]),
                ),
            },
        }
    }

    fn claim_fixture() -> PreparedSubmission {
        let mut prepared = prepared_fixture();
        let route = ClaimRoute {
            router: Address::from_bytes([0x7e; 20]),
            nft: Address::from_bytes([0x9f; 20]),
        };
        let nonce = crate::hunt::bound_nonce(prepared.miner, Uint256::from(9_u64)).unwrap();
        prepared.claim = Some(route);
        prepared.mining_nonce = nonce;
        prepared.transaction.to = route.router;
        prepared.transaction.data =
            crate::hunt::claim_call_data(prepared.miner, nonce, prepared.basket);
        prepared.expected_digest = proof_digest(&ProofInputs {
            chain_id: prepared.transaction.chain_id,
            mining_core: prepared.core,
            challenge_id: prepared.challenge_id,
            challenge: prepared.challenge,
            miner: route.router,
            nonce,
        });
        prepared
    }

    #[test]
    fn claim_journal_round_trips_as_version_three_and_refuses_tampering() {
        let prepared = claim_fixture();
        let document = PendingSubmissionDocument::from_prepared(
            Digest::ZERO,
            "0x02",
            &prepared,
            "proofHunter",
            None,
        );
        assert_eq!(document.version, PENDING_CLAIM_VERSION);
        let (_, _, restored) = document.to_prepared().unwrap();
        assert_eq!(restored.claim, prepared.claim);
        assert_eq!(restored.core, prepared.core);
        assert_eq!(restored.transaction.to, prepared.claim.unwrap().router);
        assert_eq!(restored.proof_miner(), prepared.claim.unwrap().router);

        let encoded = serde_json::to_value(&document).unwrap();
        let reload = |value: &serde_json::Value| -> Result<(), String> {
            let document: PendingSubmissionDocument =
                serde_json::from_value(value.clone()).map_err(|error| error.to_string())?;
            document.to_prepared().map(drop)
        };
        // Another nonce in the calldata, a digest for the wrong miner, a missing router,
        // or claim fields on an older version are all refused.
        let mut tampered = encoded.clone();
        let other = crate::hunt::claim_call_data(
            prepared.miner,
            prepared.mining_nonce.wrapping_add(Uint256::ONE),
            prepared.basket,
        );
        tampered["data"] = json!(hex_string(&other));
        assert!(reload(&tampered).unwrap_err().contains("calldata"));
        let mut tampered = encoded.clone();
        tampered["expectedDigest"] = json!(hex_string(&[0x44; 32]));
        assert!(reload(&tampered).unwrap_err().contains("digest"));
        let mut tampered = encoded.clone();
        tampered.as_object_mut().unwrap().remove("router");
        assert!(reload(&tampered).is_err());
        let mut tampered = encoded;
        tampered["version"] = json!(2);
        assert!(reload(&tampered).is_err());
        // v1-path journals stay version 2 and carry no claim fields.
        let direct = PendingSubmissionDocument::from_prepared(
            Digest::ZERO,
            "0x02",
            &prepared_fixture(),
            "proofHunter",
            None,
        );
        assert_eq!(direct.version, PENDING_SUBMISSION_VERSION);
        assert!(direct.router.is_none() && direct.core.is_none());
    }

    #[test]
    fn a_claim_receipt_must_deliver_the_hunter_nft_to_the_wallet() {
        let prepared = claim_fixture();
        let route = prepared.claim.unwrap();
        let hash = Digest::from_bytes([0x77; 32]);
        let block_hash = Digest::from_bytes([0x88; 32]);
        let token = Uint256::from(825_u64);
        let log = |emitter: Address, topics: Vec<String>, data: String| {
            json!({
                "address": hex_string(&emitter.to_bytes()),
                "transactionHash": hex_string(&hash.to_bytes()),
                "blockHash": hex_string(&block_hash.to_bytes()),
                "blockNumber": "0x15",
                "removed": false,
                "topics": topics,
                "data": data,
            })
        };
        let accepted = log(
            prepared.core,
            vec![
                hex_string(&event_signature(b"ProofAccepted(address,uint256,bytes32,uint256,bytes32,uint256,uint256,uint256,uint256,uint256,bool)").to_bytes()),
                address_topic(route.router),
                hex_string(&prepared.challenge_id.to_be_bytes()),
                hex_string(&prepared.expected_digest.to_bytes()),
            ],
            abi_data(&[
                prepared.seed_parent_block.to_be_bytes(),
                prepared.challenge.to_bytes(),
                prepared.mining_nonce.to_be_bytes(),
                Uint256::from(100_u64).to_be_bytes(),
                Uint256::from(2_u64).to_be_bytes(),
                Uint256::from(22_u64).to_be_bytes(),
                Uint256::from(90_u64).to_be_bytes(),
                Uint256::ZERO.to_be_bytes(),
            ]),
        );
        let minted = log(
            prepared.core,
            vec![
                hex_string(
                    &event_signature(
                        b"ProofNftMinted(address,uint256,uint256,bytes32,uint8,address)",
                    )
                    .to_bytes(),
                ),
                address_topic(route.router),
                hex_string(&token.to_be_bytes()),
                hex_string(&prepared.challenge_id.to_be_bytes()),
            ],
            abi_data(&[
                prepared.expected_digest.to_bytes(),
                Uint256::ONE.to_be_bytes(),
                crate::hunt::address_word(prepared.basket),
            ]),
        );
        let transfer_signature =
            hex_string(&event_signature(b"Transfer(address,address,uint256)").to_bytes());
        let mint_transfer = log(
            route.nft,
            vec![
                transfer_signature.clone(),
                address_topic(Address::from_bytes([0; 20])),
                address_topic(route.router),
                hex_string(&token.to_be_bytes()),
            ],
            "0x".to_owned(),
        );
        let delivery = log(
            route.nft,
            vec![
                transfer_signature,
                address_topic(route.router),
                address_topic(prepared.miner),
                hex_string(&token.to_be_bytes()),
            ],
            "0x".to_owned(),
        );
        let claimed = log(
            route.router,
            vec![
                hex_string(
                    &event_signature(b"HunterClaimed(address,uint256,uint8,uint256)").to_bytes(),
                ),
                address_topic(prepared.miner),
                hex_string(&token.to_be_bytes()),
            ],
            abi_data(&[
                Uint256::ONE.to_be_bytes(),
                prepared.challenge_id.to_be_bytes(),
            ]),
        );
        let receipt = |logs: Vec<Value>| {
            json!({
                "transactionHash": hex_string(&hash.to_bytes()),
                "from": hex_string(&prepared.miner.to_bytes()),
                "to": hex_string(&route.router.to_bytes()),
                "blockHash": hex_string(&block_hash.to_bytes()),
                "blockNumber": "0x15",
                "status": "0x1",
                "gasUsed": "0x5208",
                "effectiveGasPrice": "0x2",
                "logs": logs,
            })
        };
        let complete = vec![
            mint_transfer.clone(),
            accepted.clone(),
            minted.clone(),
            delivery.clone(),
            claimed.clone(),
        ];
        let parsed = parse_receipt(&receipt(complete), hash, &prepared).unwrap();
        assert!(parsed.succeeded && parsed.proof_nft_minted);
        assert_eq!(parsed.nft_token_id, Some(token));

        // No delivery to the wallet, no claim event, or a delivery to someone else: refused.
        let no_delivery = vec![
            mint_transfer.clone(),
            accepted.clone(),
            minted.clone(),
            claimed.clone(),
        ];
        assert!(parse_receipt(&receipt(no_delivery), hash, &prepared).is_err());
        let no_claim = vec![
            mint_transfer.clone(),
            accepted.clone(),
            minted.clone(),
            delivery.clone(),
        ];
        assert!(parse_receipt(&receipt(no_claim), hash, &prepared).is_err());
        let mut elsewhere = delivery;
        elsewhere["topics"][2] = json!(address_topic(Address::from_bytes([0x66; 20])));
        let stolen = vec![mint_transfer, accepted.clone(), minted, elsewhere, claimed];
        assert!(parse_receipt(&receipt(stolen), hash, &prepared).is_err());
        // The proof events must name the router as miner.
        let mut as_wallet = accepted;
        as_wallet["topics"][1] = json!(address_topic(prepared.miner));
        assert!(parse_receipt(&receipt(vec![as_wallet]), hash, &prepared).is_err());
    }

    fn upkeep_fixture(kind: UpkeepKind) -> PreparedSubmission {
        let mut prepared = prepared_fixture();
        let router = Address::from_bytes([0x7e; 20]);
        prepared.upkeep = Some(kind);
        prepared.transaction.to = match kind {
            UpkeepKind::Ease => prepared.core,
            UpkeepKind::Lock => router,
        };
        prepared.transaction.data = kind.call_data();
        prepared
    }

    #[test]
    fn upkeep_journals_round_trip_and_refuse_foreign_calldata() {
        for kind in [UpkeepKind::Ease, UpkeepKind::Lock] {
            let prepared = upkeep_fixture(kind);
            let document = PendingSubmissionDocument::from_prepared(
                Digest::ZERO,
                "0x02",
                &prepared,
                "upkeep",
                None,
            );
            assert_eq!(document.version, PENDING_CLAIM_VERSION);
            assert_eq!(document.upkeep.as_deref(), Some(kind.name()));
            let (_, _, restored) = document.to_prepared().unwrap();
            assert_eq!(restored.upkeep, Some(kind));
            assert!(restored.claim.is_none());
            assert_eq!(restored.transaction.to, prepared.transaction.to);

            let mut tampered = serde_json::to_value(&document).unwrap();
            tampered["data"] = json!(hex_string(&refresh_call_data()));
            let tampered: PendingSubmissionDocument = serde_json::from_value(tampered).unwrap();
            assert!(tampered.to_prepared().unwrap_err().contains("upkeep"));
        }
        let mut unknown = serde_json::to_value(PendingSubmissionDocument::from_prepared(
            Digest::ZERO,
            "0x02",
            &upkeep_fixture(UpkeepKind::Ease),
            "upkeep",
            None,
        ))
        .unwrap();
        unknown["upkeep"] = json!("draw");
        let unknown: PendingSubmissionDocument = serde_json::from_value(unknown).unwrap();
        assert!(unknown.to_prepared().is_err());
    }

    #[test]
    fn an_upkeep_receipt_needs_its_own_event_and_never_mints() {
        let prepared = upkeep_fixture(UpkeepKind::Ease);
        let hash = Digest::from_bytes([0x77; 32]);
        let block_hash = Digest::from_bytes([0x88; 32]);
        let eased = json!({
            "address": hex_string(&prepared.core.to_bytes()),
            "transactionHash": hex_string(&hash.to_bytes()),
            "blockHash": hex_string(&block_hash.to_bytes()),
            "blockNumber": "0x15",
            "removed": false,
            "topics": [
                hex_string(&event_signature(b"DifficultyEased(address,uint256,uint256,uint256)").to_bytes()),
                address_topic(prepared.miner),
            ],
            "data": abi_data(&[[1; 32], [2; 32], [3; 32]]),
        });
        let receipt = |logs: Vec<Value>, status: &str| {
            json!({
                "transactionHash": hex_string(&hash.to_bytes()),
                "from": hex_string(&prepared.miner.to_bytes()),
                "to": hex_string(&prepared.core.to_bytes()),
                "blockHash": hex_string(&block_hash.to_bytes()),
                "blockNumber": "0x15",
                "status": status,
                "gasUsed": "0x5208",
                "effectiveGasPrice": "0x2",
                "logs": logs,
            })
        };
        let parsed = parse_receipt(&receipt(vec![eased.clone()], "0x1"), hash, &prepared).unwrap();
        assert!(parsed.succeeded && !parsed.proof_nft_minted);
        assert!(parse_receipt(&receipt(vec![], "0x1"), hash, &prepared).is_err());
        assert!(
            !parse_receipt(&receipt(vec![], "0x0"), hash, &prepared)
                .unwrap()
                .succeeded
        );
        let mut other_caller = eased;
        other_caller["topics"][1] = json!(address_topic(Address::from_bytes([0x66; 20])));
        assert!(parse_receipt(&receipt(vec![other_caller], "0x1"), hash, &prepared).is_err());
    }

    fn address_topic(address: Address) -> String {
        let mut word = [0_u8; 32];
        word[12..].copy_from_slice(&address.to_bytes());
        hex_string(&word)
    }

    fn abi_data(words: &[[u8; 32]]) -> String {
        let mut data = Vec::with_capacity(words.len() * 32);
        for word in words {
            data.extend_from_slice(word);
        }
        hex_string(&data)
    }

    #[test]
    fn stale_challenge_simulation_is_rejected_before_any_send_request() {
        let (endpoint, server) = one_simulation_revert_server();
        let mining_core = Address::from_bytes([0x22; 20]);
        let challenge_inputs = ChallengeInputs {
            chain_id: Uint256::from(31_337_u64),
            mining_core,
            challenge_id: Uint256::ONE,
            previous_accepted_digest: Digest::ZERO,
            seed_parent_block: Uint256::from(1_003_u64),
            seed_blockhash: Digest::from_bytes([0x33; 32]),
        };
        let state = MiningStateFixture {
            challenge_inputs,
            challenge: derive_challenge(&challenge_inputs),
            target: Target::from_be_bytes([0xff; 32]),
        };
        assert_ne!(state.challenge, Digest::ZERO);
        assert_eq!(state.target, Target::from_be_bytes([0xff; 32]));
        let reader = RpcChainReader::new(endpoint, mining_core, challenge_inputs.chain_id);

        let outcome = prepare_submission(
            &reader,
            state.challenge_inputs,
            Address::from_bytes([0x11; 20]),
            Uint256::from(9_u64),
            Address::from_bytes([0x55; 20]),
            FeeOptions {
                fee_ceiling_wei: u128::MAX,
                base_fee_per_gas_override_wei: Some(1),
                priority_fee_per_gas_override_wei: Some(1),
                gas_margin_percent: 25,
            },
        )
        .unwrap();
        server.join().unwrap();

        match outcome {
            PreparationOutcome::SimulationRejected { reason } => {
                assert!(reason.contains("StaleChallengeId"), "reason: {reason}");
            }
            _ => panic!("stale challenge must stop at simulation"),
        }
    }

    #[test]
    fn unreachable_simulation_is_an_rpc_failure_not_a_proof_rejection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            drop(stream);
        });
        let mining_core = Address::from_bytes([0x22; 20]);
        let challenge_inputs = ChallengeInputs {
            chain_id: Uint256::from(31_337_u64),
            mining_core,
            challenge_id: Uint256::ONE,
            previous_accepted_digest: Digest::ZERO,
            seed_parent_block: Uint256::from(1_003_u64),
            seed_blockhash: Digest::from_bytes([0x33; 32]),
        };
        let reader = RpcChainReader::new(endpoint, mining_core, challenge_inputs.chain_id);
        let error = prepare_submission(
            &reader,
            challenge_inputs,
            Address::from_bytes([0x11; 20]),
            Uint256::ZERO,
            Address::from_bytes([0x55; 20]),
            FeeOptions {
                fee_ceiling_wei: u128::MAX,
                base_fee_per_gas_override_wei: Some(1),
                priority_fee_per_gas_override_wei: Some(1),
                gas_margin_percent: 25,
            },
        )
        .expect_err("unreachable endpoint must be retried, not called a rejected proof");
        server.join().unwrap();
        assert!(error.contains("failed to reach JSON-RPC endpoint"));
    }

    struct MiningStateFixture {
        challenge_inputs: ChallengeInputs,
        challenge: Digest,
        target: Target,
    }

    fn one_simulation_revert_server() -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let body = read_request_body(&mut stream);
            let request: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(request["method"], "eth_call");
            let response = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": {
                    "code": 3,
                    "message": "execution reverted: StaleChallengeId(1, 2)"
                }
            })
            .to_string();
            write_response(&mut stream, &response);
            listener.set_nonblocking(true).unwrap();
            thread::sleep(Duration::from_millis(100));
            assert!(
                matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
            );
        });
        (endpoint, server)
    }

    fn read_request_body(stream: &mut TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4_096];
        let (header_end, content_length) = loop {
            let read = stream.read(&mut buffer).unwrap();
            assert_ne!(read, 0);
            request.extend_from_slice(&buffer[..read]);
            let Some(header_start) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n")
            else {
                continue;
            };
            let header_end = header_start + 4;
            let headers = std::str::from_utf8(&request[..header_start]).unwrap();
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            break (header_end, content_length);
        };
        while request.len() < header_end + content_length {
            let read = stream.read(&mut buffer).unwrap();
            assert_ne!(read, 0);
            request.extend_from_slice(&buffer[..read]);
        }
        request[header_end..header_end + content_length].to_vec()
    }

    fn write_response(stream: &mut TcpStream, body: &str) {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
    }
}
