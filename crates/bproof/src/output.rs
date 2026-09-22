//! Stable human and JSON rendering for `bproof` commands.

use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduleNextOutput {
    pub accepted_proofs: String,
    pub total_minted_wei: String,
    pub divisor: String,
    pub reward_wei: String,
    pub reserve_wei: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduleSummaryOutput {
    pub total_proofs: String,
    pub total_minted_wei: String,
    pub first_reward_wei: String,
    pub last_reward_wei: String,
    pub first_floor_proof: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyOutput {
    pub chain_id: String,
    pub mining_core: String,
    pub challenge_id: String,
    pub previous_accepted_digest: String,
    pub seed_parent_block: String,
    pub seed_blockhash: String,
    pub miner: String,
    pub nonce: String,
    pub challenge: String,
    pub digest: String,
    pub target: String,
    pub accepted: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MineFoundOutput {
    #[serde(flatten)]
    pub proof: VerifyOutput,
    pub attempts: String,
    pub threads: String,
    pub proof_classification: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_source: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MineExhaustedOutput {
    pub found: bool,
    pub attempts: String,
    pub threads: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_source: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusOutput {
    pub chain_id: String,
    pub mining_core: String,
    pub challenge_id: String,
    pub previous_accepted_digest: String,
    pub seed_parent_block: String,
    pub seed_blockhash: String,
    pub target: String,
    pub accepted_proofs: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_minted_wei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub divisor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reward_wei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reserve_wei: Option<String>,
    pub settlement_mode: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nfts_minted_ever: Option<String>,
    pub state_source: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmissionOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nft_token_id: Option<String>,
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub transaction_hash: String,
    pub miner: String,
    pub mining_nonce: String,
    pub account_nonce: String,
    pub fee_paid_wei: String,
    pub maximum_exposure_wei: String,
    pub fee_ceiling_wei: String,
    pub base_fee_per_gas_wei: String,
    pub priority_fee_per_gas_wei: String,
    pub max_fee_per_gas_wei: String,
    pub estimated_gas: String,
    pub gas_margin_percent: String,
    pub gas_limit: String,
    pub proof_classification: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification_reason: Option<String>,
    pub state_source: &'static str,
    pub warning: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmissionRejectedOutput {
    pub status: &'static str,
    pub reason: String,
    pub miner: String,
    pub mining_nonce: String,
    pub proof_classification: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification_reason: Option<String>,
    pub state_source: &'static str,
    pub warning: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FeeRefusedOutput {
    pub status: &'static str,
    pub reason: String,
    pub miner: String,
    pub mining_nonce: String,
    pub maximum_exposure_wei: String,
    pub would_have_accepted_fee_ceiling_wei: String,
    pub fee_ceiling_wei: String,
    pub base_fee_per_gas_wei: String,
    pub priority_fee_per_gas_wei: String,
    pub max_fee_per_gas_wei: String,
    pub estimated_gas: String,
    pub gas_margin_percent: String,
    pub gas_limit: String,
    pub proof_classification: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification_reason: Option<String>,
    pub state_source: &'static str,
    pub warning: &'static str,
}

pub fn render_schedule_next(value: &ScheduleNextOutput, json: bool) -> Result<String, String> {
    if json {
        return render_json(value);
    }

    Ok(format!(
        "acceptedProofs: {}\ntotalMintedWei: {}\ndivisor: {}\nrewardWei: {}\nreserveWei: {}",
        value.accepted_proofs,
        value.total_minted_wei,
        value.divisor,
        value.reward_wei,
        value.reserve_wei
    ))
}

pub fn render_schedule_summary(
    value: &ScheduleSummaryOutput,
    json: bool,
) -> Result<String, String> {
    if json {
        return render_json(value);
    }

    Ok(format!(
        "totalProofs: {}\ntotalMintedWei: {}\nfirstRewardWei: {}\nlastRewardWei: {}\nfirstFloorProof: {}",
        value.total_proofs,
        value.total_minted_wei,
        value.first_reward_wei,
        value.last_reward_wei,
        value.first_floor_proof
    ))
}

pub fn render_verify(value: &VerifyOutput, json: bool) -> Result<String, String> {
    if json {
        return render_json(value);
    }

    Ok(format!(
        "chainId: {}\nminingCore: {}\nchallengeId: {}\npreviousAcceptedDigest: {}\nseedParentBlock: {}\nseedBlockhash: {}\nminer: {}\nnonce: {}\nchallenge: {}\ndigest: {}\ntarget: {}\naccepted: {}",
        value.chain_id,
        value.mining_core,
        value.challenge_id,
        value.previous_accepted_digest,
        value.seed_parent_block,
        value.seed_blockhash,
        value.miner,
        value.nonce,
        value.challenge,
        value.digest,
        value.target,
        value.accepted
    ))
}

pub fn render_mine_found(value: &MineFoundOutput, json: bool) -> Result<String, String> {
    if json {
        return render_json(value);
    }

    let mut output = format!(
        "{}\nattempts: {}\nthreads: {}\nproofClassification: {}",
        render_verify(&value.proof, false)?,
        value.attempts,
        value.threads,
        value.proof_classification,
    );
    if let Some(reason) = &value.classification_reason {
        output.push_str(&format!("\nclassificationReason: {reason}"));
    }
    if let Some(state_source) = &value.state_source {
        output.push_str(&format!("\nstateSource: {state_source}"));
    }
    Ok(output)
}

pub fn render_mine_exhausted(value: &MineExhaustedOutput, json: bool) -> Result<String, String> {
    if json {
        return render_json(value);
    }

    let mut output = format!(
        "found: {}\nattempts: {}\nthreads: {}",
        value.found, value.attempts, value.threads
    );
    if let Some(state_source) = &value.state_source {
        output.push_str(&format!("\nstateSource: {state_source}"));
    }
    Ok(output)
}

pub fn render_status(value: &StatusOutput, json: bool) -> Result<String, String> {
    if json {
        return render_json(value);
    }

    let mut output = format!(
        "chainId: {}\nminingCore: {}\nchallengeId: {}\npreviousAcceptedDigest: {}\nseedParentBlock: {}\nseedBlockhash: {}\ntarget: {}\nacceptedProofs: {}\nsettlementMode: {}\nstateSource: {}",
        value.chain_id,
        value.mining_core,
        value.challenge_id,
        value.previous_accepted_digest,
        value.seed_parent_block,
        value.seed_blockhash,
        value.target,
        value.accepted_proofs,
        value.settlement_mode,
        value.state_source,
    );
    for (name, field) in [
        ("nftsMintedEver", &value.nfts_minted_ever),
        ("totalMintedWei", &value.total_minted_wei),
        ("divisor", &value.divisor),
        ("rewardWei", &value.reward_wei),
        ("reserveWei", &value.reserve_wei),
    ] {
        if let Some(value) = field {
            output.push_str(&format!("\n{name}: {value}"));
        }
    }
    Ok(output)
}

pub fn render_submission(value: &SubmissionOutput, json: bool) -> Result<String, String> {
    if json {
        return render_json(value);
    }

    let mut output = format!(
        "status: {}\ntransactionHash: {}\nminer: {}\nminingNonce: {}\naccountNonce: {}\nfeePaidWei: {}\nmaximumExposureWei: {}\nfeeCeilingWei: {}\nbaseFeePerGasWei: {}\npriorityFeePerGasWei: {}\nmaxFeePerGasWei: {}\nestimatedGas: {}\ngasMarginPercent: {}\ngasLimit: {}\nproofClassification: {}\nstateSource: {}",
        value.status,
        value.transaction_hash,
        value.miner,
        value.mining_nonce,
        value.account_nonce,
        value.fee_paid_wei,
        value.maximum_exposure_wei,
        value.fee_ceiling_wei,
        value.base_fee_per_gas_wei,
        value.priority_fee_per_gas_wei,
        value.max_fee_per_gas_wei,
        value.estimated_gas,
        value.gas_margin_percent,
        value.gas_limit,
        value.proof_classification,
        value.state_source,
    );
    if let Some(classification_reason) = &value.classification_reason {
        output.push_str(&format!("\nclassificationReason: {classification_reason}"));
    }
    if let Some(id) = &value.nft_token_id {
        output.push_str(&format!("\nnftTokenId: {id}"));
    }
    if let Some(reason) = &value.reason {
        output.push_str(&format!("\nreason: {reason}"));
    }
    Ok(output)
}

pub fn render_submission_rejected(
    value: &SubmissionRejectedOutput,
    json: bool,
) -> Result<String, String> {
    if json {
        return render_json(value);
    }

    let mut output = format!(
        "status: {}\nreason: {}\nminer: {}\nminingNonce: {}\nproofClassification: {}\nstateSource: {}",
        value.status,
        value.reason,
        value.miner,
        value.mining_nonce,
        value.proof_classification,
        value.state_source,
    );
    if let Some(classification_reason) = &value.classification_reason {
        output.push_str(&format!("\nclassificationReason: {classification_reason}"));
    }
    Ok(output)
}

pub fn render_fee_refused(value: &FeeRefusedOutput, json: bool) -> Result<String, String> {
    if json {
        return render_json(value);
    }

    let mut output = format!(
        "status: {}\nreason: {}\nminer: {}\nminingNonce: {}\nmaximumExposureWei: {}\nwouldHaveAcceptedFeeCeilingWei: {}\nfeeCeilingWei: {}\nbaseFeePerGasWei: {}\npriorityFeePerGasWei: {}\nmaxFeePerGasWei: {}\nestimatedGas: {}\ngasMarginPercent: {}\ngasLimit: {}\nproofClassification: {}\nstateSource: {}",
        value.status,
        value.reason,
        value.miner,
        value.mining_nonce,
        value.maximum_exposure_wei,
        value.would_have_accepted_fee_ceiling_wei,
        value.fee_ceiling_wei,
        value.base_fee_per_gas_wei,
        value.priority_fee_per_gas_wei,
        value.max_fee_per_gas_wei,
        value.estimated_gas,
        value.gas_margin_percent,
        value.gas_limit,
        value.proof_classification,
        value.state_source,
    );
    if let Some(classification_reason) = &value.classification_reason {
        output.push_str(&format!("\nclassificationReason: {classification_reason}"));
    }
    Ok(output)
}

fn render_json<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string(value).map_err(|error| format!("failed to render JSON: {error}"))
}
