//! Command definitions and local `bproof` dispatch.

use std::time::Duration;
use std::{fmt, path::PathBuf};

use clap::{Args, Parser, Subcommand};
use proof_core::{
    ChallengeInputs, MIN_REWARD, ProofInputs, RewardSchedule, Target, Uint256, check_proof,
    derive_challenge, divisor_at, proof_digest, reserve_for, reward_at,
};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::chain::{
    CHAIN_STATE_SOURCE, ChainReader, FILE_STATE_SOURCE, FileChainReader, MiningState,
    RpcChainReader,
};
use crate::classification::{NftClassificationSnapshot, ProofClassification, classify_proof};
use crate::continuous::{ContinuousRequest, DEFAULT_WATCH_INTERVAL};
use crate::mining::{MiningRequest, MiningResult};
use crate::output::{
    FeeRefusedOutput, MineExhaustedOutput, MineFoundOutput, ScheduleNextOutput,
    ScheduleSummaryOutput, StatusOutput, SubmissionOutput, SubmissionRejectedOutput, VerifyOutput,
    render_fee_refused, render_mine_exhausted, render_mine_found, render_schedule_next,
    render_schedule_summary, render_status, render_submission, render_submission_rejected,
    render_verify,
};
use crate::parse::{
    hex_string, parse_address, parse_decimal_uint256, parse_digest, parse_nonce, parse_target,
    parse_u64, parse_u128, uint256_to_decimal,
};
use crate::submit::{
    FEE_REFUSAL_EXIT_CODE, FeeOptions, FeeQuote, PROOF_HUNTER_FEE_WARNING, PreparationOutcome,
    SUBMISSION_WARNING, prepare_submission, recover_pending_submission, send_prepared_submission,
};
use bproof::keystore::{
    PassphraseSource, create_keystore, read_keystore_address, read_passphrase, unlock_keystore,
    write_recovery_phrase,
};

const EXIT_CODE_HELP: &str = "Exit codes:\n  0  Command succeeded, or a continuous loop stopped cleanly\n  1  Verify rejected the proof, mine exhausted, or a continuous loop reached its repeated-failure limit\n  2  Usage or input parse error; also a continuous identity or keystore failure\n  3  Submission refused because maximum exposure exceeds --max-fee in single-shot mode; continuous mining reports feeRefused and continues";

/// Deterministic, non-custodial Bonded Proof utilities.
#[derive(Debug, Parser)]
#[command(name = "bproof", version, about, after_help = EXIT_CODE_HELP)]
pub struct Cli {
    /// Emit one machine-readable JSON object.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Inspect the legacy offline token reward schedule (not current NFT-only mining).
    Schedule(ScheduleArgs),
    /// Derive and check one wallet-bound proof with PROOF_VERSION 1.
    Verify(VerifyArgs),
    /// Search wallet-bound proof nonces locally.
    #[command(
        long_about = "Search wallet-bound proof nonces locally.\n\nThread i searches start+i with a stride equal to the thread count. Workers stop between fixed attempt batches. If one batch finds multiple winners, the lowest nonce in that completed batch is reported."
    )]
    Mine(Box<MineArgs>),
    /// Simulate, sign, and send one found proof.
    Submit(Box<SubmitArgs>),
    /// Inspect canonical mining state from one explicit source.
    Status(StatusArgs),
    /// Create and inspect the miner's local encrypted wallet.
    Wallet(WalletArgs),
}

#[derive(Debug, Args)]
struct WalletArgs {
    #[command(subcommand)]
    command: WalletCommand,
}

#[derive(Debug, Subcommand)]
enum WalletCommand {
    /// Generate a fresh local mining wallet and store its recovery phrase in a new 0600 file.
    New(WalletNewArgs),
    /// Read the public address without unlocking the keystore.
    Address(WalletAddressArgs),
}

#[derive(Debug, Args)]
struct WalletNewArgs {
    /// New encrypted keystore path. An existing path is never overwritten.
    #[arg(long)]
    keystore: PathBuf,
    /// New owner-only recovery phrase file. An existing path is never overwritten.
    #[arg(
        long,
        long_help = "Write the 24-word recovery phrase atomically to this new owner-only file (0600). This flag is required, including in JSON and unattended use. The phrase is never written to standard output or JSON."
    )]
    recovery_out: PathBuf,
    /// Read the passphrase from an owner-only file (0600) instead of prompting without echo.
    #[arg(
        long,
        long_help = "Read the passphrase from this file for unattended use. The file must be owned by the current user and have no group or other permissions (use 0600). Environment passphrases are refused."
    )]
    passphrase_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct WalletAddressArgs {
    /// Existing encrypted keystore path.
    #[arg(long)]
    keystore: PathBuf,
}

#[derive(Debug, Args)]
struct ScheduleArgs {
    #[command(subcommand)]
    command: ScheduleCommand,
}

#[derive(Debug, Subcommand)]
enum ScheduleCommand {
    /// Calculate the next reward and reserve.
    Next(ScheduleNextArgs),
    /// Walk the full schedule and print its landing facts.
    Summary,
}

#[derive(Debug, Args)]
struct ScheduleNextArgs {
    /// Number of proofs accepted before the next proof.
    #[arg(long)]
    accepted: String,
    /// Lifetime issuance before the next proof, in wei.
    #[arg(long)]
    minted_wei: String,
}

#[derive(Debug, Args)]
struct VerifyArgs {
    /// Chain ID as a decimal uint256.
    #[arg(long)]
    chain_id: String,
    /// MiningCore address as exactly 20 bytes of 0x-prefixed hex.
    #[arg(long)]
    mining_core: String,
    /// Challenge ID as a decimal uint256.
    #[arg(long)]
    challenge_id: String,
    /// Previous accepted digest as exactly 32 bytes of 0x-prefixed hex.
    #[arg(long)]
    previous_digest: String,
    /// Seed parent block as a decimal uint256.
    #[arg(long)]
    seed_parent_block: String,
    /// Seed blockhash as exactly 32 bytes of 0x-prefixed hex.
    #[arg(long)]
    seed_blockhash: String,
    /// Miner wallet address as exactly 20 bytes of 0x-prefixed hex.
    #[arg(long)]
    miner: String,
    /// Nonce as decimal u128 or exactly 32 bytes of 0x-prefixed hex.
    #[arg(long)]
    nonce: String,
    /// Inclusive proof target as exactly 32 bytes of 0x-prefixed hex.
    #[arg(long)]
    target: String,
}

#[derive(Debug, Args)]
struct MineArgs {
    /// Read live state directly from this HTTP or HTTPS JSON-RPC endpoint.
    #[arg(long)]
    rpc_url: Option<String>,
    #[arg(
        long,
        help = "Offline state source for development and dry runs. Live mining reads state only from the contract."
    )]
    state_file: Option<String>,
    /// Chain ID as a decimal uint256.
    #[arg(long)]
    chain_id: Option<String>,
    /// MiningCore address as exactly 20 bytes of 0x-prefixed hex.
    #[arg(long)]
    mining_core: Option<String>,
    /// Challenge ID as a decimal uint256.
    #[arg(long)]
    challenge_id: Option<String>,
    /// Previous accepted digest as exactly 32 bytes of 0x-prefixed hex.
    #[arg(long)]
    previous_digest: Option<String>,
    /// Seed parent block as a decimal uint256.
    #[arg(long)]
    seed_parent_block: Option<String>,
    /// Seed blockhash as exactly 32 bytes of 0x-prefixed hex.
    #[arg(long)]
    seed_blockhash: Option<String>,
    /// Miner wallet address. With --submit, the keystore address is authoritative.
    #[arg(long)]
    miner: Option<String>,
    /// Inclusive proof target as exactly 32 bytes of 0x-prefixed hex.
    #[arg(long)]
    target: Option<String>,
    /// Worker count; defaults to available parallelism, with a minimum of 1.
    #[arg(long)]
    threads: Option<String>,
    /// First nonce as decimal u128 or exactly 32 bytes of 0x-prefixed hex.
    #[arg(long)]
    start_nonce: Option<String>,
    /// Total attempt cap across all workers; omitted means unlimited.
    #[arg(long)]
    max_attempts: Option<String>,
    /// Submit the single proof found by this mining run.
    #[arg(long)]
    submit: bool,
    /// Continuously read, search, simulate, and submit. Requires --submit.
    #[arg(
        long = "loop",
        long_help = "Continuously read, search, simulate, and submit. Requires --submit. JSON mode streams one object per line. Event kinds: started, challengeUnavailable, challengeChanged, searchStarted, proofFound, staleWorkAbandoned, challengeLost, feeRefused, proofAccepted, rpcRetry, failure, and summary. Type `summary` followed by Enter on standard input to request a running summary. Ctrl-C stops cleanly with exit code 0."
    )]
    loop_mode: bool,
    /// Milliseconds between live challenge checks; defaults to 1000.
    #[arg(long)]
    watch_interval_ms: Option<String>,
    /// Local bproof keystore used only with --submit.
    #[arg(long)]
    keystore: Option<PathBuf>,
    /// Read the keystore passphrase from an owner-only file instead of prompting.
    #[arg(long)]
    passphrase_file: Option<PathBuf>,
    /// Required total transaction-cost ceiling in raw wei; no default. Each accepted proof mints one NFT, with no liquid token reward; the ceiling must cover the estimated mint transaction.
    #[arg(long)]
    max_fee: Option<String>,
    /// Basket asset address for HunterMiningCore.submitProof. Required with --submit.
    #[arg(long)]
    basket: Option<String>,
    /// Override the chain base fee per gas in raw wei.
    #[arg(long)]
    base_fee_per_gas: Option<String>,
    /// Override the priority fee per gas in raw wei.
    #[arg(long)]
    priority_fee_per_gas: Option<String>,
    /// Margin added to eth_estimateGas; defaults to 100 percent, still bounded by --max-fee.
    #[arg(long)]
    gas_margin_percent: Option<String>,
}

#[derive(Debug, Args)]
struct SubmitArgs {
    /// HTTP or HTTPS JSON-RPC endpoint used to simulate and send.
    #[arg(long)]
    rpc_url: String,
    /// Expected chain ID. A mismatch refuses before signing.
    #[arg(long)]
    chain_id: String,
    /// Verified MiningCore address as exactly 20 bytes of 0x-prefixed hex.
    #[arg(long)]
    mining_core: String,
    /// Basket asset address for HunterMiningCore.submitProof as exactly 20 bytes of 0x-prefixed hex.
    #[arg(long)]
    basket: String,
    /// Found mining nonce as decimal u128 or exactly 32 bytes of 0x-prefixed hex.
    #[arg(long)]
    mining_nonce: String,
    /// Local bproof keystore containing the mining wallet.
    #[arg(long)]
    keystore: PathBuf,
    /// Read the passphrase from an owner-only file instead of prompting without echo.
    #[arg(long)]
    passphrase_file: Option<PathBuf>,
    /// Total transaction-cost ceiling in raw wei. This flag is mandatory and has no default. Each accepted proof mints one NFT, with no liquid token reward; the ceiling must cover the estimated mint transaction.
    #[arg(long)]
    max_fee: String,
    /// Override the chain base fee per gas in raw wei.
    #[arg(long)]
    base_fee_per_gas: Option<String>,
    /// Override the priority fee per gas in raw wei.
    #[arg(long)]
    priority_fee_per_gas: Option<String>,
    /// Margin added to eth_estimateGas; defaults to 100 percent, still bounded by --max-fee.
    #[arg(long)]
    gas_margin_percent: Option<String>,
}

#[derive(Debug, Args)]
struct StatusArgs {
    /// Read live state directly from this HTTP or HTTPS JSON-RPC endpoint.
    #[arg(long)]
    rpc_url: Option<String>,
    #[arg(
        long,
        help = "Offline state source for development and dry runs. Live mining reads state only from the contract."
    )]
    state_file: Option<String>,
    /// Expected chain ID. Live reads refuse if the endpoint reports another chain.
    #[arg(long)]
    chain_id: Option<String>,
    /// Verified MiningCore address as exactly 20 bytes of 0x-prefixed hex.
    #[arg(long)]
    mining_core: Option<String>,
}

/// A rendered command result and its process exit code.
pub struct RunResult {
    pub output: Zeroizing<String>,
    pub exit_code: u8,
}

impl fmt::Debug for RunResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunResult")
            .field("output", &"[REDACTED]")
            .field("exit_code", &self.exit_code)
            .finish()
    }
}

/// Runs one parsed CLI command.
pub fn run(cli: Cli) -> Result<RunResult, String> {
    match cli.command {
        Command::Schedule(schedule) => run_schedule(schedule, cli.json),
        Command::Verify(verify) => run_verify(verify, cli.json),
        Command::Mine(mine) => run_mine(*mine, cli.json),
        Command::Submit(submit) => run_submit(*submit, cli.json),
        Command::Status(status) => run_status(status, cli.json),
        Command::Wallet(wallet) => run_wallet(wallet, cli.json),
    }
}

fn run_schedule(schedule: ScheduleArgs, json: bool) -> Result<RunResult, String> {
    match schedule.command {
        ScheduleCommand::Next(args) => {
            let accepted_proofs = parse_u128(&args.accepted, "--accepted")?;
            let total_minted = parse_u128(&args.minted_wei, "--minted-wei")?;
            let divisor = divisor_at(accepted_proofs);
            let reward = reward_at(accepted_proofs, total_minted);
            let reserve = reserve_for(reward);
            let output = ScheduleNextOutput {
                accepted_proofs: accepted_proofs.to_string(),
                total_minted_wei: total_minted.to_string(),
                divisor: divisor.to_string(),
                reward_wei: reward.to_string(),
                reserve_wei: reserve.to_string(),
            };

            Ok(RunResult {
                output: Zeroizing::new(render_schedule_next(&output, json)?),
                exit_code: 0,
            })
        }
        ScheduleCommand::Summary => {
            let mut schedule = RewardSchedule::new();
            let mut first_reward = None;
            let mut last_reward = None;
            let mut first_floor_proof = None;

            while let Some(reward) = schedule.next() {
                first_reward.get_or_insert(reward);
                last_reward = Some(reward);
                if first_floor_proof.is_none() && reward == MIN_REWARD {
                    first_floor_proof = Some(schedule.accepted_proofs());
                }
            }

            let output = ScheduleSummaryOutput {
                total_proofs: schedule.accepted_proofs().to_string(),
                total_minted_wei: schedule.total_minted().to_string(),
                first_reward_wei: first_reward.unwrap_or_default().to_string(),
                last_reward_wei: last_reward.unwrap_or_default().to_string(),
                first_floor_proof: first_floor_proof.unwrap_or_default().to_string(),
            };

            Ok(RunResult {
                output: Zeroizing::new(render_schedule_summary(&output, json)?),
                exit_code: 0,
            })
        }
    }
}

fn run_verify(args: VerifyArgs, json: bool) -> Result<RunResult, String> {
    let chain_id = parse_decimal_uint256(&args.chain_id, "--chain-id")?;
    let mining_core = parse_address(&args.mining_core, "--mining-core")?;
    let challenge_id = parse_decimal_uint256(&args.challenge_id, "--challenge-id")?;
    let previous_accepted_digest = parse_digest(&args.previous_digest, "--previous-digest")?;
    let seed_parent_block = parse_decimal_uint256(&args.seed_parent_block, "--seed-parent-block")?;
    let seed_blockhash = parse_digest(&args.seed_blockhash, "--seed-blockhash")?;
    let miner = parse_address(&args.miner, "--miner")?;
    let nonce = parse_nonce(&args.nonce, "--nonce")?;
    let target = parse_target(&args.target, "--target")?;

    let challenge_inputs = ChallengeInputs {
        chain_id,
        mining_core,
        challenge_id,
        previous_accepted_digest,
        seed_parent_block,
        seed_blockhash,
    };
    let challenge = derive_challenge(&challenge_inputs);
    let digest = proof_digest(&ProofInputs {
        chain_id,
        mining_core,
        challenge_id,
        challenge,
        miner,
        nonce,
    });
    let accepted = check_proof(&challenge_inputs, miner, nonce, target);
    let output = VerifyOutput {
        chain_id: uint256_to_decimal(chain_id),
        mining_core: hex_string(&mining_core.to_bytes()),
        challenge_id: uint256_to_decimal(challenge_id),
        previous_accepted_digest: hex_string(&previous_accepted_digest.to_bytes()),
        seed_parent_block: uint256_to_decimal(seed_parent_block),
        seed_blockhash: hex_string(&seed_blockhash.to_bytes()),
        miner: hex_string(&miner.to_bytes()),
        nonce: uint256_to_decimal(nonce),
        challenge: hex_string(&challenge.to_bytes()),
        digest: hex_string(&digest.to_bytes()),
        target: hex_string(&target.to_be_bytes()),
        accepted,
    };

    Ok(RunResult {
        output: Zeroizing::new(render_verify(&output, json)?),
        exit_code: if accepted { 0 } else { 1 },
    })
}

fn run_mine(args: MineArgs, json: bool) -> Result<RunResult, String> {
    let (miner, submission) = resolve_mine_identity_and_submission(&args)?;
    if args.loop_mode {
        return run_continuous_mine(&args, miner, submission, json);
    }
    if let Some(submission) = &submission {
        let endpoint = args
            .rpc_url
            .as_deref()
            .ok_or_else(|| "--rpc-url is required with --submit".to_owned())?;
        let chain_id =
            parse_decimal_uint256(required_live(&args.chain_id, "--chain-id")?, "--chain-id")?;
        let mining_core = parse_address(
            required_live(&args.mining_core, "--mining-core")?,
            "--mining-core",
        )?;
        let reader = RpcChainReader::new(endpoint, mining_core, chain_id);
        reader.verify_identity()?;
        if let Some(recovered) = recover_pending_submission(&reader, &submission.keystore)? {
            return submission_result(
                recovered.mined,
                recovered.miner,
                &recovered.proof_classification,
                recovered.classification_reason,
                json,
            );
        }
    }
    let resolved = resolve_mine_state(&args, miner)?;
    let challenge_inputs = resolved.challenge_inputs;
    let target = resolved.target;
    let state_source = resolved.state_source;
    let nft_classification = resolved.nft_classification;
    let chain_id = challenge_inputs.chain_id;
    let mining_core = challenge_inputs.mining_core;
    let challenge_id = challenge_inputs.challenge_id;
    let previous_accepted_digest = challenge_inputs.previous_accepted_digest;
    let seed_parent_block = challenge_inputs.seed_parent_block;
    let seed_blockhash = challenge_inputs.seed_blockhash;
    let threads = parse_threads(args.threads.as_deref())?;
    let start_nonce = match &args.start_nonce {
        Some(value) => parse_nonce(value, "--start-nonce")?,
        None => Uint256::ZERO,
    };
    let max_attempts = args
        .max_attempts
        .as_deref()
        .map(|value| parse_u64(value, "--max-attempts"))
        .transpose()?;

    if submission.is_some() {
        eprintln!("WARNING: {PROOF_HUNTER_FEE_WARNING}");
    }

    match crate::mining::mine(MiningRequest {
        challenge_inputs,
        miner,
        target,
        start_nonce,
        threads,
        max_attempts,
    })? {
        MiningResult::Found {
            mining_nonce,
            digest,
            attempts,
            threads,
        } => {
            let classification = classify_proof(digest, &nft_classification);
            if let Some(submission) = submission {
                let endpoint = args
                    .rpc_url
                    .as_deref()
                    .ok_or_else(|| "--rpc-url is required with --submit".to_owned())?;
                let reader = RpcChainReader::new(endpoint, mining_core, chain_id);
                return complete_submission(
                    &reader,
                    challenge_inputs,
                    miner,
                    mining_nonce,
                    submission.basket,
                    &submission.keystore,
                    submission.passphrase_file.as_deref(),
                    submission.fee_options,
                    classification,
                    json,
                );
            }

            let challenge = derive_challenge(&challenge_inputs);
            let proof = VerifyOutput {
                chain_id: uint256_to_decimal(chain_id),
                mining_core: hex_string(&mining_core.to_bytes()),
                challenge_id: uint256_to_decimal(challenge_id),
                previous_accepted_digest: hex_string(&previous_accepted_digest.to_bytes()),
                seed_parent_block: uint256_to_decimal(seed_parent_block),
                seed_blockhash: hex_string(&seed_blockhash.to_bytes()),
                miner: hex_string(&miner.to_bytes()),
                nonce: uint256_to_decimal(mining_nonce),
                challenge: hex_string(&challenge.to_bytes()),
                digest: hex_string(&digest.to_bytes()),
                target: hex_string(&target.to_be_bytes()),
                accepted: true,
            };
            let output = MineFoundOutput {
                proof,
                attempts: attempts.to_string(),
                threads: threads.to_string(),
                proof_classification: classification.name(),
                classification_reason: classification.reason().map(str::to_owned),
                state_source: state_source.map(str::to_owned),
            };

            Ok(RunResult {
                output: Zeroizing::new(render_mine_found(&output, json)?),
                exit_code: 0,
            })
        }
        MiningResult::Exhausted { attempts, threads } => {
            let output = MineExhaustedOutput {
                found: false,
                attempts: attempts.to_string(),
                threads: threads.to_string(),
                state_source: state_source.map(str::to_owned),
            };

            Ok(RunResult {
                output: Zeroizing::new(render_mine_exhausted(&output, json)?),
                exit_code: 1,
            })
        }
        MiningResult::Abandoned { .. } => {
            Err("single-shot mining was abandoned without an external watcher".to_owned())
        }
    }
}

fn run_continuous_mine(
    args: &MineArgs,
    miner: proof_core::Address,
    submission: Option<MineSubmissionConfig>,
    json: bool,
) -> Result<RunResult, String> {
    if !args.submit {
        return Err("--loop requires --submit so continuous spending is explicit".to_owned());
    }
    if args.max_attempts.is_some() {
        return Err(
            "--max-attempts is a single-shot limit and cannot be used with --loop".to_owned(),
        );
    }
    let endpoint = args
        .rpc_url
        .clone()
        .ok_or_else(|| "--rpc-url is required with --loop".to_owned())?;
    let chain_id =
        parse_decimal_uint256(required_live(&args.chain_id, "--chain-id")?, "--chain-id")?;
    let mining_core = parse_address(
        required_live(&args.mining_core, "--mining-core")?,
        "--mining-core",
    )?;
    let threads = parse_threads(args.threads.as_deref())?;
    let start_nonce = match &args.start_nonce {
        Some(value) => parse_nonce(value, "--start-nonce")?,
        None => Uint256::ZERO,
    };
    let watch_interval = args.watch_interval_ms.as_deref().map_or_else(
        || Ok(DEFAULT_WATCH_INTERVAL),
        |value| {
            let millis = parse_u64(value, "--watch-interval-ms")?;
            if millis == 0 {
                return Err("--watch-interval-ms must be at least 1".to_owned());
            }
            Ok(Duration::from_millis(millis))
        },
    )?;
    let submission = submission.ok_or_else(|| "--loop requires --submit".to_owned())?;
    let result = crate::continuous::run(
        ContinuousRequest {
            endpoint,
            chain_id,
            mining_core,
            miner,
            basket: submission.basket,
            keystore: submission.keystore,
            passphrase_file: submission.passphrase_file,
            fee_options: submission.fee_options,
            threads,
            start_nonce,
            watch_interval,
        },
        json,
    )?;
    Ok(RunResult {
        output: Zeroizing::new(result.summary),
        exit_code: result.exit_code,
    })
}

fn run_submit(args: SubmitArgs, json: bool) -> Result<RunResult, String> {
    let chain_id = parse_decimal_uint256(&args.chain_id, "--chain-id")?;
    let mining_core = parse_address(&args.mining_core, "--mining-core")?;
    let basket = parse_address(&args.basket, "--basket")?;
    let mining_nonce = parse_nonce(&args.mining_nonce, "--mining-nonce")?;
    let miner_text = read_keystore_address(&args.keystore)?;
    let miner = parse_address(&miner_text, "keystore miner address")?;
    let fee_options = parse_fee_options(
        &args.max_fee,
        args.base_fee_per_gas.as_deref(),
        args.priority_fee_per_gas.as_deref(),
        args.gas_margin_percent.as_deref(),
    )?;
    let reader = RpcChainReader::new(&args.rpc_url, mining_core, chain_id);
    reader.verify_identity()?;
    if let Some(recovered) = recover_pending_submission(&reader, &args.keystore)? {
        return submission_result(
            recovered.mined,
            recovered.miner,
            &recovered.proof_classification,
            recovered.classification_reason,
            json,
        );
    }
    let classified_state = reader.read_classified_state(Some(miner))?;
    let state = classified_state.state;
    let digest = proof_digest(&ProofInputs {
        chain_id: state.challenge_inputs.chain_id,
        mining_core: state.challenge_inputs.mining_core,
        challenge_id: state.challenge_inputs.challenge_id,
        challenge: state.challenge,
        miner,
        nonce: mining_nonce,
    });
    let classification = classify_proof(digest, &classified_state.nft_classification);
    if !check_proof(
        &state.challenge_inputs,
        miner,
        mining_nonce,
        classified_state.effective_target,
    ) {
        return rejected_submission(
            "mining nonce does not satisfy the current target".to_owned(),
            miner,
            mining_nonce,
            classification,
            json,
        );
    }

    complete_submission(
        &reader,
        state.challenge_inputs,
        miner,
        mining_nonce,
        basket,
        &args.keystore,
        args.passphrase_file.as_deref(),
        fee_options,
        classification,
        json,
    )
}

struct MineSubmissionConfig {
    keystore: PathBuf,
    passphrase_file: Option<PathBuf>,
    basket: proof_core::Address,
    fee_options: FeeOptions,
}

fn resolve_mine_identity_and_submission(
    args: &MineArgs,
) -> Result<(proof_core::Address, Option<MineSubmissionConfig>), String> {
    if args.loop_mode && !args.submit {
        return Err("--loop requires --submit so continuous spending is explicit".to_owned());
    }
    if args.watch_interval_ms.is_some() && !args.loop_mode {
        return Err("--watch-interval-ms requires --loop".to_owned());
    }
    if !args.submit {
        let submission_flags = [
            (args.keystore.is_some(), "--keystore"),
            (args.passphrase_file.is_some(), "--passphrase-file"),
            (args.max_fee.is_some(), "--max-fee"),
            (args.basket.is_some(), "--basket"),
            (args.base_fee_per_gas.is_some(), "--base-fee-per-gas"),
            (
                args.priority_fee_per_gas.is_some(),
                "--priority-fee-per-gas",
            ),
            (args.gas_margin_percent.is_some(), "--gas-margin-percent"),
        ]
        .into_iter()
        .filter_map(|(present, name)| present.then_some(name))
        .collect::<Vec<_>>();
        if !submission_flags.is_empty() {
            return Err(format!("{} require --submit", submission_flags.join(", ")));
        }
        let miner = args
            .miner
            .as_deref()
            .ok_or_else(|| "--miner is required without --submit".to_owned())?;
        return parse_address(miner, "--miner").map(|miner| (miner, None));
    }

    if args.rpc_url.is_none() {
        return Err("--rpc-url is required with --submit".to_owned());
    }
    if args.state_file.is_some() {
        return Err(
            "--state-file cannot be used with --submit; submission reads the contract".to_owned(),
        );
    }
    let keystore = args
        .keystore
        .clone()
        .ok_or_else(|| "--keystore is required with --submit".to_owned())?;
    let max_fee = args
        .max_fee
        .as_deref()
        .ok_or_else(|| "--max-fee is required with --submit and has no default".to_owned())?;
    let miner_text = read_keystore_address(&keystore)?;
    let miner = parse_address(&miner_text, "keystore miner address")?;
    if let Some(supplied) = &args.miner {
        let supplied = parse_address(supplied, "--miner")?;
        if supplied != miner {
            return Err("--miner does not match the --keystore mining address".to_owned());
        }
    }
    let basket_text = args
        .basket
        .as_deref()
        .ok_or_else(|| "--basket is required with --submit".to_owned())?;
    let basket = parse_address(basket_text, "--basket")?;
    let fee_options = parse_fee_options(
        max_fee,
        args.base_fee_per_gas.as_deref(),
        args.priority_fee_per_gas.as_deref(),
        args.gas_margin_percent.as_deref(),
    )?;
    Ok((
        miner,
        Some(MineSubmissionConfig {
            keystore,
            passphrase_file: args.passphrase_file.clone(),
            basket,
            fee_options,
        }),
    ))
}

fn parse_fee_options(
    max_fee: &str,
    base_fee_per_gas: Option<&str>,
    priority_fee_per_gas: Option<&str>,
    gas_margin_percent: Option<&str>,
) -> Result<FeeOptions, String> {
    Ok(FeeOptions {
        fee_ceiling_wei: parse_u128(max_fee, "--max-fee")?,
        base_fee_per_gas_override_wei: base_fee_per_gas
            .map(|value| parse_u128(value, "--base-fee-per-gas"))
            .transpose()?,
        priority_fee_per_gas_override_wei: priority_fee_per_gas
            .map(|value| parse_u128(value, "--priority-fee-per-gas"))
            .transpose()?,
        gas_margin_percent: gas_margin_percent.map_or_else(
            || Ok(FeeOptions::default_gas_margin_percent()),
            |value| parse_u64(value, "--gas-margin-percent"),
        )?,
    })
}

#[allow(clippy::too_many_arguments)]
fn complete_submission(
    reader: &RpcChainReader,
    challenge_inputs: ChallengeInputs,
    miner: proof_core::Address,
    mining_nonce: Uint256,
    basket: proof_core::Address,
    keystore: &std::path::Path,
    passphrase_file: Option<&std::path::Path>,
    fee_options: FeeOptions,
    classification: ProofClassification,
    json: bool,
) -> Result<RunResult, String> {
    let prepared = match prepare_submission(
        reader,
        challenge_inputs,
        miner,
        mining_nonce,
        basket,
        fee_options,
    )? {
        PreparationOutcome::SimulationRejected { reason } => {
            return rejected_submission(reason, miner, mining_nonce, classification, json);
        }
        PreparationOutcome::FeeRefused(quote) => {
            return refused_submission(quote, miner, mining_nonce, classification, json);
        }
        PreparationOutcome::Ready(prepared) => *prepared,
    };

    if !json {
        eprintln!("WARNING: {SUBMISSION_WARNING}");
    }
    let source = passphrase_file.map_or(PassphraseSource::Prompt, PassphraseSource::File);
    let passphrase = read_passphrase(source, false)?;
    let wallet = unlock_keystore(keystore, &passphrase)?;
    if parse_address(wallet.address(), "unlocked keystore miner address")? != miner {
        return Err("unlocked keystore mining address changed after simulation".to_owned());
    }
    let mined = send_prepared_submission(
        reader,
        &wallet,
        prepared,
        keystore,
        classification.name(),
        classification.reason(),
    )?;
    submission_result(
        mined,
        miner,
        classification.name(),
        classification.reason().map(str::to_owned),
        json,
    )
}

fn submission_result(
    mined: crate::submit::MinedSubmission,
    miner: proof_core::Address,
    proof_classification: &str,
    classification_reason: Option<String>,
    json: bool,
) -> Result<RunResult, String> {
    let quote = mined.fee_quote;
    let output = SubmissionOutput {
        nft_token_id: mined.nft_token_id.map(uint256_to_decimal),
        status: if mined.succeeded { "mined" } else { "rejected" },
        reason: (!mined.succeeded).then(|| {
            "transaction was mined but reverted; the challenge may have moved before inclusion"
                .to_owned()
        }),
        transaction_hash: hex_string(&mined.transaction_hash.to_bytes()),
        miner: hex_string(&miner.to_bytes()),
        mining_nonce: uint256_to_decimal(mined.mining_nonce),
        account_nonce: uint256_to_decimal(mined.account_nonce),
        fee_paid_wei: mined.fee_paid_wei.to_string(),
        maximum_exposure_wei: quote.maximum_exposure_wei.to_string(),
        fee_ceiling_wei: quote.fee_ceiling_wei.to_string(),
        base_fee_per_gas_wei: quote.base_fee_per_gas_wei.to_string(),
        priority_fee_per_gas_wei: quote.priority_fee_per_gas_wei.to_string(),
        max_fee_per_gas_wei: quote.max_fee_per_gas_wei.to_string(),
        estimated_gas: quote.estimated_gas.to_string(),
        gas_margin_percent: quote.gas_margin_percent.to_string(),
        gas_limit: quote.gas_limit.to_string(),
        proof_classification: proof_classification.to_owned(),
        classification_reason,
        state_source: CHAIN_STATE_SOURCE,
        warning: SUBMISSION_WARNING,
    };
    Ok(RunResult {
        output: Zeroizing::new(render_submission(&output, json)?),
        exit_code: if mined.succeeded { 0 } else { 1 },
    })
}

fn rejected_submission(
    reason: String,
    miner: proof_core::Address,
    mining_nonce: Uint256,
    classification: ProofClassification,
    json: bool,
) -> Result<RunResult, String> {
    let output = SubmissionRejectedOutput {
        status: "rejected",
        reason,
        miner: hex_string(&miner.to_bytes()),
        mining_nonce: uint256_to_decimal(mining_nonce),
        proof_classification: classification.name(),
        classification_reason: classification.reason().map(str::to_owned),
        state_source: CHAIN_STATE_SOURCE,
        warning: SUBMISSION_WARNING,
    };
    Ok(RunResult {
        output: Zeroizing::new(render_submission_rejected(&output, json)?),
        exit_code: 1,
    })
}

fn refused_submission(
    quote: FeeQuote,
    miner: proof_core::Address,
    mining_nonce: Uint256,
    classification: ProofClassification,
    json: bool,
) -> Result<RunResult, String> {
    let reason = fee_refusal_reason(&quote, &classification);
    let output = FeeRefusedOutput {
        status: "feeRefused",
        reason,
        miner: hex_string(&miner.to_bytes()),
        mining_nonce: uint256_to_decimal(mining_nonce),
        maximum_exposure_wei: quote.maximum_exposure_wei.to_string(),
        would_have_accepted_fee_ceiling_wei: quote.maximum_exposure_wei.to_string(),
        fee_ceiling_wei: quote.fee_ceiling_wei.to_string(),
        base_fee_per_gas_wei: quote.base_fee_per_gas_wei.to_string(),
        priority_fee_per_gas_wei: quote.priority_fee_per_gas_wei.to_string(),
        max_fee_per_gas_wei: quote.max_fee_per_gas_wei.to_string(),
        estimated_gas: quote.estimated_gas.to_string(),
        gas_margin_percent: quote.gas_margin_percent.to_string(),
        gas_limit: quote.gas_limit.to_string(),
        proof_classification: classification.name(),
        classification_reason: classification.reason().map(str::to_owned),
        state_source: CHAIN_STATE_SOURCE,
        warning: SUBMISSION_WARNING,
    };
    Ok(RunResult {
        output: Zeroizing::new(render_fee_refused(&output, json)?),
        exit_code: FEE_REFUSAL_EXIT_CODE,
    })
}

fn fee_refusal_reason(quote: &FeeQuote, classification: &ProofClassification) -> String {
    let (proof_kind, consequence) = match classification {
        ProofClassification::ProofHunter => (
            "Proof Hunter proof",
            "; refusing it leaves this proof unsubmitted",
        ),
        ProofClassification::Ordinary => ("ordinary proof", ""),
        ProofClassification::Unknown { .. } => ("proof with unknown classification", ""),
    };
    format!(
        "{proof_kind} refused: maximum exposure {} wei exceeds the --max-fee ceiling {} wei; a --max-fee ceiling of {} wei would have accepted it{consequence}",
        quote.maximum_exposure_wei, quote.fee_ceiling_wei, quote.maximum_exposure_wei,
    )
}

fn run_status(args: StatusArgs, json: bool) -> Result<RunResult, String> {
    let (state, state_source) = resolve_status_state(&args)?;
    let legacy = state.nfts_minted_ever.is_none();
    let divisor = divisor_at(state.accepted_proofs);
    let reward = reward_at(state.accepted_proofs, state.total_minted_wei);
    let reserve = reserve_for(reward);
    let inputs = state.challenge_inputs;
    let output = StatusOutput {
        chain_id: uint256_to_decimal(inputs.chain_id),
        mining_core: hex_string(&inputs.mining_core.to_bytes()),
        challenge_id: uint256_to_decimal(inputs.challenge_id),
        previous_accepted_digest: hex_string(&inputs.previous_accepted_digest.to_bytes()),
        seed_parent_block: uint256_to_decimal(inputs.seed_parent_block),
        seed_blockhash: hex_string(&inputs.seed_blockhash.to_bytes()),
        target: hex_string(&state.target.to_be_bytes()),
        accepted_proofs: state.accepted_proofs.to_string(),
        total_minted_wei: legacy.then(|| state.total_minted_wei.to_string()),
        divisor: legacy.then(|| divisor.to_string()),
        reward_wei: legacy.then(|| reward.to_string()),
        reserve_wei: legacy.then(|| reserve.to_string()),
        settlement_mode: if legacy {
            "legacyOfflineSchedule"
        } else {
            "nftOnly"
        },
        nfts_minted_ever: state.nfts_minted_ever.map(|n| n.to_string()),
        state_source: state_source.to_owned(),
    };

    Ok(RunResult {
        output: Zeroizing::new(render_status(&output, json)?),
        exit_code: 0,
    })
}

fn run_wallet(args: WalletArgs, json: bool) -> Result<RunResult, String> {
    match args.command {
        WalletCommand::New(args) => {
            validate_wallet_output_paths(&args.keystore, &args.recovery_out)?;
            let source = args
                .passphrase_file
                .as_deref()
                .map_or(PassphraseSource::Prompt, PassphraseSource::File);
            let passphrase = read_passphrase(source, args.passphrase_file.is_none())?;
            let created = create_keystore(&args.keystore, &passphrase)?;
            let address = created.address().to_owned();
            if let Err(error) =
                write_recovery_phrase(&args.recovery_out, created.into_backup_phrase())
            {
                return match std::fs::remove_file(&args.keystore) {
                    Ok(()) => Err(error),
                    Err(cleanup_error) => Err(format!(
                        "{error}; also failed to remove the new keystore {}: {cleanup_error}",
                        args.keystore.display()
                    )),
                };
            }
            Ok(RunResult {
                output: render_wallet_new(&address, &args.keystore, &args.recovery_out, json)?,
                exit_code: 0,
            })
        }
        WalletCommand::Address(args) => {
            let address = read_keystore_address(&args.keystore)?;
            Ok(RunResult {
                output: render_wallet_address(&address, &args.keystore, json)?,
                exit_code: 0,
            })
        }
    }
}

fn validate_wallet_output_paths(
    keystore: &std::path::Path,
    recovery: &std::path::Path,
) -> Result<(), String> {
    if keystore == recovery {
        return Err("--keystore and --recovery-out must be different paths".to_owned());
    }
    if recovery.exists() {
        return Err(format!(
            "refusing to overwrite existing recovery file {}",
            recovery.display()
        ));
    }
    Ok(())
}

const RECOVERY_STATUS: &str = "writtenOwnerOnly0600";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WalletNewOutput<'a> {
    address: &'a str,
    keystore: &'a str,
    recovery_file: &'a str,
    recovery_status: &'static str,
}

#[derive(Serialize)]
struct WalletAddressOutput<'a> {
    address: &'a str,
    keystore: &'a str,
    unlocked: bool,
}

fn render_wallet_new(
    address: &str,
    keystore_path: &std::path::Path,
    recovery_path: &std::path::Path,
    json: bool,
) -> Result<Zeroizing<String>, String> {
    let keystore = keystore_path.display().to_string();
    let recovery_file = recovery_path.display().to_string();
    let output = WalletNewOutput {
        address,
        keystore: &keystore,
        recovery_file: &recovery_file,
        recovery_status: RECOVERY_STATUS,
    };
    let rendered = if json {
        serde_json::to_string(&output)
            .map_err(|error| format!("failed to encode wallet output as JSON: {error}"))?
    } else {
        format!(
            "address: {}\nkeystore: {}\nrecoveryFile: {}\nrecoveryStatus: {}",
            output.address, output.keystore, output.recovery_file, output.recovery_status
        )
    };
    Ok(Zeroizing::new(rendered))
}

fn render_wallet_address(
    address: &str,
    path: &std::path::Path,
    json: bool,
) -> Result<Zeroizing<String>, String> {
    let path = path.display().to_string();
    let output = WalletAddressOutput {
        address,
        keystore: &path,
        unlocked: false,
    };
    let rendered = if json {
        serde_json::to_string(&output)
            .map_err(|error| format!("failed to encode wallet output as JSON: {error}"))?
    } else {
        format!(
            "address: {}\nkeystore: {}\nunlocked: false",
            output.address, output.keystore
        )
    };
    Ok(Zeroizing::new(rendered))
}

struct ResolvedMineState {
    challenge_inputs: ChallengeInputs,
    target: Target,
    state_source: Option<&'static str>,
    nft_classification: Result<NftClassificationSnapshot, String>,
}

fn resolve_mine_state(
    args: &MineArgs,
    miner: proof_core::Address,
) -> Result<ResolvedMineState, String> {
    if let Some(endpoint) = &args.rpc_url {
        if args.state_file.is_some() {
            return Err("--rpc-url cannot be combined with --state-file".to_owned());
        }
        let clashes = manual_state_clashes(args);
        if !clashes.is_empty() {
            return Err(format!(
                "--rpc-url cannot be combined with manual state flag(s) {}",
                clashes.join(", ")
            ));
        }

        let expected_chain_id =
            parse_decimal_uint256(required_live(&args.chain_id, "--chain-id")?, "--chain-id")?;
        let mining_core = parse_address(
            required_live(&args.mining_core, "--mining-core")?,
            "--mining-core",
        )?;
        let classified = RpcChainReader::new(endpoint, mining_core, expected_chain_id)
            .read_classified_state(Some(miner))?;
        return Ok(ResolvedMineState {
            challenge_inputs: classified.state.challenge_inputs,
            target: classified.effective_target,
            state_source: Some(CHAIN_STATE_SOURCE),
            nft_classification: classified.nft_classification,
        });
    }

    if let Some(path) = &args.state_file {
        let clashes = [
            (args.chain_id.is_some(), "--chain-id"),
            (args.mining_core.is_some(), "--mining-core"),
            (args.challenge_id.is_some(), "--challenge-id"),
            (args.previous_digest.is_some(), "--previous-digest"),
            (args.seed_parent_block.is_some(), "--seed-parent-block"),
            (args.seed_blockhash.is_some(), "--seed-blockhash"),
            (args.target.is_some(), "--target"),
        ]
        .into_iter()
        .filter_map(|(present, name)| present.then_some(name))
        .collect::<Vec<_>>();
        if !clashes.is_empty() {
            return Err(format!(
                "--state-file cannot be combined with {}",
                clashes.join(", ")
            ));
        }

        let state = FileChainReader::new(path).read_state()?;
        return Ok(ResolvedMineState {
            challenge_inputs: state.challenge_inputs,
            target: state.target,
            state_source: Some(FILE_STATE_SOURCE),
            nft_classification: Err(
                "proof classification requires a live chain snapshot".to_owned()
            ),
        });
    }

    let chain_id = parse_decimal_uint256(required(&args.chain_id, "--chain-id")?, "--chain-id")?;
    let mining_core = parse_address(
        required(&args.mining_core, "--mining-core")?,
        "--mining-core",
    )?;
    let challenge_id = parse_decimal_uint256(
        required(&args.challenge_id, "--challenge-id")?,
        "--challenge-id",
    )?;
    let previous_accepted_digest = parse_digest(
        required(&args.previous_digest, "--previous-digest")?,
        "--previous-digest",
    )?;
    let seed_parent_block = parse_decimal_uint256(
        required(&args.seed_parent_block, "--seed-parent-block")?,
        "--seed-parent-block",
    )?;
    let seed_blockhash = parse_digest(
        required(&args.seed_blockhash, "--seed-blockhash")?,
        "--seed-blockhash",
    )?;
    let target = parse_target(required(&args.target, "--target")?, "--target")?;

    Ok(ResolvedMineState {
        challenge_inputs: ChallengeInputs {
            chain_id,
            mining_core,
            challenge_id,
            previous_accepted_digest,
            seed_parent_block,
            seed_blockhash,
        },
        target,
        state_source: None,
        nft_classification: Err("proof classification requires a live chain snapshot".to_owned()),
    })
}

fn resolve_status_state(args: &StatusArgs) -> Result<(MiningState, &'static str), String> {
    if let Some(endpoint) = &args.rpc_url {
        if args.state_file.is_some() {
            return Err("--rpc-url cannot be combined with --state-file".to_owned());
        }
        let expected_chain_id =
            parse_decimal_uint256(required_live(&args.chain_id, "--chain-id")?, "--chain-id")?;
        let mining_core = parse_address(
            required_live(&args.mining_core, "--mining-core")?,
            "--mining-core",
        )?;
        let state = RpcChainReader::new(endpoint, mining_core, expected_chain_id).read_state()?;
        return Ok((state, CHAIN_STATE_SOURCE));
    }

    if let Some(path) = &args.state_file {
        let clashes = [
            (args.chain_id.is_some(), "--chain-id"),
            (args.mining_core.is_some(), "--mining-core"),
        ]
        .into_iter()
        .filter_map(|(present, name)| present.then_some(name))
        .collect::<Vec<_>>();
        if !clashes.is_empty() {
            return Err(format!(
                "--state-file cannot be combined with {}",
                clashes.join(", ")
            ));
        }
        return FileChainReader::new(path)
            .read_state()
            .map(|state| (state, FILE_STATE_SOURCE));
    }

    let supplied_identity = [
        (args.chain_id.is_some(), "--chain-id"),
        (args.mining_core.is_some(), "--mining-core"),
    ]
    .into_iter()
    .filter_map(|(present, name)| present.then_some(name))
    .collect::<Vec<_>>();
    if !supplied_identity.is_empty() {
        return Err(format!(
            "--rpc-url is required with {}",
            supplied_identity.join(", ")
        ));
    }
    Err("one state source is required: --state-file or --rpc-url".to_owned())
}

fn manual_state_clashes(args: &MineArgs) -> Vec<&'static str> {
    [
        (args.challenge_id.is_some(), "--challenge-id"),
        (args.previous_digest.is_some(), "--previous-digest"),
        (args.seed_parent_block.is_some(), "--seed-parent-block"),
        (args.seed_blockhash.is_some(), "--seed-blockhash"),
        (args.target.is_some(), "--target"),
    ]
    .into_iter()
    .filter_map(|(present, name)| present.then_some(name))
    .collect()
}

fn required_live<'a>(value: &'a Option<String>, name: &str) -> Result<&'a str, String> {
    value
        .as_deref()
        .ok_or_else(|| format!("{name} is required with --rpc-url"))
}

fn required<'a>(value: &'a Option<String>, name: &str) -> Result<&'a str, String> {
    value
        .as_deref()
        .ok_or_else(|| format!("{name} is required unless --state-file is provided"))
}

fn parse_threads(value: Option<&str>) -> Result<usize, String> {
    let Some(value) = value else {
        return Ok(std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get));
    };
    let threads = parse_u64(value, "--threads")?;
    if threads == 0 {
        return Err("--threads must be at least 1".to_owned());
    }

    usize::try_from(threads).map_err(|_| "--threads exceeds this platform's usize range".to_owned())
}

#[cfg(test)]
mod tests {
    use rand_core::{OsRng, RngCore};

    use super::*;

    #[test]
    fn secret_output_types_have_redacted_debug_output() {
        let secret = runtime_secret();
        let wallet_output = WalletNewOutput {
            address: "0x0000000000000000000000000000000000000000",
            keystore: "wallet.json",
            recovery_file: "recovery.txt",
            recovery_status: RECOVERY_STATUS,
        };
        let run_result = RunResult {
            output: Zeroizing::new(secret.to_string()),
            exit_code: 0,
        };

        let wallet_debug = format!("{wallet_output:?}");
        assert!(!wallet_debug.contains(secret.as_str()));
        let run_debug = format!("{run_result:?}");
        assert!(run_debug.contains("[REDACTED]"));
        assert!(!run_debug.contains(secret.as_str()));
    }

    #[test]
    fn proof_hunter_fee_refusal_names_the_path_and_exact_accepting_ceiling() {
        let quote = fee_quote(12_345, 10_000);
        let result = refused_submission(
            quote,
            proof_core::Address::from_bytes([0x11; 20]),
            Uint256::from(7_u64),
            ProofClassification::ProofHunter,
            true,
        )
        .unwrap();
        let output: serde_json::Value = serde_json::from_str(result.output.as_str()).unwrap();

        assert_eq!(result.exit_code, FEE_REFUSAL_EXIT_CODE);
        assert_eq!(output["proofClassification"], "proofHunter");
        assert_eq!(output["maximumExposureWei"], "12345");
        assert_eq!(output["wouldHaveAcceptedFeeCeilingWei"], "12345");
        assert!(
            output["reason"]
                .as_str()
                .unwrap()
                .contains("Proof Hunter proof")
        );
        assert!(
            output["reason"]
                .as_str()
                .unwrap()
                .contains("leaves this proof unsubmitted")
        );
        assert_new_output_has_no_secret_labels(result.output.as_str());
    }

    #[test]
    fn ordinary_fee_refusal_does_not_claim_a_proof_hunter_was_lost() {
        let result = refused_submission(
            fee_quote(12_345, 10_000),
            proof_core::Address::from_bytes([0x22; 20]),
            Uint256::from(8_u64),
            ProofClassification::Ordinary,
            false,
        )
        .unwrap();

        assert!(result.output.contains("ordinary proof refused"));
        assert!(!result.output.contains("Proof Hunter proof"));
        assert!(!result.output.contains("whole reward"));
        assert_new_output_has_no_secret_labels(result.output.as_str());
    }

    fn fee_quote(maximum_exposure_wei: u128, fee_ceiling_wei: u128) -> FeeQuote {
        FeeQuote {
            base_fee_per_gas_wei: 10,
            priority_fee_per_gas_wei: 3,
            max_fee_per_gas_wei: 23,
            estimated_gas: 400,
            gas_margin_percent: 25,
            gas_limit: 500,
            maximum_exposure_wei,
            fee_ceiling_wei,
        }
    }

    fn assert_new_output_has_no_secret_labels(output: &str) {
        for forbidden in ["privateKey", "passphrase", "mnemonic", "backupPhrase"] {
            assert!(!output.contains(forbidden), "output contained {forbidden}");
        }
    }

    fn runtime_secret() -> Zeroizing<String> {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";

        let mut bytes = Zeroizing::new([0_u8; 32]);
        OsRng.fill_bytes(bytes.as_mut());
        let mut output = String::with_capacity(64);
        for byte in bytes.iter() {
            output.push(char::from(DIGITS[usize::from(byte >> 4)]));
            output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
        Zeroizing::new(output)
    }
}
