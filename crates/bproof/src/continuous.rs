//! Continuous live mining with stale-work cancellation and bounded RPC retry delays.

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use bproof::keystore::{PassphraseSource, UnlockedWallet, read_passphrase, unlock_keystore};
use proof_core::{Address, ChallengeInputs, Target, Uint256};
use serde_json::{Map, Value, json};

use crate::chain::{
    CHAIN_STATE_SOURCE, ChallengeMarker, ChallengeStatus, HuntContracts, HuntStanding, MiningMode,
    RpcChainReader,
};
use crate::classification::{ProofClassification, classify_proof};
use crate::hunt;
use crate::mining::{MiningControl, MiningRequest, MiningResult, mine_with_control};
use crate::parse::{hex_string, parse_address, uint256_to_decimal};
use crate::submit::{
    ClaimRoute, FeeOptions, FeeQuote, PROOF_HUNTER_FEE_WARNING, PreparationOutcome,
    SUBMISSION_WARNING, pending_submission_path, prepare_claim, prepare_seed_refresh,
    prepare_submission, prepare_upkeep, recover_pending_submission, send_prepared_submission,
};
use crate::upkeep::{self, Check, Due, Next, UpkeepKind};

pub const DEFAULT_WATCH_INTERVAL: Duration = Duration::from_millis(1_000);
const RPC_BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const RPC_BACKOFF_CAP: Duration = Duration::from_secs(30);
const FAILURE_LIMIT: u64 = 3;
const INTERRUPT_POLL_INTERVAL: Duration = Duration::from_millis(25);
/// Mining v2 cadences (the app's): re-read the module and the wallet's stake at
/// most this often, re-check a waiting round, and back off while paused.
const MODE_RECHECK: Duration = Duration::from_secs(30);
const STAKE_RECHECK: Duration = Duration::from_secs(30);
const ROUND_RECHECK: Duration = Duration::from_secs(15);
const PAUSE_RECHECK: Duration = Duration::from_secs(60);
/// A refresh waits a random 0..this many ms so miners do not all send it at once.
const REFRESH_JITTER_MS: u64 = 20_000;
/// After an upkeep send whose outcome is unknown, wait this long before reconciling
/// its journal (the network usually settles it meanwhile), and between retries.
const JOURNAL_RETRY: Duration = Duration::from_secs(300);
/// Exit code when the loop stops because the wallet is not staked.
const NOT_STAKED_EXIT_CODE: u8 = 4;

pub struct ContinuousRequest {
    pub endpoint: String,
    pub chain_id: Uint256,
    pub mining_core: Address,
    /// Pinned mining router (release profile); otherwise read from the core.
    pub expected_router: Option<Address>,
    /// Never send network upkeep transactions.
    pub no_upkeep: bool,
    pub miner: Address,
    pub basket: Address,
    pub keystore: PathBuf,
    pub passphrase_file: Option<PathBuf>,
    pub fee_options: FeeOptions,
    pub threads: usize,
    pub start_nonce: Uint256,
    pub watch_interval: Duration,
}

pub struct ContinuousResult {
    pub summary: String,
    pub exit_code: u8,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct LoopCounters {
    proofs_accepted: u64,
    nfts_earned: u64,
    ordinary_proofs_fee_refused: u64,
    proof_hunters_fee_refused: u64,
    unknown_classification_fee_refused: u64,
    challenges_lost: u64,
    total_fees_paid_wei: u128,
    genuine_failures: u64,
    consecutive_failures: u64,
}

#[derive(Clone)]
struct LoopBook {
    counters: Arc<Mutex<LoopCounters>>,
    started: Instant,
}

impl LoopBook {
    fn new() -> Self {
        Self {
            counters: Arc::new(Mutex::new(LoopCounters::default())),
            started: Instant::now(),
        }
    }

    fn snapshot(&self) -> LoopCounters {
        *self
            .counters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn update(&self, update: impl FnOnce(&mut LoopCounters)) {
        let mut counters = self
            .counters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        update(&mut counters);
    }

    fn elapsed_millis(&self) -> u128 {
        self.started.elapsed().as_millis()
    }

    fn add_fee(&self, fee_paid_wei: u128) -> Result<(), String> {
        let mut counters = self
            .counters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        counters.total_fees_paid_wei = counters
            .total_fees_paid_wei
            .checked_add(fee_paid_wei)
            .ok_or_else(|| "loop fee total exceeds the supported u128 range".to_owned())?;
        Ok(())
    }
}

#[derive(Clone)]
struct EventWriter {
    json: bool,
    output_lock: Arc<Mutex<()>>,
    book: LoopBook,
}

impl EventWriter {
    fn emit(&self, event: &'static str, fields: Value) -> Result<(), String> {
        let rendered = self.render_event(event, fields)?;
        let _guard = self
            .output_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{rendered}")
            .and_then(|()| stdout.flush())
            .map_err(|error| format!("failed to write loop event: {error}"))
    }

    fn render_event(&self, event: &'static str, fields: Value) -> Result<String, String> {
        let counters = self.book.snapshot();
        let elapsed_millis = self.book.elapsed_millis();
        if self.json {
            let mut object = match fields {
                Value::Object(fields) => fields,
                _ => Map::new(),
            };
            object.insert("event".to_owned(), Value::String(event.to_owned()));
            object.insert(
                "elapsedMs".to_owned(),
                Value::String(elapsed_millis.to_string()),
            );
            object.insert(
                "summary".to_owned(),
                summary_value(counters, elapsed_millis),
            );
            return serde_json::to_string(&Value::Object(object))
                .map_err(|error| format!("failed to encode loop event as JSON: {error}"));
        }

        let details = fields.as_object().map_or_else(String::new, |fields| {
            fields
                .iter()
                .map(|(key, value)| format!(" {key}={}", display_value(value)))
                .collect::<String>()
        });
        Ok(format!(
            "event={event}{details} elapsedMs={elapsed_millis} proofsAccepted={} nftsEarned={} ordinaryProofsFeeRefused={} proofHuntersFeeRefused={} unknownClassificationFeeRefused={} challengesLost={} totalFeesPaidWei={} genuineFailures={}",
            counters.proofs_accepted,
            counters.nfts_earned,
            counters.ordinary_proofs_fee_refused,
            counters.proof_hunters_fee_refused,
            counters.unknown_classification_fee_refused,
            counters.challenges_lost,
            counters.total_fees_paid_wei,
            counters.genuine_failures,
        ))
    }
}

fn summary_value(counters: LoopCounters, elapsed_millis: u128) -> Value {
    json!({
        "proofsAccepted": counters.proofs_accepted.to_string(),
        "nftsEarned": counters.nfts_earned.to_string(),
        "ordinaryProofsFeeRefused": counters.ordinary_proofs_fee_refused.to_string(),
        "proofHuntersFeeRefused": counters.proof_hunters_fee_refused.to_string(),
        "unknownClassificationFeeRefused": counters.unknown_classification_fee_refused.to_string(),
        "challengesLost": counters.challenges_lost.to_string(),
        "totalFeesPaidWei": counters.total_fees_paid_wei.to_string(),
        "wallClockMs": elapsed_millis.to_string(),
        "genuineFailures": counters.genuine_failures.to_string(),
        "consecutiveFailures": counters.consecutive_failures.to_string(),
    })
}

fn display_value(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RetryBackoff {
    next: Duration,
    cap: Duration,
}

impl RetryBackoff {
    fn new(initial: Duration, cap: Duration) -> Self {
        Self { next: initial, cap }
    }

    fn take(&mut self) -> Duration {
        let delay = self.next;
        self.next = self.next.saturating_mul(2).min(self.cap);
        delay
    }

    fn reset(&mut self) {
        self.next = RPC_BACKOFF_INITIAL;
    }
}

enum WatchedMining {
    Mining(MiningResult),
    ChallengeMoved(ChallengeMarker),
    RpcError(String),
    /// The search's recheck deadline passed with the chain unchanged.
    Recheck {
        attempts: u128,
    },
    /// A network upkeep transaction is due; the search stopped after `attempts` hashes.
    Upkeep {
        due: Due,
        attempts: u128,
    },
}

/// Runs until interrupted, the contract reaches a terminal state, or a fatal failure occurs.
pub fn run(request: ContinuousRequest, json_output: bool) -> Result<ContinuousResult, String> {
    let book = LoopBook::new();
    let writer = EventWriter {
        json: json_output,
        output_lock: Arc::new(Mutex::new(())),
        book: book.clone(),
    };
    let shutdown = Arc::new(AtomicBool::new(false));
    install_interrupt_handler(Arc::clone(&shutdown))?;

    writer.emit(
        "started",
        json!({
            "stateSource": CHAIN_STATE_SOURCE,
            "watchIntervalMs": request.watch_interval.as_millis().to_string(),
            "rpcBackoffInitialMs": RPC_BACKOFF_INITIAL.as_millis().to_string(),
            "rpcBackoffCapMs": RPC_BACKOFF_CAP.as_millis().to_string(),
            "failureLimit": FAILURE_LIMIT.to_string(),
            "warning": SUBMISSION_WARNING,
            "proofHunterFeeWarning": PROOF_HUNTER_FEE_WARNING,
        }),
    )?;

    let reader = RpcChainReader::new(&request.endpoint, request.mining_core, request.chain_id);
    let mut backoff = RetryBackoff::new(RPC_BACKOFF_INITIAL, RPC_BACKOFF_CAP);
    loop {
        if shutdown.load(Ordering::Acquire) {
            return clean_stop(&writer, &book, "interrupt");
        }
        match reader.verify_identity() {
            Ok(()) => {
                backoff.reset();
                break;
            }
            Err(error) if is_permanent_identity_error(&error) => {
                return fatal(&writer, &book, error, 2);
            }
            Err(error) => {
                if !rpc_retry(&writer, &shutdown, &mut backoff, error)? {
                    return clean_stop(&writer, &book, "interrupt");
                }
            }
        }
    }
    match recover_pending_submission(&reader, &request.keystore) {
        Ok(Some(recovered)) => {
            if let Err(error) = book.add_fee(recovered.mined.fee_paid_wei) {
                return fatal(&writer, &book, error, 1);
            }
            if recovered.mined.succeeded
                && !recovered.mined.seed_refresh
                && recovered.mined.upkeep.is_none()
            {
                book.update(|summary| {
                    summary.proofs_accepted += 1;
                    summary.nfts_earned += u64::from(recovered.mined.proof_nft_minted);
                    summary.consecutive_failures = 0;
                });
            }
            writer.emit(
                if recovered.mined.upkeep.is_some() {
                    "upkeepRecovered"
                } else if recovered.mined.seed_refresh {
                    "seedRefreshRecovered"
                } else {
                    "submissionRecovered"
                },
                json!({
                    "transactionHash": hex_string(&recovered.mined.transaction_hash.to_bytes()),
                    "miningNonce": uint256_to_decimal(recovered.mined.mining_nonce),
                    "accountNonce": uint256_to_decimal(recovered.mined.account_nonce),
                    "feePaidWei": recovered.mined.fee_paid_wei.to_string(),
                    "succeeded": recovered.mined.succeeded,
                    "proofNftMinted": recovered.mined.proof_nft_minted,
                    "nftTokenId": recovered.mined.nft_token_id.map(uint256_to_decimal),
                    "proofClassification": recovered.proof_classification,
                    "classificationReason": recovered.classification_reason,
                }),
            )?;
        }
        Ok(None) => {}
        Err(error) => return fatal(&writer, &book, error, 2),
    }
    // Mining v2: a wallet without stake stops before its keystore is unlocked.
    match reader.mining_mode(request.expected_router) {
        Ok(MiningMode::Hunt(contracts)) => {
            if let Ok(standing) = reader.hunt_standing(contracts, request.miner)
                && hunt::stake_gate(standing.assigned, standing.unit, standing.mode)
                    == hunt::StakeGate::Needed
            {
                return not_staked(&writer, &standing, request.miner);
            }
        }
        Err(error) if is_permanent_mode_error(&error) => return fatal(&writer, &book, error, 2),
        _ => {}
    }
    let wallet = match unlock_wallet(&request) {
        Ok(wallet) => wallet,
        Err(error) => return fatal(&writer, &book, error, 2),
    };
    if let Err(error) = start_summary_listener(writer.clone(), Arc::clone(&shutdown)) {
        return fatal(&writer, &book, error, 2);
    }

    let mut mode_cache: Option<(MiningMode, Instant)> = None;
    let mut paused_announced: Option<Uint256> = None;
    let mut hunt_state = HuntState::default();
    loop {
        if shutdown.load(Ordering::Acquire) {
            return clean_stop(&writer, &book, "interrupt");
        }

        let mode = match mode_cache {
            Some((mode, checked)) if checked.elapsed() < MODE_RECHECK => mode,
            _ => match reader.mining_mode(request.expected_router) {
                Ok(mode) => {
                    mode_cache = Some((mode, Instant::now()));
                    mode
                }
                Err(error) if is_permanent_mode_error(&error) => {
                    return fatal(&writer, &book, error, 2);
                }
                Err(error) => {
                    if !rpc_retry(&writer, &shutdown, &mut backoff, error)? {
                        return clean_stop(&writer, &book, "interrupt");
                    }
                    continue;
                }
            },
        };
        match mode {
            MiningMode::Paused { resume_at } => {
                if paused_announced != Some(resume_at) {
                    writer.emit(
                        "miningPaused",
                        json!({
                            "resumeAt": uint256_to_decimal(resume_at),
                            "message": hunt::pause_message(resume_at),
                        }),
                    )?;
                    paused_announced = Some(resume_at);
                }
                mode_cache = None;
                if !wait_interruptibly(PAUSE_RECHECK, &shutdown) {
                    return clean_stop(&writer, &book, "interrupt");
                }
                continue;
            }
            MiningMode::Hunt(contracts) => {
                paused_announced = None;
                let step = HuntLoop {
                    request: &request,
                    reader: &reader,
                    writer: &writer,
                    book: &book,
                    shutdown: &shutdown,
                    wallet: &wallet,
                    contracts,
                }
                .step(&mut hunt_state, &mut backoff)?;
                if let Some(result) = step {
                    return Ok(result);
                }
                continue;
            }
            MiningMode::Direct => paused_announced = None,
        }

        let marker = match reader.read_challenge_marker() {
            Ok(marker) => marker,
            Err(error) => {
                if !rpc_retry(&writer, &shutdown, &mut backoff, error)? {
                    return clean_stop(&writer, &book, "interrupt");
                }
                continue;
            }
        };

        match marker.status {
            ChallengeStatus::Ended => return clean_stop(&writer, &book, "miningEnded"),
            ChallengeStatus::Stopped => return clean_stop(&writer, &book, "miningStopped"),
            ChallengeStatus::Expired => {
                let outcome = (|| {
                    let Some(expired) = reader.expired_seed()? else {
                        return Ok(None);
                    };
                    prepare_seed_refresh(
                        &reader,
                        request.chain_id,
                        request.mining_core,
                        request.miner,
                        expired,
                        request.fee_options,
                    )
                    .map(Some)
                })();
                match outcome {
                    Ok(Some(PreparationOutcome::Ready(prepared))) => {
                        if shutdown.load(Ordering::Acquire) {
                            return clean_stop(&writer, &book, "interrupt");
                        }
                        writer.emit("seedRefreshStarted", json!({"challengeId": uint256_to_decimal(marker.challenge_id), "maximumExposureWei": prepared.fee_quote.maximum_exposure_wei.to_string()}))?;
                        match send_prepared_submission(
                            &reader,
                            &wallet,
                            *prepared,
                            &request.keystore,
                            "seedRefresh",
                            None,
                        ) {
                            Ok(mined) => {
                                book.add_fee(mined.fee_paid_wei)?;
                                writer.emit(if mined.succeeded { "seedRefreshed" } else { "seedRefreshReverted" }, json!({"transactionHash": hex_string(&mined.transaction_hash.to_bytes()), "feePaidWei": mined.fee_paid_wei.to_string()}))?;
                                if mined.succeeded {
                                    book.update(|summary| summary.consecutive_failures = 0);
                                } else if repeated_failure(
                                    &writer,
                                    &book,
                                    &shutdown,
                                    &mut backoff,
                                    "seed refresh reverted; rechecking the current challenge"
                                        .to_owned(),
                                )? {
                                    return failed_stop(&writer, &book);
                                }
                            }
                            Err(error) => {
                                // A journal means the send could have succeeded. Never sign a replacement.
                                if crate::submit::pending_submission_path(&request.keystore)
                                    .exists()
                                {
                                    writer
                                        .emit("submissionUnresolved", json!({"reason": error}))?;
                                    return failed_stop(&writer, &book);
                                }
                                if repeated_failure(&writer, &book, &shutdown, &mut backoff, error)?
                                {
                                    return failed_stop(&writer, &book);
                                }
                            }
                        }
                    }
                    Ok(Some(PreparationOutcome::FeeRefused(quote))) => {
                        writer.emit("seedRefreshFeeRefused", json!({"maximumExposureWei": quote.maximum_exposure_wei.to_string(), "feeCeilingWei": quote.fee_ceiling_wei.to_string()}))?;
                    }
                    Ok(Some(PreparationOutcome::SimulationRejected { reason })) => {
                        if repeated_failure(&writer, &book, &shutdown, &mut backoff, reason)? {
                            return failed_stop(&writer, &book);
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        if !rpc_retry(&writer, &shutdown, &mut backoff, error)? {
                            return clean_stop(&writer, &book, "interrupt");
                        }
                    }
                }
                if !wait_interruptibly(request.watch_interval, &shutdown) {
                    return clean_stop(&writer, &book, "interrupt");
                }
                continue;
            }
            ChallengeStatus::WaitingForSeed => {
                writer.emit(
                    "challengeUnavailable",
                    json!({
                        "challengeId": uint256_to_decimal(marker.challenge_id),
                        "status": challenge_status_name(marker.status),
                    }),
                )?;
                if !wait_interruptibly(request.watch_interval, &shutdown) {
                    return clean_stop(&writer, &book, "interrupt");
                }
                continue;
            }
            ChallengeStatus::Active => {}
        }

        let classified_state = match reader.read_classified_state(Some(request.miner)) {
            Ok(state) => {
                backoff.reset();
                state
            }
            Err(error) => {
                if !rpc_retry(&writer, &shutdown, &mut backoff, error)? {
                    return clean_stop(&writer, &book, "interrupt");
                }
                continue;
            }
        };
        let state = classified_state.state;
        let expected_marker = ChallengeMarker {
            challenge_id: state.challenge_inputs.challenge_id,
            previous_accepted_digest: state.challenge_inputs.previous_accepted_digest,
            challenge: Some(state.challenge),
            status: ChallengeStatus::Active,
            target: None,
        };
        if marker != expected_marker {
            writer.emit(
                "challengeChanged",
                json!({"challengeId": uint256_to_decimal(marker.challenge_id)}),
            )?;
            continue;
        }

        writer.emit(
            "searchStarted",
            json!({
                "challengeId": uint256_to_decimal(state.challenge_inputs.challenge_id),
                "challenge": hex_string(&state.challenge.to_bytes()),
                "target": hex_string(&classified_state.effective_target.to_be_bytes()),
                "baseTarget": hex_string(&state.target.to_be_bytes()),
                "powerMultiplierWad": uint256_to_decimal(classified_state.power_multiplier_wad),
                "threads": request.threads.to_string(),
            }),
        )?;

        let watched = match watched_mine(
            &request,
            &state.challenge_inputs,
            classified_state.effective_target,
            &shutdown,
        ) {
            Ok(watched) => watched,
            Err(error) => {
                if repeated_failure(&writer, &book, &shutdown, &mut backoff, error)? {
                    return failed_stop(&writer, &book);
                }
                continue;
            }
        };
        match watched {
            WatchedMining::ChallengeMoved(current) => {
                record_challenge_move(&book, &expected_marker, &current);
                writer.emit(
                    "staleWorkAbandoned",
                    json!({
                        "abandonedChallengeId": uint256_to_decimal(expected_marker.challenge_id),
                        "currentChallengeId": uint256_to_decimal(current.challenge_id),
                        "currentStatus": challenge_status_name(current.status),
                    }),
                )?;
            }
            WatchedMining::RpcError(error) => {
                if !rpc_retry(&writer, &shutdown, &mut backoff, error)? {
                    return clean_stop(&writer, &book, "interrupt");
                }
            }
            WatchedMining::Recheck { .. } | WatchedMining::Upkeep { .. } => {}
            WatchedMining::Mining(MiningResult::Found {
                mining_nonce,
                digest,
                attempts,
                threads,
            }) => {
                let classification = classify_proof(digest, &classified_state.nft_classification);
                writer.emit(
                    "proofFound",
                    json!({
                        "challengeId": uint256_to_decimal(state.challenge_inputs.challenge_id),
                        "miningNonce": uint256_to_decimal(mining_nonce),
                        "digest": hex_string(&digest.to_bytes()),
                        "attempts": attempts.to_string(),
                        "threads": threads.to_string(),
                        "proofClassification": classification.name(),
                        "classificationReason": classification.reason(),
                    }),
                )?;
                match prepare_submission(
                    &reader,
                    state.challenge_inputs,
                    request.miner,
                    mining_nonce,
                    request.basket,
                    request.fee_options,
                ) {
                    Ok(PreparationOutcome::Ready(prepared)) => {
                        match send_prepared_submission(
                            &reader,
                            &wallet,
                            *prepared,
                            &request.keystore,
                            classification.name(),
                            classification.reason(),
                        ) {
                            Ok(mined) => {
                                if let Err(error) = book.add_fee(mined.fee_paid_wei) {
                                    return fatal(&writer, &book, error, 1);
                                }
                                if mined.succeeded {
                                    book.update(|summary| {
                                        summary.proofs_accepted += 1;
                                        summary.nfts_earned += u64::from(mined.proof_nft_minted);
                                        summary.consecutive_failures = 0;
                                    });
                                    writer.emit(
                                        "proofAccepted",
                                        json!({
                                            "challengeId": uint256_to_decimal(state.challenge_inputs.challenge_id),
                                            "transactionHash": hex_string(&mined.transaction_hash.to_bytes()),
                                            "miningNonce": uint256_to_decimal(mined.mining_nonce),
                                            "accountNonce": uint256_to_decimal(mined.account_nonce),
                                            "feePaidWei": mined.fee_paid_wei.to_string(),
                                            "maximumExposureWei": mined.fee_quote.maximum_exposure_wei.to_string(),
                                            "proofNftMinted": mined.proof_nft_minted,
                                            "nftTokenId": mined.nft_token_id.map(uint256_to_decimal),
                                        }),
                                    )?;
                                } else {
                                    match reader.read_challenge_marker() {
                                        Ok(current) if current != expected_marker => {
                                            let consumed = challenge_was_consumed(
                                                &expected_marker,
                                                &current,
                                            );
                                            book.update(|summary| {
                                                summary.challenges_lost += u64::from(consumed);
                                                summary.consecutive_failures = 0;
                                            });
                                            writer.emit(
                                                if consumed {
                                                    "challengeLost"
                                                } else {
                                                    "staleWorkAbandoned"
                                                },
                                                json!({
                                                    "challengeId": uint256_to_decimal(expected_marker.challenge_id),
                                                    "transactionHash": hex_string(&mined.transaction_hash.to_bytes()),
                                                    "feePaidWei": mined.fee_paid_wei.to_string(),
                                                    "reason": if consumed {
                                                        "another miner consumed the challenge before inclusion"
                                                    } else {
                                                        "the challenge changed before inclusion"
                                                    },
                                                }),
                                            )?;
                                        }
                                        Ok(_) => {
                                            if repeated_failure(
                                                &writer,
                                                &book,
                                                &shutdown,
                                                &mut backoff,
                                                "proof transaction reverted while the challenge remained current".to_owned(),
                                            )? {
                                                return failed_stop(&writer, &book);
                                            }
                                        }
                                        Err(error) => {
                                            if !rpc_retry(
                                                &writer,
                                                &shutdown,
                                                &mut backoff,
                                                error,
                                            )? {
                                                return clean_stop(&writer, &book, "interrupt");
                                            }
                                        }
                                    }
                                }
                            }
                            Err(error) => {
                                // A lost response may follow a successful broadcast. Stop
                                // instead of generating another signed transaction.
                                writer.emit("submissionUnresolved", json!({"reason": error}))?;
                                return failed_stop(&writer, &book);
                            }
                        }
                    }
                    Ok(PreparationOutcome::FeeRefused(quote)) => {
                        record_fee_refusal(&book, &classification);
                        writer.emit(
                            "feeRefused",
                            json!({
                                "challengeId": uint256_to_decimal(state.challenge_inputs.challenge_id),
                                "miningNonce": uint256_to_decimal(mining_nonce),
                                "maximumExposureWei": quote.maximum_exposure_wei.to_string(),
                                "wouldHaveAcceptedFeeCeilingWei": quote.maximum_exposure_wei.to_string(),
                                "feeCeilingWei": quote.fee_ceiling_wei.to_string(),
                                "proofClassification": classification.name(),
                                "classificationReason": classification.reason(),
                                "reason": fee_refusal_reason(&quote, &classification),
                            }),
                        )?;
                        if !wait_interruptibly(request.watch_interval, &shutdown) {
                            return clean_stop(&writer, &book, "interrupt");
                        }
                    }
                    Ok(PreparationOutcome::SimulationRejected { reason }) => {
                        match reader.read_challenge_marker() {
                            Ok(current) if current != expected_marker => {
                                let consumed = challenge_was_consumed(&expected_marker, &current);
                                book.update(|summary| {
                                    summary.challenges_lost += u64::from(consumed);
                                    summary.consecutive_failures = 0;
                                });
                                writer.emit(
                                    if consumed {
                                        "challengeLost"
                                    } else {
                                        "staleWorkAbandoned"
                                    },
                                    json!({
                                        "challengeId": uint256_to_decimal(expected_marker.challenge_id),
                                        "currentChallengeId": uint256_to_decimal(current.challenge_id),
                                        "reason": if consumed {
                                            "another miner consumed the challenge before simulation"
                                        } else {
                                            "the challenge changed before simulation"
                                        },
                                    }),
                                )?;
                            }
                            Ok(_) => {
                                if repeated_failure(
                                    &writer,
                                    &book,
                                    &shutdown,
                                    &mut backoff,
                                    reason,
                                )? {
                                    return failed_stop(&writer, &book);
                                }
                            }
                            Err(error) => {
                                if !rpc_retry(&writer, &shutdown, &mut backoff, error)? {
                                    return clean_stop(&writer, &book, "interrupt");
                                }
                            }
                        }
                    }
                    Err(error) if is_rpc_error(&error) => {
                        if !rpc_retry(&writer, &shutdown, &mut backoff, error)? {
                            return clean_stop(&writer, &book, "interrupt");
                        }
                    }
                    Err(error) => {
                        if repeated_failure(&writer, &book, &shutdown, &mut backoff, error)? {
                            return failed_stop(&writer, &book);
                        }
                    }
                }
            }
            WatchedMining::Mining(MiningResult::Abandoned { .. }) => {
                if shutdown.load(Ordering::Acquire) {
                    return clean_stop(&writer, &book, "interrupt");
                }
                if repeated_failure(
                    &writer,
                    &book,
                    &shutdown,
                    &mut backoff,
                    "search was abandoned without a challenge change".to_owned(),
                )? {
                    return failed_stop(&writer, &book);
                }
            }
            WatchedMining::Mining(MiningResult::Exhausted { .. }) => {
                if repeated_failure(
                    &writer,
                    &book,
                    &shutdown,
                    &mut backoff,
                    "unlimited loop search exhausted unexpectedly".to_owned(),
                )? {
                    return failed_stop(&writer, &book);
                }
            }
        }
    }
}

// ------------------------------------------------------------------ Mining v2 loop

/// What the Mining v2 loop remembers between iterations.
#[derive(Default)]
struct HuntState {
    /// When the wallet's stake was last confirmed.
    stake_checked: Option<Instant>,
    /// The last (challenge, status) announced as unavailable, so waits are reported once.
    announced: Option<(Uint256, &'static str)>,
    /// The expired challenge whose random refresh delay has already run.
    refresh_delayed: Option<Uint256>,
    /// The round being searched, announced once with `searchStarted`.
    searching: Option<ChallengeMarker>,
    /// Where to resume on the same round after a dropped candidate.
    resume: Option<(ChallengeMarker, Uint256)>,
    /// The challenge for which pending stake was reported.
    pending_reported: Option<Uint256>,
    /// Network upkeep bookkeeping, shared with the challenge watcher.
    upkeep: Arc<Mutex<upkeep::Schedule>>,
    /// When to next reconcile an upkeep transaction left in the journal.
    journal_retry_at: Option<Instant>,
}

struct HuntLoop<'a> {
    request: &'a ContinuousRequest,
    reader: &'a RpcChainReader,
    writer: &'a EventWriter,
    book: &'a LoopBook,
    shutdown: &'a Arc<AtomicBool>,
    wallet: &'a UnlockedWallet,
    contracts: HuntContracts,
}

type Step = Result<Option<ContinuousResult>, String>;

impl HuntLoop<'_> {
    /// One pass: gate on stake, then wait, refresh, or search and claim.
    fn step(&self, state: &mut HuntState, backoff: &mut RetryBackoff) -> Step {
        if state
            .stake_checked
            .is_none_or(|checked| checked.elapsed() >= STAKE_RECHECK)
        {
            match self.standing() {
                Ok(standing) => {
                    if self.needs_stake(&standing) {
                        return not_staked(self.writer, &standing, self.request.miner).map(Some);
                    }
                    state.stake_checked = Some(Instant::now());
                }
                Err(error) => return self.retry(backoff, error),
            }
        }
        // An upkeep transaction left in the journal is reconciled when due; mining
        // continues meanwhile, and no other transaction is signed until it settles.
        if pending_submission_path(&self.request.keystore).exists()
            && state.journal_retry_at.is_none_or(|at| Instant::now() >= at)
        {
            match self.resolve_journal() {
                Ok(()) => state.journal_retry_at = None,
                Err(error) => {
                    state.journal_retry_at = Some(Instant::now() + JOURNAL_RETRY);
                    self.writer
                        .emit("submissionPending", json!({"reason": error}))?;
                }
            }
        }
        let marker = match self.reader.read_challenge_marker_with_target() {
            Ok(marker) => marker,
            Err(error) => return self.retry(backoff, error),
        };
        match marker.status {
            ChallengeStatus::Ended => {
                return clean_stop(self.writer, self.book, "miningEnded").map(Some);
            }
            ChallengeStatus::Stopped => {
                return clean_stop(self.writer, self.book, "miningStopped").map(Some);
            }
            ChallengeStatus::WaitingForSeed => {
                self.announce(state, &marker, hunt::MINING_MESSAGE)?;
                return self.wait(self.request.watch_interval);
            }
            ChallengeStatus::Expired => return self.expired(state, backoff, &marker),
            ChallengeStatus::Active => {}
        }

        let round = match self
            .reader
            .read_hunt_round(self.contracts, self.request.miner)
        {
            Ok(round) => {
                backoff.reset();
                round
            }
            Err(error) if error.contains("challenge unavailable") => {
                self.announce(state, &marker, hunt::MINING_MESSAGE)?;
                return self.wait(self.request.watch_interval);
            }
            Err(error) => return self.retry(backoff, error),
        };
        let inputs = round.state.challenge_inputs;
        let current = ChallengeMarker {
            challenge_id: inputs.challenge_id,
            previous_accepted_digest: inputs.previous_accepted_digest,
            challenge: Some(round.state.challenge),
            status: ChallengeStatus::Active,
            target: Some(round.state.target),
        };
        if marker != current {
            self.writer.emit(
                "challengeChanged",
                json!({"challengeId": uint256_to_decimal(marker.challenge_id)}),
            )?;
            return Ok(None);
        }
        let first_nonce = match hunt::bound_nonce(self.request.miner, self.request.start_nonce) {
            Ok(nonce) => nonce,
            Err(error) => return fatal(self.writer, self.book, error, 2).map(Some),
        };
        let start_nonce = match state.resume {
            Some((resume_marker, nonce)) if resume_marker == current => nonce,
            _ => first_nonce,
        };
        if state.searching != Some(current) {
            state.searching = Some(current);
            self.writer.emit(
                "searchStarted",
                json!({
                    "challengeId": uint256_to_decimal(inputs.challenge_id),
                    "challenge": hex_string(&round.state.challenge.to_bytes()),
                    "target": hex_string(&round.state.target.to_be_bytes()),
                    "baseTarget": hex_string(&round.state.target.to_be_bytes()),
                    "powerMultiplierWad": crate::power::BASE_WAD.to_string(),
                    "threads": self.request.threads.to_string(),
                    "message": hunt::MINING_MESSAGE,
                }),
            )?;
        }
        self.report_pending_stake(state, &round.standing, inputs.challenge_id)?;

        // A wallet that cannot submit on this round keeps hashing, as the app does,
        // but with a target nothing meets, and rechecks the round every few seconds.
        let eligible = hunt::can_submit(&round.standing.preview);
        let upkeep_watch = upkeep::enabled(
            self.request.no_upkeep,
            round.standing.assigned,
            round.standing.unit,
        )
        .then(|| UpkeepWatch {
            schedule: Arc::clone(&state.upkeep),
            wallet: self.request.miner,
            core: self.request.mining_core,
            router: self.contracts.router,
            challenge_id: inputs.challenge_id,
            fresh: round.standing.preview.fresh,
            journal: pending_submission_path(&self.request.keystore),
        });
        let spec = if eligible {
            SearchSpec {
                challenge_inputs: inputs,
                miner: self.contracts.router,
                floor: round.band.search_floor(),
                target: round.band.search_target(),
                start_nonce,
                recheck_at: None,
                upkeep: upkeep_watch,
            }
        } else {
            SearchSpec {
                challenge_inputs: inputs,
                miner: self.contracts.router,
                floor: None,
                target: Target::from_be_bytes([0; 32]),
                start_nonce,
                recheck_at: Some(Instant::now() + ROUND_RECHECK),
                upkeep: upkeep_watch,
            }
        };
        let watched = match watched_search(self.request, spec, current, self.shutdown) {
            Ok(watched) => watched,
            Err(error) => return self.failure(backoff, error),
        };
        match watched {
            WatchedMining::ChallengeMoved(moved) => {
                record_challenge_move(self.book, &current, &moved);
                state.resume = None;
                self.writer.emit(
                    "staleWorkAbandoned",
                    json!({
                        "abandonedChallengeId": uint256_to_decimal(current.challenge_id),
                        "currentChallengeId": uint256_to_decimal(moved.challenge_id),
                        "currentStatus": challenge_status_name(moved.status),
                    }),
                )?;
                Ok(None)
            }
            WatchedMining::RpcError(error) => self.retry(backoff, error),
            WatchedMining::Recheck { attempts } => {
                state.resume = Some((current, advance(start_nonce, attempts)));
                Ok(None)
            }
            WatchedMining::Upkeep { due, attempts } => {
                state.resume = Some((current, advance(start_nonce, attempts)));
                self.run_upkeep(state, due)
            }
            WatchedMining::Mining(MiningResult::Found {
                mining_nonce,
                digest,
                attempts,
                threads,
            }) => {
                if !round.band.contains(digest)
                    || !hunt::is_bound_nonce(mining_nonce, self.request.miner)
                {
                    return self.failure(
                        backoff,
                        "local search returned a proof outside its bounds".to_owned(),
                    );
                }
                let found = Found {
                    marker: current,
                    nonce: mining_nonce,
                    digest,
                    attempts,
                    threads,
                };
                self.found(state, backoff, &round, found)
            }
            WatchedMining::Mining(MiningResult::Abandoned { .. }) => {
                if self.shutdown.load(Ordering::Acquire) {
                    return clean_stop(self.writer, self.book, "interrupt").map(Some);
                }
                self.failure(
                    backoff,
                    "search was abandoned without a challenge change".to_owned(),
                )
            }
            WatchedMining::Mining(MiningResult::Exhausted { .. }) => self.failure(
                backoff,
                "unlimited loop search exhausted unexpectedly".to_owned(),
            ),
        }
    }

    /// Expired: refresh only once the next round is open by chain time, after a random delay.
    fn expired(
        &self,
        state: &mut HuntState,
        backoff: &mut RetryBackoff,
        marker: &ChallengeMarker,
    ) -> Step {
        let standing = match self.standing() {
            Ok(standing) => standing,
            Err(error) => return self.retry(backoff, error),
        };
        if self.needs_stake(&standing) {
            return not_staked(self.writer, &standing, self.request.miner).map(Some);
        }
        let open_at = standing.preview.open_at;
        if !hunt::refresh_allowed(true, open_at, standing.chain_now) {
            self.announce(state, marker, hunt::MINING_MESSAGE)?;
            let until_open = seconds_between(standing.chain_now, open_at).saturating_add(1);
            let delay = Duration::from_secs(until_open)
                .min(ROUND_RECHECK)
                .max(self.request.watch_interval);
            return self.wait(delay);
        }
        if state.refresh_delayed != Some(marker.challenge_id) {
            state.refresh_delayed = Some(marker.challenge_id);
            return self.wait(Duration::from_millis(random_below(REFRESH_JITTER_MS + 1)));
        }
        let outcome = (|| {
            let Some(expired) = self.reader.expired_seed()? else {
                return Ok(None);
            };
            prepare_seed_refresh(
                self.reader,
                self.request.chain_id,
                self.request.mining_core,
                self.request.miner,
                expired,
                self.request.fee_options,
            )
            .map(Some)
        })();
        match outcome {
            Ok(Some(PreparationOutcome::Ready(prepared))) => {
                if self.shutdown.load(Ordering::Acquire) {
                    return clean_stop(self.writer, self.book, "interrupt").map(Some);
                }
                self.writer.emit(
                    "seedRefreshStarted",
                    json!({
                        "challengeId": uint256_to_decimal(marker.challenge_id),
                        "maximumExposureWei": prepared.fee_quote.maximum_exposure_wei.to_string(),
                    }),
                )?;
                match send_prepared_submission(
                    self.reader,
                    self.wallet,
                    *prepared,
                    &self.request.keystore,
                    "seedRefresh",
                    None,
                ) {
                    Ok(mined) => {
                        self.book.add_fee(mined.fee_paid_wei)?;
                        self.book.update(|summary| summary.consecutive_failures = 0);
                        // Another miner can refresh first; a reverted refresh is not a fault.
                        self.writer.emit(
                            if mined.succeeded {
                                "seedRefreshed"
                            } else {
                                "seedRefreshReverted"
                            },
                            json!({
                                "transactionHash": hex_string(&mined.transaction_hash.to_bytes()),
                                "feePaidWei": mined.fee_paid_wei.to_string(),
                            }),
                        )?;
                        Ok(None)
                    }
                    Err(error) => {
                        // A journal means the send could have succeeded. Never sign a replacement.
                        if crate::submit::pending_submission_path(&self.request.keystore).exists() {
                            self.writer
                                .emit("submissionUnresolved", json!({"reason": error}))?;
                            return failed_stop(self.writer, self.book).map(Some);
                        }
                        self.failure(backoff, error)
                    }
                }
            }
            Ok(Some(PreparationOutcome::FeeRefused(quote))) => {
                self.writer.emit(
                    "seedRefreshFeeRefused",
                    json!({
                        "maximumExposureWei": quote.maximum_exposure_wei.to_string(),
                        "feeCeilingWei": quote.fee_ceiling_wei.to_string(),
                    }),
                )?;
                self.wait(self.request.watch_interval)
            }
            // Someone else refreshed first: nothing to do.
            Ok(Some(PreparationOutcome::SimulationRejected { .. }) | None) => {
                self.wait(self.request.watch_interval)
            }
            Err(error) => self.retry(backoff, error),
        }
    }

    /// A found proof: submit only when the wallet would pass now; otherwise drop it quietly.
    fn found(
        &self,
        state: &mut HuntState,
        backoff: &mut RetryBackoff,
        round: &crate::chain::HuntRound,
        found: Found,
    ) -> Step {
        let next = found.nonce.wrapping_add(Uint256::ONE);
        state.resume = Some((found.marker, next));
        let standing = match self.standing() {
            Ok(standing) => standing,
            Err(error) => return self.retry(backoff, error),
        };
        if self.needs_stake(&standing) {
            return not_staked(self.writer, &standing, self.request.miner).map(Some);
        }
        state.stake_checked = Some(Instant::now());
        if !hunt::can_submit(&standing.preview) {
            // Dropped quietly; the next pass rereads the round.
            self.report_pending_stake(state, &standing, found.marker.challenge_id)?;
            return Ok(None);
        }
        let inputs = round.state.challenge_inputs;
        let classification = classify_proof(found.digest, &round.nft_classification);
        self.writer.emit(
            "proofFound",
            json!({
                "challengeId": uint256_to_decimal(inputs.challenge_id),
                "miningNonce": uint256_to_decimal(found.nonce),
                "digest": hex_string(&found.digest.to_bytes()),
                "attempts": found.attempts.to_string(),
                "threads": found.threads.to_string(),
                "proofClassification": classification.name(),
                "classificationReason": classification.reason(),
            }),
        )?;
        let route = ClaimRoute {
            router: self.contracts.router,
            nft: self.contracts.nft,
        };
        // An earlier upkeep still unresolved must settle first: never two transactions
        // with one account nonce. If it cannot, stop rather than sign past it.
        if pending_submission_path(&self.request.keystore).exists()
            && let Err(error) = self.resolve_journal()
        {
            self.writer
                .emit("submissionUnresolved", json!({"reason": error}))?;
            return failed_stop(self.writer, self.book).map(Some);
        }
        match prepare_claim(
            self.reader,
            inputs,
            self.request.miner,
            route,
            found.nonce,
            self.request.basket,
            self.request.fee_options,
        ) {
            Ok(PreparationOutcome::Ready(prepared)) => {
                let mined = match send_prepared_submission(
                    self.reader,
                    self.wallet,
                    *prepared,
                    &self.request.keystore,
                    classification.name(),
                    classification.reason(),
                ) {
                    Ok(mined) => mined,
                    Err(error) => {
                        // A lost response may follow a successful broadcast. Stop
                        // instead of generating another signed transaction.
                        self.writer
                            .emit("submissionUnresolved", json!({"reason": error}))?;
                        return failed_stop(self.writer, self.book).map(Some);
                    }
                };
                if let Err(error) = self.book.add_fee(mined.fee_paid_wei) {
                    return fatal(self.writer, self.book, error, 1).map(Some);
                }
                if mined.succeeded {
                    state.resume = None;
                    self.book.update(|summary| {
                        summary.proofs_accepted += 1;
                        summary.nfts_earned += u64::from(mined.proof_nft_minted);
                        summary.consecutive_failures = 0;
                    });
                    self.writer.emit(
                        "proofAccepted",
                        json!({
                            "challengeId": uint256_to_decimal(inputs.challenge_id),
                            "transactionHash": hex_string(&mined.transaction_hash.to_bytes()),
                            "miningNonce": uint256_to_decimal(mined.mining_nonce),
                            "accountNonce": uint256_to_decimal(mined.account_nonce),
                            "feePaidWei": mined.fee_paid_wei.to_string(),
                            "maximumExposureWei": mined.fee_quote.maximum_exposure_wei.to_string(),
                            "proofNftMinted": mined.proof_nft_minted,
                            "nftTokenId": mined.nft_token_id.map(uint256_to_decimal),
                            "message": hunt::found_message(mined.nft_token_id),
                        }),
                    )?;
                    return Ok(None);
                }
                self.lost_or_failed(
                    backoff,
                    &found.marker,
                    Some(&mined),
                    "proof transaction reverted while the challenge remained current".to_owned(),
                )
            }
            Ok(PreparationOutcome::FeeRefused(quote)) => {
                record_fee_refusal(self.book, &classification);
                self.writer.emit(
                    "feeRefused",
                    json!({
                        "challengeId": uint256_to_decimal(inputs.challenge_id),
                        "miningNonce": uint256_to_decimal(found.nonce),
                        "maximumExposureWei": quote.maximum_exposure_wei.to_string(),
                        "wouldHaveAcceptedFeeCeilingWei": quote.maximum_exposure_wei.to_string(),
                        "feeCeilingWei": quote.fee_ceiling_wei.to_string(),
                        "proofClassification": classification.name(),
                        "classificationReason": classification.reason(),
                        "reason": fee_refusal_reason(&quote, &classification),
                    }),
                )?;
                self.wait(self.request.watch_interval)
            }
            Ok(PreparationOutcome::SimulationRejected { reason }) => {
                if hunt::is_neutral_revert(&reason) {
                    // The module or router would refuse this proof now: drop it quietly.
                    return Ok(None);
                }
                self.lost_or_failed(backoff, &found.marker, None, reason)
            }
            Err(error) if is_rpc_error(&error) => self.retry(backoff, error),
            Err(error) => self.failure(backoff, error),
        }
    }

    /// After a refused or reverted proof: a moved challenge is a lost race, not a fault.
    fn lost_or_failed(
        &self,
        backoff: &mut RetryBackoff,
        expected: &ChallengeMarker,
        mined: Option<&crate::submit::MinedSubmission>,
        reason: String,
    ) -> Step {
        match self.reader.read_challenge_marker_with_target() {
            Ok(current) if current != *expected => {
                let consumed = challenge_was_consumed(expected, &current);
                self.book.update(|summary| {
                    summary.challenges_lost += u64::from(consumed);
                    summary.consecutive_failures = 0;
                });
                let mut fields = json!({
                    "challengeId": uint256_to_decimal(expected.challenge_id),
                    "currentChallengeId": uint256_to_decimal(current.challenge_id),
                    "reason": if consumed {
                        "another miner consumed the challenge before inclusion"
                    } else {
                        "the challenge changed before inclusion"
                    },
                });
                if let Some(mined) = mined {
                    fields["transactionHash"] =
                        json!(hex_string(&mined.transaction_hash.to_bytes()));
                    fields["feePaidWei"] = json!(mined.fee_paid_wei.to_string());
                }
                self.writer.emit(
                    if consumed {
                        "challengeLost"
                    } else {
                        "staleWorkAbandoned"
                    },
                    fields,
                )?;
                Ok(None)
            }
            Ok(_) => self.failure(backoff, hunt::neutral_rejection(&reason)),
            Err(error) => self.retry(backoff, error),
        }
    }

    /// Sends one due network upkeep through the journaled submit path. It is re-checked
    /// and simulated again first; any failure only logs a neutral line.
    fn run_upkeep(&self, state: &mut HuntState, due: Due) -> Step {
        let journal_pending = pending_submission_path(&self.request.keystore).exists();
        // Only reached between searches, so no claim is in flight here.
        if !upkeep::may_send(false, journal_pending) {
            lock_schedule(&state.upkeep).finish(due, false, 0);
            return self.upkeep_skipped(due.kind, None);
        }
        if due.kind == UpkeepKind::Lock
            && self.reader.router_fixed(self.contracts.router) != Ok(false)
        {
            lock_schedule(&state.upkeep).finish(due, false, 0);
            return self.upkeep_skipped(due.kind, None);
        }
        let prepared = match prepare_upkeep(
            self.reader,
            self.request.miner,
            due.kind,
            self.contracts.router,
            self.request.fee_options,
        ) {
            Ok(PreparationOutcome::Ready(prepared)) => *prepared,
            Ok(
                PreparationOutcome::FeeRefused(_) | PreparationOutcome::SimulationRejected { .. },
            )
            | Err(_) => {
                lock_schedule(&state.upkeep).finish(due, false, 0);
                return self.upkeep_skipped(due.kind, None);
            }
        };
        let sent = send_prepared_submission(
            self.reader,
            self.wallet,
            prepared,
            &self.request.keystore,
            "upkeep",
            None,
        );
        let chain_now = self.reader.latest_timestamp().unwrap_or(0);
        // Treated as sent either way: an unresolved send is never repeated.
        lock_schedule(&state.upkeep).finish(due, true, chain_now);
        if sent.is_err() {
            state.journal_retry_at = Some(Instant::now() + JOURNAL_RETRY);
        }
        match sent {
            Ok(mined) => {
                self.book.add_fee(mined.fee_paid_wei)?;
                if mined.succeeded {
                    self.writer.emit(
                        "upkeepSent",
                        json!({
                            "kind": due.kind.name(),
                            "transactionHash": hex_string(&mined.transaction_hash.to_bytes()),
                            "feePaidWei": mined.fee_paid_wei.to_string(),
                            "message": upkeep::NEUTRAL_SENT,
                        }),
                    )?;
                    Ok(None)
                } else {
                    self.upkeep_skipped(due.kind, Some(&mined))
                }
            }
            Err(_) => self.upkeep_skipped(due.kind, None),
        }
    }

    fn upkeep_skipped(
        &self,
        kind: UpkeepKind,
        mined: Option<&crate::submit::MinedSubmission>,
    ) -> Step {
        let mut fields = json!({"kind": kind.name(), "message": upkeep::NEUTRAL_SKIPPED});
        if let Some(mined) = mined {
            fields["transactionHash"] = json!(hex_string(&mined.transaction_hash.to_bytes()));
            fields["feePaidWei"] = json!(mined.fee_paid_wei.to_string());
        }
        self.writer.emit("upkeepSkipped", fields)?;
        Ok(None)
    }

    /// Reconciles the journaled transaction (rebroadcasting the same signed bytes if
    /// needed); an error means it is still unresolved.
    fn resolve_journal(&self) -> Result<(), String> {
        let Some(recovered) = recover_pending_submission(self.reader, &self.request.keystore)?
        else {
            return Ok(());
        };
        self.book.add_fee(recovered.mined.fee_paid_wei)?;
        let mined = recovered.mined;
        if let Some(kind) = mined.upkeep {
            return self.writer.emit(
                "upkeepRecovered",
                json!({
                    "kind": kind.name(),
                    "transactionHash": hex_string(&mined.transaction_hash.to_bytes()),
                    "succeeded": mined.succeeded,
                    "feePaidWei": mined.fee_paid_wei.to_string(),
                    "message": upkeep::NEUTRAL_SENT,
                }),
            );
        }
        if mined.succeeded && !mined.seed_refresh {
            self.book.update(|summary| {
                summary.proofs_accepted += 1;
                summary.nfts_earned += u64::from(mined.proof_nft_minted);
            });
        }
        self.writer.emit(
            if mined.seed_refresh {
                "seedRefreshRecovered"
            } else {
                "submissionRecovered"
            },
            json!({
                "transactionHash": hex_string(&mined.transaction_hash.to_bytes()),
                "succeeded": mined.succeeded,
                "feePaidWei": mined.fee_paid_wei.to_string(),
                "nftTokenId": mined.nft_token_id.map(uint256_to_decimal),
            }),
        )
    }

    fn standing(&self) -> Result<HuntStanding, String> {
        self.reader
            .hunt_standing(self.contracts, self.request.miner)
    }

    fn needs_stake(&self, standing: &HuntStanding) -> bool {
        hunt::stake_gate(standing.assigned, standing.unit, standing.mode) == hunt::StakeGate::Needed
    }

    /// Stake that only counts from the next round is reported once per challenge.
    fn report_pending_stake(
        &self,
        state: &mut HuntState,
        standing: &HuntStanding,
        challenge_id: Uint256,
    ) -> Result<(), String> {
        if hunt::stake_pending(&standing.preview, standing.assigned, standing.unit)
            && state.pending_reported != Some(challenge_id)
        {
            state.pending_reported = Some(challenge_id);
            self.writer.emit(
                "stakePending",
                json!({
                    "challengeId": uint256_to_decimal(challenge_id),
                    "message": hunt::STAKE_PENDING_MESSAGE,
                }),
            )?;
        }
        Ok(())
    }

    /// Reports a round that cannot be searched yet, once per (challenge, status),
    /// in neutral words: the loop is simply mining.
    fn announce(
        &self,
        state: &mut HuntState,
        marker: &ChallengeMarker,
        message: &'static str,
    ) -> Result<(), String> {
        let status = challenge_status_name(marker.status);
        if state.announced == Some((marker.challenge_id, status)) {
            return Ok(());
        }
        state.announced = Some((marker.challenge_id, status));
        self.writer.emit(
            "challengeUnavailable",
            json!({
                "challengeId": uint256_to_decimal(marker.challenge_id),
                "status": "waiting",
                "message": message,
            }),
        )
    }

    fn wait(&self, duration: Duration) -> Step {
        if wait_interruptibly(duration, self.shutdown) {
            Ok(None)
        } else {
            clean_stop(self.writer, self.book, "interrupt").map(Some)
        }
    }

    fn retry(&self, backoff: &mut RetryBackoff, error: String) -> Step {
        if rpc_retry(self.writer, self.shutdown, backoff, error)? {
            Ok(None)
        } else {
            clean_stop(self.writer, self.book, "interrupt").map(Some)
        }
    }

    fn failure(&self, backoff: &mut RetryBackoff, error: String) -> Step {
        if repeated_failure(self.writer, self.book, self.shutdown, backoff, error)? {
            failed_stop(self.writer, self.book).map(Some)
        } else {
            Ok(None)
        }
    }
}

/// What the challenge watcher needs to plan network upkeep during one search.
#[derive(Clone)]
struct UpkeepWatch {
    schedule: Arc<Mutex<upkeep::Schedule>>,
    wallet: Address,
    core: Address,
    router: Address,
    challenge_id: Uint256,
    fresh: bool,
    /// The pending-transaction journal: no upkeep is planned while it exists.
    journal: PathBuf,
}

impl UpkeepWatch {
    /// A due upkeep, or none. Runs at most one read-only simulation per call; a
    /// simulation that would succeed is scheduled after a random 0–30 s delay.
    fn tick(&self, reader: &RpcChainReader) -> Option<Due> {
        if self.journal.exists() {
            return None;
        }
        let now = Instant::now();
        let check = {
            let mut schedule = lock_schedule(&self.schedule);
            if let Some(due) = schedule.ready(self.challenge_id, now) {
                return Some(due);
            }
            schedule.next_check(self.challenge_id, self.fresh, now)
        };
        let kind = match check? {
            Check::Lock => {
                if reader.router_fixed(self.router) != Ok(false) {
                    return None;
                }
                UpkeepKind::Lock
            }
            Check::Ease => {
                let chain_now = reader.latest_timestamp().ok()?;
                let mut schedule = lock_schedule(&self.schedule);
                if !upkeep::ease_check_due(
                    chain_now,
                    schedule.ease_last_check,
                    schedule.ease_backoff_until,
                ) {
                    return None;
                }
                schedule.ease_last_check = Some(chain_now);
                UpkeepKind::Ease
            }
        };
        let to = match kind {
            UpkeepKind::Ease => self.core,
            UpkeepKind::Lock => self.router,
        };
        if reader.simulates(self.wallet, to, &kind.call_data()) == Ok(true) {
            let delay = upkeep::jitter(random_below(u64::MAX));
            lock_schedule(&self.schedule).schedule(kind, self.challenge_id, now, delay);
        }
        None
    }
}

fn lock_schedule(
    schedule: &Mutex<upkeep::Schedule>,
) -> std::sync::MutexGuard<'_, upkeep::Schedule> {
    schedule
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The nonce after `attempts` hashes from `start`, to resume a stopped search.
fn advance(start: Uint256, attempts: u128) -> Uint256 {
    start.wrapping_add(Uint256::from(attempts))
}

struct Found {
    marker: ChallengeMarker,
    nonce: Uint256,
    digest: proof_core::Digest,
    attempts: u128,
    threads: usize,
}

/// Emits the plain stake instruction and stops with exit code 4. Nothing was sent.
fn not_staked(
    writer: &EventWriter,
    standing: &HuntStanding,
    wallet: Address,
) -> Result<ContinuousResult, String> {
    writer.emit(
        "notStaked",
        json!({
            "wallet": hunt::checksum_address(wallet),
            "requiredStakeWei": uint256_to_decimal(standing.unit),
            "stakedWei": uint256_to_decimal(standing.assigned),
            "message": hunt::not_staked_message(standing.unit, wallet),
        }),
    )?;
    completion(writer, "notStaked", NOT_STAKED_EXIT_CODE)
}

/// Whole seconds from `now` until `later` (zero when `later` has passed).
fn seconds_between(now: Uint256, later: Uint256) -> u64 {
    if later <= now {
        return 0;
    }
    let low = |value: Uint256| {
        let bytes = value.to_be_bytes();
        if bytes[..24].iter().any(|byte| *byte != 0) {
            u64::MAX
        } else {
            u64::from_be_bytes(bytes[24..].try_into().expect("8 bytes"))
        }
    };
    low(later).saturating_sub(low(now))
}

fn random_below(bound: u64) -> u64 {
    use rand_core::{OsRng, RngCore};
    if bound == 0 {
        return 0;
    }
    OsRng.next_u64() % bound
}

fn unlock_wallet(request: &ContinuousRequest) -> Result<UnlockedWallet, String> {
    let source = request
        .passphrase_file
        .as_deref()
        .map_or(PassphraseSource::Prompt, PassphraseSource::File);
    let passphrase = read_passphrase(source, false)?;
    let wallet = unlock_keystore(&request.keystore, &passphrase)?;
    if parse_address(wallet.address(), "unlocked keystore miner address")? != request.miner {
        return Err("unlocked keystore mining address changed before the loop started".to_owned());
    }
    Ok(wallet)
}

fn watched_mine(
    request: &ContinuousRequest,
    challenge_inputs: &ChallengeInputs,
    target: Target,
    shutdown: &Arc<AtomicBool>,
) -> Result<WatchedMining, String> {
    let expected = ChallengeMarker {
        challenge_id: challenge_inputs.challenge_id,
        previous_accepted_digest: challenge_inputs.previous_accepted_digest,
        challenge: Some(proof_core::derive_challenge(challenge_inputs)),
        status: ChallengeStatus::Active,
        target: None,
    };
    watched_search(
        request,
        SearchSpec {
            challenge_inputs: *challenge_inputs,
            miner: request.miner,
            floor: None,
            target,
            start_nonce: request.start_nonce,
            recheck_at: None,
            upkeep: None,
        },
        expected,
        shutdown,
    )
}

/// One search and the proof it may produce.
struct SearchSpec {
    challenge_inputs: ChallengeInputs,
    miner: Address,
    floor: Option<Target>,
    target: Target,
    start_nonce: Uint256,
    /// Stop with `Recheck` at this moment even if the chain has not moved.
    recheck_at: Option<Instant>,
    /// Network upkeep checks run by the watcher during this search.
    upkeep: Option<UpkeepWatch>,
}

/// Searches until a proof, a change of the watched marker, an RPC failure or shutdown.
/// A marker with a target also stops the search when the core's target moves.
fn watched_search(
    request: &ContinuousRequest,
    spec: SearchSpec,
    expected: ChallengeMarker,
    shutdown: &Arc<AtomicBool>,
) -> Result<WatchedMining, String> {
    let control = MiningControl::new();
    let watcher_control = control.clone();
    let endpoint = request.endpoint.clone();
    let chain_id = request.chain_id;
    let mining_core = request.mining_core;
    let watch_target = expected.target.is_some();
    let watch_interval = request.watch_interval;
    let recheck_at = spec.recheck_at;
    let upkeep_watch = spec.upkeep.clone();
    let watcher_shutdown = Arc::clone(shutdown);
    let watcher = thread::Builder::new()
        .name("bproof-challenge-watcher".to_owned())
        .spawn(move || {
            let reader = RpcChainReader::new(endpoint, mining_core, chain_id);
            loop {
                if !wait_for_watch(watch_interval, &watcher_shutdown, &watcher_control) {
                    watcher_control.stop();
                    return WatchedMining::Mining(MiningResult::Abandoned {
                        attempts: 0,
                        threads: 0,
                    });
                }
                if recheck_at.is_some_and(|at| Instant::now() >= at) {
                    watcher_control.stop();
                    return WatchedMining::Recheck { attempts: 0 };
                }
                let current = if watch_target {
                    reader.read_challenge_marker_with_target()
                } else {
                    reader.read_challenge_marker()
                };
                match current {
                    Ok(current) if current != expected => {
                        watcher_control.stop();
                        return WatchedMining::ChallengeMoved(current);
                    }
                    Ok(_) => {}
                    Err(error) => {
                        watcher_control.stop();
                        return WatchedMining::RpcError(error);
                    }
                }
                if let Some(watch) = &upkeep_watch
                    && let Some(due) = watch.tick(&reader)
                {
                    watcher_control.stop();
                    return WatchedMining::Upkeep { due, attempts: 0 };
                }
            }
        })
        .map_err(|error| format!("failed to start challenge watcher: {error}"))?;

    let mining = mine_with_control(
        MiningRequest {
            challenge_inputs: spec.challenge_inputs,
            miner: spec.miner,
            floor: spec.floor,
            target: spec.target,
            start_nonce: spec.start_nonce,
            threads: request.threads,
            max_attempts: None,
        },
        control.clone(),
    );
    control.stop();
    let watched = watcher
        .join()
        .map_err(|_| "challenge watcher terminated unexpectedly".to_owned())?;
    match watched {
        WatchedMining::ChallengeMoved(_) | WatchedMining::RpcError(_) => Ok(watched),
        // A proof found in the same moment wins over a recheck or an upkeep: claims first.
        WatchedMining::Recheck { .. } | WatchedMining::Upkeep { .. } => {
            let mining = mining?;
            let attempts = match mining {
                MiningResult::Found { .. } => 0,
                MiningResult::Exhausted { attempts, .. }
                | MiningResult::Abandoned { attempts, .. } => attempts,
            };
            let upkeep_due = matches!(watched, WatchedMining::Upkeep { .. });
            match (
                upkeep::next_action(matches!(mining, MiningResult::Found { .. }), upkeep_due),
                watched,
            ) {
                (Next::Claim, _) => Ok(WatchedMining::Mining(mining)),
                (_, WatchedMining::Upkeep { due, .. }) => {
                    Ok(WatchedMining::Upkeep { due, attempts })
                }
                _ => Ok(WatchedMining::Recheck { attempts }),
            }
        }
        WatchedMining::Mining(_) => mining.map(WatchedMining::Mining),
    }
}

fn rpc_retry(
    writer: &EventWriter,
    shutdown: &Arc<AtomicBool>,
    backoff: &mut RetryBackoff,
    reason: String,
) -> Result<bool, String> {
    let delay = backoff.take();
    writer.emit(
        "rpcRetry",
        json!({
            "reason": reason,
            "retryDelayMs": delay.as_millis().to_string(),
        }),
    )?;
    Ok(wait_interruptibly(delay, shutdown))
}

fn repeated_failure(
    writer: &EventWriter,
    book: &LoopBook,
    shutdown: &Arc<AtomicBool>,
    backoff: &mut RetryBackoff,
    reason: String,
) -> Result<bool, String> {
    book.update(|summary| {
        summary.genuine_failures += 1;
        summary.consecutive_failures += 1;
    });
    let consecutive = book.snapshot().consecutive_failures;
    writer.emit(
        "failure",
        json!({
            "reason": reason,
            "consecutiveFailures": consecutive.to_string(),
            "failureLimit": FAILURE_LIMIT.to_string(),
        }),
    )?;
    if consecutive >= FAILURE_LIMIT {
        return Ok(true);
    }
    let delay = backoff.take();
    let _ = wait_interruptibly(delay, shutdown);
    Ok(false)
}

fn is_rpc_error(error: &str) -> bool {
    error.contains("JSON-RPC")
        || error.contains("RPC endpoint")
        || error.contains("transaction receipt")
}

/// A router that does not match the pinned one, or a miswired module, never heals by retrying.
fn is_permanent_mode_error(error: &str) -> bool {
    error.contains("refusing to mine")
}

fn is_permanent_identity_error(error: &str) -> bool {
    error.contains("wrong chain id")
        || error.contains("MiningCore address has no code")
        || error.contains("eth_getCode result")
}

fn wait_interruptibly(duration: Duration, shutdown: &AtomicBool) -> bool {
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        if shutdown.load(Ordering::Acquire) {
            return false;
        }
        thread::sleep((deadline - Instant::now()).min(INTERRUPT_POLL_INTERVAL));
    }
    !shutdown.load(Ordering::Acquire)
}

fn wait_for_watch(duration: Duration, shutdown: &AtomicBool, control: &MiningControl) -> bool {
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        if shutdown.load(Ordering::Acquire) || control.is_stopped() {
            return false;
        }
        thread::sleep((deadline - Instant::now()).min(INTERRUPT_POLL_INTERVAL));
    }
    !shutdown.load(Ordering::Acquire) && !control.is_stopped()
}

fn challenge_was_consumed(expected: &ChallengeMarker, current: &ChallengeMarker) -> bool {
    current.previous_accepted_digest != expected.previous_accepted_digest
}

fn record_challenge_move(book: &LoopBook, expected: &ChallengeMarker, current: &ChallengeMarker) {
    book.update(|summary| {
        summary.challenges_lost += u64::from(challenge_was_consumed(expected, current));
        summary.consecutive_failures = 0;
    });
}

fn record_fee_refusal(book: &LoopBook, classification: &ProofClassification) {
    book.update(|summary| {
        match classification {
            ProofClassification::ProofHunter => summary.proof_hunters_fee_refused += 1,
            ProofClassification::Ordinary => summary.ordinary_proofs_fee_refused += 1,
            ProofClassification::Unknown { .. } => {
                summary.unknown_classification_fee_refused += 1;
            }
        }
        summary.consecutive_failures = 0;
    });
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

fn challenge_status_name(status: ChallengeStatus) -> &'static str {
    match status {
        ChallengeStatus::WaitingForSeed => "waitingForSeed",
        ChallengeStatus::Active => "active",
        ChallengeStatus::Expired => "expired",
        ChallengeStatus::Ended => "ended",
        ChallengeStatus::Stopped => "stopped",
    }
}

fn start_summary_listener(writer: EventWriter, shutdown: Arc<AtomicBool>) -> Result<(), String> {
    thread::Builder::new()
        .name("bproof-summary-listener".to_owned())
        .spawn(move || {
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                if shutdown.load(Ordering::Acquire) {
                    break;
                }
                match line {
                    Ok(line) if line.trim() == "summary" => {
                        let _ = writer.emit("summary", json!({"reason": "requested"}));
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        })
        .map(drop)
        .map_err(|error| format!("failed to start summary listener: {error}"))
}

fn install_interrupt_handler(shutdown: Arc<AtomicBool>) -> Result<(), String> {
    ctrlc::set_handler(move || shutdown.store(true, Ordering::Release))
        .map_err(|error| format!("failed to install interrupt handler: {error}"))
}

fn fatal(
    writer: &EventWriter,
    book: &LoopBook,
    reason: String,
    exit_code: u8,
) -> Result<ContinuousResult, String> {
    book.update(|summary| {
        summary.genuine_failures += 1;
        summary.consecutive_failures += 1;
    });
    writer.emit("failure", json!({"reason": reason, "fatal": true}))?;
    completion(writer, "fatalFailure", exit_code)
}

fn clean_stop(
    writer: &EventWriter,
    _book: &LoopBook,
    reason: &'static str,
) -> Result<ContinuousResult, String> {
    completion(writer, reason, 0)
}

fn failed_stop(writer: &EventWriter, _book: &LoopBook) -> Result<ContinuousResult, String> {
    completion(writer, "repeatedFailure", 1)
}

fn completion(
    writer: &EventWriter,
    reason: &'static str,
    exit_code: u8,
) -> Result<ContinuousResult, String> {
    Ok(ContinuousResult {
        summary: writer.render_event("summary", json!({"reason": reason}))?,
        exit_code,
    })
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    use super::*;

    #[test]
    fn backoff_doubles_and_stays_capped() {
        let mut backoff = RetryBackoff::new(Duration::from_secs(1), Duration::from_secs(4));
        assert_eq!(backoff.take(), Duration::from_secs(1));
        assert_eq!(backoff.take(), Duration::from_secs(2));
        assert_eq!(backoff.take(), Duration::from_secs(4));
        assert_eq!(backoff.take(), Duration::from_secs(4));
    }

    #[test]
    fn normal_outcomes_clear_failures_without_incrementing_them() {
        let book = LoopBook::new();
        book.update(|summary| {
            summary.genuine_failures = 1;
            summary.consecutive_failures = 1;
        });
        let expected = ChallengeMarker {
            challenge_id: Uint256::ONE,
            previous_accepted_digest: proof_core::Digest::ZERO,
            challenge: Some(proof_core::Digest::from_bytes([1; 32])),
            status: ChallengeStatus::Active,
            target: None,
        };
        let consumed = ChallengeMarker {
            challenge_id: Uint256::from(2_u64),
            previous_accepted_digest: proof_core::Digest::from_bytes([2; 32]),
            challenge: None,
            status: ChallengeStatus::WaitingForSeed,
            target: None,
        };
        record_challenge_move(&book, &expected, &consumed);
        assert_eq!(book.snapshot().genuine_failures, 1);
        assert_eq!(book.snapshot().consecutive_failures, 0);
        assert_eq!(book.snapshot().challenges_lost, 1);

        record_fee_refusal(&book, &ProofClassification::Ordinary);
        assert_eq!(book.snapshot().genuine_failures, 1);
        assert_eq!(book.snapshot().ordinary_proofs_fee_refused, 1);
    }

    #[test]
    fn fee_refusal_counters_move_independently() {
        let book = LoopBook::new();
        record_fee_refusal(&book, &ProofClassification::Ordinary);
        record_fee_refusal(&book, &ProofClassification::ProofHunter);

        let counters = book.snapshot();
        assert_eq!(counters.ordinary_proofs_fee_refused, 1);
        assert_eq!(counters.proof_hunters_fee_refused, 1);
        assert_eq!(counters.unknown_classification_fee_refused, 0);

        record_fee_refusal(
            &book,
            &ProofClassification::Unknown {
                reason: "required getter failed".to_owned(),
            },
        );
        let counters = book.snapshot();
        assert_eq!(counters.ordinary_proofs_fee_refused, 1);
        assert_eq!(counters.proof_hunters_fee_refused, 1);
        assert_eq!(counters.unknown_classification_fee_refused, 1);
    }

    #[test]
    fn proof_hunter_fee_refusal_says_the_whole_reward_is_forfeited() {
        let quote = FeeQuote {
            base_fee_per_gas_wei: 10,
            priority_fee_per_gas_wei: 3,
            max_fee_per_gas_wei: 23,
            estimated_gas: 400,
            gas_margin_percent: 25,
            gas_limit: 500,
            maximum_exposure_wei: 11_500,
            fee_ceiling_wei: 10_000,
        };

        let hunter_reason = fee_refusal_reason(&quote, &ProofClassification::ProofHunter);
        let ordinary_reason = fee_refusal_reason(&quote, &ProofClassification::Ordinary);
        assert!(hunter_reason.contains("leaves this proof unsubmitted"));
        assert!(!ordinary_reason.contains("whole reward"));
        for forbidden in ["privateKey", "passphrase", "mnemonic", "backupPhrase"] {
            assert!(!hunter_reason.contains(forbidden));
        }
    }

    #[test]
    fn seed_refresh_abandons_work_without_counting_a_miner_race() {
        let book = LoopBook::new();
        let previous = proof_core::Digest::from_bytes([3; 32]);
        let expected = ChallengeMarker {
            challenge_id: Uint256::ONE,
            previous_accepted_digest: previous,
            challenge: Some(proof_core::Digest::from_bytes([1; 32])),
            status: ChallengeStatus::Active,
            target: None,
        };
        let refreshed = ChallengeMarker {
            challenge_id: Uint256::from(2_u64),
            previous_accepted_digest: previous,
            challenge: None,
            status: ChallengeStatus::WaitingForSeed,
            target: None,
        };
        record_challenge_move(&book, &expected, &refreshed);
        assert_eq!(book.snapshot().challenges_lost, 0);
        assert_eq!(book.snapshot().genuine_failures, 0);
    }

    #[test]
    fn summary_never_contains_secret_material() {
        let book = LoopBook::new();
        let writer = EventWriter {
            json: true,
            output_lock: Arc::new(Mutex::new(())),
            book,
        };
        let rendered = writer
            .render_event("summary", json!({"reason": "interrupt"}))
            .unwrap();
        for forbidden in ["privateKey", "passphrase", "mnemonic", "backupPhrase"] {
            assert!(!rendered.contains(forbidden));
        }
    }

    #[test]
    fn clean_completion_is_exit_zero_and_has_every_summary_field() {
        let book = LoopBook::new();
        let writer = EventWriter {
            json: true,
            output_lock: Arc::new(Mutex::new(())),
            book: book.clone(),
        };
        let completed = clean_stop(&writer, &book, "interrupt").unwrap();
        assert_eq!(completed.exit_code, 0);
        let value: Value = serde_json::from_str(&completed.summary).unwrap();
        assert_eq!(value["event"], "summary");
        assert_eq!(value["reason"], "interrupt");
        for key in [
            "proofsAccepted",
            "nftsEarned",
            "ordinaryProofsFeeRefused",
            "proofHuntersFeeRefused",
            "unknownClassificationFeeRefused",
            "challengesLost",
            "totalFeesPaidWei",
            "wallClockMs",
        ] {
            assert!(value["summary"].get(key).is_some(), "missing {key}");
        }
    }

    #[test]
    fn challenge_watcher_stops_a_live_search_when_the_chain_moves() {
        let (endpoint, server) = moved_challenge_server();
        let challenge_inputs = ChallengeInputs {
            chain_id: Uint256::from(31_337_u64),
            mining_core: Address::from_bytes([0x22; 20]),
            challenge_id: Uint256::ONE,
            previous_accepted_digest: proof_core::Digest::ZERO,
            seed_parent_block: Uint256::from(1_003_u64),
            seed_blockhash: proof_core::Digest::from_bytes([0x44; 32]),
        };
        let request = ContinuousRequest {
            endpoint,
            chain_id: challenge_inputs.chain_id,
            mining_core: challenge_inputs.mining_core,
            expected_router: None,
            no_upkeep: false,
            miner: Address::from_bytes([0x11; 20]),
            basket: Address::from_bytes([0x55; 20]),
            keystore: PathBuf::from("unused"),
            passphrase_file: None,
            fee_options: FeeOptions {
                fee_ceiling_wei: 1,
                base_fee_per_gas_override_wei: None,
                priority_fee_per_gas_override_wei: None,
                gas_margin_percent: 25,
            },
            threads: 2,
            start_nonce: Uint256::ZERO,
            watch_interval: Duration::from_millis(1),
        };
        let shutdown = Arc::new(AtomicBool::new(false));
        let result = watched_mine(
            &request,
            &challenge_inputs,
            Target::from_be_bytes([0; 32]),
            &shutdown,
        )
        .unwrap();
        server.join().unwrap();

        match result {
            WatchedMining::ChallengeMoved(marker) => {
                assert_eq!(marker.challenge_id, Uint256::from(2_u64));
                assert_eq!(marker.status, ChallengeStatus::WaitingForSeed);
                assert_ne!(
                    marker.previous_accepted_digest,
                    challenge_inputs.previous_accepted_digest
                );
            }
            _ => panic!("watcher must report the changed chain challenge"),
        }
    }

    fn moved_challenge_server() -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let responses = [
            json!({"jsonrpc":"2.0","id":1,"result":"0x10"}),
            json!({"jsonrpc":"2.0","id":1,"result":word_hex([0; 32])}),
            json!({"jsonrpc":"2.0","id":1,"result":word_hex({
                let mut word = [0_u8; 32];
                word[31] = 2;
                word
            })}),
            json!({"jsonrpc":"2.0","id":1,"result":word_hex([0x55; 32])}),
        ];
        let server = thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_http_request(&mut stream);
                let request: Value = serde_json::from_slice(&request).unwrap();
                assert!(matches!(
                    request["method"].as_str(),
                    Some("eth_blockNumber" | "eth_call")
                ));
                let body = response.to_string();
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
                stream.flush().unwrap();
            }
        });
        (endpoint, server)
    }

    fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 1_024];
        loop {
            let read = stream.read(&mut buffer).unwrap();
            assert!(read > 0);
            bytes.extend_from_slice(&buffer[..read]);
            let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
                continue;
            };
            let header_end = header_end + 4;
            let headers = std::str::from_utf8(&bytes[..header_end]).unwrap();
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(str::trim)
                        .map(str::parse::<usize>)
                })
                .unwrap()
                .unwrap();
            if bytes.len() >= header_end + content_length {
                return bytes[header_end..header_end + content_length].to_vec();
            }
        }
    }

    fn word_hex(bytes: [u8; 32]) -> String {
        hex_string(&bytes)
    }
}
