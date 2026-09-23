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

use crate::chain::{CHAIN_STATE_SOURCE, ChallengeMarker, ChallengeStatus, RpcChainReader};
use crate::classification::{ProofClassification, classify_proof};
use crate::mining::{MiningControl, MiningRequest, MiningResult, mine_with_control};
use crate::parse::{hex_string, parse_address, uint256_to_decimal};
use crate::submit::{
    FeeOptions, FeeQuote, PROOF_HUNTER_FEE_WARNING, PreparationOutcome, SUBMISSION_WARNING,
    prepare_seed_refresh, prepare_submission, recover_pending_submission, send_prepared_submission,
};

pub const DEFAULT_WATCH_INTERVAL: Duration = Duration::from_millis(1_000);
const RPC_BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const RPC_BACKOFF_CAP: Duration = Duration::from_secs(30);
const FAILURE_LIMIT: u64 = 3;
const INTERRUPT_POLL_INTERVAL: Duration = Duration::from_millis(25);

pub struct ContinuousRequest {
    pub endpoint: String,
    pub chain_id: Uint256,
    pub mining_core: Address,
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
            if recovered.mined.succeeded && !recovered.mined.seed_refresh {
                book.update(|summary| {
                    summary.proofs_accepted += 1;
                    summary.nfts_earned += u64::from(recovered.mined.proof_nft_minted);
                    summary.consecutive_failures = 0;
                });
            }
            writer.emit(
                if recovered.mined.seed_refresh {
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
    let wallet = match unlock_wallet(&request) {
        Ok(wallet) => wallet,
        Err(error) => return fatal(&writer, &book, error, 2),
    };
    if let Err(error) = start_summary_listener(writer.clone(), Arc::clone(&shutdown)) {
        return fatal(&writer, &book, error, 2);
    }

    loop {
        if shutdown.load(Ordering::Acquire) {
            return clean_stop(&writer, &book, "interrupt");
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
    let control = MiningControl::new();
    let watcher_control = control.clone();
    let endpoint = request.endpoint.clone();
    let chain_id = request.chain_id;
    let mining_core = request.mining_core;
    let expected = ChallengeMarker {
        challenge_id: challenge_inputs.challenge_id,
        previous_accepted_digest: challenge_inputs.previous_accepted_digest,
        challenge: Some(proof_core::derive_challenge(challenge_inputs)),
        status: ChallengeStatus::Active,
    };
    let watch_interval = request.watch_interval;
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
                match reader.read_challenge_marker() {
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
            }
        })
        .map_err(|error| format!("failed to start challenge watcher: {error}"))?;

    let mining = mine_with_control(
        MiningRequest {
            challenge_inputs: *challenge_inputs,
            miner: request.miner,
            target,
            start_nonce: request.start_nonce,
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
        };
        let consumed = ChallengeMarker {
            challenge_id: Uint256::from(2_u64),
            previous_accepted_digest: proof_core::Digest::from_bytes([2; 32]),
            challenge: None,
            status: ChallengeStatus::WaitingForSeed,
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
        };
        let refreshed = ChallengeMarker {
            challenge_id: Uint256::from(2_u64),
            previous_accepted_digest: previous,
            challenge: None,
            status: ChallengeStatus::WaitingForSeed,
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
