//! Fixed-batch multi-threaded orchestration over proof-core's search engine.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver, Sender},
};
use std::thread::{self, JoinHandle};

use proof_core::{Address, ChallengeInputs, Digest, SearchResult, Target, Uint256, search_nonce};

// Keep cancellation responsive without forcing every worker through the
// coordinator after only a few hundred hashes.  The smaller batch left most
// VPS cores waiting on channels during realistic RC2 searches.
const ATTEMPT_BATCH: u64 = 16 * 1024;

/// Cancellation shared by the challenge watcher and every search worker.
#[derive(Clone, Debug, Default)]
pub struct MiningControl {
    stop: Arc<AtomicBool>,
}

impl MiningControl {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }
}

/// Inputs for one local mining run.
pub struct MiningRequest {
    pub challenge_inputs: ChallengeInputs,
    pub miner: Address,
    pub target: Target,
    pub start_nonce: Uint256,
    pub threads: usize,
    pub max_attempts: Option<u64>,
}

/// The aggregate result across all stride workers.
#[derive(Debug, Eq, PartialEq)]
pub enum MiningResult {
    Found {
        mining_nonce: Uint256,
        digest: Digest,
        attempts: u128,
        threads: usize,
    },
    Exhausted {
        attempts: u128,
        threads: usize,
    },
    Abandoned {
        attempts: u128,
        threads: usize,
    },
}

enum WorkerCommand {
    Search(u64),
    Stop,
}

struct WorkerReport {
    worker_id: usize,
    result: SearchResult,
}

struct WorkerSlot {
    worker_id: usize,
    remaining: Option<u64>,
    commands: Sender<WorkerCommand>,
    handle: JoinHandle<()>,
}

struct WorkerContext {
    step: Uint256,
    challenge_inputs: ChallengeInputs,
    miner: Address,
    target: Target,
    stop: Arc<AtomicBool>,
    reports: Sender<WorkerReport>,
}

/// Mines with deterministic stride partitions and a total shared attempt cap.
pub fn mine(request: MiningRequest) -> Result<MiningResult, String> {
    mine_with_control(request, MiningControl::new())
}

/// Mines until a proof, the attempt cap, or an external watcher stops the work.
pub fn mine_with_control(
    request: MiningRequest,
    control: MiningControl,
) -> Result<MiningResult, String> {
    if request.threads == 0 {
        return Err("thread count must be at least 1".to_owned());
    }

    let thread_count = u64::try_from(request.threads)
        .map_err(|_| "thread count exceeds the supported u64 range".to_owned())?;
    let step = Uint256::from(thread_count);

    if request.max_attempts == Some(0) {
        return Ok(MiningResult::Exhausted {
            attempts: 0,
            threads: request.threads,
        });
    }

    if control.is_stopped() {
        return Ok(MiningResult::Abandoned {
            attempts: 0,
            threads: request.threads,
        });
    }

    let first = search_nonce(
        request.challenge_inputs,
        request.miner,
        request.target,
        request.start_nonce,
        step,
        1,
    );
    if let SearchResult::Found {
        nonce,
        digest,
        attempts,
    } = first
    {
        if control.is_stopped() {
            return Ok(MiningResult::Abandoned {
                attempts: u128::from(attempts),
                threads: request.threads,
            });
        }
        return Ok(MiningResult::Found {
            mining_nonce: nonce,
            digest,
            attempts: u128::from(attempts),
            threads: request.threads,
        });
    }

    if control.is_stopped() {
        return Ok(MiningResult::Abandoned {
            attempts: 1,
            threads: request.threads,
        });
    }

    let stop = Arc::clone(&control.stop);
    let (reports_tx, reports_rx) = mpsc::channel();
    let mut workers = Vec::new();

    for worker_id in 0..request.threads {
        let worker_id_u64 = u64::try_from(worker_id)
            .map_err(|_| "worker index exceeds the supported u64 range".to_owned())?;
        let remaining = request
            .max_attempts
            .map(|total| worker_budget(total, thread_count, worker_id_u64));
        if remaining == Some(0) {
            continue;
        }

        let worker_start = if worker_id == 0 {
            request.start_nonce.wrapping_add(step)
        } else {
            request
                .start_nonce
                .wrapping_add(Uint256::from(worker_id_u64))
        };
        match spawn_worker(
            worker_id,
            remaining,
            worker_start,
            WorkerContext {
                step,
                challenge_inputs: request.challenge_inputs,
                miner: request.miner,
                target: request.target,
                stop: Arc::clone(&stop),
                reports: reports_tx.clone(),
            },
        ) {
            Ok(worker) => workers.push(worker),
            Err(error) => {
                shutdown(workers, &stop);
                return Err(error);
            }
        }
    }
    drop(reports_tx);

    let run_result = coordinate_batches(&mut workers, &reports_rx, &stop, request.threads, 1);
    let worker_panicked = shutdown(workers, &stop);
    if worker_panicked {
        return Err("a mining worker terminated unexpectedly".to_owned());
    }

    run_result
}

fn spawn_worker(
    worker_id: usize,
    remaining: Option<u64>,
    start_nonce: Uint256,
    context: WorkerContext,
) -> Result<WorkerSlot, String> {
    let (commands_tx, commands_rx) = mpsc::channel();
    let handle = thread::Builder::new()
        .name(format!("bproof-mine-{worker_id}"))
        .spawn(move || {
            worker_loop(worker_id, start_nonce, &context, &commands_rx);
        })
        .map_err(|error| format!("failed to start mining worker {worker_id}: {error}"))?;

    Ok(WorkerSlot {
        worker_id,
        remaining,
        commands: commands_tx,
        handle,
    })
}

fn worker_loop(
    worker_id: usize,
    mut next_nonce: Uint256,
    context: &WorkerContext,
    commands: &Receiver<WorkerCommand>,
) {
    loop {
        if context.stop.load(Ordering::Acquire) {
            break;
        }

        match commands.recv() {
            Ok(WorkerCommand::Search(budget)) => {
                let result = search_nonce(
                    context.challenge_inputs,
                    context.miner,
                    context.target,
                    next_nonce,
                    context.step,
                    budget,
                );
                if let SearchResult::Exhausted { attempts } = result {
                    for _ in 0..attempts {
                        next_nonce = next_nonce.wrapping_add(context.step);
                    }
                }
                if context
                    .reports
                    .send(WorkerReport { worker_id, result })
                    .is_err()
                {
                    break;
                }
            }
            Ok(WorkerCommand::Stop) | Err(_) => break,
        }
    }
}

fn coordinate_batches(
    workers: &mut [WorkerSlot],
    reports: &Receiver<WorkerReport>,
    stop: &AtomicBool,
    configured_threads: usize,
    initial_attempts: u128,
) -> Result<MiningResult, String> {
    let mut total_attempts = initial_attempts;

    loop {
        if stop.load(Ordering::Acquire) {
            return Ok(MiningResult::Abandoned {
                attempts: total_attempts,
                threads: configured_threads,
            });
        }

        let mut active_workers = Vec::new();
        for worker in workers.iter() {
            let budget = worker
                .remaining
                .map_or(ATTEMPT_BATCH, |remaining| remaining.min(ATTEMPT_BATCH));
            if budget == 0 {
                continue;
            }
            worker
                .commands
                .send(WorkerCommand::Search(budget))
                .map_err(|_| format!("mining worker {} stopped early", worker.worker_id))?;
            active_workers.push(worker.worker_id);
        }

        if active_workers.is_empty() {
            return Ok(MiningResult::Exhausted {
                attempts: total_attempts,
                threads: configured_threads,
            });
        }

        let mut winners = Vec::new();
        for _ in 0..active_workers.len() {
            let report = reports
                .recv()
                .map_err(|_| "a mining worker stopped before reporting its batch".to_owned())?;
            let worker = workers
                .iter_mut()
                .find(|worker| worker.worker_id == report.worker_id)
                .ok_or_else(|| format!("unknown mining worker {}", report.worker_id))?;
            let attempts = match report.result {
                SearchResult::Found {
                    nonce,
                    digest,
                    attempts,
                } => {
                    winners.push((nonce, digest));
                    attempts
                }
                SearchResult::Exhausted { attempts } => attempts,
            };
            total_attempts = total_attempts
                .checked_add(u128::from(attempts))
                .ok_or_else(|| {
                    "total attempt count exceeded the supported u128 range".to_owned()
                })?;
            if let Some(remaining) = &mut worker.remaining {
                *remaining = remaining
                    .checked_sub(attempts)
                    .ok_or_else(|| "a mining worker exceeded its attempt budget".to_owned())?;
            }
        }

        if stop.load(Ordering::Acquire) {
            return Ok(MiningResult::Abandoned {
                attempts: total_attempts,
                threads: configured_threads,
            });
        }

        if let Some((nonce, digest)) = winners.into_iter().min_by_key(|winner| winner.0) {
            stop.store(true, Ordering::Release);
            return Ok(MiningResult::Found {
                mining_nonce: nonce,
                digest,
                attempts: total_attempts,
                threads: configured_threads,
            });
        }
    }
}

fn worker_budget(total_attempts: u64, threads: u64, worker_id: u64) -> u64 {
    let last_index = total_attempts - 1;
    if worker_id == 0 {
        last_index / threads
    } else if worker_id > last_index {
        0
    } else {
        1 + (last_index - worker_id) / threads
    }
}

fn shutdown(workers: Vec<WorkerSlot>, stop: &AtomicBool) -> bool {
    stop.store(true, Ordering::Release);
    for worker in &workers {
        let _ = worker.commands.send(WorkerCommand::Stop);
    }

    let mut worker_panicked = false;
    for worker in workers {
        worker_panicked |= worker.handle.join().is_err();
    }
    worker_panicked
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn challenge(challenge_id: u64) -> ChallengeInputs {
        ChallengeInputs {
            chain_id: Uint256::from(31_337_u64),
            mining_core: Address::from_bytes([0x22; 20]),
            challenge_id: Uint256::from(challenge_id),
            previous_accepted_digest: Digest::from_bytes([0x33; 32]),
            seed_parent_block: Uint256::from(1_003_u64 + challenge_id),
            seed_blockhash: Digest::from_bytes([0x44; 32]),
        }
    }

    #[test]
    fn watcher_abandons_stale_work_and_a_new_challenge_can_start() {
        let control = MiningControl::new();
        let watcher_control = control.clone();
        let watcher = thread::spawn(move || {
            thread::sleep(Duration::from_millis(10));
            watcher_control.stop();
        });
        let stale = mine_with_control(
            MiningRequest {
                challenge_inputs: challenge(1),
                miner: Address::from_bytes([0x11; 20]),
                target: Target::from_be_bytes([0; 32]),
                start_nonce: Uint256::ZERO,
                threads: 2,
                max_attempts: None,
            },
            control,
        )
        .unwrap();
        watcher.join().unwrap();
        assert!(matches!(stale, MiningResult::Abandoned { attempts, .. } if attempts > 0));

        let current = mine(MiningRequest {
            challenge_inputs: challenge(2),
            miner: Address::from_bytes([0x11; 20]),
            target: Target::from_be_bytes([0xff; 32]),
            start_nonce: Uint256::ZERO,
            threads: 2,
            max_attempts: None,
        })
        .unwrap();
        assert!(matches!(
            current,
            MiningResult::Found {
                mining_nonce,
                ..
            } if mining_nonce == Uint256::ZERO
        ));
    }
}
