//! Network upkeep for continuous mining on the upgraded system, mirroring the app.
//!
//! Two optional, permissionless transactions keep the network moving:
//! - `ease`: the core's `easeDifficulty()` after a long stretch without proofs;
//! - `lock`: the router's `fixDraw()` on a round's first fresh challenge.
//!
//! Rules (the app's): only with the wallet's own stake, only in `--loop`, never while
//! a claim is being handled, each call simulated first and sent after a random 0–30 s
//! delay; `ease` is checked at most once per chain minute and backs off 45 minutes
//! (chain time) after a send; `lock` is sent at most once per challenge. Every send
//! goes through the journaled submit path, one at a time. Failures only log a
//! neutral line; they never stop mining.

use std::time::{Duration, Instant};

use proof_core::Uint256;

/// Upper bound of the random delay before an upkeep send.
pub const JITTER_MS: u64 = 30_000;
/// At most one `ease` simulation per this many seconds of chain time.
pub const EASE_CHECK_SECONDS: u64 = 60;
/// After an `ease` send, none for this long (chain time).
pub const EASE_BACKOFF_SECONDS: u64 = 45 * 60;
/// Wall-clock spacing between checks of the same kind.
pub const CHECK_INTERVAL: Duration = Duration::from_secs(60);

pub const NEUTRAL_SENT: &str = "Network upkeep transaction sent.";
pub const NEUTRAL_SKIPPED: &str = "Network upkeep skipped.";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpkeepKind {
    Ease,
    Lock,
}

impl UpkeepKind {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ease => "ease",
            Self::Lock => "lock",
        }
    }

    pub fn from_name(name: &str) -> Result<Self, String> {
        match name {
            "ease" => Ok(Self::Ease),
            "lock" => Ok(Self::Lock),
            _ => Err(format!("unknown upkeep kind {name}")),
        }
    }

    /// The exact calldata: `easeDifficulty()` on the core, `fixDraw()` on the router.
    #[must_use]
    pub fn call_data(self) -> Vec<u8> {
        crate::hunt::selector(match self {
            Self::Ease => "easeDifficulty()",
            Self::Lock => "fixDraw()",
        })
        .to_vec()
    }
}

/// Upkeep runs only when not switched off and the wallet holds its own stake.
#[must_use]
pub fn enabled(no_upkeep: bool, assigned: Uint256, unit: Uint256) -> bool {
    !no_upkeep && assigned >= unit
}

/// A send is allowed only when no claim is being handled and no earlier transaction
/// is still unresolved in the journal (so two transactions never share a nonce).
#[must_use]
pub const fn may_send(claim_in_flight: bool, journal_pending: bool) -> bool {
    !claim_in_flight && !journal_pending
}

/// `ease` may be simulated at `chain_now`: at most once per chain minute, and not
/// while backing off after a send.
#[must_use]
pub fn ease_check_due(chain_now: u64, last_check: Option<u64>, backoff_until: Option<u64>) -> bool {
    if backoff_until.is_some_and(|until| chain_now < until) {
        return false;
    }
    last_check.is_none_or(|last| chain_now.saturating_sub(last) >= EASE_CHECK_SECONDS)
}

/// The chain time until which no further `ease` is sent.
#[must_use]
pub const fn ease_backoff_after(chain_now: u64) -> u64 {
    chain_now.saturating_add(EASE_BACKOFF_SECONDS)
}

/// `lock` is worth simulating on a fresh challenge whose result is not fixed yet,
/// and only if this wallet has not already sent it for that challenge.
#[must_use]
pub fn lock_candidate(
    fresh: bool,
    fixed: bool,
    sent_for: Option<Uint256>,
    challenge: Uint256,
) -> bool {
    fresh && !fixed && sent_for != Some(challenge)
}

/// A random delay in `[0, JITTER_MS]` from a uniform `random` word.
#[must_use]
pub const fn jitter(random: u64) -> Duration {
    Duration::from_millis(random % (JITTER_MS + 1))
}

/// What to do when a search stops with both a proof and a due upkeep: the claim wins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Next {
    Claim,
    Upkeep,
    Continue,
}

#[must_use]
pub const fn next_action(proof_found: bool, upkeep_due: bool) -> Next {
    if proof_found {
        Next::Claim
    } else if upkeep_due {
        Next::Upkeep
    } else {
        Next::Continue
    }
}

/// A simulated upkeep waiting for its random delay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Due {
    pub kind: UpkeepKind,
    pub challenge_id: Uint256,
    pub at: Instant,
}

/// Upkeep bookkeeping shared by the loop and its challenge watcher.
#[derive(Debug, Default)]
pub struct Schedule {
    pub due: Option<Due>,
    pub lock_sent_for: Option<Uint256>,
    pub lock_next_check: Option<(Uint256, Instant)>,
    pub ease_next_check: Option<Instant>,
    pub ease_last_check: Option<u64>,
    pub ease_backoff_until: Option<u64>,
}

/// Which simulation, if any, the watcher should run now.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Check {
    Lock,
    Ease,
}

impl Schedule {
    /// A due upkeep for `challenge_id` whose delay has passed. Stale entries are dropped.
    pub fn ready(&mut self, challenge_id: Uint256, now: Instant) -> Option<Due> {
        match self.due {
            Some(due) if due.challenge_id != challenge_id => {
                self.due = None;
                None
            }
            Some(due) if due.at <= now => Some(due),
            _ => None,
        }
    }

    /// The next check to run, spaced by `CHECK_INTERVAL`; none while one is waiting.
    pub fn next_check(
        &mut self,
        challenge_id: Uint256,
        fresh: bool,
        now: Instant,
    ) -> Option<Check> {
        if self.due.is_some() {
            return None;
        }
        let lock_waiting = self
            .lock_next_check
            .is_some_and(|(challenge, at)| challenge == challenge_id && now < at);
        if lock_candidate(fresh, false, self.lock_sent_for, challenge_id) && !lock_waiting {
            self.lock_next_check = Some((challenge_id, now + CHECK_INTERVAL));
            return Some(Check::Lock);
        }
        if self.ease_next_check.is_none_or(|at| now >= at) {
            self.ease_next_check = Some(now + CHECK_INTERVAL);
            return Some(Check::Ease);
        }
        None
    }

    /// Records a simulation that would succeed: send after `delay`.
    pub fn schedule(
        &mut self,
        kind: UpkeepKind,
        challenge_id: Uint256,
        now: Instant,
        delay: Duration,
    ) {
        self.due = Some(Due {
            kind,
            challenge_id,
            at: now + delay,
        });
    }

    /// Records a send (or a decision not to send) for `due`.
    pub fn finish(&mut self, due: Due, sent: bool, chain_now: u64) {
        self.due = None;
        if sent {
            match due.kind {
                UpkeepKind::Lock => self.lock_sent_for = Some(due.challenge_id),
                UpkeepKind::Ease => self.ease_backoff_until = Some(ease_backoff_after(chain_now)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNIT: u128 = 1_000_000 * 1_000_000_000_000_000_000;

    #[test]
    fn upkeep_needs_the_wallets_own_stake_and_can_be_switched_off() {
        let unit = Uint256::from(UNIT);
        assert!(enabled(false, unit, unit));
        assert!(enabled(false, Uint256::from(UNIT * 2), unit));
        assert!(!enabled(false, Uint256::from(UNIT - 1), unit));
        assert!(!enabled(false, Uint256::ZERO, unit));
        assert!(!enabled(true, unit, unit), "--no-upkeep turns it off");
    }

    #[test]
    fn claims_take_priority_and_one_transaction_at_a_time() {
        assert_eq!(next_action(true, true), Next::Claim);
        assert_eq!(next_action(true, false), Next::Claim);
        assert_eq!(next_action(false, true), Next::Upkeep);
        assert_eq!(next_action(false, false), Next::Continue);
        assert!(may_send(false, false));
        assert!(!may_send(true, false), "never while a claim is in flight");
        assert!(
            !may_send(false, true),
            "never while an earlier transaction is unresolved"
        );
    }

    #[test]
    fn jitter_stays_within_thirty_seconds() {
        assert_eq!(jitter(0), Duration::ZERO);
        assert_eq!(jitter(JITTER_MS), Duration::from_millis(JITTER_MS));
        assert_eq!(jitter(JITTER_MS + 1), Duration::ZERO);
        for random in [1, 12_345, u64::MAX, u64::MAX / 3, 987_654_321_012] {
            assert!(jitter(random) <= Duration::from_secs(30));
        }
    }

    #[test]
    fn ease_is_checked_once_per_chain_minute_and_backs_off_45_minutes_after_a_send() {
        assert!(ease_check_due(1_000, None, None));
        assert!(!ease_check_due(1_059, Some(1_000), None));
        assert!(ease_check_due(1_060, Some(1_000), None));
        let until = ease_backoff_after(1_000);
        assert_eq!(until, 1_000 + 2_700);
        assert!(!ease_check_due(1_000 + 120, None, Some(until)));
        assert!(!ease_check_due(until - 1, Some(1_000), Some(until)));
        assert!(ease_check_due(until, Some(1_000), Some(until)));

        let mut schedule = Schedule::default();
        let now = Instant::now();
        let due = Due {
            kind: UpkeepKind::Ease,
            challenge_id: Uint256::ONE,
            at: now,
        };
        schedule.due = Some(due);
        schedule.finish(due, true, 5_000);
        assert_eq!(schedule.ease_backoff_until, Some(5_000 + 2_700));
        assert!(schedule.due.is_none());
        // A skipped ease sets no backoff.
        let mut skipped = Schedule::default();
        skipped.finish(due, false, 5_000);
        assert_eq!(skipped.ease_backoff_until, None);
    }

    #[test]
    fn lock_is_sent_at_most_once_per_challenge() {
        let one = Uint256::ONE;
        let two = Uint256::from(2_u64);
        assert!(lock_candidate(true, false, None, one));
        assert!(
            !lock_candidate(false, false, None, one),
            "only a fresh challenge"
        );
        assert!(!lock_candidate(true, true, None, one), "not once fixed");
        assert!(
            !lock_candidate(true, false, Some(one), one),
            "once per challenge"
        );
        assert!(lock_candidate(true, false, Some(one), two));

        let mut schedule = Schedule::default();
        let now = Instant::now();
        assert_eq!(schedule.next_check(one, true, now), Some(Check::Lock));
        // The next lock check waits a minute; ease is checked meanwhile.
        assert_eq!(schedule.next_check(one, true, now), Some(Check::Ease));
        assert_eq!(schedule.next_check(one, true, now), None);
        schedule.schedule(UpkeepKind::Lock, one, now, Duration::from_millis(10));
        assert_eq!(
            schedule.next_check(one, true, now + CHECK_INTERVAL),
            None,
            "one at a time"
        );
        assert_eq!(schedule.ready(one, now), None, "waits for its delay");
        let due = schedule
            .ready(one, now + Duration::from_millis(10))
            .unwrap();
        schedule.finish(due, true, 0);
        assert_eq!(schedule.lock_sent_for, Some(one));
        let later = now + CHECK_INTERVAL * 2;
        assert_eq!(schedule.next_check(one, true, later), Some(Check::Ease));
        assert_eq!(schedule.next_check(two, true, later), Some(Check::Lock));
        // A due upkeep for an older challenge is dropped.
        schedule.schedule(UpkeepKind::Lock, one, now, Duration::ZERO);
        assert_eq!(schedule.ready(two, later), None);
        assert!(schedule.due.is_none());
    }

    #[test]
    fn upkeep_calldata_and_names_are_exact_and_neutral() {
        assert_eq!(UpkeepKind::Ease.call_data(), vec![0x08, 0x7e, 0x5b, 0x63]);
        assert_eq!(
            UpkeepKind::Lock.call_data(),
            crate::hunt::selector("fixDraw()").to_vec()
        );
        for kind in [UpkeepKind::Ease, UpkeepKind::Lock] {
            assert_eq!(UpkeepKind::from_name(kind.name()).unwrap(), kind);
        }
        assert!(UpkeepKind::from_name("draw").is_err());
        for text in [NEUTRAL_SENT, NEUTRAL_SKIPPED, UpkeepKind::Lock.name()] {
            let lower = text.to_lowercase();
            for forbidden in ["draw", "tier", "party", "hunt", "chance", "difficulty"] {
                assert!(!lower.contains(forbidden), "{text}");
            }
        }
    }
}
