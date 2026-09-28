//! Mining v2 helpers: stake eligibility, router claims and digest bands.
//!
//! When the core's Mining Power module is HuntStake, a proof is accepted only
//! through HuntRouter.claim(hunter, nonce, basket), sent by the hunter wallet.
//! The core then sees the router as the miner, so the digest is derived with
//! the router's address, the nonce carries the hunter in its top 160 bits,
//! and the digest must fall inside the band the router reports. Everything
//! here is pure; RPC reads live in `chain.rs`.
//!
//! User-facing wording is deliberately neutral: messages talk about mining,
//! stake and rounds only.

use proof_core::{
    Address, ChallengeInputs, Digest, ProofInputs, Target, Uint256, derive_challenge, keccak256,
    proof_digest,
};

use crate::parse::{hex_string, uint256_to_decimal};

pub const TIER_COMMON: u8 = 1;
pub const TIER_UNCOMMON: u8 = 2;
pub const TIER_RARE: u8 = 3;
pub const TIER_LEGENDARY: u8 = 4;

const TIER_DENOMINATOR: u64 = 1_000;
const LEGENDARY_NUMERATOR: u64 = 10;
const RARE_NUMERATOR: u64 = 80;
const UNCOMMON_NUMERATOR: u64 = 300;
const TIER_DOMAIN: &[u8] = b"proof-hunters/tier";

/// `preview(wallet)` reason codes, exactly as HuntStake returns them: 0 OK,
/// 1 not attached, 2 not open yet, 3 not fresh, 4 not enough matured stake,
/// 5 not selected, 6 no active challenge, 7 open to every wallet.
pub const REASON_OK: u8 = 0;
pub const REASON_NOT_ENOUGH_STAKE: u8 = 4;
pub const REASON_OPEN_MODE: u8 = 7;

/// HuntStake `mode()`: 0 normal, 1 fail-open, 2 pass-through.
pub const MODE_NORMAL: u8 = 0;

/// Where a wallet is staked. Printed in the not-staked message.
pub const STAKE_APP_URL: &str = "app.proofhunter.fun/app/mine";

const NONCE_HUNTER_BYTES: usize = 20;
const WAD: u128 = 1_000_000_000_000_000_000;

/// The first four bytes of `keccak256(signature)`.
#[must_use]
pub fn selector(signature: &str) -> [u8; 4] {
    let hash = keccak256(signature.as_bytes()).to_bytes();
    [hash[0], hash[1], hash[2], hash[3]]
}

// ------------------------------------------------------------------ tiers and bands

/// The tier the chain draws for `challenge`: keccak256(challenge ‖ keccak256("proof-hunters/tier")) mod 1000.
#[must_use]
pub fn drawn_tier(challenge: Digest) -> u8 {
    let mut preimage = [0_u8; 64];
    preimage[..32].copy_from_slice(&challenge.to_bytes());
    preimage[32..].copy_from_slice(&keccak256(TIER_DOMAIN).to_bytes());
    let draw = mod_small(keccak256(&preimage).to_bytes(), TIER_DENOMINATOR);
    if draw < LEGENDARY_NUMERATOR {
        TIER_LEGENDARY
    } else if draw < RARE_NUMERATOR {
        TIER_RARE
    } else if draw < UNCOMMON_NUMERATOR {
        TIER_UNCOMMON
    } else {
        TIER_COMMON
    }
}

/// The inclusive upper cuts (legendary, rare, uncommon) at `target`, floor division.
#[must_use]
pub fn tier_cuts(target: Target) -> (Uint256, Uint256, Uint256) {
    let cut = |numerator| {
        Uint256::from_be_bytes(
            crate::power::mul_div(target.to_be_bytes(), numerator, TIER_DENOMINATOR)
                .expect("a fraction below one of a uint256 fits a uint256"),
        )
    };
    (
        cut(LEGENDARY_NUMERATOR),
        cut(RARE_NUMERATOR),
        cut(UNCOMMON_NUMERATOR),
    )
}

/// The tier the core gives `digest` at `target`; 0 when the digest is not a valid proof.
#[cfg(test)]
#[must_use]
pub fn tier_of(digest: Digest, target: Target) -> u8 {
    let value = Uint256::from_be_bytes(digest.to_bytes());
    if value > Uint256::from_be_bytes(target.to_be_bytes()) {
        return 0;
    }
    let (legendary, rare, uncommon) = tier_cuts(target);
    if value <= legendary {
        TIER_LEGENDARY
    } else if value <= rare {
        TIER_RARE
    } else if value <= uncommon {
        TIER_UNCOMMON
    } else {
        TIER_COMMON
    }
}

/// A digest band: `low < digest <= high`; the top tier's band also includes 0.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Band {
    pub tier: u8,
    pub low: Uint256,
    pub high: Uint256,
}

impl Band {
    /// The band for `tier` at `target`, exactly as the router computes it.
    #[must_use]
    pub fn at(target: Target, tier: u8) -> Option<Self> {
        let (legendary, rare, uncommon) = tier_cuts(target);
        let top = Uint256::from_be_bytes(target.to_be_bytes());
        let (low, high) = match tier {
            TIER_LEGENDARY => (Uint256::ZERO, legendary),
            TIER_RARE => (legendary, rare),
            TIER_UNCOMMON => (rare, uncommon),
            TIER_COMMON => (uncommon, top),
            _ => return None,
        };
        Some(Self { tier, low, high })
    }

    #[must_use]
    pub fn contains(&self, digest: Digest) -> bool {
        let value = Uint256::from_be_bytes(digest.to_bytes());
        if self.tier == TIER_LEGENDARY && value == Uint256::ZERO {
            return true;
        }
        value > self.low && value <= self.high
    }

    /// The search target (inclusive upper bound).
    #[must_use]
    pub fn search_target(&self) -> Target {
        Target::from_be_bytes(self.high.to_be_bytes())
    }

    /// The search floor (exclusive lower bound); none for the top tier, whose band starts at 0.
    #[must_use]
    pub fn search_floor(&self) -> Option<Target> {
        (self.tier != TIER_LEGENDARY).then(|| Target::from_be_bytes(self.low.to_be_bytes()))
    }
}

fn mod_small(bytes: [u8; 32], modulus: u64) -> u64 {
    bytes.iter().fold(0_u64, |remainder, byte| {
        (remainder * 256 + u64::from(*byte)) % modulus
    })
}

// ------------------------------------------------------------------ bound nonces and digests

/// The first nonce for `hunter`: `uint256(hunter) << 96`.
#[must_use]
pub fn nonce_base(hunter: Address) -> Uint256 {
    let mut bytes = [0_u8; 32];
    bytes[..NONCE_HUNTER_BYTES].copy_from_slice(&hunter.to_bytes());
    Uint256::from_be_bytes(bytes)
}

/// `hunter << 96 | counter`; the counter must fit the low 96 bits.
pub fn bound_nonce(hunter: Address, counter: Uint256) -> Result<Uint256, String> {
    let counter = counter.to_be_bytes();
    if counter[..NONCE_HUNTER_BYTES].iter().any(|byte| *byte != 0) {
        return Err("the start nonce must fit in 96 bits on this network".to_owned());
    }
    let mut bytes = nonce_base(hunter).to_be_bytes();
    bytes[NONCE_HUNTER_BYTES..].copy_from_slice(&counter[NONCE_HUNTER_BYTES..]);
    Ok(Uint256::from_be_bytes(bytes))
}

/// True when the nonce's top 160 bits are `hunter` (what the router checks).
#[must_use]
pub fn is_bound_nonce(nonce: Uint256, hunter: Address) -> bool {
    nonce.to_be_bytes()[..NONCE_HUNTER_BYTES] == hunter.to_bytes()
}

/// The digest the core derives for a router claim: the router is the core's miner.
#[must_use]
pub fn router_digest(inputs: &ChallengeInputs, router: Address, nonce: Uint256) -> Digest {
    proof_digest(&ProofInputs {
        chain_id: inputs.chain_id,
        mining_core: inputs.mining_core,
        challenge_id: inputs.challenge_id,
        challenge: derive_challenge(inputs),
        miner: router,
        nonce,
    })
}

/// Calldata for `HuntRouter.claim(address hunter, uint256 nonce, address basket)`.
#[must_use]
pub fn claim_call_data(hunter: Address, nonce: Uint256, basket: Address) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 32 * 3);
    data.extend_from_slice(&selector("claim(address,uint256,address)"));
    data.extend_from_slice(&address_word(hunter));
    data.extend_from_slice(&nonce.to_be_bytes());
    data.extend_from_slice(&address_word(basket));
    data
}

/// Decodes claim calldata into (hunter, nonce, basket); None when it is not exactly a claim.
#[must_use]
pub fn decode_claim_call_data(data: &[u8]) -> Option<(Address, Uint256, Address)> {
    if data.len() != 4 + 32 * 3 || data[..4] != selector("claim(address,uint256,address)") {
        return None;
    }
    let hunter = word_address(data[4..36].try_into().ok()?)?;
    let nonce = Uint256::from_be_bytes(data[36..68].try_into().ok()?);
    let basket = word_address(data[68..100].try_into().ok()?)?;
    Some((hunter, nonce, basket))
}

#[must_use]
pub fn address_word(address: Address) -> [u8; 32] {
    let mut word = [0_u8; 32];
    word[12..].copy_from_slice(&address.to_bytes());
    word
}

/// The address in an ABI word; None when the upper 12 bytes are not zero.
#[must_use]
pub fn word_address(word: [u8; 32]) -> Option<Address> {
    if word[..12].iter().any(|byte| *byte != 0) {
        return None;
    }
    let mut bytes = [0_u8; 20];
    bytes.copy_from_slice(&word[12..]);
    Some(Address::from_bytes(bytes))
}

// ------------------------------------------------------------------ decoded views

/// `HuntRouter.currentDraw()`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Draw {
    pub active: bool,
    pub challenge_id: Uint256,
    pub band: Band,
}

/// Decodes the five static words of `currentDraw()`. Refuses anything malformed.
pub fn decode_draw(raw: &[u8]) -> Result<Draw, String> {
    let words = static_words(raw, 5, "mining router state")?;
    let active = decode_bool_word(words[0], "mining router state")?;
    let tier = small_word(words[2], 4, "mining router state")?;
    let band = Band {
        tier,
        low: Uint256::from_be_bytes(words[3]),
        high: Uint256::from_be_bytes(words[4]),
    };
    if active && (tier == 0 || band.high == Uint256::ZERO || band.low >= band.high) {
        return Err("mining router state is malformed".to_owned());
    }
    Ok(Draw {
        active,
        challenge_id: Uint256::from_be_bytes(words[1]),
        band,
    })
}

/// `HuntStake.preview(wallet)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Preview {
    pub open_at: Uint256,
    pub fresh: bool,
    pub in_party: bool,
    pub matured: Uint256,
    pub eligible: bool,
    pub reason: u8,
}

/// Decodes the seven static words of `preview(address)`. Refuses anything malformed.
pub fn decode_preview(raw: &[u8]) -> Result<Preview, String> {
    let words = static_words(raw, 7, "stake module standing")?;
    let odds = Uint256::from_be_bytes(words[3]);
    if odds > Uint256::from(WAD) {
        return Err("stake module standing is malformed".to_owned());
    }
    let preview = Preview {
        open_at: Uint256::from_be_bytes(words[0]),
        fresh: decode_bool_word(words[1], "stake module standing")?,
        in_party: decode_bool_word(words[2], "stake module standing")?,
        matured: Uint256::from_be_bytes(words[4]),
        eligible: decode_bool_word(words[5], "stake module standing")?,
        reason: small_word(words[6], REASON_OPEN_MODE, "stake module standing")?,
    };
    let expected = preview.reason == REASON_OK || preview.reason == REASON_OPEN_MODE;
    if preview.eligible != expected {
        return Err("stake module standing is inconsistent".to_owned());
    }
    Ok(preview)
}

pub fn decode_bool(raw: &[u8], name: &str) -> Result<bool, String> {
    decode_bool_word(static_words(raw, 1, name)?[0], name)
}

fn static_words(raw: &[u8], count: usize, name: &str) -> Result<Vec<[u8; 32]>, String> {
    if raw.len() != count * 32 {
        return Err(format!(
            "{name} returned {} bytes, expected {}",
            raw.len(),
            count * 32
        ));
    }
    Ok(raw
        .chunks_exact(32)
        .map(|chunk| chunk.try_into().expect("32-byte chunk"))
        .collect())
}

fn decode_bool_word(word: [u8; 32], name: &str) -> Result<bool, String> {
    match small_word(word, 1, name) {
        Ok(value) => Ok(value == 1),
        Err(_) => Err(format!("{name} is not a bool")),
    }
}

fn small_word(word: [u8; 32], maximum: u8, name: &str) -> Result<u8, String> {
    if word[..31].iter().any(|byte| *byte != 0) || word[31] > maximum {
        return Err(format!("{name} is out of range"));
    }
    Ok(word[31])
}

// ------------------------------------------------------------------ decisions

/// Whether this wallet may mine at all: its own stake at or above the unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StakeGate {
    /// Open to every wallet (fail-open or pass-through): no stake needed.
    Open,
    Staked,
    Needed,
}

/// `assignedOf(wallet)` (pending stake included) against `unit()`; `mode` is HuntStake `mode()`.
#[must_use]
pub fn stake_gate(assigned: Uint256, unit: Uint256, mode: u8) -> StakeGate {
    if mode != MODE_NORMAL {
        StakeGate::Open
    } else if assigned >= unit {
        StakeGate::Staked
    } else {
        StakeGate::Needed
    }
}

/// Submit a found proof only when HuntStake says it would pass right now.
#[must_use]
pub fn can_submit(preview: &Preview) -> bool {
    preview.eligible
}

/// Refresh an expired seed only once the next round is open by chain time: a
/// refresh before `openAt` would create a round nobody can finish, and delay mining.
#[must_use]
pub fn refresh_allowed(expired: bool, open_at: Uint256, chain_now: Uint256) -> bool {
    expired && open_at <= chain_now
}

/// Staked, but the stake only counts from the next round.
#[must_use]
pub fn stake_pending(preview: &Preview, assigned: Uint256, unit: Uint256) -> bool {
    preview.reason == REASON_NOT_ENOUGH_STAKE && assigned >= unit && preview.matured < assigned
}

/// Errors from the stake module and router that mean "this wallet cannot submit
/// this proof now". They are reported in neutral words, never by name.
const NEUTRAL_REVERTS: [&str; 14] = [
    // A pause attached mid-run; the loop notices it at its next module check.
    "MiningPaused(uint256)",
    "HuntNotOpen(uint256)",
    "PuzzleNotFresh(uint256)",
    "NotEnoughStake(uint256,uint256)",
    "NotInParty()",
    "StaleChallenge(uint256,uint256)",
    "NotViaRouter(address)",
    "WrongTier(uint8,uint8)",
    "NonceNotBound(address,uint256)",
    "NotHunter(address)",
    "PuzzleNotFreshForHunt(uint256,uint256)",
    "DrawAlreadyFixed(uint256,uint8)",
    "ModuleNotAttached()",
    "MintMismatch()",
];

/// True when a simulation error is one of the stake module's or router's refusals.
#[must_use]
pub fn is_neutral_revert(error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    NEUTRAL_REVERTS.iter().any(|signature| {
        let name = &signature[..signature.find('(').unwrap_or(signature.len())];
        let selector = hex_string(&selector(signature))[2..].to_owned();
        contains_word(error, name) || lower.contains(&selector)
    })
}

/// `name` appears as a whole identifier (so `StaleChallenge` does not match `StaleChallengeId`).
fn contains_word(text: &str, name: &str) -> bool {
    text.match_indices(name).any(|(start, _)| {
        let before = text[..start].chars().next_back();
        let after = text[start + name.len()..].chars().next();
        !before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
            && !after.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// The simulation error to show: neutral words for the stake module's and router's refusals.
#[must_use]
pub fn neutral_rejection(error: &str) -> String {
    if is_neutral_revert(error) {
        "this wallet cannot submit a proof in the current round; nothing was sent".to_owned()
    } else {
        error.to_owned()
    }
}

// ------------------------------------------------------------------ neutral messages

/// "Not staked: Stake 1M HUNTER tokens to this wallet in the app: … (your CLI wallet address: 0x…)."
#[must_use]
pub fn not_staked_message(unit: Uint256, wallet: Address) -> String {
    format!(
        "Not staked: Stake {} HUNTER tokens to this wallet in the app: {STAKE_APP_URL} (your CLI wallet address: {}).",
        format_hunter_short(unit),
        checksum_address(wallet)
    )
}

pub const STAKE_PENDING_MESSAGE: &str = "Your stake becomes active soon. Mining continues.";
pub const MINING_MESSAGE: &str = "Mining…";
/// Single-shot runs that end without sending anything while the wallet is staked.
pub const NOT_THIS_ROUND_MESSAGE: &str =
    "Mining… no proof was submitted in this run. Run again, or use --loop to keep mining.";

/// The app's pause notice, in the CLI's names for tokens and NFTs.
#[must_use]
pub fn pause_message(resume_at: Uint256) -> String {
    format!(
        "Mining is paused for an upgrade that makes it fair for everyone. No new Hunter NFTs can be found until it goes live (by {} at the latest). Your Hunter NFTs and HUNTER tokens are safe.",
        day_month_utc(resume_at)
    )
}

/// "Hunter NFT found" plus its token ID when known.
#[must_use]
pub fn found_message(token_id: Option<Uint256>) -> String {
    token_id.map_or_else(
        || "Hunter NFT found.".to_owned(),
        |id| format!("Hunter NFT found: #{}.", uint256_to_decimal(id)),
    )
}

/// HUNTER wei as "1M", "250K", "2.5M" or "750" (whole tokens, two decimals at most).
#[must_use]
pub fn format_hunter_short(amount: Uint256) -> String {
    let decimal = uint256_to_decimal(amount);
    let whole = if decimal.len() > 18 {
        &decimal[..decimal.len() - 18]
    } else {
        "0"
    };
    let Ok(whole) = whole.parse::<u128>() else {
        return whole.to_owned();
    };
    let scaled = |unit: u128, suffix: &str| {
        let hundredths = (whole * 100 + unit / 2) / unit;
        let mut text = format!("{}.{:02}", hundredths / 100, hundredths % 100);
        while text.ends_with('0') {
            text.pop();
        }
        if text.ends_with('.') {
            text.pop();
        }
        format!("{text}{suffix}")
    };
    if whole >= 1_000_000 {
        scaled(1_000_000, "M")
    } else if whole >= 1_000 {
        scaled(1_000, "K")
    } else {
        whole.to_string()
    }
}

/// EIP-55 mixed-case address.
#[must_use]
pub fn checksum_address(address: Address) -> String {
    let lower = hex_string(&address.to_bytes());
    let hex = &lower[2..];
    let hash = keccak256(hex.as_bytes()).to_bytes();
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (index, character) in hex.chars().enumerate() {
        let nibble = (hash[index / 2] >> (if index % 2 == 0 { 4 } else { 0 })) & 0x0f;
        if character.is_ascii_alphabetic() && nibble >= 8 {
            out.push(character.to_ascii_uppercase());
        } else {
            out.push(character);
        }
    }
    out
}

/// "13 Nov" for a unix time (UTC), as the app shows it.
#[must_use]
pub fn day_month_utc(unix_seconds: Uint256) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let bytes = unix_seconds.to_be_bytes();
    if bytes[..24].iter().any(|byte| *byte != 0) {
        return "a later date".to_owned();
    }
    let seconds = u64::from_be_bytes(bytes[24..].try_into().expect("8 bytes"));
    let days = i64::try_from(seconds / 86_400).unwrap_or(i64::MAX / 2);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{day} {}", MONTHS[usize::try_from(month - 1).unwrap_or(0)])
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;
    use crate::parse::{parse_address, parse_digest, parse_uint256_word};

    const VECTORS: &str = include_str!("../tests/fixtures/hunt-tier-vectors.json");

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Vector {
        challenge: String,
        drawn_tier: u8,
        target: String,
        band_low: String,
        band_high: String,
        digest: String,
        tier_of_digest: u8,
    }

    fn vectors() -> Vec<Vector> {
        serde_json::from_str(VECTORS).expect("tier vectors are valid JSON")
    }

    fn word(text: &str) -> Uint256 {
        parse_uint256_word(text, "vector word").unwrap()
    }

    #[test]
    fn band_filter_matches_every_contract_tier_vector() {
        let vectors = vectors();
        assert_eq!(vectors.len(), 64);
        let mut drawn = [0_usize; 5];
        let mut tiers_of = [0_usize; 5];
        let mut in_band = 0;
        for (index, vector) in vectors.iter().enumerate() {
            let challenge = parse_digest(&vector.challenge, "challenge").unwrap();
            let target = Target::from_be_bytes(word(&vector.target).to_be_bytes());
            let digest = parse_digest(&vector.digest, "digest").unwrap();
            assert_eq!(
                drawn_tier(challenge),
                vector.drawn_tier,
                "vector {index} draw"
            );
            drawn[usize::from(vector.drawn_tier)] += 1;
            let band = Band::at(target, vector.drawn_tier).unwrap();
            assert_eq!(band.low, word(&vector.band_low), "vector {index} low");
            assert_eq!(band.high, word(&vector.band_high), "vector {index} high");
            assert_eq!(
                tier_of(digest, target),
                vector.tier_of_digest,
                "vector {index} tierOf"
            );
            // The router accepts a digest exactly when its tier is the drawn tier.
            let accepted = vector.tier_of_digest == vector.drawn_tier;
            assert_eq!(band.contains(digest), accepted, "vector {index} band");
            in_band += usize::from(accepted);
            // The search bounds agree with the band.
            let floor_ok = band
                .search_floor()
                .is_none_or(|floor| digest.to_bytes() > floor.to_be_bytes());
            let search_ok = digest.to_bytes() <= band.search_target().to_be_bytes() && floor_ok;
            assert_eq!(search_ok, accepted, "vector {index} search bounds");
            // Every band, not only the drawn one, agrees with the contract's tierOf.
            for tier in TIER_COMMON..=TIER_LEGENDARY {
                let other = Band::at(target, tier).unwrap();
                assert_eq!(
                    other.contains(digest),
                    vector.tier_of_digest == tier,
                    "vector {index} tier {tier}"
                );
            }
            tiers_of[usize::from(vector.tier_of_digest)] += 1;
        }
        assert!(
            drawn[1..4].iter().all(|count| *count > 0),
            "drawn tiers 1-3 are covered"
        );
        assert!(
            tiers_of.iter().all(|count| *count > 0),
            "tierOf 0-4 is covered"
        );
        assert!(in_band > 0 && in_band < vectors.len());
    }

    #[test]
    fn vector_fixture_is_the_contract_copy_when_the_monorepo_is_present() {
        let contract_copy = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../contracts/config/hunt-tier-vectors.json");
        if let Ok(contract) = std::fs::read_to_string(&contract_copy) {
            assert_eq!(
                contract, VECTORS,
                "refresh tests/fixtures/hunt-tier-vectors.json"
            );
        }
    }

    #[test]
    fn legendary_band_includes_zero_and_other_bands_exclude_their_floor() {
        let target = Target::from_be_bytes([0xff; 32]);
        let legendary = Band::at(target, TIER_LEGENDARY).unwrap();
        assert!(legendary.contains(Digest::ZERO));
        assert_eq!(legendary.search_floor(), None);
        assert!(legendary.contains(Digest::from_bytes(legendary.high.to_be_bytes())));
        let rare = Band::at(target, TIER_RARE).unwrap();
        assert_eq!(rare.low, legendary.high);
        assert!(!rare.contains(Digest::from_bytes(rare.low.to_be_bytes())));
        assert!(!rare.contains(Digest::ZERO));
        assert!(rare.contains(Digest::from_bytes(rare.high.to_be_bytes())));
        let common = Band::at(target, TIER_COMMON).unwrap();
        assert_eq!(common.high, Uint256::from_be_bytes([0xff; 32]));
        assert_eq!(Band::at(target, 0), None);
        assert_eq!(Band::at(target, 5), None);
    }

    #[test]
    fn nonce_prefix_carries_the_hunter_in_the_top_160_bits() {
        let hunter = parse_address("0x1111111111111111111111111111111111111112", "hunter").unwrap();
        let base = nonce_base(hunter);
        let mut expected = [0_u8; 32];
        expected[..20].copy_from_slice(&hunter.to_bytes());
        assert_eq!(base.to_be_bytes(), expected);
        assert!(is_bound_nonce(base, hunter));

        let counter = Uint256::from(0x0123_4567_89ab_cdef_u64);
        let nonce = bound_nonce(hunter, counter).unwrap();
        assert!(is_bound_nonce(nonce, hunter));
        assert_eq!(
            &nonce.to_be_bytes()[24..],
            &0x0123_4567_89ab_cdef_u64.to_be_bytes()
        );
        // The largest 96-bit counter still fits; one more bit does not.
        let mut max = [0_u8; 32];
        max[20..].fill(0xff);
        assert!(is_bound_nonce(
            bound_nonce(hunter, Uint256::from_be_bytes(max)).unwrap(),
            hunter
        ));
        max[19] = 1;
        assert!(bound_nonce(hunter, Uint256::from_be_bytes(max)).is_err());
        // Another wallet's prefix, or a plain counter, is not bound to this hunter.
        let other = parse_address("0x2222222222222222222222222222222222222222", "other").unwrap();
        assert!(!is_bound_nonce(nonce_base(other), hunter));
        assert!(!is_bound_nonce(counter, hunter));
        // Nonces advance inside the low 96 bits.
        assert!(is_bound_nonce(
            nonce.wrapping_add(Uint256::from(1_000_000_u64)),
            hunter
        ));
    }

    #[test]
    fn router_digest_uses_the_router_as_miner_and_the_full_bound_nonce() {
        let inputs = ChallengeInputs {
            chain_id: Uint256::from(4_663_u64),
            mining_core: parse_address("0xf213854c6d5d4334d23d452574556bd53ca24c2c", "core")
                .unwrap(),
            challenge_id: Uint256::from(871_u64),
            previous_accepted_digest: Digest::from_bytes([0xa5; 32]),
            seed_parent_block: Uint256::from(24_000_000_u64),
            seed_blockhash: Digest::from_bytes([0x5a; 32]),
        };
        let router = parse_address("0x724b77b12b63217b5379c31a713017404175bac7", "router").unwrap();
        let hunter = parse_address("0x1111111111111111111111111111111111111112", "hunter").unwrap();
        let nonce = bound_nonce(hunter, Uint256::from(7_u64)).unwrap();
        let digest = router_digest(&inputs, router, nonce);
        let expected = proof_digest(&ProofInputs {
            chain_id: inputs.chain_id,
            mining_core: inputs.mining_core,
            challenge_id: inputs.challenge_id,
            challenge: derive_challenge(&inputs),
            miner: router,
            nonce,
        });
        assert_eq!(digest, expected);
        // Not the hunter-as-miner digest, and not the counter-only nonce.
        let as_hunter = proof_digest(&ProofInputs {
            miner: hunter,
            ..ProofInputs {
                chain_id: inputs.chain_id,
                mining_core: inputs.mining_core,
                challenge_id: inputs.challenge_id,
                challenge: derive_challenge(&inputs),
                miner: router,
                nonce,
            }
        });
        assert_ne!(digest, as_hunter);
        assert_ne!(digest, router_digest(&inputs, router, Uint256::from(7_u64)));
        // Claim calldata round-trips the exact nonce.
        let basket = parse_address("0xd0601ce157db5bdc3162bbac2a2c8af5320d9eec", "basket").unwrap();
        let data = claim_call_data(hunter, nonce, basket);
        assert_eq!(hex_string(&data[..4]), "0x9e96a260");
        assert_eq!(decode_claim_call_data(&data), Some((hunter, nonce, basket)));
        assert_eq!(decode_claim_call_data(&data[..99]), None);
    }

    fn preview_words(reason: u8, eligible: bool, matured: u64) -> Vec<u8> {
        let mut raw = Vec::new();
        for value in [
            1_790_575_849_u64,
            1,
            u64::from(reason == REASON_OK),
            500_000_000_000_000_000,
            matured,
            u64::from(eligible),
            u64::from(reason),
        ] {
            raw.extend_from_slice(&Uint256::from(value).to_be_bytes());
        }
        raw
    }

    #[test]
    fn eligibility_gates_submission_on_the_preview_answer() {
        for reason in 0..=7_u8 {
            let eligible = reason == REASON_OK || reason == REASON_OPEN_MODE;
            let preview = decode_preview(&preview_words(reason, eligible, 5)).unwrap();
            assert_eq!(can_submit(&preview), eligible, "reason {reason}");
            // A reply whose flag disagrees with its reason is refused, never trusted.
            assert!(decode_preview(&preview_words(reason, !eligible, 5)).is_err());
        }
        let mut malformed = preview_words(REASON_OK, true, 5);
        malformed[6 * 32 + 31] = 8;
        assert!(decode_preview(&malformed).is_err());
        assert!(decode_preview(&preview_words(0, true, 5)[..200]).is_err());
        let mut odds = preview_words(REASON_OK, true, 5);
        odds[3 * 32..4 * 32].copy_from_slice(&Uint256::from(WAD + 1).to_be_bytes());
        assert!(decode_preview(&odds).is_err());

        let unit = Uint256::from(1_000_000_u128 * WAD);
        let pending = decode_preview(&preview_words(REASON_NOT_ENOUGH_STAKE, false, 0)).unwrap();
        assert!(stake_pending(&pending, unit, unit));
        assert!(!stake_pending(&pending, Uint256::ZERO, unit));
    }

    #[test]
    fn refresh_only_when_expired_and_the_next_round_is_open() {
        let open_at = Uint256::from(1_000_u64);
        assert!(!refresh_allowed(true, open_at, Uint256::from(999_u64)));
        assert!(refresh_allowed(true, open_at, Uint256::from(1_000_u64)));
        assert!(refresh_allowed(true, open_at, Uint256::from(5_000_u64)));
        assert!(!refresh_allowed(false, open_at, Uint256::from(5_000_u64)));
    }

    #[test]
    fn stake_gate_and_not_staked_message() {
        let unit = Uint256::from(1_000_000_u128 * WAD);
        assert_eq!(
            stake_gate(Uint256::ZERO, unit, MODE_NORMAL),
            StakeGate::Needed
        );
        assert_eq!(
            stake_gate(Uint256::from(999_999_u128 * WAD), unit, MODE_NORMAL),
            StakeGate::Needed
        );
        assert_eq!(stake_gate(unit, unit, MODE_NORMAL), StakeGate::Staked);
        assert_eq!(stake_gate(Uint256::ZERO, unit, 1), StakeGate::Open);
        assert_eq!(stake_gate(Uint256::ZERO, unit, 2), StakeGate::Open);

        let wallet = parse_address("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", "wallet").unwrap();
        assert_eq!(
            not_staked_message(unit, wallet),
            "Not staked: Stake 1M HUNTER tokens to this wallet in the app: app.proofhunter.fun/app/mine (your CLI wallet address: 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed)."
        );
        assert!(
            not_staked_message(Uint256::from(2_500_000_u128 * WAD), wallet)
                .contains("Stake 2.5M HUNTER tokens")
        );
        assert_eq!(
            format_hunter_short(Uint256::from(250_000_u128 * WAD)),
            "250K"
        );
        assert_eq!(format_hunter_short(Uint256::from(750_u128 * WAD)), "750");
        assert_eq!(
            format_hunter_short(Uint256::from(10_000_000_u128 * WAD)),
            "10M"
        );
        assert_eq!(
            format_hunter_short(Uint256::from(1_234_567_u128 * WAD)),
            "1.23M"
        );
    }

    #[test]
    fn neutral_wording_never_describes_the_mechanics() {
        let unit = Uint256::from(1_000_000_u128 * WAD);
        let wallet = Address::from_bytes([0x11; 20]);
        let texts = [
            not_staked_message(unit, wallet),
            pause_message(Uint256::from(1_794_528_000_u64)),
            found_message(Some(Uint256::from(824_u64))),
            STAKE_PENDING_MESSAGE.to_owned(),
            MINING_MESSAGE.to_owned(),
            NOT_THIS_ROUND_MESSAGE.to_owned(),
        ];
        for text in texts {
            let lower = text.to_lowercase();
            for forbidden in [
                "hunt ", "hunts", "party", "parties", "pick", "draw", "chance", "odds", "gpu",
                "tier", "expired", "fresh", "seed",
            ] {
                assert!(!lower.contains(forbidden), "{text:?} mentions {forbidden}");
            }
        }
    }

    #[test]
    fn stake_and_router_refusals_are_recognised_by_name_or_revert_data() {
        assert!(is_neutral_revert("execution reverted: NotInParty()"));
        let data = hex_string(&selector("WrongTier(uint8,uint8)"));
        assert!(is_neutral_revert(&format!(
            "JSON-RPC proof simulation failed with error 3: execution reverted (revert data {data}0000)"
        )));
        assert!(!is_neutral_revert(
            "JSON-RPC proof simulation failed with error 3: execution reverted"
        ));
        assert!(!is_neutral_revert("StaleChallengeId(1, 2)"));
        let text = neutral_rejection("execution reverted: NotInParty()");
        assert!(!text.contains("Party"));
        assert_eq!(neutral_rejection("other failure"), "other failure");
    }

    #[test]
    fn pause_message_names_the_utc_day_it_ends() {
        // 13 Nov 2026 00:00:00 UTC.
        assert_eq!(day_month_utc(Uint256::from(1_794_528_000_u64)), "13 Nov");
        assert_eq!(day_month_utc(Uint256::from(0_u64)), "1 Jan");
        assert_eq!(day_month_utc(Uint256::from(951_782_400_u64)), "29 Feb");
        assert!(
            pause_message(Uint256::from(1_794_528_000_u64)).contains("(by 13 Nov at the latest)")
        );
    }

    #[test]
    fn draw_decoding_refuses_bad_replies() {
        let words = |values: [Uint256; 5]| {
            values
                .iter()
                .flat_map(|value| value.to_be_bytes())
                .collect::<Vec<_>>()
        };
        let ok = words([
            Uint256::ONE,
            Uint256::from(871_u64),
            Uint256::from(1_u64),
            Uint256::from(10_u64),
            Uint256::from(20_u64),
        ]);
        let draw = decode_draw(&ok).unwrap();
        assert!(draw.active);
        assert_eq!(draw.band.tier, TIER_COMMON);
        assert!(
            draw.band
                .contains(Digest::from_bytes(Uint256::from(20_u64).to_be_bytes()))
        );
        let inactive = words([
            Uint256::ZERO,
            Uint256::ONE,
            Uint256::ZERO,
            Uint256::ZERO,
            Uint256::ZERO,
        ]);
        assert!(!decode_draw(&inactive).unwrap().active);
        for bad in [
            words([
                Uint256::from(2_u64),
                Uint256::ONE,
                Uint256::ONE,
                Uint256::ONE,
                Uint256::from(2_u64),
            ]),
            words([
                Uint256::ONE,
                Uint256::ONE,
                Uint256::from(5_u64),
                Uint256::ONE,
                Uint256::from(2_u64),
            ]),
            words([
                Uint256::ONE,
                Uint256::ONE,
                Uint256::ONE,
                Uint256::from(3_u64),
                Uint256::from(2_u64),
            ]),
            words([
                Uint256::ONE,
                Uint256::ONE,
                Uint256::ZERO,
                Uint256::ONE,
                Uint256::from(2_u64),
            ]),
        ] {
            assert!(decode_draw(&bad).is_err());
        }
        assert!(decode_draw(&ok[..128]).is_err());
    }

    #[test]
    fn checksum_matches_eip55_examples() {
        for expected in [
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ] {
            let address = parse_address(&expected.to_lowercase(), "address").unwrap();
            assert_eq!(checksum_address(address), expected);
        }
    }
}
