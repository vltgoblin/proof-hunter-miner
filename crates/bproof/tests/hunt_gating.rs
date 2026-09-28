//! Mining v2 gating against a scripted JSON-RPC node (no chain, no network).
//!
//! The mock answers the core, stake module and router views from one scenario and
//! records every request, so each test can prove what the real binary sent:
//! nothing for an unstaked or not-yet-eligible wallet, no refresh before the next
//! round opens, and a bound router claim once the wallet is eligible.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use proof_core::{
    Address, ChallengeInputs, Digest, ProofInputs, Uint256, derive_challenge, keccak256,
    proof_digest,
};
use serde_json::{Value, json};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

const CHAIN_ID: u64 = 31_337;
const CORE: [u8; 20] = [0xc0; 20];
const STAKE: [u8; 20] = [0x5a; 20];
const ROUTER: [u8; 20] = [0x7e; 20];
const NFT: [u8; 20] = [0x9f; 20];
const BASKET: [u8; 20] = [0xba; 20];
const PAUSE: [u8; 20] = [0x50; 20];
/// 13 Nov 2026 00:00:00 UTC.
const RESUME_AT: u64 = 1_794_528_000;
const HELPER: &str = "0x00000000000000000000000000000000000c0de1";
const NOW: u64 = 1_790_000_000;
const CHALLENGE_ID: u64 = 900;
const SEED_BLOCK: u64 = 0x100;
const UNIT: u128 = 1_000_000 * 1_000_000_000_000_000_000;
/// A target whose tier cuts are exact: 10 / 80 / 300 per mille.
const TARGET: u128 = 1_000_000_000_000_000_000_000_000_000_000;

#[derive(Clone, Copy)]
struct Scenario {
    /// HunterMiningCore.challengeState(): 1 active, 2 expired.
    state: u8,
    assigned: u128,
    open_at: u64,
    /// preview() reason; eligible is derived exactly as HuntStake does.
    reason: u8,
    /// A target large enough to find a proof quickly when eligible.
    easy: bool,
    /// The core's module is a pause instead of the stake module.
    paused: bool,
    /// The router's result is not fixed yet, so `fixDraw()` would succeed.
    unfixed: bool,
    /// `easeDifficulty()` would succeed.
    ease_ok: bool,
}

impl Scenario {
    fn target(&self) -> Uint256 {
        if self.easy {
            let mut bytes = [0xff; 32];
            bytes[0] = 0x0f;
            Uint256::from_be_bytes(bytes)
        } else {
            Uint256::from(TARGET)
        }
    }
}

#[test]
fn an_unstaked_wallet_is_told_how_to_stake_and_nothing_is_sent() {
    let scenario = Scenario {
        state: 1,
        assigned: UNIT - 1,
        open_at: NOW - 60,
        reason: 4,
        easy: true,
        paused: false,
        unfixed: false,
        ease_ok: false,
    };
    let fixture = Fixture::new(scenario);
    let output = fixture.mine();
    assert_eq!(output.status.code(), Some(4), "{}", describe(&output));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "notStaked");
    assert_eq!(
        result["message"],
        format!(
            "Not staked: Stake 1M HUNTER tokens to this wallet in the app: app.proofhunter.fun/app/mine (your CLI wallet address: {}).",
            result["wallet"].as_str().unwrap()
        )
    );
    assert_eq!(
        result["wallet"].as_str().unwrap().to_lowercase(),
        fixture.wallet
    );
    fixture.node.assert_never_sent();
}

#[test]
fn an_expired_round_is_never_refreshed_before_the_next_one_opens() {
    let fixture = Fixture::new(Scenario {
        state: 2,
        assigned: UNIT,
        open_at: NOW + 120,
        reason: 6,
        easy: false,
        paused: false,
        unfixed: false,
        ease_ok: false,
    });
    let output = fixture.mine();
    assert_eq!(output.status.code(), Some(4), "{}", describe(&output));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "waiting");
    assert!(!fixture.node.simulated(&CORE, "refreshExpiredSeed()"));
    fixture.node.assert_never_sent();

    let events = fixture.run_loop_until("challengeUnavailable", Duration::from_secs(2));
    assert!(
        events
            .iter()
            .any(|event| event["event"] == "challengeUnavailable" && event["status"] == "waiting")
    );
    assert!(
        events
            .iter()
            .all(|event| event["event"] != "seedRefreshStarted")
    );
    assert!(!fixture.node.simulated(&CORE, "refreshExpiredSeed()"));
    fixture.node.assert_never_sent();
}

#[test]
fn an_expired_round_is_refreshed_once_it_is_open() {
    let fixture = Fixture::new(Scenario {
        state: 2,
        assigned: UNIT,
        open_at: NOW,
        reason: 6,
        easy: false,
        paused: false,
        unfixed: false,
        ease_ok: false,
    });
    let output = fixture.mine();
    // The mock refuses the broadcast; what matters is that the refresh was signed and sent.
    assert!(
        fixture.node.simulated(&CORE, "refreshExpiredSeed()"),
        "{}",
        describe(&output)
    );
    assert_eq!(fixture.node.sends(), 1);
}

#[test]
fn a_staked_wallet_that_cannot_submit_this_round_sends_nothing() {
    for reason in [2_u8, 3, 4, 5] {
        let fixture = Fixture::new(Scenario {
            state: 1,
            assigned: UNIT,
            open_at: NOW - 60,
            reason,
            easy: true,
            paused: false,
            unfixed: false,
            ease_ok: false,
        });
        let output = fixture.mine();
        assert_eq!(
            output.status.code(),
            Some(4),
            "reason {reason}: {}",
            describe(&output)
        );
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        let status = if reason == 4 {
            "stakePending"
        } else {
            "waiting"
        };
        assert_eq!(result["status"], status, "reason {reason}");
        let text = result["message"].as_str().unwrap().to_lowercase();
        for forbidden in ["party", "pick", "draw", "chance", "hunt", "fresh", "tier"] {
            assert!(!text.contains(forbidden), "{text}");
        }
        assert!(
            !fixture
                .node
                .simulated(&ROUTER, "claim(address,uint256,address)")
        );
        fixture.node.assert_never_sent();
    }

    // The loop keeps mining but never finds, simulates or sends a claim.
    let fixture = Fixture::new(Scenario {
        state: 1,
        assigned: UNIT,
        open_at: NOW - 60,
        reason: 5,
        easy: true,
        paused: false,
        unfixed: false,
        ease_ok: false,
    });
    let events = fixture.run_loop_until("searchStarted", Duration::from_secs(3));
    assert!(events.iter().any(|event| event["event"] == "searchStarted"));
    assert!(events.iter().all(|event| event["event"] != "proofFound"));
    assert!(
        !fixture
            .node
            .simulated(&ROUTER, "claim(address,uint256,address)")
    );
    fixture.node.assert_never_sent();
}

#[test]
fn an_eligible_wallet_claims_a_bound_band_proof_through_the_router() {
    let scenario = Scenario {
        state: 1,
        assigned: UNIT,
        open_at: NOW - 60,
        reason: 0,
        easy: true,
        paused: false,
        unfixed: false,
        ease_ok: false,
    };
    let fixture = Fixture::new(scenario);
    let _ = fixture.mine();
    let claims = fixture
        .node
        .calls_to(&ROUTER, "claim(address,uint256,address)");
    assert!(!claims.is_empty(), "no claim was simulated");
    let claim = &claims[0];
    assert_eq!(claim.from.as_deref(), Some(fixture.wallet.as_str()));
    let data = hex_bytes(&claim.data);
    let hunter = &data[4 + 12..4 + 32];
    assert_eq!(hex(hunter), fixture.wallet);
    let nonce: [u8; 32] = data[36..68].try_into().unwrap();
    assert_eq!(&nonce[..20], hunter, "nonce is not bound to the wallet");
    assert_eq!(&data[68 + 12..100], &BASKET);
    // The digest the core derives with the router as miner lies in the drawn band.
    let inputs = challenge_inputs();
    let digest = proof_digest(&ProofInputs {
        chain_id: inputs.chain_id,
        mining_core: inputs.mining_core,
        challenge_id: inputs.challenge_id,
        challenge: derive_challenge(&inputs),
        miner: Address::from_bytes(ROUTER),
        nonce: Uint256::from_be_bytes(nonce),
    });
    let (low, high) = common_band(scenario.target());
    let value = Uint256::from_be_bytes(digest.to_bytes());
    assert!(
        value > low && value <= high,
        "digest outside the drawn band"
    );
    assert_eq!(fixture.node.sends(), 1);
}

#[test]
fn a_pause_module_prints_the_pause_notice_and_sends_nothing() {
    let fixture = Fixture::new(Scenario {
        state: 1,
        assigned: UNIT,
        open_at: NOW - 60,
        reason: 0,
        easy: true,
        paused: true,
        unfixed: false,
        ease_ok: false,
    });
    let output = fixture.mine();
    assert_eq!(output.status.code(), Some(4), "{}", describe(&output));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "paused");
    assert_eq!(result["resumeAt"], RESUME_AT.to_string());
    assert_eq!(
        result["message"],
        "Mining is paused for an upgrade that makes it fair for everyone. No new Hunter NFTs can be found until it goes live (by 13 Nov at the latest). Your Hunter NFTs and HUNTER tokens are safe."
    );
    fixture.node.assert_never_sent();

    let events = fixture.run_loop_until("miningPaused", Duration::from_secs(1));
    assert!(events.iter().all(|event| event["event"] != "searchStarted"));
    fixture.node.assert_never_sent();
}

#[test]
fn a_router_other_than_the_pinned_one_refuses_to_mine() {
    let fixture = Fixture::new(Scenario {
        state: 1,
        assigned: UNIT,
        open_at: NOW - 60,
        reason: 0,
        easy: true,
        paused: false,
        unfixed: false,
        ease_ok: false,
    });
    let mut args = fixture.args(false);
    let index = args.iter().position(|arg| arg == "--router").unwrap();
    args[index + 1] = hex(&[0x01; 20]);
    let output = run(&args);
    assert_eq!(output.status.code(), Some(2), "{}", describe(&output));
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing to mine"));
    fixture.node.assert_never_sent();
}

fn upkeep_scenario(unfixed: bool, ease_ok: bool, assigned: u128) -> Scenario {
    // Staked, on a fresh round this wallet is not selected for: it keeps hashing
    // with an impossible target while the watcher plans upkeep.
    Scenario {
        state: 1,
        assigned,
        open_at: NOW - 60,
        reason: 5,
        easy: true,
        paused: false,
        unfixed,
        ease_ok,
    }
}

#[test]
fn a_staked_loop_locks_an_unfixed_round_through_the_journaled_path() {
    let fixture = Fixture::new(upkeep_scenario(true, false, UNIT));
    let events = fixture.run_loop_until("upkeepSkipped", Duration::from_millis(200));
    // Simulated from the wallet first, then signed and broadcast once (the mock refuses
    // broadcasts, so the CLI logs a neutral skip and keeps mining).
    let simulations = fixture.node.calls_to(&ROUTER, "fixDraw()");
    assert!(!simulations.is_empty());
    assert!(
        simulations
            .iter()
            .all(|call| call.from.as_deref() == Some(fixture.wallet.as_str()))
    );
    let broadcasts = fixture.node.broadcasts();
    assert_eq!(broadcasts.len(), 1, "{broadcasts:?}");
    assert!(broadcasts[0].contains(&selector_hex("fixDraw()")[2..]));
    assert!(broadcasts[0].contains(&hex(&ROUTER)[2..]));
    let skipped = events
        .iter()
        .find(|event| event["event"] == "upkeepSkipped")
        .unwrap();
    assert_eq!(skipped["kind"], "lock");
    assert_eq!(skipped["message"], "Network upkeep skipped.");
    let failures: Vec<&Value> = events
        .iter()
        .filter(|event| event["event"] == "failure")
        .collect();
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn a_staked_loop_eases_when_the_network_allows_it() {
    let fixture = Fixture::new(upkeep_scenario(false, true, UNIT));
    let events = fixture.run_loop_until("upkeepSkipped", Duration::from_millis(200));
    let broadcasts = fixture.node.broadcasts();
    assert_eq!(broadcasts.len(), 1, "{broadcasts:?}");
    assert!(broadcasts[0].contains(&selector_hex("easeDifficulty()")[2..]));
    assert!(broadcasts[0].contains(&hex(&CORE)[2..]));
    assert!(
        !fixture.node.simulated(&ROUTER, "fixDraw()"),
        "a fixed round is never locked"
    );
    let skipped = events
        .iter()
        .find(|event| event["event"] == "upkeepSkipped")
        .unwrap();
    assert_eq!(skipped["kind"], "ease");
}

#[test]
fn no_upkeep_flag_or_missing_stake_means_no_upkeep_at_all() {
    // --no-upkeep: the loop mines but never simulates or sends upkeep.
    let fixture = Fixture::new(upkeep_scenario(true, true, UNIT));
    let mut args = fixture.args(true);
    args.push("--no-upkeep".into());
    let events = fixture.run_loop_args_until(args, "searchStarted", Duration::from_secs(4));
    assert!(events.iter().any(|event| event["event"] == "searchStarted"));
    assert!(!fixture.node.simulated(&ROUTER, "fixDraw()"));
    assert!(!fixture.node.simulated(&CORE, "easeDifficulty()"));
    fixture.node.assert_never_sent();

    // Without its own stake the loop stops before any upkeep, and sends nothing.
    let fixture = Fixture::new(upkeep_scenario(true, true, UNIT - 1));
    let output = run(&fixture.args(true));
    assert_eq!(output.status.code(), Some(4), "{}", describe(&output));
    assert!(!fixture.node.simulated(&ROUTER, "fixDraw()"));
    assert!(!fixture.node.simulated(&CORE, "easeDifficulty()"));
    fixture.node.assert_never_sent();
}

// ------------------------------------------------------------------ fixture

struct Fixture {
    node: MockNode,
    directory: PathBuf,
    keystore: PathBuf,
    passphrase: PathBuf,
    wallet: String,
}

impl Fixture {
    fn new(scenario: Scenario) -> Self {
        disable_core_dumps_for_children();
        let directory = std::env::temp_dir().join(format!(
            "bproof-hunt-gating-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir(&directory).unwrap();
        let passphrase = directory.join("passphrase");
        write_owner_only(&passphrase, b"hunt-gating-test-passphrase");
        let keystore = directory.join("wallet.json");
        let created = run(&[
            "wallet".into(),
            "new".into(),
            "--keystore".into(),
            keystore.display().to_string(),
            "--recovery-out".into(),
            directory.join("recovery.txt").display().to_string(),
            "--passphrase-file".into(),
            passphrase.display().to_string(),
            "--json".into(),
        ]);
        assert_eq!(created.status.code(), Some(0), "{}", describe(&created));
        let created: Value = serde_json::from_slice(&created.stdout).unwrap();
        let wallet = created["address"].as_str().unwrap().to_lowercase();
        Self {
            node: MockNode::start(scenario),
            directory,
            keystore,
            passphrase,
            wallet,
        }
    }

    fn args(&self, loop_mode: bool) -> Vec<String> {
        let mut args: Vec<String> = vec![
            "mine".into(),
            "--submit".into(),
            "--rpc-url".into(),
            self.node.url.clone(),
            "--chain-id".into(),
            CHAIN_ID.to_string(),
            "--mining-core".into(),
            hex(&CORE),
            "--basket".into(),
            hex(&BASKET),
            "--keystore".into(),
            self.keystore.display().to_string(),
            "--passphrase-file".into(),
            self.passphrase.display().to_string(),
            "--max-fee".into(),
            "1000000000000000000".into(),
            "--priority-fee-per-gas".into(),
            "1".into(),
            "--threads".into(),
            "1".into(),
            "--router".into(),
            hex(&ROUTER),
            "--json".into(),
        ];
        if loop_mode {
            args.extend(["--loop".into(), "--watch-interval-ms".into(), "100".into()]);
        }
        args
    }

    fn mine(&self) -> Output {
        run(&self.args(false))
    }

    /// Runs `--loop` until an event of `kind` (or 120 s), keeps it running for
    /// `extra` more, then Ctrl-C; returns every JSON event.
    fn run_loop_until(&self, kind: &str, extra: Duration) -> Vec<Value> {
        self.run_loop_args_until(self.args(true), kind, extra)
    }

    fn run_loop_args_until(&self, args: Vec<String>, kind: &str, extra: Duration) -> Vec<Value> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_bproof"))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel::<Value>();
        let reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Ok(value) = serde_json::from_str::<Value>(&line) {
                    let _ = sender.send(value);
                }
            }
        });
        let mut events = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(120);
        let mut seen_at = None;
        while Instant::now() < deadline {
            if let Ok(event) = receiver.recv_timeout(Duration::from_millis(100)) {
                if event["event"] == kind && seen_at.is_none() {
                    seen_at = Some(Instant::now());
                }
                events.push(event);
            }
            if seen_at.is_some_and(|at| at.elapsed() >= extra) {
                break;
            }
        }
        let _ = Command::new("kill")
            .args(["-INT", &child.id().to_string()])
            .status();
        let stop_deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if Instant::now() > stop_deadline {
                let _ = child.kill();
                break None;
            }
            thread::sleep(Duration::from_millis(50));
        };
        let _ = child.wait();
        let _ = reader.join();
        events.extend(receiver.try_iter());
        assert!(seen_at.is_some(), "no {kind} event: {events:#?}");
        assert_eq!(
            status.and_then(|status| status.code()),
            Some(0),
            "loop did not stop cleanly"
        );
        events
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

// ------------------------------------------------------------------ scripted node

#[derive(Clone, Debug)]
struct Call {
    to: String,
    from: Option<String>,
    data: String,
}

struct MockNode {
    url: String,
    calls: Arc<Mutex<Vec<Call>>>,
    sends: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
}

impl MockNode {
    fn start(scenario: Scenario) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let calls = Arc::new(Mutex::new(Vec::new()));
        let sends = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (thread_calls, thread_sends, thread_stop) =
            (Arc::clone(&calls), Arc::clone(&sends), Arc::clone(&stop));
        thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let (calls, sends) = (Arc::clone(&thread_calls), Arc::clone(&thread_sends));
                        thread::spawn(move || serve(stream, scenario, &calls, &sends));
                    }
                    Err(_) => thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        Self {
            url,
            calls,
            sends,
            stop,
        }
    }

    fn sends(&self) -> u64 {
        self.sends.load(Ordering::Acquire)
    }

    fn assert_never_sent(&self) {
        assert_eq!(self.sends(), 0, "a transaction was broadcast");
    }

    fn calls_to(&self, to: &[u8; 20], signature: &str) -> Vec<Call> {
        let selector = selector_hex(signature);
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.to == hex(to) && call.data.starts_with(&selector))
            .cloned()
            .collect()
    }

    fn simulated(&self, to: &[u8; 20], signature: &str) -> bool {
        !self.calls_to(to, signature).is_empty()
    }

    /// Signed transactions the CLI tried to broadcast, as lowercase hex.
    fn broadcasts(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.to == "raw")
            .map(|call| call.data.clone())
            .collect()
    }
}

impl Drop for MockNode {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

fn serve(mut stream: TcpStream, scenario: Scenario, calls: &Mutex<Vec<Call>>, sends: &AtomicU64) {
    stream.set_nonblocking(false).unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut length = 0;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse().unwrap();
        }
    }
    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body).unwrap();
    let request: Value = serde_json::from_slice(&body).unwrap();
    let reply = match respond(&request, scenario, calls, sends) {
        Ok(result) => json!({"jsonrpc": "2.0", "id": request["id"], "result": result}),
        Err(message) => {
            json!({"jsonrpc": "2.0", "id": request["id"], "error": {"code": 3, "message": message}})
        }
    }
    .to_string();
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
        reply.len()
    );
}

fn respond(
    request: &Value,
    scenario: Scenario,
    calls: &Mutex<Vec<Call>>,
    sends: &AtomicU64,
) -> Result<Value, String> {
    let params = &request["params"];
    match request["method"].as_str().unwrap() {
        "eth_chainId" => Ok(json!(format!("0x{CHAIN_ID:x}"))),
        "eth_blockNumber" => Ok(json!("0x400")),
        "eth_getCode" => Ok(json!("0x6001")),
        "eth_getBlockByNumber" => Ok(json!({
            "number": "0x400",
            "hash": hex(&[0x11; 32]),
            "timestamp": format!("0x{NOW:x}"),
            "baseFeePerGas": "0x1",
        })),
        "eth_maxPriorityFeePerGas" => Ok(json!("0x1")),
        "eth_estimateGas" => Ok(json!("0x30000")),
        "eth_getTransactionCount" => Ok(json!("0x0")),
        "eth_getTransactionReceipt" => Ok(Value::Null),
        "eth_sendRawTransaction" => {
            sends.fetch_add(1, Ordering::AcqRel);
            calls.lock().unwrap().push(Call {
                to: "raw".to_owned(),
                from: None,
                data: params[0].as_str().unwrap_or_default().to_lowercase(),
            });
            Err("mock node does not broadcast".to_owned())
        }
        "eth_call" => {
            let call = Call {
                to: params[0]["to"].as_str().unwrap().to_lowercase(),
                from: params[0]["from"].as_str().map(str::to_lowercase),
                data: params[0]["data"].as_str().unwrap_or("0x").to_lowercase(),
            };
            calls.lock().unwrap().push(call.clone());
            view(&call, scenario).map(Value::String)
        }
        other => Err(format!("unexpected method {other}")),
    }
}

fn view(call: &Call, scenario: Scenario) -> Result<String, String> {
    let wallet_word = |call: &Call| call.data.get(10..74).map(str::to_owned);
    if call.to == HELPER {
        return Ok(if call.data == "0x" {
            word(Uint256::from(0x400_u64))
        } else {
            hex(&seed_blockhash().to_bytes())
        });
    }
    let selector = &call.data[..10.min(call.data.len())];
    let is = |signature: &str| selector == selector_hex(signature);
    let active = scenario.state == 1;
    if call.to == hex(&CORE) {
        return if is("miningPower()") {
            Ok(address(if scenario.paused { &PAUSE } else { &STAKE }))
        } else if is("PROOF_NFT()") {
            Ok(address(&NFT))
        } else if is("challengeState()") {
            Ok(word(Uint256::from(u64::from(scenario.state))))
        } else if is("activeChallengeId()") {
            Ok(word(Uint256::from(CHALLENGE_ID)))
        } else if is("activeSeedParentBlock()") {
            Ok(word(Uint256::from(SEED_BLOCK)))
        } else if is("previousAcceptedDigest()") {
            Ok(word(Uint256::ZERO))
        } else if is("currentTarget()") {
            Ok(word(scenario.target()))
        } else if is("acceptedProofs()") || is("nftsMintedEver()") {
            Ok(word(Uint256::from(824_u64)))
        } else if is("MAX_NFTS_EVER()") {
            Ok(word(Uint256::from(5_000_u64)))
        } else if is("currentChallenge()") && active {
            Ok(hex(&derive_challenge(&challenge_inputs()).to_bytes()))
        } else if (is("refreshExpiredSeed()") && !active)
            || (is("easeDifficulty()") && active && scenario.ease_ok)
        {
            Ok("0x".to_owned())
        } else {
            Err("execution reverted".to_owned())
        };
    }
    if call.to == hex(&PAUSE) {
        return if is("paused()") {
            Ok(word(Uint256::ONE))
        } else if is("RESUME_AT()") {
            Ok(word(Uint256::from(RESUME_AT)))
        } else {
            Err("execution reverted".to_owned())
        };
    }
    if call.to == hex(&STAKE) {
        return if is("ROUTER()") {
            Ok(address(&ROUTER))
        } else if is("unit()") {
            Ok(word(Uint256::from(UNIT)))
        } else if is("mode()") {
            Ok(word(Uint256::ZERO))
        } else if is("assignedOf(address)") {
            wallet_word(call).ok_or("bad call")?;
            Ok(word(Uint256::from(scenario.assigned)))
        } else if is("preview(address)") {
            let reason = if active { scenario.reason } else { 6 };
            let eligible = reason == 0 || reason == 7;
            let matured = if reason == 4 { 0 } else { scenario.assigned };
            let words = [
                Uint256::from(scenario.open_at),
                Uint256::from(u64::from(reason != 2 && reason != 3)),
                Uint256::from(u64::from(eligible)),
                Uint256::from(500_000_000_000_000_000_u64),
                Uint256::from(matured),
                Uint256::from(u64::from(eligible)),
                Uint256::from(u64::from(reason)),
            ];
            Ok(format!(
                "0x{}",
                words
                    .iter()
                    .map(|w| word(*w)[2..].to_owned())
                    .collect::<String>()
            ))
        } else {
            Err("execution reverted".to_owned())
        };
    }
    if call.to == hex(&ROUTER) {
        return if is("MODULE()") {
            Ok(address(&STAKE))
        } else if is("CORE()") {
            Ok(address(&CORE))
        } else if is("NFT()") {
            Ok(address(&NFT))
        } else if is("drawFixed()") {
            Ok(word(Uint256::from(u64::from(!scenario.unfixed))))
        } else if is("fixDraw()") && active && scenario.unfixed {
            Ok("0x".to_owned())
        } else if is("currentDraw()") {
            // Unfixed, the router reports this challenge's own draw; fixed, Common.
            let tier = if scenario.unfixed {
                drawn_tier(derive_challenge(&challenge_inputs()))
            } else {
                1
            };
            let (low, high) = band_for(scenario.target(), tier);
            Ok(format!(
                "0x{}{}{}{}{}",
                &word(Uint256::from(u64::from(active)))[2..],
                &word(Uint256::from(CHALLENGE_ID))[2..],
                &word(Uint256::from(u64::from(tier)))[2..],
                &word(low)[2..],
                &word(high)[2..],
            ))
        } else if is("claim(address,uint256,address)") {
            Ok(word(Uint256::from(825_u64)))
        } else {
            Err("execution reverted".to_owned())
        };
    }
    Err("execution reverted".to_owned())
}

fn challenge_inputs() -> ChallengeInputs {
    ChallengeInputs {
        chain_id: Uint256::from(CHAIN_ID),
        mining_core: Address::from_bytes(CORE),
        challenge_id: Uint256::from(CHALLENGE_ID),
        previous_accepted_digest: Digest::ZERO,
        seed_parent_block: Uint256::from(SEED_BLOCK),
        seed_blockhash: seed_blockhash(),
    }
}

fn seed_blockhash() -> Digest {
    Digest::from_bytes([0x33; 32])
}

/// The Common band at `target`: (floor(target * 300 / 1000), target].
fn common_band(target: Uint256) -> (Uint256, Uint256) {
    // target * 3 / 10 without overflow: every test target is a multiple of 10 or
    // 0x0fff…ff, whose exact floor we compute with 320-bit long division.
    let bytes = target.to_be_bytes();
    let mut wide = [0_u8; 33];
    let mut carry = 0_u16;
    for index in (0..32).rev() {
        let product = u16::from(bytes[index]) * 3 + carry;
        wide[index + 1] = product as u8;
        carry = product >> 8;
    }
    wide[0] = carry as u8;
    let mut remainder = 0_u16;
    let mut quotient = [0_u8; 33];
    for (index, byte) in wide.iter().enumerate() {
        let partial = (remainder << 8) | u16::from(*byte);
        quotient[index] = (partial / 10) as u8;
        remainder = partial % 10;
    }
    let low: [u8; 32] = quotient[1..].try_into().unwrap();
    (Uint256::from_be_bytes(low), target)
}

/// The router's draw for `challenge`: keccak256(challenge ‖ keccak256("proof-hunters/tier")) mod 1000.
fn drawn_tier(challenge: Digest) -> u8 {
    let mut preimage = [0_u8; 64];
    preimage[..32].copy_from_slice(&challenge.to_bytes());
    preimage[32..].copy_from_slice(&keccak256(b"proof-hunters/tier").to_bytes());
    let draw = keccak256(&preimage)
        .to_bytes()
        .iter()
        .fold(0_u64, |acc, byte| (acc * 256 + u64::from(*byte)) % 1_000);
    match draw {
        0..10 => 4,
        10..80 => 3,
        80..300 => 2,
        _ => 1,
    }
}

/// floor(target * numerator / 1000), exactly.
fn per_mille(target: Uint256, numerator: u64) -> Uint256 {
    let bytes = target.to_be_bytes();
    let mut wide = [0_u8; 40];
    let mut carry = 0_u128;
    for index in (0..32).rev() {
        let product = u128::from(bytes[index]) * u128::from(numerator) + carry;
        wide[index + 8] = product as u8;
        carry = product >> 8;
    }
    wide[..8].copy_from_slice(&(carry as u64).to_be_bytes());
    let mut remainder = 0_u128;
    for byte in &mut wide {
        let partial = (remainder << 8) | u128::from(*byte);
        *byte = (partial / 1_000) as u8;
        remainder = partial % 1_000;
    }
    Uint256::from_be_bytes(wide[8..].try_into().unwrap())
}

/// The router's band for `tier` at `target`: (low, high].
fn band_for(target: Uint256, tier: u8) -> (Uint256, Uint256) {
    let (legendary, rare, uncommon) = (
        per_mille(target, 10),
        per_mille(target, 80),
        per_mille(target, 300),
    );
    match tier {
        4 => (Uint256::ZERO, legendary),
        3 => (legendary, rare),
        2 => (rare, uncommon),
        _ => (uncommon, target),
    }
}

// ------------------------------------------------------------------ helpers

fn run(args: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bproof"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn describe(output: &Output) -> String {
    format!(
        "exit {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn word(value: Uint256) -> String {
    hex(&value.to_be_bytes())
}

fn address(bytes: &[u8; 20]) -> String {
    let mut padded = [0_u8; 32];
    padded[12..].copy_from_slice(bytes);
    hex(&padded)
}

fn selector_hex(signature: &str) -> String {
    hex(&keccak256(signature.as_bytes()).to_bytes()[..4])
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::from("0x");
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn hex_bytes(text: &str) -> Vec<u8> {
    let text = text.trim_start_matches("0x");
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

#[cfg(unix)]
fn write_owner_only(path: &Path, contents: &[u8]) {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(contents).unwrap();
}

#[cfg(not(unix))]
fn write_owner_only(path: &Path, contents: &[u8]) {
    std::fs::write(path, contents).unwrap();
}

#[cfg(unix)]
fn disable_core_dumps_for_children() {
    let (_, hard_limit) = rlimit::Resource::CORE.get().unwrap();
    rlimit::Resource::CORE.set(0, hard_limit).unwrap();
}

#[cfg(not(unix))]
fn disable_core_dumps_for_children() {}
