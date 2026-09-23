#![cfg(unix)]

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use proof_core::keccak256;
mod common;
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};
use zeroize::Zeroizing;

static NEXT_TEMP_DIRECTORY: AtomicU64 = AtomicU64::new(0);

const MINING_CORE: &str = common::MINING_CORE;
const CHAIN_ID: &str = "31337";
const PROOF_HUNTER_FEE_WARNING: &str = "Every accepted HunterMiningCore proof mints one NFT and pays no liquid HUNTER. Token activation and backing are separate from mining; no backing amount is promised. --max-fee must cover the estimated mint transaction or submission is refused.";

#[test]
fn loop_requires_explicit_submission_and_documents_streaming_events() {
    let refused = run(["mine", "--loop"]);
    assert_eq!(refused.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("--loop requires --submit"),
        "stderr: {}",
        String::from_utf8_lossy(&refused.stderr)
    );

    let help = run(["mine", "--help"]);
    assert_eq!(help.status.code(), Some(0));
    let help = String::from_utf8_lossy(&help.stdout);
    for text in [
        "--loop",
        "--watch-interval-ms",
        "defaults to 1000",
        "feeRefused",
        "proofAccepted",
        "staleWorkAbandoned",
        "Type `summary`",
        "Ctrl-C stops cleanly",
    ] {
        assert!(help.contains(text), "missing help text: {text}");
    }
}

#[test]
fn unreachable_endpoint_uses_growing_backoff_and_stops_cleanly() {
    disable_core_dumps_for_children();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let stop_refuser = Arc::new(AtomicBool::new(false));
    let server_stop = Arc::clone(&stop_refuser);
    let refuser = thread::spawn(move || {
        while !server_stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _)) => drop(stream),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("refusing endpoint failed: {error}"),
            }
        }
    });
    let endpoint = format!("http://127.0.0.1:{port}");
    let directory = temp_directory(port);
    let _directory = DirectoryGuard(directory.clone());
    let keystore = directory.join("backoff-wallet.json");
    let recovery_file = directory.join("backoff-wallet-recovery.txt");
    let passphrase_file = directory.join("backoff-passphrase");
    let passphrase = runtime_secret();
    write_owner_only(&passphrase_file, passphrase.as_bytes());
    let created = run([
        "wallet",
        "new",
        "--keystore",
        keystore.to_str().unwrap(),
        "--recovery-out",
        recovery_file.to_str().unwrap(),
        "--passphrase-file",
        passphrase_file.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(created.status.code(), Some(0));

    let started = Instant::now();
    let mut child = Command::new(env!("CARGO_BIN_EXE_bproof"))
        .args([
            "mine",
            "--loop",
            "--submit",
            "--rpc-url",
            &endpoint,
            "--chain-id",
            CHAIN_ID,
            "--mining-core",
            MINING_CORE,
            "--basket",
            common::BASKET,
            "--keystore",
            keystore.to_str().unwrap(),
            "--passphrase-file",
            passphrase_file.to_str().unwrap(),
            "--max-fee",
            "1",
            "--json",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let mut retry_delays = Vec::new();
    let mut events = Vec::new();
    loop {
        line.clear();
        assert!(reader.read_line(&mut line).unwrap() > 0);
        let event: Value = serde_json::from_str(line.trim()).unwrap();
        if event["event"] == "rpcRetry" {
            retry_delays.push(event["retryDelayMs"].as_str().unwrap().to_owned());
            if retry_delays.len() == 2 {
                send_interrupt(child.id());
            }
        }
        let finished = event["event"] == "summary" && event["reason"] == "interrupt";
        events.push(event);
        if finished {
            break;
        }
    }
    let status = child.wait().unwrap();
    stop_refuser.store(true, Ordering::Release);
    refuser.join().unwrap();
    let mut stderr = Vec::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut stderr)
        .unwrap();
    assert_eq!(status.code(), Some(0));
    assert!(stderr.is_empty());
    assert_eq!(retry_delays, ["1000", "2000"]);
    assert!(started.elapsed() >= Duration::from_millis(900));
    let summary = events.last().unwrap();
    assert_eq!(summary["summary"]["genuineFailures"], "0");
    assert_eq!(summary["summary"]["proofsAccepted"], "0");
}

#[test]
fn live_anvil_loop_accepts_two_proofs_then_stops_cleanly() {
    if !PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts")
        .exists()
    {
        report_live_skip("the monorepo contracts tree is unavailable in this checkout");
        return;
    }
    match Command::new("anvil").arg("--version").output() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            report_live_skip(&format!("`anvil` is unavailable: {error}"));
            return;
        }
        Err(error) => panic!("failed to check anvil availability: {error}"),
        Ok(output) if !output.status.success() => {
            report_live_skip(&format!(
                "`anvil --version` failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
            return;
        }
        Ok(_) => {}
    }

    disable_core_dumps_for_children();
    let port = unused_local_port();
    let endpoint = format!("http://127.0.0.1:{port}");
    let directory = temp_directory(port);
    let mut anvil = AnvilGuard::start(port, directory.clone());
    wait_for_anvil(&endpoint, &mut anvil.child);
    rpc(
        &endpoint,
        "anvil_setCode",
        json!(["0x00000000000000000000000000000000000ba5e7", "0x00"]),
    );
    deploy_launch_set(&endpoint, &directory);
    // RC2 uses a 64-block auto-seed margin; advance past it before starting
    // the continuous loop instead of relying on the older 40-block fixture.
    rpc(&endpoint, "anvil_mine", json!(["0x80"]));

    let keystore = directory.join("loop-wallet.json");
    let recovery_file = directory.join("loop-wallet-recovery.txt");
    let passphrase_file = directory.join("loop-passphrase");
    let passphrase = runtime_secret();
    write_owner_only(&passphrase_file, passphrase.as_bytes());
    let created = run([
        "wallet",
        "new",
        "--keystore",
        keystore.to_str().unwrap(),
        "--recovery-out",
        recovery_file.to_str().unwrap(),
        "--passphrase-file",
        passphrase_file.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(created.status.code(), Some(0));
    let wallet: Value = serde_json::from_slice(&created.stdout).unwrap();
    let miner = wallet["address"].as_str().unwrap().to_owned();
    rpc(
        &endpoint,
        "anvil_setBalance",
        json!([miner, "0xde0b6b3a7640000"]),
    );

    let nft = mining_core_child_address(&endpoint, "PROOF_NFT()");
    assert_eq!(mining_core_word(&endpoint, "activeChallengeId()"), 1);
    assert_eq!(mining_core_word(&endpoint, "nftsMintedEver()"), 0);
    assert_fee_refusal_continues(
        &endpoint,
        &keystore,
        &passphrase_file,
        passphrase.as_bytes(),
    );
    assert_eq!(mining_core_word(&endpoint, "activeChallengeId()"), 1);
    assert_eq!(account_transaction_count(&endpoint, &miner), 0);

    let mut child = Command::new(env!("CARGO_BIN_EXE_bproof"))
        .args([
            "mine",
            "--loop",
            "--submit",
            "--rpc-url",
            &endpoint,
            "--chain-id",
            CHAIN_ID,
            "--mining-core",
            MINING_CORE,
            "--basket",
            common::BASKET,
            "--keystore",
            keystore.to_str().unwrap(),
            "--passphrase-file",
            passphrase_file.to_str().unwrap(),
            "--max-fee",
            "1000000000000000000",
            "--threads",
            "2",
            "--watch-interval-ms",
            "50",
            "--json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (lines_tx, lines_rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if lines_tx.send(line.unwrap()).is_err() {
                break;
            }
        }
    });

    let deadline = Instant::now() + Duration::from_secs(90);
    let mut events = Vec::new();
    let mut accepted = Vec::new();
    let mut requested_summary_seen = false;
    let mut interrupt_sent = false;
    while Instant::now() < deadline {
        let line = lines_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|error| {
                panic!("loop produced no event: {error}; prior events: {events:?}")
            });
        let event: Value = serde_json::from_str(&line)
            .unwrap_or_else(|error| panic!("loop line is not JSON: {error}: {line}"));
        if event["event"] == "started" {
            assert_eq!(event["watchIntervalMs"], "50");
            assert_eq!(event["proofHunterFeeWarning"], PROOF_HUNTER_FEE_WARNING);
            writeln!(stdin, "summary").unwrap();
            stdin.flush().unwrap();
        }
        if event["event"] == "summary" && event["reason"] == "requested" {
            requested_summary_seen = true;
        }
        if event["event"] == "proofAccepted" {
            accepted.push(event.clone());
            if accepted.len() == 1 {
                // Each accepted proof selects a seed ahead of the current parent block.
                rpc(&endpoint, "anvil_mine", json!(["0x80"]));
            } else if accepted.len() == 2 {
                send_interrupt(child.id());
                interrupt_sent = true;
            }
        }
        let final_summary = event["event"] == "summary" && event["reason"] == "interrupt";
        events.push(event);
        if final_summary {
            break;
        }
    }
    assert!(
        interrupt_sent,
        "loop did not accept two proofs before timeout"
    );

    drop(stdin);
    let status = child.wait().unwrap();
    reader.join().unwrap();
    let mut stderr = Vec::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut stderr)
        .unwrap();
    assert_eq!(
        status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&stderr)
    );
    assert!(
        stderr.is_empty(),
        "stderr: {}",
        String::from_utf8_lossy(&stderr)
    );
    assert!(
        requested_summary_seen,
        "stdin summary request was not served"
    );
    assert_eq!(accepted.len(), 2);
    assert_eq!(accepted[0]["challengeId"], "1");
    assert_eq!(accepted[1]["challengeId"], "2");
    assert_ne!(
        accepted[0]["transactionHash"],
        accepted[1]["transactionHash"]
    );

    let summary = events
        .iter()
        .rev()
        .find(|event| event["event"] == "summary" && event["reason"] == "interrupt")
        .expect("clean interrupt summary must be emitted");
    assert_eq!(summary["summary"]["proofsAccepted"], "2");
    let expected_nfts = accepted
        .iter()
        .filter(|event| event["proofNftMinted"] == true)
        .count()
        .to_string();
    assert_eq!(summary["summary"]["nftsEarned"], expected_nfts);
    assert_eq!(summary["summary"]["genuineFailures"], "0");
    assert_eq!(summary["summary"]["consecutiveFailures"], "0");
    assert!(decimal(&summary["summary"]["totalFeesPaidWei"]) > 0);

    assert_eq!(mining_core_word(&endpoint, "activeChallengeId()"), 3);
    assert_eq!(mining_core_word(&endpoint, "acceptedProofs()"), 2);
    assert_eq!(mining_core_word(&endpoint, "nftsMintedEver()"), 2);
    assert_eq!(token_balance(&endpoint, &nft, &miner), 2);
    assert_eq!(expected_nfts, "2");
    assert_eq!(account_transaction_count(&endpoint, &miner), 2);

    let output = events
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !output
            .as_bytes()
            .windows(passphrase.len())
            .any(|window| window == passphrase.as_bytes())
    );
    assert!(
        !stderr
            .windows(passphrase.len())
            .any(|window| window == passphrase.as_bytes())
    );
    for event in &events {
        assert!(event.get("event").and_then(Value::as_str).is_some());
        assert!(event.get("elapsedMs").and_then(Value::as_str).is_some());
        assert!(event.get("summary").and_then(Value::as_object).is_some());
        assert_no_plain_transaction_count_key(event);
    }

    println!(
        "live Anvil loop transaction hashes: {}, {}",
        accepted[0]["transactionHash"].as_str().unwrap(),
        accepted[1]["transactionHash"].as_str().unwrap()
    );
}

fn assert_fee_refusal_continues(
    endpoint: &str,
    keystore: &Path,
    passphrase_file: &Path,
    passphrase: &[u8],
) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_bproof"))
        .args([
            "mine",
            "--loop",
            "--submit",
            "--rpc-url",
            endpoint,
            "--chain-id",
            CHAIN_ID,
            "--mining-core",
            MINING_CORE,
            "--basket",
            common::BASKET,
            "--keystore",
            keystore.to_str().unwrap(),
            "--passphrase-file",
            passphrase_file.to_str().unwrap(),
            "--max-fee",
            "0",
            "--threads",
            "1",
            "--watch-interval-ms",
            "10",
            "--json",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let mut refusals = 0_u64;
    let mut output = Vec::new();
    loop {
        line.clear();
        assert!(reader.read_line(&mut line).unwrap() > 0);
        let event: Value = serde_json::from_str(line.trim()).unwrap();
        if event["event"] == "feeRefused" {
            refusals += 1;
            assert_eq!(event["feeCeilingWei"], "0");
            assert_eq!(
                event["wouldHaveAcceptedFeeCeilingWei"],
                event["maximumExposureWei"]
            );
            assert!(matches!(
                event["proofClassification"].as_str(),
                Some("ordinary" | "proofHunter")
            ));
            if refusals == 2 {
                send_interrupt(child.id());
            }
        }
        let finished = event["event"] == "summary" && event["reason"] == "interrupt";
        output.extend_from_slice(line.as_bytes());
        if finished {
            // At least two, not exactly two. The interrupt is asynchronous: the
            // loop can refuse a third submission between the signal being sent
            // and being handled, which made this assertion fail roughly one run
            // in five. The property under test is that fee refusals do not stop
            // the loop and that it exits cleanly when asked — not the exact
            // count, which is a race the miner is entitled to win.
            let refused = [
                "ordinaryProofsFeeRefused",
                "proofHuntersFeeRefused",
                "unknownClassificationFeeRefused",
            ]
            .into_iter()
            .map(|key| {
                event["summary"][key]
                    .as_str()
                    .unwrap_or_else(|| panic!("{key} is reported as a string"))
                    .parse::<u64>()
                    .unwrap_or_else(|_| panic!("{key} is a decimal count"))
            })
            .sum::<u64>();
            assert!(
                refused >= 2,
                "expected at least the two refusals that triggered the interrupt, saw {refused}"
            );
            assert_eq!(event["summary"]["proofsAccepted"], "0");
            assert_eq!(event["summary"]["genuineFailures"], "0");
            break;
        }
    }
    let status = child.wait().unwrap();
    let mut stderr = Vec::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut stderr)
        .unwrap();
    assert_eq!(status.code(), Some(0));
    assert!(
        refusals >= 2,
        "expected at least the two refusals that triggered the interrupt, saw {refusals}"
    );
    assert!(stderr.is_empty());
    assert!(
        !output
            .windows(passphrase.len())
            .any(|window| window == passphrase)
    );
    assert!(
        !stderr
            .windows(passphrase.len())
            .any(|window| window == passphrase)
    );
}

fn assert_no_plain_transaction_count_key(value: &Value) {
    if let Some(fields) = value.as_object() {
        let keys = fields.keys().map(String::as_str).collect::<BTreeSet<_>>();
        assert!(!keys.contains("nonce"));
    }
}

fn send_interrupt(process_id: u32) {
    let output = Command::new("kill")
        .args(["-INT", &process_id.to_string()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "failed to interrupt loop: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn deploy_launch_set(endpoint: &str, directory: &Path) {
    common::deploy(endpoint, directory);
}

fn mining_core_child_address(endpoint: &str, signature: &str) -> String {
    let result = eth_call(endpoint, MINING_CORE, selector(signature));
    let hex = result.as_str().unwrap().strip_prefix("0x").unwrap();
    assert_eq!(hex.len(), 64);
    format!("0x{}", &hex[24..])
}

fn token_balance(endpoint: &str, token: &str, account: &str) -> u128 {
    let mut data = selector("balanceOf(address)");
    data.push_str(&"0".repeat(24));
    data.push_str(account.strip_prefix("0x").unwrap());
    word_to_u128(eth_call(endpoint, token, data).as_str().unwrap())
}

fn mining_core_word(endpoint: &str, signature: &str) -> u128 {
    contract_word(endpoint, MINING_CORE, signature)
}

fn contract_word(endpoint: &str, contract: &str, signature: &str) -> u128 {
    word_to_u128(
        eth_call(endpoint, contract, selector(signature))
            .as_str()
            .unwrap(),
    )
}

fn account_transaction_count(endpoint: &str, account: &str) -> u128 {
    quantity_to_u128(
        rpc(
            endpoint,
            "eth_getTransactionCount",
            json!([account, "latest"]),
        )
        .as_str()
        .unwrap(),
    )
}

fn eth_call(endpoint: &str, to: &str, data: String) -> Value {
    rpc(
        endpoint,
        "eth_call",
        json!([{ "to": to, "data": data }, "latest"]),
    )
}

fn selector(signature: &str) -> String {
    hex(&keccak256(signature.as_bytes()).to_bytes()[..4])
}

fn rpc(endpoint: &str, method: &str, params: Value) -> Value {
    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let body = serde_json::to_vec(&request).unwrap();
    let mut response = ureq::post(endpoint)
        .header("content-type", "application/json")
        .send(body.as_slice())
        .unwrap();
    let response_body = response.body_mut().read_to_string().unwrap();
    let response: Value = serde_json::from_str(&response_body).unwrap();
    assert!(response.get("error").is_none(), "RPC error: {response}");
    response["result"].clone()
}

fn decimal(value: &Value) -> u128 {
    value.as_str().unwrap().parse().unwrap()
}

fn word_to_u128(value: &str) -> u128 {
    u128::from_str_radix(value.strip_prefix("0x").unwrap(), 16).unwrap()
}

fn quantity_to_u128(value: &str) -> u128 {
    word_to_u128(value)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(2 + bytes.len() * 2);
    output.push_str("0x");
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn run<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    Command::new(env!("CARGO_BIN_EXE_bproof"))
        .args(args)
        .output()
        .unwrap()
}

fn runtime_secret() -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(bytes.as_mut());
    Zeroizing::new(hex(bytes.as_slice()).trim_start_matches("0x").to_owned())
}

fn temp_directory(port: u16) -> PathBuf {
    let id = NEXT_TEMP_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "bproof-loop-test-{}-{port}-{id}",
        std::process::id()
    ));
    fs::create_dir(&path).unwrap();
    path
}

fn write_owner_only(path: &Path, contents: &[u8]) {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(contents).unwrap();
}

fn unused_local_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_for_anvil(endpoint: &str, child: &mut Child) {
    let address = endpoint.strip_prefix("http://").unwrap();
    for _ in 0..50 {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("anvil exited before becoming ready: {status}");
        }
        if TcpStream::connect(address).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("anvil did not become ready at {endpoint}");
}

fn report_live_skip(reason: &str) {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "SKIP live Anvil continuous loop: {reason}");
}

struct AnvilGuard {
    child: Child,
    directory: PathBuf,
}

struct DirectoryGuard(PathBuf);

impl Drop for DirectoryGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

impl AnvilGuard {
    fn start(port: u16, directory: PathBuf) -> Self {
        let child = Command::new("anvil")
            .args([
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--chain-id",
                CHAIN_ID,
                "--timestamp",
                "1800000000",
                "--block-base-fee-per-gas",
                "1",
                "--silent",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Self { child, directory }
    }
}

impl Drop for AnvilGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn disable_core_dumps_for_children() {
    let (_, hard_limit) = rlimit::Resource::CORE.get().unwrap();
    rlimit::Resource::CORE.set(0, hard_limit).unwrap();
}
