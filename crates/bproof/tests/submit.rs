use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use proof_core::keccak256;
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};
use zeroize::Zeroizing;

static NEXT_TEMP_DIRECTORY: AtomicU64 = AtomicU64::new(0);

mod common;
const MINING_CORE: &str = common::MINING_CORE;
const CHAIN_ID: &str = "31337";
const SUBMISSION_WARNING: &str = "Another miner may consume this challenge before inclusion, and this transaction may fail. Receipt success is accepted only after transaction and event consistency checks; the configured RPC can still withhold or delay data and remains a trust source.";
const PROOF_HUNTER_FEE_WARNING: &str = "Every accepted HunterMiningCore proof mints one NFT and pays no liquid HUNTER. Token activation and backing are separate from mining; no backing amount is promised. --max-fee must cover the estimated mint transaction or submission is refused.";

#[test]
fn submit_requires_an_explicit_total_fee_ceiling() {
    let output = run([
        "submit",
        "--rpc-url",
        "http://127.0.0.1:1",
        "--chain-id",
        CHAIN_ID,
        "--mining-core",
        MINING_CORE,
        "--mining-nonce",
        "0",
        "--keystore",
        "missing-wallet.json",
    ]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("--max-fee"), "error: {error}");
}

#[test]
fn mine_submit_requires_an_explicit_total_fee_ceiling() {
    let output = run([
        "mine",
        "--submit",
        "--rpc-url",
        "http://127.0.0.1:1",
        "--chain-id",
        CHAIN_ID,
        "--mining-core",
        MINING_CORE,
        "--keystore",
        "missing-wallet.json",
    ]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("--max-fee is required"), "error: {error}");
    assert!(error.contains("has no default"), "error: {error}");
}

#[test]
fn help_documents_submission_exit_codes_and_explicit_nonce_names() {
    let top = run(["--help"]);
    let submit = run(["submit", "--help"]);
    let mine = run(["mine", "--help"]);

    assert_eq!(top.status.code(), Some(0));
    assert_eq!(submit.status.code(), Some(0));
    assert_eq!(mine.status.code(), Some(0));
    let top = String::from_utf8_lossy(&top.stdout);
    let submit = String::from_utf8_lossy(&submit.stdout);
    let mine = String::from_utf8_lossy(&mine.stdout);
    assert!(top.contains("3  Submission refused"));
    assert!(submit.contains("--mining-nonce"));
    assert!(submit.contains("--max-fee"));
    assert!(submit.contains("mandatory and has no default"));
    assert!(submit.contains("no liquid token reward"));
    assert!(submit.contains("estimated mint transaction"));
    assert!(mine.contains("--submit"));
    assert!(mine.contains("--max-fee"));
    assert!(mine.contains("no liquid token reward"));
    assert!(mine.contains("estimated mint transaction"));
}

#[test]
fn live_anvil_mines_and_submits_one_real_proof() {
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
    // RC2 uses a 64-block auto-seed margin; advance beyond it before the
    // first fee/submit rehearsal.
    rpc(&endpoint, "anvil_mine", json!(["0x80"]));

    let keystore = directory.join("mining-wallet.json");
    let recovery_file = directory.join("mining-wallet-recovery.txt");
    let passphrase_file = directory.join("passphrase");
    let passphrase = runtime_secret();
    write_owner_only(&passphrase_file, passphrase.as_bytes());
    let wallet_output = run([
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
    let wallet_stdout = Zeroizing::new(wallet_output.stdout);
    let wallet_stderr = Zeroizing::new(wallet_output.stderr);
    assert_eq!(wallet_output.status.code(), Some(0));
    assert!(wallet_stderr.is_empty());
    let wallet: Value = serde_json::from_slice(wallet_stdout.as_slice()).unwrap();
    let miner = wallet["address"].as_str().unwrap().to_owned();
    // Fund the new wallet through an actual transfer, as an external wallet does.
    let accounts = rpc(&endpoint, "eth_accounts", json!([]));
    let funding_hash = rpc(
        &endpoint,
        "eth_sendTransaction",
        json!([{
            "from": accounts[0], "to": miner, "value": "0xde0b6b3a7640000"
        }]),
    );
    let funding_receipt = rpc(
        &endpoint,
        "eth_getTransactionReceipt",
        json!([funding_hash]),
    );
    assert_eq!(funding_receipt["status"], "0x1");
    assert_eq!(
        rpc(&endpoint, "eth_getBalance", json!([miner, "latest"])),
        "0xde0b6b3a7640000"
    );

    let project_token = mining_core_child_address(&endpoint, "PROOF_NFT()");
    let reward_before = token_balance(&endpoint, &project_token, &miner);
    let challenge_before = mining_core_word(&endpoint, "activeChallengeId()");
    let account_nonce_before = account_transaction_count(&endpoint, &miner);
    assert_eq!(reward_before, 0);
    assert_eq!(challenge_before, 1);
    assert_eq!(account_nonce_before, 0);

    let wrong_chain = run(mine_submit_args(
        &endpoint,
        &keystore,
        &passphrase_file,
        "1000000000000000000",
        "1",
        Some(("10", "3")),
    ));
    assert_no_secret(&wrong_chain, passphrase.as_bytes());
    assert_eq!(wrong_chain.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&wrong_chain.stderr).contains("wrong chain id"));
    assert_eq!(account_transaction_count(&endpoint, &miner), 0);

    let unread_passphrase_file = directory.join("must-not-be-read");
    let fee_refused = run(mine_submit_args(
        &endpoint,
        &keystore,
        &unread_passphrase_file,
        "0",
        CHAIN_ID,
        Some(("10", "3")),
    ));
    assert_no_secret(&fee_refused, passphrase.as_bytes());
    assert_eq!(fee_refused.status.code(), Some(3));
    assert_eq!(
        String::from_utf8_lossy(&fee_refused.stderr).trim(),
        format!("WARNING: {PROOF_HUNTER_FEE_WARNING}")
    );
    let refused: Value = serde_json::from_slice(&fee_refused.stdout).unwrap();
    assert_eq!(refused["status"], "feeRefused");
    assert_eq!(refused["feeCeilingWei"], "0");
    assert_eq!(refused["baseFeePerGasWei"], "10");
    assert_eq!(refused["priorityFeePerGasWei"], "3");
    assert_eq!(refused["maxFeePerGasWei"], "23");
    assert!(decimal(&refused["maximumExposureWei"]) > 0);
    assert_eq!(
        refused["wouldHaveAcceptedFeeCeilingWei"],
        refused["maximumExposureWei"]
    );
    assert!(matches!(
        refused["proofClassification"].as_str(),
        Some("proofHunter")
    ));
    assert!(
        refused["reason"]
            .as_str()
            .unwrap()
            .contains("maximum exposure")
    );
    assert_exact_keys(
        &refused,
        [
            "baseFeePerGasWei",
            "estimatedGas",
            "feeCeilingWei",
            "gasLimit",
            "gasMarginPercent",
            "maxFeePerGasWei",
            "maximumExposureWei",
            "miner",
            "miningNonce",
            "priorityFeePerGasWei",
            "proofClassification",
            "reason",
            "stateSource",
            "status",
            "warning",
            "wouldHaveAcceptedFeeCeilingWei",
        ],
    );
    assert_eq!(account_transaction_count(&endpoint, &miner), 0);

    let submitted = run(mine_submit_args(
        &endpoint,
        &keystore,
        &passphrase_file,
        "1000000000000000000",
        CHAIN_ID,
        None,
    ));
    assert_no_secret(&submitted, passphrase.as_bytes());
    assert_eq!(submitted.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&submitted.stderr).trim(),
        format!("WARNING: {PROOF_HUNTER_FEE_WARNING}")
    );
    let submitted: Value = serde_json::from_slice(&submitted.stdout).unwrap();
    assert_eq!(submitted["status"], "mined");
    assert_eq!(submitted["miner"], miner);
    assert_eq!(submitted["accountNonce"], "0");
    assert!(submitted["miningNonce"].as_str().is_some());
    let base_fee_per_gas = decimal(&submitted["baseFeePerGasWei"]);
    let priority_fee_per_gas = decimal(&submitted["priorityFeePerGasWei"]);
    assert_eq!(
        decimal(&submitted["maxFeePerGasWei"]),
        base_fee_per_gas * 2 + priority_fee_per_gas
    );
    assert_eq!(submitted["gasMarginPercent"], "100");
    assert_eq!(submitted["stateSource"], "chain");
    assert_eq!(submitted["warning"], SUBMISSION_WARNING);
    assert!(matches!(
        submitted["proofClassification"].as_str(),
        Some("proofHunter")
    ));
    assert!(decimal(&submitted["feePaidWei"]) > 0);
    assert!(decimal(&submitted["feePaidWei"]) <= decimal(&submitted["maximumExposureWei"]));
    assert_exact_keys(
        &submitted,
        [
            "accountNonce",
            "baseFeePerGasWei",
            "estimatedGas",
            "feeCeilingWei",
            "feePaidWei",
            "gasLimit",
            "gasMarginPercent",
            "maxFeePerGasWei",
            "maximumExposureWei",
            "miner",
            "miningNonce",
            "nftTokenId",
            "priorityFeePerGasWei",
            "proofClassification",
            "stateSource",
            "status",
            "transactionHash",
            "warning",
        ],
    );
    assert!(submitted.get("nonce").is_none());

    let transaction_hash = submitted["transactionHash"].as_str().unwrap();
    assert_eq!(transaction_hash.len(), 66);
    assert_eq!(mining_core_word(&endpoint, "activeChallengeId()"), 2);
    assert!(token_balance(&endpoint, &project_token, &miner) > reward_before);
    assert_eq!(account_transaction_count(&endpoint, &miner), 1);
    assert_eq!(submitted["nftTokenId"], "1");
    let owner_call = format!("{}{:064x}", selector("ownerOf(uint256)"), 1);
    let owner = eth_call(&endpoint, &project_token, owner_call);
    assert_eq!(&owner.as_str().unwrap()[26..], &miner[2..]);
    // A new CLI process restores the same encrypted wallet and uses the next
    // on-chain account nonce, rather than replaying the already-mined proof.
    rpc(&endpoint, "anvil_mine", json!(["0x80"]));
    let restarted = run(mine_submit_args(
        &endpoint,
        &keystore,
        &passphrase_file,
        "1000000000000000000",
        CHAIN_ID,
        None,
    ));
    assert_no_secret(&restarted, passphrase.as_bytes());
    assert_eq!(
        restarted.status.code(),
        Some(0),
        "{}",
        format_args!(
            "{} {}",
            String::from_utf8_lossy(&restarted.stderr),
            String::from_utf8_lossy(&restarted.stdout)
        )
    );
    let restarted: Value = serde_json::from_slice(&restarted.stdout).unwrap();
    assert_eq!(restarted["accountNonce"], "1");
    assert_eq!(restarted["nftTokenId"], "2");
    assert_eq!(token_balance(&endpoint, &project_token, &miner), 2);
    assert_eq!(mining_core_word(&endpoint, "nftsMintedEver()"), 2);
    println!("live Anvil submission and restarted wallet verified: {transaction_hash}");
}

#[test]
fn lost_send_reply_recovers_exact_signed_transaction_before_new_mining() {
    if !PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts")
        .exists()
    {
        report_live_skip("the monorepo contracts tree is unavailable in this checkout");
        return;
    }
    if Command::new("anvil").arg("--version").output().is_err() {
        report_live_skip("`anvil` is unavailable");
        return;
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
    rpc(&endpoint, "anvil_mine", json!(["0x80"]));

    let keystore = directory.join("recovery-wallet.json");
    let recovery_file = directory.join("recovery-wallet-phrase.txt");
    let passphrase_file = directory.join("recovery-passphrase");
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
    let miner = wallet["address"].as_str().unwrap();
    rpc(
        &endpoint,
        "anvil_setBalance",
        json!([miner, "0xde0b6b3a7640000"]),
    );

    let proxy = LostSendReplyProxy::start(endpoint.clone());
    let first = run(mine_submit_args(
        &proxy.endpoint,
        &keystore,
        &passphrase_file,
        "1000000000000000000",
        CHAIN_ID,
        None,
    ));
    assert_no_secret(&first, passphrase.as_bytes());
    assert_eq!(first.status.code(), Some(2));
    let first_error = String::from_utf8_lossy(&first.stderr);
    assert!(
        first_error.contains("durable recovery journal retained"),
        "{first_error}"
    );
    let pending = keystore.with_file_name("recovery-wallet.json.pending-submission.json");
    assert!(pending.exists());
    assert_eq!(account_transaction_count(&endpoint, miner), 1);

    let recovered = run(mine_submit_args(
        &endpoint,
        &keystore,
        &passphrase_file,
        "1000000000000000000",
        CHAIN_ID,
        None,
    ));
    assert_no_secret(&recovered, passphrase.as_bytes());
    assert_eq!(
        recovered.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&recovered.stdout),
        String::from_utf8_lossy(&recovered.stderr)
    );
    let recovered: Value = serde_json::from_slice(&recovered.stdout).unwrap();
    assert_eq!(recovered["accountNonce"], "0");
    assert_eq!(recovered["nftTokenId"], "1");
    assert_eq!(account_transaction_count(&endpoint, miner), 1);
    assert_eq!(mining_core_word(&endpoint, "nftsMintedEver()"), 1);
    assert!(!pending.exists());
    drop(proxy);
}

fn mine_submit_args(
    endpoint: &str,
    keystore: &Path,
    passphrase_file: &Path,
    max_fee: &str,
    chain_id: &str,
    fee_overrides: Option<(&str, &str)>,
) -> Vec<String> {
    let mut args = vec![
        "mine".to_owned(),
        "--submit".to_owned(),
        "--rpc-url".to_owned(),
        endpoint.to_owned(),
        "--chain-id".to_owned(),
        chain_id.to_owned(),
        "--mining-core".to_owned(),
        MINING_CORE.to_owned(),
        "--basket".to_owned(),
        common::BASKET.to_owned(),
        "--keystore".to_owned(),
        keystore.display().to_string(),
        "--passphrase-file".to_owned(),
        passphrase_file.display().to_string(),
        "--max-fee".to_owned(),
        max_fee.to_owned(),
        "--threads".to_owned(),
        "1".to_owned(),
        "--max-attempts".to_owned(),
        "100000".to_owned(),
        "--json".to_owned(),
    ];
    if let Some((base_fee_per_gas, priority_fee_per_gas)) = fee_overrides {
        args.extend([
            "--base-fee-per-gas".to_owned(),
            base_fee_per_gas.to_owned(),
            "--priority-fee-per-gas".to_owned(),
            priority_fee_per_gas.to_owned(),
        ]);
    }
    args
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
    word_to_u128(
        eth_call(endpoint, MINING_CORE, selector(signature))
            .as_str()
            .unwrap(),
    )
}

fn account_transaction_count(endpoint: &str, account: &str) -> u128 {
    let result = rpc(
        endpoint,
        "eth_getTransactionCount",
        json!([account, "latest"]),
    );
    quantity_to_u128(result.as_str().unwrap())
}

fn eth_call(endpoint: &str, to: &str, data: String) -> Value {
    rpc(
        endpoint,
        "eth_call",
        json!([{ "to": to, "data": data }, "latest"]),
    )
}

fn selector(signature: &str) -> String {
    let bytes = keccak256(signature.as_bytes()).to_bytes();
    hex(&bytes[..4])
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

fn assert_no_secret(output: &Output, secret: &[u8]) {
    assert!(!find_bytes(&output.stdout, secret));
    assert!(!find_bytes(&output.stderr, secret));
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn assert_exact_keys<const N: usize>(value: &Value, expected: [&str; N]) {
    let actual = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected = expected.into_iter().collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
}

fn runtime_secret() -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(bytes.as_mut());
    Zeroizing::new(hex(bytes.as_slice()).trim_start_matches("0x").to_owned())
}

fn temp_directory(port: u16) -> PathBuf {
    let id = NEXT_TEMP_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "bproof-submit-test-{}-{port}-{id}",
        std::process::id()
    ));
    fs::create_dir(&path).unwrap();
    path
}

#[cfg(unix)]
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

#[cfg(not(unix))]
fn write_owner_only(path: &Path, contents: &[u8]) {
    fs::write(path, contents).unwrap();
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
    let _ = writeln!(stderr, "SKIP live Anvil submission: {reason}");
}

struct AnvilGuard {
    child: Child,
    directory: PathBuf,
}

struct LostSendReplyProxy {
    endpoint: String,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl LostSendReplyProxy {
    fn start(upstream: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            let dropped = AtomicBool::new(false);
            while !thread_stop.load(Ordering::Acquire) {
                let (mut stream, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("lost-reply proxy accept failed: {error}"),
                };
                // macOS can propagate O_NONBLOCK from the listener to an
                // accepted socket. The proxy reads one complete HTTP request,
                // so make that accepted connection explicitly blocking.
                stream.set_nonblocking(false).unwrap();
                let body = read_http_request_body(&mut stream);
                let request: Value = serde_json::from_slice(&body).unwrap();
                let is_send = request["method"] == "eth_sendRawTransaction";
                let mut response = ureq::post(&upstream)
                    .header("content-type", "application/json")
                    .send(body.as_slice())
                    .unwrap();
                let response_body = response.body_mut().read_to_string().unwrap();
                if is_send && !dropped.swap(true, Ordering::AcqRel) {
                    drop(stream);
                    continue;
                }
                write_http_response(&mut stream, &response_body);
            }
        });
        Self {
            endpoint,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for LostSendReplyProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            // Never create a second panic from a test-fixture destructor. A
            // proxy thread failure already causes the transaction assertions
            // in the owning test to fail with the useful chain evidence.
            let _ = thread.join();
        }
    }
}

fn read_http_request_body(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 8_192];
    let (header_end, content_length) = loop {
        let read = stream.read(&mut buffer).unwrap();
        assert_ne!(read, 0);
        request.extend_from_slice(&buffer[..read]);
        let Some(start) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") else {
            continue;
        };
        let headers = std::str::from_utf8(&request[..start]).unwrap();
        let length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap();
        break (start + 4, length);
    };
    while request.len() < header_end + content_length {
        let read = stream.read(&mut buffer).unwrap();
        assert_ne!(read, 0);
        request.extend_from_slice(&buffer[..read]);
    }
    request[header_end..header_end + content_length].to_vec()
}

fn write_http_response(stream: &mut TcpStream, body: &str) {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).unwrap();
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

#[cfg(unix)]
fn disable_core_dumps_for_children() {
    let (_, hard_limit) = rlimit::Resource::CORE.get().unwrap();
    rlimit::Resource::CORE.set(0, hard_limit).unwrap();
}

#[cfg(not(unix))]
fn disable_core_dumps_for_children() {}
