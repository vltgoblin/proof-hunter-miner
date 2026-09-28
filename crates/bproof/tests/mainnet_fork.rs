//! Mining v2 end to end on a local fork of Robinhood Chain mainnet (4663).
//!
//! Opt-in: set `BPROOF_FORK_RPC_URL` (for example
//! `https://rpc.mainnet.chain.robinhood.com`) and put Foundry's `anvil` on PATH.
//! The test starts one anvil bound to 127.0.0.1, uses anvil cheats only on that
//! fork, never sends anything to the public chain, and stops anvil when done.
//!
//! It runs the real `bproof` binary and checks, on canonical fork state:
//! - an unstaked wallet is told how to stake and never sends a transaction;
//! - a staked wallet never refreshes an expired round before the next one opens;
//! - once open, the CLI refreshes, then claims through the router (loop and
//!   single-shot), and each Hunter NFT lands in the CLI wallet.

use std::io::{BufRead, BufReader};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Output, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use proof_core::keccak256;
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};

const CORE: &str = "0xf213854c6d5d4334d23d452574556bd53ca24c2c";
const BASKET: &str = "0xd0601ce157db5bdc3162bbac2a2c8af5320d9eec";
const CHAIN_ID: &str = "4663";
/// Generous per-transaction ceiling for the fork (0.1 ETH).
const MAX_FEE: &str = "100000000000000000";
/// 1M HUNTER, the stake unit on mainnet.
const UNIT_WEI: u128 = 1_000_000 * 1_000_000_000_000_000_000;
/// An easy target (2^252 - 1) so a proof in any band takes a few thousand hashes.
const EASY_TARGET: &str = "0x0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
/// HuntStake storage: slot 1 `totalAssigned`, slot 20 `_openAt` (forge inspect storageLayout).
const STAKE_TOTAL_ASSIGNED_SLOT: &str = "0x1";
const STAKE_OPEN_AT_SLOT: &str = "0x14";
/// HunterMiningCore storage slot 4 is `currentTarget`.
const CORE_TARGET_SLOT: &str = "0x4";
/// The HUNTER token keeps balances in mapping slot 0.
const TOKEN_BALANCES_SLOT: u8 = 0;

#[test]
fn mainnet_fork_claims_through_the_router_and_never_spends_unstaked() {
    let Ok(fork_url) = std::env::var("BPROOF_FORK_RPC_URL") else {
        skip("BPROOF_FORK_RPC_URL is not set");
        return;
    };
    if Command::new("anvil").arg("--version").output().is_err() {
        skip("`anvil` is not on PATH");
        return;
    }
    disable_core_dumps_for_children();

    let directory = temp_directory();
    let port = unused_local_port();
    let rpc_url = format!("http://127.0.0.1:{port}");
    let mut anvil = Anvil::start(&fork_url, port, &directory);
    anvil.wait_ready(&rpc_url);
    let chain = Chain { url: rpc_url };
    // Forked blocks carry no blob-gas fields: mine one local block first.
    chain.rpc("anvil_mine", json!(["0x1"]));

    let stake = chain.address_call(CORE, "miningPower()");
    let router = chain.address_call(&stake, "ROUTER()");
    let hunter_token = chain.address_call(&stake, "HUNTER()");
    let nft = chain.address_call(&router, "NFT()");
    assert_eq!(chain.address_call(&router, "MODULE()"), stake);
    chain.set_storage(CORE, CORE_TARGET_SLOT, EASY_TARGET);

    let passphrase = directory.join("passphrase");
    write_owner_only(&passphrase, random_hex(24).as_bytes());

    // ---- 1. An unstaked wallet is told how to stake and never sends anything.
    let unstaked = new_wallet(&directory, "unstaked", &passphrase);
    chain.fund(&unstaked.address);
    let balance_before = chain.balance(&unstaked.address);
    let single = cli(&mine_args(
        &chain,
        &unstaked,
        &passphrase,
        Some(&router),
        false,
    ));
    assert_eq!(single.status.code(), Some(4), "{}", describe(&single));
    let result: Value = serde_json::from_slice(&single.stdout).unwrap();
    assert_eq!(result["status"], "notStaked");
    let message = result["message"].as_str().unwrap();
    assert!(message.starts_with("Not staked: Stake 1M HUNTER tokens to this wallet in the app: app.proofhunter.fun/app/mine (your CLI wallet address: 0x"), "{message}");
    assert!(
        message.to_lowercase().contains(&unstaked.address),
        "{message}"
    );
    let looped = cli(&mine_args(&chain, &unstaked, &passphrase, None, true));
    assert_eq!(looped.status.code(), Some(4), "{}", describe(&looped));
    let events = json_lines(&looped.stdout);
    assert!(events.iter().any(|event| event["event"] == "notStaked"));
    assert_eq!(events.last().unwrap()["reason"], "notStaked");
    assert_eq!(
        chain.nonce(&unstaked.address),
        0,
        "an unstaked wallet sent a transaction"
    );
    assert_eq!(chain.balance(&unstaked.address), balance_before);

    // ---- 2. Stake 1M HUNTER for the CLI wallet through the real contract calls.
    let miner = new_wallet(&directory, "miner", &passphrase);
    chain.fund(&miner.address);
    let depositor = "0x000000000000000000000000000000000000d00d";
    chain.fund(depositor);
    chain.set_storage(
        &hunter_token,
        &mapping_slot(depositor, TOKEN_BALANCES_SLOT),
        &word_hex(UNIT_WEI),
    );
    chain.send_as(
        depositor,
        &hunter_token,
        "approve(address,uint256)",
        &[address_word(&stake), word_hex(UNIT_WEI)],
    );
    chain.send_as(depositor, &stake, "deposit(uint256)", &[word_hex(UNIT_WEI)]);
    chain.send_as(
        depositor,
        &stake,
        "assign(address,uint256)",
        &[address_word(&miner.address), word_hex(UNIT_WEI)],
    );
    assert_eq!(
        chain.uint_call(
            &stake,
            "assignedOf(address)",
            &[address_word(&miner.address)]
        ),
        UNIT_WEI
    );

    // ---- 3. Expired, but the next round is not open: never refresh.
    let expired_id = expire_round(&chain);
    let now = chain.timestamp();
    chain.set_storage(&stake, STAKE_OPEN_AT_SLOT, &word_hex(u128::from(now + 600)));
    let early = cli(&mine_args(
        &chain,
        &miner,
        &passphrase,
        Some(&router),
        false,
    ));
    assert_eq!(early.status.code(), Some(4), "{}", describe(&early));
    let early: Value = serde_json::from_slice(&early.stdout).unwrap();
    assert_eq!(early["status"], "waiting");
    assert_eq!(
        chain.nonce(&miner.address),
        0,
        "refreshed before the round opened"
    );
    assert_eq!(
        chain.uint_call(CORE, "activeChallengeId()", &[]),
        expired_id
    );

    // ---- 4. Open the round; the loop refreshes it, then claims through the router.
    chain.rpc("evm_increaseTime", json!([700]));
    chain.rpc("anvil_mine", json!(["0x1"]));
    // Make this wallet the round's only stake so it is certain to be selected.
    chain.set_storage(&stake, STAKE_TOTAL_ASSIGNED_SLOT, &word_hex(UNIT_WEI));
    let mut miner_loop = LoopProcess::start(&mine_args(&chain, &miner, &passphrase, None, true));
    let refresh = miner_loop.wait_for(&["seedRefreshed"], Duration::from_secs(120));
    assert_eq!(refresh["event"], "seedRefreshed", "{refresh}");
    assert_eq!(
        chain.uint_call(CORE, "activeChallengeId()", &[]),
        expired_id + 1
    );
    assert!(
        chain.uint_call(&stake, "challengeOpenedAt()", &[])
            >= chain.uint_call(&stake, "openAt()", &[])
    );
    chain.rpc("anvil_mine", json!(["0x4"]));
    let accepted = miner_loop.wait_for(&["proofAccepted"], Duration::from_secs(300));
    let token_id: u128 = accepted["nftTokenId"].as_str().unwrap().parse().unwrap();
    assert!(
        accepted["message"]
            .as_str()
            .unwrap()
            .starts_with("Hunter NFT found")
    );
    assert_claimed_to(&chain, &accepted, &miner.address, &router, &nft, token_id);
    let summary = miner_loop.interrupt();
    assert_eq!(summary.0, Some(0), "loop did not stop cleanly");
    assert!(
        summary.1.iter().all(|event| event["event"] != "proofFound"
            || event["challengeId"].as_str() == Some(&(expired_id + 1).to_string())),
        "the loop submitted on a round it could not claim"
    );

    // ---- 5. The next round: single-shot refresh, then a single-shot claim.
    let open_at = chain.uint_call(&stake, "openAt()", &[]);
    let wait = u64::try_from(open_at)
        .unwrap()
        .saturating_sub(chain.timestamp())
        + 5;
    chain.rpc("evm_increaseTime", json!([wait]));
    let second_expired = expire_round(&chain);
    chain.set_storage(&stake, STAKE_TOTAL_ASSIGNED_SLOT, &word_hex(UNIT_WEI));
    let refreshed = cli(&mine_args(
        &chain,
        &miner,
        &passphrase,
        Some(&router),
        false,
    ));
    assert_eq!(refreshed.status.code(), Some(0), "{}", describe(&refreshed));
    let refreshed: Value = serde_json::from_slice(&refreshed.stdout).unwrap();
    assert_eq!(refreshed["status"], "seedRefreshed");
    assert_eq!(
        chain.uint_call(CORE, "activeChallengeId()", &[]),
        second_expired + 1
    );
    chain.rpc("anvil_mine", json!(["0x4"]));
    let claimed = retry_cold_fork(|| {
        cli(&mine_args(
            &chain,
            &miner,
            &passphrase,
            Some(&router),
            false,
        ))
    });
    assert_eq!(claimed.status.code(), Some(0), "{}", describe(&claimed));
    let claimed: Value = serde_json::from_slice(&claimed.stdout).unwrap();
    assert_eq!(claimed["status"], "mined", "{claimed}");
    let second_id: u128 = claimed["nftTokenId"].as_str().unwrap().parse().unwrap();
    assert_eq!(second_id, token_id + 1);
    assert_claimed_to(&chain, &claimed, &miner.address, &router, &nft, second_id);

    // The unstaked wallet still never sent anything.
    assert_eq!(chain.nonce(&unstaked.address), 0);
    drop(anvil);
    let _ = std::fs::remove_dir_all(directory);
}

/// The claim went to the router from the CLI wallet, and the Hunter NFT is the wallet's.
fn assert_claimed_to(
    chain: &Chain,
    result: &Value,
    wallet: &str,
    router: &str,
    nft: &str,
    token_id: u128,
) {
    let hash = result["transactionHash"].as_str().unwrap();
    let transaction = chain.rpc("eth_getTransactionByHash", json!([hash]));
    assert_eq!(transaction["from"].as_str().unwrap().to_lowercase(), wallet);
    assert_eq!(transaction["to"].as_str().unwrap().to_lowercase(), router);
    let input = transaction["input"].as_str().unwrap();
    assert!(
        input.starts_with(&selector_hex("claim(address,uint256,address)")),
        "{input}"
    );
    let owner = chain.address_call_with(nft, "ownerOf(uint256)", &[word_hex(token_id)]);
    assert_eq!(owner, wallet, "the Hunter NFT is not in the CLI wallet");
    let receipt = chain.rpc("eth_getTransactionReceipt", json!([hash]));
    assert_eq!(receipt["status"], "0x1");
    let claimed_topic = hex(&keccak256(b"HunterClaimed(address,uint256,uint8,uint256)").to_bytes());
    assert!(receipt["logs"].as_array().unwrap().iter().any(|log| {
        log["address"].as_str().unwrap().to_lowercase() == router
            && log["topics"][0].as_str() == Some(claimed_topic.as_str())
    }));
}

/// Mines past the seed's readable window so the current round is expired; returns its ID.
fn expire_round(chain: &Chain) -> u128 {
    // 257+ blocks after the seed block: challengeState() becomes EXPIRED (2).
    chain.rpc("anvil_mine", json!(["0x110"]));
    assert_eq!(
        chain.uint_call(CORE, "challengeState()", &[]),
        2,
        "round did not expire"
    );
    chain.uint_call(CORE, "activeChallengeId()", &[])
}

/// A cold fork can take longer than the CLI's 15 s RPC timeout on its first claim simulation.
fn retry_cold_fork(mut run: impl FnMut() -> Output) -> Output {
    let mut output = run();
    for _ in 0..3 {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.status.code() == Some(2) && stderr.contains("timeout") {
            output = run();
        } else {
            break;
        }
    }
    output
}

fn mine_args(
    chain: &Chain,
    wallet: &Wallet,
    passphrase: &Path,
    router: Option<&str>,
    loop_mode: bool,
) -> Vec<String> {
    let mut args = vec![
        "mine".to_owned(),
        "--submit".to_owned(),
        "--rpc-url".to_owned(),
        chain.url.clone(),
        "--chain-id".to_owned(),
        CHAIN_ID.to_owned(),
        "--mining-core".to_owned(),
        CORE.to_owned(),
        "--basket".to_owned(),
        BASKET.to_owned(),
        "--keystore".to_owned(),
        wallet.keystore.display().to_string(),
        "--passphrase-file".to_owned(),
        passphrase.display().to_string(),
        "--max-fee".to_owned(),
        MAX_FEE.to_owned(),
        "--threads".to_owned(),
        "2".to_owned(),
        "--json".to_owned(),
    ];
    if let Some(router) = router {
        args.push("--router".to_owned());
        args.push(router.to_owned());
    }
    if loop_mode {
        args.push("--loop".to_owned());
        args.push("--watch-interval-ms".to_owned());
        args.push("250".to_owned());
    }
    args
}

struct Wallet {
    address: String,
    keystore: PathBuf,
}

fn new_wallet(directory: &Path, name: &str, passphrase: &Path) -> Wallet {
    let keystore = directory.join(format!("{name}.json"));
    let output = cli(&[
        "wallet".to_owned(),
        "new".to_owned(),
        "--keystore".to_owned(),
        keystore.display().to_string(),
        "--recovery-out".to_owned(),
        directory
            .join(format!("{name}-recovery.txt"))
            .display()
            .to_string(),
        "--passphrase-file".to_owned(),
        passphrase.display().to_string(),
        "--json".to_owned(),
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", describe(&output));
    let created: Value = serde_json::from_slice(&output.stdout).unwrap();
    Wallet {
        address: created["address"].as_str().unwrap().to_lowercase(),
        keystore,
    }
}

fn cli(args: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bproof"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("bproof must run")
}

fn describe(output: &Output) -> String {
    format!(
        "exit {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn json_lines(bytes: &[u8]) -> Vec<Value> {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter(|line| line.starts_with('{'))
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

/// A `--loop` run whose JSON events are read as they arrive.
struct LoopProcess {
    child: Child,
    events: Receiver<Value>,
    seen: Vec<Value>,
}

impl LoopProcess {
    fn start(args: &[String]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_bproof"))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("bproof loop must start");
        let stdout: ChildStdout = child.stdout.take().unwrap();
        let (sender, events) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Ok(value) = serde_json::from_str::<Value>(&line)
                    && sender.send(value).is_err()
                {
                    break;
                }
            }
        });
        Self {
            child,
            events,
            seen: Vec::new(),
        }
    }

    fn wait_for(&mut self, kinds: &[&str], timeout: Duration) -> Value {
        let deadline = Instant::now() + timeout;
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match self.events.recv_timeout(left) {
                Ok(event) => {
                    self.seen.push(event.clone());
                    let kind = event["event"].as_str().unwrap_or_default();
                    assert_ne!(kind, "notStaked", "{event}");
                    assert!(
                        !(kind == "failure" && event["fatal"] == true),
                        "loop failed: {event}"
                    );
                    if kinds.contains(&kind) {
                        return event;
                    }
                }
                Err(_) => break,
            }
        }
        panic!("no {kinds:?} event; events so far: {:#?}", self.seen);
    }

    /// Ctrl-C, then the exit code and every event.
    fn interrupt(mut self) -> (Option<i32>, Vec<Value>) {
        let _ = Command::new("kill")
            .args(["-INT", &self.child.id().to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(60);
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status.code();
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                break None;
            }
            thread::sleep(Duration::from_millis(100));
        };
        while let Ok(event) = self.events.recv_timeout(Duration::from_millis(500)) {
            self.seen.push(event);
        }
        (status, std::mem::take(&mut self.seen))
    }
}

impl Drop for LoopProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ------------------------------------------------------------------ fork chain

struct Anvil {
    child: Child,
}

impl Anvil {
    fn start(fork_url: &str, port: u16, directory: &Path) -> Self {
        let log = std::fs::File::create(directory.join("anvil.log")).unwrap();
        let child = Command::new("anvil")
            .args([
                "--fork-url",
                fork_url,
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                // Cancun keeps each local block free of history-contract reads from the remote node.
                "--hardfork",
                "cancun",
                "--retries",
                "10",
                "--timeout",
                "60000",
            ])
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("anvil must start");
        Self { child }
    }

    fn wait_ready(&mut self, url: &str) {
        let address = url.strip_prefix("http://").unwrap();
        for _ in 0..600 {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!("anvil exited before becoming ready: {status}");
            }
            if TcpStream::connect(address).is_ok() {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
        panic!("anvil did not become ready at {url}");
    }
}

impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Chain {
    url: String,
}

impl Chain {
    fn rpc(&self, method: &str, params: Value) -> Value {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let agent = ureq::Agent::new_with_config(
            ureq::Agent::config_builder()
                .timeout_global(Some(Duration::from_secs(180)))
                .build(),
        );
        let text = agent
            .post(&self.url)
            .content_type("application/json")
            .send(body.to_string().as_bytes())
            .unwrap_or_else(|error| panic!("{method}: {error}"))
            .body_mut()
            .read_to_string()
            .unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        if let Some(error) = value.get("error") {
            panic!("{method} failed: {error}");
        }
        value["result"].clone()
    }

    fn call(&self, to: &str, signature: &str, arguments: &[String]) -> String {
        let mut data = selector_hex(signature);
        for argument in arguments {
            data.push_str(argument.trim_start_matches("0x"));
        }
        self.rpc("eth_call", json!([{"to": to, "data": data}, "latest"]))
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn uint_call(&self, to: &str, signature: &str, arguments: &[String]) -> u128 {
        let word = self.call(to, signature, arguments);
        let hex = word.trim_start_matches("0x");
        assert!(
            hex[..32].chars().all(|c| c == '0'),
            "{signature} exceeds u128"
        );
        u128::from_str_radix(&hex[32..64], 16).unwrap()
    }

    fn address_call(&self, to: &str, signature: &str) -> String {
        self.address_call_with(to, signature, &[])
    }

    fn address_call_with(&self, to: &str, signature: &str, arguments: &[String]) -> String {
        let word = self.call(to, signature, arguments);
        format!("0x{}", &word.trim_start_matches("0x")[24..64]).to_lowercase()
    }

    fn set_storage(&self, contract: &str, slot: &str, value: &str) {
        let slot = format!("0x{:0>64}", slot.trim_start_matches("0x"));
        let value = format!("0x{:0>64}", value.trim_start_matches("0x"));
        self.rpc("anvil_setStorageAt", json!([contract, slot, value]));
    }

    fn fund(&self, address: &str) {
        self.rpc("anvil_setBalance", json!([address, "0x8ac7230489e80000"]));
    }

    fn balance(&self, address: &str) -> String {
        self.rpc("eth_getBalance", json!([address, "latest"]))
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn nonce(&self, address: &str) -> u64 {
        let text = self.rpc("eth_getTransactionCount", json!([address, "latest"]));
        u64::from_str_radix(text.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
    }

    fn timestamp(&self) -> u64 {
        let block = self.rpc("eth_getBlockByNumber", json!(["latest", false]));
        u64::from_str_radix(
            block["timestamp"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
            16,
        )
        .unwrap()
    }

    /// A transaction from an impersonated account, required to succeed.
    fn send_as(&self, from: &str, to: &str, signature: &str, arguments: &[String]) {
        let mut data = selector_hex(signature);
        for argument in arguments {
            data.push_str(argument.trim_start_matches("0x"));
        }
        self.rpc("anvil_impersonateAccount", json!([from]));
        let hash = self.rpc(
            "eth_sendTransaction",
            json!([{"from": from, "to": to, "data": data}]),
        );
        self.rpc("anvil_stopImpersonatingAccount", json!([from]));
        for _ in 0..600 {
            let receipt = self.rpc("eth_getTransactionReceipt", json!([hash]));
            if !receipt.is_null() {
                assert_eq!(receipt["status"], "0x1", "{signature} reverted");
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
        panic!("{signature} was not mined");
    }
}

// ------------------------------------------------------------------ helpers

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

fn word_hex(value: u128) -> String {
    format!("0x{value:064x}")
}

fn address_word(address: &str) -> String {
    format!("0x{:0>64}", address.trim_start_matches("0x"))
}

fn mapping_slot(key: &str, slot: u8) -> String {
    let mut preimage = [0_u8; 64];
    let key = key.trim_start_matches("0x");
    for (index, chunk) in key.as_bytes().chunks(2).enumerate() {
        preimage[12 + index] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
    }
    preimage[63] = slot;
    hex(&keccak256(&preimage).to_bytes())
}

fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0_u8; bytes];
    OsRng.fill_bytes(&mut buffer);
    hex(&buffer)[2..].to_owned()
}

fn temp_directory() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "bproof-mainnet-fork-{}-{}",
        std::process::id(),
        random_hex(4)
    ));
    std::fs::create_dir(&path).unwrap();
    path
}

fn unused_local_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[cfg(unix)]
fn write_owner_only(path: &Path, contents: &[u8]) {
    use std::io::Write;
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

fn skip(reason: &str) {
    use std::io::Write;
    let _ = writeln!(std::io::stderr(), "SKIP mainnet fork end-to-end: {reason}");
}
