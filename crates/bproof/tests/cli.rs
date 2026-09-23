use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, JoinHandle};

use proof_core::{
    Address, ChallengeInputs, Digest, ProofInputs, Uint256, derive_challenge, divisor_at,
    proof_digest, reserve_for, reward_at,
};
use serde::Deserialize;
use serde_json::{Value, json};

const MINING_CORE_BYTES: [u8; 20] = [0x22; 20];
const PREVIOUS_DIGEST_BYTES: [u8; 32] = [0xa5; 32];
const SEED_BLOCKHASH_BYTES: [u8; 32] = [0x5a; 32];
const MINER_BYTES: [u8; 20] = [0x11; 20];
const SAMPLE_STATE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/state.json");
const RPC_FIXTURE: &str = include_str!("fixtures/rpc-chain-state.json");
static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);

#[derive(Deserialize)]
struct RecordedExchange {
    request: Value,
    response: Value,
}

#[derive(Deserialize)]
struct RecordedFixture {
    exchanges: Vec<RecordedExchange>,
}

#[test]
fn schedule_next_json_has_exact_values_and_keys() {
    let output = run([
        "schedule",
        "next",
        "--accepted",
        "0",
        "--minted-wei",
        "0",
        "--json",
    ]);

    assert_success(&output);
    let value = parse_single_json_line(&output);
    assert_eq!(
        value,
        json!({
            "acceptedProofs": "0",
            "totalMintedWei": "0",
            "divisor": "10000",
            "rewardWei": "2100000000000000000000",
            "reserveWei": "2100000000000000000000"
        })
    );
    assert_exact_keys(
        &value,
        [
            "acceptedProofs",
            "divisor",
            "reserveWei",
            "rewardWei",
            "totalMintedWei",
        ],
    );
}

#[test]
fn schedule_summary_json_has_the_five_landing_facts() {
    let output = run(["schedule", "summary", "--json"]);

    assert_success(&output);
    let value = parse_single_json_line(&output);
    assert_eq!(
        value,
        json!({
            "totalProofs": "315580",
            "totalMintedWei": "21000000000000000000000000",
            "firstRewardWei": "2100000000000000000000",
            "lastRewardWei": "512358404659727855",
            "firstFloorProof": "270231"
        })
    );
    assert_exact_keys(
        &value,
        [
            "firstFloorProof",
            "firstRewardWei",
            "lastRewardWei",
            "totalMintedWei",
            "totalProofs",
        ],
    );
}

#[test]
fn verify_accepts_a_digest_equal_to_the_target() {
    let (challenge, digest) = expected_proof();
    let output = run(verify_args(&hex_string(&digest.to_bytes())));

    assert_success(&output);
    let value = parse_single_json_line(&output);
    assert_eq!(value["challenge"], hex_string(&challenge.to_bytes()));
    assert_eq!(value["digest"], hex_string(&digest.to_bytes()));
    assert_eq!(value["target"], hex_string(&digest.to_bytes()));
    assert_eq!(value["accepted"], true);
    assert_eq!(value["chainId"], "4663");
    assert_eq!(value["challengeId"], "19");
    assert_eq!(value["seedParentBlock"], "22345678");
    assert_eq!(value["nonce"], "7");
    assert_exact_keys(
        &value,
        [
            "accepted",
            "chainId",
            "challenge",
            "challengeId",
            "digest",
            "miner",
            "miningCore",
            "nonce",
            "previousAcceptedDigest",
            "seedBlockhash",
            "seedParentBlock",
            "target",
        ],
    );
}

#[test]
fn verify_rejects_a_target_one_below_the_digest_with_exit_one() {
    let (_, digest) = expected_proof();
    let lower_target = decrement(digest.to_bytes());
    let output = run(verify_args(&hex_string(&lower_target)));

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let value = parse_single_json_line(&output);
    assert_eq!(value["digest"], hex_string(&digest.to_bytes()));
    assert_eq!(value["target"], hex_string(&lower_target));
    assert_eq!(value["accepted"], false);
}

#[test]
fn malformed_address_exits_two_without_stdout_or_panic() {
    let mut args = verify_args(&hex_string(&[0xff; 32]));
    replace_flag_value(&mut args, "--mining-core", "0x1234");
    let output = run(args);

    assert_parse_error(&output, "--mining-core");
}

#[test]
fn malformed_digest_exits_two_without_stdout_or_panic() {
    let mut args = verify_args(&hex_string(&[0xff; 32]));
    replace_flag_value(&mut args, "--previous-digest", "0xzz");
    let output = run(args);

    assert_parse_error(&output, "--previous-digest");
}

#[test]
fn full_width_hex_nonce_is_emitted_as_a_decimal_string() {
    let mut args = verify_args(&hex_string(&[0xff; 32]));
    let mut nonce = [0_u8; 32];
    nonce[0] = 1;
    replace_flag_value(&mut args, "--nonce", &hex_string(&nonce));
    let output = run(args);

    assert_success(&output);
    let value = parse_single_json_line(&output);
    assert_eq!(
        value["nonce"],
        "452312848583266388373324160190187140051835877600158453279131187530910662656"
    );
}

#[test]
fn mine_all_ff_finds_the_start_nonce_and_round_trips_through_verify() {
    let target = hex_string(&[0xff; 32]);
    let mut args = mine_args(&target, &MINER_BYTES);
    args.extend(["--start-nonce".to_owned(), "123".to_owned()]);
    let output = run(args);

    assert_success(&output);
    let value = parse_single_json_line(&output);
    assert_eq!(value["accepted"], true);
    assert_eq!(value["attempts"], "1");
    assert_eq!(value["nonce"], "123");
    assert!(value["threads"].is_string());
    assert_eq!(value["proofClassification"], "unknown");
    assert_eq!(
        value["classificationReason"],
        "proof classification requires a live chain snapshot"
    );
    assert_exact_keys(
        &value,
        [
            "accepted",
            "attempts",
            "chainId",
            "challenge",
            "challengeId",
            "classificationReason",
            "digest",
            "miner",
            "miningCore",
            "nonce",
            "previousAcceptedDigest",
            "proofClassification",
            "seedBlockhash",
            "seedParentBlock",
            "target",
            "threads",
        ],
    );

    let verify_output = run(verify_args_for(&target, &MINER_BYTES, "123"));
    assert_success(&verify_output);
    let verified = parse_single_json_line(&verify_output);
    assert_eq!(verified["digest"], value["digest"]);
    assert_eq!(verified["accepted"], true);
}

#[test]
fn mine_exhausts_one_total_budget_across_all_threads() {
    let mut args = mine_args(&hex_string(&[0; 32]), &MINER_BYTES);
    args.extend([
        "--threads".to_owned(),
        "4".to_owned(),
        "--max-attempts".to_owned(),
        "50".to_owned(),
    ]);
    let output = run(args);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let value = parse_single_json_line(&output);
    assert_eq!(value["found"], false);
    assert_eq!(value["attempts"], "50");
    assert_eq!(value["threads"], "4");
    assert_exact_keys(&value, ["attempts", "found", "threads"]);
}

#[test]
fn single_thread_mining_is_deterministic_at_nonce_37() {
    let (miner, target) = miner_with_record_at(37);
    let mut args = mine_args(&hex_string(&target.to_bytes()), &miner);
    args.extend([
        "--threads".to_owned(),
        "1".to_owned(),
        "--start-nonce".to_owned(),
        "0".to_owned(),
    ]);

    let first = run(args.clone());
    let second = run(args);

    assert_success(&first);
    assert_success(&second);
    assert_eq!(first.stdout, second.stdout);
    let value = parse_single_json_line(&first);
    assert_eq!(value["nonce"], "37");
    assert_eq!(value["attempts"], "38");
    assert_eq!(value["threads"], "1");
}

#[test]
fn four_thread_stride_partition_reports_nonce_37() {
    let (miner, target) = miner_with_record_at(37);
    let mut args = mine_args(&hex_string(&target.to_bytes()), &miner);
    args.extend([
        "--threads".to_owned(),
        "4".to_owned(),
        "--start-nonce".to_owned(),
        "0".to_owned(),
    ]);
    let output = run(args);

    assert_success(&output);
    let value = parse_single_json_line(&output);
    assert_eq!(value["nonce"], "37");
    assert_eq!(value["accepted"], true);
    assert_eq!(value["threads"], "4");
}

#[test]
fn status_from_sample_file_has_exact_state_reward_and_source_fields() {
    let output = run(["status", "--state-file", SAMPLE_STATE, "--json"]);

    assert_success(&output);
    let value = parse_single_json_line(&output);
    let accepted_proofs = 0_u128;
    let total_minted_wei = 0_u128;
    let divisor = divisor_at(accepted_proofs);
    let reward = reward_at(accepted_proofs, total_minted_wei);
    let reserve = reserve_for(reward);
    assert_eq!(
        value,
        json!({
            "chainId": "4663",
            "miningCore": hex_string(&MINING_CORE_BYTES),
            "challengeId": "19",
            "previousAcceptedDigest": hex_string(&PREVIOUS_DIGEST_BYTES),
            "seedParentBlock": "22345678",
            "seedBlockhash": hex_string(&SEED_BLOCKHASH_BYTES),
            "target": hex_string(&[0xff; 32]),
            "acceptedProofs": accepted_proofs.to_string(),
            "totalMintedWei": total_minted_wei.to_string(),
            "divisor": divisor.to_string(),
            "rewardWei": reward.to_string(),
            "reserveWei": reserve.to_string(),
            "stateSource": "file",
            "settlementMode": "legacyOfflineSchedule"
        })
    );
    assert_exact_keys(
        &value,
        [
            "acceptedProofs",
            "chainId",
            "challengeId",
            "divisor",
            "miningCore",
            "previousAcceptedDigest",
            "reserveWei",
            "rewardWei",
            "seedBlockhash",
            "seedParentBlock",
            "stateSource",
            "settlementMode",
            "target",
            "totalMintedWei",
        ],
    );
}

#[test]
fn state_file_mine_matches_flag_mine_except_for_required_source_label() {
    let file_output = run(mine_state_args(true));
    let mut flag_args = mine_args(&hex_string(&[0xff; 32]), &MINER_BYTES);
    flag_args.extend(["--threads".to_owned(), "1".to_owned()]);
    let flag_output = run(flag_args);

    assert_success(&file_output);
    assert_success(&flag_output);
    let mut file_value = parse_single_json_line(&file_output);
    let flag_value = parse_single_json_line(&flag_output);
    assert_eq!(file_value["stateSource"], "file");
    assert_exact_keys(
        &file_value,
        [
            "accepted",
            "attempts",
            "chainId",
            "challenge",
            "challengeId",
            "classificationReason",
            "digest",
            "miner",
            "miningCore",
            "nonce",
            "previousAcceptedDigest",
            "proofClassification",
            "seedBlockhash",
            "seedParentBlock",
            "stateSource",
            "target",
            "threads",
        ],
    );
    file_value
        .as_object_mut()
        .expect("file mine output must be an object")
        .remove("stateSource");
    assert_eq!(file_value, flag_value);
}

#[test]
fn file_state_errors_name_missing_unknown_and_malformed_keys() {
    let sample = include_str!("../../../examples/state.json");
    let cases = [
        (
            sample.replace("  \"acceptedProofs\": \"0\",\n", ""),
            "acceptedProofs",
        ),
        (
            sample.replacen("\"chainId\"", "\"chainTypo\"", 1),
            "chainTypo",
        ),
        (
            sample.replace("0x2222222222222222222222222222222222222222", "0x1234"),
            "miningCore",
        ),
    ];

    for (contents, expected_key) in cases {
        let path = write_temp_state(&contents);
        let output = run([
            "status",
            "--state-file",
            path.to_string_lossy().as_ref(),
            "--json",
        ]);
        let _ = fs::remove_file(&path);

        assert_parse_error(&output, expected_key);
    }
}

#[test]
fn state_file_and_state_flag_clash_exits_two() {
    let output = run([
        "mine",
        "--state-file",
        SAMPLE_STATE,
        "--chain-id",
        "4663",
        "--miner",
        "0x1111111111111111111111111111111111111111",
        "--json",
    ]);

    assert_parse_error(&output, "--chain-id");
}

#[test]
fn file_sourced_human_outputs_and_help_are_explicitly_offline() {
    let status = run(["status", "--state-file", SAMPLE_STATE]);
    let mine = run(mine_state_args(false));
    let help = run(["mine", "--help"]);

    assert_success(&status);
    assert_success(&mine);
    assert_success(&help);
    assert!(String::from_utf8_lossy(&status.stdout).contains("stateSource: file"));
    assert!(String::from_utf8_lossy(&mine.stdout).contains("stateSource: file"));
    assert!(String::from_utf8_lossy(&help.stdout).contains(
        "Offline state source for development and dry runs. Live mining reads state only from the contract."
    ));
}

#[test]
fn top_level_help_documents_all_exit_codes() {
    let output = run(["--help"]);

    assert_success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Exit codes:"));
    assert!(stdout.contains("0  Command succeeded"));
    assert!(stdout.contains("1  Verify rejected"));
    assert!(stdout.contains("2  Usage or input parse error"));
}

#[test]
fn live_status_and_mine_are_always_labelled_chain_while_file_stays_file() {
    let (status_endpoint, status_server) = spawn_recorded_rpc_server(false);
    let live_status = run([
        "status",
        "--rpc-url",
        &status_endpoint,
        "--chain-id",
        "31337",
        "--mining-core",
        "0x5fbdb2315678afecb367f032d93f642f64180aa3",
        "--json",
    ]);
    status_server
        .join()
        .expect("status fixture server must finish");
    assert_success(&live_status);
    let live_status_value = parse_single_json_line(&live_status);
    assert_eq!(live_status_value["stateSource"], "chain");
    assert_eq!(live_status_value["acceptedProofs"], "0");
    assert_eq!(live_status_value["nftsMintedEver"], "0");
    assert_eq!(live_status_value["settlementMode"], "nftOnly");
    assert!(live_status_value.get("rewardWei").is_none());
    assert!(live_status_value.get("totalMintedWei").is_none());
    assert_eq!(
        live_status_value["target"],
        "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    );

    let file_status = run(["status", "--state-file", SAMPLE_STATE, "--json"]);
    assert_success(&file_status);
    let file_status_value = parse_single_json_line(&file_status);
    assert_eq!(file_status_value["stateSource"], "file");
    assert_ne!(
        live_status_value["stateSource"],
        file_status_value["stateSource"]
    );

    let (mine_endpoint, mine_server) = spawn_recorded_rpc_server(true);
    let live_mine = run([
        "mine",
        "--rpc-url",
        &mine_endpoint,
        "--chain-id",
        "31337",
        "--mining-core",
        "0x5fbdb2315678afecb367f032d93f642f64180aa3",
        "--miner",
        "0x1111111111111111111111111111111111111111",
        "--threads",
        "1",
        "--max-attempts",
        "1",
        "--json",
    ]);
    mine_server.join().expect("mine fixture server must finish");
    assert_success(&live_mine);
    let live_mine_value = parse_single_json_line(&live_mine);
    assert_eq!(live_mine_value["stateSource"], "chain");
}

#[test]
fn rpc_url_clashes_with_file_and_each_manual_state_flag() {
    let file_clash = run([
        "mine",
        "--rpc-url",
        "http://127.0.0.1:1",
        "--state-file",
        SAMPLE_STATE,
        "--miner",
        "0x1111111111111111111111111111111111111111",
    ]);
    assert_parse_error(&file_clash, "--state-file");

    let cases = [
        ("--challenge-id", "19"),
        (
            "--previous-digest",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
        ),
        ("--seed-parent-block", "22345678"),
        (
            "--seed-blockhash",
            "0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
        ),
        (
            "--target",
            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
    ];
    for (flag, value) in cases {
        let output = run([
            "mine",
            "--rpc-url",
            "http://127.0.0.1:1",
            "--chain-id",
            "31337",
            "--mining-core",
            "0x5fbdb2315678afecb367f032d93f642f64180aa3",
            flag,
            value,
            "--miner",
            "0x1111111111111111111111111111111111111111",
        ]);
        assert_parse_error(&output, flag);
    }

    let status_clash = run([
        "status",
        "--rpc-url",
        "http://127.0.0.1:1",
        "--state-file",
        SAMPLE_STATE,
    ]);
    assert_parse_error(&status_clash, "--state-file");
}

fn run<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    Command::new(env!("CARGO_BIN_EXE_bproof"))
        .args(args)
        .output()
        .expect("bproof must run")
}

fn verify_args(target: &str) -> Vec<String> {
    verify_args_for(target, &MINER_BYTES, "7")
}

fn verify_args_for(target: &str, miner: &[u8; 20], nonce: &str) -> Vec<String> {
    vec![
        "verify".to_owned(),
        "--chain-id".to_owned(),
        "4663".to_owned(),
        "--mining-core".to_owned(),
        hex_string(&MINING_CORE_BYTES),
        "--challenge-id".to_owned(),
        "19".to_owned(),
        "--previous-digest".to_owned(),
        hex_string(&PREVIOUS_DIGEST_BYTES),
        "--seed-parent-block".to_owned(),
        "22345678".to_owned(),
        "--seed-blockhash".to_owned(),
        hex_string(&SEED_BLOCKHASH_BYTES),
        "--miner".to_owned(),
        hex_string(miner),
        "--nonce".to_owned(),
        nonce.to_owned(),
        "--target".to_owned(),
        target.to_owned(),
        "--json".to_owned(),
    ]
}

fn mine_args(target: &str, miner: &[u8; 20]) -> Vec<String> {
    vec![
        "mine".to_owned(),
        "--chain-id".to_owned(),
        "4663".to_owned(),
        "--mining-core".to_owned(),
        hex_string(&MINING_CORE_BYTES),
        "--challenge-id".to_owned(),
        "19".to_owned(),
        "--previous-digest".to_owned(),
        hex_string(&PREVIOUS_DIGEST_BYTES),
        "--seed-parent-block".to_owned(),
        "22345678".to_owned(),
        "--seed-blockhash".to_owned(),
        hex_string(&SEED_BLOCKHASH_BYTES),
        "--miner".to_owned(),
        hex_string(miner),
        "--target".to_owned(),
        target.to_owned(),
        "--json".to_owned(),
    ]
}

fn mine_state_args(json: bool) -> Vec<String> {
    let mut args = vec![
        "mine".to_owned(),
        "--state-file".to_owned(),
        SAMPLE_STATE.to_owned(),
        "--miner".to_owned(),
        hex_string(&MINER_BYTES),
        "--threads".to_owned(),
        "1".to_owned(),
    ];
    if json {
        args.push("--json".to_owned());
    }
    args
}

fn write_temp_state(contents: &str) -> PathBuf {
    let id = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "bproof-state-test-{}-{id}.json",
        std::process::id()
    ));
    fs::write(&path, contents).expect("temporary state file must be writable");
    path
}

fn expected_proof() -> (Digest, Digest) {
    let chain_id = Uint256::from(4_663_u64);
    let mining_core = Address::from_bytes(MINING_CORE_BYTES);
    let challenge_id = Uint256::from(19_u64);
    let challenge = derive_challenge(&ChallengeInputs {
        chain_id,
        mining_core,
        challenge_id,
        previous_accepted_digest: Digest::from_bytes(PREVIOUS_DIGEST_BYTES),
        seed_parent_block: Uint256::from(22_345_678_u64),
        seed_blockhash: Digest::from_bytes(SEED_BLOCKHASH_BYTES),
    });
    let digest = proof_digest(&ProofInputs {
        chain_id,
        mining_core,
        challenge_id,
        challenge,
        miner: Address::from_bytes(MINER_BYTES),
        nonce: Uint256::from(7_u64),
    });

    (challenge, digest)
}

fn miner_with_record_at(known_nonce: u64) -> ([u8; 20], Digest) {
    let challenge_inputs = ChallengeInputs {
        chain_id: Uint256::from(4_663_u64),
        mining_core: Address::from_bytes(MINING_CORE_BYTES),
        challenge_id: Uint256::from(19_u64),
        previous_accepted_digest: Digest::from_bytes(PREVIOUS_DIGEST_BYTES),
        seed_parent_block: Uint256::from(22_345_678_u64),
        seed_blockhash: Digest::from_bytes(SEED_BLOCKHASH_BYTES),
    };
    let challenge = derive_challenge(&challenge_inputs);

    for marker in 0_u16..=u16::MAX {
        let mut miner_bytes = MINER_BYTES;
        miner_bytes[18..].copy_from_slice(&marker.to_be_bytes());
        let miner = Address::from_bytes(miner_bytes);
        let target = digest_for_nonce(&challenge_inputs, challenge, miner, known_nonce);
        if (0..known_nonce)
            .all(|nonce| digest_for_nonce(&challenge_inputs, challenge, miner, nonce) > target)
        {
            return (miner_bytes, target);
        }
    }

    panic!("a deterministic nonce-37 fixture must exist");
}

fn digest_for_nonce(
    challenge_inputs: &ChallengeInputs,
    challenge: Digest,
    miner: Address,
    nonce: u64,
) -> Digest {
    proof_digest(&ProofInputs {
        chain_id: challenge_inputs.chain_id,
        mining_core: challenge_inputs.mining_core,
        challenge_id: challenge_inputs.challenge_id,
        challenge,
        miner,
        nonce: Uint256::from(nonce),
    })
}

fn parse_single_json_line(output: &Output) -> Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.lines().count(), 1, "stdout: {stdout}");
    serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON")
}

fn assert_success(output: &Output) {
    assert_eq!(output.status.code(), Some(0));
    assert!(
        output.stderr.is_empty(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_parse_error(output: &Output, expected_message: &str) {
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.is_empty());
    assert!(stderr.contains(expected_message), "stderr: {stderr}");
    assert!(!stderr.to_lowercase().contains("panicked"));
}

fn assert_exact_keys<const N: usize>(value: &Value, expected: [&str; N]) {
    let actual = value
        .as_object()
        .expect("JSON output must be an object")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected = expected.into_iter().collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
}

fn spawn_recorded_rpc_server(with_power: bool) -> (String, JoinHandle<()>) {
    let mut exchanges = serde_json::from_str::<RecordedFixture>(RPC_FIXTURE)
        .expect("recorded RPC fixture must be valid")
        .exchanges
        .into_iter()
        .filter(|exchange| exchange.request["method"] != "eth_getBlockByNumber")
        .collect::<Vec<_>>();
    if with_power {
        let selector = proof_core::keccak256(b"miningPower()").to_bytes();
        let data = format!(
            "0x{}",
            selector[..4]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        exchanges.push(RecordedExchange {
            request: json!({"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0x5fbdb2315678afecb367f032d93f642f64180aa3","data":data},"0x3ec"]}),
            response: json!({"jsonrpc":"2.0","id":1,"result":format!("0x{}", "0".repeat(64))}),
        });
    }
    let listener = TcpListener::bind("127.0.0.1:0").expect("fixture server must bind");
    let endpoint = format!(
        "http://{}",
        listener.local_addr().expect("listener has an address")
    );
    let server = thread::spawn(move || {
        for exchange in exchanges {
            let (mut stream, _) = listener.accept().expect("fixture request must connect");
            let body = read_request_body(&mut stream);
            let request: Value =
                serde_json::from_slice(&body).expect("fixture request body must be JSON");
            assert_eq!(request, exchange.request);
            let body =
                serde_json::to_string(&exchange.response).expect("fixture response must serialize");
            write_response(&mut stream, &body);
        }
    });
    (endpoint, server)
}

fn read_request_body(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4_096];
    let (header_end, content_length) = loop {
        let read = stream.read(&mut buffer).expect("fixture request must read");
        assert_ne!(read, 0, "request ended before headers");
        request.extend_from_slice(&buffer[..read]);
        if let Some(header_end) = find_bytes(&request, b"\r\n\r\n") {
            let headers =
                std::str::from_utf8(&request[..header_end]).expect("request headers are UTF-8");
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().expect("valid content length"))
                })
                .expect("request must have content length");
            break (header_end + 4, content_length);
        }
    };
    while request.len() < header_end + content_length {
        let read = stream
            .read(&mut buffer)
            .expect("fixture request body must read");
        assert_ne!(read, 0, "request ended before body");
        request.extend_from_slice(&buffer[..read]);
    }
    request[header_end..header_end + content_length].to_vec()
}

fn write_response(stream: &mut TcpStream, body: &str) {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .expect("fixture response must write");
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn replace_flag_value(args: &mut [String], flag: &str, value: &str) {
    let index = args
        .iter()
        .position(|argument| argument == flag)
        .expect("flag must exist");
    args[index + 1] = value.to_owned();
}

fn decrement(mut value: [u8; 32]) -> [u8; 32] {
    assert!(value.iter().any(|byte| *byte != 0));
    for byte in value.iter_mut().rev() {
        if *byte == 0 {
            *byte = 0xff;
        } else {
            *byte -= 1;
            break;
        }
    }
    value
}

fn hex_string(bytes: &[u8]) -> String {
    let mut output = String::from("0x");
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}
