// Local production-contract composition for CLI acceptance. No public RPCs.
pub const MINING_CORE: &str = "0x8a791620dd6260079bf849dc5567adc3f2fdc318";
#[allow(dead_code)] // The state-only unit test does not submit.
pub const BASKET: &str = "0x5fbdb2315678afecb367f032d93f642f64180aa3";

pub fn deploy(endpoint: &str, directory: &std::path::Path) {
    assert!(endpoint.starts_with("http://127.0.0.1:"));
    let contracts = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../contracts");
    let mut config: serde_json::Value = serde_json::from_slice(
        &std::fs::read(contracts.join("config/deploy-phase1.local-anvil.fake.json")).unwrap(),
    )
    .unwrap();
    config["miningStopSunset"] = serde_json::json!(1_800_000_000_u64 + 60 * 86400);
    config["liveHunt"]["moduleStopSunset"] = serde_json::json!(1_800_000_000_u64 + 400 * 86400);
    config["liveHunt"]["deploy"] = serde_json::json!(false);
    // Tests run in parallel and each live Anvil gets its own port. Include the
    // endpoint port so concurrent deployments never overwrite one another's
    // temporary composition config.
    let port = endpoint.rsplit(':').next().unwrap_or("unknown");
    let name = format!("cli-test-{}-{port}.json", std::process::id());
    std::fs::create_dir_all(contracts.join("deployment-proofs")).unwrap();
    let path = contracts.join("deployment-proofs").join(&name);
    std::fs::write(&path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    let result = std::process::Command::new("forge")
        .current_dir(&contracts)
        .env("FOUNDRY_PROFILE", "release")
        .env(
            "PHASE1_COMPOSITION_CONFIG_PATH",
            format!("deployment-proofs/{name}"),
        )
        .env("FOUNDRY_BROADCAST", directory.join("broadcast"))
        .args([
            "script",
            "script/LocalPhase1Composition.s.sol:LocalPhase1Composition",
            "--rpc-url",
            endpoint,
            "--broadcast",
            "--slow",
            "--unlocked",
            "--non-interactive",
        ])
        .output()
        .expect("forge must run");
    let _ = std::fs::remove_file(path);
    assert!(
        result.status.success(),
        "composition deployment failed\n{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}
