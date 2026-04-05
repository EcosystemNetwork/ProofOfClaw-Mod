//! Boundless Groth16 Prover for Proof of Claw
//!
//! Submits a proof request to the Boundless marketplace on Sepolia,
//! waits for fulfillment, and outputs the Groth16 seal for on-chain verification.
//!
//! Required env vars:
//!   PRIVATE_KEY       — Funded Sepolia wallet (needs Sepolia ETH + Boundless collateral)
//!   SEPOLIA_RPC_URL   — Sepolia RPC (default: publicnode)
//!   PINATA_JWT        — Pinata API token for uploading ELF to IPFS
//!
//! Setup:
//!   1. Get Sepolia ETH from a faucet
//!   2. Get Boundless collateral tokens (bridge or faucet)
//!   3. Get Pinata JWT from https://app.pinata.cloud/developers/api-keys
//!   4. Run: cargo run --release --manifest-path zkvm/boundless-prover/Cargo.toml

use anyhow::{Context, Result};
use boundless_market::{
    client::ClientBuilder,
    deployments::SEPOLIA,
    input::GuestEnv,
    storage::StorageUploaderConfig,
};
// Image ID pre-computed from the guest ELF
const IMAGE_ID_HEX: &str = "a2ad29fbb85c3aee3a8863ffcb1fa287f537d89473f44df19cb2065834f025d2";
use serde::{Deserialize, Serialize};
use std::time::Duration;

const GUEST_ELF: &[u8] = include_bytes!("../../target/riscv32im-risc0-zkvm-elf/release/proof-of-claw-guest");

#[derive(Serialize, Deserialize)]
struct ExecutionTrace {
    agent_id: String,
    inference_commitment: [u8; 32],
    tool_invocations: Vec<ToolInvocation>,
    policy_check_results: Vec<PolicyResult>,
    output_commitment: [u8; 32],
    action_value: u64,
}
#[derive(Serialize, Deserialize)]
struct ToolInvocation { tool_name: String, input_hash: [u8; 32], output_hash: [u8; 32], capability_hash: [u8; 32], within_policy: bool }
#[derive(Serialize, Deserialize)]
struct PolicyResult { rule_id: String, severity: String, details: String }
#[derive(Serialize, Deserialize)]
struct AgentPolicy { allowed_tools: Vec<String>, endpoint_allowlist: Vec<String>, max_value_autonomous: u64, capability_root: [u8; 32] }

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let image_id_bytes: [u8; 32] = hex::decode(IMAGE_ID_HEX)
        .expect("invalid IMAGE_ID_HEX")
        .try_into()
        .expect("wrong length");
    println!("Proof of Claw — Boundless Groth16 Prover");
    println!("Image ID: 0x{IMAGE_ID_HEX}");

    let private_key = std::env::var("PRIVATE_KEY")
        .context("Set PRIVATE_KEY env var (Sepolia funded wallet)")?;
    let rpc_url: url::Url = std::env::var("SEPOLIA_RPC_URL")
        .unwrap_or_else(|_| "https://ethereum-sepolia-rpc.publicnode.com".to_string())
        .parse()?;

    // Build input for the guest
    let trace = ExecutionTrace {
        agent_id: "alice.proofofclaw.eth".to_string(),
        inference_commitment: [0u8; 32],
        tool_invocations: vec![ToolInvocation {
            tool_name: "swap_tokens".to_string(),
            input_hash: [1u8; 32], output_hash: [2u8; 32],
            capability_hash: [3u8; 32], within_policy: true,
        }],
        policy_check_results: vec![],
        output_commitment: [0u8; 32],
        action_value: 50_000_000_000_000_000,
    };
    let policy = AgentPolicy {
        allowed_tools: vec!["swap_tokens".to_string(), "transfer".to_string()],
        endpoint_allowlist: vec!["https://api.uniswap.org".to_string()],
        max_value_autonomous: 100_000_000_000_000_000,
        capability_root: [0u8; 32],
    };
    let input_bytes = bincode::serialize(&(&trace, &policy))?;

    let guest_env = GuestEnv::builder()
        .write(&trace)?
        .write(&policy)?
        .build_env();

    // Build storage config for Pinata
    let storage_config = StorageUploaderConfig::builder()
        .storage_uploader(boundless_market::storage::StorageUploaderType::Pinata)
        .pinata_jwt(std::env::var("PINATA_JWT")
            .context("Set PINATA_JWT env var (get from https://app.pinata.cloud/developers/api-keys)")?)
        .build()
        .context("Failed to build storage config")?;

    // Build Boundless client
    println!("Connecting to Boundless on Sepolia...");
    let client = ClientBuilder::new()
        .with_deployment(SEPOLIA)
        .with_rpc_url(rpc_url)
        .with_private_key_str(&private_key)
        .context("Invalid PRIVATE_KEY")?
        .with_uploader_config(&storage_config)
        .await
        .context("Failed to configure storage uploader")?
        .build()
        .await
        .context("Failed to build Boundless client")?;

    println!("Wallet: {}", client.caller());

    // Submit proof request with program and env
    println!("Submitting proof request (ELF: {} bytes, input: {} bytes)...", GUEST_ELF.len(), input_bytes.len());
    // Pass image_id as raw bytes converted to the Digest type used by boundless-market
    let params = client.new_request()
        .with_program(GUEST_ELF.to_vec())
        .with_env(guest_env)
        .with_image_id(image_id_bytes);

    let (request_id, block) = client
        .submit(params)
        .await
        .context("Failed to submit proof request")?;

    println!("Request submitted! ID: {request_id} (block: {block})");
    println!("Waiting for fulfillment (up to 10 min)...");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let fulfillment = client
        .wait_for_request_fulfillment(request_id, Duration::from_secs(15), now + 600)
        .await
        .context("Proof not fulfilled in time")?;

    println!("\nProof fulfilled!");
    println!("Seal length: {} bytes", fulfillment.seal.len());

    // Save proof
    let proof_json = serde_json::json!({
        "image_id": format!("0x{IMAGE_ID_HEX}"),
        "seal": format!("0x{}", hex::encode(&fulfillment.seal)),
    });
    std::fs::write("groth16-proof.json", serde_json::to_string_pretty(&proof_json)?)?;
    println!("Proof saved to groth16-proof.json");

    Ok(())
}
