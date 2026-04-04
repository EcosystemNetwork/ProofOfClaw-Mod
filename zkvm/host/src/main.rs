use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use serde::{Deserialize, Serialize};
use anyhow::Result;

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
struct ToolInvocation {
    tool_name: String,
    input_hash: [u8; 32],
    output_hash: [u8; 32],
    capability_hash: [u8; 32],
    within_policy: bool,
}

#[derive(Serialize, Deserialize)]
struct PolicyResult {
    rule_id: String,
    severity: String,
    details: String,
}

#[derive(Serialize, Deserialize)]
struct AgentPolicy {
    allowed_tools: Vec<String>,
    endpoint_allowlist: Vec<String>,
    max_value_autonomous: u64,
    capability_root: [u8; 32],
}

const GUEST_ELF: &[u8] = include_bytes!("../../guest/target/riscv32im-risc0-zkvm-elf/release/proof-of-claw-guest");

#[tokio::main]
async fn main() -> Result<()> {
    println!("Proof of Claw - RISC Zero Host");
    
    let trace = ExecutionTrace {
        agent_id: "alice.proofofclaw.eth".to_string(),
        inference_commitment: [0u8; 32],
        tool_invocations: vec![],
        policy_check_results: vec![],
        output_commitment: [0u8; 32],
        action_value: 50_000_000_000_000_000_000,
    };
    
    let policy = AgentPolicy {
        allowed_tools: vec!["swap_tokens".to_string(), "transfer".to_string()],
        endpoint_allowlist: vec!["https://api.uniswap.org".to_string()],
        max_value_autonomous: 100_000_000_000_000_000_000,
        capability_root: [0u8; 32],
    };
    
    let receipt = generate_proof(&trace, &policy)?;
    
    println!("Proof generated successfully!");
    println!("Receipt journal length: {}", receipt.journal.bytes.len());
    
    Ok(())
}

fn generate_proof(trace: &ExecutionTrace, policy: &AgentPolicy) -> Result<Receipt> {
    let env = ExecutorEnv::builder()
        .write(trace)?
        .write(policy)?
        .build()?;
    
    let prover = default_prover();
    let receipt = prover.prove(env, GUEST_ELF)?;
    
    Ok(receipt)
}
