use risc0_zkvm::{compute_image_id, default_prover, ExecutorEnv, Receipt};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
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

#[derive(Serialize, Deserialize, Clone)]
struct ToolInvocation {
    tool_name: String,
    input_hash: [u8; 32],
    output_hash: [u8; 32],
    capability_hash: [u8; 32],
    within_policy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum PolicySeverity {
    Block,
    Warn,
    Sanitize,
    Pass,
}

#[derive(Serialize, Deserialize, Clone)]
struct PolicyResult {
    rule_id: String,
    severity: PolicySeverity,
    details: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct AgentPolicy {
    allowed_tools: Vec<String>,
    endpoint_allowlist: Vec<String>,
    max_value_autonomous: u64,
    capability_root: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug)]
struct VerifiedOutput {
    agent_id: String,
    policy_hash: [u8; 32],
    inference_commitment: [u8; 32],
    output_commitment: [u8; 32],
    all_checks_passed: bool,
    requires_ledger_approval: bool,
    action_value: u64,
}

const GUEST_ELF: &[u8] = include_bytes!("../../target/riscv32im-risc0-zkvm-elf/release/proof-of-claw-guest");

fn main() -> Result<()> {
    let image_id = compute_image_id(GUEST_ELF)?;
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║       Proof of Claw — RISC Zero ZK Prover          ║");
    println!("╚══════════════════════════════════════════════════════╝");
    println!();
    println!("Image ID: 0x{}", hex::encode(image_id.as_bytes()));
    println!("Guest ELF: {} bytes", GUEST_ELF.len());

    // Simulate an agent execution trace
    let tool_invocations = vec![
        ToolInvocation {
            tool_name: "swap_tokens".to_string(),
            input_hash: [1u8; 32],
            output_hash: [2u8; 32],
            capability_hash: [3u8; 32],
            within_policy: true,
        },
    ];

    // Compute inference commitment: SHA-256 over tool_name + input_hash + output_hash
    let mut inference_hasher = Sha256::new();
    for invocation in &tool_invocations {
        inference_hasher.update(invocation.tool_name.as_bytes());
        inference_hasher.update(&invocation.input_hash);
        inference_hasher.update(&invocation.output_hash);
    }
    let inference_commitment: [u8; 32] = inference_hasher.finalize().into();

    let trace = ExecutionTrace {
        agent_id: "alice.proofofclaw.eth".to_string(),
        inference_commitment,
        tool_invocations,
        policy_check_results: vec![],
        output_commitment: [0u8; 32],
        action_value: 50_000_000_000_000_000, // 0.05 ETH
    };

    let policy = AgentPolicy {
        allowed_tools: vec!["swap_tokens".to_string(), "transfer".to_string()],
        endpoint_allowlist: vec!["https://api.uniswap.org".to_string()],
        max_value_autonomous: 100_000_000_000_000_000, // 0.1 ETH
        capability_root: [0u8; 32],
    };

    println!("\nGenerating ZK proof of policy compliance...");
    let receipt = generate_proof(&trace, &policy)?;

    // Decode the verified output from the journal
    let output: VerifiedOutput = receipt.journal.decode()?;

    // Verify the receipt cryptographically
    receipt.verify(image_id)?;

    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║                  PROOF VERIFIED                     ║");
    println!("╠══════════════════════════════════════════════════════╣");
    println!("║  Agent:        {:<37} ║", output.agent_id);
    println!("║  Checks passed: {:<36} ║", output.all_checks_passed);
    println!("║  Ledger needed: {:<36} ║", output.requires_ledger_approval);
    println!("║  Action value:  {} wei{} ║",
        output.action_value,
        " ".repeat(36 - output.action_value.to_string().len() - 4));
    println!("║  Journal size:  {} bytes{} ║",
        receipt.journal.bytes.len(),
        " ".repeat(36 - receipt.journal.bytes.len().to_string().len() - 6));
    println!("║  Policy hash:   0x{}...  ║", hex::encode(&output.policy_hash[..8]));
    println!("╚══════════════════════════════════════════════════════╝");

    // Save receipt for on-chain submission
    let receipt_bytes = bincode::serialize(&receipt)?;
    std::fs::write("proof-receipt.bin", &receipt_bytes)?;
    println!("\nReceipt saved to proof-receipt.bin ({} bytes)", receipt_bytes.len());
    println!("Image ID for contract: 0x{}", hex::encode(image_id.as_bytes()));

    Ok(())
}

fn generate_proof(trace: &ExecutionTrace, policy: &AgentPolicy) -> Result<Receipt> {
    let env = ExecutorEnv::builder()
        .write(trace)?
        .write(policy)?
        .build()?;

    let prover = default_prover();
    let prove_info = prover.prove(env, GUEST_ELF)?;

    Ok(prove_info.receipt)
}
