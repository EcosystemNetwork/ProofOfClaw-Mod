use risc0_zkvm::{compute_image_id, default_prover, ExecutorEnv, ProverOpts, Receipt};
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

#[derive(Serialize, Deserialize, Clone)]
struct ToolInvocation {
    tool_name: String,
    input_hash: [u8; 32],
    output_hash: [u8; 32],
    capability_hash: [u8; 32],
    within_policy: bool,
}

#[derive(Serialize, Deserialize, Clone)]
struct PolicyResult {
    rule_id: String,
    severity: String,
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
    output_commitment: [u8; 32],
    all_checks_passed: bool,
    requires_ledger_approval: bool,
    action_value: u64,
}

const GUEST_ELF: &[u8] = include_bytes!("../../target/riscv32im-risc0-zkvm-elf/release/proof-of-claw-guest");

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let use_groth16 = args.iter().any(|a| a == "--groth16");

    let image_id = compute_image_id(GUEST_ELF)?;
    println!("Proof of Claw — RISC Zero Host");
    println!("Image ID: 0x{}", hex::encode(image_id.as_bytes()));
    println!("Mode: {}", if use_groth16 { "Groth16 (on-chain ready)" } else { "STARK (local)" });

    let trace = ExecutionTrace {
        agent_id: "alice.proofofclaw.eth".to_string(),
        inference_commitment: [0u8; 32],
        tool_invocations: vec![
            ToolInvocation {
                tool_name: "swap_tokens".to_string(),
                input_hash: [1u8; 32],
                output_hash: [2u8; 32],
                capability_hash: [3u8; 32],
                within_policy: true,
            },
        ],
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

    println!("Generating proof...");
    let receipt = generate_proof(&trace, &policy, use_groth16)?;

    println!("Proof generated successfully!");
    println!("Journal length: {} bytes", receipt.journal.bytes.len());

    // Decode verified output
    let output: VerifiedOutput = receipt.journal.decode()?;
    println!("Agent: {}", output.agent_id);
    println!("All checks passed: {}", output.all_checks_passed);
    println!("Requires ledger approval: {}", output.requires_ledger_approval);

    // Verify receipt
    receipt.verify(image_id)?;
    println!("Receipt verified against image ID!");

    // Extract on-chain seal
    match receipt.inner.groth16() {
        Ok(groth16_receipt) => {
            let seal_hex = hex::encode(&groth16_receipt.seal);
            println!("\n=== ON-CHAIN READY ===");
            println!("Groth16 seal ({} bytes): 0x{}", groth16_receipt.seal.len(), &seal_hex[..80.min(seal_hex.len())]);
            println!("Journal hash: 0x{}", hex::encode(receipt.journal.bytes.iter().copied().collect::<Vec<u8>>()));

            // Output in format ready for contract call
            println!("\nSolidity calldata:");
            println!("  imageId:     0x{}", hex::encode(image_id.as_bytes()));
            println!("  journalHash: 0x{}", hex::encode(sha256(&receipt.journal.bytes)));
            println!("  seal:        0x{}", seal_hex);
        }
        Err(_) => {
            println!("\nReceipt is STARK (not Groth16) — use --groth16 flag for on-chain proofs.");
            println!("Requires BONSAI_API_KEY and BONSAI_API_URL environment variables.");
            println!("\nTo get Groth16 proofs:");
            println!("  1. Sign up at https://bonsai.xyz or use Boundless marketplace");
            println!("  2. export BONSAI_API_KEY=<your-key>");
            println!("  3. export BONSAI_API_URL=https://api.bonsai.xyz");
            println!("  4. Run: ./proof-of-claw-host --groth16");
        }
    }

    Ok(())
}

fn generate_proof(trace: &ExecutionTrace, policy: &AgentPolicy, groth16: bool) -> Result<Receipt> {
    let env = ExecutorEnv::builder()
        .write(trace)?
        .write(policy)?
        .build()?;

    let prover = default_prover();

    let prove_info = if groth16 {
        prover.prove_with_opts(env, GUEST_ELF, &ProverOpts::groth16())?
    } else {
        prover.prove(env, GUEST_ELF)?
    };

    Ok(prove_info.receipt)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
