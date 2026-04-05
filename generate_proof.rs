//! Standalone proof generator for deployment
use proof_of_claw::proof_generator::ProofGenerator;
use proof_of_claw::types::ExecutionTrace;
use std::env;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let image_id = env::var("RISC_ZERO_IMAGE_ID")
        .unwrap_or_else(|_| "0x6356d10d377b75c568fe9041a6da3ef55a6134c301fcc334ea245dc843435d58".to_string());
    
    let gen = ProofGenerator::new(false, image_id.clone());
    
    let trace = ExecutionTrace {
        agent_id: "alice.proofclaw.eth".to_string(),
        session_id: "test-session".to_string(),
        timestamp: 1234567890,
        inference_commitment: "0x0000".to_string(),
        tool_invocations: vec![proof_of_claw::types::ToolInvocation {
            tool_name: "swap_tokens".to_string(),
            input_hash: "0x1111".to_string(),
            output_hash: "0x2222".to_string(),
            capability_hash: "0x3333".to_string(),
            timestamp: 1234567890,
            within_policy: true,
        }],
        policy_check_results: vec![proof_of_claw::types::PolicyResult {
            rule_id: "value_limit".to_string(),
            severity: proof_of_claw::types::PolicySeverity::Pass,
            details: "Within policy limits".to_string(),
        }],
        output_commitment: "0x4444".to_string(),
    };
    
    let receipt = gen.generate_proof(&trace).await?;
    
    let output = serde_json::json!({
        "image_id": image_id,
        "seal": format!("0x{}", hex::encode(&receipt.seal)),
        "journal": format!("0x{}", hex::encode(&receipt.journal)),
    });
    
    std::fs::write("proof_output.json", serde_json::to_string_pretty(&output)?)?;
    println!("Proof saved to proof_output.json");
    println!("\n=== DEPLOYMENT ENV ===");
    println!("export RISC_ZERO_IMAGE_ID={}", image_id);
    
    Ok(())
}
