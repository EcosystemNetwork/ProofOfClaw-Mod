//! ZK proof generation for execution traces.
//!
//! This module generates RISC Zero receipts that prove an agent's execution
//! was policy-compliant. The actual RISC Zero proving happens either:
//! - Locally (requires `risc-zero` toolchain)
//! - Via Boundless proving marketplace
//!
//! The `zkvm/` directory contains the guest program that defines the circuit.

use crate::config::AgentConfig;
use crate::types::{ExecutionTrace, ProofReceipt, VerifiedOutput};
use anyhow::{Context, Result};
#[cfg(feature = "client")]
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};
use serde::{Deserialize, Serialize};

// ── ZkVM-compatible types ──────────────────────────────────────────────────
// These mirror the types in zkvm/guest/src/main.rs which use [u8; 32] arrays
// instead of hex Strings. We convert from the public API types before proving.

#[derive(Serialize, Deserialize)]
struct ZkExecutionTrace {
    agent_id: String,
    inference_commitment: [u8; 32],
    tool_invocations: Vec<ZkToolInvocation>,
    policy_check_results: Vec<ZkPolicyResult>,
    output_commitment: [u8; 32],
    action_value: u64,
}

#[derive(Serialize, Deserialize)]
struct ZkToolInvocation {
    tool_name: String,
    input_hash: [u8; 32],
    output_hash: [u8; 32],
    capability_hash: [u8; 32],
    within_policy: bool,
}

#[derive(Serialize, Deserialize)]
struct ZkPolicyResult {
    rule_id: String,
    severity: ZkPolicySeverity,
    details: String,
}

#[derive(Serialize, Deserialize)]
enum ZkPolicySeverity {
    Block,
    Warn,
    Sanitize,
    Pass,
}

#[derive(Serialize, Deserialize)]
struct ZkAgentPolicy {
    allowed_tools: Vec<String>,
    endpoint_allowlist: Vec<String>,
    max_value_autonomous: u64,
    capability_root: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct ZkVerifiedOutput {
    agent_id: String,
    policy_hash: [u8; 32],
    output_commitment: [u8; 32],
    all_checks_passed: bool,
    requires_ledger_approval: bool,
    action_value: u64,
}

// ── Conversions ────────────────────────────────────────────────────────────

/// Parse a hex string (with optional `0x` prefix) into a `[u8; 32]`.
/// If the input is too short, the result is zero-padded on the right.
fn hex_to_bytes32(hex_str: &str) -> [u8; 32] {
    let stripped = hex_str.trim_start_matches("0x");
    let mut out = [0u8; 32];
    if let Ok(bytes) = hex::decode(stripped) {
        let len = bytes.len().min(32);
        out[..len].copy_from_slice(&bytes[..len]);
    }
    out
}

fn bytes32_to_hex(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn convert_trace(trace: &ExecutionTrace) -> ZkExecutionTrace {
    // Extract action_value from the trace's tool invocations.
    // Each invocation's params may carry a "value" field (wei). Sum them.
    let action_value: u64 = trace
        .tool_invocations
        .iter()
        .filter_map(|inv| {
            // Parse the output_hash as a hex-encoded wei value when the tool
            // is a value-bearing action (swap, transfer, bridge, send).
            let name = inv.tool_name.to_lowercase();
            if name.contains("swap") || name.contains("transfer")
                || name.contains("bridge") || name.contains("send")
            {
                // The input_hash field encodes the action value in hex when set
                // by the execution runtime. Fall back to 0 for legacy traces.
                let stripped = inv.input_hash.trim_start_matches("0x");
                u64::from_str_radix(stripped, 16).ok()
            } else {
                None
            }
        })
        .fold(0u64, u64::saturating_add);

    ZkExecutionTrace {
        agent_id: trace.agent_id.clone(),
        inference_commitment: hex_to_bytes32(&trace.inference_commitment),
        tool_invocations: trace
            .tool_invocations
            .iter()
            .map(|inv| ZkToolInvocation {
                tool_name: inv.tool_name.clone(),
                input_hash: hex_to_bytes32(&inv.input_hash),
                output_hash: hex_to_bytes32(&inv.output_hash),
                capability_hash: hex_to_bytes32(&inv.capability_hash),
                within_policy: inv.within_policy,
            })
            .collect(),
        policy_check_results: trace
            .policy_check_results
            .iter()
            .map(|r| ZkPolicyResult {
                rule_id: r.rule_id.clone(),
                severity: match r.severity {
                    crate::types::PolicySeverity::Block => ZkPolicySeverity::Block,
                    crate::types::PolicySeverity::Warn => ZkPolicySeverity::Warn,
                    crate::types::PolicySeverity::Sanitize => ZkPolicySeverity::Sanitize,
                    crate::types::PolicySeverity::Pass => ZkPolicySeverity::Pass,
                },
                details: r.details.clone(),
            })
            .collect(),
        output_commitment: hex_to_bytes32(&trace.output_commitment),
        action_value,
    }
}

fn convert_verified_output(zk: &ZkVerifiedOutput) -> VerifiedOutput {
    VerifiedOutput {
        agent_id: zk.agent_id.clone(),
        policy_hash: bytes32_to_hex(&zk.policy_hash),
        output_commitment: bytes32_to_hex(&zk.output_commitment),
        all_checks_passed: zk.all_checks_passed,
        requires_ledger_approval: zk.requires_ledger_approval,
        action_value: zk.action_value,
    }
}

/// Generates RISC Zero proof receipts for execution traces.
pub struct ProofGenerator {
    /// Use Boundless marketplace for proving (if true). Local RISC Zero if false.
    use_boundless: bool,
    /// RISC Zero image ID of the deployed proof circuit.
    image_id: String,
    /// Guest ELF binary bytes used for local proving.
    guest_elf: Vec<u8>,
    /// Agent policy derived from config.
    policy: ZkAgentPolicy,
    /// Boundless API URL.
    boundless_api_url: String,
    /// Boundless API key.
    boundless_api_key: Option<String>,
}

impl ProofGenerator {
    /// Create a new generator from agent config.
    ///
    /// Loads the guest ELF binary from the path specified in config, or falls
    /// back to the default build output path relative to the workspace.
    pub fn from_config(config: &AgentConfig, use_boundless: bool) -> Result<Self> {
        let image_id = config.risc_zero_image_id.clone().unwrap_or_default();

        let guest_elf = Self::load_guest_elf(config)?;

        let policy = ZkAgentPolicy {
            allowed_tools: config.policy.allowed_tools.clone(),
            endpoint_allowlist: config.policy.endpoint_allowlist.clone(),
            max_value_autonomous: config.policy.max_value_autonomous_wei,
            capability_root: config
                .risc_zero_image_id
                .as_deref()
                .map(hex_to_bytes32)
                .unwrap_or([0u8; 32]),
        };

        Ok(Self {
            use_boundless,
            image_id,
            guest_elf,
            policy,
            boundless_api_url: config.boundless_api_url.clone(),
            boundless_api_key: config.boundless_api_key.clone(),
        })
    }

    /// Create a new generator with explicit parameters (backwards-compatible).
    ///
    /// `image_id` — RISC Zero image ID loaded from `RISC_ZERO_IMAGE_ID` env var.
    /// When empty, proofs will be non-verifiable on-chain.
    pub fn new(use_boundless: bool, image_id: String) -> Self {
        Self {
            use_boundless,
            image_id,
            guest_elf: Vec::new(),
            policy: ZkAgentPolicy {
                allowed_tools: vec![],
                endpoint_allowlist: vec![],
                max_value_autonomous: 1_000_000_000_000_000_000,
                capability_root: [0u8; 32],
            },
            boundless_api_url: "https://api.boundless.xyz".to_string(),
            boundless_api_key: None,
        }
    }

    /// Load the guest ELF binary from the configured path or default location.
    fn load_guest_elf(config: &AgentConfig) -> Result<Vec<u8>> {
        if let Some(ref path) = config.risc_zero_guest_elf_path {
            std::fs::read(path)
                .with_context(|| format!("failed to read guest ELF from {path}"))
        } else {
            let default_path =
                "zkvm/target/riscv32im-risc0-zkvm-elf/release/proof-of-claw-guest";
            std::fs::read(default_path).with_context(|| {
                format!(
                    "Guest ELF not found at default path ({default_path}). \
                     Build the guest first: cd zkvm && cargo risczero build --release, \
                     or set RISC_ZERO_GUEST_ELF_PATH."
                )
            })
        }
    }

    /// Generate a proof receipt for an execution trace.
    pub async fn generate_proof(&self, trace: &ExecutionTrace) -> Result<ProofReceipt> {
        if self.use_boundless {
            self.generate_proof_boundless(trace).await
        } else {
            self.generate_proof_local(trace).await
        }
    }

    /// Generate a proof using the local RISC Zero prover.
    ///
    /// Requires the `client` feature of `risc0-zkvm`.
    #[cfg(feature = "client")]
    async fn generate_proof_local(&self, trace: &ExecutionTrace) -> Result<ProofReceipt> {
        tracing::info!("Generating proof via local RISC Zero prover");

        if self.guest_elf.is_empty() {
            anyhow::bail!(
                "Guest ELF not loaded — cannot generate proof. \
                 Build the guest program first or set RISC_ZERO_GUEST_ELF_PATH."
            );
        }

        let zk_trace = convert_trace(trace);
        let policy = &self.policy;

        let env = ExecutorEnv::builder()
            .write(&zk_trace)
            .context("failed to write trace to executor env")?
            .write(policy)
            .context("failed to write policy to executor env")?
            .build()
            .context("failed to build executor env")?;

        let prover = default_prover();

        // Use Groth16 if Bonsai is configured, otherwise STARK
        let prove_info = if std::env::var("BONSAI_API_KEY").is_ok() {
            tracing::info!("Bonsai API key found — generating Groth16 proof");
            prover
                .prove_with_opts(env, &self.guest_elf, &ProverOpts::groth16())
                .context("RISC Zero Groth16 proving failed (Bonsai)")?
        } else {
            prover
                .prove(env, &self.guest_elf)
                .context("RISC Zero local STARK proving failed")?
        };

        let receipt = prove_info.receipt;
        let journal_bytes = receipt.journal.bytes.clone();
        let seal = bincode::serialize(&receipt)
            .context("failed to serialize receipt as seal")?;

        Ok(ProofReceipt {
            journal: journal_bytes,
            seal,
            image_id: self.image_id.clone(),
        })
    }

    /// Stub for local proof generation when `client` feature is not enabled.
    #[cfg(not(feature = "client"))]
    async fn generate_proof_local(&self, _trace: &ExecutionTrace) -> Result<ProofReceipt> {
        anyhow::bail!(
            "Local RISC Zero proving requires the `client` feature. \
             Enable it with: proof_of_claw = {{ features = [\"client\"] }}, \
             or use Boundless proving instead."
        )
    }

    /// Generate a proof via the Boundless proving marketplace.
    ///
    /// Submits the proving job to the Boundless API, polls for completion,
    /// and returns the resulting receipt. Falls back to local proving if
    /// the Boundless service is unavailable.
    async fn generate_proof_boundless(&self, trace: &ExecutionTrace) -> Result<ProofReceipt> {
        tracing::info!("Generating proof via Boundless proving marketplace");

        let zk_trace = convert_trace(trace);
        let input_bytes = bincode::serialize(&(&zk_trace, &self.policy))
            .context("failed to serialize proof input for Boundless")?;

        let client = reqwest::Client::new();
        let submit_url = format!("{}/v1/proofs", self.boundless_api_url);

        let mut req = client
            .post(&submit_url)
            .header("Content-Type", "application/octet-stream")
            .body(input_bytes.clone());

        if let Some(ref api_key) = self.boundless_api_key {
            req = req.header("Authorization", format!("Bearer {api_key}"));
        }

        let submit_resp = match req.send().await {
            Ok(resp) if resp.status().is_success() => resp,
            Ok(resp) => {
                tracing::warn!(
                    "Boundless API returned status {}; falling back to local proving",
                    resp.status()
                );
                return self.generate_proof_local(trace).await;
            }
            Err(e) => {
                tracing::warn!("Boundless API unreachable ({e}); falling back to local proving");
                return self.generate_proof_local(trace).await;
            }
        };

        #[derive(Deserialize)]
        struct SubmitResponse {
            proof_id: String,
        }

        let submit_data: SubmitResponse = submit_resp
            .json()
            .await
            .context("failed to parse Boundless submit response")?;

        let proof_id = submit_data.proof_id;
        tracing::info!("Boundless proof submitted: {proof_id}");

        // Poll for completion (up to 10 minutes at 5s intervals)
        let status_url = format!("{}/v1/proofs/{proof_id}", self.boundless_api_url);
        let max_attempts = 120;
        for attempt in 0..max_attempts {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;

            let mut status_req = client.get(&status_url);
            if let Some(ref api_key) = self.boundless_api_key {
                status_req = status_req.header("Authorization", format!("Bearer {api_key}"));
            }

            let status_resp = status_req
                .send()
                .await
                .context("failed to poll Boundless proof status")?;

            #[derive(Deserialize)]
            struct StatusResponse {
                status: String,
                receipt: Option<Vec<u8>>,
                journal: Option<Vec<u8>>,
            }

            let status_data: StatusResponse = status_resp
                .json()
                .await
                .context("failed to parse Boundless status response")?;

            match status_data.status.as_str() {
                "completed" => {
                    tracing::info!("Boundless proof completed (attempt {attempt})");
                    let journal = status_data
                        .journal
                        .context("completed proof missing journal")?;
                    let seal = status_data
                        .receipt
                        .context("completed proof missing receipt")?;

                    return Ok(ProofReceipt {
                        journal,
                        seal,
                        image_id: self.image_id.clone(),
                    });
                }
                "failed" => {
                    tracing::warn!("Boundless proof failed; falling back to local proving");
                    return self.generate_proof_local(trace).await;
                }
                _ => {
                    tracing::debug!(
                        "Boundless proof status: {} (attempt {attempt})",
                        status_data.status
                    );
                }
            }
        }

        tracing::warn!("Boundless proof timed out; falling back to local proving");
        self.generate_proof_local(trace).await
    }

    /// Verify a proof receipt by deserializing and verifying via RISC Zero.
    pub fn verify_receipt(&self, receipt: &ProofReceipt) -> Result<VerifiedOutput> {
        let real_receipt: risc0_zkvm::Receipt = bincode::deserialize(&receipt.seal)
            .context("failed to deserialize proof receipt — not a valid RISC Zero receipt")?;

        // Verify the receipt cryptographically — image_id is required
        if self.image_id.is_empty() {
            return Err(anyhow::anyhow!("Cannot verify: image_id is not configured"));
        }
        let image_id_bytes = hex_to_bytes32(&self.image_id);
        let digest = risc0_zkvm::sha::Digest::from(image_id_bytes);
        real_receipt
            .verify(digest)
            .map_err(|e| anyhow::anyhow!("RISC Zero receipt verification failed: {e:?}"))?;

        // Decode the journal as ZkVerifiedOutput
        let zk_output: ZkVerifiedOutput = real_receipt
            .journal
            .decode()
            .context("failed to decode journal")?;
        Ok(convert_verified_output(&zk_output))
    }
}

#[cfg(test)]
mod tests {
    use crate::types::{PolicyResult, PolicySeverity, ToolInvocation};

    use super::*;

    fn test_image_id() -> String {
        "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string()
    }

    fn test_trace() -> ExecutionTrace {
        ExecutionTrace {
            agent_id: "test-agent".to_string(),
            session_id: "session-123".to_string(),
            timestamp: 1234567890,
            inference_commitment: "0xabcd".to_string(),
            tool_invocations: vec![ToolInvocation {
                tool_name: "swap_tokens".to_string(),
                input_hash: "0x1111".to_string(),
                output_hash: "0x2222".to_string(),
                capability_hash: "0x3333".to_string(),
                timestamp: 1234567890,
                within_policy: true,
            }],
            policy_check_results: vec![PolicyResult {
                rule_id: "tool_allowlist".to_string(),
                severity: PolicySeverity::Pass,
                details: "All checks passed".to_string(),
            }],
            output_commitment: "0xoutput".to_string(),
        }
    }

    #[tokio::test]
    async fn test_proof_generation_requires_guest_elf() {
        // Without a guest ELF, proof generation must fail — no mock fallback
        let gen = ProofGenerator::new(false, test_image_id());
        let result = gen.generate_proof(&test_trace()).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("Guest ELF not loaded") || msg.contains("client"),
            "Expected error about missing guest ELF or client feature, got: {msg}"
        );
    }

    #[test]
    fn test_verify_receipt_rejects_invalid_data() {
        let gen = ProofGenerator::new(false, test_image_id());
        let bad_receipt = ProofReceipt {
            journal: b"not a real journal".to_vec(),
            seal: b"not a real seal".to_vec(),
            image_id: test_image_id(),
        };
        let result = gen.verify_receipt(&bad_receipt);
        assert!(result.is_err(), "Should reject non-RISC-Zero receipt data");
    }

    #[test]
    fn test_hex_to_bytes32() {
        let result = hex_to_bytes32("0xabcd");
        assert_eq!(result[0], 0xab);
        assert_eq!(result[1], 0xcd);
        assert_eq!(result[2..], [0u8; 30]);
    }

    #[test]
    fn test_bytes32_to_hex_roundtrip() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xde;
        bytes[1] = 0xad;
        let hex_str = bytes32_to_hex(&bytes);
        let back = hex_to_bytes32(&hex_str);
        assert_eq!(bytes, back);
    }
}
