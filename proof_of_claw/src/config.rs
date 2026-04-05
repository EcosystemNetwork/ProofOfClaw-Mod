//! Configuration for Proof of Claw — loaded from environment variables.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Top-level agent configuration.
#[derive(Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Human-readable agent identifier (also used as ENS subname).
    pub agent_id: String,
    /// ENS name for this agent (e.g. `myagent.proofclaw.eth`).
    pub ens_name: String,
    /// Ethereum private key (hex, with or without `0x` prefix).
    pub private_key: String,
    /// Ethereum RPC endpoint (e.g. `https://eth-sepolia.g.alchemy.com/v3/...`).
    pub rpc_url: String,
    /// 0G Storage indexer RPC endpoint.
    pub zero_g_indexer_rpc: String,
    /// 0G Compute inference endpoint.
    pub zero_g_compute_endpoint: String,
    /// DM3 delivery service URL for encrypted messaging.
    pub dm3_delivery_service_url: String,
    /// Address of the deployed ProofOfClawVerifier contract (for EIP-712 domain).
    pub verifier_contract_address: Option<String>,
    /// Chain ID for EIP-712 domain (defaults to 11155111 / Sepolia).
    pub chain_id: Option<u64>,
    // ── EIP-8004 registries ──────────────────────────────────────────────
    pub eip8004_identity_registry: Option<String>,
    pub eip8004_reputation_registry: Option<String>,
    pub eip8004_validation_registry: Option<String>,
    pub eip8004_integration_contract: Option<String>,
    /// ERC-7857 iNFT contract address.
    pub inft_contract: Option<String>,
    /// RISC Zero image ID for the proof circuit.
    pub risc_zero_image_id: Option<String>,
    /// SHA-256 hash of the OCMB v0.1 soul backup YAML (required for iNFT minting).
    pub soul_backup_hash: Option<String>,
    /// 0G Storage URI for the encrypted soul backup.
    pub soul_backup_uri: Option<String>,
    /// Path to the guest ELF binary. Set via `RISC_ZERO_GUEST_ELF_PATH` env var.
    pub risc_zero_guest_elf_path: Option<String>,
    /// Boundless proving marketplace API endpoint. Defaults to `https://api.boundless.xyz`.
    pub boundless_api_url: String,
    /// Boundless API key for authentication. Set via `BOUNDLESS_API_KEY` env var.
    pub boundless_api_key: Option<String>,
    pub policy: PolicyConfig,
}

/// Policy thresholds and tool allowlist for this agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Tools this agent is allowed to invoke. Empty = allow all.
    pub allowed_tools: Vec<String>,
    /// Approved HTTP endpoints. Empty = allow all.
    pub endpoint_allowlist: Vec<String>,
    /// Maximum value (in wei) for autonomous actions. Actions above this
    /// require physical Ledger approval.
    pub max_value_autonomous_wei: u64,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            allowed_tools: vec!["query".to_string(), "read".to_string()],
            endpoint_allowlist: vec![],
            max_value_autonomous_wei: 1_000_000_000_000_000_000u64, // 1 ETH
        }
    }
}

impl fmt::Debug for AgentConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentConfig")
            .field("agent_id", &self.agent_id)
            .field("ens_name", &self.ens_name)
            .field("private_key", &"[REDACTED]")
            .field("rpc_url", &self.rpc_url)
            .field("zero_g_indexer_rpc", &self.zero_g_indexer_rpc)
            .field("zero_g_compute_endpoint", &self.zero_g_compute_endpoint)
            .field("dm3_delivery_service_url", &self.dm3_delivery_service_url)
            .field("verifier_contract_address", &self.verifier_contract_address)
            .field("chain_id", &self.chain_id)
            .field("eip8004_identity_registry", &self.eip8004_identity_registry)
            .field("eip8004_reputation_registry", &self.eip8004_reputation_registry)
            .field("eip8004_validation_registry", &self.eip8004_validation_registry)
            .field("eip8004_integration_contract", &self.eip8004_integration_contract)
            .field("inft_contract", &self.inft_contract)
            .field("risc_zero_image_id", &self.risc_zero_image_id)
            .field("soul_backup_hash", &self.soul_backup_hash)
            .field("soul_backup_uri", &self.soul_backup_uri)
            .field("risc_zero_guest_elf_path", &self.risc_zero_guest_elf_path)
            .field("boundless_api_url", &self.boundless_api_url)
            .field("boundless_api_key", &"[REDACTED]")
            .field("policy", &self.policy)
            .finish()
    }
}

impl AgentConfig {
    /// Load all config from environment variables.
    ///
    /// # Required env vars
    /// - `AGENT_ID`, `ENS_NAME`, `PRIVATE_KEY`, `RPC_URL`
    /// - `ZERO_G_INDEXER_RPC`, `ZERO_G_COMPUTE_ENDPOINT`
    /// - `DM3_DELIVERY_SERVICE_URL`
    /// - `ALLOWED_TOOLS`, `ENDPOINT_ALLOWLIST`, `MAX_VALUE_AUTONOMOUS_WEI`
    ///
    /// # Optional env vars
    /// - `LEDGER_ORIGIN_TOKEN`
    /// - `EIP8004_IDENTITY_REGISTRY`, `EIP8004_REPUTATION_REGISTRY`,
    ///   `EIP8004_VALIDATION_REGISTRY`, `EIP8004_INTEGRATION_CONTRACT`
    /// - `INFT_CONTRACT`, `RISC_ZERO_IMAGE_ID`
    pub fn from_env() -> Result<Self> {
        let private_key = env_required("PRIVATE_KEY")?;
        let stripped = private_key.trim_start_matches("0x");
        if stripped.chars().all(|c| c == '0') {
            anyhow::bail!("PRIVATE_KEY is set to all zeros — configure a real key in .env");
        }

        Ok(Self {
            agent_id: env_required("AGENT_ID")?,
            ens_name: env_required("ENS_NAME")?,
            private_key,
            rpc_url: env_required("RPC_URL")?,
            zero_g_indexer_rpc: env_required("ZERO_G_INDEXER_RPC")?,
            zero_g_compute_endpoint: env_required("ZERO_G_COMPUTE_ENDPOINT")?,
            dm3_delivery_service_url: env_required("DM3_DELIVERY_SERVICE_URL")?,
            verifier_contract_address: env_address("VERIFIER_CONTRACT_ADDRESS"),
            chain_id: env_opt("CHAIN_ID").and_then(|v| v.parse().ok()),
            eip8004_identity_registry: env_address("EIP8004_IDENTITY_REGISTRY"),
            eip8004_reputation_registry: env_address("EIP8004_REPUTATION_REGISTRY"),
            eip8004_validation_registry: env_address("EIP8004_VALIDATION_REGISTRY"),
            eip8004_integration_contract: env_address("EIP8004_INTEGRATION_CONTRACT"),
            inft_contract: env_address("INFT_CONTRACT"),
            risc_zero_image_id: env_hash("RISC_ZERO_IMAGE_ID"),
            soul_backup_hash: env_hash("SOUL_BACKUP_HASH"),
            soul_backup_uri: env_opt("SOUL_BACKUP_URI"),
            risc_zero_guest_elf_path: env_opt("RISC_ZERO_GUEST_ELF_PATH"),
            boundless_api_url: env_with_default("BOUNDLESS_API_URL", "https://api.boundless.xyz"),
            boundless_api_key: env_opt("BOUNDLESS_API_KEY"),
            policy: PolicyConfig {
                allowed_tools: env_with_default("ALLOWED_TOOLS", "query,read,swap_tokens,transfer")
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
                endpoint_allowlist: env_with_default("ENDPOINT_ALLOWLIST", "")
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
                max_value_autonomous_wei: env_with_default("MAX_VALUE_AUTONOMOUS_WEI", "1000000000000000000")
                    .parse()
                    .context("MAX_VALUE_AUTONOMOUS_WEI must be a valid u64")?,
            },
        })
    }

    /// Returns true when EIP-8004 registries are configured.
    pub fn has_eip8004(&self) -> bool {
        self.eip8004_identity_registry.is_some()
    }

    /// Returns true when the iNFT contract is configured.
    pub fn has_inft(&self) -> bool {
        self.inft_contract.is_some()
    }
}

// ── Env helpers ───────────────────────────────────────────────────────────────

/// Read a required env var. Returns an error if not set or empty.
fn env_required(var: &str) -> Result<String> {
    std::env::var(var)
        .ok()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow::anyhow!("{var} is required but not set. Configure it in .env"))
}

/// Read an env var with a sensible operational default (not a mock).
fn env_with_default(var: &str, default: &str) -> String {
    std::env::var(var)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn env_opt(var: &str) -> Option<String> {
    std::env::var(var).ok().filter(|v| !v.is_empty())
}

/// Read a hex address env var. Returns `None` if unset or all-zeros.
fn env_address(key: &str) -> Option<String> {
    env_opt(key).and_then(|v| {
        let stripped = v.trim_start_matches("0x");
        if stripped.chars().all(|c| c == '0') {
            None
        } else {
            Some(v)
        }
    })
}

/// Read a hex hash env var. Returns `None` if unset or all-zeros.
fn env_hash(key: &str) -> Option<String> {
    env_opt(key).and_then(|v| {
        let stripped = v.trim_start_matches("0x");
        if stripped.is_empty() || stripped.chars().all(|c| c == '0') {
            None
        } else {
            Some(v)
        }
    })
}
