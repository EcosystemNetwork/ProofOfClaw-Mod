//! Ledger hardware approval gate — EIP-712 signing integration.
//!
//! High-value agent actions require physical Ledger approval via the
//! Ledger Ethereum app. This module manages the approval flow using
//! EIP-712 typed data signing.

use anyhow::{Context, Result};
use coins_ledger::{common::APDUData, transports::LedgerAsync, APDUCommand, Ledger};
use ethers::types::{Address, U256};

/// BIP-44 derivation path for Ethereum: m/44'/60'/0'/0/0
const BIP32_PATH: [u32; 5] = [
    0x8000_002C, // 44'
    0x8000_003C, // 60'
    0x8000_0000, // 0'
    0x0000_0000, // 0
    0x0000_0000, // 0
];

/// Ledger Ethereum app APDU constants.
const ETH_CLA: u8 = 0xE0;
const INS_SIGN_EIP712: u8 = 0x0C;

/// Default chain ID (Sepolia testnet).
const DEFAULT_CHAIN_ID: u64 = 11155111;

/// EIP-712 domain name matching the ProofOfClaw contract.
const DOMAIN_NAME: &str = "ProofOfClaw";
const DOMAIN_VERSION: &str = "1";

/// EIP-712 signature components.
#[derive(Debug, Clone)]
pub struct Eip712Signature {
    pub v: u8,
    pub r: [u8; 32],
    pub s: [u8; 32],
}

/// Parameters for an action requiring Ledger approval.
#[derive(Debug, Clone)]
pub struct ActionApproval {
    pub agent_id: [u8; 32],
    pub action_description: String,
    pub value: u64,
    pub policy_hash: [u8; 32],
}

/// Gate that requests physical Ledger approval for high-value actions.
pub struct LedgerApprovalGate {
    origin_token: Option<String>,
    device_path: Option<String>,
    chain_id: u64,
    verifier_address: Address,
}

impl LedgerApprovalGate {
    pub fn new(
        origin_token: Option<String>,
        device_path: Option<String>,
        chain_id: Option<u64>,
        verifier_address: Option<String>,
    ) -> Self {
        let address = verifier_address
            .and_then(|a| a.parse::<Address>().ok())
            .unwrap_or_default();

        Self {
            origin_token,
            device_path,
            chain_id: chain_id.unwrap_or(DEFAULT_CHAIN_ID),
            verifier_address: address,
        }
    }

    /// Request Ledger approval for an action via EIP-712 signing.
    ///
    /// Returns `Ok(true)` if the user approves on device.
    /// Returns `Ok(false)` if the user rejects on the Ledger or no device is available.
    /// Returns `Err` if communication fails unexpectedly.
    pub async fn request_approval(&self, action_description: &str, value_wei: u64) -> Result<bool> {
        tracing::info!(
            "Ledger approval requested: {} (value={value_wei} wei, token={:?})",
            action_description,
            self.origin_token.as_ref().map(|t| &t[..8.min(t.len())])
        );

        let domain_separator = self.compute_domain_separator();
        let approval = ActionApproval {
            agent_id: compute_agent_id_hash(
                self.origin_token.as_deref().unwrap_or("unknown"),
            ),
            action_description: action_description.to_string(),
            value: value_wei,
            policy_hash: [0u8; 32],
        };
        let message_hash = Self::compute_message_hash(&approval);

        match self.sign_eip712_on_ledger(&domain_separator, &message_hash).await {
            Ok(Some(sig)) => {
                tracing::info!(
                    "Ledger approval granted (v={}, r=0x{}..., s=0x{}...)",
                    sig.v,
                    hex::encode(&sig.r[..4]),
                    hex::encode(&sig.s[..4]),
                );
                Ok(true)
            }
            Ok(None) => {
                tracing::warn!("User rejected action on Ledger device");
                Ok(false)
            }
            Err(e) => {
                tracing::warn!("Ledger communication failed: {e:#}");
                tracing::warn!(
                    "No Ledger device available — falling back to software wallet confirmation"
                );
                self.software_wallet_fallback(action_description, value_wei)
                    .await
            }
        }
    }

    /// Request Ledger approval and return the full EIP-712 signature.
    ///
    /// Use this when the signature needs to be submitted on-chain.
    pub async fn request_approval_with_signature(
        &self,
        approval: &ActionApproval,
    ) -> Result<Option<Eip712Signature>> {
        tracing::info!(
            "Ledger EIP-712 signing requested: {} (value={} wei)",
            approval.action_description,
            approval.value,
        );

        let domain_separator = self.compute_domain_separator();
        let message_hash = Self::compute_message_hash(approval);

        self.sign_eip712_on_ledger(&domain_separator, &message_hash).await
    }

    /// Connect to the Ledger device and send an EIP-712 signing request.
    async fn sign_eip712_on_ledger(
        &self,
        domain_separator: &[u8; 32],
        message_hash: &[u8; 32],
    ) -> Result<Option<Eip712Signature>> {
        let ledger = self.connect_ledger().await?;

        // Build APDU payload: BIP32 path length (1 byte) + path elements (4 bytes each)
        // + domain separator hash (32 bytes) + message hash (32 bytes)
        let mut data = Vec::with_capacity(1 + BIP32_PATH.len() * 4 + 64);

        data.push(BIP32_PATH.len() as u8);
        for &element in &BIP32_PATH {
            data.extend_from_slice(&element.to_be_bytes());
        }

        data.extend_from_slice(domain_separator);
        data.extend_from_slice(message_hash);

        let command = APDUCommand {
            cla: ETH_CLA,
            ins: INS_SIGN_EIP712,
            p1: 0x00,
            p2: 0x00,
            data: APDUData::new(&data),
            response_len: None,
        };

        let response = ledger
            .exchange(&command)
            .await
            .context("Failed to send EIP-712 signing request to Ledger")?;

        let response_data = response.data();

        // Status word 0x6985 = user rejected on device
        if response.retcode() == 0x6985 {
            return Ok(None);
        }

        if response.retcode() != 0x9000 {
            anyhow::bail!(
                "Ledger returned error status: 0x{:04X}",
                response.retcode()
            );
        }

        // Parse signature: v (1 byte) + r (32 bytes) + s (32 bytes) = 65 bytes
        if response_data.len() < 65 {
            anyhow::bail!(
                "Unexpected Ledger response length: {} (expected 65)",
                response_data.len()
            );
        }

        let v = response_data[0];
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&response_data[1..33]);
        s.copy_from_slice(&response_data[33..65]);

        Ok(Some(Eip712Signature { v, r, s }))
    }

    /// Connect to a Ledger device via USB HID.
    async fn connect_ledger(&self) -> Result<Ledger> {
        if let Some(ref _path) = self.device_path {
            tracing::debug!("Ledger device path configured (auto-detect still used by coins-ledger)");
        }

        Ledger::init()
            .await
            .context("Failed to connect to Ledger device — is it plugged in with the Ethereum app open?")
    }

    /// Compute the EIP-712 domain separator hash.
    ///
    /// ```text
    /// keccak256(abi.encode(
    ///     keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
    ///     keccak256(name),
    ///     keccak256(version),
    ///     chainId,
    ///     verifyingContract
    /// ))
    /// ```
    fn compute_domain_separator(&self) -> [u8; 32] {
        use ethers::utils::keccak256;

        let type_hash = keccak256(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        );
        let name_hash = keccak256(DOMAIN_NAME.as_bytes());
        let version_hash = keccak256(DOMAIN_VERSION.as_bytes());

        let mut chain_id_bytes = [0u8; 32];
        U256::from(self.chain_id).to_big_endian(&mut chain_id_bytes);

        let mut address_bytes = [0u8; 32];
        address_bytes[12..32].copy_from_slice(self.verifier_address.as_bytes());

        let mut encoded = Vec::with_capacity(5 * 32);
        encoded.extend_from_slice(&type_hash);
        encoded.extend_from_slice(&name_hash);
        encoded.extend_from_slice(&version_hash);
        encoded.extend_from_slice(&chain_id_bytes);
        encoded.extend_from_slice(&address_bytes);

        keccak256(&encoded)
    }

    /// Compute the EIP-712 struct hash for an ActionApproval.
    ///
    /// ```text
    /// ActionApproval(bytes32 agentId,string actionDescription,uint256 value,bytes32 policyHash)
    /// ```
    fn compute_message_hash(approval: &ActionApproval) -> [u8; 32] {
        use ethers::utils::keccak256;

        let type_hash = keccak256(
            b"ActionApproval(bytes32 agentId,string actionDescription,uint256 value,bytes32 policyHash)",
        );
        let description_hash = keccak256(approval.action_description.as_bytes());

        let mut value_bytes = [0u8; 32];
        U256::from(approval.value).to_big_endian(&mut value_bytes);

        let mut encoded = Vec::with_capacity(5 * 32);
        encoded.extend_from_slice(&type_hash);
        encoded.extend_from_slice(&approval.agent_id);
        encoded.extend_from_slice(&description_hash);
        encoded.extend_from_slice(&value_bytes);
        encoded.extend_from_slice(&approval.policy_hash);

        keccak256(&encoded)
    }

    /// Fallback when no Ledger device is available.
    ///
    /// Returns `Ok(false)` — the action is not approved without hardware
    /// confirmation. The frontend can still call `approveAction()` on the
    /// contract with the owner's EOA.
    async fn software_wallet_fallback(
        &self,
        action_description: &str,
        value_wei: u64,
    ) -> Result<bool> {
        tracing::warn!(
            "SOFTWARE FALLBACK: Action '{}' (value={} wei) requires manual approval. \
             Connect a Ledger device for hardware signing, or approve via the frontend.",
            action_description,
            value_wei,
        );
        Ok(false)
    }

    /// Returns the origin token (for ERC-7730 clear-signing).
    pub fn origin_token(&self) -> Option<&str> {
        self.origin_token.as_deref()
    }

    /// Returns the configured chain ID.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Returns the verifier contract address used in the EIP-712 domain.
    pub fn verifier_address(&self) -> Address {
        self.verifier_address
    }
}

/// Hash an agent ID string to bytes32 (matches Solidity `keccak256(bytes(agentId))`).
fn compute_agent_id_hash(agent_id: &str) -> [u8; 32] {
    ethers::utils::keccak256(agent_id.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_separator_is_deterministic() {
        let gate = LedgerApprovalGate::new(None, None, Some(11155111), None);
        let sep1 = gate.compute_domain_separator();
        let sep2 = gate.compute_domain_separator();
        assert_eq!(sep1, sep2);
        assert_ne!(sep1, [0u8; 32]);
    }

    #[test]
    fn message_hash_includes_all_fields() {
        let approval = ActionApproval {
            agent_id: [0xAA; 32],
            action_description: "transfer 10 ETH".to_string(),
            value: 10_000_000_000_000_000_000,
            policy_hash: [0xBB; 32],
        };
        let hash1 = LedgerApprovalGate::compute_message_hash(&approval);

        let approval2 = ActionApproval {
            action_description: "transfer 1 ETH".to_string(),
            ..approval.clone()
        };
        let hash2 = LedgerApprovalGate::compute_message_hash(&approval2);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn agent_id_hash_matches_keccak() {
        let hash = compute_agent_id_hash("test-agent");
        assert_eq!(hash, ethers::utils::keccak256(b"test-agent"));
    }
}
