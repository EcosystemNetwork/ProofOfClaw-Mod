use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use base64::Engine;

/// The image ID of the compiled guest program (computed from ELF)
const IMAGE_ID: &str = "0xa2ad29fbb85c3aee3a8863ffcb1fa287f537d89473f44df19cb2065834f025d2";

#[derive(Serialize, Deserialize)]
struct VerifiedOutput {
    agent_id: String,
    policy_hash: Vec<u8>,
    output_commitment: Vec<u8>,
    all_checks_passed: bool,
    requires_ledger_approval: bool,
    action_value: u64,
}

#[derive(Serialize)]
struct VerifyResult {
    ok: bool,
    verified_output: Option<VerifiedOutputJson>,
    verify_ms: Option<f64>,
    error: Option<String>,
    image_id: String,
    /// Always "structural" — cryptographic verification happens on-chain only.
    verification_level: String,
}

/// RISC Zero Groth16 proof method selector prefix
const GROTH16_SELECTOR: [u8; 4] = [0x31, 0x0f, 0xe5, 0x98];

#[derive(Serialize)]
struct VerifiedOutputJson {
    agent_id: String,
    policy_hash: String,
    output_commitment: String,
    all_checks_passed: bool,
    requires_ledger_approval: bool,
    action_value: String,
}

/// Validate the structure of a RISC Zero proof receipt in the browser.
///
/// # Security Model
///
/// This function performs STRUCTURAL validation only:
/// - Image ID matches the expected guest program
/// - Seal is well-formed with valid Groth16 selector prefix
/// - Seal meets minimum size requirements (256+ bytes)
/// - Journal commitment (SHA-256) appears in the seal
/// - Journal deserializes to a valid VerifiedOutput
///
/// **Cryptographic verification happens ON-CHAIN** via `RiscZeroGroth16Verifier.sol`.
/// This WASM module is a client-side pre-check for UX purposes (fast feedback).
///
/// An attacker CAN forge a structurally valid receipt that passes this check.
/// **Never use this function as a security boundary — always verify on-chain.**
#[wasm_bindgen]
pub fn validate_receipt_structure(journal_b64: &str, seal_b64: &str, image_id: &str) -> String {
    let start = js_sys::Date::now();
    let b64 = base64::engine::general_purpose::STANDARD;

    // Decode journal
    let journal_bytes = match b64.decode(journal_b64) {
        Ok(b) => b,
        Err(e) => return error_result(&format!("Invalid journal base64: {}", e)),
    };

    // Decode seal
    let seal_bytes = match b64.decode(seal_b64) {
        Ok(b) => b,
        Err(e) => return error_result(&format!("Invalid seal base64: {}", e)),
    };

    // Verify image ID matches
    let expected_id = IMAGE_ID.trim_start_matches("0x").to_lowercase();
    let provided_id = image_id.trim_start_matches("0x").to_lowercase();
    if expected_id != provided_id {
        return error_result(&format!(
            "Image ID mismatch: expected {}, got {}",
            expected_id, provided_id
        ));
    }

    // Compute journal hash (SHA-256)
    let mut hasher = Sha256::new();
    hasher.update(&journal_bytes);
    let journal_hash = hasher.finalize();

    // Check seal has minimum plausible length for a Groth16 proof
    if seal_bytes.len() < 256 {
        return error_result("Seal too short for a valid proof (minimum 256 bytes for Groth16)");
    }

    // Verify Groth16 method selector prefix
    if seal_bytes.len() >= 4 && seal_bytes[..4] != GROTH16_SELECTOR {
        return error_result(&format!(
            "Invalid seal prefix: expected Groth16 selector 0x310fe598, got 0x{}",
            hex::encode(&seal_bytes[..4])
        ));
    }

    // Check journal commitment (SHA-256) appears somewhere in the seal
    let journal_hash_bytes = journal_hash.as_slice();
    let has_commitment = seal_bytes.windows(journal_hash_bytes.len())
        .any(|w| w == journal_hash_bytes);
    if !has_commitment {
        return error_result("Journal commitment not found in seal — seal may not correspond to this journal");
    }

    // Try to deserialize the journal as VerifiedOutput
    let output: VerifiedOutput = match bincode_deserialize(&journal_bytes) {
        Some(o) => o,
        None => {
            // Try JSON fallback
            match serde_json::from_slice(&journal_bytes) {
                Ok(o) => o,
                Err(_) => return error_result("Failed to decode journal as VerifiedOutput"),
            }
        }
    };

    let elapsed = js_sys::Date::now() - start;

    let result = VerifyResult {
        ok: true,
        verified_output: Some(VerifiedOutputJson {
            agent_id: output.agent_id,
            policy_hash: hex::encode(&output.policy_hash),
            output_commitment: hex::encode(&output.output_commitment),
            all_checks_passed: output.all_checks_passed,
            requires_ledger_approval: output.requires_ledger_approval,
            action_value: output.action_value.to_string(),
        }),
        verify_ms: Some(elapsed),
        error: None,
        image_id: format!("0x{}", expected_id),
        verification_level: "structural".to_string(),
    };

    serde_json::to_string(&result).unwrap_or_else(|_| error_result("Serialization failed"))
}

/// Get the embedded image ID
#[wasm_bindgen]
pub fn get_image_id() -> String {
    IMAGE_ID.to_string()
}

fn error_result(msg: &str) -> String {
    let result = VerifyResult {
        ok: false,
        verified_output: None,
        verify_ms: None,
        error: Some(msg.to_string()),
        image_id: IMAGE_ID.to_string(),
        verification_level: "structural".to_string(),
    };
    serde_json::to_string(&result).unwrap_or_else(|_| format!(r#"{{"ok":false,"error":"{}","verification_level":"structural"}}"#, msg))
}

/// Simple bincode-compatible deserialization for the VerifiedOutput struct.
/// RISC Zero journals use bincode encoding.
fn bincode_deserialize(data: &[u8]) -> Option<VerifiedOutput> {
    // bincode format: length-prefixed strings, fixed-size arrays, bools, u64
    let mut cursor = 0;

    // agent_id: u64 length + utf8 bytes
    let agent_id = read_string(data, &mut cursor)?;

    // policy_hash: 32 bytes
    let policy_hash = read_fixed(data, &mut cursor, 32)?;

    // output_commitment: 32 bytes
    let output_commitment = read_fixed(data, &mut cursor, 32)?;

    // all_checks_passed: 1 byte bool
    if cursor >= data.len() { return None; }
    let all_checks_passed = data[cursor] != 0;
    cursor += 1;

    // requires_ledger_approval: 1 byte bool
    if cursor >= data.len() { return None; }
    let requires_ledger_approval = data[cursor] != 0;
    cursor += 1;

    // action_value: u64 little-endian
    let action_value = read_u64(data, &mut cursor)?;

    Some(VerifiedOutput {
        agent_id,
        policy_hash,
        output_commitment,
        all_checks_passed,
        requires_ledger_approval,
        action_value,
    })
}

fn read_u64(data: &[u8], cursor: &mut usize) -> Option<u64> {
    if *cursor + 8 > data.len() { return None; }
    let val = u64::from_le_bytes(data[*cursor..*cursor + 8].try_into().ok()?);
    *cursor += 8;
    Some(val)
}

fn read_string(data: &[u8], cursor: &mut usize) -> Option<String> {
    let len = read_u64(data, cursor)? as usize;
    if *cursor + len > data.len() { return None; }
    let s = std::str::from_utf8(&data[*cursor..*cursor + len]).ok()?.to_string();
    *cursor += len;
    Some(s)
}

fn read_fixed(data: &[u8], cursor: &mut usize, len: usize) -> Option<Vec<u8>> {
    if *cursor + len > data.len() { return None; }
    let v = data[*cursor..*cursor + len].to_vec();
    *cursor += len;
    Some(v)
}
