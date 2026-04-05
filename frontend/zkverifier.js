// proof_of_claw_verifier.js — thin wrapper around the WASM module
// Built with: cd zkvm/wasm-verifier && wasm-pack build --target web --release --out-dir ../../frontend/pkg
// Output: frontend/pkg/proof_of_claw_verifier.js + proof_of_claw_verifier_bg.wasm

let _wasmModule = null;
let _wasmAvailable = null; // null = not checked, true/false after check

async function ensureWasm() {
  if (_wasmModule) return _wasmModule;
  try {
    const mod = await import('./pkg/proof_of_claw_verifier.js');
    await mod.default();
    _wasmModule = mod;
    _wasmAvailable = true;
    return _wasmModule;
  } catch (e) {
    _wasmAvailable = false;
    console.warn('[zkverifier] WASM not available — falling back to mock mode.', e.message);
    return null;
  }
}

/**
 * Check whether the WASM verifier is available (non-throwing).
 * @returns {Promise<boolean>}
 */
window.zkVerifierAvailable = async function() {
  if (_wasmAvailable !== null) return _wasmAvailable;
  await ensureWasm();
  return _wasmAvailable;
};

/**
 * Validate the structure of a RISC Zero proof receipt in the browser.
 * WARNING: This performs structural validation only — NOT cryptographic verification.
 * Full cryptographic STARK/Groth16 verification MUST happen on-chain.
 * @param {string} journalB64 - Base64-encoded journal bytes
 * @param {string} sealB64   - Base64-encoded cryptographic seal
 * @param {string} imageId   - Image ID used to generate the proof (hex string)
 * @returns {Promise<{ok: boolean, verified_output?: object, verify_ms?: number, error?: string, verification_level: string, status_label: string}>}
 */
window.zkVerify = async function(journalB64, sealB64, imageId) {
  const mod = await ensureWasm();
  if (!mod) {
    return { ok: false, error: 'WASM verifier not built — proof will be verified on-chain only', mock: true, verification_level: 'none', status_label: 'Awaiting on-chain verification' };
  }
  const result = JSON.parse(window.__zkVerifyRaw(journalB64, sealB64, imageId));
  // Make verification level explicit for UI consumers
  result.verification_level = result.verification_level || 'structural';
  result.status_label = result.ok
    ? 'Structure Valid \u2014 awaiting on-chain verification'
    : 'Structure Invalid \u2014 ' + (result.error || 'unknown error');
  return result;
};

// Expose raw C→JS string return for wasm-bindgen
window.__zkVerifyRaw = function(journalB64, sealB64, imageId) {
  if (!_wasmModule) throw new Error('WASM not loaded');
  return _wasmModule.validate_receipt_structure(journalB64, sealB64, imageId);
};

/**
 * Get the image ID embedded at build time.
 * @returns {Promise<string>} Hex string prefixed with "0x", or null if WASM not available
 */
window.getImageId = async function() {
  const mod = await ensureWasm();
  if (!mod) return null;
  return _wasmModule.get_image_id();
};
