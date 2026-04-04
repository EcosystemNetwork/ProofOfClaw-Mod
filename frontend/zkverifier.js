// proof_of_claw_verifier.js — thin wrapper around the WASM module
// Built with: cargo build --release --target wasm32-unknown-unknown -p proof-of-claw-verifier
// Output: frontend/proof_of_claw_verifier.wasm + proof_of_claw_verifier.js

let _wasmModule = null;

async function ensureWasm() {
  if (_wasmModule) return _wasmModule;
  try {
    const { default: init, ...mod } = await import('./proof_of_claw_verifier.js');
    await init();
    _wasmModule = { ...mod, init };
    return _wasmModule;
  } catch (e) {
    console.error('[zkverifier] Failed to load WASM:', e);
    throw new Error(
      'ZK verifier WASM not found. Build it with:\n' +
      '  cargo build --release --target wasm32-unknown-unknown -p proof-of-claw-verifier\n' +
      'Then copy the .wasm and .js files to frontend/.'
    );
  }
}

/**
 * Verify a RISC Zero proof receipt in the browser.
 * @param {string} journalB64 - Base64-encoded journal bytes
 * @param {string} sealB64   - Base64-encoded cryptographic seal
 * @param {string} imageId   - Image ID used to generate the proof (hex string)
 * @returns {Promise<{ok: boolean, verified_output?: object, verify_ms?: number, error?: string}>}
 */
window.zkVerify = async function(journalB64, sealB64, imageId) {
  await ensureWasm();
  const result = JSON.parse(window.__zkVerifyRaw(journalB64, sealB64, imageId));
  return result;
};

// Expose raw C→JS string return for wasm-bindgen
window.__zkVerifyRaw = async function(journalB64, sealB64, imageId) {
  await ensureWasm();
  return _wasmModule.verify_receipt(journalB64, sealB64, imageId);
};

/**
 * Get the image ID embedded at build time.
 * @returns {Promise<string>} Hex string prefixed with "0x"
 */
window.getImageId = async function() {
  await ensureWasm();
  return _wasmModule.get_image_id();
};
