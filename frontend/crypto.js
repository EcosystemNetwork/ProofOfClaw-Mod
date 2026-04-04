/**
 * Proof of Claw — Browser-side AES-256-GCM Encryption
 * Uses the Web Crypto API for real encryption of agent secrets and backup data.
 *
 * ENS Hierarchy: Name.Swarm.Org.eth
 * Key Hierarchy: K_master → K_org → K_swarm → K_agent
 */

'use strict';

/* ══════════════════════════════════════
   AES-256-GCM CORE
   ══════════════════════════════════════ */

/**
 * Generate a random AES-256 key
 * @returns {Promise<CryptoKey>}
 */
async function generateAESKey() {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true, // extractable
    ['encrypt', 'decrypt']
  );
}

/**
 * Import raw bytes as an AES-256-GCM key
 * @param {ArrayBuffer|Uint8Array} rawKey - 32 bytes
 * @returns {Promise<CryptoKey>}
 */
async function importAESKey(rawKey) {
  return crypto.subtle.importKey(
    'raw',
    rawKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * Export a CryptoKey to raw bytes
 * @param {CryptoKey} key
 * @returns {Promise<ArrayBuffer>}
 */
async function exportAESKey(key) {
  return crypto.subtle.exportKey('raw', key);
}

/**
 * Encrypt data with AES-256-GCM
 * @param {string|Uint8Array} plaintext
 * @param {CryptoKey} key
 * @param {string} [aad] - Additional Authenticated Data (e.g., agentId, swarmId)
 * @returns {Promise<{ciphertext: string, nonce: string, tag: string, aad: string}>}
 *          All values are base64-encoded
 */
async function encryptAES256GCM(plaintext, key, aad) {
  const encoder = new TextEncoder();
  const data = typeof plaintext === 'string' ? encoder.encode(plaintext) : plaintext;
  const nonce = crypto.getRandomValues(new Uint8Array(12)); // 96-bit nonce
  const aadBytes = aad ? encoder.encode(aad) : new Uint8Array(0);

  const encrypted = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
      additionalData: aadBytes,
      tagLength: 128
    },
    key,
    data
  );

  // Web Crypto appends the 16-byte auth tag to the ciphertext
  const encryptedBytes = new Uint8Array(encrypted);
  const ciphertextBytes = encryptedBytes.slice(0, encryptedBytes.length - 16);
  const tagBytes = encryptedBytes.slice(encryptedBytes.length - 16);

  return {
    ciphertext: bufToBase64(ciphertextBytes),
    nonce: bufToBase64(nonce),
    tag: bufToBase64(tagBytes),
    aad: aad || ''
  };
}

/**
 * Decrypt data with AES-256-GCM
 * @param {string} ciphertextB64 - base64 ciphertext
 * @param {CryptoKey} key
 * @param {string} nonceB64 - base64 nonce
 * @param {string} tagB64 - base64 auth tag
 * @param {string} [aad] - Additional Authenticated Data
 * @returns {Promise<string>} - Decrypted plaintext
 */
async function decryptAES256GCM(ciphertextB64, key, nonceB64, tagB64, aad) {
  const ciphertext = base64ToBuf(ciphertextB64);
  const nonce = base64ToBuf(nonceB64);
  const tag = base64ToBuf(tagB64);
  const encoder = new TextEncoder();
  const aadBytes = aad ? encoder.encode(aad) : new Uint8Array(0);

  // Web Crypto expects ciphertext + tag concatenated
  const combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext);
  combined.set(tag, ciphertext.length);

  const decrypted = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
      additionalData: aadBytes,
      tagLength: 128
    },
    key,
    combined
  );

  return new TextDecoder().decode(decrypted);
}

/* ══════════════════════════════════════
   KEY DERIVATION (HKDF)
   ══════════════════════════════════════ */

/**
 * Derive a purpose-specific key using HKDF-SHA256
 * @param {CryptoKey|ArrayBuffer} masterKey
 * @param {string} info - Context string (e.g., "org:acme", "swarm:alpha", "agent:bot1")
 * @param {Uint8Array} [salt] - Optional salt
 * @returns {Promise<CryptoKey>}
 */
async function deriveKey(masterKey, info, salt) {
  const keyMaterial = masterKey instanceof CryptoKey
    ? await crypto.subtle.exportKey('raw', masterKey)
    : masterKey;

  const baseKey = await crypto.subtle.importKey(
    'raw', keyMaterial, 'HKDF', false, ['deriveKey']
  );

  const encoder = new TextEncoder();
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt || new Uint8Array(32),
      info: encoder.encode(info)
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

/* ══════════════════════════════════════
   EPOCH KEY WRAPPING (ECDH)
   ══════════════════════════════════════ */

/**
 * Wrap an epoch key for a recipient using ECDH + AES-256-GCM
 * Uses P-256 (Web Crypto supported) for ECDH key agreement
 * @param {ArrayBuffer} epochKeyRaw - 32-byte epoch key
 * @param {CryptoKey} recipientPublicKey - Recipient's ECDH public key
 * @returns {Promise<{wrappedKey: string, ephemeralPublicKey: string, nonce: string}>}
 */
async function wrapEpochKey(epochKeyRaw, recipientPublicKey) {
  // Generate ephemeral ECDH keypair
  const ephemeral = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey']
  );

  // Derive shared AES key from ECDH
  const sharedKey = await crypto.subtle.deriveKey(
    { name: 'ECDH', public: recipientPublicKey },
    ephemeral.privateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  // Encrypt the epoch key with the shared key
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const wrapped = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 },
    sharedKey,
    epochKeyRaw
  );

  // Export ephemeral public key
  const ephPubRaw = await crypto.subtle.exportKey('raw', ephemeral.publicKey);

  return {
    wrappedKey: bufToBase64(new Uint8Array(wrapped)),
    ephemeralPublicKey: bufToBase64(new Uint8Array(ephPubRaw)),
    nonce: bufToBase64(nonce)
  };
}

/**
 * Unwrap an epoch key using ECDH
 * @param {string} wrappedKeyB64 - base64 wrapped key
 * @param {string} ephemeralPubB64 - base64 ephemeral public key
 * @param {string} nonceB64 - base64 nonce
 * @param {CryptoKey} recipientPrivateKey - Recipient's ECDH private key
 * @returns {Promise<ArrayBuffer>} - Raw 32-byte epoch key
 */
async function unwrapEpochKey(wrappedKeyB64, ephemeralPubB64, nonceB64, recipientPrivateKey) {
  const ephemeralPub = await crypto.subtle.importKey(
    'raw',
    base64ToBuf(ephemeralPubB64),
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );

  const sharedKey = await crypto.subtle.deriveKey(
    { name: 'ECDH', public: ephemeralPub },
    recipientPrivateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  return crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToBuf(nonceB64), tagLength: 128 },
    sharedKey,
    base64ToBuf(wrappedKeyB64)
  );
}

/* ══════════════════════════════════════
   SECRET STORAGE (ENCRYPTED LOCALSTORAGE)
   ══════════════════════════════════════ */

/**
 * Encrypt and store a secret in localStorage
 * @param {string} storageKey - localStorage key
 * @param {string} plaintext - Secret to encrypt
 * @param {string} password - User password or derived key material
 */
async function storeEncryptedSecret(storageKey, plaintext, password) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));

  // Derive key from password using PBKDF2
  const keyMaterial = await crypto.subtle.importKey(
    'raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']
  );
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 },
    key,
    encoder.encode(plaintext)
  );

  const payload = {
    v: 1, // version
    alg: 'AES-256-GCM',
    kdf: 'PBKDF2-SHA256-100k',
    salt: bufToBase64(salt),
    nonce: bufToBase64(nonce),
    data: bufToBase64(new Uint8Array(encrypted))
  };

  localStorage.setItem(storageKey, JSON.stringify(payload));
}

/**
 * Decrypt a secret from localStorage
 * @param {string} storageKey - localStorage key
 * @param {string} password - User password
 * @returns {Promise<string|null>} - Decrypted secret or null
 */
async function loadEncryptedSecret(storageKey, password) {
  const raw = localStorage.getItem(storageKey);
  if (!raw) return null;

  try {
    const payload = JSON.parse(raw);
    if (payload.v !== 1) return null;

    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    const key = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: base64ToBuf(payload.salt),
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBuf(payload.nonce), tagLength: 128 },
      key,
      base64ToBuf(payload.data)
    );

    return new TextDecoder().decode(decrypted);
  } catch {
    return null;
  }
}

/* ══════════════════════════════════════
   HASHING
   ══════════════════════════════════════ */

/**
 * SHA-256 hash of a string or buffer
 * @param {string|Uint8Array} data
 * @returns {Promise<string>} - Hex-encoded hash
 */
async function sha256(data) {
  const encoder = new TextEncoder();
  const buf = typeof data === 'string' ? encoder.encode(data) : data;
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return bufToHex(new Uint8Array(hash));
}

/* ══════════════════════════════════════
   ENCODING HELPERS
   ══════════════════════════════════════ */

function bufToBase64(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function base64ToBuf(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function bufToHex(buf) {
  return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBuf(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  return bytes;
}
