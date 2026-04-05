/**
 * Proof of Claw — ENS Resolution & Agent Discovery
 *
 * Resolves ENS names to agent profiles by reading on-chain text records.
 * Works with any ENS-compatible RPC (Sepolia, Mainnet, 0G).
 *
 * ENS text records used by Proof of Claw agents:
 *   proofclaw.policyHash     — SHA256 of the agent's policy
 *   proofclaw.imageId        — RISC Zero guest image ID
 *   proofclaw.agentType      — Agent specialization (defi-strategist, etc.)
 *   proofclaw.skills         — Comma-separated skill tags
 *   proofclaw.dm3Profile     — DM3 delivery service URL
 *   proofclaw.inftTokenId    — 0G iNFT token ID
 *   proofclaw.description    — Human-readable description
 *   proofclaw.version        — Agent version string
 *   description              — Standard ENS description
 *   url                      — Agent endpoint / dashboard URL
 *   avatar                   — Agent avatar (ENS standard)
 */

const ENSResolver = (() => {
  // ── Config ──
  // Check for configured RPC URL from environment config
  const CONFIGURED_RPC = window.__POC_ENV__?.RPC_URL;

  if (!CONFIGURED_RPC) {
    console.warn('ENS Resolver: Using demo Alchemy API key — configure RPC_URL for production');
  }

  const RPC_ENDPOINTS = {
    sepolia: CONFIGURED_RPC || 'https://eth-sepolia.g.alchemy.com/v2/demo',
    mainnet: 'https://eth.llamarpc.com',
    og_testnet: 'https://evmrpc-testnet.0g.ai',
  };

  const ENS_REGISTRY = {
    sepolia: '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e',
    mainnet: '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e',
  };

  // ENS Universal Resolver (supports wildcard resolution for subnames)
  const UNIVERSAL_RESOLVER = {
    sepolia: '0xc8Af999e38273D658BE1b921b88A9Ddf005769cC',
    mainnet: '0xce01f8eee7E479C928F8919abD53E553a36CeF67',
  };

  // Proof of Claw text record keys
  const RECORD_KEYS = [
    'proofclaw.policyHash',
    'proofclaw.imageId',
    'proofclaw.agentType',
    'proofclaw.skills',
    'proofclaw.dm3Profile',
    'proofclaw.inftTokenId',
    'proofclaw.description',
    'proofclaw.version',
    'description',
    'url',
    'avatar',
  ];

  let _rpcUrl = RPC_ENDPOINTS.sepolia;
  let _network = 'sepolia';

  // ── ENS Name Normalization (ENSIP-15 / UTS-46 basic) ──
  // Full UTS-46 requires @adraffy/ens-normalize, but we apply basic
  // lowercase + dot-normalization to catch the most common issues.
  function normalizeEnsName(name) {
    if (!name) return name;
    // Lowercase, trim whitespace, strip trailing dots, collapse consecutive dots
    return name.trim().toLowerCase().replace(/\.+$/, '').replace(/\.{2,}/g, '.');
  }

  // ── Public API ──

  function setNetwork(network) {
    _network = network;
    _rpcUrl = RPC_ENDPOINTS[network] || RPC_ENDPOINTS.sepolia;
  }

  function setRpcUrl(url) {
    _rpcUrl = url;
  }

  /**
   * Resolve an ENS name and fetch all Proof of Claw text records.
   * Returns an agent profile object or null if not found.
   */
  async function resolveAgent(ensName) {
    ensName = normalizeEnsName(ensName);
    try {
      const address = await resolveAddress(ensName);
      if (!address) return null;

      const records = await fetchTextRecords(ensName);

      return {
        ensName,
        address,
        policyHash: records['proofclaw.policyHash'] || null,
        imageId: records['proofclaw.imageId'] || null,
        agentType: records['proofclaw.agentType'] || 'unknown',
        skills: records['proofclaw.skills']
          ? records['proofclaw.skills'].split(',').map(s => s.trim())
          : [],
        dm3Profile: records['proofclaw.dm3Profile'] || null,
        inftTokenId: records['proofclaw.inftTokenId'] || null,
        description: records['proofclaw.description'] || records['description'] || '',
        version: records['proofclaw.version'] || '1.0',
        url: records['url'] || null,
        avatar: records['avatar'] || null,
        resolvedAt: new Date().toISOString(),
        network: _network,
      };
    } catch (e) {
      console.error(`[ENS] Resolution failed for "${ensName}":`, e);
      return null;
    }
  }

  /**
   * Resolve ENS name to Ethereum address.
   */
  async function resolveAddress(ensName) {
    ensName = normalizeEnsName(ensName);
    const node = namehash(ensName);

    // Try universal resolver first (supports subnames + wildcards)
    const universalAddr = UNIVERSAL_RESOLVER[_network];
    if (universalAddr) {
      try {
        // resolve(bytes,string) → address
        const dnsEncoded = dnsEncode(ensName);
        // addr(bytes32) selector = 0x3b3b57de
        const addrCalldata = '0x3b3b57de' + node.slice(2);
        const resolveSelector = '0x9061b923'; // resolve(bytes,bytes)
        const encoded = abiEncode(
          ['bytes', 'bytes'],
          [dnsEncoded, addrCalldata]
        );
        const result = await ethCall(universalAddr, resolveSelector + encoded);
        if (result && result !== '0x' && result.length >= 130) {
          const addr = '0x' + result.slice(result.length - 40);
          if (addr !== '0x0000000000000000000000000000000000000000') {
            return addr;
          }
        }
      } catch (e) {
        console.warn(`[ENS] Universal resolver failed for "${ensName}", trying registry:`, e.message);
      }
    }

    // Fallback: direct registry lookup
    const registryAddr = ENS_REGISTRY[_network];
    if (!registryAddr) return null;

    // resolver(bytes32) selector = 0x0178b8bf
    const resolverResult = await ethCall(registryAddr, '0x0178b8bf' + node.slice(2));
    if (!resolverResult || resolverResult === '0x') return null;

    const resolverAddr = '0x' + resolverResult.slice(resolverResult.length - 40);
    if (resolverAddr === '0x0000000000000000000000000000000000000000') return null;

    // addr(bytes32) selector = 0x3b3b57de
    const addrResult = await ethCall(resolverAddr, '0x3b3b57de' + node.slice(2));
    if (!addrResult || addrResult === '0x') return null;

    const addr = '0x' + addrResult.slice(addrResult.length - 40);
    if (addr === '0x0000000000000000000000000000000000000000') return null;
    return addr;
  }

  /**
   * Fetch all Proof of Claw text records for an ENS name.
   */
  async function fetchTextRecords(ensName) {
    ensName = normalizeEnsName(ensName);
    const node = namehash(ensName);
    const records = {};

    // Get resolver address
    const registryAddr = ENS_REGISTRY[_network];
    if (!registryAddr) return records;

    const resolverResult = await ethCall(registryAddr, '0x0178b8bf' + node.slice(2));
    if (!resolverResult || resolverResult === '0x') return records;

    const resolverAddr = '0x' + resolverResult.slice(resolverResult.length - 40);
    if (resolverAddr === '0x0000000000000000000000000000000000000000') return records;

    // Fetch each text record: text(bytes32,string)
    // selector = 0x59d1d43c
    const promises = RECORD_KEYS.map(async (key) => {
      try {
        const keyHex = utf8ToHex(key);
        // ABI encode: text(bytes32 node, string key)
        const nodeParam = node.slice(2).padStart(64, '0');
        const offsetParam = '0000000000000000000000000000000000000000000000000000000000000040';
        const keyByteLen = keyHex.length / 2;
        // Right-pad key to next 32-byte boundary
        const keyPadded = keyHex + '0'.repeat((64 - (keyHex.length % 64)) % 64);

        const calldata = '0x59d1d43c' + nodeParam + offsetParam +
          keyByteLen.toString(16).padStart(64, '0') + keyPadded;

        const result = await ethCall(resolverAddr, calldata);
        if (result && result.length > 130) {
          const decoded = decodeString(result);
          if (decoded) records[key] = decoded;
        }
      } catch (e) {
        console.warn(`[ENS] Failed to fetch text record "${key}":`, e.message);
      }
    });

    await Promise.all(promises);
    return records;
  }

  /**
   * Discover agents by searching known subname patterns under a parent domain.
   * Returns array of resolved agent profiles.
   */
  async function discoverAgents(parentDomain, knownSubnames) {
    if (!knownSubnames || knownSubnames.length === 0) return [];

    const results = await Promise.all(
      knownSubnames.map(sub => resolveAgent(`${sub}.${parentDomain}`))
    );

    return results.filter(r => r !== null);
  }

  // ── Internals ──

  async function ethCall(to, data) {
    const resp = await fetch(_rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'eth_call',
        params: [{ to, data }, 'latest'],
        id: Date.now(),
      }),
    });
    const json = await resp.json();
    return json.result || null;
  }

  // ENS namehash implementation (memoized to avoid redundant keccak256 calls)
  const _namehashCache = new Map();

  function namehash(name) {
    if (_namehashCache.has(name)) return _namehashCache.get(name);

    let node = '0x' + '00'.repeat(32);
    if (!name) return node;

    const labels = name.split('.').reverse();
    for (const label of labels) {
      const labelHash = keccak256(utf8ToBytes(label));
      node = keccak256(hexToBytes(node.slice(2) + labelHash.slice(2)));
    }

    _namehashCache.set(name, node);
    return node;
  }

  // Minimal keccak256 (browser-compatible, no dependencies)
  function keccak256(input) {
    // Use Web Crypto if available, otherwise fallback
    // For ENS namehash we need synchronous keccak256.
    // Inline a minimal keccak-256 implementation.
    return '0x' + keccak256Sync(input instanceof Uint8Array ? input : hexToBytes(input));
  }

  // ── Keccak-256 (pure JS, minimal) ──
  // Based on the reference implementation — sufficient for ENS namehash in a browser.
  const KECCAK_ROUND_CONSTANTS = [
    1n, 0x8082n, 0x800000000000808an, 0x8000000080008000n,
    0x808bn, 0x80000001n, 0x8000000080008081n, 0x8000000000008009n,
    0x8an, 0x88n, 0x80008009n, 0x8000000an,
    0x8000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
    0x8000000000008002n, 0x8000000000000080n, 0x800an, 0x800000008000000an,
    0x8000000080008081n, 0x8000000000008080n, 0x80000001n, 0x8000000080008008n,
  ];

  const ROTATION_OFFSETS = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
  ];

  function keccak256Sync(data) {
    const rate = 136; // 1088 bits / 8
    const capacity = 64;
    const outputLen = 32;

    // Pad
    const msgLen = data.length;
    const padLen = rate - (msgLen % rate);
    const padded = new Uint8Array(msgLen + padLen);
    padded.set(data);
    padded[msgLen] = 0x01;
    padded[padded.length - 1] |= 0x80;

    // State: 5x5 64-bit words
    const state = new Array(25).fill(0n);

    // Absorb
    for (let offset = 0; offset < padded.length; offset += rate) {
      for (let i = 0; i < rate / 8; i++) {
        const idx = offset + i * 8;
        let lane = 0n;
        for (let b = 0; b < 8; b++) {
          lane |= BigInt(padded[idx + b]) << BigInt(b * 8);
        }
        state[i] ^= lane;
      }
      keccakF1600(state);
    }

    // Squeeze
    const hash = new Uint8Array(outputLen);
    for (let i = 0; i < outputLen / 8; i++) {
      const lane = state[i];
      for (let b = 0; b < 8; b++) {
        hash[i * 8 + b] = Number((lane >> BigInt(b * 8)) & 0xFFn);
      }
    }

    return Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function keccakF1600(state) {
    for (let round = 0; round < 24; round++) {
      // Theta
      const C = new Array(5);
      for (let x = 0; x < 5; x++) {
        C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
      }
      const D = new Array(5);
      for (let x = 0; x < 5; x++) {
        D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1n);
      }
      for (let x = 0; x < 5; x++) {
        for (let y = 0; y < 5; y++) {
          state[x + y * 5] ^= D[x];
        }
      }

      // Rho and Pi
      const B = new Array(25).fill(0n);
      for (let x = 0; x < 5; x++) {
        for (let y = 0; y < 5; y++) {
          B[y + ((2 * x + 3 * y) % 5) * 5] = rotl64(state[x + y * 5], BigInt(ROTATION_OFFSETS[x][y]));
        }
      }

      // Chi
      for (let x = 0; x < 5; x++) {
        for (let y = 0; y < 5; y++) {
          state[x + y * 5] = B[x + y * 5] ^ (~B[(x + 1) % 5 + y * 5] & B[(x + 2) % 5 + y * 5]);
        }
      }

      // Iota
      state[0] ^= KECCAK_ROUND_CONSTANTS[round];
    }
  }

  function rotl64(x, n) {
    const mask = 0xFFFFFFFFFFFFFFFFn;
    x = x & mask;
    return ((x << n) | (x >> (64n - n))) & mask;
  }

  // ── Helpers ──

  function utf8ToBytes(str) {
    return new TextEncoder().encode(str);
  }

  function utf8ToHex(str) {
    const bytes = utf8ToBytes(str);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  }

  function decodeString(hexData) {
    try {
      // ABI-encoded string: offset (32) + length (32) + data
      const clean = hexData.startsWith('0x') ? hexData.slice(2) : hexData;
      if (clean.length < 128) return null;

      // Read offset
      const offset = parseInt(clean.slice(0, 64), 16) * 2;
      // Read length at offset
      const strLen = parseInt(clean.slice(offset, offset + 64), 16);
      if (strLen === 0 || strLen > 10000) return null;

      // Read string bytes
      const strHex = clean.slice(offset + 64, offset + 64 + strLen * 2);
      const bytes = hexToBytes(strHex);
      return new TextDecoder().decode(bytes);
    } catch {
      return null;
    }
  }

  function dnsEncode(name) {
    const labels = name.split('.');
    let result = '';
    for (const label of labels) {
      const bytes = utf8ToBytes(label);
      result += bytes.length.toString(16).padStart(2, '0');
      result += utf8ToHex(label);
    }
    result += '00'; // null terminator
    return '0x' + result;
  }

  function abiEncode(types, values) {
    // Minimal ABI encoder for (bytes, bytes) used by universal resolver
    // Both are dynamic so we need offsets
    let head = '';
    let tail = '';
    let offset = types.length * 32;

    for (let i = 0; i < types.length; i++) {
      head += offset.toString(16).padStart(64, '0');
      const val = typeof values[i] === 'string' ? values[i].replace('0x', '') : values[i];
      const len = val.length / 2;
      const lenHex = len.toString(16).padStart(64, '0');
      const padded = val + '0'.repeat((64 - (val.length % 64)) % 64);
      tail += lenHex + padded;
      offset += 32 + Math.ceil(val.length / 64) * 32;
    }

    return head + tail;
  }

  // ── Runtime keccak256/namehash verification ──
  // Verify against known test vectors (EIP-137) at load time to catch
  // any regression in the hand-rolled keccak256 implementation.
  (() => {
    const vectors = [
      ['', '0x' + '00'.repeat(32)],
      ['eth', '0x93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae'],
      ['vitalik.eth', '0xee6c4522aab0003e8d14cd40a6af439055fd2577951148c14b6cea9a53475835'],
    ];
    for (const [name, expected] of vectors) {
      const got = namehash(name);
      if (got !== expected) {
        console.error(`[ENS] CRITICAL: namehash("${name}") = ${got}, expected ${expected}. Keccak256 implementation is broken.`);
      }
    }
  })();

  // ── Public exports ──
  return {
    setNetwork,
    setRpcUrl,
    resolveAgent,
    resolveAddress,
    fetchTextRecords,
    discoverAgents,
    namehash,
    normalizeEnsName,
    RECORD_KEYS,
    RPC_ENDPOINTS,
  };
})();
