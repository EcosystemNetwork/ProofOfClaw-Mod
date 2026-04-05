/**
 * Proof of Claw — Viem Blockchain Integration
 * Handles wallet connection, contract interactions, and agent onchain registration
 */

// Import viem from CDN (ES modules)
import { createPublicClient, createWalletClient, custom, http, parseAbi, encodePacked, keccak256, stringToBytes } from 'https://esm.sh/viem@2.21.44';
import { privateKeyToAccount } from 'https://esm.sh/viem@2.21.44/_esm/accounts/privateKeyToAccount.js';
import { mainnet, sepolia } from 'https://esm.sh/viem@2.21.44/chains';
import { CONTRACT_ADDRESSES, ZERO_G_CONFIG } from './env-config.js';

// ═══════════════════════════════════════
// CONTRACT CONFIGURATION
// ═══════════════════════════════════════

const CONTRACT_ABIS = {
  // ProofOfClawINFT - ERC-7857 Agent iNFT Contract
  inft: parseAbi([
    'function mint(bytes32 agentId, bytes32 policyHash, bytes32 riscZeroImageId, string calldata encryptedURI, bytes32 metadataHash, bytes32 soulBackupHash, string calldata soulBackupURI, string calldata ensName) external returns (uint256 tokenId)',
    'function mintTo(address to, bytes32 agentId, bytes32 policyHash, bytes32 riscZeroImageId, string calldata encryptedURI, bytes32 metadataHash, bytes32 soulBackupHash, string calldata soulBackupURI, string calldata ensName) external returns (uint256 tokenId)',
    'function agentToToken(bytes32 agentId) external view returns (uint256)',
    'function agents(uint256 tokenId) external view returns (address owner, bytes32 agentId, bytes32 policyHash, bytes32 riscZeroImageId, string memory encryptedURI, bytes32 metadataHash, string memory ensName, uint256 reputationScore, uint256 totalProofs, uint256 mintedAt, bool active)',
    'function ownerOf(uint256 tokenId) external view returns (address)',
    'function balanceOf(address owner) external view returns (uint256)',
    'function totalSupply() external view returns (uint256)',
    'function transferFrom(address from, address to, uint256 tokenId) external',
    'event AgentMinted(uint256 indexed tokenId, bytes32 indexed agentId, address indexed owner, string ensName)',
  ]),

  // EIP8004Integration - Agent Identity Registry
  registry: parseAbi([
    'function registerAgentIdentity(bytes32 agentId, string calldata agentURI, bytes32 policyHash, bytes32 riscZeroImageId) external returns (uint256 tokenId)',
    'function agentToTokenId(bytes32 agentId) external view returns (uint256)',
    'function getTokenId(bytes32 agentId) external view returns (uint256)',
    'event AgentIdentityRegistered(bytes32 indexed agentId, uint256 indexed tokenId, string agentURI)',
  ]),
};

// Contract addresses imported from env-config.js

// ═══════════════════════════════════════
// CLIENT STATE
// ═══════════════════════════════════════

let publicClient = null;
let walletClient = null;
let currentChain = sepolia;
let walletAddress = null;

// ═══════════════════════════════════════
// INITIALIZATION
// ═══════════════════════════════════════

/**
 * Initialize the viem clients
 * @param {string} network - 'sepolia' | 'og_testnet' | 'mainnet' | 'og_mainnet'
 */
export function initViem(network = 'sepolia') {
  // Configure chain
  if (network === 'sepolia') {
    currentChain = sepolia;
  } else if (network === 'mainnet') {
    currentChain = mainnet;
  } else {
    // 0G networks - use custom chain config from env
    const netConfig = network === 'og_testnet' ? ZERO_G_CONFIG.testnet : ZERO_G_CONFIG.mainnet;
    currentChain = {
      id: netConfig.chainId,
      name: netConfig.name,
      nativeCurrency: { name: '0G', symbol: 'OG', decimals: 18 },
      rpcUrls: {
        default: {
          http: [netConfig.rpcUrl],
        },
      },
    };
  }

  // Create public client for reading from blockchain
  publicClient = createPublicClient({
    chain: currentChain,
    transport: http(),
  });

  return { publicClient, chain: currentChain };
}

/**
 * Connect wallet using browser provider (MetaMask, etc.)
 * @returns {Promise<{address: string, client: object}>}
 */
export async function connectWallet() {
  if (!window.ethereum) {
    throw new Error('No wallet detected. Please install MetaMask or another Web3 wallet.');
  }

  // Request account access
  const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
  if (!accounts || accounts.length === 0) {
    throw new Error('No accounts authorized. Please unlock your wallet.');
  }

  walletAddress = accounts[0];

  // Create wallet client
  walletClient = createWalletClient({
    chain: currentChain,
    transport: custom(window.ethereum),
  });

  // Listen for account changes
  window.ethereum.on('accountsChanged', (newAccounts) => {
    if (newAccounts.length === 0) {
      walletAddress = null;
      walletClient = null;
      onWalletDisconnected();
    } else {
      walletAddress = newAccounts[0];
      onWalletChanged(walletAddress);
    }
  });

  // Listen for chain changes
  window.ethereum.on('chainChanged', () => {
    window.location.reload();
  });

  return { address: walletAddress, client: walletClient };
}

/**
 * Disconnect wallet
 */
export function disconnectWallet() {
  walletAddress = null;
  walletClient = null;
  if (window.ethereum && window.ethereum.removeAllListeners) {
    window.ethereum.removeAllListeners('accountsChanged');
    window.ethereum.removeAllListeners('chainChanged');
  }
}

/**
 * Get current wallet state
 */
export function getWalletState() {
  return {
    connected: !!walletAddress,
    address: walletAddress,
    chain: currentChain,
  };
}

// Callbacks for UI updates
let onWalletDisconnected = () => {};
let onWalletChanged = (addr) => {};

export function setWalletCallbacks(onDisconnect, onChange) {
  onWalletDisconnected = onDisconnect;
  onWalletChanged = onChange;
}

// ═══════════════════════════════════════
// CONTRACT INTERACTIONS
// ═══════════════════════════════════════

/**
 * Register an agent onchain - mints iNFT and registers identity
 * @param {Object} agentConfig - Agent configuration
 * @returns {Promise<{tokenId: string, txHash: string}>}
 */
export async function registerAgentOnchain(agentConfig) {
  if (!walletClient || !walletAddress) {
    throw new Error('Wallet not connected. Call connectWallet() first.');
  }

  const { name, ens, network, allowedTools, valueLimit, endpoints, description,
          storageURI, storageRootHash, soulBackupHash, soulBackupURI } = agentConfig;

  // Generate deterministic agent ID from name
  const agentId = keccak256(stringToBytes(name.toLowerCase().trim()));

  // Generate policy hash from tools and limits
  const policyData = encodePacked(
    ['string[]', 'uint256', 'string'],
    [allowedTools, BigInt(valueLimit), endpoints || '']
  );
  const policyHash = keccak256(policyData);

  // RISC Zero image ID — must be set from deployment config, not derived
  const riscZeroImageId = agentConfig.riscZeroImageId;
  if (!riscZeroImageId || riscZeroImageId === '0x' + '0'.repeat(64)) {
    throw new Error('RISC Zero image ID is required. Build the guest program and configure riscZeroImageId.');
  }

  // 0G Storage URI and hash — must come from real upload
  if (!storageURI || !storageRootHash) {
    throw new Error('Storage URI and root hash are required. Upload metadata to 0G Storage first.');
  }
  const encryptedURI = storageURI;
  const metadataHash = storageRootHash;

  // Get contract addresses for network — reject mainnet until contracts are deployed
  const addresses = CONTRACT_ADDRESSES[network] || CONTRACT_ADDRESSES.sepolia;
  if (!addresses || !addresses.inft || addresses.inft === '0x0000000000000000000000000000000000000000') {
    throw new Error(`Contracts not yet deployed on ${network}. Use sepolia or og_testnet.`);
  }

  try {
    // iNFT mints to the user's wallet (msg.sender) — user protects the valuable asset.
    // The agent's dedicated wallet only holds the ENS name as an operating credential.
    const { request: mintRequest } = await publicClient.simulateContract({
      address: addresses.inft,
      abi: CONTRACT_ABIS.inft,
      functionName: 'mint',
      args: [agentId, policyHash, riscZeroImageId, encryptedURI, metadataHash, soulBackupHash || metadataHash, soulBackupURI || encryptedURI, ens],
      account: walletAddress,
    });

    const mintTxHash = await walletClient.writeContract(mintRequest);

    // Wait for transaction receipt
    const mintReceipt = await publicClient.waitForTransactionReceipt({
      hash: mintTxHash,
    });

    // Extract token ID from event logs
    const tokenId = mintReceipt.logs[0]?.topics[1] || '0';

    // 2. Register in EIP-8004 registry (if deployed)
    try {
      const { request: regRequest } = await publicClient.simulateContract({
        address: addresses.registry,
        abi: CONTRACT_ABIS.registry,
        functionName: 'registerAgentIdentity',
        args: [agentId, encryptedURI, policyHash, riscZeroImageId],
        account: walletAddress,
      });

      await walletClient.writeContract(regRequest);
    } catch (e) {
      // Registry might not be deployed yet - continue with iNFT only
      console.warn('Registry registration skipped:', e.message);
    }

    return {
      tokenId: parseInt(tokenId, 16).toString(),
      txHash: mintTxHash,
      agentId,
      policyHash,
      address: addresses.inft,
    };

  } catch (error) {
    console.error('Onchain registration failed:', error);
    throw new Error(`Failed to register agent: ${error.message}`);
  }
}

/**
 * Check if agent is already registered
 * @param {string} agentName - Agent name
 * @param {string} network - Network key
 * @returns {Promise<{registered: boolean, tokenId: string | null}>}
 */
export async function checkAgentRegistration(agentName, network = 'sepolia') {
  if (!publicClient) initViem(network);

  const agentId = keccak256(stringToBytes(agentName.toLowerCase().trim()));
  const addresses = CONTRACT_ADDRESSES[network] || CONTRACT_ADDRESSES.sepolia;

  try {
    const tokenId = await publicClient.readContract({
      address: addresses.inft,
      abi: CONTRACT_ABIS.inft,
      functionName: 'agentToToken',
      args: [agentId],
    });

    return {
      registered: tokenId > 0,
      tokenId: tokenId > 0 ? tokenId.toString() : null,
    };
  } catch (e) {
    // Contract not deployed or error - assume not registered
    return { registered: false, tokenId: null };
  }
}

/**
 * Get agent details from iNFT contract
 * @param {string} tokenId - Token ID
 * @param {string} network - Network key
 * @returns {Promise<Object>}
 */
export async function getAgentDetails(tokenId, network = 'sepolia') {
  if (!publicClient) initViem(network);

  const addresses = CONTRACT_ADDRESSES[network] || CONTRACT_ADDRESSES.sepolia;

  const agent = await publicClient.readContract({
    address: addresses.inft,
    abi: CONTRACT_ABIS.inft,
    functionName: 'agents',
    args: [BigInt(tokenId)],
  });

  return {
    owner: agent[0],
    agentId: agent[1],
    policyHash: agent[2],
    riscZeroImageId: agent[3],
    encryptedURI: agent[4],
    metadataHash: agent[5],
    ensName: agent[6],
    reputationScore: agent[7].toString(),
    totalProofs: agent[8].toString(),
    mintedAt: new Date(Number(agent[9]) * 1000).toISOString(),
    active: agent[10],
  };
}

// ═══════════════════════════════════════
// WALLET iNFT ENUMERATION
// ═══════════════════════════════════════

/**
 * Get all iNFTs owned by a wallet address.
 * Uses AgentMinted event logs filtered by owner, then verifies current ownership
 * and fetches full agent details for each token.
 * @param {string} ownerAddress - Wallet address to query
 * @param {string} network - Network key ('sepolia' | 'og_testnet')
 * @returns {Promise<Array<{tokenId: string, owner: string, agentId: string, ensName: string, mintedAt: string, reputationScore: string, totalProofs: string, active: boolean, policyHash: string, encryptedURI: string, metadataHash: string, riscZeroImageId: string}>>}
 */
export async function getWalletINFTs(ownerAddress, network = 'sepolia') {
  if (!publicClient) initViem(network);

  const addresses = CONTRACT_ADDRESSES[network] || CONTRACT_ADDRESSES.sepolia;

  // drpc.org free tier rejects queries spanning >10 000 blocks.
  // The contract is newly deployed so all mints are in recent blocks;
  // a 9 000-block window (~30 h on Sepolia, ~18 h on mainnet) is safe
  // and covers the entire useful history.
  const BLOCK_WINDOW = 9000n;
  let fromBlock;
  try {
    const latest = await publicClient.getBlockNumber();
    fromBlock = latest > BLOCK_WINDOW ? latest - BLOCK_WINDOW : 0n;
  } catch {
    fromBlock = 0n;
  }

  // Fetch AgentMinted events where owner matches
  const logs = await publicClient.getLogs({
    address: addresses.inft,
    event: {
      type: 'event',
      name: 'AgentMinted',
      inputs: [
        { type: 'uint256', name: 'tokenId', indexed: true },
        { type: 'bytes32', name: 'agentId', indexed: true },
        { type: 'address', name: 'owner', indexed: true },
        { type: 'string', name: 'ensName', indexed: false },
      ],
    },
    args: { owner: ownerAddress },
    fromBlock,
    toBlock: 'latest',
  });

  // For each minted token, verify current ownership (may have been transferred)
  // and fetch full agent details
  const results = [];
  for (const log of logs) {
    const tokenId = log.args.tokenId;
    try {
      const currentOwner = await publicClient.readContract({
        address: addresses.inft,
        abi: CONTRACT_ABIS.inft,
        functionName: 'ownerOf',
        args: [tokenId],
      });

      // Skip if no longer owned by this address
      if (currentOwner.toLowerCase() !== ownerAddress.toLowerCase()) continue;

      const agent = await publicClient.readContract({
        address: addresses.inft,
        abi: CONTRACT_ABIS.inft,
        functionName: 'agents',
        args: [tokenId],
      });

      results.push({
        tokenId: tokenId.toString(),
        owner: agent[0],
        agentId: agent[1],
        policyHash: agent[2],
        riscZeroImageId: agent[3],
        encryptedURI: agent[4],
        metadataHash: agent[5],
        ensName: agent[6],
        reputationScore: agent[7].toString(),
        totalProofs: agent[8].toString(),
        mintedAt: new Date(Number(agent[9]) * 1000).toISOString(),
        active: agent[10],
      });
    } catch (e) {
      console.warn(`Failed to fetch details for token ${tokenId}:`, e.message);
    }
  }

  return results;
}

// ═══════════════════════════════════════
// UTILITY FUNCTIONS
// ═══════════════════════════════════════

/**
 * Switch network in wallet
 * @param {string} network - Network to switch to
 */
export async function switchNetwork(network) {
  if (!window.ethereum) throw new Error('No wallet detected');

  const chainId = network === 'sepolia' ? '0xaa36a7' // 11155111
    : network === 'og_testnet' ? '0x40da' // 16602
    : network === 'og_mainnet' ? '0x4115' // 16661
    : '0x1'; // mainnet

  try {
    await window.ethereum.request({
      method: 'wallet_switchEthereumChain',
      params: [{ chainId }],
    });
  } catch (switchError) {
    // If network not added, add it
    if (switchError.code === 4902) {
      const chainConfig = network === 'og_testnet' ? {
        chainId: '0x40da',
        chainName: '0G Testnet',
        nativeCurrency: { name: '0G', symbol: 'OG', decimals: 18 },
        rpcUrls: ['https://evmrpc-testnet.0g.ai'],
        blockExplorerUrls: ['https://chainscan-dev.0g.ai'],
      } : network === 'og_mainnet' ? {
        chainId: '0x4115',
        chainName: '0G Mainnet',
        nativeCurrency: { name: '0G', symbol: 'OG', decimals: 18 },
        rpcUrls: ['https://evmrpc.0g.ai'],
        blockExplorerUrls: ['https://chainscan.0g.ai'],
      } : null;

      if (chainConfig) {
        await window.ethereum.request({
          method: 'wallet_addEthereumChain',
          params: [chainConfig],
        });
      }
    } else {
      throw switchError;
    }
  }
}

/**
 * Format address for display (0x1234...5678)
 */
export function formatAddress(address) {
  if (!address || address.length < 10) return address;
  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}

/**
 * Get explorer URL for transaction
 */
export function getExplorerUrl(txHash, network = 'sepolia') {
  const base = getExplorerBase(network);
  return `${base}/tx/${txHash}`;
}

/**
 * Get explorer URL for an address (contract or wallet)
 */
export function getExplorerAddressUrl(address, network = 'sepolia') {
  const base = getExplorerBase(network);
  return `${base}/address/${address}`;
}

/**
 * Get explorer URL for a token (contract + tokenId)
 */
export function getExplorerTokenUrl(contractAddress, tokenId, network = 'sepolia') {
  const base = getExplorerBase(network);
  return `${base}/token/${contractAddress}?a=${tokenId}`;
}

function getExplorerBase(network) {
  return network === 'sepolia' ? 'https://sepolia.etherscan.io'
    : network === 'og_testnet' ? 'https://chainscan-galileo.0g.ai'
    : network === 'og_mainnet' ? 'https://chainscan.0g.ai'
    : 'https://etherscan.io';
}

/**
 * Fetch ALL minted iNFTs from on-chain AgentMinted events (no owner filter).
 * @param {string} network - Network key ('sepolia' | 'og_testnet')
 * @returns {Promise<Array>}
 */
export async function getAllMintedINFTs(network = 'sepolia') {
  if (!publicClient) initViem(network);

  const addresses = CONTRACT_ADDRESSES[network] || CONTRACT_ADDRESSES.sepolia;

  const BLOCK_WINDOW = 9000n;
  let fromBlock;
  try {
    const latest = await publicClient.getBlockNumber();
    fromBlock = latest > BLOCK_WINDOW ? latest - BLOCK_WINDOW : 0n;
  } catch {
    fromBlock = 0n;
  }

  const logs = await publicClient.getLogs({
    address: addresses.inft,
    event: {
      type: 'event',
      name: 'AgentMinted',
      inputs: [
        { type: 'uint256', name: 'tokenId', indexed: true },
        { type: 'bytes32', name: 'agentId', indexed: true },
        { type: 'address', name: 'owner', indexed: true },
        { type: 'string', name: 'ensName', indexed: false },
      ],
    },
    fromBlock,
    toBlock: 'latest',
  });

  const results = [];
  for (const log of logs) {
    const tokenId = log.args.tokenId;
    try {
      const agent = await publicClient.readContract({
        address: addresses.inft,
        abi: CONTRACT_ABIS.inft,
        functionName: 'agents',
        args: [tokenId],
      });

      results.push({
        tokenId: tokenId.toString(),
        owner: agent[0],
        agentId: agent[1],
        policyHash: agent[2],
        riscZeroImageId: agent[3],
        encryptedURI: agent[4],
        metadataHash: agent[5],
        ensName: agent[6],
        reputationScore: agent[7].toString(),
        totalProofs: agent[8].toString(),
        mintedAt: new Date(Number(agent[9]) * 1000).toISOString(),
        active: agent[10],
        txHash: log.transactionHash,
      });
    } catch (e) {
      console.warn(`Failed to fetch details for token ${tokenId}:`, e.message);
    }
  }

  return results;
}

// ═══════════════════════════════════════
// AGENT WALLET GENERATION
// ═══════════════════════════════════════

/**
 * Generate a dedicated wallet for an agent.
 * Uses Web Crypto for 32 bytes of randomness, then derives the address via viem.
 * The private key is returned so it can be encrypted and stored — it is NEVER logged.
 * @returns {{ address: string, privateKey: string }}
 */
export function generateAgentWallet() {
  const randomBytes = crypto.getRandomValues(new Uint8Array(32));
  const privateKey = '0x' + Array.from(randomBytes).map(b => b.toString(16).padStart(2, '0')).join('');
  // Clear random bytes from memory to reduce exposure window
  randomBytes.fill(0);
  const account = privateKeyToAccount(privateKey);
  return {
    address: account.address,
    privateKey,
  };
}

// Make available globally for non-module scripts.
// SECURITY WARNING: generateAgentWallet is exposed on window.PocViem, meaning any
// script running on this page (including third-party scripts, browser extensions,
// or XSS payloads) can call it to generate wallets. The returned private key could
// be intercepted. Consider restricting access or removing it from the global object
// if the calling code can import this module directly instead.
document.addEventListener('DOMContentLoaded', () => {
  window.PocViem = {
    init: initViem,
    connectWallet,
    disconnectWallet,
    getWalletState,
    setWalletCallbacks,
    registerAgentOnchain,
    checkAgentRegistration,
    getAgentDetails,
    getWalletINFTs,
    getAllMintedINFTs,
    switchNetwork,
    formatAddress,
    getExplorerUrl,
    getExplorerAddressUrl,
    getExplorerTokenUrl,
    generateAgentWallet,
  };
});
