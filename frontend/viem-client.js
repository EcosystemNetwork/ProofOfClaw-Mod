/**
 * Proof of Claw — Viem Blockchain Integration
 * Handles wallet connection, contract interactions, and agent onchain registration
 */

// Import viem from CDN (ES modules)
import { createPublicClient, createWalletClient, custom, http, parseAbi, encodePacked, keccak256, stringToBytes } from 'https://esm.sh/viem@2.21.44';
import { mainnet, sepolia } from 'https://esm.sh/viem@2.21.44/chains';

// ═══════════════════════════════════════
// CONTRACT CONFIGURATION
// ═══════════════════════════════════════

const CONTRACT_ABIS = {
  // ProofOfClawINFT - ERC-7857 Agent iNFT Contract
  inft: parseAbi([
    'function mint(bytes32 agentId, bytes32 policyHash, bytes32 riscZeroImageId, string calldata encryptedURI, bytes32 metadataHash, string calldata ensName) external returns (uint256 tokenId)',
    'function agentToToken(bytes32 agentId) external view returns (uint256)',
    'function agents(uint256 tokenId) external view returns (address owner, bytes32 agentId, bytes32 policyHash, bytes32 riscZeroImageId, string memory encryptedURI, bytes32 metadataHash, string memory ensName, uint256 reputationScore, uint256 totalProofs, uint256 mintedAt, bool active)',
    'function ownerOf(uint256 tokenId) external view returns (address)',
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

// Contract addresses by network
const CONTRACT_ADDRESSES = {
  sepolia: {
    inft: '0x0000000000000000000000000000000000000000', // TODO: Deploy and update
    registry: '0x0000000000000000000000000000000000000000', // TODO: Deploy and update
  },
  og_testnet: {
    inft: '0x45c69b7be9dc9a4126053a17a43e664b4ae031a1', // ProofOfClawINFT
    registry: '0xe34dab193105f3d7ec6ee4e6172cbe6213108d8b', // ProofOfClawVerifier
  },
};

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
    // 0G networks - use custom chain config
    currentChain = {
      id: network === 'og_testnet' ? 16602 : 16661,
      name: network === 'og_testnet' ? '0G Testnet' : '0G Mainnet',
      nativeCurrency: { name: '0G', symbol: 'OG', decimals: 18 },
      rpcUrls: {
        default: {
          http: [network === 'og_testnet' ? 'https://evmrpc-testnet.0g.ai' : 'https://evmrpc.0g.ai'],
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

  const { name, ens, network, allowedTools, valueLimit, endpoints, description } = agentConfig;

  // Generate deterministic agent ID from name
  const agentId = keccak256(stringToBytes(name.toLowerCase().trim()));

  // Generate policy hash from tools and limits
  const policyData = encodePacked(
    ['string[]', 'uint256', 'string'],
    [allowedTools, BigInt(valueLimit), endpoints || '']
  );
  const policyHash = keccak256(policyData);

  // Mock RISC Zero image ID (would be actual image commitment in production)
  const riscZeroImageId = keccak256(stringToBytes(`risc-zero-policy-${policyHash}`));

  // Generate encrypted metadata URI (would be actual 0G Storage URI in production)
  const encryptedURI = `0g://storage/${agentId.slice(2, 18)}/metadata.enc`;
  const metadataHash = keccak256(stringToBytes(JSON.stringify({
    name, description, tools: allowedTools, limit: valueLimit
  })));

  // Get contract addresses for network
  const addresses = CONTRACT_ADDRESSES[network] || CONTRACT_ADDRESSES.sepolia;

  try {
    // 1. Mint iNFT
    const { request: mintRequest } = await publicClient.simulateContract({
      address: addresses.inft,
      abi: CONTRACT_ABIS.inft,
      functionName: 'mint',
      args: [agentId, policyHash, riscZeroImageId, encryptedURI, metadataHash, ens],
      account: walletAddress,
    });

    const mintTxHash = await walletClient.writeContract(mintRequest);

    // Wait for transaction receipt
    const mintReceipt = await publicClient.waitForTransactionReceipt({
      hash: mintTxHash,
    });

    // Extract token ID from event logs (would parse actual event in production)
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
// UTILITY FUNCTIONS
// ═══════════════════════════════════════

/**
 * Switch network in wallet
 * @param {string} network - Network to switch to
 */
export async function switchNetwork(network) {
  if (!window.ethereum) throw new Error('No wallet detected');

  const chainId = network === 'sepolia' ? '0xaa36a7' // 11155111
    : network === 'og_testnet' ? '0x40d2' // 16602
    : network === 'og_mainnet' ? '0x410d' // 16661
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
        chainId: '0x40d2',
        chainName: '0G Testnet',
        nativeCurrency: { name: '0G', symbol: 'OG', decimals: 18 },
        rpcUrls: ['https://evmrpc-testnet.0g.ai'],
        blockExplorerUrls: ['https://chainscan-dev.0g.ai'],
      } : network === 'og_mainnet' ? {
        chainId: '0x410d',
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
  const base = network === 'sepolia' ? 'https://sepolia.etherscan.io'
    : network === 'og_testnet' ? 'https://chainscan-dev.0g.ai'
    : network === 'og_mainnet' ? 'https://chainscan.0g.ai'
    : 'https://etherscan.io';
  return `${base}/tx/${txHash}`;
}

// Make available globally for non-module scripts
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
    switchNetwork,
    formatAddress,
    getExplorerUrl,
  };
});
