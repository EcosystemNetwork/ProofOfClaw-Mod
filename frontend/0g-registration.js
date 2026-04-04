/**
 * 0G Chain Agent Registration
 * Handles on-chain agent registration with 0G testnet/mainnet and DM3 integration
 */

import { configValidator, Networks } from './config-validator.js';

// 0G Chain Configuration
const ZERO_G_CONFIG = {
  testnet: {
    chainId: 16602,
    name: '0G Testnet',
    rpcUrl: 'https://evmrpc-testnet.0g.ai',
    explorer: 'https://chainscan-dev.0g.ai',
    storage: {
      indexer: 'https://indexer-storage-testnet.0g.ai',
      broker: 'https://broker-testnet.0g.ai'
    },
    compute: {
      endpoint: 'https://broker-testnet.0g.ai'
    },
    // TODO: Update with deployed contract addresses
    contracts: {
      agentRegistry: '0xe34dab193105f3d7ec6ee4e6172cbe6213108d8b', // ProofOfClawVerifier
      iNFT: '0x45c69b7be9dc9a4126053a17a43e664b4ae031a1', // ProofOfClawINFT
      policyEngine: '0xe34dab193105f3d7ec6ee4e6172cbe6213108d8b'
    }
  },
  mainnet: {
    chainId: 16661,
    name: '0G Mainnet',
    rpcUrl: 'https://evmrpc.0g.ai',
    explorer: 'https://chainscan.0g.ai',
    storage: {
      indexer: 'https://indexer-storage.0g.ai',
      broker: 'https://broker.0g.ai'
    },
    compute: {
      endpoint: 'https://broker.0g.ai'
    },
    contracts: {
      agentRegistry: '0x0000000000000000000000000000000000000000',
      iNFT: '0x0000000000000000000000000000000000000000',
      policyEngine: '0x0000000000000000000000000000000000000000'
    }
  }
};

// DM3 Configuration
const DM3_CONFIG = {
  defaultDeliveryService: 'https://dm3-delivery-service.vercel.app',
  ensTextRecord: 'network.dm3.profile',
  profileVersion: '1.0'
};

/**
 * Agent Registration Manager
 * Handles the full registration flow including:
 * - Configuration validation
 * - On-chain identity creation
 * - DM3 profile setup
 * - 0G Storage metadata upload
 * - Policy commitment
 */
export class AgentRegistrationManager {
  constructor() {
    this.registrations = new Map();
    this.listeners = new Map();
  }

  /**
   * Start a new registration session
   */
  createSession(agentConfig) {
    const sessionId = `reg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const session = {
      id: sessionId,
      config: agentConfig,
      status: 'pending',
      progress: {
        validation: 0,
        upload: 0,
        registration: 0,
        confirmation: 0
      },
      results: {},
      errors: [],
      warnings: [],
      startTime: Date.now()
    };
    
    this.registrations.set(sessionId, session);
    return sessionId;
  }

  /**
   * Validate configuration for registration
   */
  async validateConfiguration(sessionId) {
    const session = this.registrations.get(sessionId);
    if (!session) throw new Error('Session not found');

    this.updateStatus(sessionId, 'validating', { validation: 20 });

    const validation = configValidator.validateAll(session.config);
    
    if (!validation.valid) {
      session.errors.push(...Object.values(validation.errors).flat());
      this.updateStatus(sessionId, 'failed');
      return { valid: false, errors: validation.errors, warnings: validation.warnings };
    }

    session.warnings.push(...Object.values(validation.warnings).flat());
    this.updateStatus(sessionId, 'validating', { validation: 100 });
    
    return { valid: true, warnings: validation.warnings };
  }

  /**
   * Upload encrypted metadata to 0G Storage
   */
  async uploadTo0GStorage(sessionId, metadata) {
    const session = this.registrations.get(sessionId);
    if (!session) throw new Error('Session not found');

    this.updateStatus(sessionId, 'uploading', { upload: 30 });

    try {
      const network = session.config.network.includes('mainnet') ? 'mainnet' : 'testnet';
      const config = ZERO_G_CONFIG[network];

      // Prepare encrypted metadata
      const encryptedData = await this.encryptMetadata(metadata, session.config);
      
      this.updateStatus(sessionId, 'uploading', { upload: 60 });

      // Upload to 0G Storage
      const uploadResult = await this.perform0GUpload(encryptedData, config.storage.indexer);
      
      session.results.storage = {
        rootHash: uploadResult.rootHash,
        url: `0g://${uploadResult.rootHash}`,
        timestamp: Date.now()
      };

      this.updateStatus(sessionId, 'uploading', { upload: 100 });
      
      return { success: true, storage: session.results.storage };
    } catch (error) {
      session.errors.push(`0G Storage upload failed: ${error.message}`);
      throw error;
    }
  }

  /**
   * Register agent on 0G chain
   */
  async registerOnChain(sessionId, walletClient, publicClient) {
    const session = this.registrations.get(sessionId);
    if (!session) throw new Error('Session not found');

    this.updateStatus(sessionId, 'registering', { registration: 10 });

    try {
      const { config, results } = session;
      const network = config.network.includes('mainnet') ? 'mainnet' : 'testnet';
      const zeroGConfig = ZERO_G_CONFIG[network];

      // Generate agent ID
      const agentId = this.generateAgentId(config.agentName || config.name);
      
      // Generate policy hash
      const policyHash = this.generatePolicyHash(config);
      
      // Generate RISC Zero image ID (placeholder for actual proof system)
      const riscZeroImageId = this.generateImageId(config);

      this.updateStatus(sessionId, 'registering', { registration: 40 });

      // Prepare registration data
      const registrationData = {
        agentId,
        ensName: config.ensName || config.ens,
        policyHash,
        riscZeroImageId,
        metadataHash: results.storage?.rootHash || '0x0',
        encryptedURI: results.storage?.url || '',
        skills: config.skills || [],
        maxTasks: config.maxTasks || 5,
        soulPersona: config.soulPersona || ''
      };

      this.updateStatus(sessionId, 'registering', { registration: 60 });

      // Execute on-chain registration
      // Note: Contract addresses need to be deployed and updated
      const txResult = await this.executeRegistration(
        registrationData,
        walletClient,
        publicClient,
        zeroGConfig
      );

      session.results.onchain = {
        txHash: txResult.txHash,
        tokenId: txResult.tokenId,
        contractAddress: zeroGConfig.contracts.agentRegistry,
        agentId,
        policyHash,
        timestamp: Date.now()
      };

      this.updateStatus(sessionId, 'registering', { registration: 100 });

      return { success: true, onchain: session.results.onchain };
    } catch (error) {
      session.errors.push(`On-chain registration failed: ${error.message}`);
      throw error;
    }
  }

  /**
   * Setup DM3 profile for agent
   */
  async setupDM3Profile(sessionId, walletClient) {
    const session = this.registrations.get(sessionId);
    if (!session) throw new Error('Session not found');

    try {
      const { config, results } = session;
      
      // Generate DM3 profile keys
      const dm3Profile = await this.generateDM3Profile(config, walletClient);
      
      // Store DM3 profile in ENS text record or directly
      session.results.dm3 = {
        publicEncryptionKey: dm3Profile.publicEncryptionKey,
        publicSigningKey: dm3Profile.publicSigningKey,
        deliveryServiceUrl: dm3Profile.deliveryServiceUrl,
        ensName: config.ensName || config.ens,
        setup: true
      };

      return { success: true, dm3: session.results.dm3 };
    } catch (error) {
      // DM3 setup is optional - log warning but don't fail
      session.warnings.push(`DM3 profile setup skipped: ${error.message}`);
      session.results.dm3 = { setup: false, error: error.message };
      return { success: false, warning: error.message };
    }
  }

  /**
   * Wait for transaction confirmation
   */
  async waitForConfirmation(sessionId, publicClient) {
    const session = this.registrations.get(sessionId);
    if (!session) throw new Error('Session not found');

    this.updateStatus(sessionId, 'confirming', { confirmation: 0 });

    const txHash = session.results.onchain?.txHash;
    if (!txHash) {
      throw new Error('No transaction hash available for confirmation');
    }

    try {
      // Wait for transaction receipt
      const receipt = await publicClient.waitForTransactionReceipt({
        hash: txHash,
        timeout: 120000, // 2 minutes
        pollingInterval: 2000 // Check every 2 seconds
      });

      this.updateStatus(sessionId, 'confirming', { 
        confirmation: receipt.status === 'success' ? 100 : 50 
      });

      if (receipt.status !== 'success') {
        throw new Error('Transaction failed on-chain');
      }

      session.results.confirmation = {
        blockNumber: receipt.blockNumber,
        gasUsed: receipt.gasUsed,
        effectiveGasPrice: receipt.effectiveGasPrice,
        confirmedAt: Date.now()
      };

      this.updateStatus(sessionId, 'completed');

      return { success: true, receipt };
    } catch (error) {
      session.errors.push(`Confirmation failed: ${error.message}`);
      this.updateStatus(sessionId, 'failed');
      throw error;
    }
  }

  /**
   * Full registration flow
   */
  async executeFullRegistration(sessionId, walletClient, publicClient, metadata) {
    const session = this.registrations.get(sessionId);
    
    try {
      // Step 1: Validate
      const validation = await this.validateConfiguration(sessionId);
      if (!validation.valid) {
        return { success: false, stage: 'validation', errors: validation.errors };
      }

      // Step 2: Upload to 0G Storage
      await this.uploadTo0GStorage(sessionId, metadata);

      // Step 3: Register on-chain
      await this.registerOnChain(sessionId, walletClient, publicClient);

      // Step 4: Setup DM3
      await this.setupDM3Profile(sessionId, walletClient);

      // Step 5: Wait for confirmation
      await this.waitForConfirmation(sessionId, publicClient);

      return {
        success: true,
        sessionId,
        results: session.results,
        duration: Date.now() - session.startTime
      };
    } catch (error) {
      this.updateStatus(sessionId, 'failed');
      return {
        success: false,
        sessionId,
        stage: session.status,
        error: error.message,
        errors: session.errors,
        warnings: session.warnings
      };
    }
  }

  /**
   * Get registration status
   */
  getStatus(sessionId) {
    return this.registrations.get(sessionId);
  }

  /**
   * Subscribe to status updates
   */
  onStatusChange(sessionId, callback) {
    if (!this.listeners.has(sessionId)) {
      this.listeners.set(sessionId, []);
    }
    this.listeners.get(sessionId).push(callback);
  }

  /**
   * Update status and notify listeners
   */
  updateStatus(sessionId, status, progress = null) {
    const session = this.registrations.get(sessionId);
    if (!session) return;

    session.status = status;
    if (progress) {
      Object.assign(session.progress, progress);
    }

    // Notify listeners
    const listeners = this.listeners.get(sessionId) || [];
    listeners.forEach(cb => {
      try { cb(session); } catch (e) { console.error('Listener error:', e); }
    });
  }

  // Internal helper methods

  async encryptMetadata(metadata, config) {
    // In production, this would use actual encryption
    // For now, return JSON stringified with sensitive fields masked
    const sanitized = {
      ...metadata,
      privateKey: undefined,
      secrets: '[REDACTED]'
    };
    return JSON.stringify(sanitized);
  }

  async perform0GUpload(data, indexerUrl) {
    // Placeholder for actual 0G Storage upload
    // In production, this would call the 0G Storage API
    const mockRootHash = '0x' + Array(64).fill(0).map(() => 
      Math.floor(Math.random() * 16).toString(16)
    ).join('');
    
    return { rootHash: mockRootHash, size: data.length };
  }

  async executeRegistration(data, walletClient, publicClient, networkConfig) {
    // Placeholder for actual contract interaction
    // In production, this would call the smart contract
    
    // Mock transaction for development
    const mockTxHash = '0x' + Array(64).fill(0).map(() => 
      Math.floor(Math.random() * 16).toString(16)
    ).join('');
    
    return {
      txHash: mockTxHash,
      tokenId: Math.floor(Math.random() * 10000) + 1
    };
  }

  async generateDM3Profile(config, walletClient) {
    // Generate DM3 profile data
    const ensName = config.ensName || config.ens;
    
    return {
      publicEncryptionKey: '0x' + Array(64).fill(0).map(() => 
        Math.floor(Math.random() * 16).toString(16)
      ).join(''),
      publicSigningKey: '0x' + Array(64).fill(0).map(() => 
        Math.floor(Math.random() * 16).toString(16)
      ).join(''),
      deliveryServiceUrl: DM3_CONFIG.defaultDeliveryService,
      ensName
    };
  }

  generateAgentId(name) {
    // Generate deterministic agent ID from name + timestamp
    const data = `${name.toLowerCase().trim()}_${Date.now()}`;
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
      const char = data.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return '0x' + Math.abs(hash).toString(16).padStart(64, '0');
  }

  generatePolicyHash(config) {
    // Generate hash from policy configuration
    const policyData = JSON.stringify({
      tools: config.allowedTools || config.tools || [],
      valueLimit: config.valueLimit,
      endpoints: config.endpoints || [],
      network: config.network
    });
    
    let hash = 0;
    for (let i = 0; i < policyData.length; i++) {
      const char = policyData.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return '0x' + Math.abs(hash).toString(16).padStart(64, '0');
  }

  generateImageId(config) {
    // Placeholder for RISC Zero image ID
    return '0x' + Array(64).fill(0).map(() => 
      Math.floor(Math.random() * 16).toString(16)
    ).join('');
  }
}

// Export singleton instance
export const agentRegistration = new AgentRegistrationManager();

// Export configuration
export { ZERO_G_CONFIG, DM3_CONFIG };
