/**
 * 0G Chain Agent Registration
 * Handles on-chain agent registration with 0G testnet/mainnet and DM3 integration
 * Uses real 0G Storage SDK for decentralized data upload
 */

import { configValidator, Networks } from './config-validator.js';
import { ZERO_G_CONFIG, DM3_CONFIG } from './env-config.js';
import { BrowserProvider } from 'https://esm.sh/ethers@6.13.4';

// Lazy-load 0G SDK — it uses crypto.createHash (Node.js API) which
// throws in some browser environments. Defer until first actual use.
let _ZgIndexer = null;
async function getZgIndexer() {
  if (_ZgIndexer) return _ZgIndexer;
  try {
    const mod = await import('https://esm.sh/@0glabs/0g-ts-sdk@0.3.3');
    _ZgIndexer = mod.Indexer;
  } catch (e) {
    console.warn('[0g-registration] 0G SDK unavailable:', e.message);
    _ZgIndexer = null;
  }
  return _ZgIndexer;
}

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
    this._cachedKeyMaterial = null;
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
   * Validate configuration for registration (including soul backup)
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

    // Validate soul backup YAML (OCMB v0.1 — required for iNFT minting)
    if (!session.config.soulBackupYaml || !session.config.soulBackupYaml.trim()) {
      session.errors.push('Soul backup YAML is required. Agents must have a soul to mint an iNFT.');
      this.updateStatus(sessionId, 'failed');
      return { valid: false, errors: { soulBackup: ['Missing soul backup'] }, warnings: validation.warnings };
    }

    // Validate OCMB schema if validator available
    if (typeof window !== 'undefined' && window.OCMBSchema) {
      const soulValidation = window.OCMBSchema.validateOCMBYaml(session.config.soulBackupYaml);
      if (!soulValidation.valid) {
        session.errors.push(...soulValidation.errors.map(e => `Soul backup: ${e}`));
        this.updateStatus(sessionId, 'failed');
        return { valid: false, errors: { soulBackup: soulValidation.errors }, warnings: validation.warnings };
      }
      if (soulValidation.warnings.length > 0) {
        session.warnings.push(...soulValidation.warnings.map(w => `Soul backup: ${w}`));
      }
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
      const network = session.config.network.includes('mainnet') ? 'mainnet' : session.config.network.includes('sepolia') ? 'sepolia' : 'testnet';
      const config = ZERO_G_CONFIG[network];

      // Guard: reject mainnet until storage flow contract is deployed
      if (!config.storage || !config.storage.flowContract) {
        throw new Error(`0G Storage flow contract not configured for ${network}. Use sepolia or testnet.`);
      }

      // Encrypt metadata with wallet-derived key
      const encryptedData = await this.encryptMetadata(metadata, session.config);

      this.updateStatus(sessionId, 'uploading', { upload: 60 });

      // Upload to 0G Storage (real decentralized upload)
      const uploadResult = await this.perform0GUpload(encryptedData, config.storage);
      
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
      const network = config.network.includes('mainnet') ? 'mainnet' : config.network.includes('sepolia') ? 'sepolia' : 'testnet';
      const zeroGConfig = ZERO_G_CONFIG[network];

      // Guard: reject mainnet until contracts are deployed
      if (!zeroGConfig.contracts) {
        throw new Error(`Contracts not yet deployed on ${network}. Use sepolia or testnet.`);
      }

      // Generate agent ID
      const agentId = await this.generateAgentId(config.agentName || config.name);

      // Generate policy hash
      const policyHash = await this.generatePolicyHash(config);
      
      // Get RISC Zero image ID from network config
      const riscZeroImageId = this.generateImageId(config);

      this.updateStatus(sessionId, 'registering', { registration: 40 });

      // Prepare registration data (includes soul backup hash + URI)
      const registrationData = {
        agentId,
        ensName: config.ensName || config.ens,
        policyHash,
        riscZeroImageId,
        metadataHash: results.storage?.rootHash || '0x0',
        encryptedURI: results.storage?.url || '',
        soulBackupHash: results.soulBackup?.hash || '0x0',
        soulBackupURI: results.soulBackup?.uri || '',
        skills: config.skills || [],
        maxTasks: config.maxTasks || 5,
        soulPersona: config.soulPersona || '',
        // Agent's dedicated wallet — iNFT mints directly here
        agentWalletAddress: config.walletAddress || null
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
      
      // Store DM3 profile (including private keys for the agent to use)
      session.results.dm3 = {
        publicEncryptionKey: dm3Profile.publicEncryptionKey,
        privateEncryptionKey: dm3Profile.privateEncryptionKey,
        publicSigningKey: dm3Profile.publicSigningKey,
        privateSigningKey: dm3Profile.privateSigningKey,
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
   * Upload soul backup YAML to 0G Storage and compute hash
   */
  async uploadSoulBackup(sessionId) {
    const session = this.registrations.get(sessionId);
    if (!session) throw new Error('Session not found');

    const soulYaml = session.config.soulBackupYaml;
    if (!soulYaml) throw new Error('No soul backup YAML in session config');

    this.updateStatus(sessionId, 'uploading_soul', { upload: 15 });

    try {
      const network = session.config.network.includes('mainnet') ? 'mainnet' : session.config.network.includes('sepolia') ? 'sepolia' : 'testnet';
      const config = ZERO_G_CONFIG[network];

      // Hash the soul backup using keccak256 (matches Solidity's keccak256)
      const soulBackupHash = await this.hashContent(soulYaml);

      this.updateStatus(sessionId, 'uploading_soul', { upload: 25 });

      // Encrypt and upload to 0G Storage (real decentralized upload)
      const encryptedSoul = await this.encryptMetadata({ soulBackup: soulYaml }, session.config);
      const uploadResult = await this.perform0GUpload(encryptedSoul, config.storage);

      session.results.soulBackup = {
        hash: soulBackupHash,
        uri: `0g://${uploadResult.rootHash}`,
        size: soulYaml.length,
        timestamp: Date.now()
      };

      this.updateStatus(sessionId, 'uploading_soul', { upload: 30 });

      return { success: true, soulBackup: session.results.soulBackup };
    } catch (error) {
      session.errors.push(`Soul backup upload failed: ${error.message}`);
      throw error;
    }
  }

  /**
   * Hash content using keccak256 (matches on-chain keccak256 used in Solidity)
   */
  async hashContent(content) {
    // Use keccak256 via ethers to match Solidity's keccak256()
    const { keccak256, toUtf8Bytes } = await import('https://esm.sh/ethers@6.13.4');
    return keccak256(toUtf8Bytes(content));
  }

  /**
   * Full registration flow
   */
  async executeFullRegistration(sessionId, walletClient, publicClient, metadata) {
    const session = this.registrations.get(sessionId);

    try {
      // Step 1: Validate (includes soul backup validation)
      const validation = await this.validateConfiguration(sessionId);
      if (!validation.valid) {
        return { success: false, stage: 'validation', errors: validation.errors };
      }

      // Step 2: Upload soul backup to 0G Storage
      await this.uploadSoulBackup(sessionId);

      // Step 3: Upload metadata to 0G Storage
      await this.uploadTo0GStorage(sessionId, metadata);

      // Step 4: Register on-chain (includes soul backup hash in mint calldata)
      await this.registerOnChain(sessionId, walletClient, publicClient);

      // Step 5: Setup DM3
      await this.setupDM3Profile(sessionId, walletClient);

      // Step 6: Wait for confirmation
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
    const sanitized = { ...metadata, privateKey: undefined, secrets: undefined };
    const plaintext = new TextEncoder().encode(JSON.stringify(sanitized));

    // Derive a symmetric key from a wallet signature (only the key holder can reproduce)
    const sigBytes = await this.getEncryptionKeyMaterial(config);
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      sigBytes,
      'PBKDF2',
      false,
      ['deriveKey']
    );
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const aesKey = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plaintext);

    // Pack salt + iv + ciphertext into a single buffer
    const packed = new Uint8Array(salt.length + iv.length + new Uint8Array(ciphertext).length);
    packed.set(salt, 0);
    packed.set(iv, salt.length);
    packed.set(new Uint8Array(ciphertext), salt.length + iv.length);

    return packed;
  }

  /**
   * Derive encryption key material from a deterministic wallet signature.
   * The user signs a fixed message — only the private key holder can reproduce this,
   * unlike the wallet address which is public.
   */
  async getEncryptionKeyMaterial(config) {
    if (this._cachedKeyMaterial) return this._cachedKeyMaterial;

    const message = `ProofOfClaw encryption key for ${config.walletAddress || 'agent'}`;

    if (window.ethereum) {
      const provider = new BrowserProvider(window.ethereum);
      const signer = await provider.getSigner();
      const sig = await signer.signMessage(message);
      // Use the signature bytes (not hex) as PBKDF2 input
      const sigBytes = new TextEncoder().encode(sig);
      this._cachedKeyMaterial = sigBytes;
      return sigBytes;
    }

    // Fallback for environments without a wallet (e.g. tests) — derive from config secret
    const fallback = config.encryptionSecret || config.walletAddress || 'proof-of-claw';
    console.warn('No wallet available for encryption key derivation — using fallback. Data will NOT be securely encrypted.');
    const bytes = new TextEncoder().encode(fallback);
    this._cachedKeyMaterial = bytes;
    return bytes;
  }

  /**
   * Get an ethers signer from window.ethereum (needed for 0G SDK)
   */
  async getEthersSigner() {
    if (!window.ethereum) throw new Error('No wallet detected');
    const provider = new BrowserProvider(window.ethereum);
    return await provider.getSigner();
  }

  /**
   * Upload data to 0G Storage using the real SDK
   * @param {Uint8Array|string} data - Data to upload
   * @param {Object} storageConfig - { indexer, evmRpc, flowContract }
   * @returns {{ rootHash: string, txHash: string, size: number }}
   */
  async perform0GUpload(data, storageConfig) {
    const { indexer: indexerUrl, evmRpc } = storageConfig;

    // Convert string data to bytes if needed
    const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;

    // Create a File/Blob for the SDK
    const blob = new Blob([bytes], { type: 'application/octet-stream' });
    const file = new File([blob], 'upload.bin', { type: 'application/octet-stream' });

    // Get ethers signer for 0G chain transactions
    const signer = await this.getEthersSigner();

    // Initialize 0G Storage indexer (lazy-loaded to avoid browser crypto.createHash crash)
    const ZgIndexer = await getZgIndexer();
    if (!ZgIndexer) throw new Error('0G SDK unavailable in this browser environment');
    const indexer = new ZgIndexer(indexerUrl);


    // Upload to 0G Storage — submits on-chain tx to Flow contract + uploads segments
    const [tx, err] = await indexer.upload(file, evmRpc, signer);

    if (err) {
      throw new Error(`0G Storage upload failed: ${err.message || err}`);
    }

    return {
      rootHash: tx.rootHash || tx.txHash,
      txHash: tx.txHash || tx.rootHash,
      size: bytes.length
    };
  }

  async executeRegistration(data, walletClient, publicClient, networkConfig) {
    // Use the global viem client if available, or fall back to the window.PocViem
    const viem = window.PocViem;
    if (!viem) {
      throw new Error('Viem client not available. Please ensure wallet is connected.');
    }

    // Ensure wallet is connected
    const walletState = viem.getWalletState();
    if (!walletState.connected) {
      throw new Error('Wallet not connected. Please connect your wallet first.');
    }

    // Get the actual wallet and public clients from the viem module
    // We need to call the registerAgentOnchain function through the viem client
    const agentConfig = {
      name: data.agentId ? data.agentId.slice(2, 18) : 'agent',
      ens: data.ensName || '',
      network: networkConfig.name?.toLowerCase().includes('0g') ? 'og_testnet' : 'sepolia',
      allowedTools: data.skills || ['swap_tokens', 'transfer', 'query'],
      valueLimit: data.maxTasks || 100,
      endpoints: '',
      description: data.soulPersona || '',
      // Pass real 0G Storage URIs from upload results
      storageURI: data.encryptedURI || '',
      storageRootHash: data.metadataHash || '',
      soulBackupHash: data.soulBackupHash || '',
      soulBackupURI: data.soulBackupURI || '',
      // Agent's dedicated wallet — iNFT mints directly into this wallet
      agentWalletAddress: data.agentWalletAddress || null
    };

    // Call the actual on-chain registration via viem
    try {
      const result = await viem.registerAgentOnchain(agentConfig);
      return {
        txHash: result.txHash,
        tokenId: result.tokenId
      };
    } catch (error) {
      console.error('On-chain registration error:', error);
      throw new Error(`Contract call failed: ${error.message}`);
    }
  }

  async generateDM3Profile(config, walletClient) {
    const ensName = config.ensName || config.ens;

    // Generate real X25519 encryption key pair via Web Crypto
    const encKeyPair = await crypto.subtle.generateKey(
      { name: 'X25519' },
      true,
      ['deriveBits']
    );
    const encPubRaw = await crypto.subtle.exportKey('raw', encKeyPair.publicKey);
    const encPrivRaw = await crypto.subtle.exportKey('pkcs8', encKeyPair.privateKey);
    const publicEncryptionKey = '0x' + Array.from(new Uint8Array(encPubRaw))
      .map(b => b.toString(16).padStart(2, '0')).join('');
    const privateEncryptionKey = '0x' + Array.from(new Uint8Array(encPrivRaw))
      .map(b => b.toString(16).padStart(2, '0')).join('');

    // Generate real Ed25519 signing key pair via Web Crypto
    const sigKeyPair = await crypto.subtle.generateKey(
      { name: 'Ed25519' },
      true,
      ['sign', 'verify']
    );
    const sigPubRaw = await crypto.subtle.exportKey('raw', sigKeyPair.publicKey);
    const sigPrivRaw = await crypto.subtle.exportKey('pkcs8', sigKeyPair.privateKey);
    const publicSigningKey = '0x' + Array.from(new Uint8Array(sigPubRaw))
      .map(b => b.toString(16).padStart(2, '0')).join('');
    const privateSigningKey = '0x' + Array.from(new Uint8Array(sigPrivRaw))
      .map(b => b.toString(16).padStart(2, '0')).join('');

    return {
      publicEncryptionKey,
      privateEncryptionKey,
      publicSigningKey,
      privateSigningKey,
      deliveryServiceUrl: DM3_CONFIG.defaultDeliveryService,
      ensName
    };
  }

  async generateAgentId(name) {
    // Generate deterministic agent ID using keccak256 — matches contract and viem-client
    const { keccak256, toUtf8Bytes } = await import('https://esm.sh/ethers@6.13.4');
    return keccak256(toUtf8Bytes(name.toLowerCase().trim()));
  }

  async generatePolicyHash(config) {
    // Generate policy hash using keccak256 — matches contract and viem-client
    const { keccak256, toUtf8Bytes } = await import('https://esm.sh/ethers@6.13.4');
    const policyData = JSON.stringify({
      tools: config.allowedTools || config.tools || [],
      valueLimit: config.valueLimit,
      endpoints: config.endpoints || [],
      network: config.network
    });
    return keccak256(toUtf8Bytes(policyData));
  }

  generateImageId(config) {
    // Use the deployed RISC Zero image ID from network config
    const network = config.network?.includes('sepolia') ? 'sepolia' : 'testnet';
    const networkConfig = ZERO_G_CONFIG[network];
    if (networkConfig?.riscZeroImageId) {
      return networkConfig.riscZeroImageId;
    }
    throw new Error(
      'RISC Zero image ID not configured. Build the guest program and set riscZeroImageId in ZERO_G_CONFIG.'
    );
  }
}

// Export singleton instance
export const agentRegistration = new AgentRegistrationManager();

// Export configuration
export { ZERO_G_CONFIG, DM3_CONFIG };
