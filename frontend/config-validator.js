/**
 * Agent Configuration Validator
 * Provides robust validation for agent registration configuration
 */

export const ValidationRules = {
  agentName: {
    required: true,
    minLength: 3,
    maxLength: 32,
    pattern: /^[a-z0-9-]+$/,
    message: 'Agent name must be 3-32 characters, lowercase letters, numbers, and hyphens only'
  },
  ensName: {
    required: true,
    pattern: /^[a-z0-9-]+\.[a-z0-9-]+\.(eth|test)$/i,
    message: 'ENS name must be a valid subdomain (e.g., agent.proofclaw.eth)'
  },
  privateKey: {
    required: false,
    pattern: /^0x[a-fA-F0-9]{64}$/,
    message: 'Private key must be 64 hex characters with 0x prefix'
  },
  rpcUrl: {
    required: true,
    pattern: /^https?:\/\/.+/,
    message: 'RPC URL must be a valid HTTP/HTTPS URL'
  },
  endpoints: {
    pattern: /^([a-zA-Z0-9.-]+(,[a-zA-Z0-9.-]+)*)?$/,
    message: 'Endpoints must be comma-separated domain names'
  },
  valueLimit: {
    required: true,
    min: 0,
    max: 1000000,
    message: 'Value limit must be between 0 and 1,000,000 USD'
  }
};

export const Networks = {
  sepolia: {
    id: 'sepolia',
    name: 'Sepolia',
    chainId: 11155111,
    rpcUrl: 'https://eth-sepolia.g.alchemy.com/v2/',
    currency: 'ETH',
    explorer: 'https://sepolia.etherscan.io',
    isTestnet: true,
    contracts: {
      inft: '0x0000000000000000000000000000000000000000',
      registry: '0x0000000000000000000000000000000000000000'
    }
  },
  og_testnet: {
    id: 'og_testnet',
    name: '0G Testnet',
    chainId: 16602,
    rpcUrl: 'https://evmrpc-testnet.0g.ai',
    currency: 'OG',
    explorer: 'https://chainscan-dev.0g.ai',
    isTestnet: true,
    contracts: {
      inft: '0x0000000000000000000000000000000000000000',
      registry: '0x0000000000000000000000000000000000000000'
    }
  },
  og_mainnet: {
    id: 'og_mainnet',
    name: '0G Mainnet',
    chainId: 16661,
    rpcUrl: 'https://evmrpc.0g.ai',
    currency: 'OG',
    explorer: 'https://chainscan.0g.ai',
    isTestnet: false,
    contracts: {
      inft: '0x0000000000000000000000000000000000000000',
      registry: '0x0000000000000000000000000000000000000000'
    }
  }
};

export class ConfigValidator {
  constructor() {
    this.errors = {};
    this.warnings = {};
    this.fieldStatus = {};
  }

  validateField(fieldName, value, rules = ValidationRules[fieldName]) {
    if (!rules) return { valid: true };

    const errors = [];
    const warnings = [];

    // Required check
    if (rules.required && (!value || value.trim?.() === '')) {
      errors.push(`${fieldName} is required`);
    }

    // Pattern check
    if (value && rules.pattern && !rules.pattern.test(value)) {
      errors.push(rules.message);
    }

    // Length checks
    if (value) {
      if (rules.minLength && value.length < rules.minLength) {
        errors.push(`Must be at least ${rules.minLength} characters`);
      }
      if (rules.maxLength && value.length > rules.maxLength) {
        errors.push(`Must be at most ${rules.maxLength} characters`);
      }
    }

    // Numeric range checks
    if (typeof value === 'number' || (value && !isNaN(value))) {
      const num = Number(value);
      if (rules.min !== undefined && num < rules.min) {
        errors.push(`Must be at least ${rules.min}`);
      }
      if (rules.max !== undefined && num > rules.max) {
        errors.push(`Must be at most ${rules.max}`);
      }
    }

    // Specific field validations
    switch (fieldName) {
      case 'agentName':
        if (value && this.isReservedName(value)) {
          errors.push('This name is reserved or already in use');
        }
        break;
      case 'ensName':
        if (value) {
          const ensValidation = this.validateENS(value);
          if (!ensValidation.valid) {
            errors.push(ensValidation.error);
          }
        }
        break;
      case 'privateKey':
        if (value) {
          const keyValidation = this.validatePrivateKey(value);
          if (!keyValidation.valid) {
            if (keyValidation.isDemo) {
              warnings.push('Using a demo key - only for testing');
            } else {
              errors.push(keyValidation.error);
            }
          }
          if (keyValidation.isZeroKey) {
            warnings.push('Key appears to be all zeros - will generate random key');
          }
        }
        break;
    }

    const valid = errors.length === 0;
    this.errors[fieldName] = errors;
    this.warnings[fieldName] = warnings;
    this.fieldStatus[fieldName] = valid ? (warnings.length ? 'warning' : 'valid') : 'invalid';

    return { valid, errors, warnings };
  }

  validateAll(config) {
    const results = {};
    let allValid = true;

    for (const [field, rules] of Object.entries(ValidationRules)) {
      const value = config[field];
      const result = this.validateField(field, value, rules);
      results[field] = result;
      if (!result.valid) allValid = false;
    }

    return { valid: allValid, fields: results, errors: this.errors, warnings: this.warnings };
  }

  validateENS(ensName) {
    // Basic ENS validation
    if (!ensName.includes('.')) {
      return { valid: false, error: 'ENS name must contain a dot (e.g., name.eth)' };
    }

    const parts = ensName.split('.');
    if (parts.length < 2) {
      return { valid: false, error: 'ENS name must have at least a domain and TLD' };
    }

    // Check for valid characters
    const validLabel = /^[a-z0-9-]+$/i;
    for (const part of parts) {
      if (!validLabel.test(part)) {
        return { valid: false, error: 'ENS labels can only contain letters, numbers, and hyphens' };
      }
      if (part.startsWith('-') || part.endsWith('-')) {
        return { valid: false, error: 'ENS labels cannot start or end with hyphens' };
      }
    }

    // Check TLD
    const tld = parts[parts.length - 1].toLowerCase();
    if (!['eth', 'test'].includes(tld)) {
      return { valid: false, error: 'Only .eth and .test TLDs are supported' };
    }

    return { valid: true };
  }

  validatePrivateKey(key) {
    if (!key || key.trim() === '') {
      return { valid: true, isDemo: true };
    }

    const cleanKey = key.toLowerCase().replace('0x', '');
    
    if (cleanKey.length !== 64) {
      return { valid: false, error: 'Private key must be exactly 64 hex characters' };
    }

    if (!/^[0-9a-f]+$/.test(cleanKey)) {
      return { valid: false, error: 'Private key must contain only hex characters' };
    }

    if (/^0{64}$/.test(cleanKey)) {
      return { valid: false, isZeroKey: true, error: 'Private key cannot be all zeros' };
    }

    // Check for commonly used demo/test keys
    const demoKeys = [
      '0000000000000000000000000000000000000000000000000000000000000001',
      'ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
    ];
    if (demoKeys.includes(cleanKey)) {
      return { valid: true, isDemo: true, warning: 'Using known test key - for development only' };
    }

    return { valid: true };
  }

  isReservedName(name) {
    const reserved = [
      'admin', 'root', 'system', 'test', 'demo', 'example',
      'localhost', 'api', 'www', 'app', 'docs'
    ];
    return reserved.includes(name.toLowerCase());
  }

  getFieldStatus(fieldName) {
    return this.fieldStatus[fieldName] || 'neutral';
  }

  clearField(fieldName) {
    delete this.errors[fieldName];
    delete this.warnings[fieldName];
    delete this.fieldStatus[fieldName];
  }

  clearAll() {
    this.errors = {};
    this.warnings = {};
    this.fieldStatus = {};
  }
}

// Helper to generate ENS from agent name
export function generateENS(agentName, parentDomain = 'proofclaw.eth') {
  const slug = agentName.toLowerCase().replace(/[^a-z0-9-]/g, '');
  return slug ? `${slug}.${parentDomain}` : '';
}

// Helper to estimate deployment costs
export function estimateDeploymentCost(networkId) {
  const network = Networks[networkId];
  if (!network) return null;

  // Rough gas estimates for agent registration
  const gasUnits = {
    inftMint: 150000,
    registry: 80000,
    ensRegistration: 120000
  };

  const totalGas = gasUnits.inftMint + gasUnits.registry + gasUnits.ensRegistration;
  
  return {
    gasUnits: totalGas,
    network: network.name,
    currency: network.currency,
    isTestnet: network.isTestnet,
    // Actual cost requires gas price lookup
    estimatedCost: null
  };
}

// Export singleton instance
export const configValidator = new ConfigValidator();
