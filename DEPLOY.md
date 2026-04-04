# Deploy to 0G Testnet

## Prerequisites
- Foundry installed (`forge --version`)
- 0G testnet tokens from https://faucet.0g.ai

## Deploy Commands

```bash
# Navigate to contracts directory
cd contracts

# Set your private key (with 0x prefix)
export PRIVATE_KEY=0xe770f73a119b637161fe37282ea41cffb9219eb586b29d2818ad3437f78a1860

# Run deployment
forge script script/Deploy0G.s.sol \
  --rpc-url https://evmrpc-testnet.0g.ai \
  --broadcast \
  --evm-version cancun \
  -vvv
```

## Expected Output

```
ProofOfClawVerifier deployed at: 0x...
ProofOfClawINFT deployed at: 0x...
---
Chain: 0G
Verifier: 0x...
iNFT: 0x...
```

## Update Frontend

After deployment, update these files with the contract addresses:

1. `frontend/viem-client.js` - Update contract addresses
2. `frontend/0g-registration.js` - Update ZERO_G_CONFIG
3. `.env` - Set INFT_CONTRACT address

## Verify Contracts

```bash
forge verify-contract <iNFT_ADDRESS> ProofOfClawINFT --chain-id 16602
forge verify-contract <VERIFIER_ADDRESS> ProofOfClawVerifier --chain-id 16602
```
