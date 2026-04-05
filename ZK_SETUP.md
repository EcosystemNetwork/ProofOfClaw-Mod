# ZK Proof System - Setup & Usage Guide

## Overview

This ZK proof system enables:
- **Proof Generation**: RISC Zero zkVM proofs of agent execution traces
- **On-Chain Verification**: Verification via `ProofOfClawVerifier` smart contract
- **Mock Mode**: Development mode with SHA-256 based mock proofs

## Current Status

| Component | Status |
|-----------|--------|
| Mock Proof Generation | ✅ Working (11 tests pass) |
| Solidity Contracts | ✅ Built |
| Deployment Scripts | ✅ Ready |
| RISC Zero Guest | ⚠️ Docker build failed (Cargo version issue) |
| On-Chain Verification | ✅ Ready (requires deployment) |

## Quick Start

### 1. Run Mock Proof Generation

```bash
cd proof_of_claw
cargo test -- --nocapture
```

This generates mock proof receipts using SHA-256 hashing.

### 2. Build Solidity Contracts

```bash
cd contracts
forge build
```

### 3. Run End-to-End Test

```bash
./test_zk_e2e.sh
```

## Deployment to Sepolia

### Prerequisites

Set environment variables:

```bash
export PRIVATE_KEY=0xYOUR_PRIVATE_KEY
export SEPOLIA_RPC_URL=https://rpc.sepolia.org
export RISC_ZERO_IMAGE_ID=0xYOUR_IMAGE_ID
```

### Deploy Verifier Contract

```bash
cd contracts
forge script script/DeployAndVerify.s.sol:DeployAndVerifyScript \
  --rpc-url $SEPOLIA_RPC_URL \
  --broadcast \
  -vvvv
```

### Verify a Proof On-Chain

After deployment, call `verifyAndExecute`:

```bash
cast send <VERIFIER_ADDRESS> \
  "verifyAndExecute(bytes,bytes,bytes)" \
  0x<SEAL_HEX> \
  0x<JOURNAL_HEX> \
  0x<ACTION_DATA> \
  --rpc-url $SEPOLIA_RPC_URL \
  --private-key $PRIVATE_KEY
```

## Switching to Real RISC Zero Proofs

### Option A: Local Proving (Resource Intensive)

```bash
# 1. Install RISC Zero
curl -L https://risczero.com/install | bash
rzup install

# 2. Build guest ELF
cd zkvm/guest
cargo risczero build

# 3. Get image ID
cargo run --bin risc0-image-id

# 4. Run host to generate real proof
cd zkvm/host
cargo run
```

### Option B: Boundless Proving (Recommended)

```bash
# 1. Get API key from https://boundless.xyz

# 2. Set environment variable
export BOUNDLESS_API_KEY=your_api_key

# 3. Use Boundless SDK to request proofs
# ~$0.30-$30 per proof depending on complexity
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    PROOF GENERATION                          │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │ Execution    │───→│ RISC Zero    │───→│   Receipt    │  │
│  │   Trace      │    │   Guest      │    │  (seal +     │  │
│  │              │    │  (zkVM)      │    │  journal)    │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  ON-CHAIN VERIFICATION                       │
│  ┌──────────────────────────────────────────────────────┐  │
│  │         ProofOfClawVerifier Contract                  │  │
│  │  ┌─────────────┐    ┌─────────────────────────────┐  │  │
│  │  │ IRiscZero   │───→│ verify(seal, imageId, hash) │  │  │
│  │  │  Verifier   │    └─────────────────────────────┘  │  │
│  │  └─────────────┘                                     │  │
│  │  ┌─────────────┐    ┌─────────────────────────────┐  │  │
│  │  │   Policy    │───→│  Check agent registration   │  │  │
│  │  │   Engine    │    └─────────────────────────────┘  │  │
│  │  └─────────────┘                                     │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## File Structure

- `zkvm/guest/` - RISC Zero guest program (proof circuit)
- `zkvm/host/` - Host application for generating proofs
- `contracts/src/ProofOfClawVerifier.sol` - On-chain verifier
- `contracts/script/DeployAndVerify.s.sol` - Deployment script
- `proof_of_claw/src/proof_generator.rs` - Mock proof generation

## Troubleshooting

### Docker Build Failed

The RISC Zero Docker build failed due to Cargo version incompatibility. Use local proving or Boundless instead.

### Missing Ironclaw Dependency

The ironclaw dependency is optional. The proof system works standalone without it.

## Next Steps

1. ✅ Proof generation works (mock mode)
2. ✅ Contracts compile successfully
3. ⏭️ Deploy to Sepolia with `RISC_ZERO_IMAGE_ID`
4. ⏭️ Integrate real RISC Zero proving (when toolchain available)
