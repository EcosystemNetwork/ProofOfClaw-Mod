#!/bin/bash
# Deploy ProofOfClawVerifier to 0G Testnet

set -e

# Check environment
if [ -z "$PRIVATE_KEY" ]; then
    echo "Error: PRIVATE_KEY not set"
    echo "export PRIVATE_KEY=0x..."
    exit 1
fi

# 0G Testnet RPC
export OG_TESTNET_RPC_URL="${OG_TESTNET_RPC_URL:-https://evmrpc-testnet.0g.ai}"

# Image ID from proof_output.json or env
if [ -z "$RISC_ZERO_IMAGE_ID" ]; then
    if [ -f "proof_output.json" ]; then
        export RISC_ZERO_IMAGE_ID=$(cat proof_output.json | grep -o '"image_id": "[^"]*"' | cut -d'"' -f4)
    else
        echo "Error: RISC_ZERO_IMAGE_ID not set and proof_output.json not found"
        echo "Build the guest program first: cd zkvm && cargo risczero build --release"
        exit 1
    fi
fi

echo "==================================="
echo "Deploying to 0G Testnet"
echo "==================================="
echo "RPC URL: $OG_TESTNET_RPC_URL"
echo "Image ID: $RISC_ZERO_IMAGE_ID"
echo ""

cd contracts

# Deploy Groth16 verifier + ProofOfClawVerifier
forge script script/Deploy0GTestnet.s.sol:Deploy0GTestnet \
    --rpc-url "$OG_TESTNET_RPC_URL" \
    --broadcast \
    -vvvv

echo ""
echo "==================================="
echo "Deployment Complete!"
echo "==================================="
echo "Save the contract addresses above."
echo ""
echo "To verify a proof on 0G testnet:"
echo "cast send <ProofOfClawVerifier-address> \"verifyAndExecute(bytes,bytes,bytes)\" \"
echo "  0x<seal> \"
echo "  0x<journal> \"
echo "  0x<action-data> \"
echo "  --rpc-url https://evmrpc-testnet.0g.ai \"
echo "  --private-key \$PRIVATE_KEY"
