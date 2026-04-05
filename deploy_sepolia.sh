#!/bin/bash
# Deploy ProofOfClawVerifier to Sepolia

set -e

# Check environment variables
if [ -z "$PRIVATE_KEY" ]; then
    echo "Error: PRIVATE_KEY not set"
    echo "export PRIVATE_KEY=0x..."
    exit 1
fi

if [ -z "$SEPOLIA_RPC_URL" ]; then
    echo "Using default Sepolia RPC"
    export SEPOLIA_RPC_URL="https://rpc.sepolia.org"
fi

# Use image ID from proof_output.json or env
if [ -z "$RISC_ZERO_IMAGE_ID" ]; then
    if [ -f "proof_output.json" ]; then
        export RISC_ZERO_IMAGE_ID=$(cat proof_output.json | grep -o '"image_id": "[^"]*"' | cut -d'"' -f4)
        echo "Using image ID from proof_output.json: $RISC_ZERO_IMAGE_ID"
    else
        echo "Error: RISC_ZERO_IMAGE_ID not set and proof_output.json not found"
        exit 1
    fi
fi

cd contracts

echo "Deploying ProofOfClawVerifier to Sepolia..."
echo "Image ID: $RISC_ZERO_IMAGE_ID"
echo ""

forge script script/DeployAndVerify.s.sol:DeployAndVerifyScript \
    --rpc-url $SEPOLIA_RPC_URL \
    --broadcast \
    -vvvv

echo ""
echo "Deployment complete! Save the contract address above."
