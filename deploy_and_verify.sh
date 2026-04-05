#!/bin/bash
# Deploy and immediately verify a proof on 0G Testnet

set -e

if [ -z "$PRIVATE_KEY" ]; then
    echo "Error: PRIVATE_KEY not set"
    exit 1
fi

export OG_TESTNET_RPC_URL="${OG_TESTNET_RPC_URL:-https://evmrpc-testnet.0g.ai}"

# Image ID
if [ -z "$RISC_ZERO_IMAGE_ID" ]; then
    export RISC_ZERO_IMAGE_ID="0x6356d10d377b75c568fe9041a6da3ef55a6134c301fcc334ea245dc843435d58"
fi

echo "==================================="
echo "Proof of Claw - 0G Testnet Deploy & Verify"
echo "==================================="
echo ""

cd contracts

# Deploy
echo "Step 1: Deploying contracts..."
forge script script/Deploy0GTestnet.s.sol:Deploy0GTestnet \
    --rpc-url $OG_TESTNET_RPC_URL \
    --broadcast \
    -vvvv 2>&1 | tee /tmp/deploy_output.txt

# Extract verifier address
VERIFIER_ADDRESS=$(grep "ProofOfClawVerifier deployed at:" /tmp/deploy_output.txt | tail -1 | awk '{print $NF}')

echo ""
echo "Step 2: Preparing verification..."

# Get proof data
SEAL="0xdeadbeef000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
JOURNAL="0x7b226167656e745f6964223a22616c6963652e70726f6f66636c61772e657468222c22706f6c6963795f68617368223a22307861626364222c226f75747075745f636f6d6d69746d656e74223a22307834343434222c22616c6c5f636865636b735f706173736564223a747275652c2272657175697265735f6c65646765725f617070726f76616c223a66616c73652c22616374696f6e5f76616c7565223a353030303030303030303030303030307d"
ACTION="0x"

echo "Verifier: $VERIFIER_ADDRESS"
echo ""
echo "Step 3: Submitting proof verification..."

cd ..

cast send $VERIFIER_ADDRESS \
    "verifyAndExecute(bytes,bytes,bytes)" \
    "$SEAL" \
    "$JOURNAL" \
    "$ACTION" \
    --rpc-url $OG_TESTNET_RPC_URL \
    --private-key $PRIVATE_KEY \
    --gas-limit 500000 2>&1 | tee /tmp/verify_output.txt

echo ""
echo "==================================="
echo "Complete!"
echo "==================================="
echo "Verifier: $VERIFIER_ADDRESS"
echo ""
echo "To verify again:"
echo "export VERIFIER_ADDRESS=$VERIFIER_ADDRESS"
echo "./verify_onchain.sh"
