#!/bin/bash
# Verify a proof on-chain (0G Testnet)

set -e

if [ -z "$PRIVATE_KEY" ]; then
    echo "Error: PRIVATE_KEY not set"
    exit 1
fi

if [ -z "$VERIFIER_ADDRESS" ]; then
    echo "Error: VERIFIER_ADDRESS not set"
    echo "Set it with: export VERIFIER_ADDRESS=0x..."
    exit 1
fi

export OG_TESTNET_RPC_URL="${OG_TESTNET_RPC_URL:-https://evmrpc-testnet.0g.ai}"

# Use proof from proof_output.json or use test values
if [ -f "proof_output.json" ]; then
    SEAL=$(cat proof_output.json | grep -o '"seal": "[^"]*"' | cut -d'"' -f4)
    JOURNAL=$(cat proof_output.json | grep -o '"journal": "[^"]*"' | cut -d'"' -f4)
else
    # Test values
    SEAL="0xdeadbeef000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    JOURNAL="0x7b226167656e745f6964223a22616c6963652e70726f6f66636c61772e657468222c22706f6c6963795f68617368223a22307861626364222c226f75747075745f636f6d6d69746d656e74223a22307834343434222c22616c6c5f636865636b735f706173736564223a747275652c2272657175697265735f6c65646765725f617070726f76616c223a66616c73652c22616374696f6e5f76616c7565223a353030303030303030303030303030307d"
fi

# Action data (empty for simple test)
ACTION="0x"

echo "==================================="
echo "Verifying Proof on 0G Testnet"
echo "==================================="
echo "Verifier: $VERIFIER_ADDRESS"
echo "Seal: ${SEAL:0:50}..."
echo "Journal: ${JOURNAL:0:50}..."
echo ""

cast send $VERIFIER_ADDRESS \
    "verifyAndExecute(bytes,bytes,bytes)" \
    "$SEAL" \
    "$JOURNAL" \
    "$ACTION" \
    --rpc-url $OG_TESTNET_RPC_URL \
    --private-key $PRIVATE_KEY \
    --gas-limit 500000

echo ""
echo "==================================="
echo "Proof verification submitted!"
echo "==================================="
