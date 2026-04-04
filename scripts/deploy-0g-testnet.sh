#!/bin/bash
# Deploy Proof of Claw contracts to 0G Testnet
# Usage: ./deploy-0g-testnet.sh [PRIVATE_KEY]

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check for private key
if [ -z "$1" ] && [ -z "$PRIVATE_KEY" ]; then
    echo -e "${RED}Error: Private key required${NC}"
    echo "Usage: $0 0xYOUR_PRIVATE_KEY"
    echo "Or set PRIVATE_KEY environment variable"
    exit 1
fi

PK="${1:-$PRIVATE_KEY}"

# 0G Testnet RPC
RPC_URL="https://evmrpc-testnet.0g.ai"

echo -e "${YELLOW}====================================${NC}"
echo -e "${YELLOW}Deploying to 0G Testnet${NC}"
echo -e "${YELLOW}====================================${NC}"

# Change to contracts directory
cd "$(dirname "$0")/../contracts"

# Run dry run first
echo -e "\n${YELLOW}Running dry run simulation...${NC}"
forge script script/Deploy0G.s.sol \
    --rpc-url "$RPC_URL" \
    --evm-version cancun \
    -vvv 2>&1 | head -50

echo -e "\n${GREEN}Dry run complete. Proceed with actual deployment? (y/n)${NC}"
read -r response

if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    echo -e "\n${YELLOW}Broadcasting deployment...${NC}"
    
    # Run actual deployment
    PRIVATE_KEY="$PK" \
    forge script script/Deploy0G.s.sol \
        --rpc-url "$RPC_URL" \
        --broadcast \
        --evm-version cancun \
        -vvv
    
    echo -e "\n${GREEN}Deployment complete!${NC}"
    echo -e "${YELLOW}Note: Save the deployed contract addresses and update your frontend config${NC}"
else
    echo -e "\n${YELLOW}Deployment cancelled${NC}"
fi
