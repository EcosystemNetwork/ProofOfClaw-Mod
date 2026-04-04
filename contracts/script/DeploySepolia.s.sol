// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "forge-std/console.sol";
import "../src/RiscZeroMockVerifier.sol";
import "../src/ProofOfClawVerifier.sol";
import "../src/ProofOfClawINFT.sol";
import "../src/SoulVaultSwarm.sol";
import "../src/SoulVaultERC8004RegistryAdapter.sol";
import "../src/EIP8004Integration.sol";

/// @title DeploySepolia — Deploy all Proof of Claw contracts to Ethereum Sepolia
/// @notice Deploys with a mock RISC Zero verifier suitable for testnet usage.
///
/// Usage:
///   source .env && forge script script/DeploySepolia.s.sol \
///     --rpc-url $SEPOLIA_RPC_URL --broadcast --verify \
///     --etherscan-api-key $ETHERSCAN_API_KEY
///
/// Required env vars:
///   PRIVATE_KEY          — Deployer wallet (must have Sepolia ETH for gas)
///   RISC_ZERO_IMAGE_ID   — RISC Zero guest image ID (bytes32)
contract DeploySepoliaScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        bytes32 imageId = vm.envBytes32("RISC_ZERO_IMAGE_ID");

        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy mock RISC Zero verifier (testnet only)
        RiscZeroMockVerifier mockVerifier = new RiscZeroMockVerifier();
        console.log("RiscZeroMockVerifier deployed at:", address(mockVerifier));

        // 2. Deploy ProofOfClawVerifier using the mock verifier
        ProofOfClawVerifier proofOfClaw = new ProofOfClawVerifier(
            IRiscZeroVerifier(address(mockVerifier)),
            imageId
        );
        console.log("ProofOfClawVerifier deployed at:", address(proofOfClaw));

        // 3. Deploy ProofOfClawINFT (ERC-7857 agent identity iNFT)
        ProofOfClawINFT inft = new ProofOfClawINFT(address(proofOfClaw));
        console.log("ProofOfClawINFT deployed at:", address(inft));

        // 4. Deploy SoulVaultSwarm (multi-agent coordination)
        SoulVaultSwarm swarm = new SoulVaultSwarm();
        console.log("SoulVaultSwarm deployed at:", address(swarm));

        // 5. Deploy SoulVaultERC8004RegistryAdapter (self-sovereign agent registry)
        SoulVaultERC8004RegistryAdapter registryAdapter = new SoulVaultERC8004RegistryAdapter();
        console.log("SoulVaultERC8004RegistryAdapter deployed at:", address(registryAdapter));

        // 6. Deploy EIP8004Integration (uses registry adapter as all three registries for testnet)
        EIP8004Integration eip8004 = new EIP8004Integration(
            address(registryAdapter), // identity registry
            address(registryAdapter), // reputation registry
            address(registryAdapter), // validation registry
            address(proofOfClaw)
        );
        console.log("EIP8004Integration deployed at:", address(eip8004));

        // 7. Link verifier to EIP-8004 integration
        proofOfClaw.setEIP8004Integration(address(eip8004));
        console.log("EIP-8004 integration linked to verifier");

        vm.stopBroadcast();

        // ── Summary ──────────────────────────────────────────────────
        console.log("");
        console.log("=== Sepolia Deployment Summary ===");
        console.log("Chain:                   Sepolia (11155111)");
        console.log("MockVerifier:           ", address(mockVerifier));
        console.log("ProofOfClawVerifier:    ", address(proofOfClaw));
        console.log("ProofOfClawINFT:        ", address(inft));
        console.log("SoulVaultSwarm:         ", address(swarm));
        console.log("ERC8004RegistryAdapter: ", address(registryAdapter));
        console.log("EIP8004Integration:     ", address(eip8004));
        console.log("==================================");
        console.log("");
        console.log("Next steps:");
        console.log("  1. Update .env with the deployed addresses above");
        console.log("  2. Update frontend/viem-client.js with the iNFT and registry addresses");
        console.log("  3. Verify contracts: forge verify-contract <address> <ContractName> --chain sepolia");
    }
}
