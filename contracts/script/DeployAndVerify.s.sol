// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "forge-std/console.sol";
import "../src/ProofOfClawVerifier.sol";

/// @title DeployAndVerifyScript
/// @notice Deploys the ProofOfClawVerifier and demonstrates on-chain proof verification
/// @dev This script deploys to 0G testnet
contract DeployAndVerifyScript is Script {
    // RISC Zero verifier contract address - set via environment variable
    // For 0G testnet, deploy MockRiscZeroVerifier first if needed
    address riscZeroVerifier;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        bytes32 imageId = vm.envBytes32("RISC_ZERO_IMAGE_ID");
        
        // Get verifier address from env, default to address(0)
        riscZeroVerifier = vm.envOr("RISC_ZERO_VERIFIER", address(0));

        vm.startBroadcast(deployerPrivateKey);

        // Deploy ProofOfClawVerifier with the RISC Zero verifier
        ProofOfClawVerifier proofOfClaw = new ProofOfClawVerifier(
            IRiscZeroVerifier(riscZeroVerifier),
            imageId
        );

        console.log("ProofOfClawVerifier deployed at:", address(proofOfClaw));
        console.log("Image ID:", vm.toString(imageId));

        // Example: Register an agent with policy
        bytes32 agentId = keccak256("alice.proofclaw.eth");
        bytes32 policyHash = keccak256("test-policy");
        uint256 maxValueAutonomous = 100 ether;
        address agentWallet = vm.addr(deployerPrivateKey);

        proofOfClaw.registerAgent(
            agentId,
            policyHash,
            maxValueAutonomous,
            agentWallet
        );

        console.log("Agent registered with ID:", vm.toString(agentId));
        console.log("Agent wallet:", agentWallet);

        vm.stopBroadcast();

        console.log("\n=== Deployment Complete ===");
        console.log("Network: 0G Testnet");
        console.log("To verify a proof on-chain, use:");
        console.log("cast send <verifier-address> \"verifyAndExecute(bytes,bytes,bytes)\" <seal> <journal> <action> --rpc-url $OG_TESTNET_RPC_URL --private-key $PRIVATE_KEY");
    }
}
