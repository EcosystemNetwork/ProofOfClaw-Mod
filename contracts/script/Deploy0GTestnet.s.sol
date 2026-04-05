// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "forge-std/console.sol";
import "../src/ProofOfClawVerifier.sol";
import "../src/mocks/MockRiscZeroVerifier.sol";

/// @title Deploy0GTestnet
/// @notice Deploys the ProofOfClawVerifier to 0G testnet with mock verifier
contract Deploy0GTestnet is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        bytes32 imageId = vm.envBytes32("RISC_ZERO_IMAGE_ID");
        
        vm.startBroadcast(deployerPrivateKey);
        
        // Deploy mock verifier first
        MockRiscZeroVerifier mockVerifier = new MockRiscZeroVerifier();
        console.log("MockRiscZeroVerifier deployed at:", address(mockVerifier));
        
        // Set the image ID as valid
        mockVerifier.setValidImageId(imageId, true);
        console.log("Image ID registered as valid:", vm.toString(imageId));
        
        // Deploy ProofOfClawVerifier with mock verifier
        ProofOfClawVerifier proofOfClaw = new ProofOfClawVerifier(
            IRiscZeroVerifier(address(mockVerifier)),
            imageId
        );
        console.log("ProofOfClawVerifier deployed at:", address(proofOfClaw));
        
        // Register an agent
        bytes32 agentId = keccak256("alice.proofclaw.eth");
        bytes32 policyHash = keccak256("test-policy");
        uint256 maxValueAutonomous = 100 ether;
        address agentWallet = vm.addr(deployerPrivateKey);
        
        proofOfClaw.registerAgent(agentId, policyHash, maxValueAutonomous, agentWallet);
        console.log("Agent registered with ID:", vm.toString(agentId));
        
        vm.stopBroadcast();
        
        console.log("\n=== 0G Testnet Deployment Complete ===");
        console.log("Mock Verifier:", address(mockVerifier));
        console.log("ProofOfClawVerifier:", address(proofOfClaw));
        console.log("\nTo verify a proof:");
        console.log("cast send <verifier-address> \"verifyAndExecute(bytes,bytes,bytes)\" <seal> <journal> <action> --rpc-url https://evmrpc-testnet.0g.ai --private-key $PRIVATE_KEY");
    }
}
