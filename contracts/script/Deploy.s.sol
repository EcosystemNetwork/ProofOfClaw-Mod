// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "forge-std/console.sol";
import "../src/ProofOfClawVerifier.sol";
import "../src/EIP8004Integration.sol";
import "../src/ProofOfClawINFT.sol";

contract DeployScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address verifierAddress = vm.envAddress("RISC_ZERO_VERIFIER_ADDRESS");
        bytes32 imageId = vm.envBytes32("RISC_ZERO_IMAGE_ID");

        // EIP-8004 registry addresses (deployed separately per EIP-8004 spec)
        address identityRegistry = vm.envAddress("EIP8004_IDENTITY_REGISTRY");
        address reputationRegistry = vm.envAddress("EIP8004_REPUTATION_REGISTRY");
        address validationRegistry = vm.envAddress("EIP8004_VALIDATION_REGISTRY");

        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy ProofOfClawVerifier
        ProofOfClawVerifier proofOfClaw = new ProofOfClawVerifier(
            IRiscZeroVerifier(verifierAddress),
            imageId
        );
        console.log("ProofOfClawVerifier deployed at:", address(proofOfClaw));

        // 2. Deploy EIP-8004 Integration
        EIP8004Integration eip8004 = new EIP8004Integration(
            identityRegistry,
            reputationRegistry,
            validationRegistry,
            address(proofOfClaw)
        );
        console.log("EIP8004Integration deployed at:", address(eip8004));

        // 3. Link verifier to EIP-8004 integration
        proofOfClaw.setEIP8004Integration(address(eip8004));
        console.log("EIP-8004 integration linked to verifier");

        // 4. Deploy ProofOfClawINFT (ERC-7857 iNFT for agent identity on 0G)
        ProofOfClawINFT inft = new ProofOfClawINFT(address(proofOfClaw));
        console.log("ProofOfClawINFT deployed at:", address(inft));

        vm.stopBroadcast();
    }
}
