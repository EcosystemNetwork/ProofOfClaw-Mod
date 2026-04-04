// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "forge-std/console.sol";
import "../src/ProofOfClawVerifier.sol";
import "../src/ProofOfClawINFT.sol";

/// @title Deploy0G — Deploy Proof of Claw contracts to 0G Chain
/// @notice Deploys ProofOfClawVerifier and ProofOfClawINFT to 0G Testnet or Mainnet.
///
/// Usage (testnet):
///   forge script script/Deploy0G.s.sol --rpc-url https://evmrpc-testnet.0g.ai \
///     --broadcast --evm-version cancun
///
/// Usage (mainnet):
///   forge script script/Deploy0G.s.sol --rpc-url https://evmrpc.0g.ai \
///     --broadcast --evm-version cancun
///
/// Required env vars:
///   PRIVATE_KEY                 — Deployer wallet (must have 0G tokens for gas)
///   RISC_ZERO_VERIFIER_ADDRESS  — RISC Zero verifier address on 0G
///   RISC_ZERO_IMAGE_ID          — RISC Zero guest image ID (bytes32)
contract Deploy0GScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address verifierAddress = vm.envAddress("RISC_ZERO_VERIFIER_ADDRESS");
        bytes32 imageId = vm.envBytes32("RISC_ZERO_IMAGE_ID");

        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy ProofOfClawVerifier
        ProofOfClawVerifier proofOfClaw = new ProofOfClawVerifier(
            IRiscZeroVerifier(verifierAddress),
            imageId
        );
        console.log("ProofOfClawVerifier deployed at:", address(proofOfClaw));

        // 2. Deploy ProofOfClawINFT (ERC-7857 iNFT)
        ProofOfClawINFT inft = new ProofOfClawINFT(address(proofOfClaw));
        console.log("ProofOfClawINFT deployed at:", address(inft));

        // 3. Log deployment info
        console.log("---");
        console.log("Chain: 0G");
        console.log("Verifier:", address(proofOfClaw));
        console.log("iNFT:", address(inft));
        console.log("Image ID set");
        console.log("---");
        console.log("Next steps:");
        console.log("  1. Set INFT_CONTRACT in .env to the iNFT address above");
        console.log("  2. Verify contracts: forge verify-contract <address> ProofOfClawINFT --chain-id 16602");
        console.log("  3. Mint agent iNFT via the frontend deploy wizard");

        vm.stopBroadcast();
    }
}
