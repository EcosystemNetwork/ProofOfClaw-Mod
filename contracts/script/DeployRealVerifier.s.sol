// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "forge-std/console.sol";
import "../src/RiscZeroGroth16Verifier.sol";
import "../src/ProofOfClawVerifier.sol";

/// @title DeployRealVerifier — Deploy real RISC Zero Groth16 verifier
/// @notice Deploys RiscZeroGroth16Verifier and updates ProofOfClawVerifier to point to it.
///
/// Usage:
///   # Step 1: Get VK from RISC Zero's trusted setup for your guest.
///   #         Build the guest then extract VK params, or use the RISC Zero
///   #         default testnet ceremony VK (set via env vars or use defaults).
///   #
///   # Step 2: Deploy:
///   forge script script/DeployRealVerifier.s.sol --rpc-url https://evmrpc-testnet.0g.ai \
///     --broadcast --evm-version cancun
///   #
///   # Step 3: Update .env with the new verifier address:
///   #   RISC_ZERO_VERIFIER_ADDRESS=<output address>
///   #
///   # Step 4: Generate a Groth16 proof via Bonsai/Boundless, submit on-chain
///
/// Required env vars:
///   PRIVATE_KEY                     — Deployer wallet (must be ProofOfClawVerifier owner)
///   PROOF_OF_CLAW_VERIFIER_ADDRESS  — Existing ProofOfClawVerifier contract address
///   RISC_ZERO_IMAGE_ID              — Guest program image ID (bytes32)
///
contract DeployRealVerifierScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address pocVerifierAddr = vm.envAddress("PROOF_OF_CLAW_VERIFIER_ADDRESS");

        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy RiscZeroGroth16Verifier (VK is hardcoded from risc0-groth16 v1.2.6 trusted setup)
        RiscZeroGroth16Verifier groth16Verifier = new RiscZeroGroth16Verifier();
        console.log("RiscZeroGroth16Verifier deployed at:", address(groth16Verifier));

        // 2. Update ProofOfClawVerifier to use the real verifier
        ProofOfClawVerifier pocVerifier = ProofOfClawVerifier(payable(pocVerifierAddr));
        pocVerifier.updateVerifier(address(groth16Verifier));
        console.log("ProofOfClawVerifier updated to use real Groth16 verifier");

        // 3. Update image ID to match compiled guest
        bytes32 imageId = vm.envBytes32("RISC_ZERO_IMAGE_ID");
        pocVerifier.updateImageId(imageId);
        console.log("Image ID updated");

        // 4. Log deployment info
        console.log("---");
        console.log("Groth16 Verifier:", address(groth16Verifier));
        console.log("ProofOfClawVerifier:", pocVerifierAddr);
        // console.log("Proof Selector:", uint256(uint32(proofSelector))); // removed: proofSelector undefined
        console.log("---");
        console.log("Next steps:");
        console.log("  1. Update RISC_ZERO_VERIFIER_ADDRESS in .env to:", address(groth16Verifier));
        console.log("  2. Generate a Groth16 proof via Bonsai/Boundless");
        console.log("  3. Submit on-chain via verifyAndExecute()");

        vm.stopBroadcast();
    }
}
