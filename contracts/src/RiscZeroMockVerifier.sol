// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./interfaces/IRiscZeroVerifier.sol";

/// @title RiscZeroMockVerifier — Testnet-only mock for RISC Zero proof verification
/// @notice Always accepts proofs. Replace with real verifier for mainnet.
/// @dev DO NOT use in production.
contract RiscZeroMockVerifier is IRiscZeroVerifier {
    /// @notice Mock verify — always succeeds (no-op).
    function verify(
        bytes calldata,
        bytes32,
        bytes32
    ) external pure override {
        // Accept all proofs on testnet
    }
}
