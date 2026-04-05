// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interfaces/IRiscZeroVerifier.sol";

/// @title MockRiscZeroVerifier
/// @notice Mock implementation of IRiscZeroVerifier for testing on networks without RISC Zero
contract MockRiscZeroVerifier is IRiscZeroVerifier {
    mapping(bytes32 => bool) public validImageIds;
    
    event VerificationCalled(bytes32 indexed imageId, bytes32 indexed journalHash);
    
    /// @notice Add a valid image ID (only for testing)
    function setValidImageId(bytes32 imageId, bool valid) external {
        validImageIds[imageId] = valid;
    }
    
    /// @notice Mock verify - always succeeds for valid image IDs
    function verify(bytes calldata seal, bytes32 imageId, bytes32 journalHash) external view {
        require(validImageIds[imageId], "Invalid image ID");
        // Mock: always succeeds for valid image IDs
    }
    
    /// @notice Mock verify with callback
    function verifyAndCall(
        bytes calldata seal,
        bytes32 imageId,
        bytes32 journalHash,
        address callbackContract,
        bytes calldata callbackData
    ) external {
        require(validImageIds[imageId], "Invalid image ID");
        emit VerificationCalled(imageId, journalHash);
        // Mock: would call callback here in real implementation
    }
}
