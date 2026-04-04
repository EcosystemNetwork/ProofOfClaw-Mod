// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IEIP8004IdentityRegistry, IEIP8004ReputationRegistry, IEIP8004ValidationRegistry} from "./interfaces/IEIP8004.sol";

/// @title EIP-8004 Integration for Proof of Claw
/// @notice Adapter contract that bridges ProofOfClawVerifier with EIP-8004 registries
/// @dev Manages agent identity registration, reputation feedback, and validation recording
contract EIP8004Integration {
    IEIP8004IdentityRegistry public immutable identityRegistry;
    IEIP8004ReputationRegistry public immutable reputationRegistry;
    IEIP8004ValidationRegistry public immutable validationRegistry;

    /// @notice Maps internal Proof of Claw agent ID (bytes32) to EIP-8004 token ID (uint256)
    mapping(bytes32 => uint256) public agentToTokenId;

    /// @notice Maps EIP-8004 token ID back to internal agent ID
    mapping(uint256 => bytes32) public tokenIdToAgent;

    /// @notice Maps agent ID to the address that registered it
    mapping(bytes32 => address) public agentRegistrant;

    /// @notice Authorized verifier contract (ProofOfClawVerifier) that can record validations
    address public verifier;

    event AgentIdentityRegistered(bytes32 indexed agentId, uint256 indexed tokenId, string agentURI);
    event ValidationRecorded(bytes32 indexed agentId, bytes32 requestHash, uint8 response);
    event ReputationSubmitted(bytes32 indexed agentId, uint256 indexed tokenId, int128 value);

    error AgentAlreadyRegistered();
    error AgentNotRegistered();
    error OnlyVerifier();
    error OnlyAgentOwner();
    error OnlyVerifierOrRegistrant();

    constructor(
        address _identityRegistry,
        address _reputationRegistry,
        address _validationRegistry,
        address _verifier
    ) {
        identityRegistry = IEIP8004IdentityRegistry(_identityRegistry);
        reputationRegistry = IEIP8004ReputationRegistry(_reputationRegistry);
        validationRegistry = IEIP8004ValidationRegistry(_validationRegistry);
        verifier = _verifier;
    }

    /// @notice Register a Proof of Claw agent in the EIP-8004 Identity Registry
    /// @param agentId Internal Proof of Claw agent ID (bytes32)
    /// @param agentURI URI pointing to the agent's registration file (IPFS/0G Storage)
    /// @param policyHash The agent's policy fingerprint
    /// @param riscZeroImageId The RISC Zero image ID commitment
    /// @return tokenId The minted ERC-721 token ID
    function registerAgentIdentity(
        bytes32 agentId,
        string calldata agentURI,
        bytes32 policyHash,
        bytes32 riscZeroImageId
    ) external returns (uint256 tokenId) {
        if (agentToTokenId[agentId] != 0) revert AgentAlreadyRegistered();

        IEIP8004IdentityRegistry.MetadataEntry[] memory metadata =
            new IEIP8004IdentityRegistry.MetadataEntry[](2);

        metadata[0] = IEIP8004IdentityRegistry.MetadataEntry({
            metadataKey: "policyHash",
            metadataValue: abi.encodePacked(policyHash)
        });

        metadata[1] = IEIP8004IdentityRegistry.MetadataEntry({
            metadataKey: "riscZeroImageId",
            metadataValue: abi.encodePacked(riscZeroImageId)
        });

        tokenId = identityRegistry.register(agentURI, metadata);

        agentToTokenId[agentId] = tokenId;
        tokenIdToAgent[tokenId] = agentId;
        agentRegistrant[agentId] = msg.sender;

        emit AgentIdentityRegistered(agentId, tokenId, agentURI);
    }

    /// @notice Record a RISC Zero proof verification result in the Validation Registry
    /// @dev Called by the ProofOfClawVerifier after successful proof verification
    /// @param agentId Internal agent ID
    /// @param requestHash Hash of the execution trace that was proven
    /// @param passed Whether the proof verification passed
    /// @param proofReceiptURI URI where the proof receipt is stored
    /// @param responseHash Hash of the proof receipt
    function recordValidation(
        bytes32 agentId,
        bytes32 requestHash,
        bool passed,
        string calldata proofReceiptURI,
        bytes32 responseHash
    ) external {
        if (msg.sender != verifier) revert OnlyVerifier();

        uint256 tokenId = agentToTokenId[agentId];
        if (tokenId == 0) revert AgentNotRegistered();

        uint8 response = passed ? 100 : 0;

        validationRegistry.validationResponse(
            requestHash,
            response,
            proofReceiptURI,
            responseHash,
            "risc-zero-zkvm"
        );

        emit ValidationRecorded(agentId, requestHash, response);
    }

    /// @notice Submit a validation request before proving
    /// @dev Only callable by the verifier or the agent's registrant
    /// @param agentId Internal agent ID
    /// @param traceStorageURI URI of the execution trace on 0G Storage
    /// @param requestHash Hash commitment to the trace data
    function requestValidation(
        bytes32 agentId,
        string calldata traceStorageURI,
        bytes32 requestHash
    ) external {
        if (msg.sender != verifier && msg.sender != agentRegistrant[agentId])
            revert OnlyVerifierOrRegistrant();

        uint256 tokenId = agentToTokenId[agentId];
        if (tokenId == 0) revert AgentNotRegistered();

        validationRegistry.validationRequest(
            verifier,
            tokenId,
            traceStorageURI,
            requestHash
        );
    }

    /// @notice Submit reputation feedback for an agent after a proven interaction
    /// @dev Open to any caller per EIP-8004 open reputation model, but callers
    ///      must not be the agent's own registrant (no self-review). Consumers of
    ///      reputation data should filter by trusted reviewer sets.
    /// @param agentId Internal agent ID of the agent being reviewed
    /// @param value Feedback score (e.g., 0-100)
    /// @param valueDecimals Decimal precision of the value
    /// @param tag1 Primary category (e.g., "policyCompliance", "successRate")
    /// @param tag2 Secondary category (e.g., action type)
    /// @param endpoint The endpoint that was evaluated
    /// @param feedbackURI URI to off-chain feedback details
    /// @param feedbackHash Hash commitment to the feedback data
    function submitReputation(
        bytes32 agentId,
        int128 value,
        uint8 valueDecimals,
        string calldata tag1,
        string calldata tag2,
        string calldata endpoint,
        string calldata feedbackURI,
        bytes32 feedbackHash
    ) external {
        // Prevent self-review: agent registrant cannot rate their own agent
        if (msg.sender == agentRegistrant[agentId]) revert OnlyAgentOwner();

        uint256 tokenId = agentToTokenId[agentId];
        if (tokenId == 0) revert AgentNotRegistered();

        reputationRegistry.giveFeedback(
            tokenId,
            value,
            valueDecimals,
            tag1,
            tag2,
            endpoint,
            feedbackURI,
            feedbackHash
        );

        emit ReputationSubmitted(agentId, tokenId, value);
    }

    /// @notice Query an agent's reputation summary
    /// @param agentId Internal agent ID
    /// @param reviewers Filter by specific reviewer addresses
    /// @param tag1 Filter by primary tag
    /// @param tag2 Filter by secondary tag
    function getAgentReputation(
        bytes32 agentId,
        address[] calldata reviewers,
        string calldata tag1,
        string calldata tag2
    ) external view returns (uint64 count, int128 summaryValue, uint8 summaryValueDecimals) {
        uint256 tokenId = agentToTokenId[agentId];
        if (tokenId == 0) revert AgentNotRegistered();

        return reputationRegistry.getSummary(tokenId, reviewers, tag1, tag2);
    }

    /// @notice Query an agent's validation summary
    /// @param agentId Internal agent ID
    /// @param tag Filter by validation type tag
    function getAgentValidationSummary(
        bytes32 agentId,
        string calldata tag
    ) external view returns (uint64 count, uint8 averageResponse) {
        uint256 tokenId = agentToTokenId[agentId];
        if (tokenId == 0) revert AgentNotRegistered();

        address[] memory validators = new address[](1);
        validators[0] = verifier;
        return validationRegistry.getSummary(tokenId, validators, tag);
    }

    /// @notice Look up the EIP-8004 token ID for a Proof of Claw agent
    function getTokenId(bytes32 agentId) external view returns (uint256) {
        return agentToTokenId[agentId];
    }
}
