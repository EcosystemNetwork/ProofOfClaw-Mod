// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IRiscZeroVerifier} from "./interfaces/IRiscZeroVerifier.sol";

interface IEIP8004Integration {
    function recordValidation(
        bytes32 agentId,
        bytes32 requestHash,
        bool passed,
        string calldata proofReceiptURI,
        bytes32 responseHash
    ) external;
}

contract ProofOfClawVerifier {
    IRiscZeroVerifier public immutable verifier;
    bytes32 public immutable imageId;

    /// @notice Contract deployer — only address that can configure integrations
    address public immutable owner;

    /// @notice EIP-8004 integration contract for recording validation results
    IEIP8004Integration public eip8004;

    mapping(bytes32 => AgentPolicy) public agents;
    mapping(bytes32 => PendingAction) public pendingActions;

    struct AgentPolicy {
        bytes32 policyHash;
        uint256 maxValueAutonomous;
        address owner;
        address agentWallet;
        bool active;
    }

    struct PendingAction {
        bytes32 agentId;
        bytes32 outputCommitment;
        uint256 actionValue;
        uint256 timestamp;
        bool executed;
    }

    struct VerifiedOutput {
        string agentId;
        bytes32 policyHash;
        bytes32 outputCommitment;
        bool allChecksPassed;
        bool requiresLedgerApproval;
        uint256 actionValue;
    }

    event AgentRegistered(bytes32 indexed agentId, address owner, address agentWallet);
    event ActionVerified(string agentId, bytes32 outputCommitment, bool autonomous);
    event ApprovalRequired(string agentId, bytes32 outputCommitment, uint256 value);
    event ActionExecuted(bytes32 indexed agentId, bytes32 outputCommitment);

    error InvalidProof();
    error PolicyMismatch();
    error PolicyChecksFailed();
    error Unauthorized();
    error ActionNotPending();
    error AgentNotActive();
    error AgentAlreadyExists();

    constructor(IRiscZeroVerifier _verifier, bytes32 _imageId) {
        verifier = _verifier;
        imageId = _imageId;
        owner = msg.sender;
    }

    /// @notice Set the EIP-8004 integration contract address
    /// @dev Called once after deployment. Only callable by owner when not yet set.
    function setEIP8004Integration(address _eip8004) external {
        if (msg.sender != owner) revert Unauthorized();
        require(address(eip8004) == address(0), "Already set");
        eip8004 = IEIP8004Integration(_eip8004);
    }

    function registerAgent(
        bytes32 agentId,
        bytes32 policyHash,
        uint256 maxValueAutonomous,
        address agentWallet
    ) external {
        AgentPolicy storage existing = agents[agentId];
        if (existing.active) revert AgentAlreadyExists();
        // Allow re-registration only by the original owner (for reactivation)
        if (existing.owner != address(0) && existing.owner != msg.sender) revert Unauthorized();

        agents[agentId] = AgentPolicy({
            policyHash: policyHash,
            maxValueAutonomous: maxValueAutonomous,
            owner: msg.sender,
            agentWallet: agentWallet,
            active: true
        });

        emit AgentRegistered(agentId, msg.sender, agentWallet);
    }

    function verifyAndExecute(
        bytes calldata seal,
        bytes calldata journalData,
        bytes calldata action
    ) external {
        bytes32 journalHash = sha256(journalData);
        verifier.verify(seal, imageId, journalHash);

        VerifiedOutput memory output = abi.decode(journalData, (VerifiedOutput));

        bytes32 agentId = keccak256(bytes(output.agentId));
        AgentPolicy memory policy = agents[agentId];

        if (!policy.active) revert AgentNotActive();
        if (policy.policyHash != output.policyHash) revert PolicyMismatch();
        if (!output.allChecksPassed) revert PolicyChecksFailed();

        // Record successful verification in EIP-8004 Validation Registry
        if (address(eip8004) != address(0)) {
            bytes32 requestHash = keccak256(abi.encodePacked(agentId, output.outputCommitment, block.timestamp));
            try eip8004.recordValidation(
                agentId,
                requestHash,
                true,
                "", // proofReceiptURI populated off-chain
                journalHash
            ) {} catch {
                // Non-critical: validation recording failure should not block execution
            }
        }

        if (output.requiresLedgerApproval) {
            bytes32 actionId = keccak256(abi.encodePacked(agentId, output.outputCommitment));
            pendingActions[actionId] = PendingAction({
                agentId: agentId,
                outputCommitment: output.outputCommitment,
                actionValue: output.actionValue,
                timestamp: block.timestamp,
                executed: false
            });

            emit ApprovalRequired(output.agentId, output.outputCommitment, output.actionValue);
        } else {
            if (msg.sender != policy.agentWallet) revert Unauthorized();
            _executeAction(action);
            emit ActionVerified(output.agentId, output.outputCommitment, true);
        }
    }

    function approveAction(
        bytes32 agentId,
        bytes32 outputCommitment,
        bytes calldata action
    ) external {
        AgentPolicy memory policy = agents[agentId];
        if (msg.sender != policy.owner) revert Unauthorized();

        bytes32 actionId = keccak256(abi.encodePacked(agentId, outputCommitment));
        PendingAction storage pending = pendingActions[actionId];

        if (pending.executed || pending.timestamp == 0) revert ActionNotPending();

        pending.executed = true;
        _executeAction(action);

        emit ActionExecuted(agentId, outputCommitment);
    }

    function _executeAction(bytes calldata action) internal {
        (address target, uint256 value, bytes memory data) = abi.decode(
            action,
            (address, uint256, bytes)
        );

        (bool success, ) = target.call{value: value}(data);
        require(success, "Action execution failed");
    }

    function deactivateAgent(bytes32 agentId) external {
        AgentPolicy storage policy = agents[agentId];
        if (msg.sender != policy.owner) revert Unauthorized();
        policy.active = false;
    }

    function updateAgentPolicy(
        bytes32 agentId,
        bytes32 newPolicyHash,
        uint256 newMaxValueAutonomous
    ) external {
        AgentPolicy storage policy = agents[agentId];
        if (msg.sender != policy.owner) revert Unauthorized();

        policy.policyHash = newPolicyHash;
        policy.maxValueAutonomous = newMaxValueAutonomous;
    }

    receive() external payable {}
}
