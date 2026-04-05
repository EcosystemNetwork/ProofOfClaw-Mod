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
    IRiscZeroVerifier public verifier;
    bytes32 public imageId;

    /// @notice Contract owner — address that can configure integrations
    address public owner;

    /// @notice Pending owner for two-step ownership transfer
    address public pendingOwner;

    /// @notice EIP-8004 integration contract for recording validation results
    IEIP8004Integration public eip8004;

    /// @notice Reentrancy guard state (1 = not entered, 2 = entered)
    uint256 private _reentrancyStatus = 1;

    mapping(bytes32 => AgentPolicy) public agents;
    mapping(bytes32 => PendingAction) public pendingActions;
    mapping(address => bool) public allowedTargets;
    mapping(bytes32 => bool) public usedActionIds;

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
        bytes32 actionHash;
        uint256 actionValue;
        uint256 timestamp;
        bool executed;
    }

    /// @notice Maximum time (seconds) a pending action remains approvable.
    uint256 public constant ACTION_EXPIRY = 24 hours;

    /// @notice EIP-712 type hashes for on-chain signature verification.
    bytes32 public constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public constant APPROVAL_TYPEHASH =
        keccak256("ActionApproval(bytes32 agentId,bytes32 outputCommitment,uint256 actionValue)");
    bytes32 private constant DOMAIN_NAME_HASH = keccak256("ProofOfClaw");
    bytes32 private constant DOMAIN_VERSION_HASH = keccak256("1");

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
    error TargetNotAllowed();
    error ActionAlreadySubmitted();
    error ReentrancyGuard();
    error ActionExpired();
    error ActionMismatch();
    error InvalidSignature();

    event VerifierUpdated(address oldVerifier, address newVerifier);
    event ImageIdUpdated(bytes32 oldImageId, bytes32 newImageId);
    event TargetAllowlistUpdated(address target, bool allowed);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event AgentPolicyUpdated(bytes32 indexed agentId);
    event AgentDeactivated(bytes32 indexed agentId);
    event EtherReceived(address indexed sender, uint256 amount);

    modifier nonReentrant() {
        if (_reentrancyStatus == 2) revert ReentrancyGuard();
        _reentrancyStatus = 2;
        _;
        _reentrancyStatus = 1;
    }

    constructor(IRiscZeroVerifier _verifier, bytes32 _imageId) {
        verifier = _verifier;
        imageId = _imageId;
        owner = msg.sender;
    }

    /// @notice Update the RISC Zero verifier contract address
    /// @param newVerifier Address of the new IRiscZeroVerifier implementation
    function updateVerifier(address newVerifier) external {
        if (msg.sender != owner) revert Unauthorized();
        require(newVerifier != address(0), "Zero address");
        address oldVerifier = address(verifier);
        verifier = IRiscZeroVerifier(newVerifier);
        emit VerifierUpdated(oldVerifier, newVerifier);
    }

    /// @notice Update the RISC Zero guest image ID
    /// @param newImageId New guest program image ID
    function updateImageId(bytes32 newImageId) external {
        if (msg.sender != owner) revert Unauthorized();
        bytes32 oldImageId = imageId;
        imageId = newImageId;
        emit ImageIdUpdated(oldImageId, newImageId);
    }

    /// @notice Set or update the EIP-8004 integration contract address
    function setEIP8004Integration(address _eip8004) external {
        if (msg.sender != owner) revert Unauthorized();
        require(_eip8004 != address(0), "Zero address");
        eip8004 = IEIP8004Integration(_eip8004);
    }

    /// @notice Add or remove an address from the allowed execution targets
    function setAllowedTarget(address target, bool allowed) external {
        if (msg.sender != owner) revert Unauthorized();
        require(target != address(0), "Zero address");
        allowedTargets[target] = allowed;
        emit TargetAllowlistUpdated(target, allowed);
    }

    function registerAgent(
        bytes32 agentId,
        bytes32 policyHash,
        uint256 maxValueAutonomous,
        address agentWallet
    ) external {
        require(agentWallet != address(0), "Zero agent wallet");
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
    ) external nonReentrant {
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
            bytes32 requestHash = keccak256(abi.encodePacked(agentId, output.outputCommitment, block.timestamp, block.number, msg.sender));
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
            if (usedActionIds[actionId]) revert ActionAlreadySubmitted();
            usedActionIds[actionId] = true;

            pendingActions[actionId] = PendingAction({
                agentId: agentId,
                outputCommitment: output.outputCommitment,
                actionHash: keccak256(action),
                actionValue: output.actionValue,
                timestamp: block.timestamp,
                executed: false
            });

            emit ApprovalRequired(output.agentId, output.outputCommitment, output.actionValue);
        } else {
            if (msg.sender != policy.agentWallet) revert Unauthorized();
            require(output.actionValue <= policy.maxValueAutonomous, "Value exceeds autonomous limit");
            if (keccak256(action) != output.outputCommitment) revert ActionMismatch();
            _executeAction(action);
            emit ActionVerified(output.agentId, output.outputCommitment, true);
        }
    }

    function approveAction(
        bytes32 agentId,
        bytes32 outputCommitment,
        bytes calldata action,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external nonReentrant {
        AgentPolicy memory policy = agents[agentId];
        require(policy.active, "Agent deactivated");

        bytes32 actionId = keccak256(abi.encodePacked(agentId, outputCommitment));
        PendingAction storage pending = pendingActions[actionId];

        if (pending.executed || pending.timestamp == 0) revert ActionNotPending();
        if (block.timestamp > pending.timestamp + ACTION_EXPIRY) revert ActionExpired();
        if (keccak256(action) != pending.actionHash) revert ActionMismatch();

        // EIP-712 signature verification — signer must be the agent owner (Ledger address)
        bytes32 domainSeparator = keccak256(abi.encode(
            DOMAIN_TYPEHASH, DOMAIN_NAME_HASH, DOMAIN_VERSION_HASH,
            block.chainid, address(this)
        ));
        bytes32 structHash = keccak256(abi.encode(
            APPROVAL_TYPEHASH, agentId, outputCommitment, pending.actionValue
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0) || signer != policy.owner) revert InvalidSignature();

        pending.executed = true;
        _executeAction(action);

        emit ActionExecuted(agentId, outputCommitment);
    }

    function _executeAction(bytes calldata action) internal {
        (address target, uint256 value, bytes memory data) = abi.decode(
            action,
            (address, uint256, bytes)
        );

        if (!allowedTargets[target]) revert TargetNotAllowed();
        (bool success, ) = target.call{value: value}(data);
        require(success, "Action execution failed");
    }

    function deactivateAgent(bytes32 agentId) external {
        AgentPolicy storage policy = agents[agentId];
        if (msg.sender != policy.owner) revert Unauthorized();
        policy.active = false;
        emit AgentDeactivated(agentId);
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
        emit AgentPolicyUpdated(agentId);
    }

    /// @notice Withdraw ETH held by this contract (e.g. from action execution refunds)
    function withdraw(address payable to, uint256 amount) external {
        if (msg.sender != owner) revert Unauthorized();
        require(to != address(0), "Zero address");
        (bool success, ) = to.call{value: amount}("");
        require(success, "Transfer failed");
    }

    receive() external payable {
        emit EtherReceived(msg.sender, msg.value);
    }

    /// @notice Start a two-step ownership transfer
    function transferOwnership(address newOwner) external {
        if (msg.sender != owner) revert Unauthorized();
        require(newOwner != address(0), "Zero address");
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    /// @notice Accept a pending ownership transfer
    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "Not pending owner");
        emit OwnershipTransferred(owner, msg.sender);
        owner = msg.sender;
        pendingOwner = address(0);
    }
}
