// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISoulVaultSwarm} from "./interfaces/ISoulVaultSwarm.sol";

/// @title SoulVaultSwarm
/// @author Proof of Claw
/// @notice Core coordination contract for a swarm of AI agents.
/// @dev Implements epoch-based key rotation with optimistic concurrency,
///      gated membership, agent-to-agent messaging, and data anchoring.
///      Modeled after nacmonad/soulvault, extended for Proof of Claw.
contract SoulVaultSwarm is ISoulVaultSwarm {
    // ──────────────────────────────────────────────
    //  State
    // ──────────────────────────────────────────────

    /// @inheritdoc ISoulVaultSwarm
    address public immutable override owner;

    /// @inheritdoc ISoulVaultSwarm
    bool public override paused;

    /// @inheritdoc ISoulVaultSwarm
    uint64 public override currentEpoch;

    /// @notice Monotonically increasing version bumped on every membership change.
    /// @dev Used for optimistic concurrency control during epoch rotation / rekey.
    uint64 public override membershipVersion;

    /// @inheritdoc ISoulVaultSwarm
    uint256 public override memberCount;

    /// @dev Active member records keyed by address.
    mapping(address => Member) private _members;

    /// @dev Join-request records keyed by deterministic request id.
    mapping(bytes32 => JoinRequest) private _joinRequests;

    /// @dev Per-member file-mapping metadata.
    mapping(address => MemberFileMapping) private _memberFileMappings;

    /// @dev Per-member agent manifest pointers.
    mapping(address => AgentManifest) private _agentManifests;

    /// @dev Per-sender monotonic message sequence counter.
    mapping(address => uint64) private _lastSenderSeq;

    // ──────────────────────────────────────────────
    //  Errors
    // ──────────────────────────────────────────────

    error Unauthorized();
    error ContractPaused();
    error ContractNotPaused();
    error EmptyPubkey();
    error RequestAlreadyExists(bytes32 requestId);
    error RequestNotPending(bytes32 requestId);
    error NotRequester(bytes32 requestId);
    error MemberAlreadyActive(address member);
    error MemberNotActive(address member);
    error MembershipVersionMismatch(uint64 expected, uint64 actual);
    error EpochMustIncrease(uint64 current, uint64 proposed);
    error InvalidEpochRange(uint64 from, uint64 to);
    error InvalidSequence(uint64 expected, uint64 provided);
    error EpochMismatch(uint64 current, uint64 provided);
    error ZeroAddress();

    // ──────────────────────────────────────────────
    //  Modifiers
    // ──────────────────────────────────────────────

    /// @dev Restricts to the contract deployer.
    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    /// @dev Restricts to addresses with active membership.
    modifier onlyActiveMember() {
        if (!_members[msg.sender].active) revert MemberNotActive(msg.sender);
        _;
    }

    /// @dev Prevents execution while the contract is paused.
    modifier whenNotPaused() {
        if (paused) revert ContractPaused();
        _;
    }

    // ──────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────

    /// @notice Deploys the swarm contract. The deployer becomes the permanent owner.
    constructor() {
        owner = msg.sender;
    }

    // ──────────────────────────────────────────────
    //  Membership
    // ──────────────────────────────────────────────

    /// @inheritdoc ISoulVaultSwarm
    function requestJoin(
        bytes calldata pubkey,
        string calldata pubkeyRef,
        string calldata metadataRef
    ) external whenNotPaused returns (bytes32 requestId) {
        if (pubkey.length == 0) revert EmptyPubkey();
        if (_members[msg.sender].active) revert MemberAlreadyActive(msg.sender);

        requestId = keccak256(abi.encodePacked(msg.sender, pubkey, pubkeyRef, metadataRef));

        JoinRequest storage req = _joinRequests[requestId];
        if (req.requester != address(0)) revert RequestAlreadyExists(requestId);

        req.requester = msg.sender;
        req.pubkey = pubkey;
        req.pubkeyRef = pubkeyRef;
        req.metadataRef = metadataRef;
        req.status = JoinRequestStatus.Pending;

        emit JoinRequested(requestId, msg.sender, pubkeyRef);
    }

    /// @inheritdoc ISoulVaultSwarm
    function approveJoin(bytes32 requestId) external onlyOwner whenNotPaused {
        JoinRequest storage req = _joinRequests[requestId];
        if (req.status != JoinRequestStatus.Pending) revert RequestNotPending(requestId);
        if (_members[req.requester].active) revert MemberAlreadyActive(req.requester);

        req.status = JoinRequestStatus.Approved;

        Member storage m = _members[req.requester];
        m.active = true;
        m.pubkey = req.pubkey;
        m.joinedEpoch = currentEpoch;

        unchecked {
            ++memberCount;
            ++membershipVersion;
        }

        emit JoinApproved(requestId, req.requester);
    }

    /// @inheritdoc ISoulVaultSwarm
    function rejectJoin(bytes32 requestId) external onlyOwner whenNotPaused {
        JoinRequest storage req = _joinRequests[requestId];
        if (req.status != JoinRequestStatus.Pending) revert RequestNotPending(requestId);

        req.status = JoinRequestStatus.Rejected;

        emit JoinRejected(requestId, req.requester);
    }

    /// @inheritdoc ISoulVaultSwarm
    function cancelJoin(bytes32 requestId) external whenNotPaused {
        JoinRequest storage req = _joinRequests[requestId];
        if (req.requester != msg.sender) revert NotRequester(requestId);
        if (req.status != JoinRequestStatus.Pending) revert RequestNotPending(requestId);

        req.status = JoinRequestStatus.Cancelled;

        emit JoinCancelled(requestId, req.requester);
    }

    /// @inheritdoc ISoulVaultSwarm
    function removeMember(address member) external onlyOwner whenNotPaused {
        if (member == address(0)) revert ZeroAddress();
        if (!_members[member].active) revert MemberNotActive(member);

        _members[member].active = false;

        unchecked {
            --memberCount;
            ++membershipVersion;
        }

        emit MemberRemoved(member);
    }

    // ──────────────────────────────────────────────
    //  Epoch & Key Management
    // ──────────────────────────────────────────────

    /// @inheritdoc ISoulVaultSwarm
    function rotateEpoch(
        uint64 newEpoch,
        string calldata keyBundleRef,
        bytes32 keyBundleHash,
        uint64 expectedMembershipVersion
    ) external onlyOwner whenNotPaused {
        if (expectedMembershipVersion != membershipVersion) {
            revert MembershipVersionMismatch(expectedMembershipVersion, membershipVersion);
        }
        if (newEpoch <= currentEpoch) {
            revert EpochMustIncrease(currentEpoch, newEpoch);
        }

        currentEpoch = newEpoch;

        emit EpochRotated(newEpoch, keyBundleRef, keyBundleHash);
    }

    /// @inheritdoc ISoulVaultSwarm
    function grantHistoricalKeys(
        address member,
        string calldata bundleRef,
        bytes32 bundleHash,
        uint64 fromEpoch,
        uint64 toEpoch
    ) external onlyOwner whenNotPaused {
        if (member == address(0)) revert ZeroAddress();
        if (!_members[member].active) revert MemberNotActive(member);
        if (fromEpoch > toEpoch) revert InvalidEpochRange(fromEpoch, toEpoch);

        emit HistoricalKeyBundleGranted(member, fromEpoch, toEpoch, bundleRef, bundleHash);
    }

    /// @inheritdoc ISoulVaultSwarm
    function requestRekey(string calldata trigger) external whenNotPaused {
        emit RekeyRequested(msg.sender, trigger, membershipVersion);
    }

    // ──────────────────────────────────────────────
    //  Data Anchoring
    // ──────────────────────────────────────────────

    /// @inheritdoc ISoulVaultSwarm
    function updateMemberFileMapping(
        address member,
        string calldata storageLocator,
        bytes32 merkleRoot,
        bytes32 publishTxHash,
        bytes32 manifestHash,
        uint64 epoch
    ) external whenNotPaused {
        if (member == address(0)) revert ZeroAddress();
        // Caller must be the member themselves or the owner.
        if (msg.sender != member && msg.sender != owner) revert Unauthorized();
        if (!_members[member].active) revert MemberNotActive(member);

        MemberFileMapping storage fm = _memberFileMappings[member];
        fm.storageLocator = storageLocator;
        fm.merkleRoot = merkleRoot;
        fm.publishTxHash = publishTxHash;
        fm.manifestHash = manifestHash;
        fm.epoch = epoch;
        fm.updatedAt = uint64(block.timestamp);

        emit MemberFileMappingUpdated(member, epoch, merkleRoot);
    }

    /// @inheritdoc ISoulVaultSwarm
    function updateAgentManifest(
        string calldata manifestRef,
        bytes32 manifestHash
    ) external onlyActiveMember whenNotPaused {
        _agentManifests[msg.sender] = AgentManifest({
            manifestRef: manifestRef,
            manifestHash: manifestHash
        });

        emit AgentManifestUpdated(msg.sender, manifestRef, manifestHash);
    }

    // ──────────────────────────────────────────────
    //  Messaging
    // ──────────────────────────────────────────────

    /// @inheritdoc ISoulVaultSwarm
    function postMessage(
        address to,
        bytes32 topic,
        uint64 seq,
        uint64 epoch,
        string calldata payloadRef,
        bytes32 payloadHash,
        uint32 ttl
    ) external onlyActiveMember whenNotPaused {
        if (epoch != currentEpoch) revert EpochMismatch(currentEpoch, epoch);
        if (seq <= _lastSenderSeq[msg.sender]) {
            revert InvalidSequence(_lastSenderSeq[msg.sender] + 1, seq);
        }

        _lastSenderSeq[msg.sender] = seq;

        emit AgentMessagePosted(msg.sender, to, topic, seq, epoch, payloadRef, payloadHash, ttl);
    }

    // ──────────────────────────────────────────────
    //  Backup
    // ──────────────────────────────────────────────

    /// @inheritdoc ISoulVaultSwarm
    function requestBackup(
        uint64 epoch,
        string calldata reason,
        string calldata targetRef,
        uint64 deadline
    ) external onlyOwner whenNotPaused {
        emit BackupRequested(epoch, reason, targetRef, deadline);
    }

    // ──────────────────────────────────────────────
    //  Admin
    // ──────────────────────────────────────────────

    /// @inheritdoc ISoulVaultSwarm
    function pause() external onlyOwner {
        if (paused) revert ContractPaused();
        paused = true;
        emit Paused(msg.sender);
    }

    /// @inheritdoc ISoulVaultSwarm
    function unpause() external onlyOwner {
        if (!paused) revert ContractNotPaused();
        paused = false;
        emit Unpaused(msg.sender);
    }

    // ──────────────────────────────────────────────
    //  View Helpers
    // ──────────────────────────────────────────────

    /// @notice Returns the full member record for `account`.
    function getMember(address account) external view returns (Member memory) {
        return _members[account];
    }

    /// @notice Returns a join request by its deterministic id.
    function getJoinRequest(bytes32 requestId) external view returns (JoinRequest memory) {
        return _joinRequests[requestId];
    }

    /// @notice Returns the file-mapping record for `member`.
    function getMemberFileMapping(address member) external view returns (MemberFileMapping memory) {
        return _memberFileMappings[member];
    }

    /// @notice Returns the agent manifest pointer for `member`.
    function getAgentManifest(address member) external view returns (AgentManifest memory) {
        return _agentManifests[member];
    }

    /// @notice Returns the last sequence number used by `sender`.
    function getLastSenderSeq(address sender) external view returns (uint64) {
        return _lastSenderSeq[sender];
    }
}
