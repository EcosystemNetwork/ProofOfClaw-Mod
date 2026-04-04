// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ISoulVaultSwarm
/// @author Proof of Claw
/// @notice Interface for the SoulVaultSwarm coordination contract.
/// @dev Defines the external surface for a swarm of AI agents managed
///      under a shared encryption epoch model (inspired by nacmonad/soulvault).
interface ISoulVaultSwarm {
    // ──────────────────────────────────────────────
    //  Enums
    // ──────────────────────────────────────────────

    /// @notice Lifecycle status of a join request.
    enum JoinRequestStatus {
        Pending,
        Approved,
        Rejected,
        Cancelled
    }

    // ──────────────────────────────────────────────
    //  Structs
    // ──────────────────────────────────────────────

    /// @notice On-chain record of a swarm member.
    struct Member {
        bool active;
        bytes pubkey;
        uint64 joinedEpoch;
    }

    /// @notice A pending or resolved request to join the swarm.
    struct JoinRequest {
        address requester;
        bytes pubkey;
        string pubkeyRef;
        string metadataRef;
        JoinRequestStatus status;
    }

    /// @notice File-mapping metadata anchored per member per epoch.
    struct MemberFileMapping {
        string storageLocator;
        bytes32 merkleRoot;
        bytes32 publishTxHash;
        bytes32 manifestHash;
        uint64 epoch;
        uint64 updatedAt;
    }

    /// @notice Off-chain manifest pointer for an agent.
    struct AgentManifest {
        string manifestRef;
        bytes32 manifestHash;
    }

    // ──────────────────────────────────────────────
    //  Events
    // ──────────────────────────────────────────────

    event JoinRequested(bytes32 indexed requestId, address indexed requester, string pubkeyRef);
    event JoinApproved(bytes32 indexed requestId, address indexed member);
    event JoinRejected(bytes32 indexed requestId, address indexed requester);
    event JoinCancelled(bytes32 indexed requestId, address indexed requester);
    event MemberRemoved(address indexed member);
    event EpochRotated(uint64 indexed newEpoch, string keyBundleRef, bytes32 keyBundleHash);
    event MemberFileMappingUpdated(address indexed member, uint64 indexed epoch, bytes32 merkleRoot);
    event AgentMessagePosted(
        address indexed from,
        address indexed to,
        bytes32 indexed topic,
        uint64 seq,
        uint64 epoch,
        string payloadRef,
        bytes32 payloadHash,
        uint32 ttl
    );
    event AgentManifestUpdated(address indexed member, string manifestRef, bytes32 manifestHash);
    event BackupRequested(uint64 indexed epoch, string reason, string targetRef, uint64 deadline);
    event HistoricalKeyBundleGranted(
        address indexed member,
        uint64 fromEpoch,
        uint64 toEpoch,
        string bundleRef,
        bytes32 bundleHash
    );
    event RekeyRequested(address indexed requester, string trigger, uint64 membershipVersion);
    event Paused(address indexed account);
    event Unpaused(address indexed account);

    // ──────────────────────────────────────────────
    //  Membership
    // ──────────────────────────────────────────────

    /// @notice Submit a request to join the swarm.
    /// @param pubkey  The applicant's public key (raw bytes).
    /// @param pubkeyRef  Off-chain reference to the full public-key bundle.
    /// @param metadataRef  Off-chain reference to applicant metadata / proof.
    /// @return requestId  Deterministic id derived from the request parameters.
    function requestJoin(
        bytes calldata pubkey,
        string calldata pubkeyRef,
        string calldata metadataRef
    ) external returns (bytes32 requestId);

    /// @notice Approve a pending join request (owner only).
    function approveJoin(bytes32 requestId) external;

    /// @notice Reject a pending join request (owner only).
    function rejectJoin(bytes32 requestId) external;

    /// @notice Cancel your own pending join request.
    function cancelJoin(bytes32 requestId) external;

    /// @notice Remove an active member from the swarm (owner only).
    function removeMember(address member) external;

    // ──────────────────────────────────────────────
    //  Epoch & Key Management
    // ──────────────────────────────────────────────

    /// @notice Rotate to a new encryption epoch (owner only).
    /// @dev Reverts if `expectedMembershipVersion` does not match the current
    ///      `membershipVersion`, enforcing optimistic concurrency.
    function rotateEpoch(
        uint64 newEpoch,
        string calldata keyBundleRef,
        bytes32 keyBundleHash,
        uint64 expectedMembershipVersion
    ) external;

    /// @notice Grant a member access to historical key material (owner only).
    function grantHistoricalKeys(
        address member,
        string calldata bundleRef,
        bytes32 bundleHash,
        uint64 fromEpoch,
        uint64 toEpoch
    ) external;

    /// @notice Signal that a rekey is needed (public).
    function requestRekey(string calldata trigger) external;

    // ──────────────────────────────────────────────
    //  Data Anchoring
    // ──────────────────────────────────────────────

    /// @notice Update the file-mapping record for a member.
    /// @dev Callable by the member themselves or by the owner on their behalf.
    function updateMemberFileMapping(
        address member,
        string calldata storageLocator,
        bytes32 merkleRoot,
        bytes32 publishTxHash,
        bytes32 manifestHash,
        uint64 epoch
    ) external;

    /// @notice Update your own agent manifest pointer.
    function updateAgentManifest(string calldata manifestRef, bytes32 manifestHash) external;

    // ──────────────────────────────────────────────
    //  Messaging
    // ──────────────────────────────────────────────

    /// @notice Post a message to another agent in the swarm.
    /// @param to  Recipient address (address(0) for broadcast).
    /// @param topic  Application-level topic tag.
    /// @param seq  Monotonically increasing per-sender sequence number.
    /// @param epoch  Must equal `currentEpoch`.
    /// @param payloadRef  Off-chain reference to the encrypted payload.
    /// @param payloadHash  Hash of the payload for integrity verification.
    /// @param ttl  Time-to-live hint (seconds) for off-chain indexers.
    function postMessage(
        address to,
        bytes32 topic,
        uint64 seq,
        uint64 epoch,
        string calldata payloadRef,
        bytes32 payloadHash,
        uint32 ttl
    ) external;

    // ──────────────────────────────────────────────
    //  Backup
    // ──────────────────────────────────────────────

    /// @notice Request a coordinated backup of swarm state (owner only).
    function requestBackup(
        uint64 epoch,
        string calldata reason,
        string calldata targetRef,
        uint64 deadline
    ) external;

    // ──────────────────────────────────────────────
    //  Admin
    // ──────────────────────────────────────────────

    function pause() external;
    function unpause() external;

    // ──────────────────────────────────────────────
    //  Views
    // ──────────────────────────────────────────────

    function owner() external view returns (address);
    function paused() external view returns (bool);
    function currentEpoch() external view returns (uint64);
    function membershipVersion() external view returns (uint64);
    function memberCount() external view returns (uint256);
}
