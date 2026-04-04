// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ProofOfClawINFT
/// @notice Intelligent NFT contract for Proof of Claw AI agents on 0G Chain
/// @dev Implements ERC-7857 standard — each agent's identity, policy, and encrypted
///      intelligence metadata are tokenized as an iNFT stored on 0G Storage.
contract ProofOfClawINFT {
    // ─── Storage ────────────────────────────────────────────────────────

    string public name = "ProofOfClaw Agent iNFT";
    string public symbol = "POCLAW";

    uint256 private _nextTokenId = 1;

    struct AgentINFT {
        address owner;
        bytes32 agentId;           // Proof of Claw internal agent ID
        bytes32 policyHash;        // SHA256 of agent policy
        bytes32 riscZeroImageId;   // RISC Zero image commitment
        string  encryptedURI;      // 0G Storage URI for encrypted agent metadata
        bytes32 metadataHash;      // keccak256 of plaintext metadata (integrity check)
        string  ensName;           // Agent's ENS subname
        uint256 reputationScore;   // Cached on-chain reputation
        uint256 totalProofs;       // Number of verified RISC Zero proofs
        uint256 mintedAt;          // Block timestamp
        bool    active;
    }

    /// @notice Token ID → Agent iNFT data
    mapping(uint256 => AgentINFT) public agents;

    /// @notice Agent ID (bytes32) → Token ID
    mapping(bytes32 => uint256) public agentToToken;

    /// @notice Token ID → Approved address
    mapping(uint256 => address) private _tokenApprovals;

    /// @notice Owner → Operator → Approved
    mapping(address => mapping(address => bool)) private _operatorApprovals;

    /// @notice Token ID → Executor → Permissions (ERC-7857 usage authorization)
    mapping(uint256 => mapping(address => bytes)) public usageAuthorizations;

    /// @notice Address authorized to record proofs (ProofOfClawVerifier)
    address public verifier;

    /// @notice Contract deployer
    address public admin;

    // ─── Events ─────────────────────────────────────────────────────────

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);
    event MetadataUpdated(uint256 indexed tokenId, bytes32 metadataHash);
    event UsageAuthorized(uint256 indexed tokenId, address indexed executor);
    event AgentMinted(
        uint256 indexed tokenId,
        bytes32 indexed agentId,
        address indexed owner,
        string ensName
    );
    event ProofRecorded(uint256 indexed tokenId, uint256 totalProofs);
    event ReputationUpdated(uint256 indexed tokenId, uint256 newScore);

    // ─── Errors ─────────────────────────────────────────────────────────

    error NotOwner();
    error NotAuthorized();
    error AgentAlreadyMinted();
    error TokenDoesNotExist();
    error ZeroAddress();
    error OnlyVerifier();
    error OnlyAdmin();

    // ─── Constructor ────────────────────────────────────────────────────

    constructor(address _verifier) {
        verifier = _verifier;
        admin = msg.sender;
    }

    // ─── Minting ────────────────────────────────────────────────────────

    /// @notice Mint an iNFT for a Proof of Claw agent
    /// @param agentId Internal agent identifier (keccak256 of AGENT_ID string)
    /// @param policyHash SHA256 hash of the agent's policy
    /// @param riscZeroImageId RISC Zero guest image ID commitment
    /// @param encryptedURI 0G Storage URI containing encrypted agent metadata
    /// @param metadataHash keccak256 of the plaintext metadata for integrity
    /// @param ensName Agent's ENS subname (e.g., "alice.proofofclaw.eth")
    /// @return tokenId The minted token ID
    function mint(
        bytes32 agentId,
        bytes32 policyHash,
        bytes32 riscZeroImageId,
        string calldata encryptedURI,
        bytes32 metadataHash,
        string calldata ensName
    ) external returns (uint256 tokenId) {
        if (agentToToken[agentId] != 0) revert AgentAlreadyMinted();

        tokenId = _nextTokenId++;

        agents[tokenId] = AgentINFT({
            owner: msg.sender,
            agentId: agentId,
            policyHash: policyHash,
            riscZeroImageId: riscZeroImageId,
            encryptedURI: encryptedURI,
            metadataHash: metadataHash,
            ensName: ensName,
            reputationScore: 0,
            totalProofs: 0,
            mintedAt: block.timestamp,
            active: true
        });

        agentToToken[agentId] = tokenId;

        emit Transfer(address(0), msg.sender, tokenId);
        emit AgentMinted(tokenId, agentId, msg.sender, ensName);
    }

    // ─── ERC-7857: Encrypted Metadata Management ────────────────────────

    /// @notice Update the encrypted metadata URI on 0G Storage
    /// @dev Called when agent intelligence evolves (new model, updated config)
    function updateMetadata(
        uint256 tokenId,
        string calldata newEncryptedURI,
        bytes32 newMetadataHash
    ) external {
        AgentINFT storage agent = agents[tokenId];
        if (agent.owner != msg.sender) revert NotOwner();

        agent.encryptedURI = newEncryptedURI;
        agent.metadataHash = newMetadataHash;

        emit MetadataUpdated(tokenId, newMetadataHash);
    }

    /// @notice Authorize another address to use this agent (inference, delegation)
    /// @dev ERC-7857 usage authorization — grants executor rights without ownership
    function authorizeUsage(
        uint256 tokenId,
        address executor,
        bytes calldata permissions
    ) external {
        AgentINFT storage agent = agents[tokenId];
        if (agent.owner != msg.sender) revert NotOwner();
        if (executor == address(0)) revert ZeroAddress();

        usageAuthorizations[tokenId][executor] = permissions;

        emit UsageAuthorized(tokenId, executor);
    }

    /// @notice Revoke usage authorization
    function revokeUsage(uint256 tokenId, address executor) external {
        AgentINFT storage agent = agents[tokenId];
        if (agent.owner != msg.sender) revert NotOwner();

        delete usageAuthorizations[tokenId][executor];
    }

    /// @notice Check if an address is authorized to use an agent
    function isAuthorized(uint256 tokenId, address executor) external view returns (bool) {
        return usageAuthorizations[tokenId][executor].length > 0;
    }

    // ─── Proof & Reputation Tracking ────────────────────────────────────

    /// @notice Record a successful RISC Zero proof verification for this agent
    /// @dev Only callable by the ProofOfClawVerifier contract
    function recordProof(uint256 tokenId) external {
        if (msg.sender != verifier) revert OnlyVerifier();

        AgentINFT storage agent = agents[tokenId];
        agent.totalProofs++;

        emit ProofRecorded(tokenId, agent.totalProofs);
    }

    /// @notice Update cached reputation score
    /// @dev Called by verifier or admin after aggregating off-chain reputation data
    function updateReputation(uint256 tokenId, uint256 newScore) external {
        if (msg.sender != verifier && msg.sender != admin) revert NotAuthorized();

        agents[tokenId].reputationScore = newScore;

        emit ReputationUpdated(tokenId, newScore);
    }

    // ─── Policy Management ──────────────────────────────────────────────

    /// @notice Update agent's policy hash (after policy change)
    function updatePolicy(uint256 tokenId, bytes32 newPolicyHash) external {
        AgentINFT storage agent = agents[tokenId];
        if (agent.owner != msg.sender) revert NotOwner();

        agent.policyHash = newPolicyHash;
    }

    /// @notice Deactivate an agent iNFT
    function deactivate(uint256 tokenId) external {
        AgentINFT storage agent = agents[tokenId];
        if (agent.owner != msg.sender) revert NotOwner();

        agent.active = false;
    }

    // ─── View Functions ─────────────────────────────────────────────────

    /// @notice Get token ID for a Proof of Claw agent
    function getTokenByAgent(bytes32 agentId) external view returns (uint256) {
        return agentToToken[agentId];
    }

    /// @notice Get full agent data
    function getAgent(uint256 tokenId) external view returns (AgentINFT memory) {
        return agents[tokenId];
    }

    /// @notice Get the encrypted metadata URI (0G Storage location)
    function tokenURI(uint256 tokenId) external view returns (string memory) {
        if (agents[tokenId].owner == address(0)) revert TokenDoesNotExist();
        return agents[tokenId].encryptedURI;
    }

    /// @notice Total minted iNFTs
    function totalSupply() external view returns (uint256) {
        return _nextTokenId - 1;
    }

    // ─── ERC-721 Core ───────────────────────────────────────────────────

    function balanceOf(address owner) external view returns (uint256 count) {
        if (owner == address(0)) revert ZeroAddress();
        for (uint256 i = 1; i < _nextTokenId; i++) {
            if (agents[i].owner == owner) count++;
        }
    }

    function ownerOf(uint256 tokenId) external view returns (address) {
        address owner = agents[tokenId].owner;
        if (owner == address(0)) revert TokenDoesNotExist();
        return owner;
    }

    function approve(address to, uint256 tokenId) external {
        address owner = agents[tokenId].owner;
        if (msg.sender != owner && !_operatorApprovals[owner][msg.sender]) revert NotAuthorized();

        _tokenApprovals[tokenId] = to;
        emit Approval(owner, to, tokenId);
    }

    function getApproved(uint256 tokenId) external view returns (address) {
        return _tokenApprovals[tokenId];
    }

    function setApprovalForAll(address operator, bool approved) external {
        _operatorApprovals[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    function isApprovedForAll(address owner, address operator) external view returns (bool) {
        return _operatorApprovals[owner][operator];
    }

    function transferFrom(address from, address to, uint256 tokenId) external {
        _transfer(from, to, tokenId);
    }

    function safeTransferFrom(address from, address to, uint256 tokenId) external {
        _transfer(from, to, tokenId);
    }

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes calldata) external {
        _transfer(from, to, tokenId);
    }

    function _transfer(address from, address to, uint256 tokenId) internal {
        AgentINFT storage agent = agents[tokenId];
        if (agent.owner != from) revert NotOwner();
        if (to == address(0)) revert ZeroAddress();

        bool authorized = msg.sender == from
            || _tokenApprovals[tokenId] == msg.sender
            || _operatorApprovals[from][msg.sender];
        if (!authorized) revert NotAuthorized();

        agent.owner = to;
        delete _tokenApprovals[tokenId];

        emit Transfer(from, to, tokenId);
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == 0x80ac58cd  // ERC-721
            || interfaceId == 0x01ffc9a7  // ERC-165
            || interfaceId == 0x5b5e139f; // ERC-721Metadata
    }

    // ─── Admin ──────────────────────────────────────────────────────────

    function setVerifier(address _verifier) external {
        if (msg.sender != admin) revert OnlyAdmin();
        verifier = _verifier;
    }
}
