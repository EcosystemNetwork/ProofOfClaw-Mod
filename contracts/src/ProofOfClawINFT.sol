// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC721Receiver {
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data) external returns (bytes4);
}

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
        bytes32 soulBackupHash;    // keccak256 of OCMB v0.1 soul backup YAML — required for continuity
        string  soulBackupURI;     // 0G Storage URI for encrypted soul backup
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

    /// @notice ENS name hash → Token ID (prevents duplicate ENS claims)
    mapping(bytes32 => uint256) public ensNameToToken;

    /// @notice Token ID → Approved address
    mapping(uint256 => address) private _tokenApprovals;

    /// @notice Owner → Operator → Approved
    mapping(address => mapping(address => bool)) private _operatorApprovals;

    /// @notice Owner → token count (O(1) balanceOf)
    mapping(address => uint256) private _balances;

    /// @notice Owner → ordered list of owned token IDs (enumeration support)
    mapping(address => uint256[]) private _ownedTokens;

    /// @notice Token ID → index in the owner's _ownedTokens array
    mapping(uint256 => uint256) private _ownedTokensIndex;

    /// @notice Token ID → Executor → Permissions (ERC-7857 usage authorization)
    mapping(uint256 => mapping(address => bytes)) public usageAuthorizations;

    /// @notice Address authorized to record proofs (ProofOfClawVerifier)
    address public verifier;

    /// @notice Contract deployer
    address public admin;

    /// @notice Pending admin for two-step transfer
    address public pendingAdmin;

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
    event SoulBackupRecorded(uint256 indexed tokenId, bytes32 soulBackupHash, string soulBackupURI);
    event SoulBackupUpdated(uint256 indexed tokenId, bytes32 newSoulBackupHash, string newSoulBackupURI);
    event ProofRecorded(uint256 indexed tokenId, uint256 totalProofs);
    event ReputationUpdated(uint256 indexed tokenId, uint256 newScore);
    event PolicyUpdated(uint256 indexed tokenId);
    event AgentDeactivated(uint256 indexed tokenId);
    event AdminTransferStarted(address indexed previousAdmin, address indexed newAdmin);
    event AdminTransferred(address indexed previousAdmin, address indexed newAdmin);

    // ─── Errors ─────────────────────────────────────────────────────────

    error NotOwner();
    error NotAuthorized();
    error AgentAlreadyMinted();
    error TokenDoesNotExist();
    error ZeroAddress();
    error OnlyVerifier();
    error OnlyAdmin();
    error TransferToNonReceiver();
    error SoulBackupRequired();
    error ENSNameAlreadyClaimed();
    error ENSNameEmpty();

    // ─── Constructor ────────────────────────────────────────────────────

    constructor(address _verifier) {
        verifier = _verifier;
        admin = msg.sender;
    }

    // ─── Minting ────────────────────────────────────────────────────────

    /// @notice Mint an iNFT for a Proof of Claw agent (mints to msg.sender)
    /// @param agentId Internal agent identifier (keccak256 of AGENT_ID string)
    /// @param policyHash SHA256 hash of the agent's policy
    /// @param riscZeroImageId RISC Zero guest image ID commitment
    /// @param encryptedURI 0G Storage URI containing encrypted agent metadata
    /// @param metadataHash keccak256 of the plaintext metadata for integrity
    /// @param soulBackupHash keccak256 of the OCMB v0.1 soul backup YAML
    /// @param soulBackupURI 0G Storage URI for encrypted soul backup
    /// @param ensName Agent's ENS subname (e.g., "alice.proofofclaw.eth")
    /// @return tokenId The minted token ID
    function mint(
        bytes32 agentId,
        bytes32 policyHash,
        bytes32 riscZeroImageId,
        string calldata encryptedURI,
        bytes32 metadataHash,
        bytes32 soulBackupHash,
        string calldata soulBackupURI,
        string calldata ensName
    ) external returns (uint256 tokenId) {
        return _mintTo(msg.sender, agentId, policyHash, riscZeroImageId, encryptedURI, metadataHash, soulBackupHash, soulBackupURI, ensName);
    }

    /// @notice Mint an iNFT directly into an agent's dedicated wallet
    /// @dev The caller (org/user wallet) pays gas, but the iNFT lands in the agent's wallet.
    ///      This ensures the agent wallet holds the ENS credential NFT from the start.
    /// @param to The agent's dedicated wallet address that will own this iNFT
    function mintTo(
        address to,
        bytes32 agentId,
        bytes32 policyHash,
        bytes32 riscZeroImageId,
        string calldata encryptedURI,
        bytes32 metadataHash,
        bytes32 soulBackupHash,
        string calldata soulBackupURI,
        string calldata ensName
    ) external returns (uint256 tokenId) {
        if (to == address(0)) revert ZeroAddress();
        return _mintTo(to, agentId, policyHash, riscZeroImageId, encryptedURI, metadataHash, soulBackupHash, soulBackupURI, ensName);
    }

    /// @dev Internal mint logic — shared by mint() and mintTo()
    function _mintTo(
        address to,
        bytes32 agentId,
        bytes32 policyHash,
        bytes32 riscZeroImageId,
        string calldata encryptedURI,
        bytes32 metadataHash,
        bytes32 soulBackupHash,
        string calldata soulBackupURI,
        string calldata ensName
    ) internal returns (uint256 tokenId) {
        if (agentToToken[agentId] != 0) revert AgentAlreadyMinted();
        if (soulBackupHash == bytes32(0)) revert SoulBackupRequired();
        if (bytes(ensName).length == 0) revert ENSNameEmpty();

        bytes32 ensHash = keccak256(bytes(ensName));
        if (ensNameToToken[ensHash] != 0) revert ENSNameAlreadyClaimed();

        tokenId = _nextTokenId++;

        agents[tokenId] = AgentINFT({
            owner: to,
            agentId: agentId,
            policyHash: policyHash,
            riscZeroImageId: riscZeroImageId,
            encryptedURI: encryptedURI,
            metadataHash: metadataHash,
            soulBackupHash: soulBackupHash,
            soulBackupURI: soulBackupURI,
            ensName: ensName,
            reputationScore: 0,
            totalProofs: 0,
            mintedAt: block.timestamp,
            active: true
        });

        agentToToken[agentId] = tokenId;
        ensNameToToken[ensHash] = tokenId;
        _balances[to]++;
        _ownedTokens[to].push(tokenId);
        _ownedTokensIndex[tokenId] = _ownedTokens[to].length - 1;

        emit Transfer(address(0), to, tokenId);
        emit AgentMinted(tokenId, agentId, to, ensName);
        emit SoulBackupRecorded(tokenId, soulBackupHash, soulBackupURI);

        _checkOnERC721Received(address(0), to, tokenId, "");
    }

    // ─── Soul Backup Management ─────────────────────────────────────────

    /// @notice Update an agent's soul backup after identity evolution or reassembly
    /// @dev The soul backup is the agent's continuity anchor — OCMB v0.1 format
    function updateSoulBackup(
        uint256 tokenId,
        bytes32 newSoulBackupHash,
        string calldata newSoulBackupURI
    ) external {
        AgentINFT storage agent = agents[tokenId];
        if (agent.owner != msg.sender) revert NotOwner();
        if (newSoulBackupHash == bytes32(0)) revert SoulBackupRequired();

        agent.soulBackupHash = newSoulBackupHash;
        agent.soulBackupURI = newSoulBackupURI;

        emit SoulBackupUpdated(tokenId, newSoulBackupHash, newSoulBackupURI);
    }

    /// @notice Get the soul backup data for an agent (used during reassembly)
    function getSoulBackup(uint256 tokenId) external view returns (bytes32 backupHash, string memory backupURI) {
        if (agents[tokenId].owner == address(0)) revert TokenDoesNotExist();
        return (agents[tokenId].soulBackupHash, agents[tokenId].soulBackupURI);
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
        if (agent.owner == address(0)) revert TokenDoesNotExist();
        agent.totalProofs++;

        emit ProofRecorded(tokenId, agent.totalProofs);
    }

    /// @notice Update cached reputation score
    /// @dev Called by verifier or admin after aggregating off-chain reputation data
    function updateReputation(uint256 tokenId, uint256 newScore) external {
        if (msg.sender != verifier && msg.sender != admin) revert NotAuthorized();
        if (agents[tokenId].owner == address(0)) revert TokenDoesNotExist();

        agents[tokenId].reputationScore = newScore;

        emit ReputationUpdated(tokenId, newScore);
    }

    // ─── Policy Management ──────────────────────────────────────────────

    /// @notice Update agent's policy hash (after policy change)
    function updatePolicy(uint256 tokenId, bytes32 newPolicyHash) external {
        AgentINFT storage agent = agents[tokenId];
        if (agent.owner != msg.sender) revert NotOwner();

        agent.policyHash = newPolicyHash;

        emit PolicyUpdated(tokenId);
    }

    /// @notice Deactivate an agent iNFT
    function deactivate(uint256 tokenId) external {
        AgentINFT storage agent = agents[tokenId];
        if (agent.owner != msg.sender) revert NotOwner();

        agent.active = false;

        emit AgentDeactivated(tokenId);
    }

    // ─── Burn ───────────────────────────────────────────────────────────

    /// @notice Permanently destroy an iNFT, freeing its agentId and ensName for re-registration
    /// @param tokenId The token to burn — caller must be the owner
    function burn(uint256 tokenId) external {
        AgentINFT storage agent = agents[tokenId];
        if (agent.owner != msg.sender) revert NotOwner();

        // Clear mappings
        delete agentToToken[agent.agentId];
        if (bytes(agent.ensName).length > 0) {
            bytes32 ensHash = keccak256(bytes(agent.ensName));
            delete ensNameToToken[ensHash];
        }

        // Clear enumeration
        _removeTokenFromOwner(msg.sender, tokenId);

        // Clear approvals
        delete _tokenApprovals[tokenId];

        // Update balance
        _balances[msg.sender]--;

        // Clear agent data
        delete agents[tokenId];

        emit Transfer(msg.sender, address(0), tokenId);
    }

    // ─── View Functions ─────────────────────────────────────────────────

    /// @notice Get token ID for a Proof of Claw agent
    function getTokenByAgent(bytes32 agentId) external view returns (uint256) {
        return agentToToken[agentId];
    }

    /// @notice Get token ID for an ENS name
    function getTokenByENS(string calldata ensName) external view returns (uint256) {
        return ensNameToToken[keccak256(bytes(ensName))];
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

    function balanceOf(address owner) external view returns (uint256) {
        if (owner == address(0)) revert ZeroAddress();
        return _balances[owner];
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
        _checkOnERC721Received(from, to, tokenId, "");
    }

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes calldata data) external {
        _transfer(from, to, tokenId);
        _checkOnERC721Received(from, to, tokenId, data);
    }

    function _transfer(address from, address to, uint256 tokenId) internal {
        AgentINFT storage agent = agents[tokenId];
        if (agent.owner != from) revert NotOwner();
        if (to == address(0)) revert ZeroAddress();

        bool authorized = msg.sender == from
            || _tokenApprovals[tokenId] == msg.sender
            || _operatorApprovals[from][msg.sender];
        if (!authorized) revert NotAuthorized();

        _balances[from]--;
        _balances[to]++;
        agent.owner = to;
        delete _tokenApprovals[tokenId];

        // Update owner-to-tokenIds enumeration
        _removeTokenFromOwner(from, tokenId);
        _ownedTokens[to].push(tokenId);
        _ownedTokensIndex[tokenId] = _ownedTokens[to].length - 1;

        emit Transfer(from, to, tokenId);
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == 0x80ac58cd  // ERC-721
            || interfaceId == 0x01ffc9a7  // ERC-165
            || interfaceId == 0x5b5e139f  // ERC-721Metadata
            || interfaceId == 0x780e9d63; // ERC-721Enumerable
    }

    /// @notice Get the token ID owned by `owner` at a given `index`
    /// @dev Reverts if index >= balanceOf(owner)
    function tokenOfOwnerByIndex(address owner, uint256 index) external view returns (uint256) {
        if (owner == address(0)) revert ZeroAddress();
        if (index >= _ownedTokens[owner].length) revert TokenDoesNotExist();
        return _ownedTokens[owner][index];
    }

    /// @notice Get all token IDs owned by an address
    function tokensOfOwner(address owner) external view returns (uint256[] memory) {
        return _ownedTokens[owner];
    }

    /// @dev Remove a token from the owner's enumeration using swap-and-pop
    function _removeTokenFromOwner(address owner, uint256 tokenId) internal {
        uint256 lastIndex = _ownedTokens[owner].length - 1;
        uint256 tokenIndex = _ownedTokensIndex[tokenId];

        if (tokenIndex != lastIndex) {
            uint256 lastTokenId = _ownedTokens[owner][lastIndex];
            _ownedTokens[owner][tokenIndex] = lastTokenId;
            _ownedTokensIndex[lastTokenId] = tokenIndex;
        }

        _ownedTokens[owner].pop();
        delete _ownedTokensIndex[tokenId];
    }

    /// @dev Checks if `to` is a contract and, if so, calls onERC721Received
    function _checkOnERC721Received(address from, address to, uint256 tokenId, bytes memory data) internal {
        if (to.code.length > 0) {
            try IERC721Receiver(to).onERC721Received(msg.sender, from, tokenId, data) returns (bytes4 retval) {
                if (retval != IERC721Receiver.onERC721Received.selector) revert TransferToNonReceiver();
            } catch {
                revert TransferToNonReceiver();
            }
        }
    }

    // ─── Admin ──────────────────────────────────────────────────────────

    function setVerifier(address _verifier) external {
        if (msg.sender != admin) revert OnlyAdmin();
        if (_verifier == address(0)) revert ZeroAddress();
        verifier = _verifier;
    }

    /// @notice Start a two-step admin transfer
    function transferAdmin(address newAdmin) external {
        if (msg.sender != admin) revert OnlyAdmin();
        if (newAdmin == address(0)) revert ZeroAddress();
        pendingAdmin = newAdmin;
        emit AdminTransferStarted(admin, newAdmin);
    }

    /// @notice Accept a pending admin transfer
    function acceptAdmin() external {
        if (msg.sender != pendingAdmin) revert NotAuthorized();
        emit AdminTransferred(admin, msg.sender);
        admin = msg.sender;
        pendingAdmin = address(0);
    }
}
