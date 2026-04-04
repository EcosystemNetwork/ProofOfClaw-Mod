// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title SoulVaultERC8004RegistryAdapter
/// @notice ERC-8004 compatible agent identity registry with self-sovereign registration.
///         Agents register themselves; no admin gating.
contract SoulVaultERC8004RegistryAdapter {
    // ----------------------------------------------------------------
    // State
    // ----------------------------------------------------------------

    /// @notice Maps agentId to the wallet that owns it.
    mapping(bytes32 => address) private _agentWallets;

    /// @notice Maps agentId to a base-64 data URI describing the agent.
    mapping(bytes32 => string) private _agentUris;

    /// @notice Arbitrary key/value metadata per agent.
    mapping(bytes32 => mapping(string => string)) private _metadata;

    /// @notice Reverse lookup: wallet address to all agent IDs it owns.
    mapping(address => bytes32[]) private _walletAgentIds;

    // ----------------------------------------------------------------
    // Events
    // ----------------------------------------------------------------

    event AgentRegistered(bytes32 indexed agentId, address indexed agentWallet, string agentURI);
    event AgentURIUpdated(bytes32 indexed agentId, string agentURI);
    event MetadataSet(bytes32 indexed agentId, string key, string value);

    // ----------------------------------------------------------------
    // Errors
    // ----------------------------------------------------------------

    error OnlySelf();
    error OnlyOwner();
    error AgentNotRegistered();

    // ----------------------------------------------------------------
    // Modifiers
    // ----------------------------------------------------------------

    modifier onlyAgentOwner(bytes32 agentId) {
        if (_agentWallets[agentId] == address(0)) revert AgentNotRegistered();
        if (msg.sender != _agentWallets[agentId]) revert OnlyOwner();
        _;
    }

    // ----------------------------------------------------------------
    // Write functions
    // ----------------------------------------------------------------

    /// @notice Register a new agent identity. Only the agentWallet itself may call this.
    /// @param agentWallet The wallet address that will own the agent identity.
    /// @param agentURI    A base-64 data URI describing the agent.
    /// @return agentId    The unique identifier derived from wallet, timestamp, and URI.
    function registerAgent(address agentWallet, string calldata agentURI)
        external
        returns (bytes32 agentId)
    {
        if (msg.sender != agentWallet) revert OnlySelf();

        agentId = keccak256(abi.encodePacked(agentWallet, block.timestamp, agentURI));

        _agentWallets[agentId] = agentWallet;
        _agentUris[agentId] = agentURI;
        _walletAgentIds[agentWallet].push(agentId);

        emit AgentRegistered(agentId, agentWallet, agentURI);
    }

    /// @notice Update the URI of an existing agent. Only the owning wallet may call this.
    /// @param agentId  The agent to update.
    /// @param agentURI The new base-64 data URI.
    function updateAgentURI(bytes32 agentId, string calldata agentURI)
        external
        onlyAgentOwner(agentId)
    {
        _agentUris[agentId] = agentURI;
        emit AgentURIUpdated(agentId, agentURI);
    }

    /// @notice Set or overwrite a metadata key for an agent. Only the owning wallet may call this.
    /// @param agentId The agent to update.
    /// @param key     The metadata key.
    /// @param value   The metadata value.
    function setMetadata(bytes32 agentId, string calldata key, string calldata value)
        external
        onlyAgentOwner(agentId)
    {
        _metadata[agentId][key] = value;
        emit MetadataSet(agentId, key, value);
    }

    // ----------------------------------------------------------------
    // Read functions
    // ----------------------------------------------------------------

    /// @notice Return the URI for a registered agent.
    function agentURI(bytes32 agentId) external view returns (string memory) {
        return _agentUris[agentId];
    }

    /// @notice Return the wallet address that owns the agent.
    function agentWallet(bytes32 agentId) external view returns (address) {
        return _agentWallets[agentId];
    }

    /// @notice Return a metadata value for a given agent and key.
    function metadata(bytes32 agentId, string calldata key) external view returns (string memory) {
        return _metadata[agentId][key];
    }

    /// @notice Return all agent IDs registered by a given wallet.
    function agentIdsForWallet(address wallet) external view returns (bytes32[] memory) {
        return _walletAgentIds[wallet];
    }

    /// @notice Check whether an agentId has been registered.
    function isRegistered(bytes32 agentId) external view returns (bool) {
        return _agentWallets[agentId] != address(0);
    }
}
