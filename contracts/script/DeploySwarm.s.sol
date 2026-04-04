// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/SoulVaultSwarm.sol";
import "../src/SoulVaultERC8004RegistryAdapter.sol";

/// @title DeploySwarm — Deploy SoulVault swarm coordination + identity contracts
/// @notice Deploys SoulVaultSwarm (to 0G) and ERC-8004 Registry Adapter (to Sepolia or 0G).
///
/// Usage (0G Testnet):
///   forge script script/DeploySwarm.s.sol --rpc-url https://evmrpc-testnet.0g.ai \
///     --broadcast --evm-version cancun
///
/// Usage (Sepolia — for ERC-8004 identity):
///   forge script script/DeploySwarm.s.sol --rpc-url $SEPOLIA_RPC_URL \
///     --broadcast --evm-version cancun
///
/// Required env vars:
///   PRIVATE_KEY — Deployer wallet (must have tokens for gas)
contract DeploySwarmScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy SoulVaultSwarm (core coordination)
        SoulVaultSwarm swarm = new SoulVaultSwarm();
        console.log("SoulVaultSwarm deployed at:", address(swarm));

        // 2. Deploy ERC-8004 Registry Adapter (agent identity)
        SoulVaultERC8004RegistryAdapter registry = new SoulVaultERC8004RegistryAdapter();
        console.log("ERC8004RegistryAdapter deployed at:", address(registry));

        // 3. Log deployment info
        console.log("---");
        console.log("Swarm owner:", msg.sender);
        console.log("Current epoch:", swarm.currentEpoch());
        console.log("---");
        console.log("Next steps:");
        console.log("  1. Set SOULVAULT_SWARM_CONTRACT in .env");
        console.log("  2. Set ERC8004_REGISTRY_ADDRESS in .env");
        console.log("  3. Use CLI: poc swarm join-request");
        console.log("  4. Use CLI: poc epoch rotate");

        vm.stopBroadcast();
    }
}
