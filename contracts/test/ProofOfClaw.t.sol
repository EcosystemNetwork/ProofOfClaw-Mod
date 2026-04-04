// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

import {SoulVaultSwarm} from "../src/SoulVaultSwarm.sol";
import {ISoulVaultSwarm} from "../src/interfaces/ISoulVaultSwarm.sol";
import {SoulVaultERC8004RegistryAdapter} from "../src/SoulVaultERC8004RegistryAdapter.sol";
import {ProofOfClawVerifier} from "../src/ProofOfClawVerifier.sol";
import {IRiscZeroVerifier} from "../src/interfaces/IRiscZeroVerifier.sol";

// ---------------------------------------------------------------------------
// Mock
// ---------------------------------------------------------------------------

contract MockRiscZeroVerifier is IRiscZeroVerifier {
    function verify(bytes calldata, bytes32, bytes32) external pure {}
}

// ===========================================================================
// SoulVaultSwarm Tests
// ===========================================================================

contract SoulVaultSwarmTest is Test {
    SoulVaultSwarm swarm;
    address owner = address(this);
    address member = address(0xBEEF);
    address nonOwner = address(0xCAFE);

    bytes constant PUBKEY = hex"04abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab";

    function setUp() public {
        swarm = new SoulVaultSwarm();
    }

    function _requestJoin(address who) internal returns (bytes32) {
        vm.prank(who);
        return swarm.requestJoin(PUBKEY, "ref://pubkey", "ref://metadata");
    }

    function _approveJoin(bytes32 requestId) internal {
        swarm.approveJoin(requestId);
    }

    // --- Join request & approval -------------------------------------------

    function test_joinRequestAndApproval() public {
        bytes32 requestId = _requestJoin(member);
        _approveJoin(requestId);

        ISoulVaultSwarm.Member memory m = swarm.getMember(member);
        assertTrue(m.active);
        assertEq(m.joinedEpoch, 0);
    }

    // --- Only owner can approve -------------------------------------------

    function test_onlyOwnerCanApprove() public {
        bytes32 requestId = _requestJoin(member);

        vm.prank(nonOwner);
        vm.expectRevert(SoulVaultSwarm.Unauthorized.selector);
        swarm.approveJoin(requestId);
    }

    // --- rotateEpoch version mismatch ------------------------------------

    function test_rotateEpochVersionMismatch() public {
        vm.expectRevert();
        swarm.rotateEpoch(1, "ref://bundle", keccak256("bundle"), 999);
    }

    // --- rotateEpoch success ---------------------------------------------

    function test_rotateEpochSuccess() public {
        uint64 ver = swarm.membershipVersion();
        swarm.rotateEpoch(1, "ref://bundle", keccak256("bundle"), ver);

        assertEq(swarm.currentEpoch(), 1);
    }

    // --- Message sequence must be monotonically increasing ----------------

    function test_messageSequenceMonotonic() public {
        bytes32 requestId = _requestJoin(member);
        _approveJoin(requestId);

        vm.startPrank(member);
        swarm.postMessage(
            address(0),
            keccak256("topic"),
            1,
            0, // epoch
            "ref://payload",
            keccak256("payload"),
            3600
        );

        // Same seq should revert
        vm.expectRevert();
        swarm.postMessage(
            address(0),
            keccak256("topic"),
            1,
            0,
            "ref://payload2",
            keccak256("payload2"),
            3600
        );

        // Lower seq should revert
        vm.expectRevert();
        swarm.postMessage(
            address(0),
            keccak256("topic"),
            0,
            0,
            "ref://payload3",
            keccak256("payload3"),
            3600
        );
        vm.stopPrank();
    }

    // --- Backup only owner ------------------------------------------------

    function test_backupOnlyOwner() public {
        vm.prank(nonOwner);
        vm.expectRevert(SoulVaultSwarm.Unauthorized.selector);
        swarm.requestBackup(0, "routine", "ref://target", uint64(block.timestamp + 3600));
    }

    // --- Member file mapping access control -------------------------------

    function test_memberFileMappingAccess() public {
        bytes32 requestId = _requestJoin(member);
        _approveJoin(requestId);

        // Member can update own file mapping
        vm.prank(member);
        swarm.updateMemberFileMapping(
            member,
            "0g://abc",
            keccak256("merkle"),
            keccak256("tx"),
            keccak256("manifest"),
            0
        );

        // Owner can update for member
        swarm.updateMemberFileMapping(
            member,
            "0g://def",
            keccak256("merkle2"),
            keccak256("tx2"),
            keccak256("manifest2"),
            0
        );

        // Non-owner cannot update for member
        vm.prank(nonOwner);
        vm.expectRevert(SoulVaultSwarm.Unauthorized.selector);
        swarm.updateMemberFileMapping(
            member,
            "0g://evil",
            keccak256("merkle3"),
            keccak256("tx3"),
            keccak256("manifest3"),
            0
        );
    }
}

// ===========================================================================
// ERC-8004 Registry Adapter Tests
// ===========================================================================

contract ERC8004RegistryAdapterTest is Test {
    SoulVaultERC8004RegistryAdapter registry;
    address wallet = address(0xA1);
    address other = address(0xA2);

    function setUp() public {
        registry = new SoulVaultERC8004RegistryAdapter();
    }

    // --- Register agent ---------------------------------------------------

    function test_registerAgent() public {
        vm.prank(wallet);
        bytes32 agentId = registry.registerAgent(wallet, "data:application/json;base64,abc123");

        assertEq(registry.agentURI(agentId), "data:application/json;base64,abc123");
        assertEq(registry.agentWallet(agentId), wallet);
        assertTrue(registry.isRegistered(agentId));
    }

    // --- Only self can register -------------------------------------------

    function test_onlySelfCanRegister() public {
        vm.prank(other);
        vm.expectRevert(SoulVaultERC8004RegistryAdapter.OnlySelf.selector);
        registry.registerAgent(wallet, "data:application/json;base64,abc123");
    }

    // --- Update URI -------------------------------------------------------

    function test_updateURI() public {
        vm.prank(wallet);
        bytes32 agentId = registry.registerAgent(wallet, "data:old");

        vm.prank(wallet);
        registry.updateAgentURI(agentId, "data:new");

        assertEq(registry.agentURI(agentId), "data:new");
    }

    // --- Set and read metadata --------------------------------------------

    function test_setMetadata() public {
        vm.prank(wallet);
        bytes32 agentId = registry.registerAgent(wallet, "data:uri");

        vm.prank(wallet);
        registry.setMetadata(agentId, "version", "1.0.0");

        assertEq(registry.metadata(agentId, "version"), "1.0.0");
    }

    // --- Reverse wallet lookup --------------------------------------------

    function test_reverseWalletLookup() public {
        vm.startPrank(wallet);

        bytes32 id1 = registry.registerAgent(wallet, "data:one");
        vm.warp(block.timestamp + 1);
        bytes32 id2 = registry.registerAgent(wallet, "data:two");

        vm.stopPrank();

        bytes32[] memory ids = registry.agentIdsForWallet(wallet);
        assertEq(ids.length, 2);
        assertEq(ids[0], id1);
        assertEq(ids[1], id2);
    }
}

// ===========================================================================
// ProofOfClawVerifier Tests
// ===========================================================================

contract ProofOfClawVerifierTest is Test {
    ProofOfClawVerifier verifierContract;
    MockRiscZeroVerifier mockVerifier;
    bytes32 constant IMAGE_ID = bytes32(uint256(1));
    address agentWallet = address(0xABCD);

    function setUp() public {
        mockVerifier = new MockRiscZeroVerifier();
        verifierContract = new ProofOfClawVerifier(IRiscZeroVerifier(address(mockVerifier)), IMAGE_ID);
    }

    // --- Register agent policy --------------------------------------------

    function test_registerAgentPolicy() public {
        bytes32 agentId = keccak256("agent-1");
        bytes32 policyHash = keccak256("policy-1");
        uint256 maxVal = 1 ether;

        verifierContract.registerAgent(agentId, policyHash, maxVal, agentWallet);

        (
            bytes32 storedPolicy,
            uint256 storedMax,
            address storedOwner,
            address storedWallet,
            bool active
        ) = verifierContract.agents(agentId);

        assertEq(storedPolicy, policyHash);
        assertEq(storedMax, maxVal);
        assertEq(storedOwner, address(this));
        assertEq(storedWallet, agentWallet);
        assertTrue(active);
    }

    // --- Deactivate agent -------------------------------------------------

    function test_deactivateAgent() public {
        bytes32 agentId = keccak256("agent-2");
        bytes32 policyHash = keccak256("policy-2");

        verifierContract.registerAgent(agentId, policyHash, 0, agentWallet);
        verifierContract.deactivateAgent(agentId);

        (, , , , bool active) = verifierContract.agents(agentId);
        assertFalse(active);
    }
}
