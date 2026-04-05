// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

import {SoulVaultSwarm} from "../src/SoulVaultSwarm.sol";
import {ISoulVaultSwarm} from "../src/interfaces/ISoulVaultSwarm.sol";
import {SoulVaultERC8004RegistryAdapter} from "../src/SoulVaultERC8004RegistryAdapter.sol";
import {ProofOfClawVerifier} from "../src/ProofOfClawVerifier.sol";
import {ProofOfClawINFT} from "../src/ProofOfClawINFT.sol";
import {EIP8004Integration} from "../src/EIP8004Integration.sol";
import {IEIP8004IdentityRegistry, IEIP8004ReputationRegistry, IEIP8004ValidationRegistry} from "../src/interfaces/IEIP8004.sol";
import {RiscZeroGroth16Verifier} from "../src/RiscZeroGroth16Verifier.sol";
import {IRiscZeroVerifier} from "../src/interfaces/IRiscZeroVerifier.sol";

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

contract MockRiscZeroVerifier is IRiscZeroVerifier {
    function verify(bytes calldata, bytes32, bytes32) external pure {}
}

/// @dev Mock verifier that always reverts — used to test rejection path
contract RejectingVerifier is IRiscZeroVerifier {
    function verify(bytes calldata, bytes32, bytes32) external pure {
        revert("Invalid proof");
    }
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

    // --- Update verifier (onlyOwner) --------------------------------------

    function test_updateVerifier() public {
        MockRiscZeroVerifier newVerifier = new MockRiscZeroVerifier();

        verifierContract.updateVerifier(address(newVerifier));
        assertEq(address(verifierContract.verifier()), address(newVerifier));
    }

    function test_updateVerifier_rejectsNonOwner() public {
        MockRiscZeroVerifier newVerifier = new MockRiscZeroVerifier();

        vm.prank(address(0xDEAD));
        vm.expectRevert(ProofOfClawVerifier.Unauthorized.selector);
        verifierContract.updateVerifier(address(newVerifier));
    }

    function test_updateVerifier_rejectsZeroAddress() public {
        vm.expectRevert("Zero address");
        verifierContract.updateVerifier(address(0));
    }

    // --- Update image ID (onlyOwner) --------------------------------------

    function test_updateImageId() public {
        bytes32 newImageId = bytes32(uint256(42));

        verifierContract.updateImageId(newImageId);
        assertEq(verifierContract.imageId(), newImageId);
    }

    function test_updateImageId_rejectsNonOwner() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert(ProofOfClawVerifier.Unauthorized.selector);
        verifierContract.updateImageId(bytes32(uint256(42)));
    }

    // --- Verifier switch rejects bad proofs --------------------------------

    function test_rejectingVerifier_blocksExecution() public {
        // Register agent
        bytes32 agentId = keccak256("agent-reject");
        bytes32 policyHash = keccak256("policy-reject");
        verifierContract.registerAgent(agentId, policyHash, 1 ether, agentWallet);

        // Switch to rejecting verifier
        RejectingVerifier rejecter = new RejectingVerifier();
        verifierContract.updateVerifier(address(rejecter));

        // Attempt to verify — should revert
        ProofOfClawVerifier.VerifiedOutput memory output = ProofOfClawVerifier.VerifiedOutput({
            agentId: "agent-reject",
            policyHash: policyHash,
            outputCommitment: keccak256("output"),
            allChecksPassed: true,
            requiresLedgerApproval: false,
            actionValue: 0
        });

        bytes memory journalData = abi.encode(output);
        bytes memory seal = hex"00";
        bytes memory action = abi.encode(address(0), uint256(0), bytes(""));

        vm.prank(agentWallet);
        vm.expectRevert("Invalid proof");
        verifierContract.verifyAndExecute(seal, journalData, action);
    }

    // --- Full verifyAndExecute with mock (autonomous path) -----------------

    function test_verifyAndExecute_autonomous() public {
        // Deploy a dummy target contract that accepts calls
        DummyTarget target = new DummyTarget();

        // Whitelist the target
        verifierContract.setAllowedTarget(address(target), true);

        bytes32 agentId = keccak256("agent-auto");
        bytes32 policyHash = keccak256("policy-auto");
        verifierContract.registerAgent(agentId, policyHash, 1 ether, agentWallet);

        // Build action first so outputCommitment = keccak256(action) (binding check)
        bytes memory action = abi.encode(
            address(target),
            uint256(0),
            abi.encodeCall(DummyTarget.ping, ())
        );

        ProofOfClawVerifier.VerifiedOutput memory output = ProofOfClawVerifier.VerifiedOutput({
            agentId: "agent-auto",
            policyHash: policyHash,
            outputCommitment: keccak256(action),
            allChecksPassed: true,
            requiresLedgerApproval: false,
            actionValue: 0
        });

        bytes memory journalData = abi.encode(output);
        bytes memory seal = hex"00";

        vm.prank(agentWallet);
        verifierContract.verifyAndExecute(seal, journalData, action);

        assertTrue(target.pinged());
    }
}

// ===========================================================================
// Groth16 Verifier Tests
// ===========================================================================

contract RiscZeroGroth16VerifierTest is Test {
    RiscZeroGroth16Verifier groth16Verifier;

    bytes4 constant SELECTOR = bytes4(0x310fe598);

    function setUp() public {
        groth16Verifier = new RiscZeroGroth16Verifier();
    }

    // --- Seal too short ---------------------------------------------------

    function test_rejectShortSeal() public {
        bytes memory shortSeal = hex"310fe59800";

        vm.expectRevert(RiscZeroGroth16Verifier.InvalidSealLength.selector);
        groth16Verifier.verify(shortSeal, bytes32(0), bytes32(0));
    }

    // --- Wrong selector ---------------------------------------------------

    function test_rejectWrongSelector() public {
        bytes memory seal = new bytes(260);
        seal[0] = 0xDE;
        seal[1] = 0xAD;
        seal[2] = 0xBE;
        seal[3] = 0xEF;

        vm.expectRevert(RiscZeroGroth16Verifier.InvalidProofSelector.selector);
        groth16Verifier.verify(seal, bytes32(0), bytes32(0));
    }

    // --- Invalid proof fails pairing check --------------------------------

    function test_rejectInvalidProof() public {
        // Build a seal with valid-looking but incorrect proof points
        bytes memory seal = _buildSeal(
            SELECTOR,
            uint256(1), uint256(2),  // A (G1 generator)
            uint256(10857046999023057135944570762232829481370756359578518086990519993285655852781),
            uint256(11559732032986387107991004021392285783925812861821192530917403151452391805634),
            uint256(8495653923123431417604973247489272438418190587263600148770280649306958101930),
            uint256(4082367875863433681332203403145435568316851327593401208105741076214120093531),
            uint256(1), uint256(2)   // C (G1 generator)
        );

        vm.expectRevert(); // PairingFailed — proof doesn't match VK
        groth16Verifier.verify(seal, bytes32(uint256(1)), bytes32(uint256(2)));
    }

    // --- Proof selector is stored correctly --------------------------------

    function test_proofSelectorStored() public view {
        assertEq(groth16Verifier.PROOF_SELECTOR(), SELECTOR);
    }

    // --- Helper to build seal bytes ----------------------------------------

    function _buildSeal(
        bytes4 sel,
        uint256 aX, uint256 aY,
        uint256 bX1, uint256 bX2, uint256 bY1, uint256 bY2,
        uint256 cX, uint256 cY
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            sel,
            bytes32(aX), bytes32(aY),
            bytes32(bX1), bytes32(bX2), bytes32(bY1), bytes32(bY2),
            bytes32(cX), bytes32(cY)
        );
    }
}

// ===========================================================================
// ProofOfClawINFT Tests
// ===========================================================================

contract ProofOfClawINFTTest is Test {
    ProofOfClawINFT inft;
    address admin = address(this);
    address verifierAddr = address(0xF1);
    address alice = address(0xA1);
    address bob = address(0xB0B);

    bytes32 constant AGENT_ID = keccak256("agent-1");
    bytes32 constant POLICY = keccak256("policy-1");
    bytes32 constant IMAGE_ID_INFT = bytes32(uint256(0x1234));
    bytes32 constant META_HASH = keccak256("metadata");
    bytes32 constant SOUL_HASH = keccak256("soul-backup");

    function setUp() public {
        inft = new ProofOfClawINFT(verifierAddr);
    }

    function _mint() internal returns (uint256) {
        vm.prank(alice);
        return inft.mint(AGENT_ID, POLICY, IMAGE_ID_INFT, "0g://encrypted", META_HASH, SOUL_HASH, "0g://soul-backup", "agent.proofofclaw.eth");
    }

    // --- Minting ---

    function test_mint() public {
        uint256 tokenId = _mint();
        assertEq(tokenId, 1);
        assertEq(inft.ownerOf(tokenId), alice);
        assertEq(inft.getTokenByAgent(AGENT_ID), tokenId);
        assertEq(inft.totalSupply(), 1);
    }

    function test_mint_duplicateReverts() public {
        _mint();
        vm.prank(bob);
        vm.expectRevert(ProofOfClawINFT.AgentAlreadyMinted.selector);
        inft.mint(AGENT_ID, POLICY, IMAGE_ID_INFT, "0g://other", META_HASH, SOUL_HASH, "0g://soul-backup", "bob.proofofclaw.eth");
    }

    // --- Metadata ---

    function test_updateMetadata() public {
        uint256 tokenId = _mint();
        bytes32 newHash = keccak256("new-meta");

        vm.prank(alice);
        inft.updateMetadata(tokenId, "0g://updated", newHash);

        assertEq(inft.tokenURI(tokenId), "0g://updated");
    }

    function test_updateMetadata_nonOwnerReverts() public {
        uint256 tokenId = _mint();
        vm.prank(bob);
        vm.expectRevert(ProofOfClawINFT.NotOwner.selector);
        inft.updateMetadata(tokenId, "0g://evil", keccak256("evil"));
    }

    // --- Transfers ---

    function test_transferFrom() public {
        uint256 tokenId = _mint();

        vm.prank(alice);
        inft.transferFrom(alice, bob, tokenId);

        assertEq(inft.ownerOf(tokenId), bob);
    }

    function test_transferFrom_unauthorizedReverts() public {
        uint256 tokenId = _mint();

        vm.prank(bob);
        vm.expectRevert(ProofOfClawINFT.NotAuthorized.selector);
        inft.transferFrom(alice, bob, tokenId);
    }

    function test_transferFrom_withApproval() public {
        uint256 tokenId = _mint();

        vm.prank(alice);
        inft.approve(bob, tokenId);

        vm.prank(bob);
        inft.transferFrom(alice, bob, tokenId);
        assertEq(inft.ownerOf(tokenId), bob);
    }

    function test_transferFrom_withOperatorApproval() public {
        uint256 tokenId = _mint();

        vm.prank(alice);
        inft.setApprovalForAll(bob, true);

        vm.prank(bob);
        inft.transferFrom(alice, bob, tokenId);
        assertEq(inft.ownerOf(tokenId), bob);
    }

    function test_transfer_clearsApproval() public {
        uint256 tokenId = _mint();

        vm.prank(alice);
        inft.approve(bob, tokenId);
        assertEq(inft.getApproved(tokenId), bob);

        vm.prank(alice);
        inft.transferFrom(alice, bob, tokenId);
        assertEq(inft.getApproved(tokenId), address(0));
    }

    // --- Usage Authorization (ERC-7857) ---

    function test_authorizeUsage() public {
        uint256 tokenId = _mint();

        vm.prank(alice);
        inft.authorizeUsage(tokenId, bob, "inference");

        assertTrue(inft.isAuthorized(tokenId, bob));
    }

    function test_revokeUsage() public {
        uint256 tokenId = _mint();

        vm.prank(alice);
        inft.authorizeUsage(tokenId, bob, "inference");

        vm.prank(alice);
        inft.revokeUsage(tokenId, bob);

        assertFalse(inft.isAuthorized(tokenId, bob));
    }

    // --- Proof & Reputation ---

    function test_recordProof() public {
        uint256 tokenId = _mint();

        vm.prank(verifierAddr);
        inft.recordProof(tokenId);

        ProofOfClawINFT.AgentINFT memory agent = inft.getAgent(tokenId);
        assertEq(agent.totalProofs, 1);
    }

    function test_recordProof_nonVerifierReverts() public {
        uint256 tokenId = _mint();

        vm.prank(bob);
        vm.expectRevert(ProofOfClawINFT.OnlyVerifier.selector);
        inft.recordProof(tokenId);
    }

    function test_updateReputation_byVerifier() public {
        uint256 tokenId = _mint();

        vm.prank(verifierAddr);
        inft.updateReputation(tokenId, 95);

        assertEq(inft.getAgent(tokenId).reputationScore, 95);
    }

    function test_updateReputation_byAdmin() public {
        uint256 tokenId = _mint();

        inft.updateReputation(tokenId, 80); // admin = address(this)

        assertEq(inft.getAgent(tokenId).reputationScore, 80);
    }

    function test_updateReputation_unauthorizedReverts() public {
        uint256 tokenId = _mint();

        vm.prank(bob);
        vm.expectRevert(ProofOfClawINFT.NotAuthorized.selector);
        inft.updateReputation(tokenId, 50);
    }

    // --- balanceOf ---

    function test_balanceOf() public {
        _mint();
        assertEq(inft.balanceOf(alice), 1);
        assertEq(inft.balanceOf(bob), 0);
    }

    // --- supportsInterface ---

    function test_supportsInterface() public view {
        assertTrue(inft.supportsInterface(0x80ac58cd)); // ERC-721
        assertTrue(inft.supportsInterface(0x01ffc9a7)); // ERC-165
        assertFalse(inft.supportsInterface(0xdeadbeef));
    }

    // --- Deactivate ---

    function test_deactivate() public {
        uint256 tokenId = _mint();

        vm.prank(alice);
        inft.deactivate(tokenId);

        assertFalse(inft.getAgent(tokenId).active);
    }

    // --- Soul Backup ---

    function test_mint_withoutSoulReverts() public {
        vm.prank(alice);
        vm.expectRevert(ProofOfClawINFT.SoulBackupRequired.selector);
        inft.mint(keccak256("soulless-agent"), POLICY, IMAGE_ID_INFT, "0g://enc", META_HASH, bytes32(0), "", "soulless.eth");
    }

    function test_getSoulBackup() public {
        uint256 tokenId = _mint();
        (bytes32 hash, string memory uri) = inft.getSoulBackup(tokenId);
        assertEq(hash, SOUL_HASH);
        assertEq(keccak256(bytes(uri)), keccak256(bytes("0g://soul-backup")));
    }

    function test_updateSoulBackup() public {
        uint256 tokenId = _mint();
        bytes32 newHash = keccak256("evolved-soul");

        vm.prank(alice);
        inft.updateSoulBackup(tokenId, newHash, "0g://evolved-soul");

        (bytes32 hash, string memory uri) = inft.getSoulBackup(tokenId);
        assertEq(hash, newHash);
        assertEq(keccak256(bytes(uri)), keccak256(bytes("0g://evolved-soul")));
    }

    function test_updateSoulBackup_nonOwnerReverts() public {
        uint256 tokenId = _mint();
        vm.prank(bob);
        vm.expectRevert(ProofOfClawINFT.NotOwner.selector);
        inft.updateSoulBackup(tokenId, keccak256("hijack"), "0g://evil");
    }

    function test_updateSoulBackup_zeroHashReverts() public {
        uint256 tokenId = _mint();
        vm.prank(alice);
        vm.expectRevert(ProofOfClawINFT.SoulBackupRequired.selector);
        inft.updateSoulBackup(tokenId, bytes32(0), "");
    }

    // --- Burn ---

    function test_burn() public {
        uint256 tokenId = _mint();

        // Verify token exists
        assertEq(inft.ownerOf(tokenId), alice);
        assertEq(inft.getTokenByAgent(AGENT_ID), tokenId);

        // Burn the token
        vm.prank(alice);
        inft.burn(tokenId);

        // agentToToken should be cleared — returns 0 for burned agent
        assertEq(inft.getTokenByAgent(AGENT_ID), 0);

        // Balance should be 0
        assertEq(inft.balanceOf(alice), 0);

        // ensName should be freed — can re-register with the same ensName
        vm.prank(bob);
        uint256 newTokenId = inft.mint(
            keccak256("agent-reuse"),
            POLICY,
            IMAGE_ID_INFT,
            "0g://new-enc",
            META_HASH,
            SOUL_HASH,
            "0g://soul-backup",
            "agent.proofofclaw.eth"
        );
        assertEq(inft.ownerOf(newTokenId), bob);
    }

    function test_burn_nonOwnerReverts() public {
        uint256 tokenId = _mint();

        vm.prank(bob);
        vm.expectRevert(ProofOfClawINFT.NotOwner.selector);
        inft.burn(tokenId);
    }

    function test_burn_freesAgentIdForReregistration() public {
        uint256 tokenId = _mint();

        vm.prank(alice);
        inft.burn(tokenId);

        // The same agentId can now be used for a new mint
        vm.prank(bob);
        uint256 newTokenId = inft.mint(
            AGENT_ID,
            POLICY,
            IMAGE_ID_INFT,
            "0g://re-enc",
            META_HASH,
            SOUL_HASH,
            "0g://soul-backup",
            "new-agent.proofofclaw.eth"
        );
        assertEq(inft.ownerOf(newTokenId), bob);
        assertEq(inft.getTokenByAgent(AGENT_ID), newTokenId);
    }

    // --- Admin ---

    function test_setVerifier() public {
        inft.setVerifier(address(0x999));
        assertEq(inft.verifier(), address(0x999));
    }

    function test_setVerifier_nonAdminReverts() public {
        vm.prank(bob);
        vm.expectRevert(ProofOfClawINFT.OnlyAdmin.selector);
        inft.setVerifier(address(0x999));
    }
}

// ===========================================================================
// EIP8004Integration Tests (with mock registries)
// ===========================================================================

contract MockIdentityRegistry is IEIP8004IdentityRegistry {
    uint256 nextId = 1;
    mapping(uint256 => string) public uris;

    function register(string calldata agentURI, MetadataEntry[] calldata) external returns (uint256) {
        uint256 id = nextId++;
        uris[id] = agentURI;
        return id;
    }
    function register(string calldata agentURI) external returns (uint256) {
        uint256 id = nextId++;
        uris[id] = agentURI;
        return id;
    }
    function register() external returns (uint256) { return nextId++; }
    function setAgentURI(uint256, string calldata) external {}
    function getMetadata(uint256, string calldata) external pure returns (bytes memory) { return ""; }
    function setMetadata(uint256, string calldata, bytes calldata) external {}
    function setAgentWallet(uint256, address, uint256, bytes calldata) external {}
    function getAgentWallet(uint256) external pure returns (address) { return address(0); }
    function unsetAgentWallet(uint256) external {}
}

contract MockReputationRegistry is IEIP8004ReputationRegistry {
    uint256 public feedbackCount;

    function initialize(address) external {}
    function getIdentityRegistry() external pure returns (address) { return address(0); }
    function giveFeedback(uint256, int128, uint8, string calldata, string calldata, string calldata, string calldata, bytes32) external {
        feedbackCount++;
    }
    function revokeFeedback(uint256, uint64) external {}
    function appendResponse(uint256, address, uint64, string calldata, bytes32) external {}
    function getSummary(uint256, address[] calldata, string calldata, string calldata) external pure returns (uint64, int128, uint8) {
        return (5, 85, 0);
    }
    function readFeedback(uint256, address, uint64) external pure returns (int128, uint8, string memory, string memory, bool) {
        return (0, 0, "", "", false);
    }
    function getClients(uint256) external pure returns (address[] memory) { return new address[](0); }
    function getLastIndex(uint256, address) external pure returns (uint64) { return 0; }
}

contract MockValidationRegistry is IEIP8004ValidationRegistry {
    uint256 public responseCount;

    function initialize(address) external {}
    function validationRequest(address, uint256, string calldata, bytes32) external {}
    function validationResponse(bytes32, uint8, string calldata, bytes32, string calldata) external {
        responseCount++;
    }
    function getValidationStatus(bytes32) external pure returns (address, uint256, uint8, bytes32, string memory, uint256) {
        return (address(0), 0, 0, bytes32(0), "", 0);
    }
    function getSummary(uint256, address[] calldata, string calldata) external pure returns (uint64, uint8) {
        return (3, 90);
    }
    function getAgentValidations(uint256) external pure returns (bytes32[] memory) { return new bytes32[](0); }
    function getValidatorRequests(address) external pure returns (bytes32[] memory) { return new bytes32[](0); }
}

contract EIP8004IntegrationTest is Test {
    EIP8004Integration integration;
    MockIdentityRegistry identityReg;
    MockReputationRegistry reputationReg;
    MockValidationRegistry validationReg;
    address verifierAddr = address(0xF1);
    address alice = address(0xA1);
    address bob = address(0xB0B);

    bytes32 constant AGENT_ID = keccak256("agent-eip");

    function setUp() public {
        identityReg = new MockIdentityRegistry();
        reputationReg = new MockReputationRegistry();
        validationReg = new MockValidationRegistry();
        integration = new EIP8004Integration(
            address(identityReg),
            address(reputationReg),
            address(validationReg),
            verifierAddr
        );
    }

    function _registerAgent() internal returns (uint256) {
        vm.prank(alice);
        return integration.registerAgentIdentity(
            AGENT_ID,
            "ipfs://agent-metadata",
            keccak256("policy"),
            bytes32(uint256(0x1234))
        );
    }

    // --- Registration ---

    function test_registerAgentIdentity() public {
        uint256 tokenId = _registerAgent();
        assertEq(tokenId, 1);
        assertEq(integration.agentToTokenId(AGENT_ID), 1);
        assertEq(integration.tokenIdToAgent(1), AGENT_ID);
        assertEq(integration.agentRegistrant(AGENT_ID), alice);
    }

    function test_registerAgentIdentity_duplicateReverts() public {
        _registerAgent();
        vm.prank(bob);
        vm.expectRevert(EIP8004Integration.AgentAlreadyRegistered.selector);
        integration.registerAgentIdentity(AGENT_ID, "ipfs://dup", keccak256("p"), bytes32(0));
    }

    // --- Validation Recording ---

    function test_recordValidation() public {
        _registerAgent();

        vm.prank(verifierAddr);
        integration.recordValidation(AGENT_ID, keccak256("req"), true, "ipfs://proof", keccak256("resp"));

        assertEq(validationReg.responseCount(), 1);
    }

    function test_recordValidation_nonVerifierReverts() public {
        _registerAgent();
        vm.prank(alice);
        vm.expectRevert(EIP8004Integration.OnlyVerifier.selector);
        integration.recordValidation(AGENT_ID, keccak256("req"), true, "", bytes32(0));
    }

    function test_recordValidation_unregisteredReverts() public {
        vm.prank(verifierAddr);
        vm.expectRevert(EIP8004Integration.AgentNotRegistered.selector);
        integration.recordValidation(keccak256("fake"), keccak256("req"), true, "", bytes32(0));
    }

    // --- Reputation ---

    function test_submitReputation() public {
        _registerAgent();

        vm.prank(bob); // not the registrant
        integration.submitReputation(AGENT_ID, 90, 0, "quality", "task", "/verify", "ipfs://feedback", keccak256("fb"));

        assertEq(reputationReg.feedbackCount(), 1);
    }

    function test_submitReputation_selfReviewReverts() public {
        _registerAgent();

        vm.prank(alice); // alice is the registrant
        vm.expectRevert(EIP8004Integration.OnlyAgentOwner.selector);
        integration.submitReputation(AGENT_ID, 90, 0, "quality", "task", "/verify", "ipfs://feedback", keccak256("fb"));
    }

    // --- Validation Request ---

    function test_requestValidation_byVerifier() public {
        _registerAgent();
        vm.prank(verifierAddr);
        integration.requestValidation(AGENT_ID, "0g://trace", keccak256("trace"));
    }

    function test_requestValidation_byRegistrant() public {
        _registerAgent();
        vm.prank(alice);
        integration.requestValidation(AGENT_ID, "0g://trace", keccak256("trace"));
    }

    function test_requestValidation_unauthorizedReverts() public {
        _registerAgent();
        vm.prank(bob);
        vm.expectRevert(EIP8004Integration.OnlyVerifierOrRegistrant.selector);
        integration.requestValidation(AGENT_ID, "0g://trace", keccak256("trace"));
    }

    // --- View functions ---

    function test_getAgentReputation() public {
        _registerAgent();
        address[] memory reviewers = new address[](0);
        (uint64 count, int128 value,) = integration.getAgentReputation(AGENT_ID, reviewers, "", "");
        assertEq(count, 5);
        assertEq(value, 85);
    }

    function test_getAgentValidationSummary() public {
        _registerAgent();
        (uint64 count, uint8 avg) = integration.getAgentValidationSummary(AGENT_ID, "risc-zero-zkvm");
        assertEq(count, 3);
        assertEq(avg, 90);
    }

    function test_getTokenId() public {
        _registerAgent();
        assertEq(integration.getTokenId(AGENT_ID), 1);
    }
}

// ===========================================================================
// Additional ProofOfClawVerifier Tests (new security features)
// ===========================================================================

contract ProofOfClawVerifierSecurityTest is Test {
    ProofOfClawVerifier verifierContract;
    MockRiscZeroVerifier mockVerifier;
    bytes32 constant IMG_ID = bytes32(uint256(1));
    address agentWallet = address(0xABCD);
    uint256 ownerPk = 0xA11CE;
    address owner;

    function setUp() public {
        owner = vm.addr(ownerPk);
        vm.startPrank(owner);
        mockVerifier = new MockRiscZeroVerifier();
        verifierContract = new ProofOfClawVerifier(IRiscZeroVerifier(address(mockVerifier)), IMG_ID);
        vm.stopPrank();
    }

    /// @dev Helper: sign an ActionApproval with the owner's private key via EIP-712.
    function _signApproval(bytes32 agentId, bytes32 outputCommitment, uint256 actionValue)
        internal view returns (uint8 v, bytes32 r, bytes32 s)
    {
        bytes32 domainSeparator = keccak256(abi.encode(
            verifierContract.DOMAIN_TYPEHASH(),
            keccak256("ProofOfClaw"),
            keccak256("1"),
            block.chainid,
            address(verifierContract)
        ));
        bytes32 structHash = keccak256(abi.encode(
            verifierContract.APPROVAL_TYPEHASH(),
            agentId, outputCommitment, actionValue
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (v, r, s) = vm.sign(ownerPk, digest);
    }

    function test_setAllowedTarget() public {
        vm.startPrank(owner);
        verifierContract.setAllowedTarget(address(0x123), true);
        assertTrue(verifierContract.allowedTargets(address(0x123)));

        verifierContract.setAllowedTarget(address(0x123), false);
        assertFalse(verifierContract.allowedTargets(address(0x123)));
        vm.stopPrank();
    }

    function test_setAllowedTarget_nonOwnerReverts() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert(ProofOfClawVerifier.Unauthorized.selector);
        verifierContract.setAllowedTarget(address(0x123), true);
    }

    function test_executeAction_rejectsUnwhitelistedTarget() public {
        DummyTarget target = new DummyTarget();
        // Do NOT whitelist the target

        bytes32 agentId = keccak256("agent-nowhite");
        bytes32 policyHash = keccak256("policy-nowhite");
        vm.prank(owner);
        verifierContract.registerAgent(agentId, policyHash, 1 ether, agentWallet);

        bytes memory action = abi.encode(address(target), uint256(0), abi.encodeCall(DummyTarget.ping, ()));

        ProofOfClawVerifier.VerifiedOutput memory output = ProofOfClawVerifier.VerifiedOutput({
            agentId: "agent-nowhite",
            policyHash: policyHash,
            outputCommitment: keccak256(action),
            allChecksPassed: true,
            requiresLedgerApproval: false,
            actionValue: 0
        });

        bytes memory journalData = abi.encode(output);
        bytes memory seal = hex"00";

        vm.prank(agentWallet);
        vm.expectRevert(ProofOfClawVerifier.TargetNotAllowed.selector);
        verifierContract.verifyAndExecute(seal, journalData, action);
    }

    function test_approveAction_flow() public {
        DummyTarget target = new DummyTarget();
        vm.prank(owner);
        verifierContract.setAllowedTarget(address(target), true);

        bytes32 agentId = keccak256("agent-approve");
        bytes32 policyHash = keccak256("policy-approve");
        bytes32 outputCommitment = keccak256("output-approve");
        vm.prank(owner);
        verifierContract.registerAgent(agentId, policyHash, 1 ether, agentWallet);

        bytes memory action = abi.encode(address(target), uint256(0), abi.encodeCall(DummyTarget.ping, ()));

        ProofOfClawVerifier.VerifiedOutput memory output = ProofOfClawVerifier.VerifiedOutput({
            agentId: "agent-approve",
            policyHash: policyHash,
            outputCommitment: outputCommitment,
            allChecksPassed: true,
            requiresLedgerApproval: true,
            actionValue: 1 ether
        });

        bytes memory journalData = abi.encode(output);
        bytes memory seal = hex"00";

        // Submit for approval (anyone can call when ledger approval required)
        verifierContract.verifyAndExecute(seal, journalData, action);

        // Owner signs via EIP-712 and approves
        (uint8 v, bytes32 r, bytes32 s) = _signApproval(agentId, outputCommitment, 1 ether);
        vm.prank(owner);
        verifierContract.approveAction(agentId, outputCommitment, action, v, r, s);

        assertTrue(target.pinged());
    }

    function test_approveAction_rejectsAlreadyExecuted() public {
        DummyTarget target = new DummyTarget();
        vm.prank(owner);
        verifierContract.setAllowedTarget(address(target), true);

        bytes32 agentId = keccak256("agent-replay");
        bytes32 policyHash = keccak256("policy-replay");
        bytes32 outputCommitment = keccak256("output-replay");
        vm.prank(owner);
        verifierContract.registerAgent(agentId, policyHash, 1 ether, agentWallet);

        bytes memory action = abi.encode(address(target), uint256(0), abi.encodeCall(DummyTarget.ping, ()));

        ProofOfClawVerifier.VerifiedOutput memory output = ProofOfClawVerifier.VerifiedOutput({
            agentId: "agent-replay",
            policyHash: policyHash,
            outputCommitment: outputCommitment,
            allChecksPassed: true,
            requiresLedgerApproval: true,
            actionValue: 1 ether
        });

        bytes memory journalData = abi.encode(output);
        verifierContract.verifyAndExecute(hex"00", journalData, action);

        (uint8 v, bytes32 r, bytes32 s) = _signApproval(agentId, outputCommitment, 1 ether);
        vm.prank(owner);
        verifierContract.approveAction(agentId, outputCommitment, action, v, r, s);

        // Try to approve again — should revert
        vm.prank(owner);
        vm.expectRevert(ProofOfClawVerifier.ActionNotPending.selector);
        verifierContract.approveAction(agentId, outputCommitment, action, v, r, s);
    }

    function test_replayPrevention_rejectsDuplicateActionId() public {
        bytes32 agentId = keccak256("agent-dup");
        bytes32 policyHash = keccak256("policy-dup");
        vm.prank(owner);
        verifierContract.registerAgent(agentId, policyHash, 1 ether, agentWallet);

        ProofOfClawVerifier.VerifiedOutput memory output = ProofOfClawVerifier.VerifiedOutput({
            agentId: "agent-dup",
            policyHash: policyHash,
            outputCommitment: keccak256("output-dup"),
            allChecksPassed: true,
            requiresLedgerApproval: true,
            actionValue: 1 ether
        });

        bytes memory journalData = abi.encode(output);
        verifierContract.verifyAndExecute(hex"00", journalData, hex"");

        // Same proof again — should revert with ActionAlreadySubmitted
        vm.expectRevert(ProofOfClawVerifier.ActionAlreadySubmitted.selector);
        verifierContract.verifyAndExecute(hex"00", journalData, hex"");
    }

    function test_approveAction_invalidSignatureReverts() public {
        bytes32 agentId = keccak256("agent-auth");
        bytes32 policyHash = keccak256("policy-auth");
        bytes32 outputCommitment = keccak256("output-auth");
        vm.prank(owner);
        verifierContract.registerAgent(agentId, policyHash, 1 ether, agentWallet);

        ProofOfClawVerifier.VerifiedOutput memory output = ProofOfClawVerifier.VerifiedOutput({
            agentId: "agent-auth",
            policyHash: policyHash,
            outputCommitment: outputCommitment,
            allChecksPassed: true,
            requiresLedgerApproval: true,
            actionValue: 0
        });

        verifierContract.verifyAndExecute(hex"00", abi.encode(output), hex"");

        // Sign with a different key — should be rejected
        uint256 wrongPk = 0xBAD;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPk, keccak256("garbage"));
        vm.expectRevert(ProofOfClawVerifier.InvalidSignature.selector);
        verifierContract.approveAction(agentId, outputCommitment, hex"", v, r, s);
    }

    function test_approveAction_expiredReverts() public {
        bytes32 agentId = keccak256("agent-expiry");
        bytes32 policyHash = keccak256("policy-expiry");
        bytes32 outputCommitment = keccak256("output-expiry");
        vm.prank(owner);
        verifierContract.registerAgent(agentId, policyHash, 1 ether, agentWallet);

        ProofOfClawVerifier.VerifiedOutput memory output = ProofOfClawVerifier.VerifiedOutput({
            agentId: "agent-expiry",
            policyHash: policyHash,
            outputCommitment: outputCommitment,
            allChecksPassed: true,
            requiresLedgerApproval: true,
            actionValue: 1 ether
        });

        verifierContract.verifyAndExecute(hex"00", abi.encode(output), hex"");

        // Warp past the 24h expiry
        vm.warp(block.timestamp + 25 hours);

        (uint8 v, bytes32 r, bytes32 s) = _signApproval(agentId, outputCommitment, 1 ether);
        vm.prank(owner);
        vm.expectRevert(ProofOfClawVerifier.ActionExpired.selector);
        verifierContract.approveAction(agentId, outputCommitment, hex"", v, r, s);
    }

    function test_updateAgentPolicy() public {
        bytes32 agentId = keccak256("agent-policy");
        vm.startPrank(owner);
        verifierContract.registerAgent(agentId, keccak256("old"), 1 ether, agentWallet);
        verifierContract.updateAgentPolicy(agentId, keccak256("new"), 2 ether);
        vm.stopPrank();

        (bytes32 storedPolicy, uint256 storedMax,,,) = verifierContract.agents(agentId);
        assertEq(storedPolicy, keccak256("new"));
        assertEq(storedMax, 2 ether);
    }

    // --- approveAction reverts for deactivated agent -------------------------

    function test_approveAction_revertsForDeactivatedAgent() public {
        DummyTarget target = new DummyTarget();
        vm.prank(owner);
        verifierContract.setAllowedTarget(address(target), true);

        bytes32 agentId = keccak256("agent-deact-approve");
        bytes32 policyHash = keccak256("policy-deact-approve");
        bytes32 outputCommitment = keccak256("output-deact-approve");
        vm.prank(owner);
        verifierContract.registerAgent(agentId, policyHash, 1 ether, agentWallet);

        // Submit action for approval
        bytes memory action = abi.encode(address(target), uint256(0), abi.encodeCall(DummyTarget.ping, ()));

        ProofOfClawVerifier.VerifiedOutput memory output = ProofOfClawVerifier.VerifiedOutput({
            agentId: "agent-deact-approve",
            policyHash: policyHash,
            outputCommitment: outputCommitment,
            allChecksPassed: true,
            requiresLedgerApproval: true,
            actionValue: 1 ether
        });

        verifierContract.verifyAndExecute(hex"00", abi.encode(output), action);

        // Deactivate the agent
        vm.prank(owner);
        verifierContract.deactivateAgent(agentId);

        // Try to approve — should revert because agent is deactivated
        (uint8 v, bytes32 r, bytes32 s) = _signApproval(agentId, outputCommitment, 1 ether);
        vm.prank(owner);
        vm.expectRevert("Agent deactivated");
        verifierContract.approveAction(agentId, outputCommitment, action, v, r, s);
    }

    // --- maxValueAutonomous enforcement --------------------------------------

    function test_verifyAndExecute_revertsWhenValueExceedsAutonomousLimit() public {
        DummyTarget target = new DummyTarget();
        vm.startPrank(owner);
        verifierContract.setAllowedTarget(address(target), true);

        bytes32 agentId = keccak256("agent-maxval");
        bytes32 policyHash = keccak256("policy-maxval");
        verifierContract.registerAgent(agentId, policyHash, 1 ether, agentWallet);
        vm.stopPrank();

        bytes memory action = abi.encode(address(target), uint256(0), abi.encodeCall(DummyTarget.ping, ()));

        // Action value (2 ether) exceeds maxValueAutonomous (1 ether)
        ProofOfClawVerifier.VerifiedOutput memory output = ProofOfClawVerifier.VerifiedOutput({
            agentId: "agent-maxval",
            policyHash: policyHash,
            outputCommitment: keccak256(action),
            allChecksPassed: true,
            requiresLedgerApproval: false,
            actionValue: 2 ether
        });

        bytes memory journalData = abi.encode(output);
        vm.prank(agentWallet);
        vm.expectRevert("Value exceeds autonomous limit");
        verifierContract.verifyAndExecute(hex"00", journalData, action);
    }

    // --- Two-step ownership transfer -----------------------------------------

    function test_twoStepOwnershipTransfer() public {
        address newOwner = address(0x1E01);

        // Step 1: Current owner initiates transfer
        vm.prank(owner);
        verifierContract.transferOwnership(newOwner);
        assertEq(verifierContract.pendingOwner(), newOwner);
        // Owner has not changed yet
        assertEq(verifierContract.owner(), owner);

        // Step 2: New owner accepts
        vm.prank(newOwner);
        verifierContract.acceptOwnership();
        assertEq(verifierContract.owner(), newOwner);
        assertEq(verifierContract.pendingOwner(), address(0));
    }

    function test_acceptOwnership_revertsForNonPendingOwner() public {
        address newOwner = address(0x1E02);
        address imposter = address(0xBAD);

        vm.prank(owner);
        verifierContract.transferOwnership(newOwner);

        // Imposter tries to accept — should revert
        vm.prank(imposter);
        vm.expectRevert("Not pending owner");
        verifierContract.acceptOwnership();
    }

    function test_transferOwnership_revertsForNonOwner() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(ProofOfClawVerifier.Unauthorized.selector);
        verifierContract.transferOwnership(address(0x123));
    }

    function test_transferOwnership_revertsForZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert("Zero address");
        verifierContract.transferOwnership(address(0));
    }

    // --- Zero-address rejection in registerAgent -----------------------------

    function test_registerAgent_revertsForZeroWallet() public {
        bytes32 agentId = keccak256("agent-zero-wallet");
        vm.prank(owner);
        vm.expectRevert("Zero agent wallet");
        verifierContract.registerAgent(agentId, keccak256("policy"), 1 ether, address(0));
    }

    // --- Duplicate agentId rejection -----------------------------------------

    function test_registerAgent_revertsDuplicateAgentId() public {
        bytes32 agentId = keccak256("agent-dup-id");
        bytes32 policyHash = keccak256("policy-dup-id");

        vm.prank(owner);
        verifierContract.registerAgent(agentId, policyHash, 1 ether, agentWallet);

        // Try to register another agent with the same agentId — should revert
        vm.prank(owner);
        vm.expectRevert(ProofOfClawVerifier.AgentAlreadyExists.selector);
        verifierContract.registerAgent(agentId, keccak256("other-policy"), 2 ether, address(0xBEEF));
    }

    // --- Action expiry -------------------------------------------------------

    function test_actionExpiry_approvableBeforeExpiry() public {
        DummyTarget target = new DummyTarget();
        vm.startPrank(owner);
        verifierContract.setAllowedTarget(address(target), true);

        bytes32 agentId = keccak256("agent-expiry-ok");
        bytes32 policyHash = keccak256("policy-expiry-ok");
        bytes32 outputCommitment = keccak256("output-expiry-ok");
        verifierContract.registerAgent(agentId, policyHash, 1 ether, agentWallet);
        vm.stopPrank();

        bytes memory action = abi.encode(address(target), uint256(0), abi.encodeCall(DummyTarget.ping, ()));

        ProofOfClawVerifier.VerifiedOutput memory output = ProofOfClawVerifier.VerifiedOutput({
            agentId: "agent-expiry-ok",
            policyHash: policyHash,
            outputCommitment: outputCommitment,
            allChecksPassed: true,
            requiresLedgerApproval: true,
            actionValue: 1 ether
        });

        verifierContract.verifyAndExecute(hex"00", abi.encode(output), action);

        // Warp to just before expiry (23 hours) — should still work
        vm.warp(block.timestamp + 23 hours);

        (uint8 v, bytes32 r, bytes32 s) = _signApproval(agentId, outputCommitment, 1 ether);
        vm.prank(owner);
        verifierContract.approveAction(agentId, outputCommitment, action, v, r, s);

        assertTrue(target.pinged());
    }

    function test_actionExpiry_revertsAfterExpiry() public {
        bytes32 agentId = keccak256("agent-expiry-fail");
        bytes32 policyHash = keccak256("policy-expiry-fail");
        bytes32 outputCommitment = keccak256("output-expiry-fail");
        vm.prank(owner);
        verifierContract.registerAgent(agentId, policyHash, 1 ether, agentWallet);

        ProofOfClawVerifier.VerifiedOutput memory output = ProofOfClawVerifier.VerifiedOutput({
            agentId: "agent-expiry-fail",
            policyHash: policyHash,
            outputCommitment: outputCommitment,
            allChecksPassed: true,
            requiresLedgerApproval: true,
            actionValue: 1 ether
        });

        verifierContract.verifyAndExecute(hex"00", abi.encode(output), hex"");

        // Warp past the 24h expiry
        vm.warp(block.timestamp + 25 hours);

        (uint8 v, bytes32 r, bytes32 s) = _signApproval(agentId, outputCommitment, 1 ether);
        vm.prank(owner);
        vm.expectRevert(ProofOfClawVerifier.ActionExpired.selector);
        verifierContract.approveAction(agentId, outputCommitment, hex"", v, r, s);
    }
}

// ===========================================================================
// ProofOfClawINFT — safeTransferFrom & Enumeration Tests
// ===========================================================================

contract MockERC721Receiver {
    bytes4 public constant MAGIC = bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"));
    bool public received;
    bool public shouldReject;

    function setReject(bool _reject) external { shouldReject = _reject; }

    function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4) {
        if (shouldReject) return bytes4(0xdeadbeef);
        received = true;
        return MAGIC;
    }
}

contract RejectingReceiver {
    // No onERC721Received — will cause revert
}

contract ProofOfClawINFTSafeTransferTest is Test {
    ProofOfClawINFT inft;
    MockERC721Receiver receiver;
    RejectingReceiver rejector;
    address alice = address(0xA1);
    address bob = address(0xB0B);

    bytes32 constant AGENT_ID = keccak256("safe-agent-1");
    bytes32 constant POLICY = keccak256("policy-1");
    bytes32 constant IMAGE_ID_INFT = bytes32(uint256(0x1234));
    bytes32 constant META_HASH = keccak256("metadata");
    bytes32 constant SOUL_HASH = keccak256("soul-backup");

    function setUp() public {
        inft = new ProofOfClawINFT(address(0xF1));
        receiver = new MockERC721Receiver();
        rejector = new RejectingReceiver();
    }

    function _mint(bytes32 agentId, string memory ensName) internal returns (uint256) {
        vm.prank(alice);
        return inft.mint(agentId, POLICY, IMAGE_ID_INFT, "0g://enc", META_HASH, SOUL_HASH, "0g://soul", ensName);
    }

    // --- safeTransferFrom to EOA succeeds ---
    function test_safeTransferFrom_toEOA() public {
        uint256 tokenId = _mint(AGENT_ID, "safe1.proofofclaw.eth");
        vm.prank(alice);
        inft.safeTransferFrom(alice, bob, tokenId);
        assertEq(inft.ownerOf(tokenId), bob);
    }

    // --- safeTransferFrom to valid receiver contract succeeds ---
    function test_safeTransferFrom_toValidReceiver() public {
        uint256 tokenId = _mint(AGENT_ID, "safe2.proofofclaw.eth");
        vm.prank(alice);
        inft.safeTransferFrom(alice, address(receiver), tokenId);
        assertEq(inft.ownerOf(tokenId), address(receiver));
        assertTrue(receiver.received());
    }

    // --- safeTransferFrom to rejecting contract reverts ---
    function test_safeTransferFrom_toRejectingContractReverts() public {
        uint256 tokenId = _mint(AGENT_ID, "safe3.proofofclaw.eth");
        vm.prank(alice);
        vm.expectRevert(ProofOfClawINFT.TransferToNonReceiver.selector);
        inft.safeTransferFrom(alice, address(rejector), tokenId);
    }

    // --- safeTransferFrom with data ---
    function test_safeTransferFrom_withData() public {
        uint256 tokenId = _mint(AGENT_ID, "safe4.proofofclaw.eth");
        vm.prank(alice);
        inft.safeTransferFrom(alice, address(receiver), tokenId, "hello");
        assertTrue(receiver.received());
    }

    // --- safeTransferFrom to receiver returning wrong magic reverts ---
    function test_safeTransferFrom_wrongMagicReverts() public {
        uint256 tokenId = _mint(AGENT_ID, "safe5.proofofclaw.eth");
        receiver.setReject(true);
        vm.prank(alice);
        vm.expectRevert(ProofOfClawINFT.TransferToNonReceiver.selector);
        inft.safeTransferFrom(alice, address(receiver), tokenId);
    }

    // --- mintTo validates receiver on contract addresses ---
    function test_mintTo_toValidReceiver() public {
        vm.prank(alice);
        uint256 tokenId = inft.mintTo(address(receiver), keccak256("mint-recv"), POLICY, IMAGE_ID_INFT, "0g://enc", META_HASH, SOUL_HASH, "0g://soul", "mintrx.proofofclaw.eth");
        assertEq(inft.ownerOf(tokenId), address(receiver));
        assertTrue(receiver.received());
    }

    function test_mintTo_toRejectingContractReverts() public {
        vm.prank(alice);
        vm.expectRevert(ProofOfClawINFT.TransferToNonReceiver.selector);
        inft.mintTo(address(rejector), keccak256("mint-rej"), POLICY, IMAGE_ID_INFT, "0g://enc", META_HASH, SOUL_HASH, "0g://soul", "mintrej.proofofclaw.eth");
    }
}

// ===========================================================================
// ProofOfClawINFT — Owner Enumeration Tests
// ===========================================================================

contract ProofOfClawINFTEnumerationTest is Test {
    ProofOfClawINFT inft;
    address alice = address(0xA1);
    address bob = address(0xB0B);

    bytes32 constant POLICY = keccak256("policy-1");
    bytes32 constant IMAGE_ID_INFT = bytes32(uint256(0x1234));
    bytes32 constant META_HASH = keccak256("metadata");
    bytes32 constant SOUL_HASH = keccak256("soul-backup");

    function setUp() public {
        inft = new ProofOfClawINFT(address(0xF1));
    }

    function _mintAs(address who, bytes32 agentId, string memory ensName) internal returns (uint256) {
        vm.prank(who);
        return inft.mint(agentId, POLICY, IMAGE_ID_INFT, "0g://enc", META_HASH, SOUL_HASH, "0g://soul", ensName);
    }

    function test_tokenOfOwnerByIndex_singleToken() public {
        uint256 tokenId = _mintAs(alice, keccak256("enum-1"), "enum1.proofofclaw.eth");
        assertEq(inft.tokenOfOwnerByIndex(alice, 0), tokenId);
    }

    function test_tokenOfOwnerByIndex_multipleTokens() public {
        uint256 t1 = _mintAs(alice, keccak256("enum-2a"), "enum2a.proofofclaw.eth");
        uint256 t2 = _mintAs(alice, keccak256("enum-2b"), "enum2b.proofofclaw.eth");
        uint256 t3 = _mintAs(alice, keccak256("enum-2c"), "enum2c.proofofclaw.eth");

        assertEq(inft.tokenOfOwnerByIndex(alice, 0), t1);
        assertEq(inft.tokenOfOwnerByIndex(alice, 1), t2);
        assertEq(inft.tokenOfOwnerByIndex(alice, 2), t3);
    }

    function test_tokenOfOwnerByIndex_outOfBoundsReverts() public {
        _mintAs(alice, keccak256("enum-3"), "enum3.proofofclaw.eth");
        vm.expectRevert(ProofOfClawINFT.TokenDoesNotExist.selector);
        inft.tokenOfOwnerByIndex(alice, 1);
    }

    function test_tokensOfOwner() public {
        uint256 t1 = _mintAs(alice, keccak256("enum-4a"), "enum4a.proofofclaw.eth");
        uint256 t2 = _mintAs(alice, keccak256("enum-4b"), "enum4b.proofofclaw.eth");

        uint256[] memory tokens = inft.tokensOfOwner(alice);
        assertEq(tokens.length, 2);
        assertEq(tokens[0], t1);
        assertEq(tokens[1], t2);
    }

    function test_enumeration_updatesOnTransfer() public {
        uint256 t1 = _mintAs(alice, keccak256("enum-5a"), "enum5a.proofofclaw.eth");
        uint256 t2 = _mintAs(alice, keccak256("enum-5b"), "enum5b.proofofclaw.eth");
        uint256 t3 = _mintAs(alice, keccak256("enum-5c"), "enum5c.proofofclaw.eth");

        // Transfer middle token to bob
        vm.prank(alice);
        inft.transferFrom(alice, bob, t2);

        // Alice should have t1 and t3 (swap-and-pop: t3 moved to index 1)
        uint256[] memory aliceTokens = inft.tokensOfOwner(alice);
        assertEq(aliceTokens.length, 2);
        assertEq(aliceTokens[0], t1);
        assertEq(aliceTokens[1], t3);

        // Bob should have t2
        uint256[] memory bobTokens = inft.tokensOfOwner(bob);
        assertEq(bobTokens.length, 1);
        assertEq(bobTokens[0], t2);
    }

    function test_supportsInterface_enumerable() public view {
        assertTrue(inft.supportsInterface(0x780e9d63)); // ERC-721Enumerable
    }
}

// ===========================================================================
// End-to-End Integration: Agent → 0G → RISC Zero → On-Chain Verification
// ===========================================================================

contract EndToEndIntegrationTest is Test {
    // --- Contracts ---
    ProofOfClawVerifier verifierContract;
    ProofOfClawINFT inft;
    EIP8004Integration eip8004;
    MockRiscZeroVerifier mockZkVerifier;
    MockIdentityRegistry identityReg;
    MockReputationRegistry reputationReg;
    MockValidationRegistry validationReg;
    DummyTarget target;

    // --- Actors ---
    uint256 ownerPk = 0xA11CE;
    address owner;
    address agentWallet = address(0xABCD);

    // --- Constants ---
    bytes32 constant AGENT_ID = keccak256("e2e-agent");
    bytes32 constant POLICY_HASH = keccak256("e2e-policy");
    bytes32 constant IMAGE_ID = bytes32(uint256(0xCAFE));
    bytes32 constant META_HASH = keccak256("e2e-metadata");
    bytes32 constant SOUL_HASH = keccak256("e2e-soul");

    function setUp() public {
        owner = vm.addr(ownerPk);

        // Deploy ZK verifier (mock)
        mockZkVerifier = new MockRiscZeroVerifier();

        // Deploy verifier contract
        vm.startPrank(owner);
        verifierContract = new ProofOfClawVerifier(IRiscZeroVerifier(address(mockZkVerifier)), IMAGE_ID);

        // Deploy iNFT contract with verifier as the proof recorder
        inft = new ProofOfClawINFT(address(verifierContract));

        // Deploy EIP-8004 registries
        identityReg = new MockIdentityRegistry();
        reputationReg = new MockReputationRegistry();
        validationReg = new MockValidationRegistry();
        eip8004 = new EIP8004Integration(
            address(identityReg),
            address(reputationReg),
            address(validationReg),
            address(verifierContract)
        );

        // Configure verifier with EIP-8004 integration
        verifierContract.setEIP8004Integration(address(eip8004));

        // Deploy and whitelist execution target
        target = new DummyTarget();
        verifierContract.setAllowedTarget(address(target), true);
        vm.stopPrank();
    }

    /// @notice Full autonomous execution flow:
    ///   1. Register agent identity (EIP-8004)
    ///   2. Mint agent iNFT (ERC-7857)
    ///   3. Register agent policy on-chain
    ///   4. Submit ZK-verified execution (autonomous path)
    ///   5. Verify proof recording on iNFT
    ///   6. Submit reputation feedback
    function test_e2e_autonomousExecution() public {
        // ── Step 1: Register agent in EIP-8004 Identity Registry ─────────
        vm.prank(owner);
        uint256 eip8004TokenId = eip8004.registerAgentIdentity(
            AGENT_ID,
            "0g://agent-registration.json",
            POLICY_HASH,
            IMAGE_ID
        );
        assertEq(eip8004TokenId, 1);
        assertEq(eip8004.agentRegistrant(AGENT_ID), owner);

        // ── Step 2: Mint iNFT into agent wallet ─────────────────────────
        vm.prank(owner);
        uint256 inftTokenId = inft.mintTo(
            agentWallet,
            AGENT_ID,
            POLICY_HASH,
            IMAGE_ID,
            "0g://encrypted-metadata",
            keccak256("plaintext-metadata"),
            SOUL_HASH,
            "0g://soul-backup.yaml",
            "e2e-agent.proofofclaw.eth"
        );
        assertEq(inft.ownerOf(inftTokenId), agentWallet);
        assertEq(inft.balanceOf(agentWallet), 1);
        assertEq(inft.tokenOfOwnerByIndex(agentWallet, 0), inftTokenId);

        // ── Step 3: Register agent policy on verifier ───────────────────
        vm.prank(owner);
        verifierContract.registerAgent(AGENT_ID, POLICY_HASH, 10 ether, agentWallet);

        // ── Step 4: Simulate ZK-verified autonomous execution ───────────
        //   In production: agent runs inference via 0G Compute, builds
        //   ExecutionTrace, uploads to 0G Storage, generates RISC Zero
        //   proof via Boundless, and submits on-chain.
        bytes memory action = abi.encode(
            address(target),
            uint256(0),
            abi.encodeCall(DummyTarget.ping, ())
        );

        ProofOfClawVerifier.VerifiedOutput memory output = ProofOfClawVerifier.VerifiedOutput({
            agentId: "e2e-agent",
            policyHash: POLICY_HASH,
            outputCommitment: keccak256(action),
            allChecksPassed: true,
            requiresLedgerApproval: false,
            actionValue: 0
        });

        bytes memory journalData = abi.encode(output);
        vm.prank(agentWallet);
        verifierContract.verifyAndExecute(hex"00", journalData, action);

        // Verify action was executed
        assertTrue(target.pinged());

        // Verify EIP-8004 validation was recorded
        assertEq(validationReg.responseCount(), 1);

        // ── Step 5: Record proof on iNFT ────────────────────────────────
        //   In production the verifier contract would call this automatically.
        //   Here we simulate since the verifier address is the contract itself.
        vm.prank(address(verifierContract));
        inft.recordProof(inftTokenId);

        ProofOfClawINFT.AgentINFT memory agent = inft.getAgent(inftTokenId);
        assertEq(agent.totalProofs, 1);

        // ── Step 6: Submit reputation feedback ──────────────────────────
        address reviewer = address(0xBEEF);
        vm.prank(reviewer);
        eip8004.submitReputation(
            AGENT_ID,
            95,
            0,
            "policyCompliance",
            "swap",
            "/v1/chat/completions",
            "0g://feedback",
            keccak256("feedback-data")
        );
        assertEq(reputationReg.feedbackCount(), 1);

        // ── Step 7: Verify reputation query works ───────────────────────
        address[] memory reviewers = new address[](0);
        (uint64 count, int128 value,) = eip8004.getAgentReputation(AGENT_ID, reviewers, "", "");
        assertEq(count, 5); // From mock
        assertEq(value, 85); // From mock
    }

    /// @notice Full Ledger-gated execution flow:
    ///   1. Register agent + submit high-value action requiring approval
    ///   2. Owner signs EIP-712 approval via Ledger
    ///   3. Action executes after approval
    function test_e2e_ledgerGatedExecution() public {
        // Register agent
        vm.prank(owner);
        verifierContract.registerAgent(AGENT_ID, POLICY_HASH, 1 ether, agentWallet);

        // Submit high-value action requiring Ledger approval
        bytes memory action = abi.encode(
            address(target),
            uint256(0),
            abi.encodeCall(DummyTarget.ping, ())
        );
        bytes32 outputCommitment = keccak256("high-value-output");

        ProofOfClawVerifier.VerifiedOutput memory output = ProofOfClawVerifier.VerifiedOutput({
            agentId: "e2e-agent",
            policyHash: POLICY_HASH,
            outputCommitment: outputCommitment,
            allChecksPassed: true,
            requiresLedgerApproval: true,
            actionValue: 5 ether
        });

        verifierContract.verifyAndExecute(hex"00", abi.encode(output), action);
        assertFalse(target.pinged()); // Not yet executed

        // Owner approves via EIP-712 signature (simulates Ledger signing)
        bytes32 domainSeparator = keccak256(abi.encode(
            verifierContract.DOMAIN_TYPEHASH(),
            keccak256("ProofOfClaw"),
            keccak256("1"),
            block.chainid,
            address(verifierContract)
        ));
        bytes32 structHash = keccak256(abi.encode(
            verifierContract.APPROVAL_TYPEHASH(),
            AGENT_ID,
            outputCommitment,
            5 ether
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);

        vm.prank(owner);
        verifierContract.approveAction(AGENT_ID, outputCommitment, action, v, r, s);

        assertTrue(target.pinged()); // Now executed after Ledger approval
    }

    /// @notice Test iNFT lifecycle: mint → update metadata → update soul → transfer → enumerate
    function test_e2e_inftLifecycle() public {
        // Mint
        vm.prank(owner);
        uint256 tokenId = inft.mintTo(
            agentWallet,
            AGENT_ID,
            POLICY_HASH,
            IMAGE_ID,
            "0g://v1-metadata",
            keccak256("v1-meta"),
            SOUL_HASH,
            "0g://v1-soul",
            "lifecycle.proofofclaw.eth"
        );

        // Agent evolves — update metadata
        vm.prank(agentWallet);
        inft.updateMetadata(tokenId, "0g://v2-metadata", keccak256("v2-meta"));
        assertEq(inft.tokenURI(tokenId), "0g://v2-metadata");

        // Agent undergoes reassembly — update soul backup
        vm.prank(agentWallet);
        inft.updateSoulBackup(tokenId, keccak256("evolved-soul"), "0g://v2-soul");
        (bytes32 soulHash, string memory soulURI) = inft.getSoulBackup(tokenId);
        assertEq(soulHash, keccak256("evolved-soul"));
        assertEq(keccak256(bytes(soulURI)), keccak256(bytes("0g://v2-soul")));

        // Authorize an executor
        vm.prank(agentWallet);
        inft.authorizeUsage(tokenId, address(0xE1EC), "inference,delegation");
        assertTrue(inft.isAuthorized(tokenId, address(0xE1EC)));

        // Transfer ownership to a new wallet
        vm.prank(agentWallet);
        inft.transferFrom(agentWallet, owner, tokenId);
        assertEq(inft.ownerOf(tokenId), owner);

        // Enumeration updated correctly
        assertEq(inft.tokensOfOwner(agentWallet).length, 0);
        assertEq(inft.tokensOfOwner(owner).length, 1);
        assertEq(inft.tokenOfOwnerByIndex(owner, 0), tokenId);

        // Approval cleared on transfer
        assertEq(inft.getApproved(tokenId), address(0));
    }

    /// @notice Test that the full proof pipeline records correctly:
    ///   multiple proofs → reputation update → iNFT state reflects all
    function test_e2e_multipleProofsAndReputation() public {
        // Setup: mint iNFT
        vm.prank(owner);
        uint256 tokenId = inft.mintTo(
            agentWallet,
            AGENT_ID,
            POLICY_HASH,
            IMAGE_ID,
            "0g://enc",
            META_HASH,
            SOUL_HASH,
            "0g://soul",
            "multi.proofofclaw.eth"
        );

        // Record 5 proofs
        for (uint256 i = 0; i < 5; i++) {
            vm.prank(address(verifierContract));
            inft.recordProof(tokenId);
        }

        ProofOfClawINFT.AgentINFT memory agent = inft.getAgent(tokenId);
        assertEq(agent.totalProofs, 5);

        // Update reputation via verifier
        vm.prank(address(verifierContract));
        inft.updateReputation(tokenId, 98);
        assertEq(inft.getAgent(tokenId).reputationScore, 98);
    }
}

// ===========================================================================
// Helpers
// ===========================================================================

contract DummyTarget {
    bool public pinged;

    function ping() external {
        pinged = true;
    }
}
