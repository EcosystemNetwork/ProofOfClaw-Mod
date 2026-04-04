# Proof of Claw — Specification

**Provable Private Agent Framework**

---

## 1. Overview

Proof of Claw is a framework for running autonomous AI agents whose behavior is cryptographically provable, whose communication is end-to-end encrypted, and whose high-value actions require human approval via hardware signing.

An agent built with Proof of Claw can:

- Reason privately using decentralized inference (0G Compute)
- Store persistent memory and execution traces on decentralized storage (0G Storage)
- Discover and message other agents via ENS-resolved encrypted channels (DM3)
- Prove to any on-chain verifier that it followed its declared policy (RISC Zero zkVM)
- Route high-value or out-of-policy actions to its owner's Ledger device for physical approval (Ledger DMK + Clear Signing)

The core agent runtime is adapted from IronClaw (github.com/nearai/ironclaw), a Rust-based OpenClaw reimplementation with WASM-sandboxed tool execution, capability-based permissions, and defense-in-depth security.

---

## 2. Target Bounties

| Sponsor | Track | Prize | Integration Surface |
|---------|-------|-------|---------------------|
| **0G** | Best OpenClaw Agent on 0G | $6,000 | 0G Compute (inference), 0G Storage (memory + traces) |
| **ENS** | Best ENS Integration for AI Agents | $5,000 | ENS subnames for agent identity, DM3 for encrypted inter-agent messaging |
| **Ledger** | AI Agents x Ledger | $6,000 | Ledger DMK/DSK for human-in-the-loop approval, Clear Signing metadata (ERC-7730) |


---

## 3. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     PROOF OF CLAW AGENT                         │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                  Agent Core (from IronClaw)                │  │
│  │  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐  │  │
│  │  │ Agent Loop   │  │ Tool Registry │  │ Safety Layer    │  │  │
│  │  │ (reasoning)  │  │ (WASM sandbox)│  │ (policy engine) │  │  │
│  │  └──────┬───────┘  └──────┬───────┘  └────────┬────────┘  │  │
│  └─────────┼─────────────────┼────────────────────┼───────────┘  │
│            │                 │                    │               │
│  ┌─────────▼─────────────────▼────────────────────▼───────────┐  │
│  │                    Integration Layer                        │  │
│  │                                                             │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │  │
│  │  │ 0G Compute   │  │ 0G Storage   │  │ ENS + DM3        │  │  │
│  │  │ (inference)  │  │ (memory +    │  │ (identity +      │  │  │
│  │  │              │  │  exec traces)│  │  agent messaging) │  │  │
│  │  └──────────────┘  └──────────────┘  └──────────────────┘  │  │
│  │                                                             │  │
│  │  ┌──────────────┐  ┌──────────────────────────────────────┐│  │
│  │  │ RISC Zero    │  │ Ledger Approval Gate                 ││  │
│  │  │ (prove policy│  │ (DMK + Clear Signing for             ││  │
│  │  │  compliance) │  │  high-value actions)                 ││  │
│  │  └──────────────┘  └──────────────────────────────────────┘│  │
│  │                                                             │  │
│  │  ┌──────────────────────────────────────────────────────┐  │  │
│  │  │ EIP-8004 Trustless Agents                            │  │  │
│  │  │ (Identity Registry + Reputation + Validation)        │  │  │
│  │  └──────────────────────────────────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                              │                                    │
│                    ┌─────────▼──────────┐                         │
│                    │   On-Chain Layer    │                         │
│                    │  - ZK Verifier     │                         │
│                    │  - Policy Registry │                         │
│                    │  - Agent Vault     │                         │
│                    │  - ENS Resolver    │                         │
│                    │  - EIP-8004 Regs   │                         │
│                    └────────────────────┘                         │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Components

### 4.1 Agent Core (adapted from IronClaw)

The runtime is a stripped-down fork of IronClaw's agent loop, retaining:

- **Agent Loop** — Message handling, intent routing, job coordination. Receives user instructions or inter-agent DM3 messages, classifies intent, dispatches to the appropriate tool or reasoning chain.
- **WASM Tool Sandbox** — Untrusted tools run in isolated Wasmtime containers with capability-based permissions. Each tool declares its `CapabilitiesFile` (allowed endpoints, required secrets, rate limits). The sandbox pipeline: allowlist validation → leak scan (request) → credential injection → execute → leak scan (response).
- **Safety Layer** — Prompt injection defense, content sanitization, policy enforcement. Pattern detection with severity levels (Block / Warn / Sanitize). This layer's execution becomes part of the provable trace.
- **Tool Registry** — Registry of built-in, WASM, and MCP tools. Tool metadata (capabilities, permissions) is hashed and committed on-chain as the agent's policy fingerprint.

**What we strip:** Database layer (replaced by 0G Storage), LLM provider abstraction (replaced by 0G Compute), channel system (replaced by DM3). We keep the core execution pipeline, safety layer, and WASM sandbox.

### 4.2 0G Integration

#### 4.2.1 0G Compute — Private Inference

All LLM reasoning runs through 0G's Sealed Inference infrastructure. Prompts enter encrypted; the operator cannot inspect them. Every response is cryptographically signed.

```typescript
import { createZGServingNetworkBroker } from '@0glabs/0g-serving-broker';

// Initialize broker with agent's wallet
const broker = await createZGServingNetworkBroker(wallet);
await broker.initialize();

// Discover verified inference providers
const services = await broker.inference.listService();
const provider = services.find(s => s.verifiability === 'verified');

// Acknowledge provider on-chain (one-time)
await broker.inference.acknowledgeProviderSigner(provider.provider);

// Get service metadata and auth headers
const { endpoint, model } = await broker.inference.getServiceMetadata(provider.provider);
const headers = await broker.inference.getRequestHeaders(provider.provider, prompt);

// OpenAI-compatible inference call
const response = await fetch(`${endpoint}/chat/completions`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', ...headers },
  body: JSON.stringify({
    messages: [{ role: 'system', content: agentPolicy }, { role: 'user', content: prompt }],
    model,
  }),
});

// Verify attestation on the signed response
const verified = await broker.inference.verifyResponse(response);
```

The attestation signature on each inference response serves as a commitment that can later be referenced in the RISC Zero proof — proving the agent acted on a genuinely attested LLM output, not a tampered one.

#### 4.2.2 0G Storage — Persistent Memory and Execution Traces

Agent memory (conversation history, workspace files, identity preferences) and execution traces (tool invocations, policy check results, timestamps) are stored on 0G's decentralized storage network.

```typescript
import { ZgFile, Indexer } from '@0glabs/0g-ts-sdk';
import { ethers } from 'ethers';

const indexer = new Indexer(INDEXER_RPC);
const signer = new ethers.Wallet(AGENT_PRIVATE_KEY, provider);

// Store execution trace
async function storeExecutionTrace(trace: ExecutionTrace): Promise<string> {
  const data = JSON.stringify(trace);
  const file = await ZgFile.fromBuffer(Buffer.from(data), 'trace.json');
  const [tx, err] = await indexer.upload(file, RPC_URL, signer);
  if (err) throw new Error(`Upload failed: ${err}`);
  const [tree] = await file.merkleTree();
  await file.close();
  return tree.rootHash(); // Content-addressable root hash
}

// Retrieve trace by root hash
async function retrieveTrace(rootHash: string): Promise<ExecutionTrace> {
  const stream = await indexer.downloadFileAsStream(rootHash);
  // ... reconstruct ExecutionTrace from stream
}
```

**Execution Trace Schema:**

```typescript
interface ExecutionTrace {
  agentId: string;                    // ENS name
  sessionId: string;                  // Unique session identifier
  timestamp: number;                  // Unix timestamp
  inferenceCommitment: string;        // Hash of 0G Compute signed response
  toolInvocations: ToolInvocation[];  // Ordered list of tool calls
  policyCheckResults: PolicyResult[]; // Safety layer outputs
  outputCommitment: string;           // Hash of final agent output / action
}

interface ToolInvocation {
  toolName: string;
  inputHash: string;      // keccak256 of tool input
  outputHash: string;     // keccak256 of tool output
  capabilityHash: string; // Hash of the tool's CapabilitiesFile
  timestamp: number;
  withinPolicy: boolean;  // Did this invocation pass the safety layer?
}

interface PolicyResult {
  ruleId: string;
  severity: 'Block' | 'Warn' | 'Sanitize' | 'Pass';
  details: string;
}
```

The 0G Storage root hash of each trace becomes the input to the RISC Zero prover — allowing anyone to verify that the proven execution trace matches what was actually stored.

### 4.3 ENS + DM3 — Agent Identity and Encrypted Messaging

#### 4.3.1 ENS Identity

Each agent registers as a subname under the project's ENS name:

```
alice-agent.proofofclaw.eth
bob-agent.proofofclaw.eth
```

ENS text records store agent metadata:

| Record Key | Value | Purpose |
|------------|-------|---------|
| `eth.dm3.profile` | DM3 profile data URI | Encryption keys + delivery service URL |
| `proofclaw.imageId` | RISC Zero image ID (hex) | Commitment to the agent's verified policy program |
| `proofclaw.policyHash` | keccak256 of policy JSON | Fingerprint of declared capabilities |
| `proofclaw.storageEndpoint` | 0G Storage indexer URL | Where this agent's traces are stored |
| `avatar` | Agent avatar URI | Visual identity |
| `description` | Agent description | Human-readable purpose statement |
| `proofclaw.eip8004AgentId` | `eip155:{chainId}:{registry}:{tokenId}` | Cross-reference to EIP-8004 Identity Registry |

Agent discovery flow:

1. Resolve `bob-agent.proofofclaw.eth` via ENS
2. Read `proofclaw.imageId` to verify the agent runs a known policy program
3. Read `eth.dm3.profile` to get Bob's encryption public key and delivery service URL
4. Read `proofclaw.policyHash` to check the agent's declared capabilities match expectations
5. Read `proofclaw.eip8004AgentId` to look up the agent's reputation and validation history in EIP-8004 registries

#### 4.3.2 DM3 Inter-Agent Messaging

Agents communicate via DM3's end-to-end encrypted messaging protocol. Each agent runs a lightweight DM3-compatible client that:

1. **Publishes its dm3 profile** as an ENS text record (encryption public key, signing public key, delivery service URL)
2. **Resolves other agents' profiles** by querying their ENS names
3. **Encrypts messages** with the recipient's public encryption key
4. **Signs messages** with its own signing key
5. **Delivers messages** to the recipient's delivery service via the DM3 WebSocket API

```typescript
import { createDeliveryServiceProfile, createEnvelop } from '@dm3-org/dm3-lib';

// Agent initialization — generate DM3 keys and profile
const { deliveryServiceProfile, keys } = await createDeliveryServiceProfile(
  'https://ds.proofofclaw.eth' // Our delivery service endpoint
);

// Publish profile to ENS text record
await ensContract.setText(
  namehash('alice-agent.proofofclaw.eth'),
  'eth.dm3.profile',
  toDataURI(deliveryServiceProfile)
);

// Send encrypted message to another agent
async function sendAgentMessage(recipientEns: string, message: AgentMessage) {
  // 1. Resolve recipient's DM3 profile from ENS
  const recipientProfile = await resolveDm3Profile(recipientEns);

  // 2. Create encrypted envelope
  const { encryptedEnvelope } = await createEnvelop(
    JSON.stringify(message),
    keys.signingKey,
    recipientProfile.publicEncryptionKey,
    recipientProfile.deliveryServiceUrl
  );

  // 3. Submit to recipient's delivery service
  const rpcRequest = createJsonRpcCallSubmitMessage(encryptedEnvelope);
  await fetch(recipientProfile.deliveryServiceUrl, {
    method: 'POST',
    body: JSON.stringify(rpcRequest),
  });
}
```

**Agent Message Protocol:**

Inter-agent messages use a structured schema for negotiation and coordination:

```typescript
interface AgentMessage {
  type: 'propose' | 'accept' | 'reject' | 'execute' | 'verify';
  payload: {
    action: string;           // e.g., "swap_tokens", "share_data", "joint_execution"
    params: Record<string, unknown>;
    traceRootHash?: string;   // 0G Storage root hash for verifiable context
    proofReceipt?: string;    // RISC Zero receipt for proven behavior
    requiredApproval?: boolean; // Whether this action needs Ledger approval
  };
  nonce: number;
  timestamp: number;
}
```

Example flow — two agents negotiating a token swap:

1. Alice's agent sends `{ type: 'propose', payload: { action: 'swap_tokens', params: { give: '100 USDC', receive: '0.04 ETH' } } }`
2. Bob's agent evaluates the proposal against its policy, responds with `{ type: 'accept' }` or `{ type: 'reject', payload: { reason: 'price outside tolerance' } }`
3. If accepted and the value exceeds the autonomous threshold, both agents route to their respective Ledger devices for human approval
4. Upon dual approval, both agents execute and publish RISC Zero proofs of correct execution

### 4.4 RISC Zero — Provable Policy Compliance

The core innovation: the agent's tool execution pipeline runs inside a RISC Zero zkVM guest program, producing a cryptographic receipt that anyone can verify on-chain.

#### 4.4.1 What Gets Proven

The zkVM guest program encodes a deterministic state machine that verifies:

1. **Inference commitment** — The LLM response the agent acted on matches an attested hash from 0G Compute
2. **Policy compliance** — Every tool invocation was within the agent's declared capabilities (endpoint allowlist, rate limits, permission bounds)
3. **Safety layer execution** — The prompt injection defense and content sanitization rules actually ran
4. **Output integrity** — The final action the agent proposes matches the deterministic output of the policy-checked execution

#### 4.4.2 Guest Program (Rust, compiled to RISC-V)

```rust
// guest/src/main.rs — runs inside RISC Zero zkVM
#![no_main]
risc0_zkvm::guest::entry!(main);

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct ExecutionTrace {
    agent_id: String,
    inference_commitment: [u8; 32],
    tool_invocations: Vec<ToolInvocation>,
    policy_check_results: Vec<PolicyResult>,
    output_commitment: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct AgentPolicy {
    allowed_tools: Vec<String>,
    endpoint_allowlist: Vec<String>,
    max_value_autonomous: u64, // Wei threshold for autonomous execution
    capability_root: [u8; 32], // Merkle root of tool capabilities
}

#[derive(Serialize, Deserialize)]
struct VerifiedOutput {
    agent_id: String,
    policy_hash: [u8; 32],
    output_commitment: [u8; 32],
    all_checks_passed: bool,
    requires_ledger_approval: bool,
    action_value: u64,
}

fn main() {
    // Read private inputs from host (never revealed)
    let trace: ExecutionTrace = risc0_zkvm::guest::env::read();
    let policy: AgentPolicy = risc0_zkvm::guest::env::read();

    // 1. Verify each tool invocation against policy
    let mut all_passed = true;
    for invocation in &trace.tool_invocations {
        // Check tool is in allowed list
        if !policy.allowed_tools.contains(&invocation.tool_name) {
            all_passed = false;
        }
        // Check endpoint was in allowlist
        // (simplified — real impl checks full URL pattern matching)
        if !invocation.within_policy {
            all_passed = false;
        }
    }

    // 2. Verify safety layer ran and passed
    for result in &trace.policy_check_results {
        if matches!(result.severity, PolicySeverity::Block) {
            all_passed = false;
        }
    }

    // 3. Determine if Ledger approval is required
    let requires_approval = trace.action_value() > policy.max_value_autonomous;

    // 4. Compute policy hash for on-chain verification
    let policy_hash = keccak256(&serde_json::to_vec(&policy).unwrap());

    // 5. Write verified output to journal (public)
    let output = VerifiedOutput {
        agent_id: trace.agent_id.clone(),
        policy_hash,
        output_commitment: trace.output_commitment,
        all_checks_passed: all_passed,
        requires_ledger_approval: requires_approval,
        action_value: trace.action_value(),
    };

    risc0_zkvm::guest::env::commit(&output);
}
```

#### 4.4.3 Host Program — Remote Proving via Boundless

Instead of running a local GPU prover, we use **Boundless** — RISC Zero's decentralized proving marketplace (live on Base mainnet). The agent submits a proof request to Boundless, a network of permissionless provers competes to generate the proof, and the result is settled on-chain. This takes the proof generation burden off the agent entirely.

```rust
// host/src/main.rs — submits proof request to Boundless
use risc0_zkvm::ExecutorEnv;
use boundless_sdk::{BoundlessClient, ProofRequest};

async fn request_proof(
    trace: &ExecutionTrace,
    policy: &AgentPolicy,
    boundless: &BoundlessClient,
) -> Receipt {
    // 1. Build the execution environment (same as local proving)
    let env = ExecutorEnv::builder()
        .write(trace).unwrap()
        .write(policy).unwrap()
        .build()
        .unwrap();

    // 2. Submit proof request to Boundless marketplace
    //    Provers on the network compete to generate the ZK proof
    let request = ProofRequest::new(GUEST_ELF, env)
        .with_image_id(GUEST_ID)
        .with_max_price(/* ZKC budget for this proof */);

    let proof_id = boundless.submit(request).await.unwrap();

    // 3. Poll for completion (typically seconds to low minutes)
    let receipt = boundless.wait_for_proof(proof_id).await.unwrap();

    // 4. Receipt is already verified by the Boundless network
    //    and can be submitted directly to on-chain verifier
    receipt
}
```

**Why Boundless over local proving:**

- No GPU required on the agent's machine — proof generation is outsourced to the network
- Proof cost is ~$0.30–$30 depending on computation complexity (vs. thousands on-chain)
- Boundless settles the Groth16 proof on the destination chain, so the agent just submits the receipt
- The Boundless Foundry Template provides a minimal integration scaffold for Solidity contracts
- Hundreds of active provers on the network with high availability

#### 4.4.4 On-Chain Verifier (Solidity)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";

contract ProofOfClawVerifier {
    IRiscZeroVerifier public immutable verifier;
    bytes32 public immutable imageId; // Commitment to the guest program

    // Agent registry
    mapping(bytes32 => AgentPolicy) public agents; // agentId => policy

    struct AgentPolicy {
        bytes32 policyHash;
        uint256 maxValueAutonomous;
        address owner;           // Ledger-controlled EOA
        address agentWallet;     // Server wallet for autonomous actions
    }

    struct VerifiedOutput {
        string agentId;
        bytes32 policyHash;
        bytes32 outputCommitment;
        bool allChecksPassed;
        bool requiresLedgerApproval;
        uint256 actionValue;
    }

    event ActionVerified(string agentId, bytes32 outputCommitment, bool autonomous);
    event ApprovalRequired(string agentId, bytes32 outputCommitment, uint256 value);

    constructor(IRiscZeroVerifier _verifier, bytes32 _imageId) {
        verifier = _verifier;
        imageId = _imageId;
    }

    function registerAgent(
        bytes32 agentId,
        bytes32 policyHash,
        uint256 maxValueAutonomous,
        address agentWallet
    ) external {
        agents[agentId] = AgentPolicy({
            policyHash: policyHash,
            maxValueAutonomous: maxValueAutonomous,
            owner: msg.sender,   // Must be called from Ledger
            agentWallet: agentWallet
        });
    }

    /// @notice Verify agent behavior and execute action if within policy
    function verifyAndExecute(
        bytes calldata seal,
        bytes calldata journalData,
        bytes calldata action
    ) external {
        // 1. Verify the RISC Zero proof
        verifier.verify(seal, imageId, sha256(journalData));

        // 2. Decode the verified output
        VerifiedOutput memory output = abi.decode(journalData, (VerifiedOutput));

        // 3. Check policy hash matches registered agent
        bytes32 agentId = keccak256(bytes(output.agentId));
        require(agents[agentId].policyHash == output.policyHash, "Policy mismatch");
        require(output.allChecksPassed, "Policy checks failed");

        if (output.requiresLedgerApproval) {
            // Queue for Ledger approval
            emit ApprovalRequired(output.agentId, output.outputCommitment, output.actionValue);
        } else {
            // Execute autonomously
            require(msg.sender == agents[agentId].agentWallet, "Unauthorized");
            _executeAction(action);
            emit ActionVerified(output.agentId, output.outputCommitment, true);
        }
    }

    /// @notice Owner (Ledger) approves a queued action
    function approveAction(bytes32 agentId, bytes32 outputCommitment, bytes calldata action) external {
        require(msg.sender == agents[agentId].owner, "Not owner");
        _executeAction(action);
        emit ActionVerified(string(abi.encodePacked(agentId)), outputCommitment, false);
    }

    function _executeAction(bytes calldata action) internal {
        // Decode and execute the action (swap, transfer, vote, etc.)
        (address target, uint256 value, bytes memory data) = abi.decode(action, (address, uint256, bytes));
        (bool success,) = target.call{value: value}(data);
        require(success, "Action execution failed");
    }
}
```

### 4.6 EIP-8004 — Trustless Agent Discovery, Reputation, and Validation

EIP-8004 (Trustless Agents) provides three standardized on-chain registries that enable cross-organizational agent discovery and trust establishment without pre-existing relationships. Proof of Claw integrates all three registries to complement its existing ENS identity and RISC Zero proof systems.

#### 4.6.1 Identity Registry — Standardized Agent Cards

While ENS provides human-readable names (`alice-agent.proofofclaw.eth`), the EIP-8004 Identity Registry provides a standardized, machine-readable agent identity layer built on ERC-721. Each Proof of Claw agent mints an ERC-721 identity token and publishes a structured registration file containing its capabilities, endpoints, and trust metadata.

```typescript
import { ethers } from 'ethers';

const identityRegistry = new ethers.Contract(IDENTITY_REGISTRY_ADDRESS, IDENTITY_ABI, signer);

// Register agent with URI pointing to registration file
const agentURI = 'ipfs://Qm.../alice-agent-registration.json';
const tx = await identityRegistry.register(agentURI, [
  { metadataKey: 'ensName', metadataValue: ethers.toUtf8Bytes('alice-agent.proofofclaw.eth') },
  { metadataKey: 'policyHash', metadataValue: policyHash },
  { metadataKey: 'riscZeroImageId', metadataValue: imageId },
]);
const receipt = await tx.wait();
const agentId = receipt.logs[0].args.agentId; // ERC-721 tokenId
```

**Registration File** (hosted on IPFS or 0G Storage):

```json
{
  "type": "https://eips.ethereum.org/EIPS/eip-8004#registration-v1",
  "name": "alice-agent.proofofclaw.eth",
  "description": "Autonomous trading agent with Ledger-gated high-value approvals. Policy-compliant execution proven via RISC Zero.",
  "image": "ipfs://Qm.../alice-agent-avatar.png",
  "services": [
    {
      "name": "ENS",
      "endpoint": "alice-agent.proofofclaw.eth"
    },
    {
      "name": "DM3",
      "endpoint": "wss://ds.proofofclaw.eth/alice-agent",
      "version": "1.0"
    },
    {
      "name": "MCP",
      "endpoint": "https://alice-agent.proofofclaw.eth/mcp",
      "version": "2025-03-26",
      "skills": ["swap_tokens", "query_price", "manage_portfolio"]
    }
  ],
  "x402Support": false,
  "active": true,
  "registrations": [
    {
      "agentId": 42,
      "agentRegistry": "eip155:11155111:0x<IDENTITY_REGISTRY_ADDRESS>"
    }
  ],
  "supportedTrust": ["reputation", "validation-zk"]
}
```

**Agent Discovery Flow (EIP-8004 enhanced):**

1. Querying agent discovers `bob-agent.proofofclaw.eth` via ENS *or* browses the EIP-8004 Identity Registry for agents with specific capabilities
2. Reads the agent's `agentURI` registration file to learn its services, skills, and supported trust models
3. Checks the Reputation Registry for Bob's on-chain trust score
4. Checks the Validation Registry for Bob's RISC Zero proof history
5. If trust thresholds are met, initiates DM3 encrypted communication

This enables agents from *different* organizations to discover and evaluate each other — not just agents within the `proofofclaw.eth` namespace.

#### 4.6.2 Reputation Registry — On-Chain Trust Signals

After successful interactions (verified by RISC Zero proofs), agents and users submit on-chain feedback to build a reputation layer. The Reputation Registry provides structured, filterable feedback with tags that map to Proof of Claw's domain.

```typescript
const reputationRegistry = new ethers.Contract(REPUTATION_REGISTRY_ADDRESS, REPUTATION_ABI, signer);

// After a successful, proven interaction with an agent:
await reputationRegistry.giveFeedback(
  bobAgentId,           // EIP-8004 agent tokenId
  95,                   // value: 95/100 quality score
  0,                    // valueDecimals
  'policyCompliance',   // tag1: domain-specific tag
  'swap',               // tag2: action type
  'wss://ds.proofofclaw.eth/bob-agent',  // endpoint evaluated
  'ipfs://Qm.../feedback-detail.json', // feedbackURI with proof receipt
  feedbackHash          // keccak256 commitment
);

// Query agent reputation before engaging
const [count, summaryValue, decimals] = await reputationRegistry.getSummary(
  bobAgentId,
  trustedReviewers,     // Filter by trusted reviewer addresses
  'policyCompliance',   // Filter by tag
  ''                    // No tag2 filter
);
```

**Feedback Tags for Proof of Claw:**

| tag1 | tag2 | Measurement | Example |
|------|------|-------------|---------|
| `policyCompliance` | action type | % of actions that passed RISC Zero verification | 99/100 |
| `successRate` | tool name | % of tool invocations that succeeded | 87/100 |
| `responseTime` | — | Median response time in ms | 560 |
| `safetyScore` | — | % of interactions with no safety layer blocks | 100/100 |
| `ledgerApproval` | — | % of Ledger-gated actions approved by owner | 92/100 |

**Off-chain Feedback File** (linked via `feedbackURI`):

```json
{
  "agentRegistry": "eip155:11155111:0x<IDENTITY_REGISTRY_ADDRESS>",
  "agentId": 42,
  "clientAddress": "eip155:11155111:0x<REVIEWER_ADDRESS>",
  "createdAt": "2026-04-03T10:30:00Z",
  "value": 95,
  "valueDecimals": 0,
  "tag1": "policyCompliance",
  "tag2": "swap",
  "endpoint": "wss://ds.proofofclaw.eth/bob-agent",
  "proofOfPayment": {
    "fromAddress": "0x...",
    "toAddress": "0x...",
    "chainId": "11155111",
    "txHash": "0x..."
  }
}
```

Reputation scores feed back into the agent's decision-making: before engaging with an unknown agent, the safety layer queries the Reputation Registry and enforces minimum trust thresholds defined in the agent's policy.

#### 4.6.3 Validation Registry — RISC Zero Proofs as Validator Attestations

The Validation Registry is the natural on-chain home for RISC Zero proof verification results. When an agent's execution proof is verified on-chain, the `ProofOfClawVerifier` contract records the result in the Validation Registry, creating a permanent, queryable record of proven behavior.

```typescript
const validationRegistry = new ethers.Contract(VALIDATION_REGISTRY_ADDRESS, VALIDATION_ABI, signer);

// Agent (or its owner) requests validation by submitting trace data
const requestHash = ethers.keccak256(ethers.toUtf8Bytes(JSON.stringify(traceData)));
await validationRegistry.validationRequest(
  PROOF_OF_CLAW_VERIFIER_ADDRESS,  // validatorAddress: our verifier contract
  agentTokenId,                     // EIP-8004 agentId
  traceStorageURI,                  // requestURI: 0G Storage URI of the execution trace
  requestHash                       // commitment to the trace data
);

// After RISC Zero proof verification, the verifier contract responds:
// (called internally by ProofOfClawVerifier after successful proof verification)
await validationRegistry.validationResponse(
  requestHash,          // matches the request
  100,                  // response: 100 = full pass (0-100 scale)
  proofReceiptURI,      // responseURI: where the proof receipt is stored
  responseHash,         // keccak256 of the proof receipt
  'risc-zero-zkvm'      // tag: validation method
);

// Query an agent's validation history
const [validatorAddr, agentId, response, respHash, tag, lastUpdate] =
  await validationRegistry.getValidationStatus(requestHash);

// Get aggregate validation stats
const [count, avgResponse] = await validationRegistry.getSummary(
  agentTokenId,
  [PROOF_OF_CLAW_VERIFIER_ADDRESS],  // filter by our verifier
  'risc-zero-zkvm'                    // filter by validation type
);
```

**Validation Flow Integration:**

1. Agent completes an execution → trace stored on 0G Storage
2. Agent calls `validationRequest()` on the Validation Registry, referencing the 0G Storage URI
3. Agent submits proof to Boundless → RISC Zero proof generated
4. Agent calls `verifyAndExecute()` on `ProofOfClawVerifier`
5. Upon successful verification, `ProofOfClawVerifier` calls `validationResponse()` with `response=100`
6. If verification fails, `validationResponse()` is called with `response=0`
7. Any external auditor can independently verify traces and submit their own validation responses

This creates a publicly auditable record: anyone can query the Validation Registry to see how many of an agent's executions have been proven correct, by which validators, and with what success rate.

#### 4.6.4 Bridging ENS and EIP-8004

ENS and EIP-8004 are complementary, not competing:

| Concern | ENS | EIP-8004 |
|---------|-----|----------|
| Human-readable name | `alice-agent.proofofclaw.eth` | — |
| Machine-readable identity | ENS text records | Registration file + on-chain metadata |
| Cross-org discovery | Limited to ENS namespace | Global registry, any agent can register |
| Reputation | — | Structured feedback with tags |
| Proof history | — | Validation Registry records |
| Ownership | ENS owner | ERC-721 token holder |

The agent's EIP-8004 registration file includes its ENS name as a service endpoint, and the ENS text record `proofclaw.eip8004AgentId` points back to the EIP-8004 token ID. This bidirectional linking ensures that agents discoverable via ENS are also discoverable via the global EIP-8004 registry, and vice versa.

```
ENS text record:
  proofclaw.eip8004AgentId → "eip155:11155111:0x<REGISTRY>:42"

EIP-8004 registration file:
  services: [{ name: "ENS", endpoint: "alice-agent.proofofclaw.eth" }]
```

---

### 4.5 Ledger — Human-in-the-Loop Approval

When the RISC Zero proof determines an action exceeds the agent's autonomous threshold (`requiresLedgerApproval == true`), the action is routed to the owner's Ledger device.

#### 4.5.1 Two-Tier Trust Model

| Tier | Condition | Signing | Verification |
|------|-----------|---------|--------------|
| **Autonomous** | Action value < threshold | Agent server wallet | RISC Zero proof verified on-chain |
| **Ledger-gated** | Action value ≥ threshold, or out-of-policy escalation | Owner's Ledger device | RISC Zero proof + Ledger physical approval |

#### 4.5.2 Ledger Integration (DMK + DSK)

```typescript
import { DeviceManagementKitBuilder, ConsoleLogger } from '@ledgerhq/device-management-kit';
import { webHidTransportFactory } from '@ledgerhq/device-transport-kit-web-hid';
import { SignerEthBuilder } from '@ledgerhq/device-signer-kit-ethereum';

// Initialize Ledger DMK
const dmk = new DeviceManagementKitBuilder()
  .addLogger(new ConsoleLogger())
  .addTransport(webHidTransportFactory)
  .build();

// Connect to Ledger device
const discoveredDevices = await dmk.startDiscovering();
const sessionId = await dmk.connect({ deviceId: discoveredDevices[0].id });

// Initialize Ethereum signer with Clear Signing
const signerEth = new SignerEthBuilder({
  dmk,
  sessionId,
  originToken: LEDGER_ORIGIN_TOKEN,
}).build();

// When agent requests Ledger approval:
async function requestLedgerApproval(
  agentAction: AgentAction,
  proofReceipt: RiscZeroReceipt
): Promise<string> {
  // Build the on-chain transaction
  const tx = {
    to: PROOF_OF_CLAW_VERIFIER_ADDRESS,
    data: encodeApproveAction(
      agentAction.agentId,
      agentAction.outputCommitment,
      agentAction.encodedAction
    ),
    value: '0x0',
    chainId: CHAIN_ID,
  };

  // Sign with Ledger — Clear Signing displays human-readable info:
  //   "Approve agent action: alice-agent.proofofclaw.eth
  //    Action: Swap 500 USDC → ETH on Uniswap
  //    Policy proof: Verified ✓
  //    Value: 500.00 USDC"
  const signature = await signerEth.signTransaction(tx);
  return signature;
}
```

#### 4.5.3 Clear Signing Metadata (ERC-7730)

We create a Clear Signing JSON metadata file for the `ProofOfClawVerifier` contract so that Ledger devices display human-readable information when approving agent actions:

```json
{
  "$schema": "https://erc7730.org/schema.json",
  "context": {
    "eip155": {
      "deployments": [
        {
          "chainId": 1,
          "address": "0x<VERIFIER_CONTRACT_ADDRESS>"
        }
      ]
    }
  },
  "metadata": {
    "owner": "Proof of Claw",
    "info": {
      "url": "https://proofofclaw.eth",
      "legalName": "Proof of Claw"
    }
  },
  "display": {
    "formats": {
      "approveAction(bytes32,bytes32,bytes)": {
        "intent": "Approve agent action",
        "fields": [
          {
            "path": "agentId",
            "label": "Agent",
            "format": "raw"
          },
          {
            "path": "outputCommitment",
            "label": "Action hash",
            "format": "raw"
          }
        ]
      },
      "registerAgent(bytes32,bytes32,uint256,address)": {
        "intent": "Register agent policy",
        "fields": [
          {
            "path": "policyHash",
            "label": "Policy fingerprint",
            "format": "raw"
          },
          {
            "path": "maxValueAutonomous",
            "label": "Auto-approve up to",
            "format": "amount",
            "params": { "tokenPath": null }
          },
          {
            "path": "agentWallet",
            "label": "Agent wallet",
            "format": "addressName"
          }
        ]
      }
    }
  }
}
```

This metadata file is submitted to the Clear Signing Registry via pull request so that any Ledger device automatically renders these transactions in plain language.

---

## 5. User Flows

### 5.1 Agent Setup

1. Owner connects Ledger to Proof of Claw web UI
2. Owner deploys an agent: picks an ENS subname (`my-agent.proofofclaw.eth`), sets policy parameters (allowed tools, spending limits, autonomous threshold)
3. `registerAgent()` is called from the Ledger (owner = Ledger EOA)
4. Agent mints an EIP-8004 identity token and publishes its registration file (capabilities, endpoints, trust models) to IPFS/0G Storage
5. Agent's DM3 profile, RISC Zero image ID, policy hash, and EIP-8004 agent ID are published as ENS text records
6. Agent starts: connects to 0G Compute for inference, 0G Storage for memory

### 5.2 Autonomous Action (within policy)

1. Agent receives task (user instruction or DM3 message from another agent)
2. Agent reasons via 0G Compute (Sealed Inference)
3. Agent executes tools in WASM sandbox, safety layer checks each invocation
4. Execution trace is stored on 0G Storage (returns root hash)
5. Agent submits proof request to Boundless (decentralized proving marketplace); network provers generate the RISC Zero proof
6. Agent's server wallet submits `verifyAndExecute()` with the proof + action
7. On-chain verifier checks proof, executes action, records result in EIP-8004 Validation Registry

### 5.3 Ledger-Gated Action (exceeds threshold)

1. Steps 1–5 same as above
2. RISC Zero proof indicates `requiresLedgerApproval == true`
3. Agent emits `ApprovalRequired` event on-chain
4. Web UI alerts owner, shows pending action with proof details
5. Owner reviews on Ledger device (Clear Signing shows: agent name, action type, value, proof status)
6. Owner physically presses approve on Ledger
7. Ledger signs `approveAction()` transaction, action executes

### 5.4 Inter-Agent Negotiation

1. Alice's agent wants to coordinate with Bob's agent
2. Alice's agent discovers Bob via ENS *or* EIP-8004 Identity Registry search
3. Queries Bob's EIP-8004 Reputation Registry for trust score — rejects if below policy threshold
4. Queries Bob's EIP-8004 Validation Registry for RISC Zero proof history — verifies proven track record
5. Reads Bob's DM3 profile (encryption key, delivery service URL)
6. Reads Bob's `proofclaw.imageId` to verify Bob runs a known policy program
7. Sends encrypted `propose` message via DM3
8. Bob's agent evaluates proposal against its policy (including Alice's EIP-8004 reputation)
9. Bob's agent responds via DM3 (`accept` / `reject` / `counter`)
10. If accepted and value exceeds either agent's threshold, both route to their Ledger devices
11. Upon dual approval, both agents execute and publish RISC Zero proofs
12. Both agents submit mutual feedback to the EIP-8004 Reputation Registry

---

## 6. Repository Structure

```
proof-of-claw/
├── agent/                      # Agent runtime (adapted from IronClaw)
│   ├── src/
│   │   ├── core/               # Agent loop, intent router, job scheduler
│   │   ├── tools/              # WASM sandbox, tool registry, capability validation
│   │   ├── safety/             # Policy engine, prompt injection defense
│   │   ├── integrations/
│   │   │   ├── zero_g.rs       # 0G Compute + Storage client
│   │   │   ├── ens_dm3.rs      # ENS resolution + DM3 messaging
│   │   │   ├── eip8004.rs      # EIP-8004 Identity, Reputation, Validation client
│   │   │   └── ledger.rs       # Ledger approval gate (triggers web UI)
│   │   └── main.rs
│   └── Cargo.toml
│
├── zkvm/                       # RISC Zero programs
│   ├── guest/
│   │   └── src/main.rs         # zkVM guest — policy verification logic
│   ├── host/
│   │   └── src/main.rs         # Host — proof generation orchestration
│   └── Cargo.toml
│
├── contracts/                  # On-chain contracts
│   ├── src/
│   │   ├── ProofOfClawVerifier.sol   # Main verifier + agent registry
│   │   ├── EIP8004Integration.sol    # EIP-8004 registry adapter (identity, reputation, validation)
│   │   └── interfaces/
│   ├── clear-signing/
│   │   └── proofofclaw.json    # ERC-7730 Clear Signing metadata
│   ├── script/
│   │   └── Deploy.s.sol
│   └── foundry.toml
│
├── web/                        # Web UI (Next.js)
│   ├── src/
│   │   ├── app/
│   │   │   ├── dashboard/      # Agent management, trace viewer
│   │   │   ├── approve/        # Ledger approval interface
│   │   │   └── messages/       # DM3 message viewer
│   │   ├── hooks/
│   │   │   ├── useLedger.ts    # Ledger DMK/DSK integration
│   │   │   ├── use0G.ts        # 0G SDK hooks
│   │   │   ├── useDM3.ts       # DM3 messaging hooks
│   │   │   └── useEIP8004.ts   # EIP-8004 registry hooks (identity, reputation, validation)
│   │   └── lib/
│   │       ├── ens.ts          # ENS resolution + text record management
│   │       ├── eip8004.ts      # EIP-8004 registry interactions
│   │       └── proof.ts        # RISC Zero proof submission
│   └── package.json
│
├── delivery-service/           # DM3 delivery service node
│   ├── src/
│   │   └── server.ts           # WebSocket server for agent message relay
│   └── package.json
│
└── README.md
```

---

## 7. Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Agent runtime | Rust (from IronClaw) | Core agent loop, WASM sandbox, safety layer |
| Inference | 0G Compute SDK (`@0glabs/0g-serving-broker`) | Decentralized private LLM inference |
| Storage | 0G Storage SDK (`@0glabs/0g-ts-sdk`) | Persistent memory, execution trace storage |
| Identity | ENS (ethers.js / viem) | Agent naming, metadata, discovery |
| Trust layer | EIP-8004 (Trustless Agents) | Cross-org agent discovery, on-chain reputation, validation records |
| Messaging | DM3 (`@dm3-org/dm3-lib`) | End-to-end encrypted inter-agent communication |
| ZK Proofs | RISC Zero zkVM (`risc0-zkvm`) + **Boundless** (remote proving marketplace) | Provable policy compliance; proof generation outsourced to decentralized prover network |
| Hardware signing | Ledger DMK/DSK (`@ledgerhq/device-management-kit`, `@ledgerhq/device-signer-kit-ethereum`) | Human-in-the-loop approval |
| Clear Signing | ERC-7730 JSON metadata | Human-readable transaction display on Ledger |
| Smart contracts | Solidity (Foundry) | On-chain verifier, agent registry, policy enforcement |
| Web UI | Next.js + TypeScript | Dashboard, approval interface, message viewer |

---

## 8. Demo Scenario

Two agents negotiate and execute a token swap:

1. **Alice** deploys `alice.proofofclaw.eth` with a policy: allowed to swap up to 100 USDC autonomously, anything above requires Ledger approval. Mints EIP-8004 identity token with registration file.
2. **Bob** deploys `bob.proofofclaw.eth` with similar policy. Mints EIP-8004 identity token.
3. Alice's agent discovers Bob via ENS or EIP-8004 Identity Registry, checks Bob's reputation score and validation history
4. Alice initiates DM3 encrypted negotiation
5. They agree on a 500 USDC swap (above both thresholds)
6. Both agents submit proof requests to Boundless; provers on the network generate RISC Zero proofs of policy compliance
7. Proof results are recorded in the EIP-8004 Validation Registry
8. Both owners see the pending approval on their Ledger devices with Clear Signing
9. Both press approve — swap executes on-chain with verified proofs
10. Both agents submit mutual reputation feedback to the EIP-8004 Reputation Registry

---

## 9. Security Model

| Threat | Mitigation |
|--------|-----------|
| Agent acts outside declared policy | RISC Zero proof fails verification; action blocked on-chain |
| Inference tampering | 0G Sealed Inference provides attestation; response signature included in proof |
| Inter-agent message interception | DM3 end-to-end encryption; keys derived from ENS-published profiles |
| Agent identity spoofing | ENS ownership tied to Ledger-controlled EOA; subname registration requires owner signature |
| High-value action without consent | Ledger physical approval required for actions above autonomous threshold |
| Prompt injection via agent messages | IronClaw safety layer (pattern detection, content sanitization) runs in proven execution trace |
| Server wallet compromise | Server wallet can only execute actions with valid RISC Zero proofs; high-value actions still need Ledger |
| Sybil agents / fake reputation | EIP-8004 Reputation Registry enables filtering by trusted reviewers; validation history provides cryptographic proof of past behavior |
| Engaging with unverified agents | EIP-8004 Validation Registry queried before interaction; agents without proven track record are rejected by policy |

---

## 10. Future Extensions

- **Steel zkCoprocessor** — Prove historical on-chain state within the zkVM (e.g., verify oracle prices, check collateral ratios) without trusting the agent's local state
- **Multi-agent DAOs** — Agents collectively govern a treasury, with each agent's vote proven via RISC Zero and aggregate decisions requiring M-of-N Ledger approvals
- **0G iNFTs (ERC-7857)** — Mint agents as iNFTs with ownership, composability, and automatic royalty splits
- **Cross-chain execution** — Agents operating across multiple chains via DM3 messaging + chain-specific RISC Zero verifiers
- **Policy marketplace** — Publish and share verified policy programs (RISC Zero image IDs) so users can deploy agents with audited, proven behavior templates
- **EIP-8004 reputation-gated execution** — Agents autonomously adjust trust thresholds based on counterparty reputation history, enabling fully trustless multi-agent coordination without human review of each counterparty
- **EIP-8004 validator networks** — Third-party auditors independently re-execute agent traces and submit validation responses, creating a decentralized audit layer beyond the agent's own RISC Zero proofs
- **WrapSynth integration** — Agents managing wsXMR vaults with provable collateral ratio maintenance and Ledger-gated liquidation overrides
