# Proof of Claw Architecture

## System Components

### 1. Agent Runtime (Rust)

The core agent is written in Rust and consists of:

#### Core Components
- **Proof Agent** (`agent/src/proof_agent.rs`) — Main agent struct wrapping IronClaw adapter, proof generator, and shared API state
- **Intent Router** (`agent/src/core/intent_router.rs`) — Classifies incoming messages into actionable intents (swap, transfer, query)
- **Configuration** (`agent/src/core/config.rs`) — Environment-based configuration with validation (rejects zero private keys, normalizes zero addresses to None)
- **Types** (`agent/src/core/types.rs`) — Core data structures (ExecutionTrace, AgentMessage, ToolInvocation, PolicyResult)

#### API Layer
- **REST API** (`agent/src/api.rs`) — Axum-based HTTP server on port 8420 with CORS support
  - `GET /health` — Health check
  - `GET /api/status` — Agent status, policy hash, stats
  - `POST /api/chat` — Full processing pipeline: intent routing → policy check → proof generation → response
  - `GET /api/activity` — Activity feed
  - `GET /api/proofs` — Proof history
  - `GET /api/messages` — Message records
  - `POST /api/messages/send` — Send DM3 message
- **Shared State** (`Arc<RwLock<AgentState>>`) — Thread-safe state shared between API handlers and agent runtime

#### Tools System
- **Tool Registry** (`agent/src/tools/registry.rs`) — Manages available tools with SHA256 capability hashes
- **WASM Sandbox** (`agent/src/tools/sandbox.rs`) — Wasmtime-based isolated execution; looks for `run` or `_start` exports

#### Safety Layer
- **Policy Engine** (`agent/src/safety/policy_engine.rs`) — Enforces tool allowlist, value thresholds, endpoint restrictions
- **Injection Detector** (`agent/src/safety/injection_detector.rs`) — Regex-based prompt injection detection (case-insensitive)

#### Integrations
- **0G Compute** (`agent/src/integrations/zero_g.rs`) — HTTP POST to 0G endpoint with real attestation extraction (falls back to SHA256 content hash)
- **0G Storage** (`agent/src/integrations/zero_g.rs`) — Trace upload/retrieval with content-addressable root hashes
- **ENS + DM3** (`agent/src/integrations/ens_dm3.rs`) — On-chain ENS namehash computation, text record resolution (3-tier: ENS → HTTP → fallback), DM3 encrypted messaging
- **Ledger** (`agent/src/integrations/ledger.rs`) — Hardware approval gate (currently stub — returns Ok(true))
- **EIP-8004** (`agent/src/integrations/eip8004.rs`) — Identity registration, reputation queries, validation history via eth_call/send_transaction
- **iNFT** (`agent/src/integrations/inft.rs`) — ERC-7857 agent identity minting with encrypted metadata on 0G Storage

#### Proof Generation
- **Proof Generator** (`agent/src/proof_generator.rs`) — Supports Boundless (remote), local RISC Zero, and mock (dev) backends
- **IronClaw Adapter** (`agent/src/ironclaw_adapter.rs`) — Converts IronClaw execution traces into Proof of Claw format

### 2. RISC Zero zkVM

#### Guest Program (`zkvm/guest/src/main.rs`)
Runs inside the zkVM to verify:
- Tool invocations match allowed list
- All policy checks passed
- Action value vs autonomous threshold
- Outputs policy hash and approval requirement

#### Host Program (`zkvm/host/src/main.rs`)
Orchestrates proof generation:
- Builds execution environment
- Submits to Boundless proving network
- Returns verifiable receipt

### 3. Smart Contracts (Solidity)

All contracts are deployed and verified on **0G Galileo Testnet** (chain 16602).

#### ProofOfClawVerifier (`contracts/src/ProofOfClawVerifier.sol`)
- Agent registration with policy commitment
- RISC Zero proof verification
- Autonomous vs Ledger-gated execution routing
- Optional EIP-8004 validation recording
- **Deployed:** `0xa2Df3F3998FdF9Fb7E11e43d10d6B3C62264e3A4`

#### EIP8004Integration (`contracts/src/EIP8004Integration.sol`)
- Bridges Proof of Claw with EIP-8004 identity, reputation, and validation registries
- Maps agent IDs to ERC-721 token IDs

#### ProofOfClawINFT (`contracts/src/ProofOfClawINFT.sol`)
- ERC-7857 iNFT for agent identity
- Minting, proof recording, reputation syncing
- Usage authorization grants
- **Deployed:** `0xDe61e80Cdc7ba0000d9eB9040e59f98A3C9991a3`

#### SoulVaultSwarm (`contracts/src/SoulVaultSwarm.sol`)
- Epoch-based swarm coordination with key rotation
- Membership management (join requests, approvals)
- On-chain agent file mappings and manifests
- Inter-agent messaging with sequence numbers
- **Deployed:** `0xa70EB0DF1563708F28285C2DeA2BF31aadFB544D`

#### SoulVaultERC8004RegistryAdapter (`contracts/src/SoulVaultERC8004RegistryAdapter.sol`)
- Self-sovereign agent identity registry (no admin gating)
- Maps agent IDs to wallet addresses and metadata
- Reverse lookup: wallet to owned agents
- **Deployed:** `0x9De4F1b14660B5f8145a78Cfc0312B1BFb812C46`

#### RiscZeroMockVerifier (`contracts/src/RiscZeroMockVerifier.sol`)
- Testnet-only mock that accepts all proofs
- Implements `IRiscZeroVerifier` interface
- **Deployed:** `0x93e985aCA4112771c0B05114Ad99677DB85a6A9e`
- **Warning:** Replace with real RISC Zero verifier for mainnet

#### Clear Signing Metadata (`contracts/clear-signing/proofofclaw.json`)
ERC-7730 metadata for human-readable Ledger display

### 4. Frontend (Vanilla HTML/CSS/JS)

#### Pages
- **agents.html** — Agent registry with deployment wizard, inline chat drawer, profile editor with editable permissions, reconnect/update flow
- **dashboard.html** — Live monitoring dashboard; polls API every 3 seconds when connected, falls back to static view otherwise
- **messages.html** — DM3 message threads between agents
- **proofs.html** — ZK proof explorer with policy check details
- **index.html** — Landing page with architecture overview

#### Libraries
- **poc-api.js** — API client: connect, disconnect, fetch status/activity/proofs/messages, connection badge UI
- **ens-resolver.js** — On-chain ENS resolution with full keccak256 implementation, namehash, text record lookups, agent discovery

## Data Flow

### Chat Message Flow (POST /api/chat)

1. User sends message from frontend chat drawer
2. API handler parses message into `AgentMessage` with action parameters
3. `IntentRouter` classifies intent (swap, transfer, query, unknown)
4. `PolicyEngine` checks tool allowlist and value thresholds
5. Handler generates contextual response text based on intent + policy result
6. `ExecutionTrace` built from the interaction
7. `ProofGenerator` generates ZK proof (mock in dev, Boundless in prod)
8. User message, agent response, and proof recorded in `AgentState`
9. Response returned with intent info, policy result, and proof metadata

### Autonomous Action Flow

1. Agent receives message (user chat or DM3)
2. Intent router classifies action
3. 0G Compute performs private inference (with attestation)
4. Safety layer validates against policy
5. Tool execution in WASM sandbox
6. Execution trace stored on 0G Storage
7. RISC Zero proof generated via Boundless
8. Agent wallet submits proof + action to verifier contract
9. Contract verifies proof and executes action

### Ledger-Gated Action Flow

1–7. Same as autonomous flow
8. RISC Zero proof indicates approval required
9. Contract emits `ApprovalRequired` event
10. Web UI alerts owner
11. Owner reviews on Ledger device (Clear Signing)
12. Owner physically approves
13. Ledger signs `approveAction()` transaction
14. Contract executes action

### Inter-Agent Messaging Flow

1. Agent A resolves Agent B's ENS name (on-chain namehash + text records)
2. Retrieves B's DM3 profile (encryption key, delivery service)
3. Verifies B's policy via `proofclaw.imageId` text record
4. Encrypts message with B's public key
5. Sends to B's delivery service
6. B receives, decrypts, evaluates against policy
7. B responds via same encrypted channel

### Reconnect Flow

1. Agent goes offline (process killed, network issue)
2. User opens chat drawer → sees "Agent Offline" with saved run command
3. User restarts agent with the saved command
4. Clicks **Reconnect** → PocAPI pings last known URL
5. On success: chat goes LIVE, messages resume
6. On failure: shows error, offers **Update Config** to change URL/settings

## Security Boundaries

### Trust Assumptions
- **Trusted**: Ledger device, RISC Zero verifier, 0G infrastructure
- **Untrusted**: Agent server, tool code, LLM responses, inter-agent messages

### Isolation Layers
1. **WASM Sandbox** — Tools run in isolated Wasmtime environment
2. **Inference Attestation** — 0G Compute responses include attestation signatures
3. **ZK Proof** — Agent behavior proven without revealing private data
4. **Ledger Approval** — Physical confirmation for high-value actions
5. **Policy Engine** — Tool allowlist + value threshold enforcement in proven trace

## State Management

### Backend (Rust)
- `AgentState` in `Arc<RwLock<>>` — shared between API handlers and agent runtime
- Records proofs, messages, activity, stats
- Seeded with initial activity items on startup

### Frontend (localStorage)
- `poc_agents` — Array of registered agent objects
- `poc_connection` — Active connection state (URL, agentId, ENS)
- `poc_agent_config_{id}` — Per-agent run command, secrets, last URL (for reconnect)
- `poc_chat_{id}` — Per-agent chat history (capped at 200 messages)

## Performance Characteristics

- **API Response**: <10ms for status/activity/proofs
- **Chat Processing**: ~50-100ms (intent routing + policy check + proof generation)
- **0G Inference**: ~1-5s per LLM call (depending on model)
- **0G Storage**: ~100-500ms per trace upload
- **RISC Zero Proof**: ~30s-2min via Boundless (mock is instant)
- **On-chain Verification**: ~50-100k gas per proof verification
- **Frontend Polling**: Dashboard polls every 3 seconds when connected
