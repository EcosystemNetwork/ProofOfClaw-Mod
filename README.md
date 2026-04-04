# Proof of Claw

**Provable Private Agent Framework**

> Autonomous AI agents with cryptographically provable behavior, end-to-end encrypted communication, and hardware-signed human approval.

---

## Overview

Proof of Claw is a framework for running autonomous AI agents whose behavior is cryptographically provable, whose communication is end-to-end encrypted, and whose high-value actions require human approval via hardware signing.

The core agent runtime is adapted from [IronClaw](https://github.com/nearai/ironclaw), a Rust-based OpenClaw reimplementation with WASM-sandboxed tool execution, capability-based permissions, and defense-in-depth security.

### Key Features

- **Private Inference** — Decentralized LLM reasoning via 0G Compute
- **Decentralized Storage** — Persistent memory and execution traces on 0G Storage
- **Encrypted Messaging** — Inter-agent communication via DM3 with ENS identity resolution
- **Provable Compliance** — RISC Zero zkVM proofs of policy adherence, verified on-chain via Boundless
- **Hardware Approval** — Ledger DMK/DSK integration with ERC-7730 Clear Signing for high-value actions
- **WASM Sandbox** — Untrusted tools execute in isolated Wasmtime containers with capability-based permissions
- **Swarm Protocol** — Multi-agent coordination and discovery via Swarm network
- **Trustless Discovery** — EIP-8004 agent identity, reputation, and validation registries

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     PROOF OF CLAW AGENT                         │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              Agent Core — IronClaw Runtime                 │  │
│  │  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐  │  │
│  │  │ Agent Loop   │  │ Tool Registry │  │ Safety Layer    │  │  │
│  │  │ (reasoning)  │  │ (WASM sandbox)│  │ (policy engine) │  │  │
│  │  └──────┬───────┘  └──────┬───────┘  └────────┬────────┘  │  │
│  └─────────┼─────────────────┼────────────────────┼───────────┘  │
│            │                 │                    │               │
│  ┌─────────▼─────────────────▼────────────────────▼───────────┐  │
│  │                    Integration Layer                        │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │  │
│  │  │ 0G Compute   │  │ 0G Storage   │  │ ENS + DM3        │  │  │
│  │  │ (inference)  │  │ (traces)     │  │ (identity + msg) │  │  │
│  │  └──────────────┘  └──────────────┘  └──────────────────┘  │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │  │
│  │  │ RISC Zero    │  │ Ledger DMK   │  │ Swarm Protocol   │  │  │
│  │  │ (ZK proofs)  │  │ (approval)   │  │ (coordination)   │  │  │
│  │  └──────────────┘  └──────────────┘  └──────────────────┘  │  │
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

### Two-Tier Trust Model

| Tier | Condition | Signing | Verification |
|------|-----------|---------|-------------|
| **Autonomous** | Action value < threshold | Agent server wallet | RISC Zero proof on-chain |
| **Ledger-Gated** | Value >= threshold or escalation | Owner's Ledger device | RISC Zero + Ledger approval |

## How It Works

1. Agent receives a task (user message or encrypted DM3 message from another agent)
2. Intent router classifies the action
3. 0G Compute performs private inference — prompts stay encrypted
4. Safety layer validates against the agent's declared policy
5. Tool execution happens in a WASM sandbox with capability-based permissions
6. Execution trace is stored on 0G Storage with content-addressable root hashes
7. RISC Zero proof of policy compliance is generated via Boundless
8. Agent submits proof + action to the on-chain verifier contract
9. If value exceeds threshold, Ledger approval is required — owner sees Clear Signing details on device

## Repository Structure

```
proof-of-claw/
├── agent/                      # Rust agent runtime
│   └── src/
│       ├── core/               # Agent loop, intent router, job scheduler
│       ├── tools/              # WASM sandbox, tool registry, capabilities
│       ├── safety/             # Policy engine, sanitizer, injection detector
│       └── integrations/       # 0G, ENS/DM3, Ledger, EIP-8004 integrations
│
├── zkvm/                       # RISC Zero zkVM programs
│   ├── guest/                  # Guest program (policy verification)
│   └── host/                   # Host program (proof generation via Boundless)
│
├── contracts/                  # Solidity smart contracts
│   ├── src/
│   │   ├── ProofOfClawVerifier.sol
│   │   └── EIP8004Integration.sol
│   ├── clear-signing/
│   │   └── proofofclaw.json    # ERC-7730 metadata
│   └── script/Deploy.s.sol
│
├── frontend/                   # Web UI
│   ├── index.html              # Landing page
│   ├── docs.html               # Documentation
│   ├── agents.html             # Agent management
│   ├── dashboard.html          # Monitoring dashboard
│   ├── deploy.html             # Agent deployment
│   ├── messages.html           # DM3 message viewer
│   └── proofs.html             # ZK proof explorer
│
├── spec.md                     # Full technical specification
├── ARCHITECTURE.md             # Detailed architecture docs
└── IRONCLAW_INTEGRATION.md     # IronClaw integration guide
```

## Quick Start

### Prerequisites

- Rust 1.75+
- Foundry (forge, cast)
- RISC Zero toolchain
- Node.js 18+ (for web UI, optional)

### 1. Build the Agent Runtime

```bash
cd agent
cargo build --release
```

### 2. Build RISC Zero Programs

```bash
cd zkvm
cargo build --release
```

### 3. Deploy Smart Contracts

```bash
cd contracts
forge build
forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast
```

### 4. Configure the Agent

Create a `.env` file in the `agent/` directory (see [.env.example](.env.example)):

```env
AGENT_ID=alice-agent
ENS_NAME=alice.proofclaw.eth
PRIVATE_KEY=0x...
RPC_URL=https://eth-sepolia.g.alchemy.com/v2/...
ZERO_G_INDEXER_RPC=https://indexer-storage-testnet.0g.ai
ZERO_G_COMPUTE_ENDPOINT=https://broker-testnet.0g.ai
DM3_DELIVERY_SERVICE_URL=http://localhost:3001
ALLOWED_TOOLS=swap_tokens,transfer,query
MAX_VALUE_AUTONOMOUS_WEI=1000000000000000000
```

### 5. Run the Agent

```bash
cd agent
cargo run
```

## Integrations

| Integration | Purpose | SDK |
|-------------|---------|-----|
| **0G Compute** | Private LLM inference via Sealed Inference | `@0glabs/0g-serving-broker` |
| **0G Storage** | Decentralized execution trace storage | `@0glabs/0g-ts-sdk` |
| **ENS** | Agent identity via subnames (e.g. `alice-agent.proofclaw.eth`) | `ethers.js` |
| **DM3** | End-to-end encrypted inter-agent messaging | `@dm3-org/dm3-lib` |
| **RISC Zero** | ZK proofs of policy compliance | `risc0-zkvm` |
| **Boundless** | Decentralized proof generation network | Boundless SDK |
| **Ledger DMK** | Hardware-gated human approval | `@ledgerhq/device-management-kit` |
| **Ledger DSK** | Ethereum transaction signing | `@ledgerhq/device-signer-kit-ethereum` |
| **EIP-8004** | Trustless agent discovery, reputation, validation | EIP-8004 registries |
| **Swarm Protocol** | Multi-agent coordination and discovery | Swarm SDK |

## Security Model

| Threat | Mitigation |
|--------|-----------|
| Agent acts outside policy | RISC Zero proof fails; action blocked on-chain |
| Inference tampering | 0G Compute attestation; signature in proof |
| Message interception | DM3 end-to-end encryption with keys from ENS profiles |
| Identity spoofing | ENS ownership tied to Ledger EOA |
| High-value action without consent | Physical Ledger approval with Clear Signing display |
| Prompt injection | Safety layer (injection detector + content sanitizer) in proven execution trace |
| Sybil agents / fake reputation | EIP-8004 Reputation Registry filtering by trusted reviewers |
| Engaging unverified agents | EIP-8004 Validation Registry queried before interaction |

## Project Status

### What's Working

| Component | Status | Details |
|-----------|--------|---------|
| **Rust Agent Runtime** | **Compiles, 35/35 tests pass** | Full agent loop, intent router, job scheduler, REST API (Axum on port 8420) |
| **Policy Engine** | **Working** | Tool allowlist enforcement, value threshold checks, severity levels |
| **Injection Detector** | **Working** | Regex-based prompt injection detection with case-insensitive matching |
| **WASM Sandbox** | **Working** | Wasmtime-based isolated execution for untrusted tools |
| **Tool Registry** | **Working** | Content-addressable tool registration with SHA256 capability hashes |
| **0G Compute Integration** | **Working** | HTTP-based inference with attestation extraction, fallback to content hash |
| **0G Storage Integration** | **Working** | Trace upload/retrieval with content-addressable root hashes, graceful degradation |
| **ENS + DM3 Integration** | **Working** | Full namehash computation, on-chain resolution, DM3 profile lookup with 3-tier fallback, encrypted messaging |
| **EIP-8004 Integration** | **Working** | Identity registration, reputation queries, validation history, trust threshold checks |
| **iNFT (ERC-7857)** | **Working** | Agent minting with encrypted metadata on 0G Storage |
| **Proof Generator** | **Working** | Supports Boundless (remote), local RISC Zero, and mock (dev) backends |
| **Smart Contracts** | **Compile successfully** | ProofOfClawVerifier, EIP8004Integration, ProofOfClawINFT — all feature-complete |
| **Deployment Scripts** | **Ready** | Foundry scripts for Sepolia, 0G Testnet, 0G Mainnet |
| **RISC Zero Guest** | **Working** | Real zkVM guest program with policy verification logic |
| **Frontend UI** | **Working** | All 7 pages functional with live API + mock fallback mode |
| **ENS Resolver (JS)** | **Working** | Real on-chain ENS resolution via RPC with multi-network support |
| **API Client (JS)** | **Working** | Real fetch-based client with connection state management |

### What's Stubbed / Incomplete

| Component | Status | What's Missing |
|-----------|--------|---------------|
| **Ledger Approval Gate** | **Stub** | Always returns `Ok(true)` — no actual Ledger device communication (15 lines) |
| **RISC Zero Host** | **Mock data** | Real RISC Zero host program but seeds hardcoded test traces instead of real input |
| **Contract Tests** | **Missing** | Zero Foundry test files — no `test/` directory |
| **ERC-7730 Metadata** | **Partial** | Contract address is `0x000...000` (needs post-deployment update), missing some method formats |
| **ProofOfClawINFT** | **Incomplete ERC-721** | `balanceOf()` is O(n), missing `safeTransferFrom` receiver checks |

### What Needs to Be Done

**High Priority:**
- [ ] Implement Ledger DMK/DSK approval flow (replace stub in `agent/src/integrations/ledger.rs`)
- [ ] Write Foundry contract tests (`contracts/test/`)
- [ ] Wire RISC Zero host to accept real execution traces from the agent
- [ ] Deploy contracts to testnet and update ERC-7730 metadata with real addresses

**Medium Priority:**
- [ ] Add `safeTransferFrom` ERC-721 receiver validation to ProofOfClawINFT
- [ ] Optimize `balanceOf()` with owner-to-tokenIds mapping in ProofOfClawINFT
- [ ] Complete ERC-7730 Clear Signing metadata for all contract methods
- [ ] Add persistent storage for job scheduler (currently in-memory only)
- [ ] End-to-end integration test: agent -> 0G -> RISC Zero -> on-chain verification

**Nice to Have:**
- [ ] Production RISC Zero proof generation via Boundless (currently falls back to mock in dev)
- [ ] Multi-chain deployment scripts and ERC-7730 metadata
- [ ] Agent dashboard real-time WebSocket updates (currently polling)
- [ ] DM3 delivery service node setup and docs
- [ ] IronClaw full integration mode testing

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Agent Runtime | Rust, Tokio, Wasmtime |
| Inference | 0G Compute SDK |
| Storage | 0G Storage SDK |
| Identity | ENS (ethers.js) |
| Trust Layer | EIP-8004 (Trustless Agents) |
| Messaging | DM3 protocol |
| ZK Proofs | RISC Zero zkVM + Boundless |
| Hardware Signing | Ledger DMK/DSK |
| Clear Signing | ERC-7730 metadata |
| Smart Contracts | Solidity (Foundry) |
| Multi-Agent | Swarm Protocol |
| Frontend | Vanilla HTML/CSS/JS |

## Documentation

Full documentation is available at [frontend/docs.html](frontend/docs.html), covering:

- Architecture deep-dive and system design
- Integration guides for each protocol (0G, ENS, DM3, RISC Zero, Ledger)
- Smart contract reference (ProofOfClawVerifier, ERC-7730 Clear Signing)
- Security threat model and safety layer details
- Configuration reference
- Repository structure

See also:
- [spec.md](spec.md) — Full technical specification
- [ARCHITECTURE.md](ARCHITECTURE.md) — Detailed architecture documentation
- [IRONCLAW_INTEGRATION.md](IRONCLAW_INTEGRATION.md) — IronClaw runtime integration guide

## License

MIT
