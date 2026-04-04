# Proof of Claw

**Provable Private Agent Framework**

> Autonomous AI agents with cryptographically provable behavior, end-to-end encrypted communication, and hardware-signed human approval.

---

## Overview

Proof of Claw is a framework for running autonomous AI agents whose behavior is cryptographically provable, whose communication is end-to-end encrypted, and whose high-value actions require human approval via hardware signing.

The core agent runtime is adapted from [IronClaw](https://github.com/nearai/ironclaw), a Rust-based OpenClaw reimplementation with WASM-sandboxed tool execution, capability-based permissions, and defense-in-depth security.

### Key Features

- **Real-Time Chat** — Register an agent, connect it, and chat in real time with proof badges on every response
- **Private Inference** — Decentralized LLM reasoning via 0G Compute
- **Decentralized Storage** — Persistent memory and execution traces on 0G Storage
- **Encrypted Messaging** — Inter-agent communication via DM3 with ENS identity resolution
- **Provable Compliance** — RISC Zero zkVM proofs of policy adherence, verified on-chain via Boundless
- **Hardware Approval** — Ledger DMK/DSK integration with ERC-7730 Clear Signing for high-value actions
- **WASM Sandbox** — Untrusted tools execute in isolated Wasmtime containers with capability-based permissions
- **Trustless Discovery** — EIP-8004 agent identity, reputation, and validation registries
- **Inline Permissions** — Edit agent tools, value limits, and endpoints from the profile modal

## User Flow

### 1. Register an Agent

Open the frontend (`agents.html`) and click **New Agent**. The wizard walks through:

- **Type** — Choose from 10 agent specializations (DeFi Strategist, Security Auditor, etc.)
- **Identity** — Name, ENS subdomain, network (Sepolia, 0G Testnet, etc.)
- **Skills** — Tag capabilities and define a SOUL persona
- **Policy** — Allowed tools, autonomous value limit, endpoint allowlist
- **Secrets** — Private key (optional — demo keypair generated if omitted)

### 2. Start the Agent

The success screen shows the exact `cargo run` command pre-filled with your config. Copy and paste it into a terminal:

```bash
cd agent && \
AGENT_ID=my-agent \
ENS_NAME=my-agent.proofclaw.eth \
PRIVATE_KEY=0x... \
RPC_URL=https://eth-sepolia.g.alchemy.com/v2/... \
ZERO_G_INDEXER_RPC=https://indexer-storage-testnet.0g.ai \
ZERO_G_COMPUTE_ENDPOINT=https://broker-testnet.0g.ai \
DM3_DELIVERY_SERVICE_URL=http://localhost:3001 \
ALLOWED_TOOLS=swap_tokens,transfer,query \
ENDPOINT_ALLOWLIST=https://api.uniswap.org,https://api.0x.org \
MAX_VALUE_AUTONOMOUS_WEI=1000000000000000000 \
cargo run
```

The agent starts an API server on port 8420.

### 3. Connect

Click **Connect OpenClaw** in the sidebar → enter `http://localhost:8420` → connected. The agent shows a green **LIVE** badge.

### 4. Chat

Click any connected agent card → chat drawer slides in → type messages → get real responses with proof metadata badges showing intent, policy result, and ZK proof commitment.

### 5. Reconnect / Update

If the agent disconnects:
- Click the agent → see **Agent Offline** with your saved run command + **Copy** button
- Click **Reconnect** to try the last known URL
- Click **Update Config** to change tools/limits/endpoints and get an updated command

To edit permissions anytime: click the agent's **Profile** link → **Edit** in the Permissions section → save → get new command → restart.

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
│  │  │ RISC Zero    │  │ Ledger DMK   │  │ EIP-8004         │  │  │
│  │  │ (ZK proofs)  │  │ (approval)   │  │ (trust layer)    │  │  │
│  │  └──────────────┘  └──────────────┘  └──────────────────┘  │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                              │                                    │
│                    ┌─────────▼──────────┐                         │
│                    │   On-Chain Layer    │                         │
│                    │  - ZK Verifier     │                         │
│                    │  - Policy Registry │                         │
│                    │  - iNFT (ERC-7857) │                         │
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

## API Endpoints

The agent exposes a REST API on port 8420 (configurable via `API_PORT`):

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/status` | GET | Agent ID, ENS, uptime, stats, policy hash |
| `/api/chat` | POST | Send a message → intent routing → policy check → proof generation → response |
| `/api/activity` | GET | Activity feed (proofs, messages, violations) |
| `/api/proofs` | GET | Proof history with policy check details |
| `/api/messages` | GET | Message records |
| `/api/messages/send` | POST | Send a DM3 message to another agent |

### Chat Endpoint

```bash
curl -X POST http://localhost:8420/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "swap 100 USDC for ETH"}'
```

Response:
```json
{
  "response": "Executing swap: swap 100 USDC for ETH. Policy verified. Autonomous execution approved.",
  "intent": { "action_type": "swap", "confidence": 0.95 },
  "policy_result": { "allowed": true, "approval_type": "autonomous", "checks": [...] },
  "proof": { "proof_id": "...", "status": "verified", "output_commitment": "0x..." }
}
```

## Repository Structure

```
proof-of-claw/
├── agent/                      # Rust agent runtime (IronClaw workspace)
│   ├── crates/
│   │   ├── proof_of_claw/      # Core Proof of Claw agent crate
│   │   ├── ironclaw_engine/    # Agent reasoning loop, capabilities, memory
│   │   ├── ironclaw_safety/    # Safety layer (injection detection, leak detection, fuzzing)
│   │   ├── ironclaw_skills/    # Extensible skills system
│   │   └── ironclaw_common/    # Shared types and utilities
│   └── src/
│       ├── main.rs             # Entry point + CLI
│       ├── app.rs              # App startup orchestration
│       ├── agent/              # Core agent loop, dispatcher, sessions
│       ├── channels/           # Multi-channel input (HTTP, CLI, REPL, WebSocket, WASM)
│       ├── tools/              # Extensible tool system with WASM sandbox + MCP
│       ├── llm/                # Multi-provider LLM abstraction
│       ├── db/                 # Dual-backend persistence (PostgreSQL + libSQL)
│       ├── workspace/          # Persistent memory (hybrid FTS + vector search)
│       ├── safety/             # Prompt injection detection (re-exports ironclaw_safety)
│       ├── sandbox/            # Docker execution isolation + network proxy
│       ├── skills/             # SKILL.md prompt extension system
│       ├── hooks/              # Lifecycle hooks (6 hook points)
│       ├── tunnel/             # Public exposure (Cloudflare, ngrok, Tailscale)
│       ├── secrets/            # AES-256-GCM secrets management
│       └── integrations/       # 0G, ENS, DM3, Ledger, EIP-8004, iNFT
│
├── zkvm/                       # RISC Zero zkVM programs
│   ├── guest/src/main.rs       # Policy verification guest program
│   └── host/src/main.rs        # Proof generation host program
│
├── contracts/                  # Solidity smart contracts (Foundry)
│   ├── src/
│   │   ├── ProofOfClawVerifier.sol  # RISC Zero proof verification + execution routing
│   │   ├── EIP8004Integration.sol   # EIP-8004 registry bridge
│   │   └── ProofOfClawINFT.sol      # ERC-7857 iNFT for agent identity
│   ├── interfaces/
│   │   ├── IRiscZeroVerifier.sol
│   │   └── IEIP8004.sol
│   ├── clear-signing/
│   │   └── proofofclaw.json         # ERC-7730 Ledger Clear Signing metadata
│   └── script/
│       ├── Deploy.s.sol             # Sepolia/Mainnet deployment
│       └── Deploy0G.s.sol           # 0G Chain deployment
│
├── frontend/                   # Web UI (vanilla HTML/CSS/JS)
│   ├── index.html              # Landing page + architecture overview
│   ├── agents.html             # Agent registry, wizard, inline chat, profile editor
│   ├── dashboard.html          # Live monitoring (polls API every 3s when connected)
│   ├── messages.html           # DM3 message threads
│   ├── proofs.html             # ZK proof explorer
│   ├── soul-vault.html         # Agent deployment interface
│   ├── docs.html               # Interactive technical documentation
│   ├── deploy.html             # Redirect → agents.html
│   ├── poc-api.js              # API client (connect, fetch, send)
│   ├── ens-resolver.js         # On-chain ENS resolution (keccak256 + namehash)
│   ├── shared.css              # Unified design system
│   ├── shared.js               # Shared UI utilities
│   └── public/                 # Favicons, logos, sponsor assets
│
├── spec.md                     # Full technical specification
├── ARCHITECTURE.md             # System architecture docs
├── IRONCLAW_INTEGRATION.md     # IronClaw integration guide
├── Makefile                    # Build/test/deploy targets
├── vercel.json                 # Vercel deployment config (serves frontend/)
└── .env.example                # Configuration reference
```

## Quick Start

### Prerequisites

- Rust 1.92+
- Foundry (`curl -L https://foundry.paradigm.xyz | bash && foundryup`)
- RISC Zero toolchain (`curl -L https://risczero.com/install | bash && rzup install`)

### Build & Test

```bash
# Agent runtime
cd agent && cargo build --release && cargo test

# Smart contracts
cd contracts && forge build

# RISC Zero programs
cd zkvm && cargo build --release
```

### Run

```bash
# Terminal 1: Start the agent
cd agent && AGENT_ID=my-agent ENS_NAME=my-agent.proofclaw.eth \
  PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  RPC_URL=https://eth-sepolia.g.alchemy.com/v2/demo \
  ZERO_G_INDEXER_RPC=https://indexer-storage-testnet.0g.ai \
  ZERO_G_COMPUTE_ENDPOINT=https://broker-testnet.0g.ai \
  DM3_DELIVERY_SERVICE_URL=http://localhost:3001 \
  ALLOWED_TOOLS=swap_tokens,transfer,query \
  ENDPOINT_ALLOWLIST=https://api.uniswap.org,https://api.0x.org \
  MAX_VALUE_AUTONOMOUS_WEI=1000000000000000000 \
  cargo run

# Terminal 2: Serve the frontend
cd frontend && python3 -m http.server 8080
```

Open `http://localhost:8080/agents.html` → Connect OpenClaw → Chat.

### Deploy Contracts

```bash
cd contracts
forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast --private-key $PRIVATE_KEY
```

## Integrations

| Integration | Purpose | Status |
|-------------|---------|--------|
| **0G Compute** | Private LLM inference with attestation | Working — real HTTP + attestation extraction |
| **0G Storage** | Decentralized execution trace storage | Working — upload/retrieve with content hashing |
| **ENS** | Agent identity via subnames | Working — on-chain namehash + text records |
| **DM3** | End-to-end encrypted messaging | Working — 3-tier resolution (ENS → HTTP → fallback) |
| **RISC Zero** | ZK proofs of policy compliance | Working — guest/host programs + Boundless |
| **Ledger** | Hardware-gated human approval | Stub — needs real DMK/DSK integration |
| **EIP-8004** | Trustless agent discovery & reputation | Working — identity, reputation, validation queries |
| **iNFT (ERC-7857)** | Agent identity NFT on 0G Chain | Working — minting, metadata, proof recording |

## Security Model

| Threat | Mitigation |
|--------|-----------|
| Agent acts outside policy | RISC Zero proof fails; action blocked on-chain |
| Inference tampering | 0G Compute attestation; signature in proof |
| Message interception | DM3 end-to-end encryption with keys from ENS profiles |
| Identity spoofing | ENS ownership tied to Ledger EOA |
| High-value action without consent | Physical Ledger approval with Clear Signing display |
| Prompt injection | Safety layer (injection detector) in proven execution trace |
| Sybil agents / fake reputation | EIP-8004 Reputation Registry filtering by trusted reviewers |

## Build Status

| Component | Status |
|-----------|--------|
| Rust Agent | 0 warnings, 35/35 tests pass |
| Smart Contracts | `forge build` compiles clean |
| RISC Zero | Toolchain installed (cargo-risczero 3.0.5) |
| Frontend | All pages functional, no external dependencies |

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Agent Runtime | Rust, Tokio, Axum, Wasmtime |
| Inference | 0G Compute |
| Storage | 0G Storage |
| Identity | ENS + ethers |
| Trust Layer | EIP-8004 |
| Messaging | DM3 protocol |
| ZK Proofs | RISC Zero zkVM + Boundless |
| Hardware Signing | Ledger DMK/DSK + ERC-7730 |
| Smart Contracts | Solidity (Foundry) |
| Frontend | Vanilla HTML/CSS/JS |

## Documentation

- [docs.html](frontend/docs.html) — Interactive technical documentation (served at `/docs.html`)
- [spec.md](spec.md) — Full technical specification
- [ARCHITECTURE.md](ARCHITECTURE.md) — System architecture
- [IRONCLAW_INTEGRATION.md](IRONCLAW_INTEGRATION.md) — IronClaw integration guide
- [.env.example](.env.example) — All configuration variables

## License

MIT
