#!/usr/bin/env node

/**
 * ProofOfClaw ↔ Swarm Protocol Bridge
 *
 * Bidirectional message bridge that connects ProofOfClaw agents (DM3 messaging)
 * to the Swarm Protocol hub (swarmprotocol.fun).
 *
 * Architecture:
 *   ┌─────────────┐     ┌──────────────┐     ┌─────────────────────┐
 *   │ POC Agents   │◄───►│ DM3 Delivery │◄───►│   Swarm Bridge      │◄───► Swarm Hub
 *   │ (port 8420)  │     │ (port 3001)  │     │   (this service)    │     (wss://swarmprotocol.fun)
 *   └─────────────┘     └──────────────┘     └─────────────────────┘
 *
 * Message flow:
 *   Swarm → POC:  Hub WS message → bridge → POST /messages on DM3 delivery service
 *   POC → Swarm:  DM3 WS dm3_message → bridge → POST /api/v1/send on Hub (Ed25519 signed)
 *
 * Usage:
 *   node bridge.mjs                          # Start bridge (reads .env or env vars)
 *   node bridge.mjs --register-only          # Register with Swarm hub and exit
 *
 * Environment Variables:
 *   SWARM_HUB_URL          — Swarm hub (default: https://swarmprotocol.fun)
 *   SWARM_ORG_ID           — Organization ID on Swarm hub (required for registration)
 *   SWARM_AGENT_NAME       — Bridge agent name on Swarm (default: "ProofOfClaw Bridge")
 *   SWARM_AGENT_TYPE       — Agent type (default: "Coordinator")
 *   DM3_DELIVERY_URL       — DM3 delivery service (default: http://localhost:3001)
 *   BRIDGE_PORT            — Health endpoint port (default: 3002)
 *   BRIDGE_DEFAULT_CHANNEL — Default Swarm channel for unmapped messages
 *   POC_AGENTS_JSON        — JSON mapping: { "ensName": "swarmAgentId", ... }
 */

import crypto from "node:crypto";
import http from "node:http";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import WebSocket from "ws";

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

const __dirname = dirname(fileURLToPath(import.meta.url));
const KEYS_DIR = join(__dirname, "keys");
const PRIVATE_KEY_PATH = join(KEYS_DIR, "private.pem");
const PUBLIC_KEY_PATH = join(KEYS_DIR, "public.pem");
const CONFIG_PATH = join(__dirname, "config.json");
const IDENTITY_MAP_PATH = join(__dirname, "identity-map.json");

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

function arg(flag) {
  const idx = process.argv.indexOf(flag);
  return idx !== -1 && idx + 1 < process.argv.length ? process.argv[idx + 1] : undefined;
}

const SWARM_HUB_URL = arg("--hub") || process.env.SWARM_HUB_URL || "https://swarmprotocol.fun";
const SWARM_ORG_ID = arg("--org") || process.env.SWARM_ORG_ID;
const SWARM_AGENT_NAME = arg("--name") || process.env.SWARM_AGENT_NAME || "ProofOfClaw Bridge";
const SWARM_AGENT_TYPE = arg("--type") || process.env.SWARM_AGENT_TYPE || "Coordinator";
const DM3_DELIVERY_URL = arg("--dm3") || process.env.DM3_DELIVERY_URL || "http://localhost:3001";
const BRIDGE_PORT = parseInt(arg("--port") || process.env.BRIDGE_PORT || "3002", 10);
const BRIDGE_DEFAULT_CHANNEL = arg("--channel") || process.env.BRIDGE_DEFAULT_CHANNEL || null;
const REGISTER_ONLY = process.argv.includes("--register-only");

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

function log(tag, msg, data) {
  const ts = new Date().toISOString();
  console.log(`[${ts}] [${tag}] ${msg}`, data !== undefined ? JSON.stringify(data) : "");
}

// ---------------------------------------------------------------------------
// Ed25519 Key Management
// ---------------------------------------------------------------------------

function ensureKeypair() {
  if (existsSync(PRIVATE_KEY_PATH) && existsSync(PUBLIC_KEY_PATH)) {
    return {
      privateKey: readFileSync(PRIVATE_KEY_PATH, "utf-8").trim(),
      publicKey: readFileSync(PUBLIC_KEY_PATH, "utf-8").trim(),
    };
  }

  log("KEYS", "Generating Ed25519 keypair...");
  mkdirSync(KEYS_DIR, { recursive: true });

  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  writeFileSync(PRIVATE_KEY_PATH, privateKey);
  writeFileSync(PUBLIC_KEY_PATH, publicKey);
  log("KEYS", "Keypair saved to ./keys/ (private key never leaves this directory)");

  return { privateKey: privateKey.trim(), publicKey: publicKey.trim() };
}

function sign(message, privateKeyPem) {
  const pk = crypto.createPrivateKey({ key: privateKeyPem, format: "pem", type: "pkcs8" });
  return crypto.sign(null, Buffer.from(message, "utf-8"), pk).toString("base64");
}

// ---------------------------------------------------------------------------
// Identity Mapping (ENS name ↔ Swarm agent ID)
// ---------------------------------------------------------------------------

// Bidirectional maps
const ensToSwarm = new Map();   // "alice.proofclaw.eth" → { agentId, channelId }
const swarmToEns = new Map();   // "swarm-agent-id" → "alice.proofclaw.eth"
const channelToEns = new Map(); // "channel-id" → "alice.proofclaw.eth" (for channel messages)

function loadIdentityMap() {
  // Load from file
  if (existsSync(IDENTITY_MAP_PATH)) {
    try {
      const data = JSON.parse(readFileSync(IDENTITY_MAP_PATH, "utf-8"));
      for (const [ens, mapping] of Object.entries(data)) {
        ensToSwarm.set(ens, mapping);
        if (mapping.agentId) swarmToEns.set(mapping.agentId, ens);
        if (mapping.channelId) channelToEns.set(mapping.channelId, ens);
      }
      log("IDENTITY", `Loaded ${ensToSwarm.size} identity mapping(s) from file`);
    } catch (e) {
      log("IDENTITY", `Failed to load identity map: ${e.message}`);
    }
  }

  // Load from env (overrides file)
  if (process.env.POC_AGENTS_JSON) {
    try {
      const envMap = JSON.parse(process.env.POC_AGENTS_JSON);
      for (const [ens, value] of Object.entries(envMap)) {
        const mapping = typeof value === "string" ? { agentId: value } : value;
        ensToSwarm.set(ens, mapping);
        if (mapping.agentId) swarmToEns.set(mapping.agentId, ens);
        if (mapping.channelId) channelToEns.set(mapping.channelId, ens);
      }
      log("IDENTITY", `Loaded ${Object.keys(envMap).length} mapping(s) from POC_AGENTS_JSON`);
    } catch (e) {
      log("IDENTITY", `Failed to parse POC_AGENTS_JSON: ${e.message}`);
    }
  }
}

function saveIdentityMap() {
  const data = Object.fromEntries(ensToSwarm);
  writeFileSync(IDENTITY_MAP_PATH, JSON.stringify(data, null, 2) + "\n");
}

function registerMapping(ensName, agentId, channelId) {
  const mapping = { agentId, channelId, registeredAt: Date.now() };
  ensToSwarm.set(ensName, mapping);
  if (agentId) swarmToEns.set(agentId, ensName);
  if (channelId) channelToEns.set(channelId, ensName);
  saveIdentityMap();
  log("IDENTITY", `Mapped ${ensName} ↔ ${agentId || "no-agent"}/${channelId || "no-channel"}`);
}

// ---------------------------------------------------------------------------
// Swarm Hub Registration
// ---------------------------------------------------------------------------

function loadConfig() {
  if (!existsSync(CONFIG_PATH)) return null;
  try { return JSON.parse(readFileSync(CONFIG_PATH, "utf-8")); } catch { return null; }
}

function saveConfig(config) {
  writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2) + "\n");
}

async function registerWithSwarm(publicKey) {
  const existing = loadConfig();
  if (existing?.agentId && !REGISTER_ONLY) {
    log("REG", `Already registered as "${existing.agentName}" (${existing.agentId})`);
    return existing;
  }

  if (!SWARM_ORG_ID) {
    log("REG", "SWARM_ORG_ID required for registration. Set it in .env or pass --org");
    if (!existing) process.exit(1);
    return existing;
  }

  log("REG", `Registering bridge with ${SWARM_HUB_URL}...`);

  const body = {
    publicKey,
    agentName: SWARM_AGENT_NAME,
    agentType: SWARM_AGENT_TYPE,
    orgId: SWARM_ORG_ID,
    skills: [
      { id: "dm3-bridge", name: "DM3 Message Bridge", type: "skill" },
      { id: "proofclaw", name: "Proof of Claw Integration", type: "skill" },
      { id: "ens-resolution", name: "ENS Name Resolution", type: "skill" },
      { id: "zk-proofs", name: "ZK Proof Verification", type: "skill" },
    ],
    bio: "Bridges ProofOfClaw agents (DM3/ENS) to Swarm Protocol. Routes messages bidirectionally with identity mapping.",
    ...(existing?.agentId ? { existingAgentId: existing.agentId } : {}),
  };

  const resp = await fetch(`${SWARM_HUB_URL}/api/v1/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    log("REG", `Registration failed (${resp.status}): ${err.error || "Unknown"}`);
    if (existing) return existing;
    process.exit(1);
  }

  const data = await resp.json();
  const config = {
    hubUrl: SWARM_HUB_URL,
    orgId: SWARM_ORG_ID,
    agentId: data.agentId,
    agentName: data.agentName || SWARM_AGENT_NAME,
    agentType: SWARM_AGENT_TYPE,
    asn: data.asn || null,
    registeredAt: Date.now(),
  };

  saveConfig(config);
  log("REG", `Registered as "${config.agentName}" (${config.agentId})`);
  if (data.asn) log("REG", `ASN: ${data.asn}`);

  return config;
}

// ---------------------------------------------------------------------------
// Swarm Hub WebSocket Connection
// ---------------------------------------------------------------------------

let swarmWs = null;
let swarmReconnectTimer = null;
let swarmConnected = false;
const SWARM_RECONNECT_DELAY = 5000;
const SWARM_PING_INTERVAL = 25000;

function connectToSwarmHub(config, privateKeyPem) {
  if (swarmWs) {
    try { swarmWs.close(); } catch {}
  }

  const ts = Date.now().toString();
  const message = `WS:connect:${config.agentId}:${ts}`;
  const sig = sign(message, privateKeyPem);

  const wsUrl = config.hubUrl.replace(/^http/, "ws");
  const url = `${wsUrl}/ws/agents/${config.agentId}?sig=${encodeURIComponent(sig)}&ts=${ts}`;

  log("SWARM-WS", `Connecting to hub...`);
  swarmWs = new WebSocket(url);

  swarmWs.on("open", () => {
    swarmConnected = true;
    log("SWARM-WS", "Connected to Swarm hub");
  });

  swarmWs.on("message", (raw) => {
    try {
      const data = JSON.parse(raw.toString());
      handleSwarmMessage(data, config, privateKeyPem);
    } catch (e) {
      log("SWARM-WS", `Failed to parse message: ${e.message}`);
    }
  });

  swarmWs.on("ping", (payload) => {
    // Hub sends ping with { request_vitals: true }
    const vitals = JSON.stringify({
      cpu: 0,
      memory: Math.round(process.memoryUsage.rss?.() || process.memoryUsage().rss / 1024 / 1024),
      disk: 0,
      memoryUsedMB: Math.round(process.memoryUsage().rss / 1024 / 1024),
      memoryTotalMB: 0,
      uptime: Math.round(process.uptime()),
    });
    try { swarmWs.pong(vitals); } catch {}
  });

  swarmWs.on("close", (code, reason) => {
    swarmConnected = false;
    log("SWARM-WS", `Disconnected (${code}: ${reason || "no reason"})`);
    scheduleSwarmReconnect(config, privateKeyPem);
  });

  swarmWs.on("error", (err) => {
    log("SWARM-WS", `Error: ${err.message}`);
  });
}

function scheduleSwarmReconnect(config, privateKeyPem) {
  if (swarmReconnectTimer) return;
  swarmReconnectTimer = setTimeout(() => {
    swarmReconnectTimer = null;
    connectToSwarmHub(config, privateKeyPem);
  }, SWARM_RECONNECT_DELAY);
}

// ---------------------------------------------------------------------------
// DM3 Delivery Service WebSocket Connection
// ---------------------------------------------------------------------------

let dm3Ws = null;
let dm3ReconnectTimer = null;
let dm3Connected = false;
const DM3_RECONNECT_DELAY = 3000;

// Track which ENS names we're subscribed to
const dm3Subscriptions = new Set();

function connectToDm3() {
  if (dm3Ws) {
    try { dm3Ws.close(); } catch {}
  }

  const wsUrl = DM3_DELIVERY_URL.replace(/^http/, "ws");
  log("DM3-WS", `Connecting to ${wsUrl}/ws...`);
  dm3Ws = new WebSocket(`${wsUrl}/ws`);

  dm3Ws.on("open", () => {
    dm3Connected = true;
    log("DM3-WS", "Connected to DM3 delivery service");

    // Re-subscribe to all known ENS names
    for (const ensName of ensToSwarm.keys()) {
      subscribeDm3(ensName);
    }
  });

  dm3Ws.on("message", (raw) => {
    try {
      const data = JSON.parse(raw.toString());
      handleDm3Message(data);
    } catch (e) {
      log("DM3-WS", `Failed to parse message: ${e.message}`);
    }
  });

  dm3Ws.on("close", () => {
    dm3Connected = false;
    dm3Subscriptions.clear();
    log("DM3-WS", "Disconnected");
    scheduleDm3Reconnect();
  });

  dm3Ws.on("error", (err) => {
    log("DM3-WS", `Error: ${err.message}`);
  });
}

function scheduleDm3Reconnect() {
  if (dm3ReconnectTimer) return;
  dm3ReconnectTimer = setTimeout(() => {
    dm3ReconnectTimer = null;
    connectToDm3();
  }, DM3_RECONNECT_DELAY);
}

function subscribeDm3(ensName) {
  if (!dm3Connected || dm3Subscriptions.has(ensName)) return;
  dm3Ws.send(JSON.stringify({ type: "subscribe", ensName }));
  dm3Subscriptions.add(ensName);
  log("DM3-WS", `Subscribed to ${ensName}`);
}

// ---------------------------------------------------------------------------
// Message Handlers
// ---------------------------------------------------------------------------

/**
 * Handle messages FROM Swarm hub → route to DM3 delivery service.
 *
 * Message types we care about:
 *   - "message"   (channel message)
 *   - "a2a"       (agent-to-agent direct)
 *   - "invoke"    (task invocation)
 *   - "connected" (welcome, ignore)
 *   - "channels"  (channel list, store for routing)
 */

const swarmChannels = new Map(); // channelId → channelName

async function handleSwarmMessage(data, config, privateKeyPem) {
  switch (data.type) {
    case "connected":
      log("SWARM", `Welcome: ${data.agentName} (${data.agentId})`);
      break;

    case "channels":
      // Store channel list for routing
      if (Array.isArray(data.channels)) {
        for (const ch of data.channels) {
          swarmChannels.set(ch.id, ch.name);
        }
        log("SWARM", `Received ${data.channels.length} channel(s)`);
      }
      break;

    case "message": {
      // Channel message from Swarm → forward to DM3
      if (data.from === config.agentName) break; // Skip our own messages

      // Determine target ENS name
      const targetEns = channelToEns.get(data.channelId) || resolveSwarmSenderToEns(data);
      if (!targetEns) {
        log("SWARM→DM3", `No ENS mapping for channel ${data.channelId}, dropping message from ${data.from}`);
        break;
      }

      await forwardToDm3({
        to: targetEns,
        from: `${data.from}.swarm.proofclaw.eth`,
        message: data.text,
        metadata: {
          swarmChannelId: data.channelId,
          swarmChannelName: swarmChannels.get(data.channelId),
          swarmMessageId: data.messageId,
          swarmFrom: data.from,
          swarmFromType: data.fromType,
        },
      });
      break;
    }

    case "a2a": {
      // Direct agent-to-agent from Swarm → forward to DM3
      const targetEns = swarmToEns.get(data.to) || swarmToEns.get(data.toName);
      if (!targetEns) {
        log("SWARM→DM3", `No ENS mapping for Swarm agent ${data.to || data.toName}`);
        break;
      }

      const senderEns = swarmToEns.get(data.from) || `${data.fromName}.swarm.proofclaw.eth`;

      await forwardToDm3({
        to: targetEns,
        from: senderEns,
        message: typeof data.payload === "string" ? data.payload : JSON.stringify(data.payload),
        metadata: { swarmType: "a2a", swarmFrom: data.from, swarmFromName: data.fromName },
      });
      break;
    }

    case "invoke": {
      // Hub invocation request → forward to first registered POC agent
      const firstAgent = ensToSwarm.keys().next().value;
      if (!firstAgent) {
        log("SWARM→DM3", "Invoke received but no POC agents registered");
        break;
      }

      await forwardToDm3({
        to: firstAgent,
        from: "swarm-hub.proofclaw.eth",
        message: JSON.stringify({
          type: "invoke",
          requestId: data.requestId,
          prompt: data.prompt,
        }),
      });
      break;
    }

    case "replay:end":
      log("SWARM", `Replay complete: ${data.count} message(s) from ${data.channels} channel(s)`);
      break;

    default:
      // Ignore batched presence events, typing indicators, etc.
      break;
  }
}

/**
 * Handle messages FROM DM3 → route to Swarm hub.
 */
async function handleDm3Message(data) {
  if (data.type !== "dm3_message" || !data.envelope) return;

  const envelope = data.envelope;
  const { from, to, message: content } = envelope;

  log("DM3→SWARM", `Message from ${from} to ${to}`);

  // Look up Swarm routing for the sender
  const senderMapping = ensToSwarm.get(from);

  // Look up target — is the recipient a known Swarm agent?
  const recipientMapping = ensToSwarm.get(to);

  // Determine if this is a cross-system message (POC agent → external Swarm agent)
  // or an intra-POC message that should also be mirrored to Swarm

  // Try to parse content for invoke responses
  let parsedContent;
  try {
    parsedContent = JSON.parse(content);
  } catch {
    parsedContent = null;
  }

  // Handle invoke response
  if (parsedContent?.type === "invoke_response" && parsedContent?.requestId) {
    if (swarmConnected && swarmWs) {
      swarmWs.send(JSON.stringify({
        type: "invoke:response",
        requestId: parsedContent.requestId,
        result: parsedContent.result || { response: content },
        ts: Date.now(),
      }));
      log("DM3→SWARM", `Forwarded invoke response ${parsedContent.requestId}`);
    }
    return;
  }

  // Forward to Swarm channel or A2A
  if (recipientMapping?.agentId && recipientMapping.agentId !== senderMapping?.agentId) {
    // Direct A2A to a specific Swarm agent
    await sendSwarmA2A(recipientMapping.agentId, content, from);
  } else if (senderMapping?.channelId || BRIDGE_DEFAULT_CHANNEL) {
    // Send to the agent's mapped channel or default channel
    const channelId = senderMapping?.channelId || BRIDGE_DEFAULT_CHANNEL;
    await sendToSwarmChannel(channelId, content, from);
  } else {
    log("DM3→SWARM", `No Swarm routing for ${from} → ${to}, message buffered`);
  }
}

// ---------------------------------------------------------------------------
// Message Forwarding
// ---------------------------------------------------------------------------

/** Forward a message to the DM3 delivery service */
async function forwardToDm3({ to, from, message, metadata }) {
  const body = {
    to,
    from,
    message: metadata ? JSON.stringify({ text: message, _bridge: metadata }) : message,
    timestamp: Date.now(),
  };

  try {
    const resp = await fetch(`${DM3_DELIVERY_URL}/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (!resp.ok) {
      const err = await resp.text();
      log("SWARM→DM3", `Failed to forward: ${resp.status} ${err}`);
      return;
    }

    const result = await resp.json();
    log("SWARM→DM3", `Forwarded to ${to} (id: ${result.id})`);
  } catch (e) {
    log("SWARM→DM3", `Error forwarding to DM3: ${e.message}`);
  }
}

/** Send a message to a Swarm channel via signed HTTP */
async function sendToSwarmChannel(channelId, text, fromEns) {
  const config = loadConfig();
  if (!config?.agentId) return;

  const { privateKey } = ensureKeypair();
  const nonce = crypto.randomUUID();
  const prefixedText = `[${fromEns}] ${text}`;
  const signedMessage = `POST:/v1/send:${channelId}:${prefixedText}::${nonce}`;
  const sig = sign(signedMessage, privateKey);

  try {
    const resp = await fetch(`${config.hubUrl}/api/v1/send`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        agent: config.agentId,
        channelId,
        text: prefixedText,
        nonce,
        sig,
      }),
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      log("DM3→SWARM", `Send failed (${resp.status}): ${err.error || "unknown"}`);
      return;
    }

    const result = await resp.json();
    log("DM3→SWARM", `Sent to channel ${channelId} (msg: ${result.messageId})`);
  } catch (e) {
    log("DM3→SWARM", `Error sending to Swarm: ${e.message}`);
  }
}

/** Send A2A message via Swarm WebSocket */
async function sendSwarmA2A(targetAgentId, text, fromEns) {
  if (!swarmConnected || !swarmWs) {
    log("DM3→SWARM", "Hub not connected, cannot send A2A");
    return;
  }

  const config = loadConfig();
  swarmWs.send(JSON.stringify({
    type: "a2a",
    id: crypto.randomUUID(),
    from: config.agentId,
    fromName: config.agentName,
    to: targetAgentId,
    payload: { text, fromEns },
    metadata: { bridge: "proofclaw-dm3", fromEns },
    timestamp: Date.now(),
  }));

  log("DM3→SWARM", `Sent A2A to ${targetAgentId} from ${fromEns}`);
}

function resolveSwarmSenderToEns(data) {
  // Try to find by sender agent name
  for (const [ens, mapping] of ensToSwarm.entries()) {
    if (mapping.agentName === data.from) return ens;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Health / Status HTTP Server
// ---------------------------------------------------------------------------

function startHealthServer() {
  const server = http.createServer((req, res) => {
    res.setHeader("Content-Type", "application/json");
    res.setHeader("Access-Control-Allow-Origin", "*");

    if (req.url === "/health") {
      res.writeHead(200);
      res.end(JSON.stringify({
        status: "ok",
        uptime: process.uptime(),
        swarmConnected,
        dm3Connected,
        identityMappings: ensToSwarm.size,
        swarmChannels: swarmChannels.size,
      }));
      return;
    }

    if (req.url === "/mappings") {
      res.writeHead(200);
      res.end(JSON.stringify({
        ensToSwarm: Object.fromEntries(ensToSwarm),
        swarmChannels: Object.fromEntries(swarmChannels),
      }));
      return;
    }

    // POST /register-agent — dynamically register an ENS ↔ Swarm mapping
    if (req.method === "POST" && req.url === "/register-agent") {
      let body = "";
      req.on("data", (chunk) => { body += chunk; });
      req.on("end", () => {
        try {
          const { ensName, agentId, channelId } = JSON.parse(body);
          if (!ensName) {
            res.writeHead(400);
            res.end(JSON.stringify({ error: "ensName required" }));
            return;
          }
          registerMapping(ensName, agentId || null, channelId || null);
          // Subscribe to DM3 messages for this agent
          subscribeDm3(ensName);
          res.writeHead(201);
          res.end(JSON.stringify({ ok: true, ensName, agentId, channelId }));
        } catch (e) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: e.message }));
        }
      });
      return;
    }

    res.writeHead(404);
    res.end(JSON.stringify({ error: "not found" }));
  });

  server.listen(BRIDGE_PORT, () => {
    log("HTTP", `Health server on http://localhost:${BRIDGE_PORT}`);
    log("HTTP", `  GET  /health          — bridge status`);
    log("HTTP", `  GET  /mappings        — identity mappings`);
    log("HTTP", `  POST /register-agent  — register ENS ↔ Swarm mapping`);
  });
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  log("INIT", "ProofOfClaw ↔ Swarm Protocol Bridge starting...");
  log("INIT", `Hub:     ${SWARM_HUB_URL}`);
  log("INIT", `DM3:     ${DM3_DELIVERY_URL}`);
  log("INIT", `Port:    ${BRIDGE_PORT}`);

  // 1. Generate or load Ed25519 keypair
  const { publicKey, privateKey } = ensureKeypair();

  // 2. Load identity mappings
  loadIdentityMap();

  // 3. Register with Swarm hub
  const config = await registerWithSwarm(publicKey);

  if (REGISTER_ONLY) {
    log("INIT", "Registration complete (--register-only). Exiting.");
    process.exit(0);
  }

  // 4. Start health server
  startHealthServer();

  // 5. Connect to DM3 delivery service
  connectToDm3();

  // 6. Connect to Swarm hub WebSocket
  connectToSwarmHub(config, privateKey);

  // 7. Graceful shutdown
  for (const signal of ["SIGINT", "SIGTERM"]) {
    process.on(signal, () => {
      log("SHUTDOWN", `Received ${signal}, closing connections...`);
      if (swarmWs) swarmWs.close();
      if (dm3Ws) dm3Ws.close();
      clearTimeout(swarmReconnectTimer);
      clearTimeout(dm3ReconnectTimer);
      process.exit(0);
    });
  }

  log("INIT", "Bridge running. Press Ctrl+C to stop.");
}

main().catch((err) => {
  log("FATAL", err.message);
  console.error(err);
  process.exit(1);
});
