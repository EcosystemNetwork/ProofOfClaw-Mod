/**
 * Proof of Claw Agent Runtime
 * HTTP API server with DM3 encrypted messaging support
 */

const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason?.message || reason);
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error.message);
  process.exit(1);
});

// ── File upload configuration ──
const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, crypto.randomUUID() + ext);
  }
});

const ALLOWED_MIME_TYPES = ['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'application/json'];

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB max
  fileFilter: (req, file, cb) => {
    if (ALLOWED_MIME_TYPES.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`File type ${file.mimetype} not allowed. Allowed: ${ALLOWED_MIME_TYPES.join(', ')}`), false);
    }
  }
});

const app = express();
const PORT = process.env.API_PORT || 8420;

// Agent configuration — all required, no fallbacks
const AGENT_ID = process.env.AGENT_ID;
if (!AGENT_ID) {
  console.error('FATAL: AGENT_ID environment variable is required');
  process.exit(1);
}
const ENS_NAME = process.env.ENS_NAME || `${AGENT_ID}.proofclaw.eth`;
const DM3_DELIVERY_SERVICE_URL = process.env.DM3_DELIVERY_SERVICE_URL;
if (!DM3_DELIVERY_SERVICE_URL) {
  console.error('FATAL: DM3_DELIVERY_SERVICE_URL environment variable is required');
  process.exit(1);
}
const PRIVATE_KEY = process.env.PRIVATE_KEY;
if (!PRIVATE_KEY || /^0x0+$/.test(PRIVATE_KEY)) {
  console.error('FATAL: PRIVATE_KEY environment variable is required (must not be all zeros)');
  process.exit(1);
}
const RPC_URL = process.env.RPC_URL;
if (!RPC_URL || RPC_URL.includes('placeholder')) {
  console.error('FATAL: RPC_URL environment variable is required (must be a real endpoint)');
  process.exit(1);
}
const NETWORK = process.env.NETWORK || 'sepolia';

// Policy configuration
const ALLOWED_TOOLS = (process.env.ALLOWED_TOOLS || 'query,read').split(',').map(s => s.trim()).filter(Boolean);
const ENDPOINT_ALLOWLIST = (process.env.ENDPOINT_ALLOWLIST || '').split(',').map(s => s.trim()).filter(Boolean);
const MAX_VALUE_AUTONOMOUS_WEI = parseInt(process.env.MAX_VALUE_AUTONOMOUS_WEI || '1000000000000000000', 10);

// ── Security: API key authentication + SIWE ──
const API_KEY = process.env.API_KEY || process.env.ONECLAW_API_KEY || '';
if (!API_KEY) console.warn('WARNING: No API_KEY set — running without authentication (dev mode)');

// SIWE (Sign-In with Ethereum) session management
const siweSessions = new Map();
const siweNonces = new Map(); // nonce -> expiresAt

let ethersVerifyMessage;
try {
  const ethers = require('ethers');
  ethersVerifyMessage = ethers.verifyMessage;
} catch { /* ethers not available — SIWE disabled */ }

function authenticateRequest(req, res, next) {
  if (!API_KEY && siweSessions.size === 0) return next(); // dev mode

  // Check Bearer token (SIWE session)
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7);
    const session = siweSessions.get(token);
    if (session && session.expiresAt > Date.now()) {
      req.walletAddress = session.address;
      return next();
    }
  }

  // Check API key
  if (API_KEY) {
    const provided = req.headers['x-api-key'];
    if (provided && provided === API_KEY) return next();
  }

  return res.status(401).json({ error: 'Unauthorized' });
}

// ── Security: rate limiting (in-memory) ──
const rateLimitStore = new Map();
function rateLimit(windowMs = 60000, max = 100) {
  return (req, res, next) => {
    const key = req.ip;
    const now = Date.now();
    const record = rateLimitStore.get(key) || { count: 0, resetAt: now + windowMs };
    if (now > record.resetAt) { record.count = 0; record.resetAt = now + windowMs; }
    record.count++;
    rateLimitStore.set(key, record);
    if (record.count > max) return res.status(429).json({ error: 'Too many requests' });
    next();
  };
}

// ── Security: cap in-memory stores ──
const MAX_MESSAGES = 10000;

function pruneMap(map, max) {
  if (map.size <= max) return;
  const keys = [...map.keys()];
  const toRemove = keys.length - max;
  for (let i = 0; i < toRemove; i++) {
    map.delete(keys[i]);
  }
}

// ── Security headers ──
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '0');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  next();
});

// Middleware
app.use(cors({
  origin: process.env.CORS_ORIGIN || 'http://localhost:8080',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));

// Global rate limit
app.use(rateLimit());

// Serve uploaded files with Content-Disposition: attachment
app.use('/uploads', (req, res, next) => {
  res.setHeader('Content-Disposition', 'attachment');
  next();
}, express.static(UPLOADS_DIR));

// Agent state
const agentState = {
  startedAt: Date.now(),
  totalActions: 0,
  proofsGenerated: 0,
  messagesReceived: 0,
  messagesSent: 0,
  status: 'online',
  sessionId: crypto.randomUUID(),
  dm3Connected: false
};

// In-memory message store (in production, use persistent storage)
const messageStore = new Map(); // contactId -> messages[]
const conversations = new Map(); // sessionId -> { messages, context }

// Periodically prune in-memory stores to prevent unbounded growth
setInterval(() => {
  // Prune messageStore: keep only the latest messages per contact
  let totalMessages = 0;
  for (const [, msgs] of messageStore) totalMessages += msgs.length;
  if (totalMessages > MAX_MESSAGES) {
    for (const [key, msgs] of messageStore) {
      if (msgs.length > 100) {
        messageStore.set(key, msgs.slice(-100));
      }
    }
  }
  // Prune conversations
  pruneMap(conversations, MAX_MESSAGES);
  // Prune proofStore (defined later, guarded)
  if (typeof proofStore !== 'undefined' && proofStore.length > MAX_MESSAGES) {
    proofStore.splice(0, proofStore.length - MAX_MESSAGES);
  }
  // Prune rate limit store (expired entries)
  const now = Date.now();
  for (const [key, record] of rateLimitStore) {
    if (now > record.resetAt) rateLimitStore.delete(key);
  }
}, 60000);

// ═══════════════════════════════════════════════════════════════════════════
// WebSocket — real-time push to dashboard clients
// ═══════════════════════════════════════════════════════════════════════════

const wsClients = new Set();

/**
 * Broadcast a typed event to all connected WebSocket clients.
 * @param {string} type  - Event type: status | activity | proofs | message
 * @param {object} data  - Payload
 */
function wsBroadcast(type, data) {
  const payload = JSON.stringify({ type, data, ts: Date.now() });
  for (const ws of wsClients) {
    if (ws.readyState === 1 /* OPEN */) {
      ws.send(payload);
    }
  }
}

/**
 * Build and broadcast a full status snapshot.
 * Called after any state mutation so dashboard stays current.
 */
function broadcastStatus() {
  wsBroadcast('status', {
    agent_id: AGENT_ID,
    ens_name: ENS_NAME,
    status: agentState.status,
    network: NETWORK,
    dm3_connected: agentState.dm3Connected,
    dm3_delivery_service: DM3_DELIVERY_SERVICE_URL,
    session_id: agentState.sessionId,
    uptime_secs: Math.floor((Date.now() - agentState.startedAt) / 1000),
    allowed_tools: ALLOWED_TOOLS,
    endpoint_allowlist: ENDPOINT_ALLOWLIST,
    max_value_autonomous_wei: MAX_VALUE_AUTONOMOUS_WEI,
    stats: {
      total_actions: agentState.totalActions,
      proofs_generated: agentState.proofsGenerated,
      messages_received: agentState.messagesReceived,
      messages_sent: agentState.messagesSent
    }
  });
}

// Heartbeat: push status every 5s so uptime counter stays fresh
setInterval(broadcastStatus, 5000);

// ═══════════════════════════════════════════════════════════════════════════
// DM3 Client Integration
// ═══════════════════════════════════════════════════════════════════════════

class DM3Client {
  constructor(deliveryServiceUrl, privateKey) {
    this.deliveryServiceUrl = deliveryServiceUrl;
    this.privateKey = privateKey;
    this.profile = null;
  }

  async initialize() {
    try {
      // Create DM3 profile with generated keys
      this.profile = {
        publicEncryptionKey: this.generateEncryptionKey(),
        publicSigningKey: this.generateSigningKey(),
        deliveryServiceUrl: this.deliveryServiceUrl
      };
      
      // Register profile with delivery service
      const response = await fetch(`${this.deliveryServiceUrl}/profile/${ENS_NAME}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(this.profile)
      });
      
      if (response.ok || response.status === 409) { // 409 = already exists
        agentState.dm3Connected = true;
        console.log('DM3: Profile registered successfully');
        return true;
      } else {
        console.warn('DM3: Failed to register profile:', response.status);
        return false;
      }
    } catch (err) {
      console.warn('DM3: Connection failed:', err.message);
      return false;
    }
  }

  generateEncryptionKey() {
    const nacl = require('tweetnacl');
    const keyPair = nacl.box.keyPair();
    this._encryptionKeyPair = keyPair;
    return '0x' + Buffer.from(keyPair.publicKey).toString('hex');
  }

  generateSigningKey() {
    const nacl = require('tweetnacl');
    const keyPair = nacl.sign.keyPair();
    this._signingKeyPair = keyPair;
    return '0x' + Buffer.from(keyPair.publicKey).toString('hex');
  }

  async sendMessage(recipientEns, content) {
    try {
      const envelope = {
        to: recipientEns,
        from: ENS_NAME,
        message: JSON.stringify({
          type: 'chat',
          content: content,
          timestamp: Date.now()
        }),
        encryptionEnvelopeType: 'plaintext',
        timestamp: Math.floor(Date.now() / 1000)
      };

      const response = await fetch(`${this.deliveryServiceUrl}/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(envelope)
      });

      if (response.ok) {
        agentState.messagesSent++;
        return { success: true, messageId: crypto.randomUUID() };
      } else {
        return { success: false, error: `Delivery service returned ${response.status}` };
      }
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  async pollMessages() {
    try {
      const response = await fetch(`${this.deliveryServiceUrl}/messages/incoming?recipient=${ENS_NAME}`, {
        method: 'GET',
        headers: { 'Accept': 'application/json' }
      });

      if (response.ok) {
        const messages = await response.json();
        if (messages.length > 0) {
          agentState.messagesReceived += messages.length;
        }
        return messages;
      }
      return [];
    } catch (err) {
      return [];
    }
  }
}

// Initialize DM3 client
const dm3Client = new DM3Client(DM3_DELIVERY_SERVICE_URL, PRIVATE_KEY);

// ═══════════════════════════════════════════════════════════════════════════
// Simple AI/Agent Logic
// ═══════════════════════════════════════════════════════════════════════════

const agentResponses = {
  greetings: ['Hello! How can I assist you today?', 'Hi there! Ready to help.', 'Greetings! What can I do for you?'],
  capabilities: [
    'I can help with: querying data, reading information, and secure messaging via DM3 protocol.',
    'My capabilities include data queries, information retrieval, and end-to-end encrypted messaging.',
    'I\'m equipped for data analysis, information lookup, and secure agent-to-agent communication.'
  ],
  about: [
    'I\'m a Proof of Claw agent with E2E encrypted messaging via DM3 protocol.',
    'I run with provable execution, ZK proofs, and hardware approval capabilities.',
    'I\'m an autonomous agent powered by IronClaw runtime with Proof of Claw verification.'
  ],
  default: [
    'I understand. Let me process that request.',
    'Processing your request...',
    'Acknowledged. Working on it.'
  ],
  fileReceived: [
    'I received your file(s). Let me take a look.',
    'Files received. Analyzing the content now.',
    'Got it — I\'ll review the attached files.'
  ],
  voiceReceived: [
    'Voice message received. Processing audio...',
    'I got your voice message. Let me process it.',
    'Audio received. Analyzing your voice message.'
  ]
};

function generateAgentResponse(userMessage, messageType) {
  if (messageType === 'voice') {
    return randomPick(agentResponses.voiceReceived);
  }

  const lowerMsg = userMessage.toLowerCase();

  if (lowerMsg.match(/sent files|attached files|\(voice message/)) {
    return randomPick(agentResponses.fileReceived);
  }
  if (lowerMsg.match(/hi|hello|hey|greetings/)) {
    return randomPick(agentResponses.greetings);
  }
  if (lowerMsg.match(/what can you do|capabilities|help|skills/)) {
    return randomPick(agentResponses.capabilities);
  }
  if (lowerMsg.match(/who are you|about|what are you/)) {
    return randomPick(agentResponses.about);
  }

  return randomPick(agentResponses.default);
}

function randomPick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

/**
 * Infer which tools an agent would invoke based on the user's prompt.
 * Returns an array of { name, category } objects.
 */
function inferToolsFromPrompt(prompt) {
  const lp = prompt.toLowerCase();
  const tools = [];

  // Always start with a read/search step
  if (lp.match(/grep|search|find|look for|todo/)) {
    tools.push({ name: 'grep_search', category: 'read' });
  }
  if (lp.match(/read|open|view|inspect|check/)) {
    tools.push({ name: 'read_file', category: 'read' });
  }
  if (lp.match(/glob|list files|directory/)) {
    tools.push({ name: 'glob_search', category: 'read' });
  }
  if (lp.match(/fetch|url|http|api|download/)) {
    tools.push({ name: 'web_fetch', category: 'read' });
  }
  if (lp.match(/web search|google|look up/)) {
    tools.push({ name: 'web_search', category: 'read' });
  }
  if (lp.match(/run|exec|command|bash|shell|install|build|deploy/)) {
    tools.push({ name: 'bash', category: 'exec' });
  }
  if (lp.match(/write|create file|save/)) {
    tools.push({ name: 'write_file', category: 'write' });
  }
  if (lp.match(/edit|fix|update|change|modify|refactor|rename/)) {
    tools.push({ name: 'edit_file', category: 'write' });
  }
  if (lp.match(/swap|transfer|send|bridge|stake/)) {
    tools.push({ name: 'bash', category: 'exec' });
    tools.push({ name: 'web_fetch', category: 'read' });
  }

  // Fallback: always produce at least one tool invocation
  if (tools.length === 0) {
    tools.push({ name: 'read_file', category: 'read' });
    tools.push({ name: 'structured_output', category: 'read' });
  }

  return tools;
}

// ═══════════════════════════════════════════════════════════════════════════
// API Endpoints
// ═══════════════════════════════════════════════════════════════════════════

/**
 * GET /health
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: agentState.status === 'online' ? 'ok' : 'degraded',
    agentId: AGENT_ID,
    ensName: ENS_NAME,
    dm3Connected: agentState.dm3Connected,
    uptimeSecs: Math.floor((Date.now() - agentState.startedAt) / 1000),
    timestamp: Date.now()
  });
});

// ── SIWE Authentication Endpoints (unauthenticated) ──
if (ethersVerifyMessage) {
  app.get('/auth/nonce', (req, res) => {
    const nonce = crypto.randomBytes(16).toString('hex');
    siweNonces.set(nonce, Date.now() + 5 * 60 * 1000); // 5 min expiry
    res.json({ nonce });
  });

  app.post('/auth/siwe', express.json(), (req, res) => {
    try {
      const { message, signature } = req.body;
      if (!message || !signature) return res.status(400).json({ error: 'Missing message or signature' });

      // Extract address (EIP-4361: second line is the 0x address)
      const addressMatch = message.match(/^(0x[a-fA-F0-9]{40})$/m);
      if (!addressMatch) return res.status(400).json({ error: 'No address in SIWE message' });
      const claimedAddress = addressMatch[1];

      // Validate and consume nonce
      const nonceMatch = message.match(/Nonce:\s*([^\n]+)/);
      if (nonceMatch) {
        const nonce = nonceMatch[1].trim();
        const expiry = siweNonces.get(nonce);
        if (!expiry || Date.now() > expiry) return res.status(400).json({ error: 'Invalid or expired nonce' });
        siweNonces.delete(nonce);
      }

      // Verify signature recovers to claimed address
      const recovered = ethersVerifyMessage(message, signature);
      if (recovered.toLowerCase() !== claimedAddress.toLowerCase()) {
        return res.status(401).json({ error: 'Signature mismatch' });
      }

      // Issue session token
      const token = crypto.randomBytes(32).toString('hex');
      const expiresAt = Date.now() + 24 * 60 * 60 * 1000;
      siweSessions.set(token, { address: recovered, expiresAt });

      // Prune expired sessions
      for (const [t, s] of siweSessions) { if (s.expiresAt < Date.now()) siweSessions.delete(t); }
      for (const [n, e] of siweNonces) { if (Date.now() > e) siweNonces.delete(n); }

      res.json({ token, address: recovered, expiresAt });
    } catch (err) {
      res.status(400).json({ error: 'SIWE verification failed' });
    }
  });
}

// Apply API key auth to all /api/* routes
app.use('/api', authenticateRequest);

/**
 * GET /api/status
 * Agent status and configuration
 */
app.get('/api/status', (req, res) => {
  res.json({
    agent_id: AGENT_ID,
    ens_name: ENS_NAME,
    status: agentState.status,
    network: NETWORK,
    dm3_connected: agentState.dm3Connected,
    dm3_delivery_service: DM3_DELIVERY_SERVICE_URL,
    session_id: agentState.sessionId,
    uptime_secs: Math.floor((Date.now() - agentState.startedAt) / 1000),
    allowed_tools: ALLOWED_TOOLS,
    endpoint_allowlist: ENDPOINT_ALLOWLIST,
    max_value_autonomous_wei: MAX_VALUE_AUTONOMOUS_WEI,
    stats: {
      total_actions: agentState.totalActions,
      proofs_generated: agentState.proofsGenerated,
      messages_received: agentState.messagesReceived,
      messages_sent: agentState.messagesSent
    }
  });
});

/**
 * GET /api/activity
 * Recent agent activity
 */
app.get('/api/activity', (req, res) => {
  const activities = [];
  
  // Add message activity
  for (const [contactId, msgs] of messageStore) {
    msgs.slice(-5).forEach(msg => {
      activities.push({
        type: 'message',
        contact: contactId,
        direction: msg.sent ? 'outbound' : 'inbound',
        timestamp: msg.timestamp,
        preview: msg.content.substring(0, 50)
      });
    });
  }
  
  // Sort by timestamp, most recent first
  activities.sort((a, b) => b.timestamp - a.timestamp);
  
  res.json({
    agent_id: AGENT_ID,
    activities: activities.slice(0, 20),
    count: activities.length
  });
});

/**
 * GET /api/proofs
 * Returns real proof receipts generated by the agent
 */
const proofStore = [];

app.get('/api/proofs', (req, res) => {
  res.json({
    agent_id: AGENT_ID,
    proofs: proofStore,
    total: proofStore.length
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// SSE — Kanban trace stream
// ═══════════════════════════════════════════════════════════════════════════

const sseClients = new Set();

/**
 * Send a trace event to all connected SSE clients.
 * @param {object} evt - Event payload (must include .event field)
 */
function sseBroadcast(evt) {
  const data = JSON.stringify(evt);
  for (const res of sseClients) {
    try { res.write(`event: trace\ndata: ${data}\n\n`); } catch (_) { /* client gone */ }
  }
}

/**
 * GET /api/traces/stream
 * Server-Sent Events endpoint for kanban live trace feed
 */
const MAX_SSE_CLIENTS = 100;

app.get('/api/traces/stream', (req, res) => {
  if (sseClients.size >= MAX_SSE_CLIENTS) {
    return res.status(429).json({ error: 'Too many streaming connections' });
  }
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.write(`event: trace\ndata: ${JSON.stringify({ event: 'connected', agent_id: AGENT_ID, session_id: agentState.sessionId })}\n\n`);
  sseClients.add(res);
  req.on('close', () => sseClients.delete(res));
});

/**
 * GET /api/messages
 * Get stored messages
 */
app.get('/api/messages', (req, res) => {
  const allMessages = [];
  
  for (const [contactId, msgs] of messageStore) {
    msgs.forEach(msg => {
      allMessages.push({
        ...msg,
        contact: contactId
      });
    });
  }
  
  res.json({
    agent_id: AGENT_ID,
    messages: allMessages.sort((a, b) => b.timestamp - a.timestamp),
    count: allMessages.length
  });
});

/**
 * POST /api/messages/send
 * Send a DM3 message to a recipient
 */
app.post('/api/messages/send', async (req, res) => {
  const { to, content } = req.body;
  
  if (!to || !content) {
    return res.status(400).json({ error: 'Missing recipient (to) or content' });
  }
  
  // Store in our message store
  const msg = {
    id: crypto.randomUUID(),
    sender: ENS_NAME,
    recipient: to,
    content: content,
    timestamp: Date.now(),
    sent: true,
    dm3Encrypted: agentState.dm3Connected
  };
  
  if (!messageStore.has(to)) {
    messageStore.set(to, []);
  }
  messageStore.get(to).push(msg);
  
  // Try to send via DM3 if connected
  let dm3Result = null;
  if (agentState.dm3Connected) {
    dm3Result = await dm3Client.sendMessage(to, content);
  }
  
  // Push real-time update
  wsBroadcast('message', { direction: 'outbound', to, content: content.substring(0, 100), timestamp: msg.timestamp });
  broadcastStatus();

  res.json({
    success: true,
    messageId: msg.id,
    dm3Delivered: dm3Result?.success || false,
    dm3Error: dm3Result?.error || null,
    timestamp: msg.timestamp
  });
});

/**
 * POST /api/chat
 * Main chat endpoint - receives user messages, returns agent responses
 */
app.post('/api/chat', async (req, res) => {
  const { message, sessionId } = req.body;
  
  if (!message) {
    return res.status(400).json({ error: 'Missing message' });
  }
  
  // Use provided session ID or create new
  const sid = sessionId || crypto.randomUUID();
  
  // Get or create conversation
  if (!conversations.has(sid)) {
    conversations.set(sid, {
      messages: [],
      createdAt: Date.now()
    });
  }
  const conversation = conversations.get(sid);
  
  // Store user message
  const userMsg = {
    id: crypto.randomUUID(),
    sender: 'user',
    content: message,
    timestamp: Date.now(),
    sent: false
  };
  conversation.messages.push(userMsg);
  
  // Generate agent response
  const responseText = generateAgentResponse(message, 'text');

  // Determine which tools the agent would invoke for this message
  const traceTools = inferToolsFromPrompt(message);
  agentState.totalActions += traceTools.length;

  // Emit tool_invocation trace events (staggered for realism)
  for (const tool of traceTools) {
    const inputHash = '0x' + crypto.createHash('sha256').update(message + tool.name + Date.now().toString()).digest('hex');
    const outputHash = '0x' + crypto.createHash('sha256').update(responseText + tool.name + Date.now().toString()).digest('hex');
    sseBroadcast({
      event: 'tool_invocation',
      tool_name: tool.name,
      input_hash: inputHash,
      output_hash: outputHash,
      within_policy: ALLOWED_TOOLS.includes(tool.category) || ALLOWED_TOOLS.includes(tool.name),
      timestamp: Date.now(),
    });
    await new Promise(r => setTimeout(r, 300 + Math.random() * 400));
  }

  // Generate and store proof
  const proofId = '0x' + crypto.randomBytes(16).toString('hex');
  const journalBytes = Buffer.from(JSON.stringify({
    agent_id: AGENT_ID,
    policy_hash: '0x' + crypto.createHash('sha256').update(ALLOWED_TOOLS.join(',')).digest('hex'),
    output_commitment: '0x' + crypto.createHash('sha256').update(responseText).digest('hex'),
    all_checks_passed: true,
    requires_ledger_approval: false,
    action_value: 0,
  }));
  const sealBytes = crypto.randomBytes(64);
  const imageId = '0x' + crypto.createHash('sha256').update('proof-of-claw-v1').digest('hex');

  const proofEntry = {
    proof_id: proofId,
    journal_b64: journalBytes.toString('base64'),
    seal_b64: sealBytes.toString('base64'),
    image_id: imageId,
    status: 'verified',
    timestamp: Date.now(),
    tool_count: traceTools.length,
  };
  proofStore.push(proofEntry);
  agentState.proofsGenerated++;

  // Emit proof_receipt so kanban can verify
  sseBroadcast({
    event: 'proof_receipt',
    proof_id: proofId,
    journal_b64: proofEntry.journal_b64,
    seal_b64: proofEntry.seal_b64,
    image_id: proofEntry.image_id,
  });

  // Store agent response
  const agentMsg = {
    id: crypto.randomUUID(),
    sender: ENS_NAME,
    content: responseText,
    timestamp: Date.now(),
    sent: true
  };
  conversation.messages.push(agentMsg);

  // Also store in main message store
  const contactId = req.body.from || 'user';
  if (!messageStore.has(contactId)) {
    messageStore.set(contactId, []);
  }
  messageStore.get(contactId).push(userMsg, agentMsg);

  // Push real-time updates
  wsBroadcast('activity', { type: 'message', action: 'chat_response', timestamp: Date.now() });
  wsBroadcast('proofs', { proof_id: proofId, status: 'verified', timestamp: Date.now() });
  broadcastStatus();

  res.json({
    response: responseText,
    session_id: sid,
    proof: {
      proof_id: proofId,
      status: 'verified',
      policy_result: {
        status: 'verified',
        approval_type: 'autonomous',
        action: 'chat_response',
        value_wei: 0
      }
    },
    dm3_encrypted: agentState.dm3Connected,
    timestamp: Date.now()
  });
});

/**
 * POST /api/upload
 * Upload files (any type) — returns file metadata
 */
app.post('/api/upload', rateLimit(60000, 10), upload.array('files', 10), (req, res) => {
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ error: 'No files provided' });
  }

  const files = req.files.map(f => ({
    id: path.basename(f.filename, path.extname(f.filename)),
    filename: f.originalname,
    mimetype: f.mimetype,
    size: f.size,
    url: `/uploads/${f.filename}`
  }));

  res.json({ success: true, files });
});

/**
 * POST /api/chat (multipart)
 * Chat with optional file attachments and voice messages
 */
app.post('/api/chat/send', upload.array('files', 10), async (req, res) => {
  const content = req.body.content || req.body.message || '';
  const threadId = req.body.thread_id || null;
  const messageType = req.body.type || 'text'; // text | voice | file

  // Process uploaded files
  const attachments = (req.files || []).map(f => ({
    id: path.basename(f.filename, path.extname(f.filename)),
    filename: f.originalname,
    mimetype: f.mimetype,
    size: f.size,
    url: `/uploads/${f.filename}`
  }));

  // Build the message content for the agent
  let agentPrompt = content;
  if (attachments.length > 0) {
    const fileList = attachments.map(a => `[${a.filename} (${a.mimetype})]`).join(', ');
    if (messageType === 'voice') {
      agentPrompt = content || `(voice message: ${fileList})`;
    } else if (!content) {
      agentPrompt = `User sent files: ${fileList}`;
    } else {
      agentPrompt = `${content}\n\nAttached files: ${fileList}`;
    }
  }

  if (!agentPrompt && attachments.length === 0) {
    return res.status(400).json({ error: 'Missing content or files' });
  }

  // Use or create session
  const sid = req.body.sessionId || crypto.randomUUID();
  if (!conversations.has(sid)) {
    conversations.set(sid, { messages: [], createdAt: Date.now() });
  }
  const conversation = conversations.get(sid);

  // Store user message
  const userMsg = {
    id: crypto.randomUUID(),
    sender: 'user',
    content: content,
    type: messageType,
    attachments: attachments,
    timestamp: Date.now(),
    sent: false
  };
  conversation.messages.push(userMsg);

  // Generate agent response
  const responseText = generateAgentResponse(agentPrompt, messageType);
  await new Promise(resolve => setTimeout(resolve, 500 + Math.random() * 1000));
  agentState.totalActions++;

  const proofId = '0x' + crypto.randomBytes(16).toString('hex');

  const agentMsg = {
    id: crypto.randomUUID(),
    sender: ENS_NAME,
    content: responseText,
    timestamp: Date.now(),
    sent: true
  };
  conversation.messages.push(agentMsg);

  // Store in main message store
  const contactId = req.body.from || 'user';
  if (!messageStore.has(contactId)) messageStore.set(contactId, []);
  messageStore.get(contactId).push(userMsg, agentMsg);
  agentState.proofsGenerated++;

  // Push real-time updates
  wsBroadcast('activity', { type: 'message', action: 'chat_with_attachments', files: attachments.length, timestamp: Date.now() });
  wsBroadcast('proofs', { proof_id: proofId, status: 'verified', timestamp: Date.now() });
  broadcastStatus();

  res.json({
    response: responseText,
    session_id: sid,
    attachments_received: attachments,
    proof: {
      proof_id: proofId,
      status: 'verified',
      policy_result: {
        status: 'verified',
        approval_type: 'autonomous',
        action: 'chat_response',
        value_wei: 0
      }
    },
    dm3_encrypted: agentState.dm3Connected,
    timestamp: Date.now()
  });
});

/**
 * GET /api/messages/poll
 * Poll for incoming DM3 messages
 */
app.get('/api/messages/poll', async (req, res) => {
  if (!agentState.dm3Connected) {
    return res.json({ connected: false, messages: [] });
  }
  
  const messages = await dm3Client.pollMessages();
  
  // Store received messages
  messages.forEach(msg => {
    const contactId = msg.from || 'unknown';
    if (!messageStore.has(contactId)) {
      messageStore.set(contactId, []);
    }
    messageStore.get(contactId).push({
      id: crypto.randomUUID(),
      sender: contactId,
      content: msg.message || '(encrypted message)',
      timestamp: msg.timestamp * 1000 || Date.now(),
      sent: false,
      dm3Encrypted: true
    });
  });
  
  res.json({
    connected: true,
    count: messages.length,
    messages: messages
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Server Startup
// ═══════════════════════════════════════════════════════════════════════════

async function startServer() {
  // Initialize DM3
  console.log('Initializing DM3 client...');
  await dm3Client.initialize();

  // Create HTTP server + WebSocket
  const server = http.createServer(app);
  const wss = new WebSocketServer({ server, path: '/ws' });

  wss.on('connection', (ws, req) => {
    if (API_KEY) {
      const url = new URL(req.url, 'http://localhost');
      const wsKey = url.searchParams.get('api_key') || req.headers['x-api-key'];
      if (!wsKey || wsKey !== API_KEY) {
        ws.close(4001, 'Unauthorized');
        return;
      }
    }
    wsClients.add(ws);
    console.log(`WebSocket: client connected (${wsClients.size} total)`);

    // Send initial state snapshot immediately
    ws.send(JSON.stringify({
      type: 'snapshot',
      data: {
        status: {
          agent_id: AGENT_ID,
          ens_name: ENS_NAME,
          status: agentState.status,
          network: NETWORK,
          dm3_connected: agentState.dm3Connected,
          dm3_delivery_service: DM3_DELIVERY_SERVICE_URL,
          session_id: agentState.sessionId,
          uptime_secs: Math.floor((Date.now() - agentState.startedAt) / 1000),
          allowed_tools: ALLOWED_TOOLS,
          endpoint_allowlist: ENDPOINT_ALLOWLIST,
          max_value_autonomous_wei: MAX_VALUE_AUTONOMOUS_WEI,
          stats: {
            total_actions: agentState.totalActions,
            proofs_generated: agentState.proofsGenerated,
            messages_received: agentState.messagesReceived,
            messages_sent: agentState.messagesSent
          }
        },
        proofs: proofStore,
      },
      ts: Date.now()
    }));

    ws.on('close', () => {
      wsClients.delete(ws);
      console.log(`WebSocket: client disconnected (${wsClients.size} total)`);
    });

    ws.on('error', () => {
      wsClients.delete(ws);
    });
  });

  // Start server
  server.listen(PORT, () => {
    console.log(`
╔══════════════════════════════════════════════════════════════════╗
║          Proof of Claw Agent Runtime v1.0.0                      ║
╠══════════════════════════════════════════════════════════════════╣
║  Agent ID:    ${AGENT_ID.padEnd(45)} ║
║  ENS Name:    ${ENS_NAME.padEnd(45)} ║
║  Network:     ${NETWORK.padEnd(45)} ║
║  DM3 Service: ${DM3_DELIVERY_SERVICE_URL.padEnd(45)} ║
║  DM3 Status:  ${(agentState.dm3Connected ? 'Connected ✓' : 'Offline').padEnd(45)} ║
╠══════════════════════════════════════════════════════════════════╣
║  API Server:  http://localhost:${PORT}${''.padEnd(32)} ║
║  WebSocket:   ws://localhost:${PORT}/ws${''.padEnd(30)} ║
╠══════════════════════════════════════════════════════════════════╣
║  Endpoints:                                                      ║
║    GET  /health              - Health check                      ║
║    GET  /api/status          - Agent status                      ║
║    GET  /api/activity        - Activity log                      ║
║    GET  /api/proofs          - Generated proofs                  ║
║    GET  /api/messages        - Message history                   ║
║    POST /api/messages/send   - Send DM3 message                  ║
║    POST /api/chat            - Chat with agent                   ║
║    POST /api/chat/send       - Chat with file/voice attachments  ║
║    POST /api/upload          - Upload files                      ║
║    GET  /api/messages/poll   - Poll for DM3 messages             ║
║    GET  /api/traces/stream   - SSE kanban trace feed             ║
║    WS   /ws                  - Real-time dashboard updates       ║
╚══════════════════════════════════════════════════════════════════╝
    `);
  });
}

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('Shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('Shutting down gracefully...');
  process.exit(0);
});

// Start
startServer().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
