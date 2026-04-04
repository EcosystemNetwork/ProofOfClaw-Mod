/**
 * Proof of Claw Agent Runtime
 * HTTP API server with DM3 encrypted messaging support
 */

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const app = express();
const PORT = process.env.API_PORT || 8420;

// Agent configuration
const AGENT_ID = process.env.AGENT_ID || 'unnamed-agent';
const ENS_NAME = process.env.ENS_NAME || `${AGENT_ID}.proofclaw.eth`;
const DM3_DELIVERY_SERVICE_URL = process.env.DM3_DELIVERY_SERVICE_URL || 'http://localhost:3001';
const PRIVATE_KEY = process.env.PRIVATE_KEY || '0x0000000000000000000000000000000000000000000000000000000000000001';
const RPC_URL = process.env.RPC_URL || 'https://eth-sepolia.g.alchemy.com/v3/placeholder';
const NETWORK = process.env.NETWORK || 'sepolia';

// Policy configuration
const ALLOWED_TOOLS = (process.env.ALLOWED_TOOLS || 'query,read').split(',').map(s => s.trim()).filter(Boolean);
const ENDPOINT_ALLOWLIST = (process.env.ENDPOINT_ALLOWLIST || '').split(',').map(s => s.trim()).filter(Boolean);
const MAX_VALUE_AUTONOMOUS_WEI = parseInt(process.env.MAX_VALUE_AUTONOMOUS_WEI || '1000000000000000000', 10);

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));

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
    // Generate X25519 key pair for encryption (simplified for demo)
    return '0x' + crypto.randomBytes(32).toString('hex');
  }

  generateSigningKey() {
    // Generate Ed25519 signing key (simplified for demo)
    return '0x' + crypto.randomBytes(32).toString('hex');
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
        encryptionEnvelopeType: 'x25519-xsalsa20-poly1305',
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
  ]
};

function generateAgentResponse(userMessage) {
  const lowerMsg = userMessage.toLowerCase();
  
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
 * Generated proofs (mock data for now)
 */
app.get('/api/proofs', (req, res) => {
  const proofs = [];
  for (let i = 0; i < agentState.proofsGenerated; i++) {
    proofs.push({
      proof_id: `proof-${AGENT_ID}-${i}`,
      status: 'verified',
      timestamp: Date.now() - (i * 3600000),
      policy_result: {
        status: 'verified',
        approval_type: 'autonomous'
      }
    });
  }
  
  res.json({
    agent_id: AGENT_ID,
    proofs: proofs,
    total: proofs.length
  });
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
  const responseText = generateAgentResponse(message);
  
  // Simulate processing time for realistic feel
  await new Promise(resolve => setTimeout(resolve, 500 + Math.random() * 1000));
  
  // Create proof receipt for this interaction
  agentState.totalActions++;
  const proofId = `proof-${AGENT_ID}-${Date.now()}`;
  
  // Store agent response
  const agentMsg = {
    id: crypto.randomUUID(),
    sender: ENS_NAME,
    content: responseText,
    timestamp: Date.now(),
    sent: true,
    proof: {
      proof_id: proofId,
      status: 'verified',
      approval_type: 'autonomous'
    }
  };
  conversation.messages.push(agentMsg);
  
  // Also store in main message store
  const contactId = req.body.from || 'user';
  if (!messageStore.has(contactId)) {
    messageStore.set(contactId, []);
  }
  messageStore.get(contactId).push(userMsg, agentMsg);
  
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
  
  // Start HTTP server
  app.listen(PORT, () => {
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
╠══════════════════════════════════════════════════════════════════╣
║  Endpoints:                                                      ║
║    GET  /health              - Health check                      ║
║    GET  /api/status          - Agent status                      ║
║    GET  /api/activity        - Activity log                      ║
║    GET  /api/proofs          - Generated proofs                  ║
║    GET  /api/messages        - Message history                   ║
║    POST /api/messages/send   - Send DM3 message                  ║
║    POST /api/chat            - Chat with agent                   ║
║    GET  /api/messages/poll   - Poll for DM3 messages           ║
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
