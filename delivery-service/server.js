const express = require("express");
const http = require("http");
const { WebSocketServer } = require("ws");
const cors = require("cors");
const { v4: uuidv4 } = require("uuid");

const PORT = process.env.PORT || 3001;

// ---------------------------------------------------------------------------
// In-memory stores
// ---------------------------------------------------------------------------

// messages: Map<ensName, Array<envelope>>
const messageStore = new Map();

// profiles: Map<ensName, profileObject>
const profileStore = new Map();

// ws subscribers: Map<ensName, Set<WebSocket>>
const wsSubscribers = new Map();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function log(tag, msg, data) {
  const ts = new Date().toISOString();
  console.log(`[${ts}] [${tag}] ${msg}`, data !== undefined ? data : "");
}

function enqueueMessage(recipient, envelope) {
  if (!messageStore.has(recipient)) {
    messageStore.set(recipient, []);
  }
  messageStore.get(recipient).push(envelope);
}

function drainMessages(recipient) {
  const msgs = messageStore.get(recipient) || [];
  messageStore.set(recipient, []);
  return msgs;
}

function notifySubscribers(recipient, envelope) {
  const subs = wsSubscribers.get(recipient);
  if (!subs) return;
  const payload = JSON.stringify({ type: "dm3_message", envelope });
  for (const ws of subs) {
    if (ws.readyState === 1 /* OPEN */) {
      ws.send(payload);
    }
  }
}

// ---------------------------------------------------------------------------
// Security: API key authentication
// ---------------------------------------------------------------------------

const API_KEY = process.env.API_KEY || '';
if (!API_KEY) console.warn('WARNING: No API_KEY set — running without authentication (dev mode)');

function authenticateRequest(req, res, next) {
  if (!API_KEY) return next(); // dev mode
  const provided = req.headers['x-api-key'];
  if (!provided || provided !== API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// ---------------------------------------------------------------------------
// Security: rate limiting (in-memory)
// ---------------------------------------------------------------------------

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

// Clean up expired rate limit entries periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, record] of rateLimitStore) {
    if (now > record.resetAt) rateLimitStore.delete(key);
  }
}, 60000);

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------

const app = express();

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '0');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  next();
});

app.use(cors({
  origin: process.env.CORS_ORIGIN || 'http://localhost:8080',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  credentials: true
}));
app.use(express.json());

// Global rate limit
app.use(rateLimit());

// --- Health ---
app.get("/health", (_req, res) => {
  res.json({ status: "ok", uptime: process.uptime() });
});

// --- POST /messages — receive a DM3 envelope ---
app.post("/messages", authenticateRequest, (req, res) => {
  const { to, from, message, encryptionEnvelopeType, timestamp } = req.body;

  if (!to || !from || !message) {
    log("MSG", "rejected envelope — missing fields");
    return res.status(400).json({ error: "to, from, and message are required" });
  }

  const envelope = {
    id: uuidv4(),
    to,
    from,
    message,
    encryptionEnvelopeType: encryptionEnvelopeType || "x25519-xsalsa20-poly1305",
    timestamp: timestamp || Date.now(),
    receivedAt: Date.now(),
  };

  enqueueMessage(to, envelope);
  log("MSG", `stored envelope ${envelope.id}`, { from, to });

  // Push over WebSocket if recipient is connected
  notifySubscribers(to, envelope);

  res.status(201).json({ id: envelope.id });
});

// --- GET /messages/incoming?ensName=... — retrieve pending messages ---
app.get("/messages/incoming", authenticateRequest, (req, res) => {
  const ensName = req.query.ensName;
  if (!ensName) {
    return res.status(400).json({ error: "ensName query parameter is required" });
  }

  const msgs = drainMessages(ensName);
  log("MSG", `drained ${msgs.length} message(s) for ${ensName}`);
  res.json({ messages: msgs });
});

// --- POST /profile — register a DM3 profile ---
app.post("/profile", authenticateRequest, (req, res) => {
  const { ensName, publicSigningKey, publicEncryptionKey, deliveryServiceUrl } = req.body;

  if (!ensName) {
    return res.status(400).json({ error: "ensName is required" });
  }

  const profile = {
    ensName,
    publicSigningKey: publicSigningKey || null,
    publicEncryptionKey: publicEncryptionKey || null,
    deliveryServiceUrl: deliveryServiceUrl || `http://localhost:${PORT}`,
    registeredAt: Date.now(),
  };

  profileStore.set(ensName, profile);
  log("PROFILE", `registered profile for ${ensName}`);
  res.status(201).json(profile);
});

// --- GET /profile/:ensName — look up a DM3 profile ---
app.get("/profile/:ensName", authenticateRequest, (req, res) => {
  const profile = profileStore.get(req.params.ensName);
  if (!profile) {
    return res.status(404).json({ error: "profile not found" });
  }
  res.json(profile);
});

// ---------------------------------------------------------------------------
// HTTP + WebSocket server
// ---------------------------------------------------------------------------

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: "/ws" });

wss.on("connection", (ws, req) => {
  // WebSocket authentication
  if (API_KEY) {
    const url = new URL(req.url, 'http://localhost');
    if (url.searchParams.get('api_key') !== API_KEY) {
      ws.close(4001, 'Unauthorized');
      return;
    }
  }

  log("WS", "new connection", req.url);

  ws.on("message", (raw) => {
    try {
      const data = JSON.parse(raw);

      // Clients subscribe by sending { type: "subscribe", ensName: "..." }
      if (data.type === "subscribe" && data.ensName) {
        if (!wsSubscribers.has(data.ensName)) {
          wsSubscribers.set(data.ensName, new Set());
        }
        wsSubscribers.get(data.ensName).add(ws);
        log("WS", `subscribed ${data.ensName}`);
        ws.send(JSON.stringify({ type: "subscribed", ensName: data.ensName }));
      }
    } catch {
      log("WS", "invalid message received");
    }
  });

  ws.on("close", () => {
    // Remove from all subscriber sets
    for (const [, subs] of wsSubscribers) {
      subs.delete(ws);
    }
    log("WS", "connection closed");
  });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

server.listen(PORT, () => {
  log("INIT", `DM3 delivery service listening on http://localhost:${PORT}`);
  log("INIT", `WebSocket available at ws://localhost:${PORT}/ws`);
});
