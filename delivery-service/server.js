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
// Express app
// ---------------------------------------------------------------------------

const app = express();
app.use(cors());
app.use(express.json());

// --- Health ---
app.get("/health", (_req, res) => {
  res.json({ status: "ok", uptime: process.uptime() });
});

// --- POST /messages — receive a DM3 envelope ---
app.post("/messages", (req, res) => {
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
app.get("/messages/incoming", (req, res) => {
  const ensName = req.query.ensName;
  if (!ensName) {
    return res.status(400).json({ error: "ensName query parameter is required" });
  }

  const msgs = drainMessages(ensName);
  log("MSG", `drained ${msgs.length} message(s) for ${ensName}`);
  res.json({ messages: msgs });
});

// --- POST /profile — register a DM3 profile ---
app.post("/profile", (req, res) => {
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
app.get("/profile/:ensName", (req, res) => {
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
