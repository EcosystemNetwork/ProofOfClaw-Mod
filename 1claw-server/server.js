/**
 * 1clawAI API Server
 * Simple storage/retrieval API for Google Calendar credentials and agent data
 */

const express = require('express');
const cors = require('cors');
const crypto = require('node:crypto');
const fs = require('fs').promises;
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
const db = require('./db');

const app = express();
const PORT = process.env.ONECLAW_PORT || 3456;
const DATA_DIR = path.join(__dirname, 'data');

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

// Clean up expired rate limit entries periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, record] of rateLimitStore) {
    if (now > record.resetAt) rateLimitStore.delete(key);
  }
}, 60000);

// Security headers
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

// Stripe setup (must be before webhook route)
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
let stripe = null;

if (STRIPE_SECRET_KEY) {
  stripe = require('stripe')(STRIPE_SECRET_KEY);
  console.log('Stripe payment routes enabled');
} else {
  console.warn('WARNING: STRIPE_SECRET_KEY not set — payment routes disabled');
}

// Stripe webhook needs raw body — mount BEFORE express.json()
app.post('/v1/payment/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) {
    return res.status(503).json({ error: 'Webhook not configured' });
  }

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send('Webhook Error');
  }

  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object;
      console.log(`Payment completed: tier=${session.metadata.tier}, agent=${session.metadata.agentId}`);
      break;
    }
    default:
      console.log(`Unhandled Stripe event: ${event.type}`);
  }

  res.json({ received: true });
});

app.use(express.json({ limit: '10mb' }));

// Global rate limit
app.use(rateLimit());

// Ensure data directory exists
async function ensureDataDir() {
  try {
    await fs.mkdir(DATA_DIR, { recursive: true });
  } catch (e) {
    console.error('Failed to create data directory:', e);
  }
}

// Path traversal guard — ensures resolved path stays within DATA_DIR
function safePath(key) {
  const resolved = path.resolve(DATA_DIR, `${key}.json`);
  if (!resolved.startsWith(path.resolve(DATA_DIR) + path.sep)) {
    return null;
  }
  return resolved;
}

// HTML-escape for safe template rendering
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Timing-safe string comparison to prevent timing attacks on API keys
function timingSafeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    // Compare against self to maintain constant time
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

// ── SIWE (Sign-In with Ethereum) ──
const siweSessions = new Map();
const siweNonces = new Map();

let ethersVerifyMessage;
try {
  const ethers = require('ethers');
  ethersVerifyMessage = ethers.verifyMessage;
} catch { /* ethers not available — SIWE disabled */ }

if (ethersVerifyMessage) {
  app.get('/auth/nonce', (req, res) => {
    const nonce = crypto.randomBytes(16).toString('hex');
    siweNonces.set(nonce, Date.now() + 5 * 60 * 1000);
    res.json({ nonce });
  });

  app.post('/auth/siwe', (req, res) => {
    try {
      const { message, signature } = req.body;
      if (!message || !signature) return res.status(400).json({ error: 'Missing message or signature' });

      const addressMatch = message.match(/^(0x[a-fA-F0-9]{40})$/m);
      if (!addressMatch) return res.status(400).json({ error: 'No address in SIWE message' });
      const claimedAddress = addressMatch[1];

      const nonceMatch = message.match(/Nonce:\s*([^\n]+)/);
      if (nonceMatch) {
        const nonce = nonceMatch[1].trim();
        const expiry = siweNonces.get(nonce);
        if (!expiry || Date.now() > expiry) return res.status(400).json({ error: 'Invalid or expired nonce' });
        siweNonces.delete(nonce);
      }

      const recovered = ethersVerifyMessage(message, signature);
      if (recovered.toLowerCase() !== claimedAddress.toLowerCase()) {
        return res.status(401).json({ error: 'Signature mismatch' });
      }

      const token = crypto.randomBytes(32).toString('hex');
      const expiresAt = Date.now() + 24 * 60 * 60 * 1000;
      siweSessions.set(token, { address: recovered, expiresAt });

      for (const [t, s] of siweSessions) { if (s.expiresAt < Date.now()) siweSessions.delete(t); }
      for (const [n, e] of siweNonces) { if (Date.now() > e) siweNonces.delete(n); }

      res.json({ token, address: recovered, expiresAt });
    } catch (err) {
      res.status(400).json({ error: 'SIWE verification failed' });
    }
  });
}

// Auth middleware
function authenticateApiKey(req, res, next) {
  // Check SIWE Bearer token first
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7);
    const session = siweSessions.get(token);
    if (session && session.expiresAt > Date.now()) {
      req.walletAddress = session.address;
      return next();
    }
  }

  const apiKey = req.headers['x-api-key'];
  const userAuth = req.headers['x-user-auth'];
  const operatorAuth = req.headers['x-operator-auth'];

  const validKeys = [
    process.env.ONECLAW_API_KEY,
    process.env.USER_AUTH_KEY,
    process.env.OPERATOR_AUTH_KEY,
  ].filter(Boolean);

  if (!apiKey && !userAuth && !operatorAuth) {
    return res.status(401).json({ error: 'Missing authentication' });
  }

  // Reject all requests if no API keys are configured
  if (validKeys.length === 0) {
    return res.status(503).json({ error: 'Server not configured — no API keys set' });
  }

  // Validate the provided key against known valid keys (timing-safe)
  const providedKey = apiKey || userAuth || operatorAuth;
  const isValid = validKeys.some(key => timingSafeCompare(key, providedKey));
  if (!isValid) {
    return res.status(403).json({ error: 'Invalid authentication key' });
  }

  req.agentId = req.body.agentId || req.query.agentId || 'anonymous';
  next();
}

// ==================== STORAGE ENDPOINTS ====================

/**
 * POST /v1/store
 * Store arbitrary data with a key
 */
app.post('/v1/store', authenticateApiKey, async (req, res) => {
  try {
    const { key, data, metadata = {}, ttl } = req.body;
    
    if (!key || !data) {
      return res.status(400).json({ error: 'Missing key or data' });
    }
    
    const storageKey = crypto.createHash('sha256')
      .update(`${req.agentId}:${key}`)
      .digest('hex');
    
    // Sanitize originalKey: only allow alphanumeric, hyphens, underscores, dots, colons
    const safeKey = key.replace(/[^a-zA-Z0-9\-_.:\/]/g, '');

    const record = {
      key: storageKey,
      originalKey: safeKey,
      agentId: req.agentId,
      data,
      metadata,
      createdAt: Date.now(),
      expiresAt: ttl ? Date.now() + ttl : null,
      version: 1
    };
    
    // Save to file
    const filePath = path.join(DATA_DIR, `${storageKey}.json`);
    await fs.writeFile(filePath, JSON.stringify(record, null, 2));
    
    res.json({
      success: true,
      storageKey,
      url: `/v1/retrieve/${storageKey}`,
      createdAt: record.createdAt
    });
    
  } catch (error) {
    console.error('Store error:', error);
    res.status(500).json({ error: 'Storage failed', details: 'Internal error' });
  }
});

/**
 * GET /v1/retrieve/:key
 * Retrieve stored data by key
 */
app.get('/v1/retrieve/:key', authenticateApiKey, async (req, res) => {
  try {
    const { key } = req.params;
    const filePath = safePath(key);
    if (!filePath) return res.status(400).json({ error: 'Invalid key' });
    
    try {
      const content = await fs.readFile(filePath, 'utf-8');
      const record = JSON.parse(content);
      
      // Check expiration
      if (record.expiresAt && record.expiresAt < Date.now()) {
        await fs.unlink(filePath);
        return res.status(410).json({ error: 'Data expired' });
      }
      
      res.json({
        success: true,
        data: record.data,
        metadata: record.metadata,
        createdAt: record.createdAt,
        version: record.version
      });
      
    } catch (e) {
      if (e.code === 'ENOENT') {
        return res.status(404).json({ error: 'Key not found' });
      }
      throw e;
    }
    
  } catch (error) {
    console.error('Retrieve error:', error);
    res.status(500).json({ error: 'Retrieval failed', details: 'Internal error' });
  }
});

/**
 * POST /v1/retrieve
 * Retrieve with agent-scoped key
 */
app.post('/v1/retrieve', authenticateApiKey, async (req, res) => {
  try {
    const { key, agentId } = req.body;
    
    if (!key) {
      return res.status(400).json({ error: 'Missing key' });
    }
    
    const targetAgent = agentId || req.agentId;
    const storageKey = crypto.createHash('sha256')
      .update(`${targetAgent}:${key}`)
      .digest('hex');
    
    const filePath = path.join(DATA_DIR, `${storageKey}.json`);
    
    try {
      const content = await fs.readFile(filePath, 'utf-8');
      const record = JSON.parse(content);
      
      if (record.expiresAt && record.expiresAt < Date.now()) {
        await fs.unlink(filePath);
        return res.status(410).json({ error: 'Data expired' });
      }
      
      res.json({
        success: true,
        data: record.data,
        metadata: record.metadata,
        createdAt: record.createdAt
      });
      
    } catch (e) {
      if (e.code === 'ENOENT') {
        return res.status(404).json({ error: 'Key not found' });
      }
      throw e;
    }
    
  } catch (error) {
    console.error('Retrieve error:', error);
    res.status(500).json({ error: 'Retrieval failed' });
  }
});

/**
 * DELETE /v1/delete/:key
 * Delete stored data
 */
app.delete('/v1/delete/:key', authenticateApiKey, async (req, res) => {
  try {
    const { key } = req.params;
    const filePath = safePath(key);
    if (!filePath) return res.status(400).json({ error: 'Invalid key' });
    
    try {
      await fs.unlink(filePath);
      res.json({ success: true, deleted: key });
    } catch (e) {
      if (e.code === 'ENOENT') {
        return res.status(404).json({ error: 'Key not found' });
      }
      throw e;
    }
    
  } catch (error) {
    res.status(500).json({ error: 'Delete failed' });
  }
});

// ==================== LICENSE ENDPOINTS ====================

// License format validation: POC-GCAL-XXXX-XXXX-XXXX (alphanumeric segments, 20+ chars)
function validateLicenseFormat(key) {
  return /^POC-GCAL-[A-Z0-9]{4,}-[A-Z0-9]{4,}-[A-Z0-9]{4,}$/.test(key);
}

/**
 * POST /v1/license/verify
 * Verify license key
 */
app.post('/v1/license/verify', authenticateApiKey, async (req, res) => {
  const { licenseKey, feature, agentId } = req.body;
  
  // Validate license format: POC-GCAL-XXXX-XXXX-XXXX with minimum length and structure
  const isValid = licenseKey && validateLicenseFormat(licenseKey);
  const tier = licenseKey?.split('-')[2] || 'free';
  
  res.json({
    valid: isValid,
    tier: ['free', 'basic', 'pro', 'enterprise'].includes(tier) ? tier : 'free',
    features: [feature || 'google-calendar'],
    expiresAt: null
  });
});

/**
 * POST /v1/license/validate
 * Validate package license
 */
app.post('/v1/license/validate', authenticateApiKey, async (req, res) => {
  const { licenseKey, feature } = req.body;
  
  // Store license check for analytics
  const checkRecord = {
    licenseKey: licenseKey?.substring(0, 20) + '...',
    feature,
    checkedAt: Date.now(),
    ip: req.ip
  };
  
  console.log('License check:', checkRecord);
  
  const isValid = licenseKey && validateLicenseFormat(licenseKey);
  res.json({ valid: isValid, timestamp: Date.now() });
});

// ==================== PAYMENT ENDPOINTS (Stripe) ====================
// NOTE: stripe, STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET declared above express.json() middleware

const TIER_PRICES = {
  basic: { amount: 999, name: '1clawAI Basic' },
  pro: { amount: 2999, name: '1clawAI Pro' }
};

/**
 * POST /v1/payment/checkout
 * Create a real Stripe Checkout Session
 */
app.post('/v1/payment/checkout', authenticateApiKey, async (req, res) => {
  if (!stripe) {
    return res.status(503).json({ error: 'Payment system not configured. Set STRIPE_SECRET_KEY.' });
  }

  const { tier, agentId, successUrl, cancelUrl } = req.body;
  const priceInfo = TIER_PRICES[tier];
  if (!priceInfo) {
    return res.status(400).json({ error: `Unknown tier: ${tier}. Valid: basic, pro` });
  }

  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: { name: priceInfo.name },
          unit_amount: priceInfo.amount
        },
        quantity: 1
      }],
      mode: 'payment',
      success_url: successUrl || `${req.protocol}://${req.get('host')}/v1/payment/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: cancelUrl || `${req.protocol}://${req.get('host')}/`,
      metadata: { agentId: agentId || '', tier }
    });

    res.json({
      sessionId: session.id,
      checkoutUrl: session.url,
      tier,
      amount: priceInfo.amount / 100
    });
  } catch (err) {
    console.error('Stripe checkout error:', err.message);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

// NOTE: /v1/payment/webhook is mounted above express.json() to receive raw body for Stripe signature verification

/**
 * GET /v1/payment/success
 * Payment success redirect page
 */
app.get('/v1/payment/success', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>Payment Success</title></head>
    <body>
      <h1>Payment Successful!</h1>
      <p>You can close this window and return to the app.</p>
      <script>
        setTimeout(() => window.close(), 3000);
      </script>
    </body>
    </html>
  `);
});

// ==================== AGENT TASKS ENDPOINTS ====================

/**
 * POST /v1/agents/tasks
 * Store agent tasks
 */
app.post('/v1/agents/tasks', authenticateApiKey, async (req, res) => {
  try {
    const { agentId, tasks, source, timestamp } = req.body;
    
    const storageKey = `tasks-${agentId}-${Date.now()}`;
    const hashedKey = crypto.createHash('sha256').update(storageKey).digest('hex');
    
    const record = {
      key: hashedKey,
      agentId,
      tasks,
      source: source || 'unknown',
      timestamp: timestamp || Date.now(),
      createdAt: Date.now()
    };
    
    const filePath = path.join(DATA_DIR, `${hashedKey}.json`);
    await fs.writeFile(filePath, JSON.stringify(record, null, 2));
    
    res.json({
      success: true,
      taskCount: tasks.length,
      storageKey: hashedKey
    });
    
  } catch (error) {
    res.status(500).json({ error: 'Failed to store tasks' });
  }
});

/**
 * GET /v1/agents/:agentId/tasks
 * Retrieve agent tasks
 */
app.get('/v1/agents/:agentId/tasks', authenticateApiKey, async (req, res) => {
  try {
    const { agentId } = req.params;

    // TODO: Bind agentId to authenticated identity — currently any authenticated user
    // can query any agent's tasks. For now, log access for audit trail.
    console.log(`Task query: agent=${req.params.agentId} from=${req.ip}`);

    const files = await fs.readdir(DATA_DIR);
    
    const tasks = [];
    for (const file of files) {
      if (!file.endsWith('.json')) continue;
      
      try {
        const content = await fs.readFile(path.join(DATA_DIR, file), 'utf-8');
        const record = JSON.parse(content);
        if (record.agentId === agentId && record.tasks) {
          tasks.push(record);
        }
      } catch (e) {
        // Skip invalid files
      }
    }
    
    res.json({
      success: true,
      agentId,
      taskSets: tasks.sort((a, b) => b.createdAt - a.createdAt)
    });
    
  } catch (error) {
    res.status(500).json({ error: 'Failed to retrieve tasks' });
  }
});

// ==================== SOUL BACKUP ENDPOINTS (OCMB v0.1) ====================

/**
 * POST /v1/soul-backup/upload
 * Store an agent's soul backup (OCMB v0.1 YAML)
 * Required before iNFT minting — agents must have a soul to exist.
 */
app.post('/v1/soul-backup/upload', authenticateApiKey, async (req, res) => {
  try {
    const { agentId, soulBackupYaml, metadata = {} } = req.body;

    if (!agentId || !soulBackupYaml) {
      return res.status(400).json({ error: 'Missing agentId or soulBackupYaml' });
    }

    // Validate OCMB minimum: must contain openclaw_backup and the_reach
    if (!soulBackupYaml.includes('openclaw_backup') || !soulBackupYaml.includes('the_reach')) {
      return res.status(400).json({
        error: 'Invalid OCMB format',
        details: 'Soul backup must contain openclaw_backup header and the_reach section'
      });
    }

    // Compute SHA-256 hash
    const hash = crypto.createHash('sha256').update(soulBackupYaml).digest('hex');
    const soulBackupHash = '0x' + hash;

    // Store with agent-scoped key
    const storageKey = crypto.createHash('sha256')
      .update(`soul-backup:${agentId}`)
      .digest('hex');

    const record = {
      key: storageKey,
      agentId,
      type: 'soul-backup',
      version: '0.1',
      soulBackupYaml,
      soulBackupHash,
      metadata,
      createdAt: Date.now(),
      updatedAt: Date.now()
    };

    const filePath = path.join(DATA_DIR, `${storageKey}.json`);
    await fs.writeFile(filePath, JSON.stringify(record, null, 2));

    res.json({
      success: true,
      agentId,
      soulBackupHash,
      storageKey,
      url: `/v1/soul-backup/${agentId}`,
      createdAt: record.createdAt
    });

  } catch (error) {
    console.error('Soul backup upload error:', error);
    res.status(500).json({ error: 'Soul backup upload failed', details: 'Internal error' });
  }
});

/**
 * GET /v1/soul-backup/:agentId
 * Retrieve an agent's soul backup for reassembly
 */
app.get('/v1/soul-backup/:agentId', authenticateApiKey, async (req, res) => {
  try {
    const { agentId } = req.params;
    const storageKey = crypto.createHash('sha256')
      .update(`soul-backup:${agentId}`)
      .digest('hex');

    const filePath = path.join(DATA_DIR, `${storageKey}.json`);

    try {
      const content = await fs.readFile(filePath, 'utf-8');
      const record = JSON.parse(content);

      res.json({
        success: true,
        agentId: record.agentId,
        soulBackupYaml: record.soulBackupYaml,
        soulBackupHash: record.soulBackupHash,
        version: record.version,
        createdAt: record.createdAt,
        updatedAt: record.updatedAt
      });
    } catch (e) {
      if (e.code === 'ENOENT') {
        return res.status(404).json({ error: 'No soul backup found for this agent' });
      }
      throw e;
    }

  } catch (error) {
    console.error('Soul backup retrieve error:', error);
    res.status(500).json({ error: 'Soul backup retrieval failed' });
  }
});

/**
 * POST /v1/soul-backup/verify
 * Verify a soul backup hash matches stored content
 */
app.post('/v1/soul-backup/verify', authenticateApiKey, async (req, res) => {
  try {
    const { agentId, soulBackupHash } = req.body;

    if (!agentId || !soulBackupHash) {
      return res.status(400).json({ error: 'Missing agentId or soulBackupHash' });
    }

    const storageKey = crypto.createHash('sha256')
      .update(`soul-backup:${agentId}`)
      .digest('hex');

    const filePath = path.join(DATA_DIR, `${storageKey}.json`);

    try {
      const content = await fs.readFile(filePath, 'utf-8');
      const record = JSON.parse(content);
      const matches = record.soulBackupHash === soulBackupHash;

      res.json({
        success: true,
        agentId,
        verified: matches,
        storedHash: record.soulBackupHash,
        providedHash: soulBackupHash
      });
    } catch (e) {
      if (e.code === 'ENOENT') {
        return res.json({ success: true, agentId, verified: false, reason: 'No backup found' });
      }
      throw e;
    }

  } catch (error) {
    res.status(500).json({ error: 'Verification failed' });
  }
});

// ==================== USER PREFERENCES (Neon DB) ====================

/**
 * Middleware: extract wallet address from header
 */
function requireWallet(req, res, next) {
  const wallet = req.headers['x-wallet-address'];
  if (!wallet || !/^0x[a-fA-F0-9]{40}$/.test(wallet)) {
    return res.status(400).json({ error: 'Missing or invalid x-wallet-address header' });
  }
  req.wallet = wallet.toLowerCase();
  next();
}

/**
 * GET /v1/preferences
 * Get all preferences for a wallet
 */
app.get('/v1/preferences', authenticateApiKey, requireWallet, async (req, res) => {
  try {
    const prefs = await db.getAllPreferences(req.wallet);
    res.json({ success: true, preferences: prefs });
  } catch (error) {
    console.error('Get preferences error:', error);
    res.status(500).json({ error: 'Failed to retrieve preferences' });
  }
});

/**
 * GET /v1/preferences/:key
 * Get a single preference
 */
app.get('/v1/preferences/:key', authenticateApiKey, requireWallet, async (req, res) => {
  try {
    const value = await db.getPreference(req.wallet, req.params.key);
    if (value === null) {
      return res.status(404).json({ error: 'Preference not found' });
    }
    res.json({ success: true, key: req.params.key, value });
  } catch (error) {
    console.error('Get preference error:', error);
    res.status(500).json({ error: 'Failed to retrieve preference' });
  }
});

/**
 * PUT /v1/preferences/:key
 * Set a single preference
 */
app.put('/v1/preferences/:key', authenticateApiKey, requireWallet, async (req, res) => {
  try {
    const { value } = req.body;
    if (value === undefined) {
      return res.status(400).json({ error: 'Missing value in request body' });
    }
    await db.setPreference(req.wallet, req.params.key, value);
    res.json({ success: true, key: req.params.key });
  } catch (error) {
    console.error('Set preference error:', error);
    res.status(500).json({ error: 'Failed to save preference' });
  }
});

/**
 * PUT /v1/preferences
 * Bulk set preferences { preferences: { key: value, ... } }
 */
app.put('/v1/preferences', authenticateApiKey, requireWallet, async (req, res) => {
  try {
    const { preferences } = req.body;
    if (!preferences || typeof preferences !== 'object') {
      return res.status(400).json({ error: 'Missing preferences object in body' });
    }
    await db.bulkSetPreferences(req.wallet, preferences);
    res.json({ success: true, count: Object.keys(preferences).length });
  } catch (error) {
    console.error('Bulk set preferences error:', error);
    res.status(500).json({ error: 'Failed to save preferences' });
  }
});

/**
 * DELETE /v1/preferences/:key
 * Delete a single preference
 */
app.delete('/v1/preferences/:key', authenticateApiKey, requireWallet, async (req, res) => {
  try {
    await db.deletePreference(req.wallet, req.params.key);
    res.json({ success: true, deleted: req.params.key });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete preference' });
  }
});

// ── Organization endpoints ──

/**
 * GET /v1/org
 * Get user's organization
 */
app.get('/v1/org', authenticateApiKey, requireWallet, async (req, res) => {
  try {
    const org = await db.getOrg(req.wallet);
    if (!org) return res.status(404).json({ error: 'No organization found' });
    res.json({ success: true, org });
  } catch (error) {
    console.error('Get org error:', error);
    res.status(500).json({ error: 'Failed to retrieve organization' });
  }
});

/**
 * PUT /v1/org
 * Create or update organization
 */
app.put('/v1/org', authenticateApiKey, requireWallet, async (req, res) => {
  try {
    const { org } = req.body;
    if (!org || !org.id || !org.name || !org.slug) {
      return res.status(400).json({ error: 'Missing org data (id, name, slug required)' });
    }
    await db.upsertOrg(req.wallet, org);
    res.json({ success: true, org });
  } catch (error) {
    console.error('Upsert org error:', error);
    res.status(500).json({ error: 'Failed to save organization' });
  }
});

// ── Swarm endpoints ──

/**
 * GET /v1/swarms
 * Get all swarms for user
 */
app.get('/v1/swarms', authenticateApiKey, requireWallet, async (req, res) => {
  try {
    const swarms = await db.getSwarms(req.wallet);
    res.json({ success: true, swarms });
  } catch (error) {
    console.error('Get swarms error:', error);
    res.status(500).json({ error: 'Failed to retrieve swarms' });
  }
});

/**
 * PUT /v1/swarms
 * Create or update a swarm
 */
app.put('/v1/swarms', authenticateApiKey, requireWallet, async (req, res) => {
  try {
    const { swarm } = req.body;
    if (!swarm || !swarm.id || !swarm.name || !swarm.slug || !swarm.orgId) {
      return res.status(400).json({ error: 'Missing swarm data (id, name, slug, orgId required)' });
    }
    await db.upsertSwarm(req.wallet, swarm);
    res.json({ success: true, swarm });
  } catch (error) {
    console.error('Upsert swarm error:', error);
    res.status(500).json({ error: 'Failed to save swarm' });
  }
});

/**
 * DELETE /v1/swarms/:id
 * Delete a swarm
 */
app.delete('/v1/swarms/:id', authenticateApiKey, requireWallet, async (req, res) => {
  try {
    await db.deleteSwarm(req.wallet, req.params.id);
    res.json({ success: true, deleted: req.params.id });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete swarm' });
  }
});

// ==================== HEALTH & INFO ====================

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: Date.now(),
    version: '1.1.0',
    database: !!process.env.DATABASE_URL,
    endpoints: [
      'POST /v1/store',
      'GET /v1/retrieve/:key',
      'POST /v1/retrieve',
      'DELETE /v1/delete/:key',
      'POST /v1/soul-backup/upload',
      'GET /v1/soul-backup/:agentId',
      'POST /v1/soul-backup/verify',
      'POST /v1/license/verify',
      'POST /v1/license/validate',
      'POST /v1/payment/checkout',
      'POST /v1/agents/tasks',
      'GET /v1/agents/:agentId/tasks',
      'GET /v1/preferences',
      'GET /v1/preferences/:key',
      'PUT /v1/preferences/:key',
      'PUT /v1/preferences',
      'DELETE /v1/preferences/:key',
      'GET /v1/org',
      'PUT /v1/org',
      'GET /v1/swarms',
      'PUT /v1/swarms',
      'DELETE /v1/swarms/:id'
    ]
  });
});

app.get('/', (req, res) => {
  res.json({
    name: '1clawAI API Server',
    version: '1.0.0',
    description: 'Storage and retrieval API for Google Calendar integration',
    docs: '/health'
  });
});

// Start server
Promise.all([ensureDataDir(), db.initDB()]).then(([, dbReady]) => {
  app.listen(PORT, () => {
    console.log(`
╔════════════════════════════════════════════════════════╗
║           1clawAI API Server v1.1.0                    ║
╠════════════════════════════════════════════════════════╣
║  Running on: http://localhost:${PORT}                   ║
║  Database:   ${dbReady ? 'Neon Postgres ✓' : 'Not configured (localStorage-only)'}${' '.repeat(Math.max(0, 25 - (dbReady ? 16 : 38)))}║
║  Data directory: ${DATA_DIR}            ║
╚════════════════════════════════════════════════════════╝

Endpoints:
  POST /v1/store            - Store data
  GET  /v1/retrieve/:key    - Retrieve data
  POST /v1/license/verify   - Verify license
  POST /v1/payment/checkout - Create checkout
  POST /v1/agents/tasks     - Store agent tasks
  GET  /v1/preferences      - Get all user preferences
  PUT  /v1/preferences/:key - Set a preference
  GET  /v1/org              - Get organization
  PUT  /v1/org              - Save organization
  GET  /v1/swarms           - Get swarms
  PUT  /v1/swarms           - Save swarm
  GET  /health              - Health check
    `);
  });
});
