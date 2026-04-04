/**
 * 1clawAI API Server
 * Simple storage/retrieval API for Google Calendar credentials and agent data
 */

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const app = express();
const PORT = process.env.ONECLAW_PORT || 3456;
const DATA_DIR = path.join(__dirname, 'data');

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Ensure data directory exists
async function ensureDataDir() {
  try {
    await fs.mkdir(DATA_DIR, { recursive: true });
  } catch (e) {
    console.error('Failed to create data directory:', e);
  }
}

// Auth middleware
function authenticateApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  const userAuth = req.headers['x-user-auth'];
  const operatorAuth = req.headers['x-operator-auth'];
  
  // In production, validate against database
  // For now, accept any non-empty API key or the hardcoded ones
  const validKeys = [
    process.env.ONECLAW_API_KEY,
    process.env.USER_AUTH_KEY,
    process.env.OPERATOR_AUTH_KEY,
    'test-key'
  ].filter(Boolean);
  
  if (!apiKey && !userAuth && !operatorAuth) {
    return res.status(401).json({ error: 'Missing authentication' });
  }
  
  // Simple validation - in production use proper key validation
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
    
    const record = {
      key: storageKey,
      originalKey: key,
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
    res.status(500).json({ error: 'Storage failed', details: error.message });
  }
});

/**
 * GET /v1/retrieve/:key
 * Retrieve stored data by key
 */
app.get('/v1/retrieve/:key', authenticateApiKey, async (req, res) => {
  try {
    const { key } = req.params;
    const filePath = path.join(DATA_DIR, `${key}.json`);
    
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
    res.status(500).json({ error: 'Retrieval failed', details: error.message });
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
    const filePath = path.join(DATA_DIR, `${key}.json`);
    
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

/**
 * POST /v1/license/verify
 * Verify license key
 */
app.post('/v1/license/verify', authenticateApiKey, async (req, res) => {
  const { licenseKey, feature, agentId } = req.body;
  
  // Simple license validation - in production check against database
  const isValid = licenseKey && licenseKey.startsWith('POC-GCAL-');
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
  
  const isValid = licenseKey && licenseKey.startsWith('POC-GCAL-');
  res.json({ valid: isValid, timestamp: Date.now() });
});

// ==================== PAYMENT ENDPOINTS ====================

/**
 * POST /v1/payment/checkout
 * Create checkout session
 */
app.post('/v1/payment/checkout', authenticateApiKey, async (req, res) => {
  const { tier, agentId, feature, successUrl, cancelUrl } = req.body;
  
  // In production, integrate with Stripe/PayPal
  // For now, return a mock checkout URL
  const mockSessionId = crypto.randomBytes(16).toString('hex');
  
  res.json({
    sessionId: mockSessionId,
    checkoutUrl: `/v1/payment/mock-checkout?session=${mockSessionId}&tier=${tier}`,
    tier,
    amount: tier === 'basic' ? 9.99 : tier === 'pro' ? 29.99 : 0
  });
});

/**
 * GET /v1/payment/mock-checkout
 * Mock checkout page
 */
app.get('/v1/payment/mock-checkout', (req, res) => {
  const { session, tier } = req.query;
  
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>1clawAI Checkout - ${tier}</title>
      <style>
        body { font-family: system-ui; max-width: 400px; margin: 50px auto; padding: 20px; }
        .card { border: 1px solid #ddd; border-radius: 8px; padding: 20px; }
        button { width: 100%; padding: 12px; background: #00e5ff; border: none; border-radius: 6px; cursor: pointer; }
      </style>
    </head>
    <body>
      <div class="card">
        <h2>1clawAI Checkout</h2>
        <p>Plan: <strong>${tier}</strong></p>
        <p>Amount: $${tier === 'basic' ? '9.99' : tier === 'pro' ? '29.99' : '0'}</p>
        <button onclick="completePayment()">Complete Payment (Mock)</button>
      </div>
      <script>
        function completePayment() {
          window.location.href = '/v1/payment/success?session=${session}&tier=${tier}';
        }
      </script>
    </body>
    </html>
  `);
});

/**
 * GET /v1/payment/success
 * Payment success callback
 */
app.get('/v1/payment/success', (req, res) => {
  const { session, tier } = req.query;
  
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>Payment Success</title></head>
    <body>
      <h1>Payment Successful!</h1>
      <p>Tier: ${tier}</p>
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

// ==================== HEALTH & INFO ====================

app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: Date.now(),
    version: '1.0.0',
    endpoints: [
      'POST /v1/store',
      'GET /v1/retrieve/:key',
      'POST /v1/retrieve',
      'DELETE /v1/delete/:key',
      'POST /v1/license/verify',
      'POST /v1/license/validate',
      'POST /v1/payment/checkout',
      'POST /v1/agents/tasks',
      'GET /v1/agents/:agentId/tasks'
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
ensureDataDir().then(() => {
  app.listen(PORT, () => {
    console.log(`
╔════════════════════════════════════════════════════════╗
║           1clawAI API Server v1.0.0                    ║
╠════════════════════════════════════════════════════════╣
║  Running on: http://localhost:${PORT}                   ║
║  Data directory: ${DATA_DIR}            ║
╚════════════════════════════════════════════════════════╝

Endpoints:
  POST /v1/store          - Store data
  GET  /v1/retrieve/:key  - Retrieve data
  POST /v1/license/verify - Verify license
  POST /v1/payment/checkout - Create checkout
  POST /v1/agents/tasks - Store agent tasks
  GET  /health          - Health check
    `);
  });
});
