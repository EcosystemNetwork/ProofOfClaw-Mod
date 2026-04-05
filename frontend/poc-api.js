/**
 * Proof of Claw — Universal Agent Connection Layer
 * Framework-agnostic: supports OpenClaw, Swarm, Agent Zero, PicoClaw, ElizaOS, and any agent with an HTTP API.
 *
 * localStorage keys:
 *   poc_agents       — array of agent objects (synced from live runtime)
 *   poc_connection    — { url, agentId, ens, framework, connectedAt } when connected to live agent
 */

const PocAPI = (() => {
  // ── connection state ──
  function getConnection() {
    try { return JSON.parse(localStorage.getItem('poc_connection')); } catch { return null; }
  }
  function setConnection(conn) {
    localStorage.setItem('poc_connection', JSON.stringify(conn));
    if (typeof PocPersist !== 'undefined') PocPersist.savePref('poc_connection', conn);
  }
  function clearConnection() {
    localStorage.removeItem('poc_connection');
    if (typeof PocPersist !== 'undefined') PocPersist.savePref('poc_connection', null);
  }
  function isConnected() {
    return !!getConnection();
  }

  // ── Framework detection ──
  // Probe multiple endpoints to identify what framework the agent is running
  const FRAMEWORK_PROBES = {
    health:  ['/health', '/api/status', '/status', '/ready', '/api/v1/status', '/healthz'],
    status:  ['/api/status', '/health', '/status', '/api/v1/status', '/agents'],
    chat:    ['/api/messages/send', '/v1/chat', '/api/chat', '/api/v1/send', '/chat/completions'],
    activity:['/api/activity'],
    proofs:  ['/api/proofs'],
    messages:['/api/messages', '/api/v1/messages', '/api/webhooks/messages'],
  };

  // Try a list of paths, return first that works
  async function probeEndpoints(baseUrl, paths, method, body, timeout) {
    timeout = timeout || 5000;
    for (const path of paths) {
      try {
        const opts = { method: method || 'GET', signal: AbortSignal.timeout(timeout) };
        if (body) {
          opts.headers = { 'Content-Type': 'application/json' };
          opts.body = JSON.stringify(body);
        }
        const r = await fetch(`${baseUrl}${path}`, opts);
        if (!r.ok) continue;
        const ct = r.headers.get('content-type') || '';
        const data = ct.includes('json') ? await r.json() : null;
        return { ok: true, path, data };
      } catch {}
    }
    return { ok: false };
  }

  // Detect which framework from a status/health response
  function detectFramework(data, hitPath) {
    if (!data) return 'unknown';
    // ElizaOS: returns { agents: [...] } from /agents
    if (hitPath === '/agents' || (Array.isArray(data.agents) && data.agents[0]?.name)) return 'eliza';
    // Swarm: /health returns { status, agents (number), gateways, connections }
    if (typeof data.agents === 'number' && data.gateways !== undefined) return 'swarm';
    // OpenClaw: /api/status returns { agent, status, version } or { agent_id, ... }
    if (data.agent || data.agent_id) return 'openclaw';
    // Agent Zero: /health returns { status: "ok" } — minimal
    if (data.status === 'ok' && Object.keys(data).length <= 3) return 'agentzero';
    // PicoClaw: /health or /ready
    if (hitPath === '/ready' || hitPath === '/healthz') return 'picoclaw';
    // Generic: has a status field
    if (data.status) return 'generic';
    return 'unknown';
  }

  // Normalize any framework's status into our standard shape
  function normalizeStatus(data, framework) {
    if (!data) data = {};
    const norm = {
      agent_id: data.agent_id || data.agent || data.agentId || data.name || data.id || null,
      ens_name: data.ens_name || data.ens || null,
      status: data.status || 'online',
      network: data.network || data.chain || null,
      version: data.version || null,
      framework: framework,
      allowed_tools: data.allowed_tools || data.skills || data.tools || data.capabilities || [],
      max_value_autonomous_wei: data.max_value_autonomous_wei || 0,
      endpoint_allowlist: data.endpoint_allowlist || [],
      stats: {
        total_actions: data.stats?.total_actions || data.stats?.actions || data.actions || 0,
        proofs_generated: data.stats?.proofs_generated || data.stats?.proofs || data.proofs || 0,
      },
      uptime_secs: data.uptime_secs || data.uptime || 0,
    };
    // ElizaOS: first agent in array
    if (framework === 'eliza' && Array.isArray(data.agents) && data.agents[0]) {
      const a = data.agents[0];
      norm.agent_id = a.id || a.name || norm.agent_id;
      norm.status = 'online';
      norm._elizaAgentId = a.id; // needed for ElizaOS chat routing
    }
    // Swarm: use hub info
    if (framework === 'swarm') {
      norm.agent_id = norm.agent_id || 'swarm-hub';
      norm.stats.total_actions = data.connections || 0;
    }
    // Fallback ID
    if (!norm.agent_id) norm.agent_id = framework + '-agent';
    if (!norm.network) norm.network = 'unknown';
    return norm;
  }

  // ── API calls (framework-aware) ──
  async function fetchStatus(baseUrl) {
    const result = await probeEndpoints(baseUrl, FRAMEWORK_PROBES.status, 'GET', null, 5000);
    if (!result.ok) throw new Error('No status endpoint found');
    const fw = detectFramework(result.data, result.path);
    return normalizeStatus(result.data, fw);
  }

  async function fetchActivity(baseUrl) {
    const result = await probeEndpoints(baseUrl, FRAMEWORK_PROBES.activity);
    if (!result.ok) return null;
    return result.data;
  }
  async function fetchProofs(baseUrl) {
    const result = await probeEndpoints(baseUrl, FRAMEWORK_PROBES.proofs);
    if (!result.ok) return null;
    return result.data;
  }
  async function fetchMessages(baseUrl) {
    const result = await probeEndpoints(baseUrl, FRAMEWORK_PROBES.messages);
    if (!result.ok) return null;
    return result.data;
  }

  async function sendMessage(baseUrl, to, content) {
    const conn = getConnection();
    const fw = conn?.framework || 'unknown';

    // Framework-specific chat endpoints (try specific first, then probe all)
    const fwPaths = {
      openclaw:  ['/v1/chat', '/api/messages/send', '/api/chat'],
      swarm:     ['/api/v1/send', '/api/webhooks/reply', '/api/messages/send'],
      agentzero: ['/api/chat', '/v1/chat'],
      picoclaw:  ['/chat/completions', '/api/chat'],
      eliza:     [conn?._elizaAgentId ? `/${conn._elizaAgentId}/message` : '/message', '/api/chat'],
    };
    const paths = fwPaths[fw] || FRAMEWORK_PROBES.chat;

    // Build body variants per framework
    const bodies = {
      openclaw:  { message: content, session_id: to || 'default' },
      swarm:     { to, content, type: 'text' },
      agentzero: { message: content, session_id: to || 'default' },
      picoclaw:  { model: 'default', messages: [{ role: 'user', content }] },
      eliza:     { text: content, userId: to || 'user', roomId: to || 'default' },
    };
    const defaultBody = { to, content, message: content, session_id: to || 'default' };
    const body = bodies[fw] || defaultBody;

    for (const path of paths) {
      try {
        const r = await fetch(`${baseUrl}${path}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });
        if (r.ok) return r.json();
      } catch {}
    }
    throw new Error('No chat endpoint responded');
  }

  async function healthCheck(baseUrl) {
    const result = await probeEndpoints(baseUrl, FRAMEWORK_PROBES.health, 'GET', null, 3000);
    return result.ok;
  }

  // ── Spec validation (framework-agnostic) ──
  async function validateSpec(baseUrl) {
    const results = {};

    // Probe health (any of the known paths)
    results.health = await probeEndpoints(baseUrl, FRAMEWORK_PROBES.health, 'GET', null, 5000);
    // Probe status (may be same as health for some frameworks)
    results.status = await probeEndpoints(baseUrl, FRAMEWORK_PROBES.status, 'GET', null, 5000);
    // Optional endpoints
    results.activity = await probeEndpoints(baseUrl, FRAMEWORK_PROBES.activity);
    results.proofs = await probeEndpoints(baseUrl, FRAMEWORK_PROBES.proofs);
    results.messages = await probeEndpoints(baseUrl, FRAMEWORK_PROBES.messages);

    // Valid if we got any response from health or status
    results.valid = results.health.ok || results.status.ok;

    // Detect framework and normalize
    const statusData = results.status.ok ? results.status : results.health;
    const fw = detectFramework(statusData.data, statusData.path);
    results.framework = fw;

    if (statusData.ok && statusData.data) {
      results.agentPreview = normalizeStatus(statusData.data, fw);
    } else {
      results.agentPreview = null;
    }

    // Surface which paths actually worked
    results.detectedPaths = {
      health: results.health.ok ? results.health.path : null,
      status: results.status.ok ? results.status.path : null,
      activity: results.activity.ok ? results.activity.path : null,
      proofs: results.proofs.ok ? results.proofs.path : null,
      messages: results.messages.ok ? results.messages.path : null,
    };

    return results;
  }

  // ── Connect flow ──
  async function connect(url, origin) {
    // Normalize URL
    let baseUrl = url.replace(/\/+$/, '');
    if (!baseUrl.startsWith('http')) baseUrl = 'https://' + baseUrl;

    // Health check (probes all known paths)
    const ok = await healthCheck(baseUrl);
    if (!ok) throw new Error('Agent not reachable — no health or status endpoint found');

    // Fetch & normalize status
    const status = await fetchStatus(baseUrl);

    // Save connection with detected framework
    const conn = {
      url: baseUrl,
      agentId: status.agent_id,
      ens: status.ens_name,
      status: status.status,
      network: status.network,
      framework: status.framework,
      _elizaAgentId: status._elizaAgentId || null,
      connectedAt: new Date().toISOString()
    };
    setConnection(conn);

    // Sync agent into poc_agents list
    syncLiveAgent(status, origin || 'connected');

    return conn;
  }

  function disconnect() {
    const conn = getConnection();
    if (conn) {
      // Mark agent as disconnected in local list
      let agents = getAgents();
      const idx = agents.findIndex(a => a.id === conn.agentId);
      if (idx >= 0) {
        agents[idx].live = false;
        agents[idx].status = 'offline';
        localStorage.setItem('poc_agents', JSON.stringify(agents));
        if (typeof PocPersist !== 'undefined') PocPersist.savePref('poc_agents', agents);
      }
    }
    clearConnection();
  }

  // ── Sync live agent data into localStorage agents ──
  function syncLiveAgent(status, origin) {
    let agents = getAgents();
    const idx = agents.findIndex(a => a.id === status.agent_id);
    const fw = status.framework || 'unknown';
    const fwLabels = {
      openclaw: 'OpenClaw Agent', swarm: 'Swarm Agent', agentzero: 'Agent Zero',
      picoclaw: 'PicoClaw Agent', eliza: 'ElizaOS Agent', generic: 'Agent', unknown: 'Agent'
    };
    const agentObj = {
      id: status.agent_id,
      name: status.agent_id,
      ens: status.ens_name,
      type: fw + '-agent',
      framework: fw,
      network: status.network,
      skills: status.allowed_tools || [],
      allowedTools: status.allowed_tools || [],
      valueLimit: Math.floor((status.max_value_autonomous_wei || 0) / 1e18 * 100),
      endpoints: (status.endpoint_allowlist || []).join(', '),
      status: 'online',
      live: true,
      origin: origin || 'connected',
      deployedAt: new Date().toISOString(),
      description: fwLabels[fw] + ' connected via API',
      stats: {
        actions: status.stats?.total_actions || 0,
        proofs: status.stats?.proofs_generated || 0,
        uptime: formatUptime(status.uptime_secs || 0)
      }
    };
    if (idx >= 0) {
      agents[idx] = { ...agents[idx], ...agentObj };
    } else {
      agents.unshift(agentObj);
    }
    localStorage.setItem('poc_agents', JSON.stringify(agents));
    if (typeof PocPersist !== 'undefined') PocPersist.savePref('poc_agents', agents);
  }

  function getAgents() {
    try { return JSON.parse(localStorage.getItem('poc_agents')) || []; } catch { return []; }
  }

  function formatUptime(secs) {
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    return `${h}h ${m}m`;
  }

  // ── HTML escaping (XSS prevention) ──
  function escHtml(str) {
    if (str == null) return '';
    return String(str).replace(/[&<>"']/g, c =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  }

  // ── Connection status indicator (injects into sidebar) ──
  function renderConnectionBadge(container) {
    if (!container) return;
    const conn = getConnection();
    container.innerHTML = conn
      ? `<div class="conn-badge connected" role="status" aria-label="Connected to ${escHtml(conn.agentId)}" onclick="PocAPI.showDisconnectPrompt()">
           <span class="conn-dot" aria-hidden="true"></span>
           <span class="conn-text">${escHtml(conn.agentId)}</span>
           <span class="conn-label">LIVE</span>
         </div>`
      : `<button class="conn-badge disconnected" aria-label="Connect agent" onclick="PocAPI.showConnectModal()">
           <span class="conn-dot" aria-hidden="true"></span>
           <span class="conn-text">Connect Agent</span>
         </button>`;
  }

  // ── Modal UI (injected into page) ──
  function injectModal() {
    if (document.getElementById('poc-connect-modal')) return;
    const modal = document.createElement('div');
    modal.id = 'poc-connect-modal';
    modal.className = 'poc-modal-overlay';
    modal.innerHTML = `
      <div class="poc-modal" role="dialog" aria-modal="true" aria-labelledby="poc-modal-title">
        <div class="poc-modal-header">
          <h2 id="poc-modal-title">Connect Agent</h2>
          <button class="poc-modal-close" onclick="PocAPI.hideConnectModal()" aria-label="Close">&times;</button>
        </div>
        <div class="poc-modal-body">
          <p class="poc-modal-desc">Connect any agent framework — OpenClaw, Swarm, Agent Zero, PicoClaw, ElizaOS, or any HTTP agent.</p>
          <div class="poc-form-group">
            <label for="poc-connect-url">Agent API URL</label>
            <input type="text" id="poc-connect-url" placeholder="https://xxx.trycloudflare.com" value="" autocomplete="url">
            <div class="poc-form-hint">Paste your tunnel URL or local address (e.g. http://localhost:8082)</div>
          </div>
          <div id="poc-connect-error" class="poc-error" style="display:none;"></div>
          <div id="poc-connect-success" class="poc-success" style="display:none;"></div>
          <div class="poc-modal-actions">
            <button class="poc-btn-connect" id="poc-btn-connect" onclick="PocAPI.doConnect()">Connect</button>
            <button class="poc-btn-cancel" onclick="PocAPI.hideConnectModal()">Cancel</button>
          </div>
        </div>
        <div class="poc-modal-footer">
          <div class="poc-help-text">
            <strong>How to connect:</strong><br>
            1. Start your agent locally (any framework)<br>
            2. Expose via tunnel: <code>cloudflared tunnel --url http://localhost:PORT</code><br>
            3. Paste the URL above — we auto-detect your framework<br>
            <span style="opacity:0.6;font-size:11px;">Supports /health, /api/status, /agents, /ready, and more.</span>
          </div>
        </div>
      </div>`;
    document.body.appendChild(modal);
  }

  function showConnectModal() {
    injectModal();
    const modal = document.getElementById('poc-connect-modal');
    modal.classList.add('active');
    document.getElementById('poc-connect-error').style.display = 'none';
    document.getElementById('poc-connect-success').style.display = 'none';
    document.getElementById('poc-btn-connect').disabled = false;
    document.getElementById('poc-btn-connect').textContent = 'Connect';

    // Auto-fill URL when running on localhost; otherwise leave empty so user must provide it
    const urlInput = document.getElementById('poc-connect-url');
    if (!urlInput.value) {
      const host = window.location.hostname;
      if (host === 'localhost' || host === '127.0.0.1' || host === '::1') {
        urlInput.value = 'http://localhost:8082';
      }
    }

    // Focus trap for accessibility
    if (typeof trapFocus === 'function') trapFocus(modal.querySelector('.poc-modal'));
    urlInput.focus();
  }
  function hideConnectModal() {
    const m = document.getElementById('poc-connect-modal');
    if (m) m.classList.remove('active');
  }

  async function doConnect() {
    const url = document.getElementById('poc-connect-url').value.trim();
    const errEl = document.getElementById('poc-connect-error');
    const succEl = document.getElementById('poc-connect-success');
    const btn = document.getElementById('poc-btn-connect');

    errEl.style.display = 'none';
    succEl.style.display = 'none';

    if (!url) {
      errEl.textContent = 'Please enter your agent API URL.';
      errEl.style.display = 'block';
      return;
    }

    btn.disabled = true;
    btn.textContent = 'Connecting...';

    try {
      const conn = await connect(url);
      succEl.textContent = `Connected to ${conn.agentId || 'agent'} (${conn.ens || 'unknown'})`;
      succEl.style.display = 'block';
      btn.textContent = 'Connected!';

      // Refresh page after short delay to show live data
      setTimeout(() => {
        hideConnectModal();
        window.location.reload();
      }, 1200);
    } catch (e) {
      errEl.textContent = `Connection failed: ${e.message}. Make sure your agent is running.`;
      errEl.style.display = 'block';
      btn.disabled = false;
      btn.textContent = 'Retry';
    }
  }

  function showDisconnectPrompt() {
    if (confirm('Disconnect from live agent?')) {
      disconnect();
      window.location.reload();
    }
  }

  // ── Auto-init: inject styles + connection badge ──
  function init() {
    injectStyles();
    injectModal();
    const container = document.getElementById('poc-connection-slot');
    if (container) renderConnectionBadge(container);
  }

  function injectStyles() {
    if (document.getElementById('poc-api-styles')) return;
    const style = document.createElement('style');
    style.id = 'poc-api-styles';
    style.textContent = `
      /* Connection badge */
      .conn-badge {
        display: flex; align-items: center; gap: 8px;
        padding: 8px 12px; border-radius: 8px;
        font-family: 'JetBrains Mono', monospace; font-size: 11px;
        cursor: pointer; transition: all 0.2s; width: 100%;
        border: 1px solid rgba(255,255,255,0.06); background: #0c1018;
        color: #8892a4; text-align: left;
      }
      .conn-badge:hover { border-color: rgba(0,229,255,0.3); }
      .conn-badge.connected {
        background: rgba(0,230,118,0.08); border-color: rgba(0,230,118,0.3);
        color: #00e676;
      }
      .conn-dot {
        width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0;
        background: #4a5568;
      }
      .conn-badge.connected .conn-dot {
        background: #00e676; box-shadow: 0 0 8px rgba(0,230,118,0.6);
        animation: pulse-dot 2s ease-in-out infinite;
      }
      .conn-text { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
      .conn-label {
        font-size: 9px; font-weight: 700; letter-spacing: 0.1em;
        padding: 2px 6px; border-radius: 3px;
        background: rgba(0,230,118,0.15); color: #00e676;
      }
      @keyframes pulse-dot {
        0%, 100% { opacity: 1; } 50% { opacity: 0.4; }
      }

      /* Modal */
      .poc-modal-overlay {
        display: none; position: fixed; inset: 0; z-index: 10000;
        background: rgba(6,8,13,0.9); backdrop-filter: blur(8px);
        align-items: center; justify-content: center;
      }
      .poc-modal-overlay.active { display: flex; }
      .poc-modal {
        background: #0f1520; border: 1px solid rgba(255,255,255,0.06);
        border-radius: 12px; width: 90%; max-width: 520px;
        box-shadow: 0 0 40px rgba(0,229,255,0.1);
      }
      .poc-modal-header {
        display: flex; justify-content: space-between; align-items: center;
        padding: 20px 24px; border-bottom: 1px solid rgba(255,255,255,0.06);
      }
      .poc-modal-header h2 {
        font-family: 'Syne', sans-serif; font-weight: 700; font-size: 1.2rem;
        color: #e8ecf4;
      }
      .poc-modal-close {
        background: none; border: none; color: #4a5568; font-size: 24px;
        cursor: pointer; transition: color 0.2s;
      }
      .poc-modal-close:hover { color: #e8ecf4; }
      .poc-modal-body { padding: 24px; }
      .poc-modal-desc { color: #8892a4; font-size: 13px; margin-bottom: 20px; line-height: 1.6; }
      .poc-form-group { margin-bottom: 16px; }
      .poc-form-group label {
        display: block; margin-bottom: 6px; font-weight: 600;
        color: #e8ecf4; font-size: 13px;
      }
      .poc-form-group input {
        width: 100%; padding: 10px 14px; background: #0c1018;
        border: 1px solid rgba(255,255,255,0.06); border-radius: 6px;
        color: #e8ecf4; font-family: 'JetBrains Mono', monospace; font-size: 13px;
        transition: all 0.2s;
      }
      .poc-form-group input:focus {
        outline: none; border-color: #00e5ff;
        box-shadow: 0 0 0 3px rgba(0,229,255,0.15);
      }
      .poc-form-hint { font-size: 11px; color: #4a5568; margin-top: 4px; }
      .poc-error {
        padding: 10px 14px; background: rgba(255,61,90,0.08);
        border: 1px solid rgba(255,61,90,0.3); border-radius: 6px;
        color: #ff3d5a; font-size: 12px; margin-bottom: 16px;
      }
      .poc-success {
        padding: 10px 14px; background: rgba(0,230,118,0.08);
        border: 1px solid rgba(0,230,118,0.3); border-radius: 6px;
        color: #00e676; font-size: 12px; margin-bottom: 16px;
      }
      .poc-modal-actions { display: flex; gap: 8px; }
      .poc-btn-connect {
        flex: 1; padding: 10px; background: #00e5ff; color: #06080d;
        border: none; border-radius: 6px; font-family: 'JetBrains Mono', monospace;
        font-weight: 700; font-size: 13px; cursor: pointer; transition: all 0.2s;
        text-transform: uppercase; letter-spacing: 0.05em;
      }
      .poc-btn-connect:hover:not(:disabled) {
        background: #00a3b5; box-shadow: 0 0 20px rgba(0,229,255,0.3);
      }
      .poc-btn-connect:disabled { opacity: 0.6; cursor: not-allowed; }
      .poc-btn-cancel {
        padding: 10px 20px; background: #0c1018; color: #8892a4;
        border: 1px solid rgba(255,255,255,0.06); border-radius: 6px;
        font-family: 'JetBrains Mono', monospace; font-size: 13px;
        cursor: pointer; transition: all 0.2s;
      }
      .poc-btn-cancel:hover { border-color: rgba(255,255,255,0.15); color: #e8ecf4; }
      .poc-modal-footer {
        padding: 16px 24px; border-top: 1px solid rgba(255,255,255,0.06);
      }
      .poc-help-text {
        font-size: 11px; color: #4a5568; line-height: 1.8;
      }
      .poc-help-text code {
        display: block; margin-top: 6px; padding: 8px 12px;
        background: #06080d; border-radius: 4px; color: #00e5ff;
        font-size: 11px; word-break: break-all;
      }
    `;
    document.head.appendChild(style);
  }

  // ── WebSocket real-time connection ──
  let _ws = null;
  let _wsReconnectTimer = null;
  let _wsListeners = []; // array of { type, fn }

  /**
   * Open a WebSocket to the connected agent runtime.
   * Falls back to polling if WebSocket fails after 2 attempts.
   */
  function openWebSocket() {
    const conn = getConnection();
    if (!conn) return;

    // Derive ws:// URL from http:// URL
    const wsUrl = conn.url.replace(/^http/, 'ws') + '/ws';

    if (_ws && (_ws.readyState === WebSocket.OPEN || _ws.readyState === WebSocket.CONNECTING)) {
      return; // already connected
    }

    try {
      _ws = new WebSocket(wsUrl);
    } catch (e) {
      return; // WebSocket not supported or bad URL
    }

    _ws.onopen = function() {
      if (_wsReconnectTimer) { clearTimeout(_wsReconnectTimer); _wsReconnectTimer = null; }
      _dispatchWsEvent('ws_open', {});
    };

    _ws.onmessage = function(evt) {
      try {
        var msg = JSON.parse(evt.data);
        _dispatchWsEvent(msg.type, msg.data, msg.ts);
      } catch (e) { /* ignore malformed */ }
    };

    _ws.onclose = function() {
      _dispatchWsEvent('ws_close', {});
      // Auto-reconnect after 3s
      if (!_wsReconnectTimer && isConnected()) {
        _wsReconnectTimer = setTimeout(function() {
          _wsReconnectTimer = null;
          openWebSocket();
        }, 3000);
      }
    };

    _ws.onerror = function() {
      // onclose will fire after onerror
    };
  }

  function closeWebSocket() {
    if (_wsReconnectTimer) { clearTimeout(_wsReconnectTimer); _wsReconnectTimer = null; }
    if (_ws) { _ws.close(); _ws = null; }
  }

  /**
   * Subscribe to WebSocket events.
   * @param {string} type - Event type: snapshot, status, activity, proofs, message, ws_open, ws_close
   * @param {function} fn - Callback receiving (data, ts)
   * @returns {function} Unsubscribe function
   */
  function onWsEvent(type, fn) {
    var entry = { type: type, fn: fn };
    _wsListeners.push(entry);
    return function() {
      _wsListeners = _wsListeners.filter(function(e) { return e !== entry; });
    };
  }

  function _dispatchWsEvent(type, data, ts) {
    for (var i = 0; i < _wsListeners.length; i++) {
      if (_wsListeners[i].type === type || _wsListeners[i].type === '*') {
        try { _wsListeners[i].fn(data, ts); } catch (e) { /* ignore listener errors */ }
      }
    }
  }

  function isWebSocketOpen() {
    return _ws && _ws.readyState === WebSocket.OPEN;
  }

  // Public API
  return {
    init,
    isConnected,
    getConnection,
    connect,
    disconnect,
    fetchStatus,
    fetchActivity,
    fetchProofs,
    fetchMessages,
    sendMessage,
    healthCheck,
    validateSpec,
    showConnectModal,
    hideConnectModal,
    doConnect,
    showDisconnectPrompt,
    renderConnectionBadge,
    openWebSocket,
    closeWebSocket,
    onWsEvent,
    isWebSocketOpen,
  };
})();

// Auto-init on DOM ready
document.addEventListener('DOMContentLoaded', PocAPI.init);
