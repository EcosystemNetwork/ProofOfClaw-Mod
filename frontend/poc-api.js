/**
 * Proof of Claw — API Connection Layer
 * Shared across all app pages. Manages connection to a live OpenClaw agent runtime.
 *
 * localStorage keys:
 *   poc_agents       — array of agent objects (mock or synced)
 *   poc_connection    — { url, agentId, ens, connectedAt } when connected to live agent
 */

const PocAPI = (() => {
  // ── connection state ──
  function getConnection() {
    try { return JSON.parse(localStorage.getItem('poc_connection')); } catch { return null; }
  }
  function setConnection(conn) {
    localStorage.setItem('poc_connection', JSON.stringify(conn));
  }
  function clearConnection() {
    localStorage.removeItem('poc_connection');
  }
  function isConnected() {
    return !!getConnection();
  }

  // ── API calls ──
  async function fetchStatus(baseUrl) {
    const r = await fetch(`${baseUrl}/api/status`);
    if (!r.ok) throw new Error(`Status ${r.status}`);
    return r.json();
  }
  async function fetchActivity(baseUrl) {
    const r = await fetch(`${baseUrl}/api/activity`);
    if (!r.ok) throw new Error(`Status ${r.status}`);
    return r.json();
  }
  async function fetchProofs(baseUrl) {
    const r = await fetch(`${baseUrl}/api/proofs`);
    if (!r.ok) throw new Error(`Status ${r.status}`);
    return r.json();
  }
  async function fetchMessages(baseUrl) {
    const r = await fetch(`${baseUrl}/api/messages`);
    if (!r.ok) throw new Error(`Status ${r.status}`);
    return r.json();
  }
  async function sendMessage(baseUrl, to, content) {
    const r = await fetch(`${baseUrl}/api/messages/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ to, content })
    });
    if (!r.ok) throw new Error(`Status ${r.status}`);
    return r.json();
  }
  async function healthCheck(baseUrl) {
    const r = await fetch(`${baseUrl}/health`, { signal: AbortSignal.timeout(3000) });
    return r.ok;
  }

  // ── Spec validation ──
  async function validateSpec(baseUrl) {
    const results = {};
    const check = async (name, method, path, body) => {
      try {
        const opts = { method, signal: AbortSignal.timeout(5000) };
        if (body) {
          opts.headers = { 'Content-Type': 'application/json' };
          opts.body = JSON.stringify(body);
        }
        const r = await fetch(`${baseUrl}${path}`, opts);
        if (!r.ok) return { ok: false, error: `HTTP ${r.status}` };
        const contentType = r.headers.get('content-type') || '';
        const data = contentType.includes('json') ? await r.json() : null;
        return { ok: true, data };
      } catch (e) {
        return { ok: false, error: e.message };
      }
    };

    results.health = await check('health', 'GET', '/health');
    results.status = await check('status', 'GET', '/api/status');
    results.activity = await check('activity', 'GET', '/api/activity');
    results.proofs = await check('proofs', 'GET', '/api/proofs');
    results.messages = await check('messages', 'GET', '/api/messages');
    // Skip /api/chat — don't auto-send a message during validation

    results.valid = results.health.ok && results.status.ok;
    results.agentPreview = results.status.ok ? results.status.data : null;
    return results;
  }

  // ── Connect flow ──
  async function connect(url, origin) {
    // Normalize URL
    let baseUrl = url.replace(/\/+$/, '');
    if (!baseUrl.startsWith('http')) baseUrl = 'http://' + baseUrl;

    // Health check
    const ok = await healthCheck(baseUrl);
    if (!ok) throw new Error('Agent not reachable');

    // Fetch status
    const status = await fetchStatus(baseUrl);

    // Save connection
    const conn = {
      url: baseUrl,
      agentId: status.agent_id,
      ens: status.ens_name,
      status: status.status,
      network: status.network,
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
      }
    }
    clearConnection();
  }

  // ── Sync live agent data into localStorage agents ──
  function syncLiveAgent(status, origin) {
    let agents = getAgents();
    const idx = agents.findIndex(a => a.id === status.agent_id);
    const agentObj = {
      id: status.agent_id,
      name: status.agent_id,
      ens: status.ens_name,
      type: 'openclaw-agent',
      network: status.network,
      skills: status.allowed_tools || [],
      allowedTools: status.allowed_tools || [],
      valueLimit: Math.floor((status.max_value_autonomous_wei || 0) / 1e18 * 100), // rough USD
      endpoints: (status.endpoint_allowlist || []).join(', '),
      status: 'online',
      live: true,
      origin: origin || 'connected',
      deployedAt: new Date().toISOString(),
      description: 'Live agent connected via API',
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
      : `<button class="conn-badge disconnected" aria-label="Connect to OpenClaw agent" onclick="PocAPI.showConnectModal()">
           <span class="conn-dot" aria-hidden="true"></span>
           <span class="conn-text">Connect OpenClaw</span>
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
          <h2 id="poc-modal-title">Connect OpenClaw Agent</h2>
          <button class="poc-modal-close" onclick="PocAPI.hideConnectModal()" aria-label="Close">&times;</button>
        </div>
        <div class="poc-modal-body">
          <p class="poc-modal-desc">Enter the API endpoint of your running Proof of Claw agent runtime.</p>
          <div class="poc-form-group">
            <label for="poc-connect-url">Agent API URL</label>
            <input type="text" id="poc-connect-url" placeholder="http://localhost:8420" value="" autocomplete="url">
            <div class="poc-form-hint">Default port is 8420. Set API_PORT env var to change.</div>
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
            <strong>How to start your agent:</strong><br>
            <code>cd agent && AGENT_ID=my-agent ENS_NAME=my.proofofclaw.eth PRIVATE_KEY=0x... cargo run</code>
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
        urlInput.value = 'http://localhost:8420';
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
  };
})();

// Auto-init on DOM ready
document.addEventListener('DOMContentLoaded', PocAPI.init);
