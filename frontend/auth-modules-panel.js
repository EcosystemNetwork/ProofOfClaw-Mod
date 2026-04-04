/**
 * Proof of Claw — Auth Modules Panel with 1clawAI Monetization
 * Google Calendar integration with packaging and agent prioritization
 */

'use strict';

const PocAuthModules = (function() {
  let rootEl = null;
  let config = {
    onConnect: null,
    onDisconnect: null,
    compact: false,
    googleClientId: null,
    userAuthKey: null,
    operatorAuthKey: null,
    apiEndpoint: null,
    // 1clawAI Configuration
    oneclawApiKey: null,
    oneclawEndpoint: 'https://api.1claw.ai/v1',
    pricingTier: 'free',
    agentId: null
  };

  const PRICING_TIERS = {
    free: { name: 'Free', price: 0, maxEvents: 10, agentPrioritization: false },
    basic: { name: 'Basic', price: 9.99, maxEvents: 50, agentPrioritization: true },
    pro: { name: 'Pro', price: 29.99, maxEvents: 200, agentPrioritization: true },
    enterprise: { name: 'Enterprise', price: 'Custom', maxEvents: -1, agentPrioritization: true }
  };

  let googleClient = null;

  async function verifyLicenseWithOneClaw() {
    if (!config.oneclawApiKey) return { valid: true, tier: config.pricingTier };
    try {
      const response = await fetch(`${config.oneclawEndpoint}/license/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': config.oneclawApiKey },
        body: JSON.stringify({ agentId: config.agentId, feature: 'google-calendar' })
      });
      const data = await response.json();
      config.pricingTier = data.tier || 'free';
      return data;
    } catch (error) {
      return { valid: false, tier: 'free' };
    }
  }

  function exportCredentialPackage() {
    const connections = getStoredConnections();
    if (!connections.google?.connected) return null;
    return {
      version: '1.0',
      agentId: config.agentId,
      tier: config.pricingTier,
      credentials: { type: 'google-calendar-oauth', accessToken: connections.google.accessToken },
      monetization: { platform: '1clawAI', licenseKey: generateLicenseKey() }
    };
  }

  function generateLicenseKey() {
    return `POC-GCAL-${config.pricingTier}-${Date.now().toString(36)}-${Math.random().toString(36).substr(2, 9)}`;
  }

  function downloadCredentialPackage() {
    const pkg = exportCredentialPackage();
    if (!pkg) { showToast('No credentials to export', 'error'); return; }
    const blob = new Blob([JSON.stringify(pkg, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `poc-calendar-${config.pricingTier}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Package exported!', 'success');
  }

  async function importCredentialPackage(pkg) {
    if (typeof pkg === 'string') pkg = JSON.parse(pkg);
    const connections = getStoredConnections();
    connections.google = { connected: true, accessToken: pkg.credentials.accessToken };
    setStoredConnections(connections);
    config.pricingTier = pkg.tier || 'free';
    render();
    showToast('Package imported!', 'success');
  }

  function calculateTaskPriority(event) {
    const tier = PRICING_TIERS[config.pricingTier];
    if (!tier.agentPrioritization) return { priority: 'normal', score: 0 };
    const hoursUntil = (new Date(event.start?.dateTime) - Date.now()) / (1000 * 60 * 60);
    let priority = 'normal', score = 0;
    if (hoursUntil < 1) { priority = 'critical'; score = 100; }
    else if (hoursUntil < 4) { priority = 'high'; score = 75; }
    else if (hoursUntil < 24) { priority = 'medium'; score = 50; }
    else { priority = 'low'; score = 25; }
    return { priority, score };
  }

  function syncTasksToAgent() {
    const connections = getStoredConnections();
    if (!connections.google?.events) { showToast('No events to sync', 'error'); return; }
    const tasks = connections.google.events.slice(0, PRICING_TIERS[config.pricingTier].maxEvents).map(e => ({
      ...calculateTaskPriority(e),
      title: e.summary,
      start: e.start?.dateTime
    }));
    localStorage.setItem('poc_agent_tasks', JSON.stringify({ synced: Date.now(), tasks }));
    showToast(`Synced ${tasks.length} tasks`, 'success');
  }

  function loadGoogleGIS() {
    return new Promise((resolve, reject) => {
      if (window.google?.accounts?.oauth2) { resolve(window.google.accounts.oauth2); return; }
      const script = document.createElement('script');
      script.src = 'https://accounts.google.com/gsi/client';
      script.onload = () => resolve(window.google.accounts.oauth2);
      script.onerror = () => reject(new Error('Failed to load Google GIS'));
      document.head.appendChild(script);
    });
  }

  async function initGoogleAuth() {
    const oauth2 = await loadGoogleGIS();
    googleClient = oauth2.initTokenClient({
      client_id: config.googleClientId,
      scope: 'https://www.googleapis.com/auth/calendar.readonly',
      callback: handleGoogleTokenResponse
    });
    return googleClient;
  }

  async function handleGoogleTokenResponse(tokenResponse) {
    if (tokenResponse.error) { showToast('Auth failed', 'error'); return; }
    const connections = getStoredConnections();
    connections.google = { connected: true, accessToken: tokenResponse.access_token };
    setStoredConnections(connections);
    showToast('Connected!', 'success');
    render();
  }

  function getStoredConnections() {
    try { return JSON.parse(localStorage.getItem('poc_auth_connections')) || {}; } catch { return {}; }
  }

  function setStoredConnections(connections) {
    localStorage.setItem('poc_auth_connections', JSON.stringify(connections));
  }

  function toggleConnection(id) {
    const connections = getStoredConnections();
    if (connections.google?.connected) {
      connections.google = { connected: false };
      setStoredConnections(connections);
      render();
    } else {
      initGoogleAuth().then(c => c.requestAccessToken({ prompt: 'consent' }));
    }
  }

  function render() {
    if (!rootEl) return;
    const connections = getStoredConnections();
    const isConnected = connections.google?.connected;
    const tier = PRICING_TIERS[config.pricingTier];
    rootEl.innerHTML = `
      <div class="poc-auth">
        <h2>🔐 Auth & Monetization</h2>
        <div class="tier-banner">${tier.name} Plan - $${tier.price}/mo</div>
        <div class="actions">
          <button onclick="PocAuthModules.toggleConnection()">${isConnected ? 'Disconnect' : 'Connect Google'}</button>
          ${isConnected ? `<button onclick="PocAuthModules.downloadCredentialPackage()">Export Package</button>` : ''}
          ${tier.agentPrioritization && isConnected ? `<button onclick="PocAuthModules.syncTasksToAgent()">Sync to Agent</button>` : ''}
        </div>
      </div>`;
  }

  function showToast(msg, type) {
    const t = document.createElement('div');
    t.textContent = msg;
    t.style.cssText = `position:fixed;bottom:20px;right:20px;padding:12px 20px;background:${type === 'success' ? '#0e6' : '#f36'};color:#000;border-radius:8px;z-index:10000;`;
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 3000);
  }

  return {
    mount: (el, opts = {}) => { rootEl = typeof el === 'string' ? document.getElementById(el) : el; config = { ...config, ...opts }; verifyLicenseWithOneClaw().then(() => render()); },
    toggleConnection,
    downloadCredentialPackage,
    importCredentialPackage,
    syncTasksToAgent,
    getConnections: getStoredConnections
  };
})();

window.PocAuthModules = PocAuthModules;
