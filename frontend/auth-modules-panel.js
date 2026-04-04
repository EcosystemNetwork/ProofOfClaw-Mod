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
    oneclawEndpoint: 'http://localhost:3456/v1', // Local 1claw server
    pricingTier: 'free',
    agentId: null,
    storageEnabled: false
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

  async function testOneClawConnection() {
    try {
      const response = await fetch(`${config.oneclawEndpoint.replace('/v1', '')}/health`, {
        method: 'GET',
        headers: { 'X-API-Key': config.oneclawApiKey || 'test-key' }
      });
      if (response.ok) {
        config.storageEnabled = true;
        console.log('✅ 1claw API connected');
        return true;
      }
    } catch (e) {
      console.log('❌ 1claw API not available, using localStorage fallback');
    }
    return false;
  }

  async function storeOnOneClaw(key, data, metadata = {}) {
    if (!config.storageEnabled) {
      // Fallback to localStorage
      localStorage.setItem(`1claw_${key}`, JSON.stringify({ data, metadata, storedAt: Date.now() }));
      return { success: true, storageKey: key, local: true };
    }

    try {
      const response = await fetch(`${config.oneclawEndpoint}/store`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': config.oneclawApiKey || 'test-key',
          'X-User-Auth': config.userAuthKey || '',
          'X-Operator-Auth': config.operatorAuthKey || ''
        },
        body: JSON.stringify({
          key,
          data,
          metadata: {
            ...metadata,
            agentId: config.agentId,
            tier: config.pricingTier
          },
          agentId: config.agentId
        })
      });

      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return await response.json();
    } catch (error) {
      console.error('1claw store failed:', error);
      // Fallback to localStorage
      localStorage.setItem(`1claw_${key}`, JSON.stringify({ data, metadata, storedAt: Date.now() }));
      return { success: true, storageKey: key, local: true, error: error.message };
    }
  }

  async function retrieveFromOneClaw(key) {
    if (!config.storageEnabled) {
      // Fallback to localStorage
      const stored = localStorage.getItem(`1claw_${key}`);
      if (!stored) return { success: false, error: 'Key not found' };
      const parsed = JSON.parse(stored);
      return { success: true, data: parsed.data, metadata: parsed.metadata, local: true };
    }

    try {
      const response = await fetch(`${config.oneclawEndpoint}/retrieve`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': config.oneclawApiKey || 'test-key'
        },
        body: JSON.stringify({ key, agentId: config.agentId })
      });

      if (!response.ok) {
        if (response.status === 404) return { success: false, error: 'Key not found' };
        throw new Error(`HTTP ${response.status}`);
      }
      return await response.json();
    } catch (error) {
      console.error('1claw retrieve failed:', error);
      // Fallback to localStorage
      const stored = localStorage.getItem(`1claw_${key}`);
      if (!stored) return { success: false, error: error.message };
      const parsed = JSON.parse(stored);
      return { success: true, data: parsed.data, metadata: parsed.metadata, local: true, error: error.message };
    }
  }

  async function storeCredentialPackageOnOneClaw() {
    const pkg = exportCredentialPackage();
    if (!pkg) {
      showToast('No credentials to store', 'error');
      return;
    }

    const key = `gcal-package-${config.agentId}-${Date.now()}`;
    const result = await storeOnOneClaw(key, pkg, {
      type: 'credential-package',
      tier: config.pricingTier,
      licenseKey: pkg.monetization.licenseKey
    });

    if (result.success) {
      showToast(result.local ? 'Stored locally (1claw server unavailable)' : 'Stored on 1claw server!', 'success');
      // Store the storage key for retrieval
      localStorage.setItem('last_1claw_package_key', key);
    } else {
      showToast('Failed to store package', 'error');
    }

    return result;
  }

  async function retrieveCredentialPackageFromOneClaw(key) {
    if (!key) {
      key = localStorage.getItem('last_1claw_package_key');
      if (!key) {
        showToast('No package key provided or stored', 'error');
        return null;
      }
    }

    const result = await retrieveFromOneClaw(key);
    if (result.success) {
      await importCredentialPackage(result.data);
      showToast(result.local ? 'Retrieved from local storage' : 'Retrieved from 1claw server!', 'success');
      return result.data;
    } else {
      showToast('Failed to retrieve: ' + result.error, 'error');
      return null;
    }
  }

  async function syncTasksToOneClaw() {
    const connections = getStoredConnections();
    if (!connections.google?.events) {
      showToast('No events to sync', 'error');
      return;
    }

    const tasks = connections.google.events.slice(0, PRICING_TIERS[config.pricingTier].maxEvents).map(e => ({
      ...calculateTaskPriority(e),
      title: e.summary,
      start: e.start?.dateTime,
      eventId: e.id
    }));

    const result = await storeOnOneClaw(`tasks-${config.agentId}-${Date.now()}`, tasks, {
      type: 'agent-tasks',
      count: tasks.length,
      source: 'google-calendar'
    });

    if (result.success) {
      localStorage.setItem('poc_agent_tasks', JSON.stringify({ synced: Date.now(), tasks, storageKey: result.storageKey }));
      showToast(`Synced ${tasks.length} tasks to 1claw!`, 'success');
    } else {
      showToast('Sync failed', 'error');
    }

    return tasks;
  }

  async function loadGoogleGIS() {
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
    
    // Auto-store credentials on 1claw if enabled
    if (config.oneclawApiKey) {
      await storeCredentialPackageOnOneClaw();
    }
    
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
    const storageStatus = config.storageEnabled ? '🟢 1claw Connected' : '🟡 Using Local Storage';
    
    rootEl.innerHTML = `
      <div class="poc-auth">
        <h2>🔐 Auth & Monetization</h2>
        <div class="tier-banner">${tier.name} Plan - $${tier.price}/mo</div>
        <div class="storage-status">${storageStatus}</div>
        <div class="actions">
          <button onclick="PocAuthModules.toggleConnection()">${isConnected ? 'Disconnect' : 'Connect Google'}</button>
          ${isConnected ? `<button onclick="PocAuthModules.storeCredentialPackageOnOneClaw()">Store on 1claw</button>` : ''}
          ${isConnected ? `<button onclick="PocAuthModules.retrieveCredentialPackageFromOneClaw()">Retrieve from 1claw</button>` : ''}
          ${tier.agentPrioritization && isConnected ? `<button onclick="PocAuthModules.syncTasksToOneClaw()">Sync Tasks to 1claw</button>` : ''}
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
    mount: (el, opts = {}) => { 
      rootEl = typeof el === 'string' ? document.getElementById(el) : el; 
      config = { ...config, ...opts }; 
      testOneClawConnection().then(() => verifyLicenseWithOneClaw()).then(() => render()); 
    },
    toggleConnection,
    downloadCredentialPackage,
    importCredentialPackage,
    syncTasksToAgent: syncTasksToOneClaw,
    storeCredentialPackageOnOneClaw,
    retrieveCredentialPackageFromOneClaw,
    storeOnOneClaw,
    retrieveFromOneClaw,
    getConnections: getStoredConnections,
    testConnection: testOneClawConnection
  };
})();

window.PocAuthModules = PocAuthModules;
