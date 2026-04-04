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
    // 1clawAI Configuration - REAL API
    oneclawApiKey: null,
    oneclawEndpoint: 'https://api.1claw.xyz/v1',
    agentId: null,
    vaultId: 'default',
    oneclawToken: null,
    storageEnabled: false
  };

  const PRICING_TIERS = {
    free: { name: 'Free', price: 0, maxEvents: 10, agentPrioritization: false },
    basic: { name: 'Basic', price: 9.99, maxEvents: 50, agentPrioritization: true },
    pro: { name: 'Pro', price: 29.99, maxEvents: 200, agentPrioritization: true },
    enterprise: { name: 'Enterprise', price: 'Custom', maxEvents: -1, agentPrioritization: true }
  };

  let googleClient = null;
  let oneClawToken = null;

  // ==================== REAL 1claw API AUTH ====================
  
  async function authenticateWithOneClaw() {
    if (!config.oneclawApiKey || !config.agentId) {
      console.log('1claw: No API key configured');
      return false;
    }

    try {
      const response = await fetch(`${config.oneclawEndpoint}/auth/agent-token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          agent_id: config.agentId,
          api_key: config.oneclawApiKey
        })
      });

      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      
      const data = await response.json();
      oneClawToken = data.access_token;
      config.oneclawToken = oneClawToken;
      config.storageEnabled = true;
      
      console.log('✅ 1claw authenticated');
      return true;
      
    } catch (error) {
      console.error('1claw auth failed:', error);
      config.storageEnabled = false;
      return false;
    }
  }

  async function fetchBotFatherKeyFromVault() {
    if (!oneClawToken) {
      const authed = await authenticateWithOneClaw();
      if (!authed) return null;
    }

    try {
      const response = await fetch(
        `${config.oneclawEndpoint}/vaults/${config.vaultId}/secrets/api-keys/botfather`,
        {
          headers: {
            'Authorization': `Bearer ${oneClawToken}`,
            'Content-Type': 'application/json'
          }
        }
      );

      if (!response.ok) {
        if (response.status === 404) {
          console.log('BotFather key not found in vault');
          return null;
        }
        throw new Error(`HTTP ${response.status}`);
      }

      const data = await response.json();
      console.log('✅ BotFather key retrieved from 1claw vault');
      return data.value || data.secret || data;
      
    } catch (error) {
      console.error('Failed to fetch from vault:', error);
      return null;
    }
  }

  async function storeGoogleCredentialsOnOneClaw() {
    if (!oneClawToken) {
      const authed = await authenticateWithOneClaw();
      if (!authed) {
        showToast('1claw authentication failed', 'error');
        return null;
      }
    }

    const connections = getStoredConnections();
    if (!connections.google?.connected) {
      showToast('No Google Calendar connected', 'error');
      return null;
    }

    const credentialPackage = {
      version: '1.0',
      type: 'google-calendar-oauth',
      agentId: config.agentId,
      credentials: {
        accessToken: connections.google.accessToken,
        scope: connections.google.scope,
        tokenType: connections.google.tokenType,
        connected: connections.google.connected
      },
      storedAt: new Date().toISOString()
    };

    try {
      const response = await fetch(
        `${config.oneclawEndpoint}/vaults/${config.vaultId}/secrets`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${oneClawToken}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            name: 'google-calendar-credentials',
            value: JSON.stringify(credentialPackage),
            tags: { type: 'oauth', service: 'google-calendar', source: 'poc-auth-modules' }
          })
        }
      );

      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      
      showToast('Google credentials stored in 1claw vault!', 'success');
      localStorage.setItem('gcal_oneclaw_reference', JSON.stringify({
        secretName: 'google-calendar-credentials',
        storedAt: Date.now()
      }));
      
      return { success: true };
      
    } catch (error) {
      console.error('Failed to store:', error);
      showToast('Failed to store: ' + error.message, 'error');
      return { success: false, error: error.message };
    }
  }

  async function retrieveGoogleCredentialsFromOneClaw() {
    if (!oneClawToken) {
      const authed = await authenticateWithOneClaw();
      if (!authed) {
        showToast('1claw authentication failed', 'error');
        return null;
      }
    }

    try {
      const response = await fetch(
        `${config.oneclawEndpoint}/vaults/${config.vaultId}/secrets/google-calendar-credentials`,
        {
          headers: {
            'Authorization': `Bearer ${oneClawToken}`,
            'Content-Type': 'application/json'
          }
        }
      );

      if (!response.ok) {
        if (response.status === 404) {
          showToast('No Google credentials found in vault', 'info');
          return null;
        }
        throw new Error(`HTTP ${response.status}`);
      }

      const data = await response.json();
      const pkg = JSON.parse(data.value || data.secret || '{}');
      
      // Restore credentials
      const connections = getStoredConnections();
      connections.google = {
        ...connections.google,
        ...pkg.credentials,
        connected: true
      };
      setStoredConnections(connections);
      
      showToast('Google credentials restored from 1claw!', 'success');
      render();
      return pkg;
      
    } catch (error) {
      console.error('Failed to retrieve:', error);
      showToast('Failed to retrieve: ' + error.message, 'error');
      return null;
    }
  }

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
    // Skip health check for real 1claw API - just try to authenticate
    if (config.oneclawApiKey && config.agentId) {
      const authed = await authenticateWithOneClaw();
      return authed;
    }
    console.log('1claw: No API key configured');
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
    if (!config.googleClientId) {
      showToast('Google Client ID not configured', 'error');
      console.error('Missing GOOGLE_CLIENT_ID. Get one at https://console.cloud.google.com/apis/credentials');
      return null;
    }
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
      initGoogleAuth().then(c => {
        if (c) c.requestAccessToken({ prompt: 'consent' });
      });
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
          <button onclick="window.location.href='custom-auth.html'">Custom Auth</button>
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

  function showCustomAuthForm() {
    const form = document.getElementById('custom-auth-form');
    if (form) form.style.display = 'block';
  }

  function hideCustomAuthForm() {
    const form = document.getElementById('custom-auth-form');
    if (form) {
      form.style.display = 'none';
      // Clear inputs
      const nameInput = document.getElementById('custom-secret-name');
      const valueInput = document.getElementById('custom-secret-value');
      const tagInput = document.getElementById('custom-secret-tag');
      if (nameInput) nameInput.value = '';
      if (valueInput) valueInput.value = '';
      if (tagInput) tagInput.value = '';
    }
  }

  async function saveCustomSecret() {
    const nameInput = document.getElementById('custom-secret-name');
    const valueInput = document.getElementById('custom-secret-value');
    const tagInput = document.getElementById('custom-secret-tag');
    
    const name = nameInput?.value?.trim();
    const value = valueInput?.value?.trim();
    const tag = tagInput?.value?.trim() || 'custom';
    
    if (!name || !value) {
      showToast('Name and value are required', 'error');
      return;
    }

    // Store in localStorage for now (will sync to 1claw if available)
    const customSecrets = JSON.parse(localStorage.getItem('poc_custom_secrets') || '{}');
    customSecrets[name] = { value, tag, createdAt: Date.now() };
    localStorage.setItem('poc_custom_secrets', JSON.stringify(customSecrets));
    
    // Try to store on 1claw if connected
    if (config.storageEnabled && oneClawToken) {
      try {
        const response = await fetch(
          `${config.oneclawEndpoint}/vaults/${config.vaultId}/secrets`,
          {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${oneClawToken}`,
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({
              name: `custom-${name}`,
              value: value,
              tags: { type: 'custom-auth', tag: tag, source: 'poc-auth-modules' }
            })
          }
        );
        
        if (response.ok) {
          showToast(`Secret '${name}' saved to 1claw vault!`, 'success');
        } else {
          showToast(`Secret '${name}' saved locally`, 'success');
        }
      } catch (e) {
        showToast(`Secret '${name}' saved locally`, 'success');
      }
    } else {
      showToast(`Secret '${name}' saved locally`, 'success');
    }
    
    hideCustomAuthForm();
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
    testConnection: testOneClawConnection,
    showCustomAuthForm,
    hideCustomAuthForm,
    saveCustomSecret
  };
})();

window.PocAuthModules = PocAuthModules;
