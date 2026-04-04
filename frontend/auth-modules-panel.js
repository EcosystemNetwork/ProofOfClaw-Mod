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
    storageEnabled: false,
    pricingTier: 'free'
  };

  const PRICING_TIERS = {
    free: { name: 'Free', price: 0, maxEvents: 10, agentPrioritization: false },
    basic: { name: 'Basic', price: 9.99, maxEvents: 50, agentPrioritization: true },
    pro: { name: 'Pro', price: 29.99, maxEvents: 200, agentPrioritization: true },
    enterprise: { name: 'Enterprise', price: 'Custom', maxEvents: -1, agentPrioritization: true }
  };

  let googleClient = null;
  let oneClawToken = null;

  function isLocalhost() {
    return window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
  }

  // ==================== REAL 1claw API AUTH ====================
  
  async function authenticateWithOneClaw() {
    if (!config.oneclawApiKey || !config.agentId) {
      console.log('1claw: No API key configured');
      return false;
    }

    // Skip 1claw auth on localhost due to CORS
    if (isLocalhost()) {
      console.log('1claw: Skipping auth on localhost (CORS restricted)');
      config.storageEnabled = false;
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
      console.error('1claw auth failed:', error.message);
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
    // Skip on localhost due to CORS
    if (isLocalhost() || !config.oneclawApiKey) {
      return { valid: true, tier: config.pricingTier };
    }
    try {
      const response = await fetch(`${config.oneclawEndpoint}/license/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': config.oneclawApiKey },
        body: JSON.stringify({ agentId: config.agentId, feature: 'google-calendar' })
      });
      const data = await response.json();
      config.pricingTier = data.tier || config.pricingTier;
      return data;
    } catch (error) {
      return { valid: false, tier: config.pricingTier };
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

  const AUTH_MODULES = [
    { 
      id: 'github', 
      name: 'GitHub', 
      tagline: 'OAuth App · GitHub App',
      icon: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"></path></svg>`, 
      accent: '#f0f6fc',
      desc: 'Delegate identity to GitHub accounts. Use for developer tooling, repo-scoped agents, and org membership checks.',
      chips: ['OAuth2', 'Device flow', 'Fine-grained tokens'],
      flow: ['Redirect to GitHub authorize URL with client_id and scopes', 'Exchange code at token endpoint; store refresh token if offline access', 'Map id / login to your user record; issue your own session or JWT']
    },
    { 
      id: 'google', 
      name: 'Google', 
      tagline: 'OpenID Connect',
      icon: `<svg viewBox="0 0 24 24" width="26" height="26"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"></path><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"></path><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"></path><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"></path></svg>`, 
      accent: '#4285f4',
      desc: 'Sign in with Google for consumer-friendly onboarding. OIDC id_token carries verified email and subject (sub).',
      chips: ['OIDC', 'email_verified', 'refresh token'],
      flow: ['Use Google\'s discovery document for JWKS and token endpoint URLs', 'Validate id_token audience, issuer, and expiry server-side', 'Aligns with "Google OAuth" style flows in vault APIs such as 1Claw']
    },
    { 
      id: 'discord', 
      name: 'Discord', 
      tagline: 'OAuth2 · Bot',
      icon: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"></path></svg>`, 
      accent: '#5865f2',
      desc: 'Guild-aware bots and "Login with Discord" for communities. Combine user OAuth with bot tokens for channel actions.',
      chips: ['guilds', 'bot scope', 'webhook'],
      flow: ['Register application; set redirect URIs for your web or deep link', 'Request identify / guilds as needed; add bot install URL separately', 'Store Discord user id; respect rate limits on the REST API']
    },
    { 
      id: 'telegram', 
      name: 'Telegram', 
      tagline: 'Bot API · Login Widget',
      icon: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M11.944 0A12 12 0 0 0 0 12a12 12 0 0 0 12 12 12 12 0 0 0 12-12A12 12 0 0 0 12 0a12 12 0 0 0-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 0 1 .171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.48.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z"></path></svg>`, 
      accent: '#2aabee',
      desc: 'Bots for messaging and the Login Widget for lightweight web auth without a full OAuth server in some setups.',
      chips: ['Bot token', 'HMAC verify', 'Mini Apps'],
      flow: ['Create bot via BotFather; keep token server-side only', 'For Login Widget: verify hash of auth payload with bot token', 'Use deep links (t.me/) to start conversations from your site']
    },
    { 
      id: 'slack', 
      name: 'Slack', 
      tagline: 'OAuth v2 · workspace',
      icon: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M5.042 15.165a2.528 2.528 0 0 1-2.52 2.523A2.528 2.528 0 0 1 0 15.165a2.527 2.527 0 0 1 2.522-2.52h2.52v2.52zM6.313 15.165a2.527 2.527 0 0 1 2.521-2.52 2.527 2.527 0 0 1 2.521 2.52v6.313A2.528 2.528 0 0 1 8.834 24a2.528 2.528 0 0 1-2.521-2.522v-6.313zM8.834 5.042a2.528 2.528 0 0 1-2.521-2.52A2.528 2.528 0 0 1 8.834 0a2.528 2.528 0 0 1 2.521 2.522v2.52H8.834V5.042zm0 1.27a2.528 2.528 0 0 1 2.521 2.521 2.528 2.528 0 0 1-2.521 2.521H2.522A2.528 2.528 0 0 1 0 8.834a2.528 2.528 0 0 1 2.522-2.521h6.312zm11.126 2.521a2.528 2.528 0 0 1 2.522-2.521A2.528 2.528 0 0 1 24 8.834a2.528 2.528 0 0 1-2.522 2.521h-2.522V8.834zm-1.27 0a2.528 2.528 0 0 1-2.523 2.521 2.527 2.527 0 0 1-2.52-2.521V2.522A2.527 2.527 0 0 1 15.165 0a2.528 2.528 0 0 1 2.523 2.522v6.312zm-2.523 11.126a2.527 2.527 0 0 1 2.52 2.522A2.527 2.527 0 0 1 15.165 24a2.528 2.528 0 0 1-2.52-2.522v-2.522h2.52zm0-1.27a2.527 2.527 0 0 1-2.52-2.523 2.526 2.526 0 0 1 2.52-2.52h6.313A2.528 2.528 0 0 1 24 15.165a2.528 2.528 0 0 1-2.522 2.523h-6.313z"></path></svg>`, 
      accent: '#e01e5a',
      desc: 'Install apps into customer workspaces; user tokens vs bot tokens determine whether you act as a user or the app.',
      chips: ['user_scope', 'bot token', 'signing secret'],
      flow: ['Start OAuth with client id, scopes, and redirect URI registered in Slack app', 'Exchange code for access token; store team id and token type', 'Verify incoming requests with signing secret for Events API']
    },
    { 
      id: 'custom', 
      name: 'Custom', 
      tagline: 'API key · mTLS · OIDC',
      icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path><circle cx="12" cy="16" r="1.25" fill="currentColor" stroke="none"></circle></svg>`, 
      accent: '#ffb300',
      desc: 'First-party credentials and enterprise patterns: static API keys, mutual TLS, or OIDC client credentials for service-style agents.',
      chips: ['api_key', 'mtls', 'oidc_client_credentials'],
      flow: ['Issue scoped secrets; rotate and audit like vault "agent" auth methods', 'mTLS: terminate at gateway; forward client cert fingerprint to policy layer', 'OIDC client credentials: machine token → your API JWT (e.g. agent-token exchange)']
    }
  ];

  function render() {
    if (!rootEl) return;
    const connections = getStoredConnections();
    const tier = PRICING_TIERS[config.pricingTier] || PRICING_TIERS.free;
    const storageStatus = config.storageEnabled ? '🟢 1claw Connected' : '🟡 Using Local Storage';
    
    rootEl.innerHTML = `
      <div class="poc-auth">
        <h2>🔐 Auth Modules</h2>
        <div class="tier-banner">${tier.name} Plan - $${tier.price}/mo</div>
        <div class="storage-status">${storageStatus}</div>
        
        <div class="module-grid">
          ${AUTH_MODULES.map(mod => {
            const isConnected = connections[mod.id]?.connected;
            const isCustom = mod.id === 'custom';
            return `
            <article class="auth-card ${isConnected ? 'connected' : ''}" style="--accent:${mod.accent}">
              <div class="auth-card-header">
                <div class="auth-icon" aria-hidden="true">${mod.icon}</div>
                <div>
                  <h2>${mod.name}</h2>
                  <p class="tagline">${mod.tagline}</p>
                </div>
              </div>
              <p class="desc">${mod.desc}</p>
              <div class="chips">
                ${mod.chips.map(chip => `<span class="chip">${chip}</span>`).join('')}
              </div>
              <ul class="flow-list">
                ${mod.flow.map(step => `<li>${step}</li>`).join('')}
              </ul>
              ${isConnected ? '<div class="connected-badge">● Connected</div>' : ''}
              ${isCustom ? '<button class="connect-btn" onclick="window.location.href=\'custom-auth.html\'">Manage Secrets</button>' : '<button class="connect-btn" onclick="PocAuthModules.toggleModule(\'' + mod.id + '\')">' + (isConnected ? 'Disconnect' : 'Connect') + '</button>'}
            </article>
          `}).join('')}
        </div>
        
        ${connections.google?.connected ? `
        <div class="google-actions" style="margin-top:20px;padding:15px;border:1px solid var(--border-cyan);border-radius:8px;">
          <h4>Google Calendar Actions</h4>
          <button onclick="PocAuthModules.storeCredentialPackageOnOneClaw()">Store on 1claw</button>
          <button onclick="PocAuthModules.retrieveCredentialPackageFromOneClaw()">Retrieve from 1claw</button>
          ${tier.agentPrioritization ? `<button onclick="PocAuthModules.syncTasksToOneClaw()">Sync Tasks</button>` : ''}
        </div>` : ''}
      </div>
      
      <style>
        .module-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
          gap: 16px;
          margin-top: 20px;
        }
        .auth-card {
          background: rgba(10, 12, 18, 0.8);
          border: 1px solid var(--border);
          border-radius: 12px;
          padding: 20px;
          transition: all 0.2s;
          display: flex;
          flex-direction: column;
        }
        .auth-card:hover {
          border-color: var(--accent);
          box-shadow: 0 0 20px var(--accent);
        }
        .auth-card.connected {
          border-color: #0e6;
        }
        .auth-card-header {
          display: flex;
          align-items: center;
          gap: 12px;
          margin-bottom: 12px;
        }
        .auth-icon {
          width: 32px;
          height: 32px;
          color: var(--accent);
        }
        .auth-icon svg {
          width: 100%;
          height: 100%;
        }
        .auth-card h2 {
          font-family: var(--font-display);
          font-size: 1.1rem;
          font-weight: 600;
          margin: 0;
        }
        .tagline {
          font-size: 0.7rem;
          color: var(--text-secondary);
          margin: 2px 0 0 0;
          text-transform: uppercase;
          letter-spacing: 0.05em;
        }
        .desc {
          font-size: 0.8rem;
          color: var(--text-secondary);
          line-height: 1.5;
          margin: 8px 0;
          flex: 1;
        }
        .chips {
          display: flex;
          flex-wrap: wrap;
          gap: 6px;
          margin: 10px 0;
        }
        .chip {
          font-size: 0.65rem;
          padding: 3px 10px;
          background: rgba(0, 229, 255, 0.1);
          border: 1px solid var(--border-cyan);
          border-radius: 100px;
          color: var(--cyan);
          text-transform: uppercase;
          letter-spacing: 0.05em;
        }
        .flow-list {
          list-style: none;
          margin: 10px 0 0 0;
          padding: 0;
          font-size: 0.75rem;
          color: var(--text-secondary);
        }
        .flow-list li {
          padding: 6px 0;
          border-bottom: 1px solid var(--border);
          line-height: 1.4;
        }
        .flow-list li:last-child {
          border-bottom: none;
        }
        .flow-list li::before {
          content: '→ ';
          color: var(--accent);
        }
        .connected-badge {
          font-size: 0.7rem;
          color: #0e6;
          margin-top: 12px;
          text-align: center;
        }
        .connect-btn {
          margin-top: 12px;
          width: 100%;
          padding: 10px;
          background: var(--accent);
          color: #000;
          border: none;
          border-radius: 6px;
          font-family: var(--font-mono);
          font-size: 0.75rem;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s;
          text-transform: uppercase;
          letter-spacing: 0.05em;
        }
        .connect-btn:hover {
          filter: brightness(1.2);
        }
        .google-actions {
          display: flex;
          gap: 10px;
          flex-wrap: wrap;
        }
        .google-actions button {
          flex: 1;
          min-width: 120px;
        }
      </style>`;
  }

  function toggleModule(moduleId) {
    if (moduleId === 'custom') {
      window.location.href = 'custom-auth.html';
      return;
    }
    if (moduleId === 'google') {
      toggleConnection();
      return;
    }
    // For other modules, simulate toggle for now
    const connections = getStoredConnections();
    if (connections[moduleId]?.connected) {
      connections[moduleId] = { connected: false };
      showToast(`${moduleId} disconnected`, 'success');
    } else {
      connections[moduleId] = { connected: true, simulated: true };
      showToast(`${moduleId} connected (simulated)`, 'success');
    }
    setStoredConnections(connections);
    render();
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
    toggleModule,
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
