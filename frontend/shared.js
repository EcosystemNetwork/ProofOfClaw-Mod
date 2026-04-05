/**
 * Proof of Claw — Shared Utilities
 * Common functions used across all app pages.
 */

'use strict';

/* ── HTML Escaping (XSS Prevention) ── */
const _escMap = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

function esc(str) {
  if (str == null) return '';
  return String(str).replace(/[&<>"']/g, c => _escMap[c]);
}

/* ══════════════════════════════════════
   PERSISTENCE LAYER (Neon DB + localStorage fallback)
   Syncs user preferences, orgs, and swarms to the server
   when a wallet is connected. Falls back to localStorage.
   ══════════════════════════════════════ */

const PocPersist = (() => {
  const API_BASE = window.POC_API_URL || 'http://localhost:3456';
  let _wallet = null;
  let _syncQueue = [];
  let _syncing = false;

  /** Get the connected wallet address (lowercase) */
  function getWallet() {
    if (_wallet) return _wallet;
    // Check common wallet sources
    if (typeof window.ethereum !== 'undefined' && window.ethereum.selectedAddress) {
      _wallet = window.ethereum.selectedAddress.toLowerCase();
    } else {
      // Check localStorage for cached wallet
      try { _wallet = localStorage.getItem('poc_wallet_address'); } catch (_) {}
    }
    return _wallet;
  }

  /** Set wallet address (call after wallet connect) */
  function setWallet(addr) {
    _wallet = addr ? addr.toLowerCase() : null;
    try { localStorage.setItem('poc_wallet_address', _wallet || ''); } catch (_) {}
    if (_wallet) flushQueue();
  }

  /** Make an API call with wallet header */
  async function api(method, path, body) {
    const wallet = getWallet();
    if (!wallet) return null;

    const opts = {
      method,
      headers: { 'Content-Type': 'application/json', 'x-wallet-address': wallet },
    };
    if (body !== undefined) opts.body = JSON.stringify(body);

    try {
      const resp = await fetch(`${API_BASE}${path}`, opts);
      if (!resp.ok) return null;
      return await resp.json();
    } catch (_) {
      return null; // Server unreachable — localStorage will cover us
    }
  }

  /** Queue a write for when wallet becomes available */
  function enqueue(fn) {
    if (getWallet()) {
      fn().catch(() => {});
    } else {
      _syncQueue.push(fn);
    }
  }

  /** Flush pending writes */
  async function flushQueue() {
    if (_syncing || _syncQueue.length === 0) return;
    _syncing = true;
    const queue = _syncQueue.splice(0);
    for (const fn of queue) {
      try { await fn(); } catch (_) {}
    }
    _syncing = false;
  }

  // ── Preference helpers ──

  /** Save a preference to both localStorage and server */
  function savePref(key, value) {
    try { localStorage.setItem(key, typeof value === 'string' ? value : JSON.stringify(value)); } catch (_) {}
    enqueue(() => api('PUT', `/v1/preferences/${encodeURIComponent(key)}`, { value }));
  }

  /** Get a preference from localStorage (instant), server sync happens on load */
  function getPref(key) {
    try { return localStorage.getItem(key); } catch (_) { return null; }
  }

  /** Load all preferences from server and merge into localStorage */
  async function syncFromServer() {
    const result = await api('GET', '/v1/preferences');
    if (!result || !result.preferences) return false;

    for (const [key, value] of Object.entries(result.preferences)) {
      try {
        localStorage.setItem(key, typeof value === 'string' ? value : JSON.stringify(value));
      } catch (_) {}
    }
    return true;
  }

  /** Push all current localStorage preferences to server (initial sync) */
  async function syncToServer() {
    const prefs = {};
    // Static keys we always sync
    const keysToSync = [
      'poc_sidebar_collapsed', 'poc_org', 'poc_swarms',
      'poc_auth_connections', 'poc_agent_tasks', 'poc_agents',
      'poc_connection', 'poc_gateway_token', 'poc_ens_domain',
      'poc_custom_secrets', 'gcal_oneclaw_reference',
      'last_1claw_package_key', 'poc_wallet_connected'
    ];
    for (const key of keysToSync) {
      try {
        const val = localStorage.getItem(key);
        if (val !== null) {
          try { prefs[key] = JSON.parse(val); } catch (_) { prefs[key] = val; }
        }
      } catch (_) {}
    }
    // Dynamic keys: agent configs, chat history, 1claw cache, encrypted secrets
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && (key.startsWith('poc_agent_config_') || key.startsWith('poc_chat_') || key.startsWith('1claw_') || key.startsWith('poc_encrypted_'))) {
          const val = localStorage.getItem(key);
          if (val !== null) {
            try { prefs[key] = JSON.parse(val); } catch (_) { prefs[key] = val; }
          }
        }
      }
    } catch (_) {}
    if (Object.keys(prefs).length > 0) {
      await api('PUT', '/v1/preferences', { preferences: prefs });
    }
  }

  // ── Org helpers ──

  async function saveOrgToServer(org) {
    await api('PUT', '/v1/org', { org });
  }

  async function loadOrgFromServer() {
    const result = await api('GET', '/v1/org');
    if (result && result.org) {
      try { localStorage.setItem('poc_org', JSON.stringify(result.org)); } catch (_) {}
      return result.org;
    }
    return null;
  }

  // ── Swarm helpers ──

  async function saveSwarmToServer(swarm) {
    await api('PUT', '/v1/swarms', { swarm });
  }

  async function loadSwarmsFromServer() {
    const result = await api('GET', '/v1/swarms');
    if (result && result.swarms) {
      try { localStorage.setItem('poc_swarms', JSON.stringify(result.swarms)); } catch (_) {}
      return result.swarms;
    }
    return null;
  }

  /** Full sync: pull from server then push anything missing */
  async function fullSync() {
    if (!getWallet()) return;
    const pulled = await syncFromServer();
    if (!pulled) {
      // Server had nothing — push our local state up
      await syncToServer();
      // Also push org and swarms if they exist locally
      const org = (() => { try { return JSON.parse(localStorage.getItem('poc_org')); } catch (_) { return null; } })();
      if (org) await saveOrgToServer(org);
      const swarms = (() => { try { return JSON.parse(localStorage.getItem('poc_swarms')); } catch (_) { return []; } })();
      for (const s of swarms) await saveSwarmToServer(s);
    } else {
      // Also pull org and swarms
      await loadOrgFromServer();
      await loadSwarmsFromServer();
    }
  }

  return {
    getWallet, setWallet, api,
    savePref, getPref,
    syncFromServer, syncToServer, fullSync,
    saveOrgToServer, loadOrgFromServer,
    saveSwarmToServer, loadSwarmsFromServer,
    enqueue,
  };
})();

/* ── Sidebar Toggle ── */
function toggleSidebar() {
  document.body.classList.toggle('sidebar-collapsed');
  const collapsed = document.body.classList.contains('sidebar-collapsed');
  PocPersist.savePref('poc_sidebar_collapsed', String(collapsed));
}

/* ── Mobile Sidebar Toggle ── */
function toggleMobileSidebar() {
  var sidebar = document.querySelector('.sidebar');
  var overlay = document.querySelector('.sidebar-overlay');
  if (!sidebar) return;
  if (sidebar.classList.contains('mobile-open')) {
    closeMobileSidebar();
  } else {
    sidebar.classList.add('mobile-open');
    if (overlay) overlay.classList.add('active');
  }
}

function closeMobileSidebar() {
  var sidebar = document.querySelector('.sidebar');
  var overlay = document.querySelector('.sidebar-overlay');
  if (sidebar) sidebar.classList.remove('mobile-open');
  if (overlay) overlay.classList.remove('active');
}

/* Restore sidebar state on load + mobile enhancements */
document.addEventListener('DOMContentLoaded', () => {
  try {
    if (localStorage.getItem('poc_sidebar_collapsed') === 'true') {
      document.body.classList.add('sidebar-collapsed');
    }
  } catch (_) { /* ignore */ }

  /* Close mobile sidebar when a nav link is clicked */
  var sidebarNav = document.querySelector('.sidebar-nav');
  if (sidebarNav) {
    sidebarNav.addEventListener('click', function(e) {
      if (e.target.closest('a') && window.innerWidth <= 768) {
        closeMobileSidebar();
      }
    });
  }

  /* Close mobile sidebar on window resize past breakpoint */
  var resizeTimer;
  window.addEventListener('resize', function() {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(function() {
      if (window.innerWidth > 768) {
        closeMobileSidebar();
      }
    }, 150);
  });
});

/* ── Keyboard Navigation for onclick elements ── */
document.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' || e.key === ' ') {
    const el = document.activeElement;
    if (el && el.hasAttribute('role') && (el.getAttribute('role') === 'button' || el.getAttribute('role') === 'tab')) {
      e.preventDefault();
      el.click();
    }
  }
});

/* ── Modal Focus Trap ── */
function trapFocus(modal) {
  const focusable = modal.querySelectorAll(
    'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])'
  );
  if (focusable.length === 0) return;

  const first = focusable[0];
  const last = focusable[focusable.length - 1];

  modal.addEventListener('keydown', (e) => {
    if (e.key !== 'Tab') return;
    if (e.shiftKey) {
      if (document.activeElement === first) {
        e.preventDefault();
        last.focus();
      }
    } else {
      if (document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
  });

  first.focus();
}

/* ── Time Formatting ── */
function formatUptime(secs) {
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = Math.floor(secs % 60);
  return h > 0 ? `${h}h ${m}m ${s}s` : `${m}m ${s}s`;
}

function timeAgo(isoString) {
  const diff = Date.now() - new Date(isoString).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

/* ══════════════════════════════════════
   ORGANIZATION & SWARM SYSTEM
   ENS Hierarchy: Name.Swarm.Org.eth
   ══════════════════════════════════════ */

/* ── Organization Storage ── */
function getOrg() {
  try { return JSON.parse(localStorage.getItem('poc_org')); } catch { return null; }
}

function saveOrg(org) {
  localStorage.setItem('poc_org', JSON.stringify(org));
  PocPersist.enqueue(() => PocPersist.saveOrgToServer(org));
}

/* ── Swarm Storage ── */
function getSwarms() {
  try { return JSON.parse(localStorage.getItem('poc_swarms')) || []; } catch { return []; }
}

function saveSwarms(swarms) {
  localStorage.setItem('poc_swarms', JSON.stringify(swarms));
  // Sync the latest swarm to server
  if (swarms.length > 0) {
    const latest = swarms[swarms.length - 1];
    PocPersist.enqueue(() => PocPersist.saveSwarmToServer(latest));
  }
}

function getSwarmById(id) {
  return getSwarms().find(s => s.id === id) || null;
}

/* ── ENS Builder ── */
function buildAgentENS(agentSlug, swarmId) {
  const org = getOrg();
  const swarm = getSwarmById(swarmId);
  if (!org || !swarm) return agentSlug + '.proofofclaw.eth';
  return `${agentSlug}.${swarm.slug}.${org.slug}.proofofclaw.eth`;
}

function buildSwarmENS(swarmSlug) {
  const org = getOrg();
  if (!org) return swarmSlug + '.proofofclaw.eth';
  return `${swarmSlug}.${org.slug}.proofofclaw.eth`;
}

function buildOrgENS(orgSlug) {
  return `${orgSlug}.proofofclaw.eth`;
}

function toSlug(str) {
  return str.trim().toLowerCase().replace(/[^a-z0-9-]/g, '');
}

/* ── ENS Availability Checker ── */
let _ensCheckTimers = {};

function createENSChecker(ensInputId) {
  const wrap = document.createElement('div');
  wrap.className = 'ens-check-status';
  wrap.id = ensInputId + '-status';
  wrap.style.cssText = 'font-size:11px;margin-top:4px;min-height:16px;transition:opacity 0.2s;';
  return wrap;
}

function checkENSAvailability(ensName, statusElId) {
  const el = document.getElementById(statusElId);
  if (!el) return;

  if (!ensName || ensName.length < 5) {
    el.textContent = '';
    return;
  }

  // Debounce
  clearTimeout(_ensCheckTimers[statusElId]);
  el.innerHTML = '<span style="color:var(--text-dim);">Checking availability...</span>';

  _ensCheckTimers[statusElId] = setTimeout(async () => {
    if (typeof ENSResolver === 'undefined') {
      el.innerHTML = '<span style="color:var(--text-dim);">ENS resolver not loaded</span>';
      return;
    }

    try {
      // Check iNFT contract first — an ENS name is "taken" if already minted as an agent iNFT,
      // not just if it has an ENS address record.
      let taken = false;
      if (typeof PocViem !== 'undefined' && PocViem.checkAgentRegistration) {
        // checkAgentRegistration checks by agentId (name hash), but we need ENS name check.
        // Fall through to ENS resolver if PocViem doesn't expose getTokenByENS yet.
      }
      // Fallback: check if ENS name already resolves to an address
      const addr = await ENSResolver.resolveAddress(ensName);
      taken = !!addr;

      if (taken) {
        el.innerHTML = `<span style="color:var(--red);">&#x2717; <strong>${esc(ensName)}</strong> is already taken</span>`;
      } else {
        el.innerHTML = `<span style="color:var(--green);">&#x2713; <strong>${esc(ensName)}</strong> is available</span>`;
      }
    } catch (e) {
      el.innerHTML = `<span style="color:var(--text-dim);">Could not check — ${esc(e.message)}</span>`;
    }
  }, 500);
}

/* ── Org Badge Injection ── */
function injectOrgBadge() {
  const org = getOrg();
  if (!org) return;

  // Find topbar-right on the page
  const topbarRight = document.querySelector('.topbar-right');
  if (!topbarRight) return;

  // Don't double-inject
  if (topbarRight.querySelector('.org-badge')) return;

  const badge = document.createElement('div');
  badge.className = 'org-badge';
  badge.innerHTML = `
    <span class="org-badge-icon">${esc(org.icon || '\u2B23')}</span>
    <span class="org-badge-name">${esc(org.name)}</span>
    <span class="org-badge-ens">${esc(org.ens)}</span>
  `;
  topbarRight.prepend(badge);
}

/* ── Org Registration Modal ── */
function showOrgRegistration() {
  // Don't show if org already exists or if we're on landing/docs pages
  if (getOrg()) return;
  const isAppPage = document.querySelector('.sidebar');
  if (!isAppPage) return;

  // Create overlay
  const overlay = document.createElement('div');
  overlay.id = 'org-register-overlay';
  overlay.className = 'modal-overlay active';
  overlay.style.zIndex = '9000';
  overlay.innerHTML = `
    <div class="modal" style="max-width:560px;">
      <div class="modal-header">
        <h2 style="font-family:var(--font-display);font-weight:700;">Register Your Organization</h2>
      </div>
      <div class="modal-body">
        <p style="color:var(--text-secondary);font-size:13px;margin-bottom:20px;line-height:1.7;">
          Before you can create swarms and register agents, you need to claim your organization's on-chain identity.
          Your ENS will follow the hierarchy: <strong style="color:var(--cyan);">Agent.Swarm.Org.eth</strong>
        </p>

        <div class="form-group">
          <label>Organization Name</label>
          <input type="text" id="org-name-input" placeholder="e.g. Proof of Claw Labs" autofocus>
        </div>
        <div class="form-group">
          <label>ENS Domain</label>
          <input type="text" id="org-ens-input" placeholder="auto-generated" readonly
                 style="color:var(--cyan);background:var(--bg-primary);">
          <div class="form-hint">Your organization's top-level ENS domain</div>
          <div id="org-ens-input-status" class="ens-check-status" style="font-size:11px;margin-top:4px;min-height:16px;"></div>
        </div>
        <div class="form-group">
          <label>Description</label>
          <textarea id="org-desc-input" placeholder="What does your organization do?" rows="3"></textarea>
        </div>
        <div class="form-group">
          <label>Network</label>
          <select id="org-network-input">
            <option value="sepolia">Sepolia (Testnet)</option>
            <option value="og_testnet">0G Testnet (Chain ID 16602)</option>
            <option value="mainnet">Ethereum Mainnet</option>
            <option value="og_mainnet">0G Mainnet (Chain ID 16661)</option>
          </select>
        </div>

        <div class="form-group">
          <label>Wallet Security</label>
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <label style="display:flex;align-items:center;gap:6px;padding:10px 16px;background:var(--bg-primary);border:2px solid var(--border-cyan);border-radius:8px;cursor:pointer;flex:1;min-width:180px;" id="org-wallet-browser-opt">
              <input type="radio" name="org-wallet-type" value="browser" checked onchange="updateOrgWalletChoice()">
              <div>
                <div style="font-size:12px;font-weight:600;color:var(--text-primary);">Browser Wallet</div>
                <div style="font-size:10px;color:var(--text-dim);">MetaMask, WalletConnect, etc.</div>
              </div>
            </label>
            <label style="display:flex;align-items:center;gap:6px;padding:10px 16px;background:var(--bg-primary);border:2px solid var(--border);border-radius:8px;cursor:pointer;flex:1;min-width:180px;" id="org-wallet-ledger-opt">
              <input type="radio" name="org-wallet-type" value="ledger" onchange="updateOrgWalletChoice()">
              <div>
                <div style="font-size:12px;font-weight:600;color:var(--text-primary);">Ledger Hardware</div>
                <div style="font-size:10px;color:var(--text-dim);">Sign with secure element</div>
              </div>
            </label>
          </div>
          <div id="org-ledger-status" style="display:none;margin-top:8px;padding:10px;background:rgba(179,136,255,0.06);border:1px solid rgba(179,136,255,0.2);border-radius:8px;font-size:11px;">
            <div style="color:var(--purple);font-weight:600;margin-bottom:4px;">Ledger Connection</div>
            <div style="color:var(--text-secondary);">Connect your Ledger, open the Ethereum app, then click below.</div>
            <button class="btn" style="margin-top:8px;padding:8px 16px;font-size:11px;background:linear-gradient(135deg,#bb86fc,#9c27b0);color:#fff;border:none;border-radius:6px;cursor:pointer;" onclick="connectLedgerForOrg()">
              Connect Ledger
            </button>
            <div id="org-ledger-address" style="margin-top:6px;font-family:var(--font-mono);font-size:10px;color:var(--cyan);word-break:break-all;"></div>
          </div>
        </div>

        <div style="background:rgba(0,229,255,0.06);border:1px solid var(--border-cyan);border-radius:8px;padding:14px;margin-bottom:20px;">
          <div style="font-size:11px;color:var(--text-dim);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;">Wallet Ownership Hierarchy</div>
          <div style="font-family:var(--font-mono);font-size:12px;line-height:2;">
            <div><span style="color:var(--text-dim);">Org Wallet:</span> <strong id="org-preview-org" style="color:var(--cyan);">—</strong> <span style="color:var(--text-dim);font-size:10px;">holds swarm ENS names</span></div>
            <div style="padding-left:16px;"><span style="color:var(--text-dim);">Swarm Wallet:</span> <span id="org-preview-swarm" style="color:var(--purple);">team-name.<span class="org-slug-preview">org</span>.eth</span> <span style="color:var(--text-dim);font-size:10px;">holds agent ENS names</span></div>
            <div style="padding-left:32px;"><span style="color:var(--text-dim);">Agent Wallet:</span> <span id="org-preview-agent" style="color:var(--green);">agent-name.team-name.<span class="org-slug-preview">org</span>.eth</span> <span style="color:var(--text-dim);font-size:10px;">holds credentials</span></div>
          </div>
        </div>

        <button id="org-register-btn" class="btn btn-primary" style="width:100%;padding:12px;font-size:14px;font-weight:700;" disabled onclick="submitOrgRegistration()">
          Register Organization
        </button>
      </div>
    </div>
  `;

  document.body.appendChild(overlay);

  // Bind name -> ENS auto-gen
  const nameInput = overlay.querySelector('#org-name-input');
  const ensInput = overlay.querySelector('#org-ens-input');
  const btn = overlay.querySelector('#org-register-btn');

  nameInput.addEventListener('input', function() {
    const slug = toSlug(this.value);
    const ens = slug ? slug + '.proofofclaw.eth' : '';
    ensInput.value = ens;
    btn.disabled = !slug;

    // Update preview
    overlay.querySelector('#org-preview-org').textContent = ens || '\u2014';
    overlay.querySelectorAll('.org-slug-preview').forEach(el => {
      el.textContent = slug || 'org';
    });

    // Check ENS availability
    checkENSAvailability(ens, 'org-ens-input-status');
  });

  // Focus trap
  trapFocus(overlay.querySelector('.modal'));
}

async function submitOrgRegistration() {
  const name = document.getElementById('org-name-input').value.trim();
  const slug = toSlug(name);
  if (!slug) return;

  const btn = document.getElementById('org-register-btn');
  btn.disabled = true;
  btn.textContent = 'Registering...';

  const description = document.getElementById('org-desc-input').value.trim();
  const network = document.getElementById('org-network-input').value;

  // Register org on the swarm bridge (local service)
  const BRIDGE_URL = window.POC_BRIDGE_URL || 'http://localhost:3002';
  let bridgeResult = null;
  try {
    const resp = await fetch(`${BRIDGE_URL}/create-org`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, slug, description, network }),
    });
    if (resp.ok) {
      bridgeResult = await resp.json();
    }
  } catch (_) {
    // Bridge not running — org still works locally
  }

  // Org wallet = user's connected wallet (MetaMask / Ledger hardware)
  // This wallet owns everything — swarms, agents, ENS hierarchy
  const walletType = document.querySelector('input[name="org-wallet-type"]:checked')?.value || 'browser';
  const ownerWallet = walletType === 'ledger' && window._orgLedgerAddress
    ? window._orgLedgerAddress
    : (typeof walletState !== 'undefined' && walletState.address)
      ? walletState.address
      : localStorage.getItem('poc_wallet_address') || null;

  const org = {
    id: bridgeResult?.orgId || ('org-' + Date.now()),
    name: name,
    slug: slug,
    ens: slug + '.proofofclaw.eth',
    description: description,
    network: network,
    icon: '\u2B23',
    // Org wallet = user's own wallet (hardware or browser)
    walletAddress: ownerWallet,
    walletType: walletType, // 'browser' | 'ledger'
    defaultChannelId: bridgeResult?.defaultChannelId || null,
    bridgeConfigured: !!bridgeResult,
    createdAt: new Date().toISOString()
  };

  saveOrg(org);
  injectOrgBadge();

  // Show success
  const overlay = document.getElementById('org-register-overlay');
  const modal = overlay.querySelector('.modal');
  const bridgeNote = bridgeResult
    ? '<p style="color:var(--green);font-size:12px;margin-top:8px;">Swarm bridge configured automatically.</p>'
    : '<p style="color:var(--text-dim);font-size:12px;margin-top:8px;">Swarm bridge not running \u2014 org saved locally. Start the bridge to enable cross-swarm messaging.</p>';

  modal.innerHTML = `
    <div class="modal-body" style="padding:32px;">
      <div style="text-align:center;margin-bottom:24px;">
        <div style="font-size:40px;margin-bottom:12px;">\u2705</div>
        <h2 style="font-family:var(--font-display);font-weight:700;margin-bottom:4px;">Organization Registered!</h2>
        <p style="color:var(--cyan);font-family:var(--font-mono);font-size:14px;">${esc(org.ens)}</p>
        ${org.walletAddress ? `<p style="font-size:11px;color:var(--text-dim);font-family:var(--font-mono);margin-top:4px;">Owner Wallet: ${esc(org.walletAddress.slice(0,6))}...${esc(org.walletAddress.slice(-4))}</p>` : ''}
        <p style="font-size:11px;color:var(--text-secondary);margin-top:8px;">Your wallet owns this org. Swarms and agents below it will each receive their own wallets to hold ENS credentials.</p>
        ${bridgeNote}
      </div>
      <button class="btn btn-primary" style="width:100%;padding:12px 32px;font-size:14px;font-weight:700;" onclick="closeOrgRegistration()">Continue</button>
    </div>
  `;
}


function closeOrgRegistration() {
  const overlay = document.getElementById('org-register-overlay');
  if (overlay) overlay.remove();
}

/* ── Ledger Hardware Wallet Support ── */

/**
 * Update UI when user toggles between browser/ledger wallet for org.
 */
function updateOrgWalletChoice() {
  const choice = document.querySelector('input[name="org-wallet-type"]:checked')?.value;
  const ledgerStatus = document.getElementById('org-ledger-status');
  const browserOpt = document.getElementById('org-wallet-browser-opt');
  const ledgerOpt = document.getElementById('org-wallet-ledger-opt');

  if (choice === 'ledger') {
    ledgerStatus.style.display = 'block';
    ledgerOpt.style.borderColor = 'var(--purple)';
    browserOpt.style.borderColor = 'var(--border)';
  } else {
    ledgerStatus.style.display = 'none';
    browserOpt.style.borderColor = 'var(--border-cyan)';
    ledgerOpt.style.borderColor = 'var(--border)';
  }
}

/**
 * Connect Ledger hardware wallet for org ownership.
 * Uses WebHID/WebUSB to communicate with Ledger device.
 * The Ledger address becomes the org's owner wallet.
 */
async function connectLedgerForOrg() {
  const statusEl = document.getElementById('org-ledger-address');
  const btn = document.querySelector('[onclick="connectLedgerForOrg()"]');

  if (btn) { btn.disabled = true; btn.textContent = 'Connecting...'; }
  statusEl.innerHTML = '<span style="color:var(--amber);">&#x23F3; Connecting to Ledger\u2026 Unlock device and open Ethereum app.</span>';

  // Ensure ledger-sdk.js is loaded (lazy-load for pages that don't include it)
  if (!window.LedgerSDK) {
    await new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = 'ledger-sdk.js?v=20260404f';
      s.onload = resolve;
      s.onerror = () => reject(new Error('Failed to load ledger-sdk.js'));
      document.head.appendChild(s);
    });
  }

  const TransportWebHID = window.LedgerSDK?.TransportWebHID;
  const Eth             = window.LedgerSDK?.Eth;
  const DERIVE_PATH     = "44'/60'/0'/0/0";

  try {
    let addr;

    if (!navigator.hid || !TransportWebHID || !Eth) {
      // WebHID not available (Firefox / non-HTTPS) — simulated demo
      await new Promise(r => setTimeout(r, 900));
      addr = '0xSimulated' + Math.random().toString(16).slice(2,10).toUpperCase().padEnd(32,'0');
      statusEl.innerHTML = `<span style="color:var(--amber);">&#x26A0;&#xFE0F; WebHID not supported — simulated: <strong style="color:var(--cyan);">${esc(addr.slice(0,8)+'\u2026'+addr.slice(-4))}</strong></span>`;
    } else {
      // Real WebHID path — same logic as approve.html
      const permitted = await TransportWebHID.list();
      const transport = permitted.length > 0
        ? await TransportWebHID.open(permitted[0])
        : await TransportWebHID.request();
      const eth    = new Eth(transport);
      const result = await eth.getAddress(DERIVE_PATH, false, false);
      addr = result.address;
      statusEl.innerHTML = `<span style="color:var(--green);">&#x2713; Connected: <strong style="color:var(--cyan);font-family:var(--font-mono);">${esc(addr)}</strong></span>`;
    }

    window._orgLedgerAddress = addr;

    if (btn) { btn.textContent = '\u2714 Connected'; btn.style.background = 'var(--green, #00e676)'; btn.style.color = '#000'; }
    const regBtn = document.getElementById('org-register-btn');
    if (regBtn) regBtn.disabled = false;

  } catch (err) {
    const msg = err.message || String(err);
    if (btn) { btn.disabled = false; btn.textContent = 'Connect Ledger'; }

    if (msg.toLowerCase().includes('cancel') || msg.toLowerCase().includes('no device')) {
      statusEl.innerHTML = '<span style="color:var(--text-dim);">Cancelled. Click Connect Ledger to try again.</span>';
      return;
    }
    if (msg.includes('0x5515') || msg.toLowerCase().includes('locked')) {
      statusEl.innerHTML = '<span style="color:var(--amber);">&#x26A0;&#xFE0F; Device locked — enter PIN then click Connect Ledger again.</span>';
    } else if (msg.includes('0x6d00') || msg.includes('0x6e00') || msg.toLowerCase().includes('ethereum')) {
      statusEl.innerHTML = '<span style="color:var(--amber);">&#x26A0;&#xFE0F; Open the Ethereum app on your Ledger, then click Connect Ledger again.</span>';
    } else {
      statusEl.innerHTML = `<span style="color:var(--red);">&#x2717; ${esc(msg.slice(0, 120))}</span>`;
    }
    console.error('connectLedgerForOrg:', err);
  }
}

/* ── Swarm Creation Modal ── */
function showSwarmCreation() {
  const org = getOrg();
  if (!org) {
    showOrgRegistration();
    return;
  }

  // Remove existing if any
  const existing = document.getElementById('swarm-create-overlay');
  if (existing) existing.remove();

  const overlay = document.createElement('div');
  overlay.id = 'swarm-create-overlay';
  overlay.className = 'modal-overlay active';
  overlay.style.zIndex = '9000';
  overlay.innerHTML = `
    <div class="modal" style="max-width:520px;">
      <div class="modal-header">
        <h2 style="font-family:var(--font-display);font-weight:700;">Create Swarm</h2>
        <button class="modal-close" onclick="closeSwarmCreation()" aria-label="Close">&times;</button>
      </div>
      <div class="modal-body">
        <p style="color:var(--text-secondary);font-size:13px;margin-bottom:20px;line-height:1.7;">
          A swarm is a team of agents within <strong style="color:var(--cyan);">${esc(org.name)}</strong>.
          Agents registered to this swarm will get an ENS under <strong style="color:var(--purple);">swarm-name.${esc(org.slug)}.eth</strong>
        </p>

        <div class="form-group">
          <label>Swarm Name</label>
          <input type="text" id="swarm-name-input" placeholder="e.g. alpha-team" autofocus>
        </div>
        <div class="form-group">
          <label>ENS Subdomain</label>
          <input type="text" id="swarm-ens-input" placeholder="auto-generated" readonly
                 style="color:var(--purple);background:var(--bg-primary);">
          <div class="form-hint">Swarm ENS: swarm-name.${esc(org.slug)}.eth</div>
          <div id="swarm-ens-input-status" class="ens-check-status" style="font-size:11px;margin-top:4px;min-height:16px;"></div>
        </div>
        <div class="form-group">
          <label>Description</label>
          <textarea id="swarm-desc-input" placeholder="What is this swarm's purpose?" rows="2"></textarea>
        </div>

        <div style="background:rgba(179,136,255,0.06);border:1px solid rgba(179,136,255,0.2);border-radius:8px;padding:14px;margin-bottom:20px;">
          <div style="font-size:11px;color:var(--text-dim);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px;">Swarm Wallet &amp; ENS Preview</div>
          <div style="font-family:var(--font-mono);font-size:12px;line-height:2;">
            <div><span style="color:var(--purple);">Swarm ENS:</span> <span id="swarm-slug-preview">swarm</span>.${esc(org.slug)}.eth</div>
            <div><span style="color:var(--green);">Agent ENS:</span> agent-name.<span id="swarm-slug-preview-agent">swarm</span>.${esc(org.slug)}.eth</div>
          </div>
          <div style="font-size:10px;color:var(--text-dim);margin-top:6px;">
            A dedicated wallet is auto-generated for this swarm to hold its agents' ENS credentials.
            ${org.walletType === 'ledger' ? '<br><span style="color:var(--purple);">Parent org uses Ledger hardware wallet for signing.</span>' : ''}
          </div>
        </div>

        <button id="swarm-create-btn" class="btn" style="width:100%;padding:12px;font-size:14px;font-weight:700;background:linear-gradient(135deg,#bb86fc,#9c27b0);color:#fff;border:none;" disabled onclick="submitSwarmCreation()">
          Create Swarm
        </button>

        ${getSwarms().length > 0 ? `
          <div style="margin-top:20px;border-top:1px solid var(--border);padding-top:16px;">
            <div style="font-size:11px;color:var(--text-dim);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;">Existing Swarms</div>
            ${getSwarms().map(s => `
              <div style="display:flex;align-items:center;justify-content:space-between;padding:8px 12px;background:var(--bg-card);border:1px solid var(--border);border-radius:6px;margin-bottom:4px;">
                <div>
                  <span style="color:var(--text-primary);font-size:13px;font-weight:600;">${esc(s.name)}</span>
                  <span style="color:var(--purple);font-size:11px;margin-left:8px;">${esc(s.ens)}</span>
                  ${s.walletAddress ? `<div style="font-size:9px;color:var(--text-dim);font-family:var(--font-mono);margin-top:2px;">${esc(s.walletAddress.slice(0,6))}...${esc(s.walletAddress.slice(-4))}</div>` : ''}
                </div>
                <span style="font-size:11px;color:var(--text-dim);">${s.agentCount || 0} agents</span>
              </div>
            `).join('')}
          </div>
        ` : ''}
      </div>
    </div>
  `;

  document.body.appendChild(overlay);

  // Bind name -> ENS auto-gen
  const nameInput = overlay.querySelector('#swarm-name-input');
  const ensInput = overlay.querySelector('#swarm-ens-input');
  const btn = overlay.querySelector('#swarm-create-btn');

  nameInput.addEventListener('input', function() {
    const slug = toSlug(this.value);
    const ens = slug ? `${slug}.${org.slug}.eth` : '';
    ensInput.value = ens;
    btn.disabled = !slug;
    overlay.querySelector('#swarm-slug-preview').textContent = slug || 'swarm';
    const agentPreview = overlay.querySelector('#swarm-slug-preview-agent');
    if (agentPreview) agentPreview.textContent = slug || 'swarm';

    // Check ENS availability
    checkENSAvailability(ens, 'swarm-ens-input-status');
  });

  trapFocus(overlay.querySelector('.modal'));
}

async function submitSwarmCreation() {
  const org = getOrg();
  const name = document.getElementById('swarm-name-input').value.trim();
  const slug = toSlug(name);
  if (!slug || !org) return;

  const swarms = getSwarms();

  // Check for duplicate
  if (swarms.some(s => s.slug === slug)) {
    document.getElementById('swarm-name-input').style.borderColor = 'var(--red)';
    return;
  }

  // Register channel on bridge if available
  const BRIDGE_URL = window.POC_BRIDGE_URL || 'http://localhost:3002';
  let channelId = null;
  try {
    const resp = await fetch(`${BRIDGE_URL}/create-org`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: `${org.name} / ${name}`,
        slug: `${org.slug}-${slug}`,
        description: document.getElementById('swarm-desc-input').value.trim(),
      }),
    });
    if (resp.ok) {
      const data = await resp.json();
      channelId = data.defaultChannelId;
    }
  } catch (_) {
    // Bridge offline — continue with local-only swarm
  }

  // Generate a dedicated wallet for this swarm
  // Swarm wallet holds the agent ENS names registered under it
  let swarmWallet = null;
  if (window.PocViem && window.PocViem.generateAgentWallet) {
    swarmWallet = window.PocViem.generateAgentWallet();
  }

  const swarm = {
    id: 'swarm-' + Date.now(),
    name: name,
    slug: slug,
    ens: `${slug}.${org.slug}.eth`,
    description: document.getElementById('swarm-desc-input').value.trim(),
    orgId: org.id,
    // Swarm's own wallet — holds agent ENS names as sub-credentials
    walletAddress: swarmWallet ? swarmWallet.address : null,
    walletKey: swarmWallet ? swarmWallet.privateKey : null,
    channelId: channelId,
    agentCount: 0,
    createdAt: new Date().toISOString()
  };

  swarms.push(swarm);
  saveSwarms(swarms);
  closeSwarmCreation();

  // If a swarm selector exists on the page, refresh it
  if (typeof refreshSwarmSelector === 'function') refreshSwarmSelector();
  // Refresh swarm grid if on the swarms tab
  if (typeof renderSwarmGrid === 'function') renderSwarmGrid();
}

function closeSwarmCreation() {
  const overlay = document.getElementById('swarm-create-overlay');
  if (overlay) overlay.remove();
}

/* ── Init: check for org on app pages ── */
document.addEventListener('DOMContentLoaded', () => {
  // Inject org badge if org exists
  injectOrgBadge();

  // Show org registration on first visit to an app page
  setTimeout(() => {
    if (!getOrg() && document.querySelector('.sidebar')) {
      showOrgRegistration();
    }
  }, 300);

  // Sync preferences from Neon DB (non-blocking)
  PocPersist.fullSync().then(() => {
    // Re-apply sidebar state after server sync (may have changed)
    try {
      if (localStorage.getItem('poc_sidebar_collapsed') === 'true') {
        document.body.classList.add('sidebar-collapsed');
      } else {
        document.body.classList.remove('sidebar-collapsed');
      }
    } catch (_) {}
    // Re-inject org badge in case server had newer data
    injectOrgBadge();
  }).catch(() => {});

  // Listen for wallet connect events (MetaMask / WalletConnect)
  if (typeof window.ethereum !== 'undefined') {
    window.ethereum.on('accountsChanged', (accounts) => {
      if (accounts.length > 0) {
        PocPersist.setWallet(accounts[0]);
        PocPersist.fullSync().catch(() => {});
      }
    });
  }
});
