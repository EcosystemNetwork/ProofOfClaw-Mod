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

/* ── Sidebar Toggle ── */
function toggleSidebar() {
  document.body.classList.toggle('sidebar-collapsed');
  try {
    localStorage.setItem('poc_sidebar_collapsed', document.body.classList.contains('sidebar-collapsed'));
  } catch (_) { /* ignore */ }
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

/* Restore sidebar state on load */
document.addEventListener('DOMContentLoaded', () => {
  try {
    if (localStorage.getItem('poc_sidebar_collapsed') === 'true') {
      document.body.classList.add('sidebar-collapsed');
    }
  } catch (_) { /* ignore */ }
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
}

/* ── Swarm Storage ── */
function getSwarms() {
  try { return JSON.parse(localStorage.getItem('poc_swarms')) || []; } catch { return []; }
}

function saveSwarms(swarms) {
  localStorage.setItem('poc_swarms', JSON.stringify(swarms));
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
      const addr = await ENSResolver.resolveAddress(ensName);
      if (addr) {
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

        <div style="background:rgba(0,229,255,0.06);border:1px solid var(--border-cyan);border-radius:8px;padding:14px;margin-bottom:20px;">
          <div style="font-size:11px;color:var(--text-dim);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;">ENS Hierarchy Preview</div>
          <div style="font-family:var(--font-mono);font-size:12px;line-height:2;">
            <div><span style="color:var(--text-dim);">Org:</span> <strong id="org-preview-org" style="color:var(--cyan);">—</strong></div>
            <div><span style="color:var(--text-dim);">Swarm:</span> <span id="org-preview-swarm" style="color:var(--purple);">team-name.<span class="org-slug-preview">org</span>.eth</span></div>
            <div><span style="color:var(--text-dim);">Agent:</span> <span id="org-preview-agent" style="color:var(--green);">agent-name.team-name.<span class="org-slug-preview">org</span>.eth</span></div>
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

  const org = {
    id: bridgeResult?.orgId || ('org-' + Date.now()),
    name: name,
    slug: slug,
    ens: slug + '.proofofclaw.eth',
    description: description,
    network: network,
    icon: '\u2B23',
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
          <div style="font-size:11px;color:var(--text-dim);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px;">Agent ENS Preview</div>
          <div style="font-family:var(--font-mono);font-size:12px;color:var(--green);">
            agent-name.<span id="swarm-slug-preview">swarm</span>.${esc(org.slug)}.eth
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

  const swarm = {
    id: 'swarm-' + Date.now(),
    name: name,
    slug: slug,
    ens: `${slug}.${org.slug}.eth`,
    description: document.getElementById('swarm-desc-input').value.trim(),
    orgId: org.id,
    channelId: channelId,
    agentCount: 0,
    createdAt: new Date().toISOString()
  };

  swarms.push(swarm);
  saveSwarms(swarms);
  closeSwarmCreation();

  // If a swarm selector exists on the page, refresh it
  if (typeof refreshSwarmSelector === 'function') refreshSwarmSelector();
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
});
