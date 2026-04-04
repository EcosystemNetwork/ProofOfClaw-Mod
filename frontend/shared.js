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
