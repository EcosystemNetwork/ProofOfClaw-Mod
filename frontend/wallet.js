/**
 * Proof of Claw — Shared Wallet Functions
 * Common wallet connection UI handling for all pages
 */

// Wallet state
let walletState = { connected: false, address: null };

/**
 * Connect wallet UI handler
 */
async function connectWalletUI() {
  if (!window.PocViem) {
    alert('Wallet module loading... Please try again in a moment.');
    return;
  }

  const btn = document.getElementById('wallet-connect-btn');
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Connecting...';
  }

  try {
    const { address } = await window.PocViem.connectWallet();
    updateWalletUI(address);
    // Store connection in localStorage for cross-page persistence
    localStorage.setItem('poc_wallet_connected', 'true');
  } catch (e) {
    alert('Wallet connection failed: ' + e.message);
    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Connect Wallet';
    }
  }
}

/**
 * Update wallet UI after connection
 */
function updateWalletUI(address) {
  walletState = { connected: true, address };

  const btn = document.getElementById('wallet-connect-btn');
  const display = document.getElementById('wallet-display');
  const addressEl = document.getElementById('wallet-address');

  if (btn) btn.style.display = 'none';
  if (display) display.style.display = 'flex';
  if (addressEl && window.PocViem) {
    addressEl.textContent = window.PocViem.formatAddress(address);
  }
}

/**
 * Disconnect wallet
 */
function disconnectWalletUI() {
  walletState = { connected: false, address: null };
  localStorage.removeItem('poc_wallet_connected');

  if (window.PocViem) window.PocViem.disconnectWallet();

  const btn = document.getElementById('wallet-connect-btn');
  const display = document.getElementById('wallet-display');

  if (btn) {
    btn.style.display = '';
    btn.textContent = 'Connect Wallet';
    btn.disabled = false;
  }
  if (display) display.style.display = 'none';
}

/**
 * Check for existing wallet connection
 */
async function checkWalletConnection() {
  if (!window.PocViem) {
    setTimeout(checkWalletConnection, 500);
    return;
  }

  // Check if user previously connected
  const wasConnected = localStorage.getItem('poc_wallet_connected');
  if (wasConnected) {
    try {
      const state = window.PocViem.getWalletState();
      if (state.connected) {
        updateWalletUI(state.address);
      }
    } catch (e) {
      // Silent fail - wallet might not be available
    }
  }
}

/**
 * Get current wallet state
 */
function getWalletState() {
  return walletState;
}

// Auto-check wallet connection on load
document.addEventListener('DOMContentLoaded', checkWalletConnection);
