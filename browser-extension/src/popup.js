/**
 * GhostGuard Popup Script
 */

document.addEventListener('DOMContentLoaded', () => {
  // Get elements
  const enabledToggle = document.getElementById('enabled');
  const showIndicatorToggle = document.getElementById('showIndicator');
  const strategySelect = document.getElementById('strategy');
  const detectedCountEl = document.getElementById('detectedCount');
  const activeTabsEl = document.getElementById('activeTabs');
  const clearStatsBtn = document.getElementById('clearStats');

  // Load current config
  chrome.runtime.sendMessage({ type: 'GET_CONFIG' }, (config) => {
    if (config) {
      enabledToggle.checked = config.enabled !== false;
      showIndicatorToggle.checked = config.showIndicator !== false;
      strategySelect.value = config.strategy || 'placeholder';
    }
  });

  // Load stats
  chrome.runtime.sendMessage({ type: 'GET_STATS' }, (stats) => {
    if (stats) {
      detectedCountEl.textContent = stats.detectedCount || 0;
      activeTabsEl.textContent = (stats.protectedTabs || []).length;
    }
  });

  // Handle toggle changes
  enabledToggle.addEventListener('change', () => {
    const config = { enabled: enabledToggle.checked };
    chrome.runtime.sendMessage({ type: 'SET_CONFIG', config });
  });

  showIndicatorToggle.addEventListener('change', () => {
    const config = { showIndicator: showIndicatorToggle.checked };
    chrome.runtime.sendMessage({ type: 'SET_CONFIG', config });
  });

  strategySelect.addEventListener('change', () => {
    const config = { strategy: strategySelect.value };
    chrome.runtime.sendMessage({ type: 'SET_CONFIG', config });
  });

  // Clear stats
  clearStatsBtn.addEventListener('click', () => {
    chrome.runtime.sendMessage({ type: 'RESET_STATS' }, () => {
      detectedCountEl.textContent = '0';
      activeTabsEl.textContent = '0';
    });
  });

  // Update stats periodically
  setInterval(() => {
    chrome.runtime.sendMessage({ type: 'GET_STATS' }, (stats) => {
      if (stats) {
        detectedCountEl.textContent = stats.detectedCount || 0;
        activeTabsEl.textContent = (stats.protectedTabs || []).length;
      }
    });
  }, 2000);
});
