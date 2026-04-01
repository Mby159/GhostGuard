/**
 * GhostGuard Background Service Worker
 * 
 * Handles configuration, statistics, and cross-tab communication.
 */

// Configuration
const DEFAULT_CONFIG = {
  enabled: true,
  autoRedact: true,
  showIndicator: true,
  strategy: 'placeholder',
  detectedCount: 0,
  protectedTabs: [],
};

// Initialize
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.sync.get(null, (result) => {
    // Set defaults if not exist
    const config = { ...DEFAULT_CONFIG, ...result };
    chrome.storage.sync.set(config);
  });
  
  console.log('[GhostGuard] Extension installed');
});

// Message handler
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.type) {
    case 'GET_CONFIG':
      chrome.storage.sync.get(null, (config) => {
        sendResponse(config);
      });
      return true;

    case 'SET_CONFIG':
      chrome.storage.sync.set(message.config, () => {
        // Notify all content scripts
        notifyContentScripts({ type: 'UPDATE_CONFIG', config: message.config });
        sendResponse({ success: true });
      });
      return true;

    case 'INCREMENT_COUNTER':
      chrome.storage.sync.get('detectedCount', (result) => {
        const newCount = (result.detectedCount || 0) + (message.count || 1);
        chrome.storage.sync.set({ detectedCount: newCount });
        sendResponse({ count: newCount });
      });
      return true;

    case 'GET_STATS':
      chrome.storage.sync.get(['detectedCount', 'protectedTabs'], (result) => {
        sendResponse({
          detectedCount: result.detectedCount || 0,
          protectedTabs: result.protectedTabs || [],
        });
      });
      return true;

    case 'RESET_STATS':
      chrome.storage.sync.set({ detectedCount: 0, protectedTabs: [] }, () => {
        sendResponse({ success: true });
      });
      return true;

    case 'TAB_UPDATED':
      // Track which tabs have active protection
      const tabId = sender.tab?.id;
      if (tabId) {
        chrome.storage.sync.get('protectedTabs', (result) => {
          const tabs = result.protectedTabs || [];
          if (!tabs.includes(tabId)) {
            tabs.push(tabId);
            chrome.storage.sync.set({ protectedTabs: tabs });
          }
        });
      }
      return true;

    case 'OPEN_POPUP':
      chrome.action.openPopup();
      return true;
  }
});

// Notify all content scripts
function notifyContentScripts(message) {
  chrome.tabs.query({}, (tabs) => {
    tabs.forEach(tab => {
      chrome.tabs.sendMessage(tab.id, message).catch(() => {
        // Tab might not have content script
      });
    });
  });
}

// Update badge based on state
function updateBadge(tabId, enabled) {
  if (enabled) {
    chrome.action.setBadgeText({ tabId, text: 'ON' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#667eea' });
  } else {
    chrome.action.setBadgeText({ tabId, text: '' });
  }
}

// Listen for tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    // Check if this is a supported AI site
    const supportedSites = [
      'chat.openai.com',
      'chatgpt.com',
      'claude.ai',
      'bard.google.com',
      'gemini.google.com',
      'poe.com',
    ];
    
    const isSupported = supportedSites.some(site => tab.url.includes(site));
    
    if (isSupported) {
      chrome.storage.sync.get('enabled', (result) => {
        updateBadge(tabId, result.enabled !== false);
      });
    }
  }
});

// Clean up when tabs are closed
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.sync.get('protectedTabs', (result) => {
    const tabs = (result.protectedTabs || []).filter(id => id !== tabId);
    chrome.storage.sync.set({ protectedTabs: tabs });
  });
});
