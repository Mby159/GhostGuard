/**
 * GhostGuard Content Script
 * 
 * Monitors and processes sensitive information in AI chat interfaces.
 * Works with ChatGPT, Claude, Bard, and other AI chat platforms.
 */

(function() {
  'use strict';

  // Configuration
  const CONFIG = {
    enabled: true,
    autoRedact: true,
    showIndicator: true,
    strategy: 'placeholder', // placeholder, mask, remove
  };

  // Placeholder mapping for current session
  let placeholderMap = {};
  let reverseMap = {};
  let placeholderCounter = 0;

  // Sensitive patterns (simplified - full logic in background)
  const PATTERNS = {
    phone: /(?<![\d\-])(?:\+?86[-\s]?)?(1[3-9]\d{9})(?![\d\-])/g,
    email: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g,
    idCard: /(?<![\dXx])\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?![\dXx])/g,
    bankCard: /(?<![\d])\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}(?![\d])/g,
  };

  // Initialize
  function init() {
    loadConfig();
    setupInputListeners();
    setupMutationObserver();
    
    console.log('[GhostGuard] Privacy shield active');
  }

  // Load configuration from storage
  function loadConfig() {
    chrome.storage.sync.get(['enabled', 'autoRedact', 'strategy'], (result) => {
      CONFIG.enabled = result.enabled !== false;
      CONFIG.autoRedact = result.autoRedact !== false;
      CONFIG.strategy = result.strategy || 'placeholder';
    });
  }

  // Setup input listeners
  function setupInputListeners() {
    // Find all text inputs and textareas
    const inputs = document.querySelectorAll('textarea, input[type="text"], [contenteditable="true"]');
    
    inputs.forEach(input => {
      // Skip if already processed
      if (input.dataset.ghostguardProcessed) return;
      input.dataset.ghostguardProcessed = 'true';

      // Listen for paste events
      input.addEventListener('paste', handlePaste, true);
      
      // Listen for input events (for contenteditable)
      if (input.contentEditable === 'true') {
        input.addEventListener('input', handleInput, true);
      }
    });

    // Also observe for new inputs
    observeNewInputs();
  }

  // Observe for dynamically added inputs
  function observeNewInputs() {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach(mutation => {
        mutation.addedNodes.forEach(node => {
          if (node.nodeType === Node.ELEMENT_NODE) {
            const inputs = node.querySelectorAll?.('textarea, input[type="text"], [contenteditable="true"]');
            inputs?.forEach(input => {
              if (!input.dataset.ghostguardProcessed) {
                input.dataset.ghostguardProcessed = 'true';
                input.addEventListener('paste', handlePaste, true);
              }
            });
          }
        });
      });
    });

    observer.observe(document.body, { childList: true, subtree: true });
  }

  // Setup mutation observer for AI responses
  function setupMutationObserver() {
    // Observe chat response areas for restoration
    const observer = new MutationObserver((mutations) => {
      if (!CONFIG.enabled) return;

      mutations.forEach(mutation => {
        mutation.addedNodes.forEach(node => {
          if (node.nodeType === Node.ELEMENT_NODE) {
            restoreInElement(node);
          }
        });
      });
    });

    // Common chat response selectors
    const selectors = [
      '[data-message-author-role="assistant"]',
      '.assistant-message',
      '.model-response',
      '.prose',
      '.markdown',
      '[class*="response"]',
      '[class*="message"]',
    ];

    // Observe main chat containers
    const chatContainers = document.querySelector('main') || document.body;
    observer.observe(chatContainers, { childList: true, subtree: true });
  }

  // Handle paste event
  function handlePaste(event) {
    if (!CONFIG.enabled || !CONFIG.autoRedact) return;

    const pastedText = event.clipboardData?.getData('text');
    if (!pastedText) return;

    const { redacted, mappings } = redactText(pastedText);
    
    if (Object.keys(mappings).length > 0) {
      // Store mappings
      Object.assign(placeholderMap, mappings);
      for (const [placeholder, original] of Object.entries(mappings)) {
        reverseMap[placeholder] = original;  // P0 fix: was reversed
      }

      // Prevent default paste and insert redacted text
      event.preventDefault();
      event.stopPropagation();

      const target = event.target;
      
      if (target.contentEditable === 'true') {
        // For contenteditable
        document.execCommand('insertText', false, redacted);
      } else {
        // For regular inputs
        const start = target.selectionStart;
        const end = target.selectionEnd;
        const value = target.value;
        target.value = value.slice(0, start) + redacted + value.slice(end);
        target.selectionStart = target.selectionEnd = start + redacted.length;
      }

      // Show indicator
      showIndicator(`Redacted ${Object.keys(mappings).length} items`);
    }
  }

  // Handle input for contenteditable
  function handleInput(event) {
    // Could add real-time redaction here if needed
  }

  // Redact text
  function redactText(text) {
    let redacted = text;
    const mappings = {};

    // Phone numbers
    redacted = redacted.replace(PATTERNS.phone, (match) => {
      const placeholder = createPlaceholder('PHONE');
      mappings[placeholder] = match;
      return placeholder;
    });

    // Emails
    redacted = redacted.replace(PATTERNS.email, (match) => {
      const placeholder = createPlaceholder('EMAIL');
      mappings[placeholder] = match;
      return placeholder;
    });

    // ID cards
    redacted = redacted.replace(PATTERNS.idCard, (match) => {
      const placeholder = createPlaceholder('ID');
      mappings[placeholder] = match;
      return placeholder;
    });

    // Bank cards
    redacted = redacted.replace(PATTERNS.bankCard, (match) => {
      const placeholder = createPlaceholder('BANK');
      mappings[placeholder] = match;
      return placeholder;
    });

    return { redacted, mappings };
  }

  // Create placeholder
  function createPlaceholder(type) {
    placeholderCounter++;
    return `[REDACTED_${type}_${placeholderCounter}]`;
  }

  // Restore placeholders in element
  function restoreInElement(element) {
    if (Object.keys(reverseMap).length === 0) return;

    const walker = document.createTreeWalker(
      element,
      NodeFilter.SHOW_TEXT,
      null,
      false
    );

    let node;
    while (node = walker.nextNode()) {
      let text = node.textContent;
      let modified = false;

      for (const [placeholder, original] of Object.entries(reverseMap)) {
        if (text.includes(placeholder)) {
          text = text.replace(new RegExp(escapeRegex(placeholder), 'g'), original);
          modified = true;
        }
      }

      if (modified) {
        node.textContent = text;
      }
    }
  }

  // Escape regex special characters
  function escapeRegex(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  // Show notification indicator
  function showIndicator(message) {
    if (!CONFIG.showIndicator) return;

    // Remove existing indicator
    document.querySelector('.ghostguard-indicator')?.remove();

    const indicator = document.createElement('div');
    indicator.className = 'ghostguard-indicator';
    indicator.innerHTML = `
      <span class="ghostguard-icon">👻</span>
      <span class="ghostguard-message">${message}</span>
    `;
    document.body.appendChild(indicator);

    // Animate in
    requestAnimationFrame(() => {
      indicator.classList.add('ghostguard-visible');
    });

    // Remove after delay
    setTimeout(() => {
      indicator.classList.remove('ghostguard-visible');
      setTimeout(() => indicator.remove(), 300);
    }, 2000);
  }

  // Listen for messages from popup/background
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    switch (message.type) {
      case 'UPDATE_CONFIG':
        Object.assign(CONFIG, message.config);
        sendResponse({ success: true });
        break;

      case 'GET_STATUS':
        sendResponse({
          enabled: CONFIG.enabled,
          mappingsCount: Object.keys(reverseMap).length,
          placeholderCount: placeholderCounter,
        });
        break;

      case 'TOGGLE_ENABLED':
        CONFIG.enabled = !CONFIG.enabled;
        sendResponse({ enabled: CONFIG.enabled });
        break;

      case 'CLEAR_MAPPINGS':
        placeholderMap = {};
        reverseMap = {};
        placeholderCounter = 0;
        sendResponse({ success: true });
        break;

      case 'RESTORE_ALL':
        // Restore all placeholders on the page
        const allText = document.body.innerText;
        let restored = allText;
        for (const [placeholder, original] of Object.entries(reverseMap)) {
          restored = restored.replace(new RegExp(escapeRegex(placeholder), 'g'), original);
        }
        sendResponse({ restored, count: Object.keys(reverseMap).length });
        break;
    }
    return true;
  });

  // Start
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
