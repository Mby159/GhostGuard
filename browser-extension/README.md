# GhostGuard Browser Extension

AI Privacy Shield for ChatGPT, Claude, and other AI chat interfaces.

## Features

- **Auto-redact sensitive data** - Phone numbers, emails, ID cards, bank cards
- **Works with popular AI platforms**:
  - ChatGPT (chat.openai.com, chatgpt.com)
  - Claude (claude.ai)
  - Google Bard/Gemini
  - Poe
  - DeepSeek
  - Moonshot
  - Zhipu AI
- **Multiple strategies**: Placeholder, mask, or remove
- **Real-time protection**: Instant feedback when sensitive data is detected
- **Statistics**: Track how many items have been protected

## Installation

### From Source

1. Clone or download this folder
2. Open Chrome and go to `chrome://extensions/`
3. Enable "Developer mode" (top right)
4. Click "Load unpacked"
5. Select the `browser-extension` folder

### From Chrome Web Store

*Coming soon*

## Usage

1. Install the extension
2. Visit any supported AI chat website
3. The extension automatically protects your data
4. Click the GhostGuard icon to configure settings

### Settings

- **Enable Protection**: Turn auto-redaction on/off
- **Show Notifications**: Display toast when data is protected
- **Strategy**: Choose how to hide sensitive data
  - **Placeholder**: `[REDACTED_PHONE_1]`
  - **Mask**: `138****5678`
  - **Remove**: Remove completely

## Supported Data Types

| Type | Example | Risk Level |
|------|---------|------------|
| Phone | 13812345678 | Medium |
| Email | user@example.com | Medium |
| ID Card | 110101199003074562 | Critical |
| Bank Card | 6228480402564890018 | High |

## Keyboard Shortcuts

- **Ctrl+Shift+G**: Toggle protection on/off
- **Ctrl+Shift+R**: Clear all stored mappings

## Development

The extension consists of:

- `manifest.json` - Extension configuration
- `src/content.js` - Content script that monitors input fields
- `src/background.js` - Service worker for state management
- `src/popup.html/js` - Popup UI for settings
- `src/content.css` - Styles for indicators

## Privacy

- All processing happens locally in your browser
- No data is sent to any server
- Sensitive information never leaves your device

## License

MIT
