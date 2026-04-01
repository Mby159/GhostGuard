# GhostGuard

[English](#english) | [中文](#中文)

---

## English

Privacy middleware for AI applications - detect, redact, and restore sensitive information.

### Features

- **Middleware API**: Process user input before AI, restore after AI response
- **AI Proxy Server**: Intercept AI API calls, auto redact/restore
- **System-Wide Service**: Monitor clipboard, protect anywhere
- **Browser Extension**: Auto-protect in ChatGPT, Claude, etc.
- **Secrets Scanner**: Prevent commits of API keys, passwords, tokens
- **OCR Detection**: Scan images for sensitive information
- **Multi-type Detection**: Phone, email, ID card, bank card, SSN, and more
- **Multiple Strategies**: Placeholder, mask, remove, or hash
- **Extensible**: Add custom detectors and rules
- **CLI & MCP**: Command-line interface and MCP server support

### Installation

```bash
# Basic installation
pip install -e .

# With MCP support
pip install -e ".[mcp]"

# With global system service (Windows)
pip install -e ".[global]"

# With AI proxy
pip install -e ".[agents]"

# With OCR (Tesseract)
pip install -e ".[ocr]"

# With OCR (EasyOCR - better Chinese support)
pip install -e ".[ocr-easyocr]"
```

### Quick Start

#### As Python Library

```python
from ghostguard import GhostGuard

guard = GhostGuard()

# Middleware flow
user_input = "User Zhang San's phone is 13812345678"
clean_input, mapping = guard.process_input(user_input)
# clean_input: "User Zhang San's phone is [REDACTED_PHONE_1]"

# AI generates response
ai_response = "OK Zhang San, I will contact you at 13812345678"

# Restore before showing to user
final = guard.process_output(ai_response, mapping)
# final: "OK Zhang San, I will contact you at 13812345678"
```

#### As CLI

```bash
# Detect sensitive info
ghostguard detect "My phone is 13812345678"

# Redact text
ghostguard redact "Contact: 13812345678"

# Run demo
ghostguard demo

# Start MCP server
ghostguard mcp
```

### AI API Privacy Proxy

Intercept all AI API calls to automatically redact/restore sensitive data:

```bash
# Start proxy server
ghostguard proxy

# Custom port
ghostguard proxy --port 9999 --strategy mask
```

```python
import openai
openai.api_base = "http://localhost:8888/v1"  # Only change needed!

# All calls are automatically protected
response = openai.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Call Zhang San at 13812345678"}]
)
```

### System-Wide Privacy Service

```bash
# Start with defaults (auto-redact + hotkeys)
ghostguard global

# Hotkeys: Ctrl+Shift+P/R/D
```

### Secrets Scanner

```bash
# Scan files
ghostguard secrets check ./src

# Check staged files
ghostguard secrets check-staged

# Install git pre-commit hook
ghostguard secrets install-hook
```

### OCR - Image Privacy Detection

```bash
# Scan image
ghostguard ocr scan screenshot.png

# Redact sensitive areas
ghostguard ocr redact input.png output.png --method blur
```

### Supported Types

| Type | Risk Level | Description |
|------|------------|-------------|
| phone | medium | Chinese mobile numbers |
| email | medium | Email addresses |
| id_card | critical | Chinese ID card numbers |
| bank_card | high | Bank card numbers (Luhn validated) |
| ssn | critical | US Social Security Numbers |
| ipv4 | low | IPv4 addresses |
| url | low | URLs |
| china_passport | high | Chinese passport numbers |
| china_credit_code | critical | Chinese unified social credit code |
| jwt_token | high | JWT tokens |
| amount | low | Monetary amounts |

### License

MIT

---

## 中文

AI应用的隐私中间件 - 检测、脱敏和还原敏感信息。

### 功能特性

- **中间件API**: 在AI处理前脱敏用户输入，AI响应后还原
- **AI代理服务器**: 拦截AI API调用，自动脱敏/还原
- **系统级服务**: 监控剪贴板，随时随地保护
- **浏览器扩展**: 在ChatGPT、Claude等网站自动保护
- **密钥扫描**: 防止提交API密钥、密码、Token
- **OCR检测**: 扫描图片中的敏感信息
- **多类型检测**: 手机号、邮箱、身份证、银行卡、SSN等
- **多种策略**: 占位符、掩码、删除或哈希
- **可扩展**: 支持自定义检测器和规则
- **CLI & MCP**: 命令行工具和MCP服务器支持

### 安装

```bash
# 基础安装
pip install -e .

# 支持MCP
pip install -e ".[mcp]"

# 支持系统级服务 (Windows)
pip install -e ".[global]"

# 支持AI代理
pip install -e ".[agents]"

# 支持OCR (Tesseract)
pip install -e ".[ocr]"

# 支持OCR (EasyOCR - 中文支持更好)
pip install -e ".[ocr-easyocr]"
```

### 快速开始

#### 作为Python库

```python
from ghostguard import GhostGuard

guard = GhostGuard()

# 中间件流程
user_input = "用户张三的电话是13812345678"
clean_input, mapping = guard.process_input(user_input)
# clean_input: "用户张三的电话是[REDACTED_PHONE_1]"

# AI生成响应
ai_response = "好的张三，我会联系您13812345678"

# 还原后展示给用户
final = guard.process_output(ai_response, mapping)
# final: "好的张三，我会联系您13812345678"
```

#### 作为CLI工具

```bash
# 检测敏感信息
ghostguard detect "我的手机号是13812345678"

# 脱敏文本
ghostguard redact "联系人: 13812345678"

# 运行演示
ghostguard demo

# 启动MCP服务器
ghostguard mcp
```

### AI API隐私代理

拦截所有AI API调用，自动脱敏/还原敏感数据：

```bash
# 启动代理服务器
ghostguard proxy

# 自定义端口
ghostguard proxy --port 9999 --strategy mask
```

```python
import openai
openai.api_base = "http://localhost:8888/v1"  # 只需改这一行！

# 所有调用自动受到保护
response = openai.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "帮张三(13812345678)预约"}]
)
```

### 系统级隐私服务

```bash
# 启动（默认：自动脱敏 + 快捷键）
ghostguard global

# 快捷键: Ctrl+Shift+P/R/D
```

### 密钥扫描

```bash
# 扫描文件
ghostguard secrets check ./src

# 检查暂存区文件
ghostguard secrets check-staged

# 安装git pre-commit钩子
ghostguard secrets install-hook
```

### OCR - 图片隐私检测

```bash
# 扫描图片
ghostguard ocr scan screenshot.png

# 脱敏敏感区域
ghostguard ocr redact input.png output.png --method blur
```

### 支持的类型

| 类型 | 风险等级 | 说明 |
|------|----------|------|
| phone | 中 | 中国手机号 |
| email | 中 | 邮箱地址 |
| id_card | 极高 | 中国身份证号 |
| bank_card | 高 | 银行卡号（Luhn验证） |
| ssn | 极高 | 美国社会安全号 |
| ipv4 | 低 | IPv4地址 |
| url | 低 | 网址 |
| china_passport | 高 | 中国护照号 |
| china_credit_code | 极高 | 统一社会信用代码 |
| jwt_token | 高 | JWT令牌 |
| amount | 低 | 金额 |

### 许可证

MIT
