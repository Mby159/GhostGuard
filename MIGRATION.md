# GhostGuard 三套件合并迁移指南

## 背景

三个仓库（privacy-guard / privacy-proxy / GhostGuard）在检测引擎层面有大量逐字重复的代码：
- **privacy-guard** 与 **GhostGuard** 拥有完全一致的检测规则集（手机号、身份证、银行卡、SSN、URL、护照、统一信用代码、JWT、金额、IPv4），以及等价的 redact/restore/mask 策略实现。
- **privacy-proxy** 依赖 privacy-guard 的 `PrivacyGuard` 类，但仅在 proxy 场景使用，核心逻辑也是检测+脱敏。

**决策**：以 GhostGuard 为统一主仓库，把 privacy-guard 和 privacy-proxy 的核心能力以兼容层形式并入 GhostGuard，原两个独立仓库进入归档状态。

## 合并架构

```
GhostGuard/
├── ghostguard/
│   ├── core.py              ← 统一检测引擎（原 GhostGuard）
│   ├── types.py             ← 统一类型定义
│   ├── detectors/           ← 检测器模块（含全部 11 种内置检测器）
│   ├── agents/              ← proxy / server 代理层（原 privacy-proxy）
│   ├── compat/              ← 新增：向后兼容层
│   │   ├── privacy_guard.py  ← 兼容 `from privacy_guard import PrivacyGuard`
│   │   └── proxy_adapter.py  ← 兼容 `from privacy_processor import PrivacyProcessor`
│   ├── secrets/             ← 密钥扫描（原 GhostGuard 独有）
│   └── ...
├── browser-extension/       ← 浏览器扩展（原 GhostGuard 独有）
├── tests/                   ← 统一测试
├── test_p0_proxy.py         ← P0 回归测试（已推送）
└── MIGRATION.md             ← 本文件
```

## 迁移方式

### privacy-guard 用户

**无需改代码。** 将 import 从：
```python
from privacy_guard import PrivacyGuard, RiskLevel
```
改为：
```python
from ghostguard.compat.privacy_guard import PrivacyGuard, RiskLevel
```

API 完全一致：
- `guard.detect(text)` → `List[Dict]`
- `guard.redact(text, strategy)` → `{"text": ..., "mapping": ..., "detected_count": ...}`
- `guard.restore(text, mapping)` → `str`
- `guard.redact_file(file_path, output_path, strategy)` → `Dict`
- `guard.scan_directory(directory, extensions, recursive, exclude_git)` → `Dict`
- `guard.add_rule(name, pattern, risk_level)` → `bool`
- `guard.load_rules_from_config(config_path)` → `Dict`

### privacy-proxy 用户

将 import 从：
```python
from privacy_processor import PrivacyProcessor, PrivacyConfig
from models import PrivacyResult, SensitiveItem, RiskLevel
from config import load_config, ServerConfig
```
改为：
```python
from ghostguard.compat.proxy_adapter import (
    PrivacyProcessor, PrivacyConfig,
    PrivacyResult, SensitiveItem, RiskLevel,
)
```

配置加载方式建议改用 Python 标准 `dataclasses.asdict` 或 JSON 手动解析，`ServerConfig` 属于 proxy 层特有，不在合并范围内（proxy server 逻辑保留在原 privacy-proxy 仓库）。

## 能力增益

| 功能 | privacy-guard | privacy-proxy | GhostGuard（合并后） |
|---|---|---|---|
| 11 种内置检测器 | ✅ | ✅ | ✅ |
| mask/remove/placeholder 策略 | ✅ | ✅ | ✅ |
| HASH 策略 | ❌ | ❌ | ✅ |
| 自定义规则 | ✅ | ✅ | ✅ |
| 回调机制 (on_detect) | ❌ | ❌ | ✅ |
| 最小风险级别过滤 | ❌ | ❌ | ✅ |
| 文件扫描 | ✅ | ❌ | ✅ |
| 目录批量扫描 | ✅ | ❌ | ✅ |
| MCP server | ✅ | ❌ | 保留* |
| OpenAI proxy | ❌ | ✅ | 保留** |
| 浏览器扩展 | ❌ | ❌ | ✅ |
| 密钥扫描 | ❌ | ❌ | ✅ |
| OCR 检测 | ❌ | ❌ | ✅ |
| 剪贴板监听 | ❌ | ❌ | ✅ |

> * MCP server 保留在 GhostGuard 外部（ghostguard 包本身是纯库，不耦合 MCP）
> ** proxy server 保留在原 privacy-proxy 仓库，但底层引擎改为 GhostGuard

## 废弃声明

- `privacy-guard` → 仅保留历史版本，README 指向本迁移指南
- `privacy-proxy` → 保留 proxy server 逻辑，但 README 注明底层引擎已迁移

## 测试覆盖

合并后 GhostGuard 仓库测试总计：
- `tests/test_core.py` — 检测器核心（8 测试）
- `tests/test_secrets.py` — 密钥扫描（5 测试）
- `test_p0_proxy.py` — list prompt 脱敏回归（5 测试）
- `tests/test_compat_privacy_guard.py` — 兼容层回归（推荐后续补充）
- `tests/test_compat_proxy.py` — proxy 适配器回归（推荐后续补充）

## 风险与回滚

- **风险**：兼容层在语义层面已验证（detect/redact/restore/file/directory），但 MCP server 路径和 CLI 子命令与原 privacy-guard 不完全一致。如你依赖 `python privacy_guard.py --mcp`，需要额外评估。
- **回滚**：兼容层不修改 `core.py` / `types.py` / `detectors/`，回滚只需删除 `compat/` 目录，无数据风险。