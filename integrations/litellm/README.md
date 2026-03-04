# LiteLLM + ContextForge Plugin Framework (CMF) Integration

This integration adds policy enforcement (PII detection, content scanning, redaction) to any LLM provider via [LiteLLM Proxy](https://docs.litellm.ai/docs/simple_proxy) guardrails and the ContextForge Plugin Extensibility Framework (CPEX).

## How It Works

```
  Client Request                        LLM Response
       │                                     │
       ▼                                     ▼
┌──────────────────────────────────────────────────────┐
│                   LiteLLM Proxy                      │
│                                                      │
│  ┌──────────────┐              ┌───────────────────┐ │
│  │  Pre-Call     │              │  Post-Call         │ │
│  │  Guardrail    │              │  Guardrail         │ │
│  │              │              │                   │ │
│  │  • Block PII  │    ┌────┐   │  • Redact PII in   │ │
│  │  • Redact     │───▶│ LLM│──▶│    LLM responses   │ │
│  │    inputs     │    └────┘   │  • Block sensitive  │ │
│  │              │              │    outputs          │ │
│  └──────────────┘              └───────────────────┘ │
│                                                      │
│           CMFProxyHandler (CustomGuardrail)           │
│                      │                               │
│                      ▼                               │
│            ┌───────────────────┐                     │
│            │  CPEX Plugin      │                     │
│            │  Manager          │                     │
│            │  (evaluate hook)  │                     │
│            └───────────────────┘                     │
└──────────────────────────────────────────────────────┘
```

**Pre-call guardrail**: scans user input before it reaches the LLM. Can block requests (e.g., SSN detected) or redact content (e.g., replace emails with `[EMAIL REDACTED]`).

**Post-call guardrail**: scans LLM responses before they reach the client. Can redact sensitive data the LLM generated or block responses entirely.

## Prerequisites

- Python 3.11+
- [cpex](https://pypi.org/project/cpex/) (ContextForge Plugin Extensibility Framework)
- [litellm](https://pypi.org/project/litellm/) with proxy support

## Installation

```bash
# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate

# Install the framework and LiteLLM proxy
pip install cpex "litellm[proxy]"
```

## Project Structure

```
.
├── integrations/litellm/
│   ├── cmf_guardrail.py       # Entry point for LiteLLM guardrail system
│   ├── proxy_handler.py       # Core guardrail handler (pre/post call hooks)
│   ├── converter.py           # LiteLLM ↔ CMF message conversion
│   ├── proxy_config.yaml      # LiteLLM Proxy configuration
│   ├── test_proxy_client.py   # Python test client (OpenAI SDK)
│   └── test_proxy_live.sh     # Shell test script (curl)
│
└── plugins/examples/
    ├── plugin_config.yaml                        # Plugin configuration
    └── content_scanner/
        └── content_scanner.py                  # Example: PII scanner plugin
```

### Core Files

| File | Purpose |
|------|---------|
| `cmf_guardrail.py` | Thin wrapper that LiteLLM instantiates. Reads `CMF_PLUGIN_CONFIG` env var for the plugin config path. |
| `proxy_handler.py` | `CMFProxyHandler(CustomGuardrail)` — implements `async_pre_call_hook` and `async_post_call_success_hook`. Converts messages to CMF, runs them through the plugin manager, and returns modified/blocked results. |
| `converter.py` | `LiteLLMToCMFConverter` — bidirectional conversion between OpenAI-format messages and CMF `Message` objects. Handles text, tool calls, tool results, and images. |
| `proxy_config.yaml` | Configures LiteLLM models and registers the CMF guardrails. |

## Quick Start

### 1. Configure Your LLM Provider

Edit `integrations/litellm/proxy_config.yaml` to set up your model(s):

```yaml
model_list:
  - model_name: my-model
    litellm_params:
      model: watsonx/ibm/granite-8b-code-instruct
      # Credentials via environment: WATSONX_APIKEY, WATSONX_URL, WATSONX_PROJECT_ID

  - model_name: gpt-4
    litellm_params:
      model: gpt-4
      # Credentials via environment: OPENAI_API_KEY
```

LiteLLM supports [100+ providers](https://docs.litellm.ai/docs/providers). Set the required environment variables for your provider.

### 2. Configure Guardrails

The guardrails section in the same file controls when policy evaluation runs:

```yaml
guardrails:
  # Scan inputs before they reach the LLM
  - guardrail_name: "cmf-policy-pre"
    litellm_params:
      guardrail: cmf_guardrail.CMFGuardrail
      mode: "pre_call"
      default_on: true

  # Scan LLM outputs before they reach the client
  - guardrail_name: "cmf-policy-post"
    litellm_params:
      guardrail: cmf_guardrail.CMFGuardrail
      mode: "post_call"
      default_on: true
```

### 3. Configure Plugins

The plugin config defines what patterns to scan for. Set the path via `CMF_PLUGIN_CONFIG` environment variable, or it defaults to `plugins/examples/plugin_config.yaml`.

```yaml
# plugins/examples/plugin_config.yaml
plugins:
  - name: "ContentScanner"
    kind: "plugins.examples.content_scanner.content_scanner.ContentScannerPlugin"
    hooks: ["evaluate"]
    mode: "enforce"
    priority: 10
    config:
      patterns:
        - name: "ssn"
          pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
          severity: "critical"
          block: true           # Block the request entirely
        - name: "email"
          pattern: "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b"
          severity: "medium"
          redact: true           # Replace with placeholder
          redact_replacement: "[EMAIL REDACTED]"
        - name: "phone"
          pattern: "\\b(?:\\+?1[-.]?)?\\(?\\d{3}\\)?[-.]?\\d{3}[-.]?\\d{4}\\b"
          severity: "medium"
          redact: true
          redact_replacement: "[PHONE REDACTED]"
```

### 4. Start the Proxy

```bash
# Load provider credentials
set -a && source .env && set +a

# Start LiteLLM Proxy from the project root
cd /path/to/project
litellm --config integrations/litellm/proxy_config.yaml
```

The proxy starts on `http://localhost:4000` by default.

### 5. Test It

**Python client** (uses the OpenAI SDK, since the proxy is OpenAI-compatible):

```bash
pip install openai
python integrations/litellm/test_proxy_client.py
```

The test client runs four scenarios:

| Test | Input | Expected |
|------|-------|----------|
| 1. Simple greeting | `"Hello, how are you?"` | Pass through |
| 2. SSN in input | `"My SSN is 123-45-6789"` | Blocked (400) |
| 3. Email + phone in input | `"Contact john.doe@example.com or call 555-123-4567"` | Redacted before LLM |
| 4. Ask LLM to generate PII | `"Generate a fictional employee record..."` | Response redacted |

You can configure via environment variables:

```bash
PROXY_URL=http://localhost:4000 MODEL=watsonx python integrations/litellm/test_proxy_client.py
```

**Shell script** (curl-based alternative):

```bash
./integrations/litellm/test_proxy_live.sh
```

**Manual curl**:

```bash
# Clean message — passes through
curl http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "my-model", "messages": [{"role": "user", "content": "Hello!"}]}'

# SSN in input — blocked (400 error)
curl http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "my-model", "messages": [{"role": "user", "content": "My SSN is 123-45-6789"}]}'

# Email in input — redacted before reaching LLM
curl http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "my-model", "messages": [{"role": "user", "content": "Contact john@example.com"}]}'
```

## Writing Custom Plugins

Create a plugin by subclassing `Plugin` and implementing the `evaluate` hook:

```python
from cpex.framework import Plugin, PluginConfig, PluginContext, PluginViolation
from cpex.framework.hooks.message import MessagePayload, MessageResult

class MyPolicyPlugin(Plugin):
    def __init__(self, config: PluginConfig):
        super().__init__(config)

    async def evaluate(self, payload: MessagePayload, context: PluginContext) -> MessageResult:
        # Scan message content using MessageView
        for view in payload.message.iter_views():
            if "forbidden" in view.content:
                return MessageResult(
                    continue_processing=False,
                    violation=PluginViolation(
                        reason="Forbidden content detected",
                        code="FORBIDDEN_CONTENT",
                    ),
                )
        return MessageResult()  # Allow
```

Register it in your plugin config YAML:

```yaml
plugins:
  - name: "MyPolicy"
    kind: "path.to.my_plugin.MyPolicyPlugin"
    hooks: ["evaluate"]
    mode: "enforce"
    priority: 10
```

## Configuration Reference

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CMF_PLUGIN_CONFIG` | Path to plugin configuration YAML | `plugins/examples/plugin_config.yaml` |
| Provider-specific vars | e.g., `OPENAI_API_KEY`, `WATSONX_APIKEY` | (required by your provider) |

### CMFProxyHandler Options

Set in `cmf_guardrail.py` or via subclass:

| Option | Description | Default |
|--------|-------------|---------|
| `config_path` | Path to plugin config YAML | (required) |
| `log_decisions` | Log allow/block/redact decisions | `True` |
| `fail_open` | Allow requests if plugin manager fails to initialize | `False` |

### Guardrail Modes

| Mode | Hook | Use Case |
|------|------|----------|
| `pre_call` | `async_pre_call_hook` | Scan/modify inputs before LLM call |
| `post_call` | `async_post_call_success_hook` | Scan/modify LLM responses before client receives them |

Both modes can be enabled simultaneously for full input + output policy enforcement.

## Debugging

Use LiteLLM's detailed debug mode to see what's actually being sent to the LLM provider (useful for verifying redaction):

```bash
litellm --config integrations/litellm/proxy_config.yaml --detailed_debug
```

## Sources

- [LiteLLM Proxy Guardrails](https://docs.litellm.ai/docs/proxy/guardrails/quick_start)
- [LiteLLM Proxy Configuration](https://docs.litellm.ai/docs/simple_proxy)
- [LiteLLM Supported Providers](https://docs.litellm.ai/docs/providers)
