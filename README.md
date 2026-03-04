# CMF Policy Integrations

This directory contains integrations between the ContextForge Plugin Extensibility Framework (CPEX) and popular LLM ecosystems. All integrations use the Common Message Format (CMF) for unified policy evaluation.

## Available Integrations

| Integration | Description | Providers |
|-------------|-------------|-----------|
| [LiteLLM](./litellm/) | Universal LLM proxy with guardrail hooks | 100+ (OpenAI, Anthropic, Azure, Bedrock, WatsonX, etc.) |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Your Application                             │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Integration Layer                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │   LiteLLM   │  │  LangGraph  │  │   CrewAI    │  ...        │
│  │  Handler    │  │  Handler    │  │  Handler    │             │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘             │
│         │                │                │                     │
│         └────────────────┼────────────────┘                     │
│                          │                                       │
│                          ▼                                       │
│         ┌─────────────────────────────────────┐                 │
│         │    CMF Converter                     │                 │
│         │  (Framework format → CMF Message)    │                 │
│         └─────────────────┬───────────────────┘                 │
│                           │                                      │
│                           ▼                                      │
│         ┌─────────────────────────────────────┐                 │
│         │    PluginManager                     │                 │
│         │    evaluate hook                     │                 │
│         └─────────────────┬───────────────────┘                 │
│                           │                                      │
│                     Allow / Deny                                 │
└───────────────────────────┼─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                      LLM Providers                               │
│     OpenAI │ Anthropic │ Azure │ AWS │ Google │ WatsonX │ ...   │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

See the [LiteLLM integration README](./litellm/README.md) for a complete walkthrough.

## Common Message Format (CMF)

All integrations convert framework-specific message formats to the unified CMF:

```python
from cpex.framework.cmf.message import (
    Message, Role, ContentType, TextContent, ToolCall
)

# Simple text message
message = Message(
    role=Role.USER,
    content=[TextContent(text="Hello, world!")],
)

# Multimodal content
message = Message(
    role=Role.ASSISTANT,
    content=[
        TextContent(text="Let me search..."),
        ToolCall(name="search", arguments={"q": "test"}),
    ],
)
```

## Policy Plugins

The CMF enables unified policy evaluation across all integrations:

| Plugin | Purpose |
|--------|---------|
| `content_scanner` | Detect PII, secrets, sensitive content; redact or block |
| `tool_allowlist` | Allow/block tools by URI pattern |
| `role_guard` | RBAC for tool access |
| `opa_policy` | External OPA policy evaluation |

See [plugins/examples/](../plugins/examples/) for full source and configuration.

## Adding New Integrations

To add a new integration:

1. Create `integrations/<framework>/` directory
2. Implement a converter (`converter.py`) that maps to CMF `Message` objects
3. Implement a handler that hooks into the framework's callback/middleware system
4. Register plugins via the `PluginManager` and invoke the `evaluate` hook

See `integrations/litellm/` for a complete example.
