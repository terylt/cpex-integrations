# Plugin Examples

This directory contains example plugins demonstrating various plugin patterns using the
Common Message Format (CMF) and MessageView for policy evaluation.

## Plugins

### content_scanner

Content scanning for sensitive patterns using MessageView's content accessor.

**Demonstrates:**
- Using `view.content` to get scannable text
- Filtering by `view.is_pre` / `view.is_post`
- Filtering by `view.kind` (text, tool_call, tool_result)
- Pattern-based scanning with severity levels
- Redaction via immutable `model_copy` pattern

**Use Case:** Detect PII, secrets, API keys in messages before/after LLM processing.

```yaml
patterns:
  - name: "ssn"
    pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
    severity: "critical"
    block: true
    scan_pre: true
    scan_post: true
  - name: "email"
    severity: "medium"
    redact: true
    redact_replacement: "[EMAIL REDACTED]"
```

### role_guard

Role-based access control using MessageView's principal accessors.

**Demonstrates:**
- Accessing `view.roles` and `view.permissions`
- Using `view.has_role()` and `view.has_permission()`
- Checking `view.environment` for environment-specific rules
- Tool-level RBAC with patterns

**Use Case:** Restrict dangerous tools to admin users, block tools in production.

```yaml
tool_permissions:
  - tool_pattern: "dangerous_*"
    required_roles: ["admin", "security"]
    denied_environments: ["production"]
```

### tool_allowlist

URI-based access control using MessageView's URI matching.

**Demonstrates:**
- Using `view.uri` to get tool/resource URIs
- Using `view.matches_uri_pattern()` for glob matching
- Filtering by `view.kind` (TOOL_CALL, RESOURCE, PROMPT_REQUEST)
- Using `view.action` to understand operation type

**Use Case:** Allowlist safe tools, block access to sensitive files.

```yaml
allowed_tools:
  - "tool://*/search"
  - "tool://mcp/**"
blocked_resources:
  - "file:///etc/**"
  - "file:///**/.env"
```

### opa_policy

External policy evaluation using OPA (Open Policy Agent).

**Demonstrates:**
- Using `view.to_opa_input()` for OPA-compatible format
- Sending policy requests to OPA server
- Handling OPA responses with deny reasons

**Use Case:** Externalize policy decisions to OPA for complex rules.

Includes `example_policy.rego` with sample Rego rules:
```rego
package apex

# Allow read-only tools
allow {
    input.kind == "tool_call"
    startswith(input.name, "read_")
}

# Deny dangerous tools
deny[msg] {
    input.kind == "tool_call"
    input.name == "execute_shell"
    msg := "Shell execution is not allowed"
}
```

## Writing a Plugin

Plugins use the `evaluate` hook which receives a CMF `MessagePayload`:

```python
from cpex.framework import Plugin, PluginConfig, PluginContext, PluginViolation
from cpex.framework.hooks.message import MessagePayload, MessageResult
from cpex.framework.cmf.view import ViewKind

class MyPlugin(Plugin):
    async def evaluate(
        self, payload: MessagePayload, context: PluginContext
    ) -> MessageResult:
        # Get views from the message
        for view in payload.message.iter_views():
            # Check view type
            if view.kind == ViewKind.TOOL_CALL:
                print(f"Tool: {view.name}, URI: {view.uri}")

            # Check content
            if view.content and "secret" in view.content:
                return MessageResult(
                    continue_processing=False,
                    violation=PluginViolation(
                        reason="Secret detected",
                        code="SECRET_DETECTED",
                    )
                )

        return MessageResult()
```

## MessageView Properties

| Property | Description |
|----------|-------------|
| `view.kind` | ViewKind enum (TEXT, TOOL_CALL, RESOURCE, etc.) |
| `view.content` | Text content for scanning |
| `view.uri` | URI for tools, resources, prompts |
| `view.name` | Human-readable name |
| `view.is_pre` | True if input/request content |
| `view.is_post` | True if output/response content |
| `view.role` | Message role (USER, ASSISTANT, etc.) |
| `view.roles` | Principal's roles |
| `view.permissions` | Principal's permissions |
| `view.environment` | Execution environment |
| `view.headers` | HTTP headers |
| `view.labels` | Data classification labels |

## Serialization for External Policy Engines

MessageView can be serialized to JSON for external policy engines like OPA:

```python
# Single view to JSON dict
view_dict = view.to_dict()

# Single view in OPA format
opa_input = view.to_opa_input()
# {"input": {"kind": "tool_call", "name": "search", ...}}
```

The `to_dict()` output includes:
- `kind`, `is_pre`, `is_post`, `role`
- `uri`, `name`, `action`
- `content`, `size_bytes`, `mime_type`
- `arguments` (for tool calls)
- `properties` (type-specific)
- `context` (principal, environment, labels, headers)
