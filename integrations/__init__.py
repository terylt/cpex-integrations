# -*- coding: utf-8 -*-
"""ContextForge CMF Integrations.

This package provides integrations between the ContextForge CMF (Common Message Format)
policy framework and popular LLM providers, agentic frameworks, and proxies.

Available Integrations:
    - litellm: LiteLLM integration for 100+ LLM providers

Usage:
    from integrations.litellm import CMFPolicyHandler

    handler = CMFPolicyHandler("plugins/config.yaml")
    await handler.initialize()

    import litellm
    litellm.callbacks = [handler]
"""

__all__ = ["litellm"]
