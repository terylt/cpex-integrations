# -*- coding: utf-8 -*-
"""LiteLLM integration for ContextForge CMF policy enforcement.

This module provides a custom callback handler that integrates the
ContextForge plugin framework with LiteLLM, enabling policy enforcement
on LLM requests and responses across 100+ providers.

Usage (SDK mode):
    import litellm
    from integrations.litellm import CMFPolicyHandler

    # Initialize the handler
    handler = CMFPolicyHandler("plugins/config.yaml")
    await handler.initialize()

    # Register with LiteLLM
    litellm.callbacks = [handler]

    # Now all LiteLLM calls go through policy evaluation
    response = await litellm.acompletion(
        model="gpt-4",
        messages=[{"role": "user", "content": "Hello"}]
    )

Usage (Proxy mode):
    # In your custom_callbacks.py
    from integrations.litellm import CMFProxyHandler

    handler = CMFProxyHandler("plugins/config.yaml")
    proxy_handler_instance = handler

    # Then in config.yaml:
    # litellm_settings:
    #   callbacks: custom_callbacks.proxy_handler_instance
"""

from .handler import CMFPolicyHandler
from .proxy_handler import CMFProxyHandler
from .converter import LiteLLMToCMFConverter

__all__ = [
    "CMFPolicyHandler",
    "CMFProxyHandler",
    "LiteLLMToCMFConverter",
]
