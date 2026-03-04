# -*- coding: utf-8 -*-
"""Location: ./integrations/litellm/cmf_guardrail.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

CMF Guardrail wrapper for LiteLLM Proxy.

This file provides a simple entry point for LiteLLM's guardrail system,
which expects a `file.ClassName` format.

Usage in proxy_config.yaml:
    guardrails:
      - guardrail_name: "cmf-policy"
        litellm_params:
          guardrail: cmf_guardrail.CMFGuardrail
          mode: "pre_call"
"""

# Standard
import os
import sys

# Ensure project root is in path (go up from integrations/litellm/ to project root)
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# First-Party
from integrations.litellm.proxy_handler import CMFProxyHandler


class CMFGuardrail(CMFProxyHandler):
    """CMF Guardrail with default configuration.

    LiteLLM instantiates guardrails without arguments, so we provide defaults.
    """

    def __init__(self, **kwargs):
        config_path = os.environ.get(
            "CMF_PLUGIN_CONFIG",
            os.path.join(project_root, "plugins", "examples", "plugin_config.yaml")
        )
        super().__init__(
            config_path=config_path,
            log_decisions=True,
            fail_open=False,
            **kwargs,
        )


__all__ = ["CMFGuardrail"]
