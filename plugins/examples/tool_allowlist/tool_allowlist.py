# -*- coding: utf-8 -*-
"""Location: ./plugins/examples/tool_allowlist/tool_allowlist.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

Tool Allowlist Plugin - Example demonstrating tool and resource access control.

This plugin shows how to use the Common Message Format's MessageView to implement
allowlist-based access control for tools and resources using URI patterns.
"""

import logging
from typing import Any, List, Optional

from pydantic import BaseModel, Field

from cpex.framework import (
    Plugin,
    PluginConfig,
    PluginContext,
    PluginViolation,
)
from cpex.framework.hooks.message import (
    MessagePayload,
    MessageResult,
)
from cpex.framework.cmf.view import ViewKind

logger = logging.getLogger(__name__)


class ToolAllowlistConfig(BaseModel):
    """Configuration for the Tool Allowlist plugin."""

    # Tool allowlist (glob patterns)
    allowed_tools: List[str] = Field(
        default_factory=list,
        description="Allowed tool URI patterns (e.g., 'tool://*/search', 'tool://mcp/*')",
    )
    blocked_tools: List[str] = Field(
        default_factory=list,
        description="Explicitly blocked tool patterns (checked before allowlist)",
    )

    # Resource allowlist
    allowed_resources: List[str] = Field(
        default_factory=list,
        description="Allowed resource URI patterns (e.g., 'file:///safe/**')",
    )
    blocked_resources: List[str] = Field(
        default_factory=list,
        description="Explicitly blocked resource patterns",
    )

    # Prompt allowlist
    allowed_prompts: List[str] = Field(
        default_factory=list,
        description="Allowed prompt URI patterns",
    )

    # Behavior
    default_allow_tools: bool = Field(
        default=False,
        description="Allow tools not matching any pattern (less secure)",
    )
    default_allow_resources: bool = Field(
        default=False,
        description="Allow resources not matching any pattern",
    )
    default_allow_prompts: bool = Field(
        default=True,
        description="Allow prompts not matching any pattern",
    )
    log_decisions: bool = Field(
        default=True,
        description="Log allow/deny decisions",
    )


class ToolAllowlistPlugin(Plugin):
    """Tool and resource allowlist using CMF MessageView.

    This plugin demonstrates how to:
    1. Use MessageView.uri for tool/resource identification
    2. Use matches_uri_pattern() for glob matching
    3. Use ViewKind to differentiate tools, resources, prompts
    """

    def __init__(self, config: PluginConfig):
        """Initialize the plugin."""
        super().__init__(config)
        self.allowlist_config = ToolAllowlistConfig.model_validate(self._config.config)

        logger.info(
            f"ToolAllowlistPlugin initialized: "
            f"{len(self.allowlist_config.allowed_tools)} tool patterns, "
            f"{len(self.allowlist_config.allowed_resources)} resource patterns"
        )

    def _check_patterns(
        self,
        uri: str,
        view: Any,
        allowed: List[str],
        blocked: List[str],
        default_allow: bool,
    ) -> tuple[bool, Optional[str]]:
        """Check URI against allowed/blocked patterns.

        Args:
            uri: The URI to check.
            view: The MessageView for pattern matching.
            allowed: List of allowed patterns.
            blocked: List of blocked patterns.
            default_allow: Default decision if no patterns match.

        Returns:
            Tuple of (is_allowed, matching_pattern).
        """
        # Check blocked patterns first
        for pattern in blocked:
            if view.matches_uri_pattern(pattern):
                return (False, pattern)

        # Check allowed patterns
        for pattern in allowed:
            if view.matches_uri_pattern(pattern):
                return (True, pattern)

        # No pattern matched - use default
        return (default_allow, None)

    async def evaluate(
        self, payload: MessagePayload, context: PluginContext
    ) -> MessageResult:
        """Evaluate a message for tool/resource access control.

        Uses MessageView to get URIs for tools, resources, and prompts,
        match against allowlist patterns, and make access decisions.

        Args:
            payload: The CMF MessagePayload to evaluate.
            context: Plugin execution context.

        Returns:
            MessageResult with potential violation if access denied.
        """
        views = list(payload.message.iter_views())

        for view in views:
            uri = view.uri
            if not uri:
                continue

            # Check tool calls
            if view.kind == ViewKind.TOOL_CALL:
                allowed, pattern = self._check_patterns(
                    uri,
                    view,
                    self.allowlist_config.allowed_tools,
                    self.allowlist_config.blocked_tools,
                    self.allowlist_config.default_allow_tools,
                )

                if self.allowlist_config.log_decisions:
                    action = "ALLOWED" if allowed else "BLOCKED"
                    match_info = f" (matched: {pattern})" if pattern else " (no match, default)"
                    logger.info(f"Tool {action}: {uri}{match_info}")

                if not allowed:
                    violation = PluginViolation(
                        reason="Tool not allowed",
                        description=f"Tool '{view.name}' is not in the allowlist",
                        code="TOOL_NOT_ALLOWED",
                        details={
                            "uri": uri,
                            "tool_name": view.name,
                            "action": view.action.value if view.action else None,
                            "matched_pattern": pattern,
                        },
                    )
                    return MessageResult(continue_processing=False, violation=violation)

            # Check resource access
            elif view.kind in (ViewKind.RESOURCE, ViewKind.RESOURCE_REF):
                allowed, pattern = self._check_patterns(
                    uri,
                    view,
                    self.allowlist_config.allowed_resources,
                    self.allowlist_config.blocked_resources,
                    self.allowlist_config.default_allow_resources,
                )

                if self.allowlist_config.log_decisions:
                    action = "ALLOWED" if allowed else "BLOCKED"
                    match_info = f" (matched: {pattern})" if pattern else " (no match, default)"
                    logger.info(f"Resource {action}: {uri}{match_info}")

                if not allowed:
                    violation = PluginViolation(
                        reason="Resource not allowed",
                        description=f"Resource '{uri}' is not in the allowlist",
                        code="RESOURCE_NOT_ALLOWED",
                        details={
                            "uri": uri,
                            "resource_name": view.name,
                            "action": view.action.value if view.action else None,
                            "matched_pattern": pattern,
                        },
                    )
                    return MessageResult(continue_processing=False, violation=violation)

            # Check prompt requests
            elif view.kind == ViewKind.PROMPT_REQUEST:
                allowed, pattern = self._check_patterns(
                    uri,
                    view,
                    self.allowlist_config.allowed_prompts,
                    [],  # No blocked prompts by default
                    self.allowlist_config.default_allow_prompts,
                )

                if self.allowlist_config.log_decisions:
                    action = "ALLOWED" if allowed else "BLOCKED"
                    match_info = f" (matched: {pattern})" if pattern else " (no match, default)"
                    logger.info(f"Prompt {action}: {uri}{match_info}")

                if not allowed:
                    violation = PluginViolation(
                        reason="Prompt not allowed",
                        description=f"Prompt '{view.name}' is not in the allowlist",
                        code="PROMPT_NOT_ALLOWED",
                        details={
                            "uri": uri,
                            "prompt_name": view.name,
                            "matched_pattern": pattern,
                        },
                    )
                    return MessageResult(continue_processing=False, violation=violation)

        return MessageResult()

    async def shutdown(self) -> None:
        """Cleanup when plugin shuts down."""
        logger.info("ToolAllowlistPlugin shutting down")
