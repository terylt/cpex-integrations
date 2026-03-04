# -*- coding: utf-8 -*-
"""Location: ./plugins/examples/role_guard/role_guard.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

Role Guard Plugin - Example demonstrating role-based access control using CMF MessageView.

This plugin shows how to use the Common Message Format's MessageView to evaluate
principal roles and permissions for access control decisions.
"""

import logging
from typing import List, Set

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


class ToolPermission(BaseModel):
    """Permission requirement for a tool."""

    tool_pattern: str = Field(description="Tool name pattern (supports * wildcard)")
    required_roles: Set[str] = Field(default_factory=set, description="Roles that can access this tool")
    required_permissions: Set[str] = Field(default_factory=set, description="Permissions required")
    denied_environments: Set[str] = Field(default_factory=set, description="Environments where tool is blocked")


class RoleGuardConfig(BaseModel):
    """Configuration for the Role Guard plugin."""

    tool_permissions: List[ToolPermission] = Field(
        default_factory=list,
        description="List of tool permission rules",
    )
    default_allow: bool = Field(
        default=True,
        description="Allow tools not explicitly configured",
    )
    admin_bypass: bool = Field(
        default=True,
        description="Allow admin role to bypass all checks",
    )
    admin_role: str = Field(
        default="admin",
        description="Role name that gets bypass privileges",
    )
    log_decisions: bool = Field(
        default=True,
        description="Log access control decisions",
    )


class RoleGuardPlugin(Plugin):
    """Role-based access control using CMF MessageView.

    This plugin demonstrates how to:
    1. Use MessageView to inspect message content
    2. Access principal roles and permissions via MessageView
    3. Check environment context for conditional rules
    4. Make allow/deny decisions based on RBAC
    """

    def __init__(self, config: PluginConfig):
        """Initialize the plugin."""
        super().__init__(config)
        self.guard_config = RoleGuardConfig.model_validate(self._config.config)
        logger.info(
            f"RoleGuardPlugin initialized with {len(self.guard_config.tool_permissions)} tool rules"
        )

    def _matches_pattern(self, name: str, pattern: str) -> bool:
        """Check if a tool name matches a pattern.

        Args:
            name: The tool name.
            pattern: Pattern with optional * wildcard.

        Returns:
            True if name matches pattern.
        """
        if pattern == "*":
            return True
        if "*" not in pattern:
            return name == pattern
        if pattern.endswith("*"):
            return name.startswith(pattern[:-1])
        if pattern.startswith("*"):
            return name.endswith(pattern[1:])
        return name == pattern

    def _find_matching_rules(self, tool_name: str) -> List[ToolPermission]:
        """Find all permission rules that match a tool name.

        Args:
            tool_name: The tool being called.

        Returns:
            List of matching permission rules.
        """
        matching = []
        for rule in self.guard_config.tool_permissions:
            if self._matches_pattern(tool_name, rule.tool_pattern):
                matching.append(rule)
        return matching

    async def evaluate(
        self, payload: MessagePayload, context: PluginContext
    ) -> MessageResult:
        """Evaluate a message for role-based access control.

        Uses MessageView to iterate over message content, check tool calls
        against RBAC rules, and access principal roles and permissions.

        Args:
            payload: The CMF MessagePayload to evaluate.
            context: Plugin execution context.

        Returns:
            MessageResult with potential violation if access denied.
        """
        views = list(payload.message.iter_views())

        for view in views:
            # Only check tool calls
            if view.kind != ViewKind.TOOL_CALL:
                continue

            tool_name = view.name
            if not tool_name:
                continue

            # Check for admin bypass
            if self.guard_config.admin_bypass:
                if view.has_role(self.guard_config.admin_role):
                    if self.guard_config.log_decisions:
                        logger.info(f"Admin bypass for tool '{tool_name}'")
                    continue

            # Find matching rules
            rules = self._find_matching_rules(tool_name)

            if not rules:
                # No rules match - use default
                if not self.guard_config.default_allow:
                    violation = PluginViolation(
                        reason="Tool not in allowlist",
                        description=f"Tool '{tool_name}' is not explicitly allowed",
                        code="TOOL_NOT_ALLOWED",
                        details={"tool": tool_name},
                    )
                    return MessageResult(continue_processing=False, violation=violation)
                continue

            # Check each matching rule
            for rule in rules:
                # Check environment restrictions
                env = view.environment
                if env and env in rule.denied_environments:
                    if self.guard_config.log_decisions:
                        logger.warning(
                            f"Tool '{tool_name}' blocked in environment '{env}'"
                        )
                    violation = PluginViolation(
                        reason="Tool blocked in this environment",
                        description=f"Tool '{tool_name}' is not allowed in '{env}' environment",
                        code="TOOL_BLOCKED_IN_ENV",
                        details={"tool": tool_name, "environment": env},
                    )
                    return MessageResult(continue_processing=False, violation=violation)

                # Check role requirements
                if rule.required_roles:
                    has_required_role = any(
                        view.has_role(role) for role in rule.required_roles
                    )
                    if not has_required_role:
                        if self.guard_config.log_decisions:
                            logger.warning(
                                f"Tool '{tool_name}' denied - missing required role"
                            )
                        violation = PluginViolation(
                            reason="Insufficient role",
                            description=f"Tool '{tool_name}' requires one of: {rule.required_roles}",
                            code="MISSING_ROLE",
                            details={
                                "tool": tool_name,
                                "required_roles": list(rule.required_roles),
                                "user_roles": list(view.roles),
                            },
                        )
                        return MessageResult(continue_processing=False, violation=violation)

                # Check permission requirements
                if rule.required_permissions:
                    has_required_perm = any(
                        view.has_permission(perm) for perm in rule.required_permissions
                    )
                    if not has_required_perm:
                        if self.guard_config.log_decisions:
                            logger.warning(
                                f"Tool '{tool_name}' denied - missing required permission"
                            )
                        violation = PluginViolation(
                            reason="Insufficient permission",
                            description=f"Tool '{tool_name}' requires one of: {rule.required_permissions}",
                            code="MISSING_PERMISSION",
                            details={
                                "tool": tool_name,
                                "required_permissions": list(rule.required_permissions),
                                "user_permissions": list(view.permissions),
                            },
                        )
                        return MessageResult(continue_processing=False, violation=violation)

            if self.guard_config.log_decisions:
                logger.info(f"Tool '{tool_name}' allowed for principal")

        return MessageResult()

    async def shutdown(self) -> None:
        """Cleanup when plugin shuts down."""
        logger.info("RoleGuardPlugin shutting down")
