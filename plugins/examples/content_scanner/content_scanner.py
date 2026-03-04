# -*- coding: utf-8 -*-
"""Location: ./plugins/examples/content_scanner/content_scanner.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

Content Scanner Plugin - Example demonstrating content scanning using CMF MessageView.

This plugin shows how to use the Common Message Format's MessageView to scan
message content for sensitive patterns like PII, secrets, or prohibited content.
"""

import logging
import re
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from cpex.framework import (
    Plugin,
    PluginConfig,
    PluginContext,
    PluginViolation,
)
from cpex.framework.hooks.message import (
    MessageHookType,
    MessagePayload,
    MessageResult,
)
from cpex.framework.cmf.message import ContentType, TextContent
from cpex.framework.cmf.view import ViewKind

logger = logging.getLogger(__name__)


class ScanPattern(BaseModel):
    """A pattern to scan for in content."""

    name: str = Field(description="Pattern name for reporting")
    pattern: str = Field(description="Regex pattern to match")
    severity: str = Field(default="medium", description="Severity: low, medium, high, critical")
    block: bool = Field(default=False, description="Block message if pattern found")
    redact: bool = Field(default=False, description="Redact (replace) matched content instead of blocking")
    redact_replacement: str = Field(default="[REDACTED]", description="Replacement text for redaction")
    scan_pre: bool = Field(default=True, description="Scan input messages (pre)")
    scan_post: bool = Field(default=True, description="Scan output messages (post)")
    view_kinds: List[str] = Field(
        default_factory=lambda: ["text", "tool_call", "tool_result"],
        description="ViewKinds to scan",
    )


class ContentScannerConfig(BaseModel):
    """Configuration for the Content Scanner plugin."""

    patterns: List[ScanPattern] = Field(
        default_factory=list,
        description="Patterns to scan for",
    )
    log_matches: bool = Field(
        default=True,
        description="Log pattern matches",
    )
    include_match_in_metadata: bool = Field(
        default=False,
        description="Include matched text in metadata (caution: may log sensitive data)",
    )


# Default patterns for common sensitive data
DEFAULT_PATTERNS = [
    ScanPattern(
        name="ssn",
        pattern=r"\b\d{3}-\d{2}-\d{4}\b",
        severity="critical",
        block=True,
    ),
    ScanPattern(
        name="credit_card",
        pattern=r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        severity="critical",
        block=True,
    ),
    ScanPattern(
        name="email",
        pattern=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        severity="medium",
        block=False,
    ),
    ScanPattern(
        name="api_key",
        pattern=r'\b(?:api[_-]?key|apikey|api_token)[:\s]+[\'"]?[A-Za-z0-9\-_]{20,}[\'"]?\b',
        severity="high",
        block=True,
    ),
    ScanPattern(
        name="aws_key",
        pattern=r"\bAKIA[0-9A-Z]{16}\b",
        severity="critical",
        block=True,
    ),
]


class ContentScannerPlugin(Plugin):
    """Content scanning using CMF MessageView.

    This plugin demonstrates how to:
    1. Use MessageView.content to access text for scanning
    2. Use is_pre/is_post to differentiate input vs output
    3. Filter by ViewKind (text, tool_call, tool_result, etc.)
    4. Report findings with severity levels
    """

    def __init__(self, config: PluginConfig):
        """Initialize the plugin."""
        super().__init__(config)
        self.scanner_config = ContentScannerConfig.model_validate(self._config.config)

        # Use default patterns if none configured
        if not self.scanner_config.patterns:
            self.scanner_config.patterns = DEFAULT_PATTERNS

        # Compile regex patterns
        self.compiled_patterns: List[tuple[ScanPattern, re.Pattern]] = []
        for pattern in self.scanner_config.patterns:
            try:
                compiled = re.compile(pattern.pattern, re.IGNORECASE)
                self.compiled_patterns.append((pattern, compiled))
            except re.error as e:
                logger.error(f"Invalid regex pattern '{pattern.name}': {e}")

        logger.info(
            f"ContentScannerPlugin initialized with {len(self.compiled_patterns)} patterns"
        )

    def _should_scan_view(self, view: Any, pattern: ScanPattern) -> bool:
        """Check if we should scan this view with this pattern."""
        if view.is_pre and not pattern.scan_pre:
            return False
        if view.is_post and not pattern.scan_post:
            return False

        if pattern.view_kinds:
            view_kind_str = view.kind.value
            if view_kind_str not in pattern.view_kinds:
                return False

        return True

    async def evaluate(
        self, payload: MessagePayload, context: PluginContext
    ) -> MessageResult:
        """Evaluate a message by scanning content for sensitive patterns.

        Uses MessageView to access content, check direction, and filter by kind.

        Args:
            payload: The CMF MessagePayload to evaluate.
            context: Plugin execution context.

        Returns:
            MessageResult with potential violation if blocking pattern found,
            or modified_payload if redaction was performed.
        """
        findings: List[Dict[str, Any]] = []
        blocking_finding: Optional[Dict[str, Any]] = None
        redactions: Dict[int, str] = {}  # part index -> redacted content

        # Get views from the message
        views = list(payload.message.iter_views())

        for view_idx, view in enumerate(views):
            # Get content to scan
            content = view.content
            if not content:
                continue

            # Track if this view's content needs redaction
            redacted_content = content

            # Check each pattern
            for pattern, compiled in self.compiled_patterns:
                if not self._should_scan_view(view, pattern):
                    continue

                # Scan for matches
                matches = compiled.findall(redacted_content)
                if matches:
                    finding = {
                        "pattern_name": pattern.name,
                        "severity": pattern.severity,
                        "view_kind": view.kind.value,
                        "is_pre": view.is_pre,
                        "match_count": len(matches),
                        "action": "redact" if pattern.redact else ("block" if pattern.block else "log"),
                    }

                    if self.scanner_config.include_match_in_metadata:
                        finding["matches"] = matches[:5]

                    findings.append(finding)

                    if self.scanner_config.log_matches:
                        phase = "input" if view.is_pre else "output"
                        action = "redacting" if pattern.redact else ("blocking" if pattern.block else "logging")
                        logger.warning(
                            f"Pattern '{pattern.name}' ({pattern.severity}) found in {phase} "
                            f"{view.kind.value}: {len(matches)} match(es) - {action}"
                        )

                    # Handle redaction (takes priority over blocking)
                    if pattern.redact:
                        redacted_content = compiled.sub(pattern.redact_replacement, redacted_content)
                    elif pattern.block and blocking_finding is None:
                        blocking_finding = finding

            # Track redactions by view index (same as part index)
            if redacted_content != content:
                redactions[view_idx] = redacted_content

        # Store findings in metadata
        if findings:
            context.metadata["content_scan_findings"] = findings
            context.metadata["content_scan_blocked"] = blocking_finding is not None
            context.metadata["content_scan_redacted"] = len(redactions) > 0

        # If redactions were made, build a new frozen payload via model_copy
        if redactions:
            logger.info("Content redacted - returning modified message")
            new_parts = list(payload.message.content)
            for part_idx, redacted_text in redactions.items():
                part = new_parts[part_idx]
                if part.content_type == ContentType.TEXT:
                    new_parts[part_idx] = TextContent(text=redacted_text)
                elif part.content_type == ContentType.TOOL_RESULT:
                    new_result = part.content.model_copy(update={"content": redacted_text})
                    new_parts[part_idx] = part.model_copy(update={"content": new_result})

            new_message = payload.message.model_copy(update={"content": new_parts})
            modified_payload = payload.model_copy(update={"message": new_message})
            return MessageResult(modified_payload=modified_payload)

        # If we have a blocking finding (and no redaction), return violation
        if blocking_finding:
            violation = PluginViolation(
                reason=f"Sensitive content detected: {blocking_finding['pattern_name']}",
                description=f"Found {blocking_finding['severity']} severity pattern "
                            f"'{blocking_finding['pattern_name']}' in message content",
                code="SENSITIVE_CONTENT_DETECTED",
                details={
                    "pattern": blocking_finding["pattern_name"],
                    "severity": blocking_finding["severity"],
                    "view_kind": blocking_finding["view_kind"],
                    "match_count": blocking_finding["match_count"],
                },
            )
            return MessageResult(continue_processing=False, violation=violation)

        return MessageResult()

    async def shutdown(self) -> None:
        """Cleanup when plugin shuts down."""
        logger.info("ContentScannerPlugin shutting down")
