# -*- coding: utf-8 -*-
"""Location: ./integrations/litellm/proxy_handler.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

CMF Policy Handler for LiteLLM Proxy.

This module provides a proxy-compatible handler that integrates the
ContextForge plugin framework with LiteLLM Proxy's hook system.

Usage:
    # custom_callbacks.py
    from integrations.litellm import CMFProxyHandler

    handler = CMFProxyHandler("plugins/config.yaml")
    proxy_handler_instance = handler

    # config.yaml
    litellm_settings:
      callbacks: custom_callbacks.proxy_handler_instance
"""

# Standard
import asyncio
import logging
from datetime import datetime
from typing import Any, AsyncGenerator, Dict, Literal, Optional

# Third-Party
from litellm.integrations.custom_guardrail import CustomGuardrail

# First-Party
from cpex.framework import GlobalContext, PluginManager
from cpex.framework.cmf.message import ContentType, Message, TextContent
from cpex.framework.hooks.message import MessageHookType, MessagePayload

from .converter import LiteLLMToCMFConverter

logger = logging.getLogger(__name__)


class CMFProxyHandler(CustomGuardrail):
    """LiteLLM Proxy handler with CMF policy enforcement.

    This handler inherits from CustomGuardrail to integrate with LiteLLM's
    guardrail system and evaluate requests/responses against the ContextForge
    plugin framework.

    The proxy handler supports:
    - async_pre_call_hook: Modify/reject requests before LLM call
    - async_moderation_hook: Parallel moderation (can reject)
    - async_post_call_success_hook: Process successful responses
    - async_post_call_failure_hook: Transform error responses
    """

    def __init__(
        self,
        config_path: str,
        log_decisions: bool = True,
        fail_open: bool = False,
        **kwargs,
    ):
        """Initialize the CMF proxy handler.

        Args:
            config_path: Path to plugin configuration YAML.
            log_decisions: Log policy decisions.
            fail_open: Allow requests if plugin manager fails.
            **kwargs: Passed through to CustomGuardrail (guardrail_name, event_hook, default_on, etc.).
        """
        # Default to on if LiteLLM doesn't explicitly set default_on
        if not kwargs.get("default_on"):
            kwargs["default_on"] = True
        super().__init__(**kwargs)
        self.config_path = config_path
        self.log_decisions = log_decisions
        self.fail_open = fail_open

        self._manager: Optional[PluginManager] = None
        self._initialized = False
        self._init_lock = asyncio.Lock()
        self._request_counter = 0

    async def _ensure_initialized(self) -> bool:
        """Ensure plugin manager is initialized (lazy init)."""
        if self._initialized:
            return True

        async with self._init_lock:
            if self._initialized:
                return True

            try:
                PluginManager.reset()
                self._manager = PluginManager(self.config_path)
                await self._manager.initialize()
                self._initialized = True
                logger.info(
                    f"CMFProxyHandler initialized with {self._manager.plugin_count} plugins"
                )
                return True
            except Exception as e:
                logger.error(f"Failed to initialize CMFProxyHandler: {e}")
                if self.fail_open:
                    return False
                raise

    def _get_request_id(self) -> str:
        """Generate a unique request ID."""
        self._request_counter += 1
        return f"proxy-{self._request_counter}-{datetime.now().strftime('%H%M%S%f')}"

    def _create_global_context(
        self,
        data: Dict[str, Any],
        user_api_key_dict: Any,
        request_id: str,
    ) -> GlobalContext:
        """Create GlobalContext from request data.

        Args:
            data: Request data dict.
            user_api_key_dict: User authentication info from LiteLLM.
            request_id: Unique request identifier.

        Returns:
            GlobalContext for plugin execution.
        """
        user = None
        if user_api_key_dict:
            user = getattr(user_api_key_dict, "user_id", None) or "anonymous"

        return GlobalContext(
            request_id=request_id,
            user=user,
            metadata={
                "model": data.get("model", "unknown"),
                "provider": "litellm-proxy",
                "call_type": data.get("call_type", "completion"),
            },
        )

    async def _evaluate_messages(
        self,
        messages: list[Message],
        global_context: GlobalContext,
    ) -> tuple[bool, Optional[Dict], list[Message]]:
        """Evaluate messages through plugin framework.

        Returns:
            Tuple of (allowed, violation_info, potentially_modified_messages).
        """
        modified_messages = []
        any_modified = False

        for i, message in enumerate(messages):
            payload = MessagePayload(message=message)
            result, _ = await self._manager.invoke_hook(
                hook_type=MessageHookType.EVALUATE.value,
                payload=payload,
                global_context=global_context,
            )

            if not result.continue_processing:
                violation = {
                    "message_index": i,
                    "role": message.role.value,
                    "reason": result.violation.reason if result.violation else "Policy denied",
                    "code": result.violation.code if result.violation else "POLICY_DENIED",
                    "details": result.violation.details if result.violation else {},
                }

                if self.log_decisions:
                    logger.warning(
                        f"Message {i} blocked: {violation['reason']} ({violation['code']})"
                    )

                return False, violation, messages

            # Check for modifications
            if result.modified_payload is not None:
                modified_messages.append(result.modified_payload.message)
                any_modified = True
                if self.log_decisions:
                    logger.info(f"Message {i} modified by plugin")
            else:
                modified_messages.append(message)

        return True, None, (modified_messages if any_modified else messages)

    # =========================================================================
    # LiteLLM Proxy Hook Interface
    # =========================================================================

    async def async_pre_call_hook(
        self,
        user_api_key_dict: Any,
        cache: Any,
        data: Dict[str, Any],
        call_type: Literal[
            "completion", "text_completion", "embeddings",
            "image_generation", "moderation", "audio_transcription"
        ],
    ) -> Optional[Dict]:
        """Hook called before LLM API call.

        Can modify the request data or raise HTTPException to reject.

        Args:
            user_api_key_dict: User authentication info.
            cache: LiteLLM cache object.
            data: Request data (can be modified).
            call_type: Type of LLM call.

        Returns:
            Modified data dict, or None to use original.

        Raises:
            HTTPException: To reject the request.
        """
        if not await self._ensure_initialized():
            if self.fail_open:
                return data
            from fastapi import HTTPException
            raise HTTPException(status_code=503, detail="Policy engine unavailable")

        request_id = self._get_request_id()
        data["_cmf_request_id"] = request_id

        if self.log_decisions:
            logger.info(
                f"[{request_id}] Pre-call: model={data.get('model')}, "
                f"call_type={call_type}"
            )

        # Only process completion calls with messages
        if call_type not in ("completion", "text_completion", "acompletion"):
            return data

        messages = data.get("messages", [])
        if not messages:
            return data

        # Convert to CMF
        cmf_messages = LiteLLMToCMFConverter.litellm_messages_to_cmf(messages)

        # Create context
        global_context = self._create_global_context(data, user_api_key_dict, request_id)

        # Evaluate (may modify messages)
        allowed, violation, modified_cmf = await self._evaluate_messages(cmf_messages, global_context)

        if not allowed:
            from fastapi import HTTPException
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "policy_violation",
                    "reason": violation["reason"],
                    "code": violation["code"],
                    "details": violation.get("details", {}),
                },
            )

        # If messages were modified, convert back and update data
        if modified_cmf is not cmf_messages:
            modified_litellm = LiteLLMToCMFConverter.cmf_messages_to_litellm(modified_cmf)
            data["messages"] = modified_litellm
            if self.log_decisions:
                logger.info(f"[{request_id}] Returning modified messages")

        return data

    async def async_moderation_hook(
        self,
        data: Dict[str, Any],
        user_api_key_dict: Any = None,
        call_type: Literal[
            "completion", "embeddings", "image_generation",
            "moderation", "audio_transcription"
        ] = None,
    ) -> None:
        """Hook called in parallel with LLM call for moderation.

        Raise HTTPException to reject the request.

        Args:
            data: Request data.
            user_api_key_dict: User authentication info.
            call_type: Type of LLM call.

        Raises:
            HTTPException: To reject the request.
        """
        # Moderation is handled in pre_call_hook
        pass

    async def async_post_call_success_hook(
        self,
        data: Dict[str, Any],
        user_api_key_dict: Any,
        response: Any,
    ) -> Optional[Any]:
        """Hook called after successful LLM response.

        Can modify the response or block it by raising HTTPException.

        Args:
            data: Original request data.
            user_api_key_dict: User authentication info.
            response: LLM response object.

        Returns:
            Modified response object, or None to use original.

        Raises:
            HTTPException: To block the response from reaching client.
        """
        if not await self._ensure_initialized():
            if self.fail_open:
                return None
            from fastapi import HTTPException
            raise HTTPException(status_code=503, detail="Policy engine unavailable")

        request_id = data.get("_cmf_request_id", self._get_request_id())

        if self.log_decisions:
            logger.info(f"[{request_id}] Post-call success check")

        try:
            # Convert response to CMF
            cmf_response = LiteLLMToCMFConverter.litellm_response_to_cmf(response)

            # Create context
            global_context = self._create_global_context(data, user_api_key_dict, request_id)

            # Evaluate (may return modified message)
            allowed, violation, modified_messages = await self._evaluate_messages(
                [cmf_response], global_context
            )

            if not allowed:
                if self.log_decisions:
                    logger.warning(
                        f"[{request_id}] Response blocked: {violation['reason']}"
                    )
                from fastapi import HTTPException
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "response_policy_violation",
                        "reason": violation["reason"],
                        "code": violation["code"],
                        "message": "Response blocked by policy - potential data leakage detected",
                    },
                )

            # Check if response was modified (e.g., redacted)
            if modified_messages and modified_messages[0] is not cmf_response:
                modified_cmf = modified_messages[0]
                # Extract text content from the modified CMF message
                modified_content = None
                for part in modified_cmf.content:
                    if part.content_type == ContentType.TEXT:
                        modified_content = part.text
                        break

                if modified_content is not None and hasattr(response, 'choices'):
                    response.choices[0].message.content = modified_content
                    if self.log_decisions:
                        logger.info(f"[{request_id}] Response modified by policy")
                    return response

            return None  # No modification, use original

        except Exception as e:
            if "HTTPException" in type(e).__name__:
                raise
            logger.warning(f"[{request_id}] Post-call evaluation failed: {e}")
            return None

    async def async_post_call_failure_hook(
        self,
        request_data: Dict[str, Any],
        original_exception: Exception,
        user_api_key_dict: Any,
        traceback_str: Optional[str] = None,
    ) -> Optional[Any]:
        """Hook called after failed LLM call.

        Args:
            request_data: Original request data.
            original_exception: The exception that occurred.
            user_api_key_dict: User authentication info.
            traceback_str: Optional traceback string.

        Returns:
            HTTPException to transform error, or None for original.
        """
        request_id = request_data.get("_cmf_request_id", "unknown")

        if self.log_decisions:
            logger.info(f"[{request_id}] Post-call failure: {original_exception}")

        return None

    async def async_post_call_streaming_hook(
        self,
        user_api_key_dict: Any,
        response: str,
    ) -> None:
        """Hook called for streaming response chunks.

        Args:
            user_api_key_dict: User authentication info.
            response: Streaming response chunk.
        """
        pass

    async def async_post_call_streaming_iterator_hook(
        self,
        user_api_key_dict: Any,
        response: Any,
        request_data: Dict[str, Any],
    ) -> AsyncGenerator:
        """Hook to wrap streaming response iterator.

        Args:
            user_api_key_dict: User authentication info.
            response: Original async generator.
            request_data: Original request data.

        Yields:
            Streaming response chunks.
        """
        async for chunk in response:
            yield chunk

    async def shutdown(self) -> None:
        """Shutdown the plugin manager."""
        if self._manager:
            await self._manager.shutdown()
            self._initialized = False
