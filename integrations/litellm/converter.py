# -*- coding: utf-8 -*-
"""Location: ./integrations/litellm/converter.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

LiteLLM to CMF Message Converter.

Converts between LiteLLM's message format (OpenAI-compatible) and the
CMF unified message format for policy evaluation.

LiteLLM uses OpenAI's message format:
    {"role": "user", "content": "Hello"}
    {"role": "assistant", "content": "Hi there!", "tool_calls": [...]}
    {"role": "tool", "tool_call_id": "...", "content": "result"}

CMF uses:
    Message(role=Role.USER, content=[TextContent(text="Hello")])
    Message(role=Role.ASSISTANT, content=[ToolCallContentPart(content=ToolCall(...))])
"""

# Standard
import json
import logging
from typing import Any, Dict, List

# First-Party
from cpex.framework.cmf.message import (
    Channel,
    ContentType,
    ImageContentPart,
    ImageSource,
    Message,
    Role,
    TextContent,
    ToolCall,
    ToolCallContentPart,
    ToolResult,
    ToolResultContentPart,
)

logger = logging.getLogger(__name__)


class LiteLLMToCMFConverter:
    """Converts between LiteLLM and CMF message formats."""

    # Role mapping from LiteLLM/OpenAI to CMF
    ROLE_MAP = {
        "system": Role.SYSTEM,
        "user": Role.USER,
        "assistant": Role.ASSISTANT,
        "tool": Role.TOOL,
        "function": Role.TOOL,  # Legacy OpenAI function calling
        "developer": Role.DEVELOPER,
    }

    # Reverse mapping
    CMF_TO_LITELLM_ROLE = {
        Role.SYSTEM: "system",
        Role.USER: "user",
        Role.ASSISTANT: "assistant",
        Role.TOOL: "tool",
        Role.DEVELOPER: "system",  # Map developer to system for compatibility
    }

    @classmethod
    def litellm_message_to_cmf(
        cls,
        message: Dict[str, Any],
        is_response: bool = False,
    ) -> Message:
        """Convert a single LiteLLM message to CMF Message.

        Args:
            message: LiteLLM/OpenAI format message dict.
            is_response: True if this is a response message (affects channel).

        Returns:
            CMF Message object.
        """
        role_str = message.get("role", "user").lower()
        role = cls.ROLE_MAP.get(role_str, Role.USER)

        content = message.get("content")
        tool_calls = message.get("tool_calls", [])
        tool_call_id = message.get("tool_call_id")
        name = message.get("name")  # For tool results

        # Determine channel based on context
        channel = Channel.FINAL if is_response else None

        # Build content parts
        parts = []

        # Handle text content
        if isinstance(content, str) and content:
            parts.append(TextContent(text=content))
        elif isinstance(content, list):
            # Multimodal content (OpenAI vision format)
            for item in content:
                if isinstance(item, dict):
                    item_type = item.get("type", "text")
                    if item_type == "text":
                        parts.append(TextContent(text=item.get("text", "")))
                    elif item_type == "image_url":
                        image_url = item.get("image_url", {})
                        url = image_url.get("url", "") if isinstance(image_url, dict) else str(image_url)

                        # Determine if base64 or URL
                        if url.startswith("data:"):
                            parts.append(ImageContentPart(
                                content=ImageSource(
                                    type="base64",
                                    data=url.split(",", 1)[-1] if "," in url else url,
                                    media_type=url.split(";")[0].split(":")[1] if ";" in url else None,
                                ),
                            ))
                        else:
                            parts.append(ImageContentPart(
                                content=ImageSource(type="url", data=url),
                            ))

        # Handle tool calls (assistant requesting tool execution)
        for tc in tool_calls:
            tc_id = tc.get("id", "")
            tc_function = tc.get("function", {})
            tc_name = tc_function.get("name", "")
            tc_args_str = tc_function.get("arguments", "{}")

            # Parse arguments
            try:
                tc_args = json.loads(tc_args_str) if isinstance(tc_args_str, str) else tc_args_str
            except json.JSONDecodeError:
                tc_args = {"_raw": tc_args_str}

            parts.append(ToolCallContentPart(
                content=ToolCall(
                    tool_call_id=tc_id,
                    name=tc_name,
                    arguments=tc_args,
                ),
            ))

        # Handle tool result (tool role with tool_call_id)
        if role == Role.TOOL and tool_call_id:
            result_content = content if isinstance(content, str) else json.dumps(content) if content else ""
            parts.append(ToolResultContentPart(
                content=ToolResult(
                    tool_call_id=tool_call_id,
                    tool_name=name or "",
                    content=result_content,
                    is_error=False,
                ),
            ))

        # If no parts were created, add empty text
        if not parts:
            parts.append(TextContent(text=""))

        return Message(role=role, content=parts, channel=channel)

    @classmethod
    def litellm_messages_to_cmf(
        cls,
        messages: List[Dict[str, Any]],
    ) -> List[Message]:
        """Convert a list of LiteLLM messages to CMF Messages.

        Args:
            messages: List of LiteLLM/OpenAI format message dicts.

        Returns:
            List of CMF Message objects.
        """
        return [cls.litellm_message_to_cmf(m) for m in messages]

    @classmethod
    def litellm_response_to_cmf(
        cls,
        response: Any,
    ) -> Message:
        """Convert a LiteLLM response to CMF Message.

        Args:
            response: LiteLLM ModelResponse object.

        Returns:
            CMF Message object representing the response.
        """
        if hasattr(response, "choices") and response.choices:
            choice = response.choices[0]
            if hasattr(choice, "message"):
                msg = choice.message
                msg_dict = {
                    "role": getattr(msg, "role", "assistant"),
                    "content": getattr(msg, "content", None),
                }
                if hasattr(msg, "tool_calls") and msg.tool_calls:
                    msg_dict["tool_calls"] = [
                        {
                            "id": tc.id,
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments,
                            }
                        }
                        for tc in msg.tool_calls
                    ]
                return cls.litellm_message_to_cmf(msg_dict, is_response=True)
            elif hasattr(choice, "text"):
                return Message(
                    role=Role.ASSISTANT,
                    content=[TextContent(text=choice.text)],
                    channel=Channel.FINAL,
                )

        logger.warning(f"Unknown LiteLLM response format: {type(response)}")
        return Message(
            role=Role.ASSISTANT,
            content=[TextContent(text=str(response))],
            channel=Channel.FINAL,
        )

    @classmethod
    def cmf_to_litellm_message(
        cls,
        message: Message,
    ) -> Dict[str, Any]:
        """Convert a CMF Message back to LiteLLM format.

        Args:
            message: CMF Message object.

        Returns:
            LiteLLM/OpenAI format message dict.
        """
        result: Dict[str, Any] = {
            "role": cls.CMF_TO_LITELLM_ROLE.get(message.role, "user"),
        }

        tool_calls = []
        content_parts = []
        tool_result = None

        for part in message.content:
            if part.content_type == ContentType.TEXT:
                content_parts.append({"type": "text", "text": part.text})
            elif part.content_type == ContentType.IMAGE:
                image = part.content
                if image.type == "url":
                    content_parts.append({
                        "type": "image_url",
                        "image_url": {"url": image.data},
                    })
                else:
                    media_type = image.media_type or "image/png"
                    data_url = f"data:{media_type};base64,{image.data}"
                    content_parts.append({
                        "type": "image_url",
                        "image_url": {"url": data_url},
                    })
            elif part.content_type == ContentType.TOOL_CALL:
                tc = part.content
                tool_calls.append({
                    "id": tc.tool_call_id,
                    "type": "function",
                    "function": {
                        "name": tc.name,
                        "arguments": json.dumps(tc.arguments),
                    },
                })
            elif part.content_type == ContentType.TOOL_RESULT:
                tool_result = part.content

        # Build result
        if tool_result:
            result["role"] = "tool"
            result["tool_call_id"] = tool_result.tool_call_id
            result["content"] = tool_result.content if isinstance(tool_result.content, str) else json.dumps(tool_result.content) if tool_result.content else ""
            if tool_result.tool_name:
                result["name"] = tool_result.tool_name
        elif len(content_parts) == 1 and content_parts[0]["type"] == "text":
            result["content"] = content_parts[0]["text"]
        elif content_parts:
            result["content"] = content_parts
        else:
            result["content"] = ""

        if tool_calls:
            result["tool_calls"] = tool_calls

        return result

    @classmethod
    def cmf_messages_to_litellm(
        cls,
        messages: List[Message],
    ) -> List[Dict[str, Any]]:
        """Convert a list of CMF Messages to LiteLLM format.

        Args:
            messages: List of CMF Message objects.

        Returns:
            List of LiteLLM/OpenAI format message dicts.
        """
        return [cls.cmf_to_litellm_message(m) for m in messages]
