#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Location: ./integrations/litellm/test_proxy_client.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

Test client for the LiteLLM Proxy with CMF policy guardrails.

Uses the OpenAI Python SDK to connect to the LiteLLM proxy, which is
OpenAI-compatible. Demonstrates pre-call blocking, pre-call redaction,
and post-call redaction.

Usage:
    # Start the proxy first:
    #   litellm --config integrations/litellm/proxy_config.yaml
    #
    # Then run:
    #   python integrations/litellm/test_proxy_client.py
    #
    # Options:
    #   PROXY_URL=http://localhost:4000  (default)
    #   API_KEY=sk-your-key              (optional, if proxy requires auth)
    #   MODEL=watsonx                    (default)
"""

import os
import sys

from openai import OpenAI, APIStatusError


PROXY_URL = os.environ.get("PROXY_URL", "http://localhost:4000")
API_KEY = os.environ.get("API_KEY", "dummy")  # OpenAI SDK requires a non-empty key
MODEL = os.environ.get("MODEL", "watsonx")

client = OpenAI(base_url=f"{PROXY_URL}/v1", api_key=API_KEY)


def separator(title: str) -> None:
    print(f"\n{'─' * 50}")
    print(f"  {title}")
    print(f"{'─' * 50}")


def run_test(name: str, messages: list[dict], expected: str, max_tokens: int = 50) -> None:
    """Run a single test case.

    Args:
        name: Test name for display.
        messages: OpenAI-format messages.
        expected: Description of expected behavior.
        max_tokens: Max tokens for completion.
    """
    separator(f"{name} — expected: {expected}")
    print(f"  Input: {messages[0]['content'][:80]}")

    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=messages,
            max_tokens=max_tokens,
        )
        content = response.choices[0].message.content
        print(f"  Status: OK")
        print(f"  Response: {content}")
    except APIStatusError as e:
        print(f"  Status: {e.status_code}")
        print(f"  Error: {e.body}")


def main() -> None:
    print("=" * 50)
    print("  LiteLLM Proxy — CMF Policy Test Client")
    print("=" * 50)
    print(f"  Proxy:  {PROXY_URL}")
    print(f"  Model:  {MODEL}")

    # Test 1: Clean message — should pass through
    run_test(
        "TEST 1: Simple greeting",
        [{"role": "user", "content": "Hello, how are you?"}],
        "PASS",
    )

    # Test 2: SSN in input — should be blocked (400)
    run_test(
        "TEST 2: SSN in input",
        [{"role": "user", "content": "My SSN is 123-45-6789"}],
        "BLOCK (400)",
    )

    # Test 3: Email + phone in input — should be redacted before reaching LLM
    run_test(
        "TEST 3: Email + phone in input",
        [{"role": "user", "content": "Contact john.doe@example.com or call 555-123-4567"}],
        "REDACT input",
    )

    # Test 4: Ask LLM to generate PII — response should be redacted by post-call hook
    run_test(
        "TEST 4: Post-call redaction",
        [{"role": "user", "content": "Generate a fictional employee record with the following fields: name, email address, and phone number. Use realistic-looking fake data."}],
        "REDACT response",
        max_tokens=150,
    )

    print(f"\n{'=' * 50}")
    print("  Tests complete — check proxy logs for details")
    print(f"{'=' * 50}\n")


if __name__ == "__main__":
    main()
