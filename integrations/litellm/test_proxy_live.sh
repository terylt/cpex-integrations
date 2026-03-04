#!/bin/bash
# Test the LiteLLM Proxy with CMF Policy Handler
#
# Make sure proxy is running first:
#   litellm --config integrations/litellm/proxy_config.yaml
#
# Then run this script:
#   ./integrations/litellm/test_proxy_live.sh
#
# If using master_key, set API_KEY:
#   API_KEY=sk-cmf-proxy-test-key ./integrations/litellm/test_proxy_live.sh

PROXY_URL="${PROXY_URL:-http://localhost:4000}"
API_KEY="${API_KEY:-}"

# Build auth header only if API_KEY is set
AUTH_HEADER=()
if [ -n "$API_KEY" ]; then
  AUTH_HEADER=(-H "Authorization: Bearer $API_KEY")
fi

echo "========================================"
echo "Testing LiteLLM Proxy with CMF Policies"
echo "========================================"
echo "Proxy URL: $PROXY_URL"
echo ""

# Test 1: Simple greeting (should pass)
echo "----------------------------------------"
echo "TEST 1: Simple greeting (should PASS)"
echo "----------------------------------------"
curl -s "$PROXY_URL/v1/chat/completions" \
  -H "Content-Type: application/json" \
  "${AUTH_HEADER[@]}" \
  -d '{
    "model": "watsonx",
    "messages": [{"role": "user", "content": "Hello, how are you?"}],
    "max_tokens": 50
  }' | python3 -m json.tool 2>/dev/null || echo "Request failed"
echo ""

# Test 2: Message with SSN (should be BLOCKED)
echo "----------------------------------------"
echo "TEST 2: Message with SSN (should BLOCK)"
echo "----------------------------------------"
curl -s "$PROXY_URL/v1/chat/completions" \
  -H "Content-Type: application/json" \
  "${AUTH_HEADER[@]}" \
  -d '{
    "model": "watsonx",
    "messages": [{"role": "user", "content": "My SSN is 123-45-6789"}],
    "max_tokens": 50
  }' | python3 -m json.tool 2>/dev/null || echo "Request failed (expected if blocked)"
echo ""

# Test 3: Message with email (should be REDACTED)
echo "----------------------------------------"
echo "TEST 3: Message with email (should REDACT)"
echo "----------------------------------------"
echo "Original: Contact john.doe@example.com or call 555-123-4567"
curl -s "$PROXY_URL/v1/chat/completions" \
  -H "Content-Type: application/json" \
  "${AUTH_HEADER[@]}" \
  -d '{
    "model": "watsonx",
    "messages": [{"role": "user", "content": "Contact john.doe@example.com or call 555-123-4567"}],
    "max_tokens": 50
  }' | python3 -m json.tool 2>/dev/null || echo "Request failed"
echo ""

# Test 4: Post-call redaction (LLM response should be REDACTED)
# The input has no PII so pre-call passes it through cleanly.
# The LLM should generate PII in its response, which post-call should redact.
echo "----------------------------------------"
echo "TEST 4: Post-call redaction (response should have PII REDACTED)"
echo "----------------------------------------"
echo "Asking LLM to generate a fictional employee record..."
curl -s "$PROXY_URL/v1/chat/completions" \
  -H "Content-Type: application/json" \
  "${AUTH_HEADER[@]}" \
  -d '{
    "model": "watsonx",
    "messages": [{"role": "user", "content": "Generate a fictional employee record with the following fields: name, email address, and phone number. Use realistic-looking fake data."}],
    "max_tokens": 150
  }' | python3 -m json.tool 2>/dev/null || echo "Request failed"
echo ""
echo ">>> If post-call redaction works, email and phone in the response should be replaced with [EMAIL REDACTED] / [PHONE REDACTED]."
echo ""

echo "========================================"
echo "Test Complete!"
echo "========================================"
echo ""
echo "Check the proxy logs for details on redaction."
