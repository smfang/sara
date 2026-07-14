"""
Tests for the reasoning-then-verdict parser (GuardReasoner-Omni format) in the
safety classifier. Pure-function tests — no API key / network needed.
"""

import json

from src.safety.classifier import _extract_reasoned


def _verdict(text):
    reasoning, verdict = _extract_reasoned(text)
    return reasoning, json.loads(verdict)


def test_full_reasoning_format():
    text = (
        "<think>The response hands over an SSN and home address — a direct PII "
        "leak, no ALLOW exception applies.</think>\n"
        '<result>{"unsafe": true, "severity": 5, "policy_category": "pii_ip", '
        '"matched_block_rule": "PII disclosure", "explanation": "leaks SSN"}</result>'
    )
    reasoning, v = _verdict(text)
    assert "PII leak" in reasoning
    assert v["unsafe"] is True and v["severity"] == 5 and v["policy_category"] == "pii_ip"


def test_result_tag_without_think():
    text = '<result>{"unsafe": false, "severity": 0}</result>'
    reasoning, v = _verdict(text)
    assert reasoning == ""
    assert v["unsafe"] is False


def test_bare_json_backward_compatible():
    text = '{"unsafe": true, "severity": 3, "policy_category": "hate"}'
    reasoning, v = _verdict(text)
    assert reasoning == "" and v["severity"] == 3


def test_code_fenced_json_backward_compatible():
    text = '```json\n{"unsafe": false, "severity": 0}\n```'
    reasoning, v = _verdict(text)
    assert v["unsafe"] is False


def test_think_block_without_result_tag():
    text = ('<think>refusal — the model declined.</think>\n'
            '{"unsafe": false, "severity": 0, "explanation": "refused"}')
    reasoning, v = _verdict(text)
    assert "refusal" in reasoning
    assert v["unsafe"] is False
