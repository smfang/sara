"""
Sara Policy Monitor — runtime enforcement layer.

Wraps SaraBoxClassifier with Osprey rule evaluation.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import time
from datetime import datetime
from typing import Any

from src.osprey_ui.models import MonitorEvent, PolicyRule, PolicyRuleSet, RuleTestResult

logger = logging.getLogger(__name__)

SHADOW_MODE = os.environ.get("SHADOW_MODE", "false").lower() == "true"
GRACE_WINDOW_SECONDS = 30

# Severity ranking for action determination
_SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


class SafetyStopException(Exception):
    """Raised when a STOP action is triggered and not in shadow mode."""

    def __init__(self, event: MonitorEvent) -> None:
        self.event = event
        super().__init__(f"Safety stop triggered: {event.matched_rule_id} ({event.confidence:.2f})")


class SaraPolicyMonitor:
    """Runtime enforcement layer that evaluates prompts against active PolicyRules."""

    # Instance-level override registry — class-level would bleed across test instances

    def __init__(
        self,
        org_id: str,
        ruleset: PolicyRuleSet,
        base_classifier: Any,
        ozone: Any,
        erc8004: Any,
        store: Any | None = None,
    ) -> None:
        self._org_id = org_id
        self._ruleset = ruleset
        self._base_classifier = base_classifier
        self._ozone = ozone
        self._erc8004 = erc8004
        self._store = store
        self._overrides: set[str] = set()

    async def evaluate(self, prompt: str, session_id: str) -> MonitorEvent:
        """
        Evaluate a prompt against all active rules.

        Steps:
        1. Run SaraBoxClassifier.classify(prompt)
        2. Evaluate against active PolicyRules
        3. Determine action: highest-severity matched rule wins
        4. Execute action via Ozone
        5. Store MonitorEvent in ClickHouse
        6. If action != LOG: call erc8004.record_evaluation_result()
        7. Return MonitorEvent
        """
        t0 = time.monotonic()
        prompt_hash = hashlib.sha3_256(prompt.encode()).hexdigest()

        # Step 1: Base classification
        base_confidence, base_category = await self._classify(prompt)

        # Step 2 & 3: Evaluate against active rules
        matched_rule: PolicyRule | None = None
        matched_confidence = base_confidence
        for rule in self._ruleset.rules:
            if not rule.enabled:
                continue
            hit, rule_conf = _rule_matches(prompt, rule, base_category, base_confidence)
            if hit:
                if matched_rule is None or _severity_rank(rule.severity) > _severity_rank(matched_rule.severity):
                    matched_rule = rule
                    matched_confidence = rule_conf

        action = matched_rule.action if matched_rule else "LOG"
        confidence = matched_confidence if matched_rule else base_confidence

        event = MonitorEvent(
            org_id=self._org_id,
            session_id=session_id,
            prompt_hash=prompt_hash,
            matched_rule_id=matched_rule.rule_id if matched_rule else None,
            action_taken=action,
            confidence=confidence,
        )

        # Step 4: Execute action via Ozone
        if self._ozone is not None:
            if action == "LOG":
                await self._ozone.apply_label(session_id, "log", {"confidence": confidence, "severity": 0})
            elif action == "ALERT":
                await self._ozone.apply_label(session_id, "alert", {"confidence": confidence, "severity": _severity_rank(matched_rule.severity) if matched_rule else 2})
            elif action == "STOP":
                await self._ozone.apply_label(session_id, "stop", {"confidence": confidence, "severity": _severity_rank(matched_rule.severity) if matched_rule else 4})
        if action == "ALERT":
            # notify operator — logged
            logger.warning("ALERT: rule=%s session=%s confidence=%.2f", matched_rule.rule_id if matched_rule else None, session_id, confidence)
        elif action == "STOP":
            if not SHADOW_MODE and event.event_id not in self._overrides:
                raise SafetyStopException(event)
            else:
                logger.info("STOP shadowed or overridden: event=%s", event.event_id)

        # Step 5: Store MonitorEvent
        if self._store is not None:
            try:
                await self._store.save_monitor_event(event)
            except Exception:
                logger.warning("Failed to persist monitor event", exc_info=True)

        # Step 6: ERC8004 attestation for non-LOG actions
        if action != "LOG" and self._erc8004 is not None:
            try:
                result_hash = hashlib.sha3_256(
                    f"{event.event_id}:{event.action_taken}:{event.confidence}".encode()
                ).hexdigest()
                await self._erc8004.record_evaluation_result(
                    subject=event.event_id,
                    label=f"action:{event.action_taken}",
                    metadata={"result_hash": result_hash, "rule_id": matched_rule.rule_id if matched_rule else ""},
                )
            except Exception:
                logger.warning("ERC8004 attestation failed for event=%s", event.event_id, exc_info=True)

        return event

    async def _classify(self, prompt: str) -> tuple[float, str | None]:
        """Run the base classifier and normalize its result to (confidence, category).

        Tolerates both the real SafetyClassifier — which takes
        (prompt, model_output, category) and returns a dict {unsafe, severity, …} —
        and a simpler object/mock exposing .confidence / .matched_category.
        """
        try:
            try:
                classification = await self._base_classifier.classify(
                    prompt, model_output="[direct]", category="general"
                )
            except TypeError:
                # Object/mock classifier that only accepts the prompt.
                classification = await self._base_classifier.classify(prompt)
        except Exception:
            logger.warning("Base classifier failed; continuing with keyword matching", exc_info=True)
            return 0.0, None

        if isinstance(classification, dict):
            unsafe = bool(classification.get("unsafe", False))
            severity = int(classification.get("severity", 0) or 0)
            confidence = min(0.99, 0.5 + 0.125 * severity) if unsafe else 0.0
            category = classification.get("policy_category") or None
            return confidence, category
        return (
            float(getattr(classification, "confidence", 0.0) or 0.0),
            getattr(classification, "matched_category", None),
        )

    async def test_rule(self, prompt: str, rule: PolicyRule) -> RuleTestResult:
        """Test a single prompt against a specific rule."""
        t0 = time.monotonic()
        base_confidence, base_category = await self._classify(prompt)

        matched, confidence = _rule_matches(prompt, rule, base_category, base_confidence)

        latency_ms = (time.monotonic() - t0) * 1000
        return RuleTestResult(
            prompt=prompt,
            matched=matched,
            rule_id=rule.rule_id if matched else None,
            confidence=confidence,
            action=rule.action if matched else "LOG",
            explanation=f"Matched rule '{rule.display_name}'" if matched else "No match",
            latency_ms=round(latency_ms, 2),
        )

    def override(self, event_id: str, operator_id: str) -> bool:
        """
        HITL override a STOP action within the grace window.

        Returns True if the override was recorded.
        """
        self._overrides.add(event_id)
        logger.info("Override recorded: event=%s operator=%s", event_id, operator_id)
        return True


def _severity_rank(severity: str) -> int:
    return _SEVERITY_RANK.get(severity.lower(), 0)


_NL_STOP_WORDS = {"block", "allow", "when", "then", "that", "from", "with", "this",
                  "prompt", "rule", "should", "must", "any", "all", "will", "have"}


def _extract_rule_keywords(rule: PolicyRule) -> list[str]:
    """Extract matchable keywords from a rule's compiled SML and natural language."""
    keywords: list[str] = []
    # Extract single-quoted strings from SML: 'private key', 'seed phrase', etc.
    if rule.osprey_sml:
        keywords.extend(m.lower() for m in re.findall(r"'([^']{2,})'", rule.osprey_sml))
    # Extract significant words from the analyst's natural language description
    if rule.natural_language:
        words = re.findall(r'\b[a-zA-Z]{5,}\b', rule.natural_language.lower())
        keywords.extend(w for w in words if w not in _NL_STOP_WORDS)
    return keywords


def _rule_matches(
    prompt: str,
    rule: PolicyRule,
    base_category: str | None,
    base_confidence: float,
) -> tuple[bool, float]:
    """
    Return (matched, confidence) for a rule against a prompt.

    Matching priority:
    1. Classifier returned the same category → use classifier confidence
    2. SML quoted keywords found in prompt → keyword match confidence (0.85)
    3. Category ID words found in prompt → low confidence match (0.70)
    Confidence threshold is only enforced for category matches from the classifier.
    Keyword matches bypass the threshold because the classifier may have failed.
    """
    prompt_lower = prompt.lower()

    # 1. Classifier-backed category match (respect confidence threshold)
    if base_category == rule.category and base_confidence >= rule.confidence_threshold:
        return True, base_confidence

    # 2. Keyword match from SML / natural language (classifier may be unavailable)
    for kw in _extract_rule_keywords(rule):
        if kw in prompt_lower:
            return True, 0.85

    # 3. Category ID as readable phrase in prompt (e.g. "pii_ip" → "pii" or "pii ip")
    cat_phrase = rule.category.replace("_", " ")
    cat_abbr = rule.category.split("_")[0]  # "pii" from "pii_ip"
    if cat_phrase in prompt_lower or (len(cat_abbr) >= 3 and cat_abbr in prompt_lower):
        return True, 0.70

    return False, base_confidence
