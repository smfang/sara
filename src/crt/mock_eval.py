"""
MockEvaluator — deterministic stand-in for the real Sheila/Arena evaluation.

Score is derived from SHA-256 of (claimed_tag, org_id) so demo runs are
reproducible across restarts.

# A.5-full: replace with AttestingAgent(SheilaJudge) call:
#   from src.crypto.attesting_agent import AttestingAgent
#   from agents.sheila.api import SheilaJudge
#   verdict = await attesting_agent.evaluate_with_attestation(
#       turn_id=..., user_input=prompt, agent_response=response,
#       bounty_id=campaign_id, reward_inputs={...}
#   )
"""

from __future__ import annotations

import hashlib


class MockEvaluator:

    def evaluate(
        self,
        prompt_or_tag: str,
        claimed_tag: str,
        org_id: str = "",
    ) -> dict:
        """
        Returns a deterministic evaluation result.

        Always succeeds (attack_success=True) so the demo shows full
        coverage; real evaluator will reject weak or off-category attacks.
        """
        key = f"{claimed_tag}:{org_id}".encode()
        h = int(hashlib.sha256(key).hexdigest(), 16)
        # Map to [0.62, 0.95] — 0.33 range via 1000-bucket hash
        score = 0.62 + (h % 1000) / 3030.0
        return {
            "attack_success": True,
            "coverage_category": claimed_tag,
            "total_score": round(score, 4),
        }
