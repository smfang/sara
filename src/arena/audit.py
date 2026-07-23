"""
Arena ZK audit-trail glue (§7.3, CAT-01/02/05).

Turns a completed `EvaluationResult` into the L1 commitment + L2 signed
attestation the crypto layer defines, WITHOUT re-running any judge. The arena
scorer already judged each prompt (via `SafetyClassifier`); this module only
records that outcome cryptographically.

This is deliberately NOT `src.crypto.attesting_agent.AttestingAgent`: that class
wraps `SheilaJudge` and re-judges, which is wrong for the arena path (different
judge, doubled cost). We reuse the same primitives (`make_commitment`,
`EvaluationAttestation`, `AttestationSigner`) so the persisted records are
schema-identical.

GDPR: `make_commitment` stores only SHA3-256 hashes of its inputs, never raw
prompt/response text — so the canonical bindings below are safe to pass.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any, Optional

from src.crypto.attestation import EvaluationAttestation
from src.crypto.commitment import CommitmentRecord, make_commitment


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def build_signed_attestation(
    submission_prompts: list,
    result: Any,
    scoring_config: Any,
    signer: Any,
    prev_hash: Optional[str] = None,
) -> tuple[EvaluationAttestation, CommitmentRecord]:
    """Build (signed L2 attestation, L1 commitment) for a scored submission.

    - L1: salted SHA3-256 commitment over the canonical prompt set + evaluation
      outcome, chained to `prev_hash` (CAT-02).
    - L2: `EvaluationAttestation` bound to the commitment, recording the decision,
      the scoring formula inputs (α/β/γ/δ) and the final score, signed P-384.

    The judge here is the arena `SafetyClassifier`; the attestation field is named
    `sheila_decision` for schema compatibility with the shared crypto record.
    """
    prompt_repr = _canonical(sorted(p.prompt for p in submission_prompts))
    outcome_repr = _canonical({
        "total_score": round(result.total_score, 6),
        "category_coverage": result.category_coverage,
        "outcomes": [
            {"category": e.category, "attack_success": e.attack_success, "severity": e.severity}
            for e in result.prompt_evaluations
        ],
    })

    commitment = make_commitment(
        prompt=prompt_repr,
        response=outcome_repr,
        bounty_id=result.bounty_id,
        prev_hash=prev_hash,
    )

    n = len(result.prompt_evaluations)
    n_success = sum(1 for e in result.prompt_evaluations if e.attack_success)
    decision = "violation" if n_success else "clean"
    top_category = (
        max(result.category_coverage, key=result.category_coverage.get)
        if result.category_coverage else None
    )

    attestation = EvaluationAttestation(
        attestation_id=f"att_{uuid.uuid4().hex[:16]}",
        commitment_id=commitment.commitment_id,
        bounty_id=result.bounty_id,
        sheila_decision=decision,
        sheila_category=top_category,
        confidence=(n_success / n) if n else 0.0,
        reward_alpha=getattr(scoring_config, "alpha", 0.0),
        reward_beta=getattr(scoring_config, "beta", 0.0),
        reward_gamma=getattr(scoring_config, "gamma", 0.0),
        reward_delta=getattr(scoring_config, "delta", 0.0),
        final_score=result.total_score,
        timestamp_ms=int(time.time() * 1000),
        public_key_id=signer.key_id,
    )
    signed = signer.sign(attestation)
    return signed, commitment
