"""
reproducibility.py — pinned, versioned bundle for RL training rounds.

A ReproducibilityBundle captures exactly which inputs (judge model, prompt,
seed, rule versions) declared for a training run. Two runs with the same
bundle_hash used identical declared inputs and their reward signals are
directly comparable.

See docs/determinism.md for the GPU/kernel nondeterminism boundary.

Seam for full A.2 (do NOT build yet):
    sign_attestation(score: float, bundle: ReproducibilityBundle) -> str
    When the signing layer lands, the reward will consume attested scores.
    Today it consumes raw_score + run_id. No interface change needed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from src.crypto.canonical import SCHEMA_VERSION, digest
from src.crypto.hashing import hash_input


@dataclass(frozen=True)
class ReproducibilityBundle:
    """
    Frozen, hashable record of all inputs declared for a training run.

    Fields
    ------
    schema_version      Always SCHEMA_VERSION — ensures canonical encoding is versioned.
    corpus_version      Tag of the red-team / evaluation dataset used.
    suite_version       Version of the evaluation suite (prompt templates, rubric).
    judge_model_id      Model identifier for Sheila's judge (e.g. "claude-opus-4-6").
    judge_prompt_hash   SHA3-256 of the exact system prompt fed to the judge.
                        Never store the raw prompt — only the hash (GDPR RL-09).
    sheila_seed         RNG seed declared for Sheila's sampling. See determinism.md
                        for why this is a declaration, not a guarantee.
    osprey_rules_version  Semantic version of the active Osprey rule pack.
    agent_card_version  Version of the Sara/Sheila agent cards used.
    """

    schema_version: str
    corpus_version: str
    suite_version: str
    judge_model_id: str
    judge_prompt_hash: str
    sheila_seed: int
    osprey_rules_version: str
    agent_card_version: str

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        corpus_version: str,
        suite_version: str,
        judge_model_id: str,
        judge_prompt: str,
        sheila_seed: int,
        osprey_rules_version: str,
        agent_card_version: str,
    ) -> "ReproducibilityBundle":
        """
        Construct a bundle, hashing the raw judge_prompt before storage.

        Never persists the raw prompt (GDPR RL-09) — stores only its
        SHA3-256 hash via hashing.hash_input().
        """
        return cls(
            schema_version=SCHEMA_VERSION,
            corpus_version=corpus_version,
            suite_version=suite_version,
            judge_model_id=judge_model_id,
            judge_prompt_hash=hash_input(judge_prompt),
            sheila_seed=sheila_seed,
            osprey_rules_version=osprey_rules_version,
            agent_card_version=agent_card_version,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "corpus_version": self.corpus_version,
            "suite_version": self.suite_version,
            "judge_model_id": self.judge_model_id,
            "judge_prompt_hash": self.judge_prompt_hash,
            "sheila_seed": self.sheila_seed,
            "osprey_rules_version": self.osprey_rules_version,
            "agent_card_version": self.agent_card_version,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ReproducibilityBundle":
        return cls(
            schema_version=d["schema_version"],
            corpus_version=d["corpus_version"],
            suite_version=d["suite_version"],
            judge_model_id=d["judge_model_id"],
            judge_prompt_hash=d["judge_prompt_hash"],
            sheila_seed=int(d["sheila_seed"]),
            osprey_rules_version=d["osprey_rules_version"],
            agent_card_version=d["agent_card_version"],
        )


# ---------------------------------------------------------------------------
# Bundle hash and run_id
# ---------------------------------------------------------------------------


def bundle_hash(bundle: ReproducibilityBundle) -> str:
    """
    SHA3-256 digest of the canonical encoding of *bundle*.

    Stable across runs and interpreter restarts (property of canonical.digest).
    """
    return digest(bundle.to_dict())


def verify_bundle(bundle: ReproducibilityBundle, expected_hash: str) -> bool:
    """Return True iff bundle_hash(bundle) matches *expected_hash*."""
    import hmac as _hmac
    computed = bundle_hash(bundle)
    return _hmac.compare_digest(computed, expected_hash)


def derive_run_id(
    bundle: ReproducibilityBundle,
    training_round: int,
    started_at: datetime,
) -> str:
    """
    Deterministic, human-greppable run identifier.

    derive_run_id(same_bundle, same_round, same_started_at) == same value
    across runs and interpreter restarts.

    started_at must be timezone-aware (UTC). Raises NonCanonicalValue for
    naive datetimes (enforced by canonical.py).
    """
    payload = {
        "bundle_hash": bundle_hash(bundle),
        "training_round": training_round,
        "started_at": started_at,
    }
    return digest(payload)


# ---------------------------------------------------------------------------
# RL seam — expose bundle to the training loop
# ---------------------------------------------------------------------------


@dataclass
class RewardSampleMetadata:
    """
    Metadata recorded alongside each RL reward sample.

    The reward function attaches this to every (prompt, response, score) tuple
    so a reward regression can later be traced to a specific judge/prompt/seed.
    """

    run_id: str
    reproducibility_hash: str
    training_round: int
    judge_model_id: str
    judge_prompt_hash: str
    sheila_seed: int

    # TODO(A.2-full): add attestation_signature: str | None = None
    # When the signing layer lands, the reward will consume attested scores.
    # Today it uses raw_score + run_id. No interface change needed at that point.


def make_reward_metadata(
    bundle: ReproducibilityBundle,
    training_round: int,
    started_at: datetime,
) -> RewardSampleMetadata:
    """Build the metadata block the reward function should attach to each sample."""
    run_id = derive_run_id(bundle, training_round, started_at)
    return RewardSampleMetadata(
        run_id=run_id,
        reproducibility_hash=bundle_hash(bundle),
        training_round=training_round,
        judge_model_id=bundle.judge_model_id,
        judge_prompt_hash=bundle.judge_prompt_hash,
        sheila_seed=bundle.sheila_seed,
    )


# ---------------------------------------------------------------------------
# current_bundle() — entry point for the training loop (Spec §6)
# ---------------------------------------------------------------------------

# Module-level singleton. Set by the training harness before any reward
# computation begins. The training loop calls:
#
#   from src.crypto.reproducibility import set_current_bundle, current_bundle
#   set_current_bundle(bundle)
#   ...
#   meta = make_reward_metadata(current_bundle(), round_n, started_at)

_current_bundle: ReproducibilityBundle | None = None


def set_current_bundle(bundle: ReproducibilityBundle) -> None:
    """Register *bundle* as the active bundle for this training run.

    Call once at the start of each training round, before any reward
    computation or logging. Subsequent calls to current_bundle() will
    return this bundle until the next set_current_bundle() call.
    """
    global _current_bundle
    _current_bundle = bundle


def current_bundle() -> ReproducibilityBundle:
    """Return the bundle registered for the current training run.

    Raises RuntimeError if set_current_bundle() has not been called yet.
    The training loop must call set_current_bundle(bundle) once before
    invoking any reward computation.
    """
    if _current_bundle is None:
        raise RuntimeError(
            "No ReproducibilityBundle registered. "
            "Call set_current_bundle(bundle) at the start of the training round."
        )
    return _current_bundle
