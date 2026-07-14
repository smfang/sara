"""
Gold-leaf curriculum — how the gold set is kept fresh across GRPO rounds.

CRITICAL DESIGN RULE: the gold set is refreshed BETWEEN rounds, never inside the
GRPO loop. Letting the policy relabel its own training data would move its own
goalposts (reward hacking). So:

  1. Candidate prompts come from four sources (mining, federation, arena, benign).
  2. Each candidate's LABEL is assigned by an INDEPENDENT verifier — the Osprey
     rule pass and/or a high-agreement judge ensemble — NEVER the policy being
     trained. (This is the paper's 3-round LLM-as-Judge refinement.)
  3. Only the TRAIN split grows. The gold HOLD-OUT is frozen forever (it anchors
     the exit gate: macro-F1 ≥ 0.90, STOP-FP < 1%).
  4. Dedup by SHA3(prompt); cap per leaf for balance; drop low-agreement rows.

The flywheel: eval finds weak leaves → retrieve/mine more of those → verifier
labels them → append to train → next GRPO round. RAG (the Federated Incident
Store) and the arena's confirmed findings are two of the candidate sources.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional, Protocol

from src.agent_rl.tinker_spike.reward import GoldRow


def _sha3(text: str) -> str:
    return hashlib.sha3_256(text.encode()).hexdigest()


@dataclass
class Candidate:
    """An unlabelled prompt proposed for the gold set."""
    prompt: str
    source: str   # "mined" | "federated" | "arena" | "benign"


@dataclass
class VerifierLabel:
    leaf: str          # gold leaf / Osprey gate
    verdict: str       # "STOP" | "ALERT" | "ALLOW"
    is_benign: bool
    confidence: float  # agreement / verifier confidence in [0, 1]


class Verifier(Protocol):
    """Assigns a gold label INDEPENDENTLY of the policy being trained.

    Real implementations: an Osprey-rule-pass verifier (deterministic gate) and/or
    a judge-agreement verifier (Sheila judge sampled N times, kept only when the
    label is high-agreement). # A.5-full.
    """
    def label(self, prompt: str) -> Optional[VerifierLabel]: ...


class GoldUpdater:
    """Refreshes the gold TRAIN split from verified candidates."""

    def __init__(
        self,
        leaves: list[str],
        min_confidence: float = 0.8,
        max_per_leaf: int = 500,
    ) -> None:
        self._leaves = set(leaves)
        self._min_confidence = min_confidence
        self._max_per_leaf = max_per_leaf

    def refresh(
        self,
        train_gold: list[GoldRow],
        candidates: list[Candidate],
        verifier: Verifier,
        holdout: Optional[list[GoldRow]] = None,
    ) -> list[GoldRow]:
        """Return the updated TRAIN split (train_gold + verified new rows).

        The hold-out, if supplied, is only READ (to exclude its prompts from the
        train split) — it is never modified. Returns a NEW list; inputs untouched.
        """
        seen = {_sha3(g.prompt) for g in train_gold}
        seen |= {_sha3(g.prompt) for g in (holdout or [])}  # never train on hold-out prompts
        per_leaf = self._leaf_counts(train_gold)

        additions: list[GoldRow] = []
        for cand in candidates:
            h = _sha3(cand.prompt)
            if h in seen:
                continue                                  # dedup
            lab = verifier.label(cand.prompt)
            if lab is None or lab.confidence < self._min_confidence:
                continue                                  # drop low-agreement
            if lab.leaf not in self._leaves:
                continue                                  # off-taxonomy
            if per_leaf.get(lab.leaf, 0) >= self._max_per_leaf:
                continue                                  # leaf-balance cap
            additions.append(GoldRow(
                prompt=cand.prompt,
                label=lab.verdict,
                expected_gate=lab.leaf,
                leaf=lab.leaf,
                is_benign=lab.is_benign,
            ))
            seen.add(h)
            per_leaf[lab.leaf] = per_leaf.get(lab.leaf, 0) + 1

        return list(train_gold) + additions

    def _leaf_counts(self, rows: list[GoldRow]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for r in rows:
            counts[r.leaf] = counts.get(r.leaf, 0) + 1
        return counts
