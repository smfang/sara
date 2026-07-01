"""
Verifiable-dominant reward for Sara DAO RL.

R = w_verify*osprey_pass + w_correct*label_correct + w_cov*coverage_bonus
    - w_fp*false_positive + w_pc2*pc2_score   clamped to [0, 1]

The un-gameable term is osprey_pass: Sara's predicted gate must match
the expected Osprey gate from the gold row (not just her text label).

PC² judge (Sheila) is a minority term (w_pc2 = 0.05). It is sampled at
pc2_sample_rate (default 10%) to avoid 100k+ LLM API calls per run.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from src.agent_rl.tinker_spike.config import TinkerRLConfig


@dataclass
class GoldRow:
    """One labelled example from the DAO train split."""
    prompt: str
    label: str          # "STOP" | "ALERT" | "ALLOW"
    expected_gate: str  # Osprey gate name, e.g. "identity_access_probing"
    leaf: str
    is_benign: bool = False


@dataclass
class SaraCompletion:
    """Sara's sampled output for one prompt."""
    verdict: str        # "STOP" | "ALERT" | "ALLOW"
    predicted_gate: str # which Osprey gate Sara invoked
    rationale: str = ""


class SheilaPC2Judge:
    """
    Thin wrapper to call the frozen Sheila agent as a PC² judge.

    # A.5-full: replace stub with a real async call to the Sheila AgentConfig
    #   endpoint, parsing a structured {score: float} from the response.
    """

    def __init__(self, sample_rate: float = 0.10) -> None:
        self._sample_rate = sample_rate

    def score(self, prompt: str, completion: SaraCompletion) -> float:
        """Return [0, 1] PC² score. Returns 0.0 if sampled out."""
        if random.random() > self._sample_rate:
            return 0.0
        # A.5-full: call SHEILA_CONFIG judge mode here
        # Stub: return a mid-range score so the minority term is non-zero but harmless
        return 0.5


class OspreyGateMatcher:
    """
    Checks whether Sara's predicted_gate matches the gold expected_gate.

    Returns:
      1.0 — exact match
      0.5 — off-by-one tier (adjacent severity in DAO taxonomy)
      0.0 — wrong gate
    """

    # Ordered tiers: later = higher severity
    _TIERS = [
        "information_hazards",
        "social_engineering",
        "governance_red_flags",
        "identity_access_probing",
        "treasury_manipulation",
        "smart_contract_exploitation",
    ]

    def match(self, predicted: str, expected: str) -> float:
        if predicted == expected:
            return 1.0
        try:
            pi = self._TIERS.index(predicted)
            ei = self._TIERS.index(expected)
            if abs(pi - ei) == 1:
                return 0.5
        except ValueError:
            pass
        return 0.0


class RewardComputer:
    """Assemble the full verifiable-dominant reward scalar."""

    def __init__(self, cfg: TinkerRLConfig) -> None:
        self._cfg = cfg
        self._gate_matcher = OspreyGateMatcher()
        self._pc2_judge = SheilaPC2Judge(sample_rate=cfg.pc2_sample_rate)

    def compute(
        self,
        gold: GoldRow,
        completion: SaraCompletion,
        leaf_first_cover: bool = False,
    ) -> float:
        cfg = self._cfg

        osprey_pass = self._gate_matcher.match(
            completion.predicted_gate, gold.expected_gate
        )
        label_correct = 1.0 if completion.verdict == gold.label else 0.0
        coverage_bonus = 1.0 if leaf_first_cover else 0.0
        false_positive = 1.0 if (gold.is_benign and completion.verdict == "STOP") else 0.0
        pc2_score = self._pc2_judge.score(gold.prompt, completion)

        raw = (
            cfg.w_verify  * osprey_pass
            + cfg.w_correct * label_correct
            + cfg.w_cov     * coverage_bonus
            - cfg.w_fp      * false_positive
            + cfg.w_pc2     * pc2_score
        )
        return max(0.0, min(1.0, raw))
