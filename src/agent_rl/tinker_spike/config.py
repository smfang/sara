"""
TinkerRLConfig — all hyperparameters for the Sara DAO RL spike.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from src.sarabox.taxonomy import DAO_TAXONOMY


@dataclass
class TinkerRLConfig:
    # Model
    base_model: str = "Qwen/Qwen3-8B"
    smoke_base_model: str = "Qwen/Qwen3-1.7B"
    lora_rank: int = 32

    # Training scale
    max_steps: int = 400
    prompts_per_step: int = 32
    group_size: int = 8          # G completions per prompt → GRPO group-relative advantage
    eval_every: int = 50

    # Cost cap — MUST be overridden for real runs; default is a safe smoke limit
    max_usd: float = 5.0

    # Reward weights — dominance rule: w_verify + w_correct > 0.5, w_pc2 ≤ 0.10
    w_verify:  float = 0.55
    w_correct: float = 0.20
    w_cov:     float = 0.10
    w_fp:      float = 0.10
    w_pc2:     float = 0.05

    # PC² sampling rate — Sheila called on this fraction of completions only
    # (pc2 is minority weight; full sampling at 102k calls/run is infeasible)
    pc2_sample_rate: float = 0.10

    # Reasoning-format reward shaping (GuardReasoner-Omni, arXiv 2602.03328).
    # Not part of the weight-sum invariant: the format gate is a 0/1 multiplier
    # and the conciseness penalty only applies to already-correct completions.
    concise_target_tokens: int = 250   # L_target — reasoning length before any trim
    concise_beta: float = 0.05         # β — max conciseness penalty (accuracy-conditioned)

    # Leaf IDs — single source of truth
    dao_leaves: list[str] = field(
        default_factory=lambda: [c["id"] for c in DAO_TAXONOMY]
    )

    def __post_init__(self) -> None:
        assert self.w_verify + self.w_correct > 0.5, (
            f"Dominance rule violated: w_verify({self.w_verify}) + "
            f"w_correct({self.w_correct}) must exceed 0.5"
        )
        assert self.w_pc2 <= 0.10, (
            f"w_pc2({self.w_pc2}) must be ≤ 0.10 (minority term)"
        )
        total = self.w_verify + self.w_correct + self.w_cov + self.w_fp + self.w_pc2
        assert abs(total - 1.0) < 1e-6, (
            f"Reward weights must sum to 1.0, got {total}"
        )
