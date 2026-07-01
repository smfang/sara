"""
DaoProblemEnv — single-turn RLVR environment for DAO safety classification.

Sara samples a verdict + gate + rationale for a DAO attack prompt.
The reward is computed by reward.RewardComputer.

Group rollouts produce G completions per prompt, feeding compute_advantages()
with group-relative baselines (the GRPO mechanism).

Prompts are drawn from the TRAIN split only. Gold hold-out is never touched here.

GDPR: only SHA3-256(prompt) is written to persistent logs, never raw text.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from src.agent_rl.tinker_spike.config import TinkerRLConfig
from src.agent_rl.tinker_spike.reward import GoldRow, RewardComputer, SaraCompletion
from src.crypto.canonical import digest


@dataclass
class Trajectory:
    """One sampled completion with its reward."""
    prompt_hash: str        # SHA3-256(prompt) — GDPR: never store raw prompt in logs
    completion: SaraCompletion
    reward: float
    logprob: float = 0.0    # rollout-policy logprob for importance-sampling correction


@dataclass
class TrajectoryGroup:
    """G trajectories for the same prompt (GRPO group)."""
    prompt_hash: str
    gold: GoldRow
    trajectories: list[Trajectory] = field(default_factory=list)
    advantages: list[float] = field(default_factory=list)


def compute_advantages(rewards: list[float]) -> list[float]:
    """
    Group-relative advantage: A_i = (r_i - mean(r)) / (std(r) + eps).
    Constant-reward groups → near-zero advantage (no wasted gradient).
    """
    if not rewards:
        return []
    mean = sum(rewards) / len(rewards)
    variance = sum((r - mean) ** 2 for r in rewards) / len(rewards)
    std = variance ** 0.5
    eps = 1e-8
    return [(r - mean) / (std + eps) for r in rewards]


class SamplingClient:
    """
    Thin abstraction over the model sampler.

    In smoke/test mode: returns deterministic mock completions.
    In Tinker mode: wraps tinker's sampling client.
    # A.5-full: inject real Tinker SamplingClient here.
    """

    def __init__(self, mock: bool = True) -> None:
        self._mock = mock
        self._verdicts = ["STOP", "ALERT", "ALLOW"]

    def sample(self, prompt: str, n: int = 1) -> list[SaraCompletion]:
        """Sample n completions for a prompt."""
        if self._mock:
            return [
                SaraCompletion(
                    verdict=random.choice(self._verdicts),
                    predicted_gate=random.choice([
                        "identity_access_probing", "treasury_manipulation",
                        "governance_red_flags", "social_engineering",
                        "smart_contract_exploitation", "information_hazards",
                    ]),
                    rationale="[mock rationale]",
                )
                for _ in range(n)
            ]
        raise NotImplementedError(
            "Real Tinker sampler not wired. Set TINKER_API_KEY and inject tinker.SamplingClient."
        )


class DaoProblemEnv:
    """
    Single-turn DAO safety classification environment.

    Each step: draw a leaf-balanced batch of gold rows → get G completions per row
    from the sampling client → compute reward for each → return TrajectoryGroups.
    """

    def __init__(
        self,
        cfg: TinkerRLConfig,
        train_rows: list[GoldRow],
        reward_computer: RewardComputer,
    ) -> None:
        self._cfg = cfg
        self._train_rows = train_rows
        self._reward = reward_computer
        # Track which leaves have been covered (for coverage_bonus)
        self._covered: set[str] = set()

    def _sample_batch(self, n: int) -> list[GoldRow]:
        """Draw a leaf-balanced batch including benign controls."""
        leaf_pools: dict[str, list[GoldRow]] = {}
        benign = []
        for row in self._train_rows:
            if row.is_benign:
                benign.append(row)
            else:
                leaf_pools.setdefault(row.leaf, []).append(row)

        batch: list[GoldRow] = []
        leaves = self._cfg.dao_leaves
        per_leaf = max(1, n // (len(leaves) + 1))
        for leaf in leaves:
            pool = leaf_pools.get(leaf, [])
            if pool:
                batch.extend(random.choices(pool, k=per_leaf))
        # Add benign controls (~1 per batch)
        if benign:
            batch.append(random.choice(benign))
        return batch[:n]

    def rollout_groups(
        self,
        sampler: SamplingClient,
        n_prompts: int,
        group_size: int,
    ) -> list[TrajectoryGroup]:
        batch = self._sample_batch(n_prompts)
        groups: list[TrajectoryGroup] = []

        for gold in batch:
            completions = sampler.sample(gold.prompt, n=group_size)
            phash = digest({"prompt": gold.prompt})  # GDPR: log only hash
            group = TrajectoryGroup(prompt_hash=phash, gold=gold)

            for comp in completions:
                first_cover = gold.leaf not in self._covered
                r = self._reward.compute(gold, comp, leaf_first_cover=first_cover)
                if comp.predicted_gate == gold.expected_gate:
                    self._covered.add(gold.leaf)
                group.trajectories.append(
                    Trajectory(prompt_hash=phash, completion=comp, reward=r)
                )

            group.advantages = compute_advantages(
                [t.reward for t in group.trajectories]
            )
            groups.append(group)

        return groups
