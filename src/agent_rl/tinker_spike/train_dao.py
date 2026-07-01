"""
Cookbook RL training loop for the Sara DAO spike.

Architecture mirrors the Tinker cookbook pattern:
  rollout_groups → compute_advantages (in env) → forward_backward → optim_step

Tinker APIs are stubbed via TinkerClientStub. Real swap:
  # A.3a-full: replace TinkerClientStub with:
  #   sc   = tinker.ServiceClient()
  #   sara = sc.create_lora_training_client(base_model=cfg.base_model, rank=cfg.lora_rank)
  # A.3a-trl: replace with TRL GRPOTrainer (torch/trl/peft are installed).

GDPR: only SHA3-256(prompt) persisted locally (see dao_env.DaoProblemEnv).
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field

from src.agent_rl.tinker_spike.config import TinkerRLConfig
from src.agent_rl.tinker_spike.dao_env import DaoProblemEnv, SamplingClient, TrajectoryGroup
from src.agent_rl.tinker_spike.reward import GoldRow, RewardComputer

logger = logging.getLogger(__name__)


# ── Tinker stub (replaces tinker.ServiceClient for smoke/test) ────────────────

class _TinkerLoRAClientStub:
    """Mimics the Tinker LoRA training client API surface."""

    def __init__(self, base_model: str, lora_rank: int, mock: bool = True) -> None:
        self._model = base_model
        self._rank = lora_rank
        self._mock = mock
        self._step = 0
        self._total_usd = 0.0

    def save_weights_and_get_sampling_client(self, name: str) -> SamplingClient:
        # A.3a-full: sc.sara.save_weights_and_get_sampling_client(name)
        return SamplingClient(mock=self._mock)

    async def forward_backward_async(
        self, groups: list[TrajectoryGroup], method: str = "importance_sampling"
    ) -> dict:
        # A.3a-full: await sara.forward_backward_async(assemble_training_data(groups), method)
        self._total_usd += 0.001 * len(groups)  # stub cost estimate
        return {"loss": 0.0, "usd": self._total_usd}

    async def optim_step_async(self, lr: float = 1e-4) -> None:
        # A.3a-full: await sara.optim_step_async(AdamParams(learning_rate=lr))
        self._step += 1

    def save_state(self, name: str) -> str:
        # A.3a-full: sara.save_state(name) → checkpoint ID
        logger.info("checkpoint saved: %s (stub)", name)
        return f"stub-checkpoint-{name}"

    @property
    def total_usd(self) -> float:
        return self._total_usd


# ── Train state ───────────────────────────────────────────────────────────────

@dataclass
class TrainState:
    step: int = 0
    total_usd: float = 0.0
    eval_results: list[dict] = field(default_factory=list)
    checkpoints: list[str] = field(default_factory=list)


# ── Main training loop ────────────────────────────────────────────────────────

async def _train_loop(
    cfg: TinkerRLConfig,
    env: DaoProblemEnv,
    sara: _TinkerLoRAClientStub,
    state: TrainState,
) -> TrainState:
    base_lr = 1e-4
    # A.3a-full: base_lr *= get_lora_lr_multiplier(cfg.lora_rank)

    for step in range(state.step, cfg.max_steps):
        # On-policy sampling client (snaps weights at this step)
        sampler = sara.save_weights_and_get_sampling_client(
            name=f"sara-dao-{step}"
        ) if step % cfg.eval_every == 0 else sara.save_weights_and_get_sampling_client(
            name=f"sara-dao-{step}"
        )

        groups = env.rollout_groups(
            sampler, cfg.prompts_per_step, cfg.group_size
        )

        fb_result = await sara.forward_backward_async(groups, "importance_sampling")
        await sara.optim_step_async(lr=base_lr)
        state.step = step + 1
        state.total_usd = sara.total_usd

        if step % cfg.eval_every == 0:
            logger.info("step %d | usd=%.3f", step, state.total_usd)
            ckpt = sara.save_state(name=f"step-{step}")
            state.checkpoints.append(ckpt)

        if state.total_usd > cfg.max_usd:
            logger.warning(
                "spend cap hit: $%.3f > $%.3f — stopping", state.total_usd, cfg.max_usd
            )
            break

    return state


def run_training(
    cfg: TinkerRLConfig,
    train_rows: list[GoldRow],
    smoke: bool = False,
    resume_state: TrainState | None = None,
) -> TrainState:
    """Entry point for both smoke and real training runs."""
    if smoke:
        cfg = TinkerRLConfig(
            base_model=cfg.smoke_base_model,
            max_steps=5,
            prompts_per_step=4,
            group_size=2,
            max_usd=0.10,
            w_verify=0.55, w_correct=0.20, w_cov=0.10, w_fp=0.10, w_pc2=0.05,
        )

    reward_computer = RewardComputer(cfg)
    env = DaoProblemEnv(cfg, train_rows, reward_computer)
    sara = _TinkerLoRAClientStub(
        base_model=cfg.base_model,
        lora_rank=cfg.lora_rank,
        mock=True,  # A.3a-full: mock=False, use real Tinker client
    )
    state = resume_state or TrainState()

    return asyncio.run(_train_loop(cfg, env, sara, state))
