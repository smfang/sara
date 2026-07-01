"""
Tests for the Sara DAO RL spike.

All tests are offline: no GPU, no network, no Tinker API key required.

Run:
    uv run python -m pytest src/agent_rl/tinker_spike/test_tinker_spike.py -v
"""

from __future__ import annotations

import os

import pytest

from src.agent_rl.tinker_spike.cli import _check_calibration, _check_gold_holdout, _check_tinker_key, _make_smoke_rows
from src.agent_rl.tinker_spike.config import TinkerRLConfig
from src.agent_rl.tinker_spike.dao_env import DaoProblemEnv, SamplingClient, compute_advantages
from src.agent_rl.tinker_spike.evaluate import run_eval
from src.agent_rl.tinker_spike.reward import GoldRow, OspreyGateMatcher, RewardComputer, SaraCompletion
from src.agent_rl.tinker_spike.train_dao import TrainState, run_training


# ── Helpers ───────────────────────────────────────────────────────────────────

def _cfg(**overrides) -> TinkerRLConfig:
    defaults = dict(
        max_steps=2, prompts_per_step=4, group_size=2, max_usd=1.0,
        w_verify=0.55, w_correct=0.20, w_cov=0.10, w_fp=0.10, w_pc2=0.05,
    )
    defaults.update(overrides)
    return TinkerRLConfig(**defaults)


def _gold(leaf: str = "treasury_manipulation", label: str = "STOP", benign: bool = False) -> GoldRow:
    return GoldRow(
        prompt="fake prompt",
        label=label,
        expected_gate=leaf,
        leaf=leaf,
        is_benign=benign,
    )


# ── Reward ────────────────────────────────────────────────────────────────────

class TestReward:

    def test_osprey_match_full_score(self) -> None:
        """A completion matching both gate AND label gets max verifiable score."""
        cfg = _cfg()
        rc = RewardComputer(cfg)
        gold = _gold("treasury_manipulation", "STOP")
        comp = SaraCompletion(verdict="STOP", predicted_gate="treasury_manipulation")
        r = rc.compute(gold, comp)
        # osprey_pass=1.0, label_correct=1.0 → raw = 0.55+0.20 = 0.75 (no coverage bonus, no fp, pc2≈0)
        assert r >= 0.70

    def test_osprey_fail_low_score(self) -> None:
        """A judge-pleasing but Osprey-failing completion scores LOW (verifiable dominates)."""
        cfg = _cfg()
        rc = RewardComputer(cfg)
        gold = _gold("treasury_manipulation", "STOP")
        # Wrong gate → osprey_pass=0.0; correct label → label_correct=1.0
        comp = SaraCompletion(verdict="STOP", predicted_gate="social_engineering")
        r = rc.compute(gold, comp)
        # raw = 0*0.55 + 1.0*0.20 + 0 - 0 + ~0 = 0.20
        assert r <= 0.25, f"Osprey-failing sample should score low, got {r}"

    def test_false_positive_penalised(self) -> None:
        """STOPping a benign prompt incurs fp penalty."""
        cfg = _cfg()
        rc = RewardComputer(cfg)
        gold = _gold(benign=True, label="ALLOW")
        comp = SaraCompletion(verdict="STOP", predicted_gate="treasury_manipulation")
        r_fp = rc.compute(gold, comp)
        comp_allow = SaraCompletion(verdict="ALLOW", predicted_gate="treasury_manipulation")
        r_ok = rc.compute(gold, comp_allow)
        assert r_fp < r_ok

    def test_reward_clamped_to_unit_interval(self) -> None:
        cfg = _cfg()
        rc = RewardComputer(cfg)
        gold = _gold()
        for verdict in ("STOP", "ALERT", "ALLOW"):
            comp = SaraCompletion(verdict=verdict, predicted_gate=gold.leaf)
            r = rc.compute(gold, comp)
            assert 0.0 <= r <= 1.0, f"reward {r} out of [0,1]"


class TestOspreyGateMatcher:

    def test_exact_match(self) -> None:
        assert OspreyGateMatcher().match("treasury_manipulation", "treasury_manipulation") == 1.0

    def test_adjacent_partial(self) -> None:
        # information_hazards and social_engineering are adjacent in _TIERS
        score = OspreyGateMatcher().match("information_hazards", "social_engineering")
        assert score == 0.5

    def test_wrong_gate(self) -> None:
        score = OspreyGateMatcher().match("treasury_manipulation", "information_hazards")
        assert score == 0.0


# ── Advantages ────────────────────────────────────────────────────────────────

class TestComputeAdvantages:

    def test_zero_mean_within_group(self) -> None:
        rewards = [0.2, 0.4, 0.6, 0.8]
        advs = compute_advantages(rewards)
        assert abs(sum(advs)) < 1e-6, "advantages must be zero-mean"

    def test_constant_rewards_near_zero_advantage(self) -> None:
        rewards = [0.5] * 8
        advs = compute_advantages(rewards)
        assert all(abs(a) < 1e-4 for a in advs), "constant rewards → ~0 advantage"

    def test_high_reward_positive_advantage(self) -> None:
        rewards = [0.1, 0.1, 0.1, 0.9]
        advs = compute_advantages(rewards)
        assert advs[-1] > 0, "highest reward must get positive advantage"

    def test_empty_returns_empty(self) -> None:
        assert compute_advantages([]) == []


# ── GDPR ──────────────────────────────────────────────────────────────────────

class TestGDPR:

    def test_trajectory_has_no_raw_prompt(self) -> None:
        """Trajectories must store SHA3-256 hash, not raw prompt text."""
        cfg = _cfg()
        rc = RewardComputer(cfg)
        train_rows = _make_smoke_rows(leaves=2)
        env = DaoProblemEnv(cfg, train_rows, rc)
        sampler = SamplingClient(mock=True)
        groups = env.rollout_groups(sampler, n_prompts=2, group_size=2)

        for g in groups:
            for t in g.trajectories:
                assert len(t.prompt_hash) == 64, "must be SHA3-256 (64 hex chars)"
                assert "[smoke]" not in t.prompt_hash, "raw prompt text must not appear in hash field"

    def test_prompt_hash_is_deterministic(self) -> None:
        """Same prompt always produces the same hash."""
        from src.crypto.canonical import digest
        h1 = digest({"prompt": "test attack"})
        h2 = digest({"prompt": "test attack"})
        assert h1 == h2


# ── Pre-flight gates ──────────────────────────────────────────────────────────

class TestPreflightGates:

    def test_calibration_blocked_when_no_file(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        ok, msg = _check_calibration()
        assert not ok
        assert "BLOCKED" in msg

    def test_calibration_passes_with_go_decision(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "calibration_report.json").write_text('{"result": "DECISION: GO"}')
        ok, _ = _check_calibration()
        assert ok

    def test_gold_holdout_blocked_when_missing(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        ok, msg = _check_gold_holdout()
        assert not ok
        assert "BLOCKED" in msg

    def test_gold_holdout_blocked_with_fill_placeholder(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "data").mkdir()
        (tmp_path / "data" / "dao").mkdir()
        (tmp_path / "data" / "dao" / "gold_holdout.jsonl").write_text(
            '{"prompt": "[fill]", "label": "STOP"}\n'
        )
        ok, msg = _check_gold_holdout()
        assert not ok
        assert "fill" in msg.lower()

    def test_gold_holdout_passes_when_valid(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "data").mkdir()
        (tmp_path / "data" / "dao").mkdir()
        (tmp_path / "data" / "dao" / "gold_holdout.jsonl").write_text(
            '{"prompt": "real attack", "label": "STOP"}\n'
        )
        ok, _ = _check_gold_holdout()
        assert ok

    def test_tinker_key_blocked_when_missing(self, monkeypatch) -> None:
        monkeypatch.delenv("TINKER_API_KEY", raising=False)
        ok, msg = _check_tinker_key()
        assert not ok
        assert "BLOCKED" in msg

    def test_tinker_key_passes_when_set(self, monkeypatch) -> None:
        monkeypatch.setenv("TINKER_API_KEY", "test-key-123")
        ok, _ = _check_tinker_key()
        assert ok


# ── Smoke train loop ──────────────────────────────────────────────────────────

class TestSmokeTrain:

    def test_smoke_runs_end_to_end(self) -> None:
        """2-step loop, mocked Tinker client + mocked judge, completes without error."""
        cfg = _cfg(max_steps=2, prompts_per_step=2, group_size=2)
        train_rows = _make_smoke_rows(leaves=2)
        state = run_training(cfg, train_rows, smoke=True)
        assert state.step >= 1
        assert state.total_usd >= 0.0

    def test_smoke_produces_checkpoints(self) -> None:
        cfg = _cfg(max_steps=2, prompts_per_step=2, group_size=2, eval_every=1)
        train_rows = _make_smoke_rows(leaves=2)
        state = run_training(cfg, train_rows, smoke=True)
        # eval_every=1 means checkpoint on step 0
        assert len(state.checkpoints) >= 1

    def test_spend_cap_stops_training(self) -> None:
        """Training stops early when total_usd exceeds max_usd."""
        cfg = _cfg(max_steps=100, prompts_per_step=4, group_size=2, max_usd=0.0)
        train_rows = _make_smoke_rows(leaves=2)
        state = run_training(cfg, train_rows, smoke=False)
        # With max_usd=0.0 the loop should stop on the first step that incurs cost
        assert state.step < 100


# ── Eval exit gate ────────────────────────────────────────────────────────────

class TestEvalExitGate:

    def test_eval_detects_failing_f1(self) -> None:
        """A mock sampler returning all ALLOW on attack prompts fails the F1 gate."""
        class AlwaysAllow(SamplingClient):
            def sample(self, prompt, n=1):
                return [SaraCompletion(verdict="ALLOW", predicted_gate="treasury_manipulation")] * n

        hold_out = [
            GoldRow("p1", "STOP", "treasury_manipulation", "treasury_manipulation"),
            GoldRow("p2", "STOP", "treasury_manipulation", "treasury_manipulation"),
            GoldRow("benign", "ALLOW", "information_hazards", "information_hazards", is_benign=True),
        ]
        result = run_eval(AlwaysAllow(mock=False), hold_out)
        assert not result.exit_gate_passed
        assert result.macro_f1 == 0.0

    def test_eval_passes_perfect_sampler(self) -> None:
        """A sampler that always gets it right passes the gate."""
        class PerfectSampler(SamplingClient):
            def sample(self, prompt, n=1):
                if "benign" in prompt:
                    return [SaraCompletion(verdict="ALLOW", predicted_gate="information_hazards")] * n
                return [SaraCompletion(verdict="STOP", predicted_gate="treasury_manipulation")] * n

        hold_out = [
            GoldRow("attack", "STOP", "treasury_manipulation", "treasury_manipulation"),
            GoldRow("benign", "ALLOW", "information_hazards", "information_hazards", is_benign=True),
        ]
        result = run_eval(PerfectSampler(mock=False), hold_out)
        assert result.macro_f1 == 1.0
        assert result.stop_fp_rate == 0.0
        assert result.exit_gate_passed


# ── Config invariants ─────────────────────────────────────────────────────────

class TestConfig:

    def test_reward_weights_sum_to_one(self) -> None:
        cfg = TinkerRLConfig()
        total = cfg.w_verify + cfg.w_correct + cfg.w_cov + cfg.w_fp + cfg.w_pc2
        assert abs(total - 1.0) < 1e-6

    def test_dominance_rule_holds(self) -> None:
        cfg = TinkerRLConfig()
        assert cfg.w_verify + cfg.w_correct > 0.5

    def test_pc2_is_minority(self) -> None:
        cfg = TinkerRLConfig()
        assert cfg.w_pc2 <= 0.10

    def test_dao_leaves_match_taxonomy(self) -> None:
        from src.sarabox.taxonomy import DAO_TAXONOMY
        expected = [c["id"] for c in DAO_TAXONOMY]
        assert TinkerRLConfig().dao_leaves == expected
