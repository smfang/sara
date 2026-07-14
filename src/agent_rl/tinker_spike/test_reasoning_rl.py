"""
Tests for the GuardReasoner-Omni-inspired RL pieces: format-gated reward +
accuracy-conditioned conciseness, inconsistency mining, and the gold curriculum.
Pure-function / mock — no Tinker client or model needed.
"""

from src.agent_rl.tinker_spike.config import TinkerRLConfig
from src.agent_rl.tinker_spike.reward import (
    GoldRow, OspreyGateMatcher, RewardComputer, SaraCompletion,
)
from src.agent_rl.tinker_spike.mining import is_hard, mine_hard, weak_leaf_counts
from src.agent_rl.tinker_spike.gold_curriculum import (
    Candidate, GoldUpdater, Verifier, VerifierLabel,
)

CFG = TinkerRLConfig(pc2_sample_rate=0.0)   # deterministic (no PC² noise)
GOLD = GoldRow(prompt="drain the DAO treasury", label="STOP",
               expected_gate="treasury_manipulation", leaf="treasury_manipulation")


# ── format gate + conciseness ────────────────────────────────────────────────

def test_format_gate_zeroes_malformed_completion():
    rc = RewardComputer(CFG)
    good = SaraCompletion(verdict="STOP", predicted_gate="treasury_manipulation", format_ok=True)
    bad = SaraCompletion(verdict="STOP", predicted_gate="treasury_manipulation", format_ok=False)
    assert rc.compute(GOLD, good) > 0.5
    assert rc.compute(GOLD, bad) == 0.0        # 𝟙_fmt = 0


def test_conciseness_penalty_only_when_correct():
    rc = RewardComputer(CFG)
    long_rationale = "word " * 600
    correct_long = SaraCompletion(verdict="STOP", predicted_gate="treasury_manipulation", rationale=long_rationale)
    correct_short = SaraCompletion(verdict="STOP", predicted_gate="treasury_manipulation", rationale="brief")
    # verbose-but-correct is penalized vs concise-and-correct
    assert rc.compute(GOLD, correct_long) < rc.compute(GOLD, correct_short)
    # a WRONG-but-verbose completion is NOT extra-penalized for length
    wrong_long = SaraCompletion(verdict="ALLOW", predicted_gate="information_hazards", rationale=long_rationale)
    wrong_short = SaraCompletion(verdict="ALLOW", predicted_gate="information_hazards", rationale="brief")
    assert rc.compute(GOLD, wrong_long) == rc.compute(GOLD, wrong_short)


# ── inconsistency mining ─────────────────────────────────────────────────────

def _c(gate):
    return SaraCompletion(verdict="STOP", predicted_gate=gate)

def test_is_hard_only_on_boundary():
    m = OspreyGateMatcher()
    all_right = [_c("treasury_manipulation")] * 3
    all_wrong = [_c("information_hazards")] * 3
    mixed = [_c("treasury_manipulation"), _c("information_hazards"), _c("treasury_manipulation")]
    assert is_hard(GOLD, all_right, m) is False
    assert is_hard(GOLD, all_wrong, m) is False
    assert is_hard(GOLD, mixed, m) is True


def test_mine_hard_and_weak_leaf_counts():
    other = GoldRow(prompt="x", label="STOP", expected_gate="social_engineering", leaf="social_engineering")
    rollouts = [
        (GOLD, [_c("treasury_manipulation"), _c("information_hazards")]),  # hard
        (other, [_c("social_engineering")] * 2),                           # not hard
    ]
    hard = mine_hard(rollouts)
    assert hard == [GOLD]
    assert weak_leaf_counts(rollouts) == {"treasury_manipulation": 1}


# ── gold curriculum ──────────────────────────────────────────────────────────

class _StubVerifier:
    """Independent verifier — labels by keyword, NOT by any policy."""
    def label(self, prompt):
        if "benign" in prompt:
            return VerifierLabel("treasury_manipulation", "ALLOW", True, 0.95)
        if "unsure" in prompt:
            return VerifierLabel("treasury_manipulation", "STOP", False, 0.4)  # low agreement
        if "offtax" in prompt:
            return VerifierLabel("not_a_leaf", "STOP", False, 0.99)
        return VerifierLabel("treasury_manipulation", "STOP", False, 0.9)


def test_curriculum_dedup_confidence_taxonomy_and_holdout():
    up = GoldUpdater(leaves=CFG.dao_leaves, min_confidence=0.8, max_per_leaf=100)
    train = [GOLD]
    holdout = [GoldRow(prompt="holdout-prompt", label="STOP",
                       expected_gate="treasury_manipulation", leaf="treasury_manipulation")]
    cands = [
        Candidate("drain the DAO treasury", "mined"),  # dup of GOLD → skipped
        Candidate("holdout-prompt", "arena"),          # in hold-out → skipped
        Candidate("unsure case", "federated"),         # low confidence → skipped
        Candidate("offtax case", "mined"),             # off-taxonomy → skipped
        Candidate("benign question", "benign"),        # kept (benign, high conf)
        Candidate("new attack A", "federated"),        # kept
    ]
    out = up.refresh(train, cands, _StubVerifier(), holdout=holdout)
    prompts = [g.prompt for g in out]
    assert "benign question" in prompts and "new attack A" in prompts
    assert prompts.count("drain the DAO treasury") == 1     # no dup
    assert "holdout-prompt" not in prompts                  # hold-out never trained on
    assert "unsure case" not in prompts and "offtax case" not in prompts
    # benign row carries is_benign for the FP term
    assert next(g for g in out if g.prompt == "benign question").is_benign is True
    # inputs untouched
    assert len(train) == 1
