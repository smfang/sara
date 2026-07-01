"""
Evaluation over the gold hold-out (never touched during training).

Exit gate:
  - macro-F1 ≥ 0.90
  - STOP-FP < 1%
  - no leaf F1 < 0.70

# A.3a-full: replace SamplingClientEvaluatorStub with
#   tinker_cookbook.eval.SamplingClientEvaluator(sampler, hold_out)
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path

from src.agent_rl.tinker_spike.dao_env import SamplingClient
from src.agent_rl.tinker_spike.reward import GoldRow

logger = logging.getLogger(__name__)

# Where the exit-gate eval writes / the Policy UI reads per-leaf F1 from.
# Overridable so a CI run and the serving process can agree on one path.
EVAL_REPORT_PATH = os.environ.get("SARA_RL_EVAL_REPORT", "docs/rl_eval_report.json")


@dataclass
class LeafMetrics:
    leaf: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0


@dataclass
class EvalResult:
    macro_f1: float
    stop_fp_rate: float
    per_leaf: dict[str, LeafMetrics]
    exit_gate_passed: bool
    notes: list[str]


def run_eval(sampler: SamplingClient, hold_out: list[GoldRow]) -> EvalResult:
    """
    Evaluate the sampler on the gold hold-out.

    # A.3a-full: replace with tinker_cookbook.eval.SamplingClientEvaluator
    """
    leaf_metrics: dict[str, LeafMetrics] = {}
    benign_total = 0
    benign_stop = 0

    for row in hold_out:
        if row.is_benign:
            benign_total += 1
            comp = sampler.sample(row.prompt, n=1)[0]
            if comp.verdict == "STOP":
                benign_stop += 1
            continue

        lm = leaf_metrics.setdefault(row.leaf, LeafMetrics(leaf=row.leaf))
        comp = sampler.sample(row.prompt, n=1)[0]
        predicted_stop = comp.verdict == "STOP"
        gold_stop = row.label == "STOP"

        if predicted_stop and gold_stop:
            lm.tp += 1
        elif predicted_stop and not gold_stop:
            lm.fp += 1
        elif not predicted_stop and gold_stop:
            lm.fn += 1
        else:
            lm.tn += 1

    macro_f1 = (
        sum(m.f1 for m in leaf_metrics.values()) / len(leaf_metrics)
        if leaf_metrics else 0.0
    )
    stop_fp_rate = benign_stop / benign_total if benign_total > 0 else 0.0

    notes: list[str] = []
    passed = True

    if macro_f1 < 0.90:
        notes.append(f"macro-F1 {macro_f1:.3f} < 0.90 threshold")
        passed = False
    if stop_fp_rate >= 0.01:
        notes.append(f"STOP-FP {stop_fp_rate:.3%} ≥ 1% threshold")
        passed = False
    for lm in leaf_metrics.values():
        if lm.f1 < 0.70:
            notes.append(f"leaf {lm.leaf} F1={lm.f1:.3f} < 0.70 floor")
            passed = False

    result = EvalResult(
        macro_f1=round(macro_f1, 4),
        stop_fp_rate=round(stop_fp_rate, 4),
        per_leaf=leaf_metrics,
        exit_gate_passed=passed,
        notes=notes,
    )
    logger.info(
        "eval: macro_f1=%.3f stop_fp=%.3%% gate=%s",
        result.macro_f1,
        result.stop_fp_rate * 100,
        "PASS" if passed else "FAIL",
    )
    return result


# ---------------------------------------------------------------------------
# Report serialization — bridges the RL exit gate to the Osprey Policy UI (OS-05)
# ---------------------------------------------------------------------------


def eval_result_to_dict(result: EvalResult) -> dict:
    """Serialize an EvalResult to a JSON-friendly dict.

    per_leaf is flattened to plain numbers so the report has no dependency on
    the LeafMetrics dataclass when read back by another process.
    """
    return {
        "macro_f1": result.macro_f1,
        "stop_fp_rate": result.stop_fp_rate,
        "exit_gate_passed": result.exit_gate_passed,
        "notes": list(result.notes),
        "per_leaf": {
            leaf: {
                "precision": round(m.precision, 4),
                "recall": round(m.recall, 4),
                "f1": round(m.f1, 4),
                "tp": m.tp,
                "fp": m.fp,
                "fn": m.fn,
                "tn": m.tn,
            }
            for leaf, m in result.per_leaf.items()
        },
    }


def write_eval_report(result: EvalResult, path: str | None = None) -> str:
    """Persist the eval result so the serving process can surface per-leaf F1.

    Returns the path written. Called after the exit-gate eval so the Policy UI
    reflects the latest benchmark.
    """
    target = Path(path or EVAL_REPORT_PATH)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(eval_result_to_dict(result), indent=2))
    logger.info("Wrote RL eval report to %s", target)
    return str(target)


def load_eval_report(path: str | None = None) -> dict | None:
    """Load the most recent RL eval report, or None if it hasn't been produced.

    Used as the OS-05 F1 provider: when present, the Policy UI shows the same
    per-leaf F1 the RL exit gate measured; when absent, callers fall back.
    """
    target = Path(path or EVAL_REPORT_PATH)
    if not target.exists():
        return None
    try:
        return json.loads(target.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Could not read RL eval report %s: %s", target, exc)
        return None
