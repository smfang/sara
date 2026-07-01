"""
CLI for the Sara DAO RL spike.

Usage:
    # Smoke — always safe, no API key needed, mocked Tinker, 5 steps
    uv run python -m src.agent_rl.tinker_spike.cli smoke

    # Real train — BLOCKED until A.2.5 gates pass
    uv run python -m src.agent_rl.tinker_spike.cli train --vertical dao

Pre-flight gates (train only):
  (a) calibration_report.json contains "DECISION: GO"  (run A.2.5 first)
  (b) data/dao/gold_holdout.jsonl exists and has no [fill] placeholders
  (c) TINKER_API_KEY env var is set
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import click

from src.agent_rl.tinker_spike.config import TinkerRLConfig
from src.agent_rl.tinker_spike.reward import GoldRow
from src.agent_rl.tinker_spike.train_dao import run_training
from src.sarabox.taxonomy import DAO_TAXONOMY


# ── Gate checks ───────────────────────────────────────────────────────────────

def _check_calibration() -> tuple[bool, str]:
    for path in ("calibration_report.json", "docs/calibration_report.json"):
        try:
            text = Path(path).read_text()
            if "DECISION: GO" in text:
                return True, ""
        except FileNotFoundError:
            pass
    return False, "BLOCKED: run A.2.5 judge calibration to produce DECISION: GO first"


def _check_gold_holdout() -> tuple[bool, str]:
    p = Path("data/dao/gold_holdout.jsonl")
    if not p.exists():
        return False, "BLOCKED: data/dao/gold_holdout.jsonl not found (A.2.5 dataset)"
    if "[fill]" in p.read_text():
        return False, "BLOCKED: gold_holdout.jsonl has unfilled [fill] placeholders"
    return True, ""


def _check_tinker_key() -> tuple[bool, str]:
    if not os.environ.get("TINKER_API_KEY"):
        return False, "BLOCKED: TINKER_API_KEY is not set"
    return True, ""


def _preflight_train() -> None:
    """Run all three gates. Print failures and exit if any fail."""
    gates = [_check_calibration, _check_gold_holdout, _check_tinker_key]
    failures = []
    for gate in gates:
        ok, msg = gate()
        if not ok:
            failures.append(msg)
    if failures:
        for msg in failures:
            click.echo(msg, err=True)
        sys.exit(1)


# ── Synthetic train rows for smoke (avoids needing real data) ─────────────────

def _make_smoke_rows(leaves: int = 3) -> list[GoldRow]:
    selected = [c["id"] for c in DAO_TAXONOMY[:leaves]]
    rows = []
    for leaf in selected:
        for label in ("STOP", "ALERT"):
            rows.append(GoldRow(
                prompt=f"[smoke] attack on {leaf}",
                label=label,
                expected_gate=leaf,
                leaf=leaf,
                is_benign=False,
            ))
    # Benign controls
    rows.append(GoldRow(
        prompt="[smoke] benign: what time is it?",
        label="ALLOW",
        expected_gate="information_hazards",
        leaf="information_hazards",
        is_benign=True,
    ))
    return rows


def _load_train_rows(jsonl_path: str) -> list[GoldRow]:
    rows = []
    with open(jsonl_path) as f:
        for line in f:
            d = json.loads(line)
            rows.append(GoldRow(
                prompt=d["prompt"],
                label=d["label"],
                expected_gate=d["expected_gate"],
                leaf=d["leaf"],
                is_benign=d.get("is_benign", False),
            ))
    return rows


# ── Commands ──────────────────────────────────────────────────────────────────

@click.group()
def cli() -> None:
    """Sara DAO RL spike CLI."""


@cli.command()
@click.option("--base-model", default="Qwen/Qwen3-1.7B", show_default=True)
@click.option("--max-steps", default=5, show_default=True)
@click.option("--leaves", default=3, show_default=True)
def smoke(base_model: str, max_steps: int, leaves: int) -> None:
    """Safe smoke run — mocked Tinker, tiny model, no API key needed."""
    cfg = TinkerRLConfig(
        base_model=base_model,
        smoke_base_model=base_model,
        max_steps=max_steps,
        prompts_per_step=4,
        group_size=2,
        max_usd=0.10,
        w_verify=0.55, w_correct=0.20, w_cov=0.10, w_fp=0.10, w_pc2=0.05,
    )
    train_rows = _make_smoke_rows(leaves=leaves)
    click.echo(f"smoke: {max_steps} steps, {leaves} leaves, model={base_model}")

    state = run_training(cfg, train_rows, smoke=True)

    click.echo(f"smoke done: {state.step} steps, ${state.total_usd:.4f} usd")
    click.echo(f"checkpoints: {state.checkpoints}")
    click.echo("SMOKE PASSED")


@cli.command()
@click.option("--vertical", default="dao", show_default=True)
@click.option("--train-data", default="data/dao/train.jsonl", show_default=True)
@click.option("--rounds", default=1, show_default=True)
def train(vertical: str, train_data: str, rounds: int) -> None:
    """Real training run — blocked until calibration + gold + TINKER_API_KEY."""
    _preflight_train()

    cfg = TinkerRLConfig()
    train_rows = _load_train_rows(train_data)
    click.echo(f"train: {cfg.max_steps} steps, {len(train_rows)} rows, model={cfg.base_model}")

    for r in range(rounds):
        click.echo(f"round {r + 1}/{rounds}")
        state = run_training(cfg, train_rows, smoke=False)
        click.echo(f"round {r + 1} done: {state.step} steps, ${state.total_usd:.4f} usd")

    click.echo("TRAIN COMPLETE")


if __name__ == "__main__":
    cli()
