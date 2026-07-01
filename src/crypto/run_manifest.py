"""
run_manifest.py — per-round RL manifest that makes training runs reproducible.

Write one manifest per training checkpoint. Two manifests with identical
run_id + reward_config_hash have byte-identical declared inputs; any
unexplained reward difference is attributable to hardware/kernel nondeterminism
(see docs/determinism.md) or a changed input that wasn't captured here.

Usage
-----
    from src.crypto.run_manifest import RunManifest, write, load, reward_config_hash

    manifest = RunManifest(
        run_id=derive_run_id(bundle, round_n, started_at),
        reproducibility_bundle=bundle,
        reward_config_hash=reward_config_hash({"alpha": 0.4, "beta": 0.3, ...}),
        dataset_version="v2.1.0",
        base_model_id="Qwen/Qwen2.5-7B-Instruct",
        lora_rank=64,
        stage="dpo",
        created_at=datetime.now(timezone.utc),
    )
    write(manifest, checkpoint_dir / "manifest.json")

    # Later:
    loaded = load(checkpoint_dir / "manifest.json")
    assert loaded == manifest
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from src.crypto.canonical import SCHEMA_VERSION, digest
from src.crypto.reproducibility import ReproducibilityBundle


# ---------------------------------------------------------------------------
# reward_config_hash helper
# ---------------------------------------------------------------------------


def reward_config_hash(config: dict[str, Any]) -> str:
    """
    Digest of the reward weights + guard settings.

    A change to any weight (α, β, γ, δ) or guard threshold produces a new
    hash, making silent RL drift visible as a changed manifest.

    *config* may contain floats; they are serialised to 6-dp strings by
    canonical.py so the hash is stable even across float precision quirks.
    """
    return digest(config)


# ---------------------------------------------------------------------------
# RunManifest
# ---------------------------------------------------------------------------

VALID_STAGES = frozenset({"sft", "dpo", "rlvr", "grpo"})


@dataclass
class RunManifest:
    """
    Records everything needed to reproduce or compare an RL training round.

    Fields
    ------
    run_id                 From derive_run_id(bundle, training_round, started_at).
    reproducibility_bundle Pinned inputs (judge model, prompt hash, seed, etc.).
    reward_config_hash     digest(reward_weights + guard settings). Changes when
                           any weight or guard threshold changes.
    dataset_version        Version tag of the training dataset used.
    base_model_id          HuggingFace model ID of the base model fine-tuned.
    lora_rank              LoRA rank used (0 if full fine-tune).
    stage                  Training objective: sft | dpo | rlvr | grpo.
    created_at             UTC timestamp (timezone-aware).
    """

    run_id: str
    reproducibility_bundle: ReproducibilityBundle
    reward_config_hash: str
    dataset_version: str
    base_model_id: str
    lora_rank: int
    stage: Literal["sft", "dpo", "rlvr", "grpo"]
    created_at: datetime

    def __post_init__(self) -> None:
        if self.stage not in VALID_STAGES:
            raise ValueError(f"stage must be one of {sorted(VALID_STAGES)}, got {self.stage!r}")
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware (use datetime.now(timezone.utc))")

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": self.run_id,
            "reproducibility_bundle": self.reproducibility_bundle.to_dict(),
            "reward_config_hash": self.reward_config_hash,
            "dataset_version": self.dataset_version,
            "base_model_id": self.base_model_id,
            "lora_rank": self.lora_rank,
            "stage": self.stage,
            "created_at": self.created_at.astimezone(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f"
            ) + "Z",
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "RunManifest":
        raw_ts = d["created_at"]
        # Parse RFC 3339 Z timestamp
        if raw_ts.endswith("Z"):
            raw_ts = raw_ts[:-1] + "+00:00"
        created_at = datetime.fromisoformat(raw_ts)
        return cls(
            run_id=d["run_id"],
            reproducibility_bundle=ReproducibilityBundle.from_dict(d["reproducibility_bundle"]),
            reward_config_hash=d["reward_config_hash"],
            dataset_version=d["dataset_version"],
            base_model_id=d["base_model_id"],
            lora_rank=int(d["lora_rank"]),
            stage=d["stage"],
            created_at=created_at,
        )

    def manifest_hash(self) -> str:
        """Digest of this manifest (excludes run_id to avoid circular dependency)."""
        d = self.to_dict()
        d.pop("run_id", None)
        return digest(d)


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------


def write(manifest: RunManifest, path: Path | str) -> None:
    """
    Write *manifest* as human-readable JSON next to the training checkpoint.

    Uses canonical.digest order (sort_keys=True) for stable diffs across runs.
    Two runs with identical inputs produce identical manifest files.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = manifest.to_dict()
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, sort_keys=True, indent=2, ensure_ascii=False)
        fh.write("\n")


def load(path: Path | str) -> RunManifest:
    """Load and deserialise a manifest written by write()."""
    with open(Path(path), encoding="utf-8") as fh:
        data = json.load(fh)
    return RunManifest.from_dict(data)
