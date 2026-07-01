# A.2-lite — Reproducibility Layer for the RL Spike (no crypto yet)

> **Why this exists.** The RL reward consumes Sheila's judge *scores*, not a signature. The only
> part of A.2 that actually serves RL is **reproducibility + versioning**: pinning the exact inputs
> that produced a score so training is deterministic to debug and runs are comparable across rounds.
> This prompt builds *only* that slice. Cryptographic attestation (ECDSA signing, hash-chain, SP1)
> is **deferred** until there is an external trust need (bounty payouts, Arena entrants, regulators,
> multi-org). It is designed to be **additive**: the full A.2 drops in later without rework.
>
> **Audience:** an autonomous Claude coding agent in the Sara/Sheila repo.
> **Non-negotiables:** one canonical encoder (`canonical.py`) is the single source of truth for any
> hashing; never store raw prompts (GDPR — store `SHA3-256(prompt)` only).

---

## 0. Scope

**In scope (build now):**
- `canonical.py` — deterministic encoder (also the foundation the later signing layer reuses).
- `reproducibility.py` — `ReproducibilityBundle`, `bundle_hash()`, `derive_run_id()`.
- `run_manifest.py` — per-round manifest that pins bundle + reward config so RL runs are reproducible.
- `hashing.py` — `hash_input()` GDPR helper (used by `rl_training.*` tables, satisfies RL-09).

**Deferred (do NOT build yet — leave the seams):**
- `attestation.py` (ECDSA P-384, `signatures[]`, `key_id`, JWKS), `keys.py`
- `audit_log.py` (hash-chain / immutable log / ClickHouse projection)
- `sp1_stub.py` (L3)

> Keep everything under `src/crypto/` even though there's no crypto yet, so the full A.2 is purely
> additive (it adds files, doesn't move these). If you prefer a neutral name, `src/repro/` is fine —
> but pick one and keep `canonical.py` shared.

---

## 1. Pre-flight (report before writing code)

```bash
find src/ agents/ -name "*.py" | head -50
```
1. List `src/crypto/` (or `src/repro/`), `src/rl_training/`, `src/sarabox/`, `agents/sheila/`.
2. `grep -rin "canonical\|reproducib\|run_id\|judge_prompt\|sha3" src/ | head -40`
3. Report findings + intended file list **before** writing code. Do not duplicate existing modules.

---

## 2. `canonical.py` — deterministic encoder (build first)

Same contract the full A.2 will reuse for signing, so get the typed-field rules right now.

- `canonical_bytes(obj: Mapping) -> bytes` — RFC 8785 (JCS): keys sorted, no insignificant
  whitespace, UTF-8, no trailing newline.
- **Typed-field rules (the determinism traps):**
  - `Decimal` (e.g. any payout figure) → integer micro-units; exact, else raise `NonCanonicalValue`.
  - `float` (`raw_score`, `novelty_score`) → fixed-scale **string** (e.g. 6 dp), not a JSON number.
  - `datetime` → RFC 3339 UTC `Z`, fixed microsecond precision; reject naive datetimes.
  - `bytes` → base64url, no padding; reject `NaN`/`Infinity`.
- `digest(obj) -> str` = `sha3_256(canonical_bytes(obj)).hexdigest()`.
- `SCHEMA_VERSION = "1.0"`; require `schema_version` on every serialized record.

**Tests:** identical bytes across runs and a fresh interpreter; key-order independence; Decimal/float/
datetime edge cases; naive datetime and non-finite floats rejected.

---

## 3. `reproducibility.py` — the core of this prompt

- `ReproducibilityBundle` (frozen, hashable) fields:
  `schema_version, corpus_version, suite_version, judge_model_id, judge_prompt_hash,
  sheila_seed: int, osprey_rules_version, agent_card_version`.
- `bundle_hash() -> str` = `digest(bundle)` via `canonical.py`.
- `verify_bundle(bundle, expected_hash) -> bool`.
- `derive_run_id(bundle, training_round: int, started_at: datetime) -> str`
  = `digest({bundle_hash, training_round, started_at})` — deterministic, human-greppable run id.

> **Determinism honesty (put this in `docs/determinism.md`):** pinning `sheila_seed` does **not**
> guarantee bit-identical LLM judge output on GPU (kernel nondeterminism, batching, model updates).
> The bundle records *which inputs were declared* so two runs are comparable and a reward regression
> can be traced to a changed input — it is not a claim of bit-exact replay.

**Tests:** hash stability; `verify_bundle` success/failure; `run_id` deterministic for identical
inputs, distinct when any field changes.

---

## 4. `run_manifest.py` — make each RL round reproducible

This is what turns "we trained a model" into "we can reproduce and compare this run."

- `RunManifest` (dataclass) fields:
  `run_id, reproducibility_bundle, reward_config_hash, dataset_version, base_model_id,
  lora_rank, stage (sft|dpo|rlvr|grpo), created_at`.
  - `reward_config_hash` = `digest(reward_weights + guard settings)` so a change to reward weights
    (the single biggest source of silent RL drift) shows up as a new manifest, not a hidden edit.
- `write(manifest, path)` / `load(path)` — JSON via `canonical.py` (stable, diff-able).
- On every training round, write a manifest next to the checkpoint. Two runs with the same
  `run_id` + `reward_config_hash` must be byte-identical in their declared inputs.

**Tests:** manifest round-trips; changing any reward weight changes `reward_config_hash`; two
manifests with identical inputs compare equal.

---

## 5. `hashing.py` — GDPR helper (nearly free, keep it)

- `hash_input(text: str) -> str` = `sha3_256(text).hexdigest()`.
- Mandate: `rl_training.*` tables and any logged prompt store **only** the hash, never raw text
  (satisfies RL-09 / PRD §8 Privacy). Add a test asserting no raw prompt strings are persisted.

---

## 6. Seam for the RL reward (A.3) — wire this thin interface

So the reward consumes a *pinned, versioned* judge rather than an ad-hoc score:
- Expose `current_bundle() -> ReproducibilityBundle` and `run_id` to the training loop.
- The reward function records `run_id` + `reproducibility_hash` alongside each reward sample, so a
  later run can be diffed and reward-hacking can be attributed to a specific judge/prompt/seed.
- **Deferred seam (leave a TODO, don't build):** `sign_attestation(score, bundle)` — when the full
  A.2 lands, the reward will consume *attested* scores; today it consumes the raw score plus the
  manifest. No interface change needed when signing is added.

---

## 7. Acceptance criteria

- `python3 -m pytest tests/test_repro.py -v` green.
- `bundle_hash` and `run_id` are stable across runs and across a fresh interpreter (hypothesis test).
- Changing any bundle field or reward weight produces a new hash/run_id.
- No raw prompt text in any persisted record (GDPR test passes).
- `docs/determinism.md` exists and states the seed/GPU determinism boundary.

**Verify:**
```bash
python3 -m pytest tests/test_repro.py -v
grep -rin "raw_prompt\|prompt_text" src/ | grep -vi "hash" || echo "no raw prompt persisted"
```

## 8. Do / Don't

**Do:** route all hashing through `canonical.py`; pin the judge (model id + prompt hash) and seed in
the bundle; write a `RunManifest` per round; hash prompts before storage; document the determinism boundary.

**Don't:** build signing/keys/hash-chain/SP1 yet; store raw prompts; create a second serializer;
serialize scores as JSON floats or money as floats; treat `run_id` as a security guarantee (it is a
reproducibility id, not an attestation).