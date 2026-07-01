# Determinism Boundary for Sara/Sheila RL Training

## What the ReproducibilityBundle pins

A `ReproducibilityBundle` records the *declared inputs* for a training round:

| Field | What it pins |
|---|---|
| `corpus_version` | Which red-team dataset was used |
| `suite_version` | Which evaluation suite (prompt templates, rubric) |
| `judge_model_id` | The exact model ID of Sheila's judge |
| `judge_prompt_hash` | SHA3-256 of the exact system prompt fed to the judge |
| `sheila_seed` | The RNG seed *declared* for Sheila's sampling |
| `osprey_rules_version` | Which Osprey rule pack was active |
| `agent_card_version` | Which Sara/Sheila agent cards were in use |

Two runs with the same `bundle_hash` used identical *declared* inputs. Their
reward signals are directly comparable and any regression can be traced to a
changed input.

## What the bundle does NOT guarantee

**Pinning `sheila_seed` does NOT guarantee bit-identical LLM judge output.**

Reasons for non-determinism despite an identical seed:

1. **GPU kernel nondeterminism.** CUDA / ROCm operations like `atomicAdd` on
   floating-point accumulators are not associativity-guaranteed. The order of
   partial sums varies across thread warps, producing ULP-level differences in
   logits and therefore different sampled tokens.

2. **Batching effects.** If Sheila evaluates multiple prompts in a batch, the
   padding and attention mask patterns affect numerical results even when the
   logical seed is identical.

3. **Model updates.** If `judge_model_id` is a moving-target alias (e.g.
   `claude-sonnet-latest`) rather than a pinned version (e.g.
   `claude-sonnet-4-6-20251001`), the weights change under the run.
   Always use a fully-pinned model ID.

4. **Framework version drift.** A venv update to PyTorch, vLLM, or the
   Anthropic SDK can change numerical behavior even when everything else is
   identical.

## What the bundle IS useful for

- **Tracing reward regressions.** If reward drops between two runs, compare
  their `bundle_hash` values. If they differ, a changed input caused it.
  If they are identical, look at hardware / framework drift.

- **Audit trail.** The `run_id` (derived from `bundle_hash` + `training_round`
  + `started_at`) is a stable, greppable identifier that appears in ClickHouse
  alongside every reward sample.

- **Comparative evaluation.** Two research runs that share a `bundle_hash`
  are measuring the same declared experimental conditions.

## Recommendations for maximising reproducibility

1. Pin the judge model to a dated, immutable model ID (not a `latest` alias).
2. Use a fixed random seed in Sheila's sampling config (`temperature=0` or a
   specific seed if the framework exposes it).
3. Pin the Python/CUDA/vLLM version in `pyproject.toml` and lock the venv.
4. Run evaluation on a single GPU with `CUBLAS_WORKSPACE_CONFIG=:16:8` to
   disable the most common source of nondeterminism in cuBLAS.
5. Record the `run_id` in every ClickHouse reward row so regressions are
   attributable to a specific manifest.

## Future: cryptographic attestation (A.2-full)

When the full A.2 signing layer ships, the reward function will consume
*attested* scores (ECDSA P-384 signed by Sheila's TEE key) rather than
raw scores + `run_id`. The `ReproducibilityBundle` interface will not change
— the signing layer is purely additive. The deferred seam is the `# TODO(A.2-full)`
comment in `src/crypto/reproducibility.py` (`sign_attestation(score, bundle)`).
The pre-existing `src/crypto/attestation.py` implements `AttestationSigner` for
a different flow (EvaluationAttestation); it is not the same seam.
