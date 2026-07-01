# Spec Review — rl (RL Training Pipeline)

_Read-only review against PRD v3 §7. Spec status: In Progress, DAO first. Real path: `src/agent_rl/` (NOT `src/rl_training/`)._

**Summary (3 lines)**
- The verifiable-reward dominance rule is implemented and asserted at construction; the A.2.5 calibration gate and the ≥0.90 macro-F1 / STOP-FP<1% exit criteria are enforced in the tinker_spike path.
- The current spike is **one-sided RLVR** (Sara vs a frozen Sheila judge), not the two-model co-evolution the spec describes; `data_router` and `ScanBenchmark` do not exist, and no reflective replay buffer is present.
- `src/rl_training/` is correctly absent; `src/agent_rl/tinker_spike/test_tinker_spike.py` (29 tests) passes.

| Requirement | Status | Evidence (file:line) | Gap | Severity |
|---|---|---|---|---|
| Two-model co-evolution (Sara SFT→DPO→RLVR/GRPO; Sheila GRPO multiplicative) | PARTIAL | Sara DPO infra `src/agent_rl/layer4_finetune.py:53-85` (`PreferencePairBuilder`, `DPODatasetBuilder`); tinker RLVR `tinker_spike/train_dao.py` | Spike is one-sided (Sheila frozen, `tinker_spike/__init__.py`); **Sheila GRPO multiplicative-reward co-evolution absent** | med |
| Decoupled ALTERNATING updates; reflective replay buffer | ABSENT | no `replay_buffer`/`reflective`/`alternating` symbols in `src/agent_rl` | Not implemented | med |
| Verifiable reward dominates (`w_verify+w_correct>0.5`, `w_pc2≤0.10`); `R_osprey` gate | PRESENT | `tinker_spike/config.py:29-52` (weights + asserted invariants); `w_cov/w_fp/w_pc2` present | `R_osprey` gate-match term present as reward component; naming not literally `R_osprey` | low |
| Per-leaf F1 via ScanBenchmark; `weak_leaves` feed next round + reward-hack detection | DIVERGENT | Per-leaf F1 exists `tinker_spike/evaluate.py:24-53` (`LeafMetrics`,`run_eval`,`per_leaf`) | Implemented as tinker_spike eval, **not `ScanBenchmark`**; `weak_leaves`→next-round feedback and reward-hack detection not implemented | med |
| `data_router`: HarmBench/BeaverTails/WildGuardMix → 6 DAO leaves | ABSENT | no `data_router` file; no HarmBench/BeaverTails/WildGuardMix references in repo | Training-data routing layer missing | **high** |
| GDPR: only SHA3-256(prompt) persisted to training tables | PRESENT | `tinker_spike/dao_env.py:12,28` (`prompt_hash = SHA3-256`, raw never logged); `train_dao.py:13` | — | — |
| A.2.5 calibration = GO before A.3a; exit ≥0.90 macro-F1, STOP-FP<1% | PRESENT | `tinker_spike/cli.py:34-42` (`_check_calibration` requires `DECISION: GO`); `evaluate.py:96-101` (macro-F1≥0.90, STOP-FP<1%, leaf floor 0.70) | Exit gate is in the spike eval; not yet run on a real vertical hold-out | med |

**Gaps (severity-ranked)**
1. **high — `data_router` absent.** No layer maps HarmBench/BeaverTails/WildGuardMix into the 6 DAO leaves, so the pipeline has no specified training-data source. _Action:_ implement `data_router` (even a thin mapper) before A.3a training is meaningful.
2. **med — one-sided, not co-evolution.** Sheila is frozen; the spec's Sheila-GRPO multiplicative-reward loop and alternating updates are not built. _Action:_ scope the Sheila update path or explicitly re-classify the spike as Phase-1 in the spec.
3. **med — no reflective replay buffer.** Past misses are not re-presented. _Action:_ add a replay buffer keyed on prior FN/FP.
4. **med — F1 is not `ScanBenchmark`; no weak-leaf feedback / reward-hack detection.** _Action:_ either rename/adapt the eval to the `ScanBenchmark` contract or update the spec; wire `weak_leaves` back into round selection.
5. **low — reward term naming (`R_osprey`).** Present functionally; align naming.

`DECISION: NOT-READY (verifiable-reward invariant + gates are solid, but data_router is absent and the co-evolution/replay/ScanBenchmark machinery the spec requires is not yet built)`
