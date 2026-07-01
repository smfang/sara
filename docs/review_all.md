# Spec Review — ALL (cross-component roll-up)

_Read-only review against PRD v3 §7. Aggregates the seven per-component reviews
(`docs/review_{sara-box,osprey,zk,rl,crt,a2a,boundary}.md`). No code changed._

## Combined DECISION roll-up

| Component | Spec status | Review verdict | One-line reason |
|---|---|---|---|
| §7.1 sara-box | Implemented | **READY** | NL→SkillFile classifier + `DAO_TAXONOMY` single-source all PRESENT; only extensibility nicety open |
| §7.2 osprey | Implemented | **READY** | Save/validate/preview/probe pipeline PRESENT + tested; role-gating, real-SML engine, report-writer are hardening items |
| §7.3 zk | In Progress | **NOT-READY** | L1/L2/chain work, but L2 `EvaluationAttestation` schema **DIVERGENT** from the PRD field contract (HIGH) |
| §7.4 rl | In Progress | **NOT-READY** | Reward invariant + gates solid, but `data_router` **ABSENT** (HIGH) and co-evolution/replay/ScanBenchmark unbuilt |
| §7.5 crt | Later-Stage | **READY** | Privacy invariant enforced type-level + tested; only named stubs + deferred persistence outstanding (in scope) |
| §7.6 a2a | Additive | **READY** | Extraction seam exists; all functional A2A features intentionally deferred to Phase 5 |
| boundary | Critical | **READY** | Boundary invariant enforced + CI-tested; gaps are naming/spec-alignment only |

**Overall:** 5 READY / 2 NOT-READY. The two NOT-READY components (zk, rl) are both
spec-status *In Progress*, so this is consistent with the roadmap — but each carries
one HIGH-severity gap that blocks the *next* milestone (L3 circuit work; A.3a training).
Nothing HIGH was found in any component marked *Implemented*.

## Top 5 cross-component gaps (by severity)

1. **[HIGH · zk] L2 attestation schema contradicts the spec contract.**
   `src/crypto/attestation.py:32-47` — `EvaluationAttestation` carries a reward-component
   schema (`sheila_decision`, `reward_alpha/beta/gamma/delta`, `final_score`, …); only
   `bounty_id` overlaps the PRD's 10 named fields (`attack_success`, `commitment_hash`,
   `coverage_category`, `judge_model_id`, `target_model_id`, `novelty_score`, `raw_score`,
   `payout_usdc`, `evaluated_at`). Any external verifier or ZK circuit built to the PRD
   will fail to deserialize. **Verified firsthand.** _Action:_ pick one canonical schema
   (update PRD **or** add the missing fields) before L3/verifier work depends on it.

2. **[HIGH · rl] `data_router` absent — pipeline has no specified training-data source.**
   No `data_router` module and no HarmBench/BeaverTails/WildGuardMix references anywhere in
   `src/`. **Verified firsthand** (`find src -name '*data_router*'` and dataset grep both
   empty). _Action:_ implement at least a thin mapper into the 6 DAO leaves before A.3a
   training is meaningful.

3. **[MED · osprey] Deploy is not role-gated.** Spec requires role-gated deploy; only a
   shared API key guards endpoints (`src/osprey_ui/server.py:39`), no per-role check.
   Rule changes ship without an authorization tier. _Action:_ add a role/permission check
   on create/update/install.

4. **[MED · rl] One-sided spike, not two-model co-evolution.** Sheila is frozen
   (`tinker_spike/__init__.py`); the spec's Sheila-GRPO multiplicative loop, alternating
   updates, and reflective replay buffer are absent. _Action:_ scope the Sheila update path
   or explicitly re-classify the current spike as Phase-1 in the spec.

5. **[MED · boundary] Boundary test filename mismatch.** Invariant is enforced and passing,
   but the test is `tests/test_two_agent_boundary.py`, not the spec/CLAUDE.md-cited
   `tests/test_boundary.py` — anyone following the spec path finds it "ABSENT." _Action:_
   add a thin `tests/test_boundary.py` shim or correct the spec/CLAUDE.md reference.
   (Also affects zk med row: `evaluate_with_attestation` end-to-end wiring into Sheila judge
   mode is unverified — worth an integration test in the same pass.)

## Note on spec-vs-repo naming drift (recurring, low individually)

Several LOW gaps share one root cause — the PRD/CLAUDE.md names differ from the shipped
symbols: `PurpleTeam` interface (repo: `SheilaJudge`/`SheilaRedTeam` in
`agents/sheila/api.py`), `test_boundary.py` (repo: `test_two_agent_boundary.py`),
`insurance_defaults.py` (repo: `vertical_defaults.py`), `ScanBenchmark` (repo:
`tinker_spike/evaluate.py`), `R_osprey` (repo: unnamed reward term). None are functional
defects, but together they make a spec-literal reader over-report ABSENT. _Action:_ a single
reconciliation pass on the PRD wording (or thin alias symbols) would clear all of them.

`DECISION: 5 READY / 2 NOT-READY — the two NOT-READY (zk, rl) are In-Progress components each blocked by one HIGH gap (attestation-schema contract mismatch; missing data_router). No Implemented component carries a HIGH gap.`
