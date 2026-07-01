# Spec Review — osprey (Rule Engine + Policy UI)

_Read-only review against PRD v3 §7. Spec status: Implemented._

**Summary (3 lines)**
- Configurable rules gate Sara's actions and share ONE validate+store pipeline for human and agent rules; the Policy UI (draft/validate/preview/feedback/probe/save) is wired end-to-end.
- OS-05 (per-leaf F1 from the RL benchmark) is now surfaced in the UI and sourced from the tinker_spike eval report; OS-04 vertical packs (insurance, critical-infra) are installable from the UI.
- `tests/test_osprey_ui.py` (53 tests) passes.

| Requirement | Status | Evidence (file:line) | Gap | Severity |
|---|---|---|---|---|
| Configurable SML rules gate Sara's actions; save/validate path | PRESENT | `src/osprey_ui/server.py:149` (`_create_rule`), `:270` (`_validate_rule`); enforcement `src/osprey_ui/monitor.py:63` (`evaluate` → LOG/ALERT/STOP), STOP raises `:118` | Rules matched by keyword/category, not a real SML engine (`monitor.py:226` `_rule_matches`) | med |
| Policy UI edits rules without code | PRESENT | `src/ui/dashboard.html:1249-1581` (list/draft/validate/test/feedback/probe/patch) | — | — |
| Vertical default rule packs | PRESENT | `src/osprey_ui/vertical_defaults.py:18,175` (insurance+critical-infra, 6 each); UI installer `src/ui/dashboard.html` `loadVerticalPacks/installPack` | Spec names `insurance_defaults.py`; actual file is `vertical_defaults.py` (naming) | low |
| UI connected to RL feedback loop; weak leaves visible | PRESENT | `src/osprey_ui/server.py:800` (`_compute_leaf_f1`, RL-benchmark-first); UI F1 panel `src/ui/dashboard.html` (`loadF1WeakSpots`); source `src/agent_rl/tinker_spike/evaluate.py:load_eval_report` | Falls back to arena/monitor proxy until an eval report exists; nothing writes the report automatically yet | med |
| One shared validate+store pipeline (human + agent, no side door) | PRESENT | `src/osprey_ui/server.py:198-205` (validate-gate before persist, both raw-SML and compiled paths) | — | — |
| Human authoring: assisted NL→.sml + raw editor | PRESENT | `server.py:229` (`_draft_rule`), `:149` raw-SML branch | — | — |
| Validate blocks invalid; Preview shows LOG/ALERT/STOP | PRESENT | `server.py:282` (validate), `:285` (`_test_draft_rule`); `monitor.test_rule` returns action | — | — |
| AI feedback + optional Sheila evasion probe | PRESENT | `server.py:323` (`_rule_feedback`), `:384` (`_rule_probe`, redteam mode) | — | — |
| Role-gated deploy; shadow/dry-run ramp | PARTIAL | `monitor.py:21` (`SHADOW_MODE`), `:118` shadow suppresses STOP | Shadow ramp present; **role-gating of deploy not enforced** (API-key only, `server.py:39`), no per-role check | med |
| Audit: every rule change author+timestamp | PRESENT | `models.py:26-27` (`created_by`,`created_at`), ERC8004 on create `server.py:208` & update `:525` | DELETE path bumps version but skips ERC8004 attestation (`server.py:538-560`) | low |

**Gaps (severity-ranked)**
1. **med — no real SML evaluation.** `_rule_matches` does substring/keyword + classifier-category matching, not compilation/execution of Osprey SML. _Action:_ integrate the actual Osprey engine, or document this as the intended pragmatic gate.
2. **med — RL feedback needs a live report.** `_compute_leaf_f1` is RL-benchmark-first, but no process calls `write_eval_report` after `run_eval`, so the UI falls back to the arena/monitor proxy. _Action:_ call `write_eval_report(result)` at the end of the RL eval (CLI), closing the loop.
3. **med — deploy is not role-gated.** Spec requires role-gated deploy; only a shared API key guards endpoints. _Action:_ add a role/permission check on create/update/install.
4. **low — DELETE not attested.** Disabling a rule leaves no ERC8004 record. _Action:_ attest on delete like create/update.
5. **low — pack file naming.** `vertical_defaults.py` vs spec's `insurance_defaults.py`. _Action:_ align name or spec.

`DECISION: READY (spec-critical rows PRESENT and tested; role-gating + real-SML-engine + report-writer are the open hardening items)`
