# Spec Review — crt (Collaborative Red Teaming)

_Read-only review against PRD v3 §7. Spec status: Later-Stage (interfaces + coverage map only). Location: `src/crt/`._

**Summary (3 lines)**
- All five models exist and the type-level privacy invariant holds: `CoverageMap` has no org identity, `record_coverage` has no org param, and public coverage is stored without `org_id` (attribution kept in a separate private table).
- Coordinator lifecycle, credits, diversity score, and a canonical-JSON `report_hash` are implemented; heavy crypto is stubbed with `# A.5-full:` markers as specified.
- `src/crt/test_crt_mvp.py` and `tests/test_crt_server.py` pass.

| Requirement | Status | Evidence (file:line) | Gap | Severity |
|---|---|---|---|---|
| Models: OrgProfile, CRTCampaign, OrgSubmission, CoverageMap, CRTReport | PRESENT | `src/crt/models.py:25,35,48,60,79` | — | — |
| **Privacy: `CoverageMap` has NO org identity field** | PRESENT | `src/crt/models.py:60-66` (class + invariant note; `org_id` fields belong to OrgProfile:28 / OrgSubmission:53 only) | — | — |
| `record_coverage(campaign_id, tag, score)` — no org param | PRESENT | `src/crt/aggregator.py:23`, `src/crt/store.py:56` | — | — |
| `crt.leaf_coverage` table has no `org_id` column | PRESENT | `src/crt/store.py:20,54` (public coverage, no org_id); attribution isolated `:25,67-70` | Store is in-memory; ClickHouse `leaf_coverage` deferred (`store.py:5` A.5-full) | low |
| `GET /crt/campaigns/{id}/coverage` returns CoverageMap only | PRESENT | `src/crt/server.py:123-130` (returns coverage + diversity, no org identity) | — | — |
| Coordinator create/enrol/submit/confirm/finalise; `min_orgs=3` | PRESENT | `coordinator.py:30,45,100,126,172`; `min_orgs: int = 3` at `:34` | — | — |
| Credits `score*10 + (5 first-cover)` | PRESENT | `coordinator.py:161-163` (`amount = score * 10 + (5.0 if first_cover else 0.0)`) | — | — |
| `diversity_score = distinct org_types / 4` | PRESENT | `aggregator.py:61` (`diversity_score`); `cli.py:124` ("distinct org types / 4") | Backed by in-memory type counts; MPC path deferred (`aggregator.py:8`) | low |
| `report_hash = SHA3-256(canonical JSON of public fields)` | PRESENT | `report.py:23-38` (public dict, NO org_id, `digest()` RFC 8785 JCS); test `test_crt_mvp.py:290` (64-hex) | — | — |
| A.5-full stubs: `share_gradient_update`, `mpc_severity_distribution` | PARTIAL | `# A.5-full:` markers at `coordinator.py:181`, `store.py:5,70`, `server.py:8`, `aggregator.py:8` | Named stubs `share_gradient_update()`/`mpc_severity_distribution()` not found by name | low |

**Gaps (severity-ranked)**
1. **low — named federated stubs absent.** The spec calls out `share_gradient_update()` and `mpc_severity_distribution()`; `# A.5-full:` markers exist but not those exact stubs. _Action:_ add the two named no-op stubs so the future interface is pinned, or drop them from the spec.
2. **low — persistence deferred.** Coverage/attribution are in-memory; ClickHouse `crt.leaf_coverage` is A.5-full. Consistent with Later-Stage status. _Action:_ none now; track for A.5.

`DECISION: READY (privacy invariant enforced type-level and tested; lifecycle/credits/report_hash complete; only named stubs + deferred persistence outstanding, consistent with Later-Stage scope)`
