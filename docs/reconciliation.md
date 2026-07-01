# Sara/Sheila — A.0 Reconciliation Report

**Branch:** `main` | **Repo:** `smfang/sara` | **Date:** 2026-06-17  
**Purpose:** Audit prompt-suite assumptions against repo reality before launching the CRT spike (A.5-MVP).

---

## Phase 1 — Assumption → Reality Table

| # | Assumption | Status | Evidence Path | Gap | CRT Impact |
|---|-----------|--------|---------------|-----|------------|
| 1 | Two-agent split: Sara (classifier) + Sheila (red-team judge) | **PRESENT** | `agents/sheila/` (6 files), `src/crypto/attesting_agent.py` wraps `SheilaJudge` | A.1 rename completed this session | None — use Sheila only as display string in MVP |
| 2 | `agents/sheila/` package | **PRESENT** | `agents/sheila/{config,judge,red_team,api,a2a_client}.py` | None | Real `SheilaJudge` available as A.5-full seam |
| 3 | `src/arena/` economy (bounties, submissions, evaluations, payouts) | **PRESENT** | `src/arena/{models,scorer,server,store,taxonomy,context}.py`; 9 ClickHouse tables | None | CRT can optionally record sessions as arena submissions |
| 4 | `src/sarabox/taxonomy.py::DAO_TAXONOMY` (6 leaves) | **PRESENT** | `src/sarabox/taxonomy.py` lines 11–end; leaf IDs match spec exactly | None | Import directly — no local copy needed |
| 5 | DAO leaf IDs: `identity_access_probing`, `treasury_manipulation`, `governance_red_flags`, `social_engineering`, `smart_contract_exploitation`, `information_hazards` | **PRESENT** | `src/sarabox/taxonomy.py` — all 6 present in this exact order | None | Import for CRT taxonomy; share with DAO fine-tuning seed (identical IDs) |
| 6 | `src/crypto/canonical.py` (RFC 8785 JCS, SHA3-256 single source) | **PRESENT** | Built in A.2-lite; `sha3_hex`, `digest`, `canonical_bytes`, `ReproducibilityBundle` | None | Use `digest()` for `CRTReport.report_hash` |
| 7 | `ReproducibilityBundle` + `bundle_hash` + `run_manifest` | **PRESENT** | `src/crypto/reproducibility.py`, `src/crypto/run_manifest.py` | None | Wire as A.5-full seam |
| 8 | ERC-8004 (on-chain attestation standard) | **PARTIAL** | Referenced in `src/crypto/attesting_agent.py`, `src/crypto/attestation.py`, `admin.html`, `sara_default_v1.yaml`; publisher is injected interface, no live contract | No deployed contract | CRT: skip — log `erc8004_tx_hash = ""` for now |
| 9 | x402 (USDC micro-payments) | **PRESENT** | `src/x402/` (client + wallet), `src/config.py` x402 fields, `src/arena/scorer.py` wires `X402Client` | Dev wallet only in dev mode | CRT MVP: no payments needed; seam documented |
| 10 | `ScoringConfig` with α/β/γ/δ weights | **PRESENT** | `src/arena/scorer.py:ScoringConfig(alpha, beta, gamma, delta, payout_rate)` | None | CRT can reuse formula or mock; use mock for MVP |
| 11 | `SafetyClassifier` | **PRESENT** | `src/safety/classifier.py` (imported by scorer); also `src/sarabox/classifier.py` | None | CRT MVP: mock — real classifier as A.5-full seam |
| 12 | ClickHouse `sara_interactions` table | **PARTIAL** | DDL in `src/agent_rl/ARCHITECTURE.md`; `InteractionStore` in `src/learning/layer1_logging.py`; `layer4_finetune.py` queries it | No `CREATE TABLE` in Python DDL (only MD doc) | CRT uses in-memory store for MVP |
| 13 | Osprey SML rule engine | **PRESENT** | `src/osprey/{osprey,policy,sml_reference,udfs}.py`; `src/osprey_ui/` (compiler, DAO defaults, vertical_defaults, Policy UI); Kafka adapter | None | CRT: read Osprey org rules to pick attack categories; seam documented |
| 14 | `AttestingAgent` | **PRESENT** | `src/crypto/attesting_agent.py` — wraps `SheilaJudge`, chains L1+L2 commitment | None | A.5-full seam |
| 15 | `src/rl_training/` (RL pipeline) | **ABSENT** (name) | RL code lives in `src/agent_rl/` (ARCHITECTURE.md + 4 layers) and `src/learning/` (layer1_logging, local_rl_trainer, orchestrator, playbook_engine) | Directory name differs; content present | CRT: no dependency |
| 16 | `src/crt/` (collaborative red-teaming package) | **ABSENT — greenfield** | `find src/crt` → not found | Full greenfield build required | This is the spike target |

---

## Phase 2a — PRD "Implemented" Claim Audit

The commit message on `main` (`b262dc8`) claims Sara v1.0 with "two-agent (Sara classifier + Sheila red team judge), ZK audit trail: SHA3-256 L1 + ECDSA P-384 L2." Status by component:

| Claim | Reality |
|-------|---------|
| Sara classifier | PRESENT — `src/safety/classifier.py`, `src/sarabox/classifier.py` |
| Sheila red team judge | PRESENT — `agents/sheila/judge.py`, `agents/sheila/red_team.py`, `agents/sheila/api.py` |
| SHA3-256 L1 ZK trail | PRESENT — `src/crypto/canonical.py` + `src/crypto/commitment.py` |
| ECDSA P-384 L2 | PRESENT (interface) — `src/crypto/attestation.py:AttestationSigner`; key management is injected, not hardcoded |
| Arena economy (bounties / payouts) | PRESENT — `src/arena/` full stack, ClickHouse DDL, x402 wiring |
| Osprey SML rule engine + Policy UI | PRESENT — `src/osprey/` + `src/osprey_ui/` + Kafka adapter + vertical packs |
| RL pipeline | PRESENT (renamed) — `src/agent_rl/` + `src/learning/`; not in `src/rl_training/` |
| Collaborative red-teaming (CRT / A.5) | **ABSENT** — greenfield; this doc green-lights the spike |

---

## Phase 2b — CRT Spike Readiness Decision

### What the MVP must NOT depend on

The spike stays **standalone** and in-memory. It must not block on:
- A live Sheila API (mock eval only)
- ClickHouse (in-memory store)
- x402 / ERC-8004 (no payments in MVP)
- The A.1 rename (already done) — Sheila is a display string

### Taxonomy source of truth

`src/sarabox/taxonomy.py::DAO_TAXONOMY` **exists** and has the 6 correct leaf IDs. Import it directly in `src/crt/`:

```python
from src.sarabox.taxonomy import DAO_TAXONOMY
```

Both the CRT coverage map and the DAO fine-tuning seed set (`dao_gold_seed.jsonl`) share these same IDs — no divergence possible.

### Canonical encoder

`src/crypto/canonical.py` **exists** (A.2-lite). Use `digest()` for `CRTReport.report_hash` directly:

```python
from src.crypto.canonical import digest
```

No second serializer needed.

### Files to create in `src/crt/`

| File | Responsibility |
|------|---------------|
| `__init__.py` | Package marker |
| `models.py` | `CRTSession`, `CRTRound`, `AttackEntry`, `CRTReport` dataclasses |
| `coordinator.py` | Orchestrates rounds: pick leaves → generate attacks → call eval → record |
| `aggregator.py` | Produces per-leaf coverage summary and gap list |
| `store.py` | In-memory `CRTStore` (dict-backed); `# A.5-full: swap for ClickHouse arena.crt_sessions` |
| `mock_eval.py` | `MockEvaluator` — deterministic stub; `# A.5-full: replace with AttestingAgent.evaluate_with_attestation()` |
| `report.py` | `build_report()` → `CRTReport`; `report_hash = digest(report.to_dict())` via `src.crypto.canonical` |
| `cli.py` | `python -m src.crt run --org-id <id> --rounds <n>` |

Test file: `tests/test_crt_mvp.py`

### Integration seams (documented, not built)

```python
# A.5-full: replace MockEvaluator with:
#   from src.crypto.attesting_agent import AttestingAgent
#   from agents.sheila.api import SheilaJudge
#   verdict = await attesting_agent.evaluate_with_attestation(...)

# A.5-full: replace in-memory store with:
#   ArenaStore ClickHouse tables (arena.bounties / arena.submissions)

# A.5-full: read org Osprey rules to weight attack leaf selection:
#   from src.osprey.policy import PolicyEngine
#   weak_leaves = await policy_engine.get_coverage_gaps(org_id)

# A.5-full: wire CRTReport hash to ERC-8004 attestation publisher
```

---

## Phase 2c — Go / No-Go

**DECISION: GO ✓**

All hard dependencies for the standalone MVP are present:
- `src/sarabox/taxonomy.py` — DAO_TAXONOMY ✓
- `src/crypto/canonical.py` — digest() ✓  
- `agents/sheila/` — display name + future eval seam ✓
- No live database, payments, or contract required ✓

### Ordered steps to run the CRT spike

```bash
# 1. Build the package (all in src/crt/)
#    Create: __init__.py, models.py, coordinator.py, aggregator.py,
#            store.py, mock_eval.py, report.py, cli.py

# 2. Add tests
#    Create: tests/test_crt_mvp.py

# 3. Run the test suite
.venv/bin/python -m pytest tests/test_crt_mvp.py -v --tb=short

# 4. Smoke-test the CLI
.venv/bin/python -m src.crt run --org-id demo-dao-001 --rounds 3

# 5. Verify full suite still green
.venv/bin/python -m pytest tests/ -q --tb=short 2>&1 | tail -5

# 6. Confirm leaf IDs match fine-tuning seed:
python3 -c "
from src.sarabox.taxonomy import DAO_TAXONOMY
from src.crt.aggregator import LEAF_IDS
assert [l['id'] for l in DAO_TAXONOMY] == LEAF_IDS, 'leaf ID mismatch'
print('OK — leaf IDs aligned')
"
```

### What comes next (after GO)

- **Track A (CRT spike):** `src/crt/` as described above.
- **Track B (DAO fine-tuning seed):** `data/dao_gold_seed.jsonl` — share the 6 leaf IDs from `DAO_TAXONOMY` so coverage maps never diverge.
- **Both tracks run in parallel.** First sync point: Step 6 above confirms IDs are aligned.
