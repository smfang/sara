# Spec Review — a2a (Multi-Agent Interoperability)

_Read-only review against PRD v3 §7. Spec status: Additive / net-new (future Phase 5)._

**Summary (3 lines)**
- The `PurpleTeam`-style seam is in place: `agents/sheila/api.py` exposes local `SheilaJudge`/`SheilaRedTeam`, and `agents/sheila/a2a_client.py` mirrors that interface for a future remote enclave — so Sheila is extractable to a service behind the A2A endpoint.
- Everything else is stubbed or absent: no signed Agent Card, no DID/ERC-8004 binding, no A2A task lifecycle, no turn protocol (`max_turns`/referee); `a2a_client` methods raise `NotImplementedError`.
- Consistent with the "additive / Phase 5" status — nothing here blocks current work.

| Requirement | Status | Evidence (file:line) | Gap | Severity |
|---|---|---|---|---|
| Signed Agent Card per agent; card→DID→ERC-8004; reuse x402 | ABSENT | no `AgentCard`/`agent_card`/DID symbols in `agents/`; `src/x402/` exists but unlinked to cards | Not implemented (Phase 5) | med |
| A2A task lifecycle (submitted/working/input-required/completed/failed); 1 eval = 1 task | ABSENT | no lifecycle states found | Not implemented | med |
| MCP for tools; A2A agent↔agent; turn protocol (`max_turns` + referee) | ABSENT | no `max_turns`/`referee` symbols | Multi-turn Sheila protocol not built | low |
| Sheila extractable to FastAPI service behind A2A endpoint (PurpleTeam seam) | PARTIAL | `agents/sheila/api.py:38,79` (local impls); `agents/sheila/a2a_client.py:15-40` (HTTP client, same signature, raises `NotImplementedError`); `SHEILA_A2A_URL` switch `src/config.py:121` | Seam + client shell present; remote impl and the FastAPI service itself are Phase-5 TODO | low |

**Gaps (severity-ranked)**
1. **med — Agent Card + DID/ERC-8004 binding absent.** Core of A2A identity. _Action:_ defer to Phase 5 per spec; no action now unless prioritized.
2. **med — task lifecycle absent.** _Action:_ define the task-state enum + one-eval-one-task mapping when A2A work starts.
3. **low — turn protocol / remote impl.** _Action:_ Phase-5; the interface seam already isolates call sites, so this is low-risk to add later.

`DECISION: READY (for its Additive/Phase-5 status — the extraction seam exists; all functional A2A features are intentionally deferred)`
