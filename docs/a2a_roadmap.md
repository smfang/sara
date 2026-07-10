# A2A Framework — Build Roadmap

Concrete, incremental plan for Sheila's Agent-to-Agent framework, grounded in
PRD v3 §7.6. Supersedes the read-only assessment in `docs/review_a2a.md` with
buildable steps. The `PurpleTeam` interface (`agents/sheila/api.py`) is the seam;
Sara never learns whether Sheila is local or remote.

## Done
- **Slice 1 — Transport** ✅ (`agents/sheila/a2a_server.py`, `a2a_client.py`).
  Sheila runs as a Starlette service; `SHEILA_A2A_URL` routes `judge`/`redteam`
  over HTTP. `uv run main.py sheila-a2a`.
- **Slice 2 — Signed identity** ✅ (`agents/sheila/agent_card.py`).
  P-384-signed Agent Card at `/.well-known/agent-card.json` + `did:web` doc at
  `/.well-known/did.json`. `card → did:web → ERC-8004` (stub) + x402 seam.
- **Slice 3 — Task lifecycle** ✅ (`agents/sheila/a2a_tasks.py`).
  `submitted → working → completed/failed/canceled`; one eval = one task;
  `POST /tasks`, `GET /tasks/{id}`, `POST /tasks/{id}/cancel`; submit+poll client.
- **Slice 4 — Turn protocol** ✅ (`agents/sheila/a2a_turns.py`).
  Multi-turn sessions with `max_turns` + a referee (stops on bypass / at cap).
  Two modes: `input-required` (caller drives the target via `POST /tasks/{id}/input`)
  and `simulated`. Signed transcript (same P-384 key). Client `run_turn_session`.

## Outstanding — stub completions (`# A.5-full:` markers in done slices)
- Real ERC-8004 registration → fill `card.erc8004.tx_hash` (reuse `src/crypto/attesting_agent.py`).
- Real x402-gated `/judge` (402 + settle via `src/x402/`), not just advertised.
- Key management / TEE — private key never leaves the enclave (currently env/ephemeral).
- Persistence — task store + transcripts to ClickHouse.

## Outstanding — cross-cutting hardening
- Auth/authz on the service (verify caller's Agent Card signature; only authorized agents invoke Sheila).
- Streaming (SSE) for long red-team runs.
- Agent discovery/registry (how peers find Sheila's card/DID; pairs with ERC-8004).
- Sara as an A2A agent too (publishes a signed card, speaks A2A) — full agent↔agent interop.
- Version negotiation + standardized error envelope (`protocol: a2a/0.1` handshake).
- Explicit MCP-for-tools / A2A-for-agents boundary guard (test).

## Dependency order
```
Slice 3 (tasks) ──► Slice 4 (turns)
      └─► ERC-8004 + x402 completion, auth, streaming (any order after tasks)
```
Slices 3→4 are the PRD-required functional remainder; the rest makes it production-grade.
