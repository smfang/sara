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
- **Slice 5 — Conformant A2A (third-party interop)** ✅ (`agents/sheila/a2a_conformant.py`).
  Real A2A **v0.3.0** surface alongside the bespoke one — an off-the-shelf A2A
  client interoperates with no Sheila SDK. Conformant Agent Card at
  `/.well-known/agent-card.json` (object `capabilities`, `protocolVersion`,
  `defaultInput/OutputModes`, `skills[]`, `preferredTransport=JSONRPC`), signed
  with a detached **JWS ES384** verifiable from the embedded JWK by any JOSE lib.
  **JSON-RPC 2.0** at `POST /a2a/v1`: `message/send` (Message/Part→Task+Artifact),
  `tasks/get`, `tasks/cancel`, with standard A2A error codes. Reuses the Slice-3
  `TaskStore`/`process_task`, so judge/redteam run the same backend. The bespoke
  card moved to `/.well-known/agent-card.legacy.json`. Tests: `test_a2a_conformant.py`.
  Not yet conformant: `message/stream` (SSE), `pushNotifications`, did:web key
  resolution — advertised as unsupported (`capabilities.streaming=false`) and
  returned as `UnsupportedOperationError`, not faked.
- **Slice 6 — Sara as an A2A agent** ✅ (`src/sarabox/a2a.py`, CLI `sara-a2a`).
  Sara (the classifier) is now a conformant A2A agent too, closing the roadmap's
  "Sara as an A2A agent" item. Signed Agent Card advertising a `classify` skill;
  JSON-RPC `message/send` maps a `Message` → `SaraBoxClassifier.classify()`,
  returning the `ClassificationResult` as a Task Artifact; `tasks/get`/`tasks/cancel`.
  Runs standalone against a default taxonomy (`uv run main.py sara-a2a`) — no org
  provisioning / ClickHouse; org-scoped, credit-metered classification stays on
  the bespoke `/sarabox/*` REST API. Tests: `tests/test_sara_a2a.py`.
- **Shared protocol library** ✅ (`src/a2a/protocol.py`). The A2A *wire contract*
  (JWS ES384 card signing/verify, JSON-RPC envelope + error codes, Task/Artifact
  serialization, dispatcher) is now a NEUTRAL shared lib both agents import.
  Respects the boundary invariant: Sara imports `src.a2a`, never `agents.sheila`
  (asserted by `tests/test_sara_a2a.py::test_sara_a2a_does_not_import_sheila`).
  Sheila's `a2a_conformant.py` was refactored onto it — single source of truth
  for the crypto; all prior tests still green.

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
