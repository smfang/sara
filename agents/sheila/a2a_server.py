"""
Sheila A2A service — the remote enclave endpoint.

A Starlette app that exposes the LOCAL Sheila agent (judge + red-team) over HTTP,
so `SheilaA2AClient` / `SheilaA2ARedTeamClient` can dispatch to it. This is the
"Sheila extractable to a FastAPI service behind the A2A endpoint" piece: the
PurpleTeam interface (`agents/sheila/api.py`) is the seam, and this module is the
service on the far side of it.

BOUNDARY: this module is part of the Sheila agent and MAY import Sheila
internals. Sara code (`src/safety/`, `src/sarabox/`) must NEVER import it.

Run it:  uv run main.py sheila-a2a --port 8100
Point at it:  SHEILA_A2A_URL=http://localhost:8100 uv run main.py arena
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import asdict

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

logger = logging.getLogger("sheila.a2a_server")

# Lazy singletons so the (LLM-backed) local agents are built once, not per request.
_JUDGE = None
_REDTEAM = None


def _judge_backend():
    global _JUDGE
    if _JUDGE is None:
        from agents.sheila.judge import SheilaJudgeLocal
        _JUDGE = SheilaJudgeLocal()
    return _JUDGE


def _redteam_backend():
    global _REDTEAM
    if _REDTEAM is None:
        from agents.sheila.red_team import SheilaRedTeamLocal
        _REDTEAM = SheilaRedTeamLocal()
    return _REDTEAM


async def _health(request: Request) -> Response:
    return JSONResponse({"status": "ok", "agent": "sheila"})


async def _judge(request: Request) -> Response:
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)

    turn_id = body.get("turn_id")
    user_input = body.get("user_input")
    agent_response = body.get("agent_response")
    if not turn_id or user_input is None or agent_response is None:
        return JSONResponse(
            {"error": "turn_id, user_input, and agent_response are required"},
            status_code=400,
        )

    verdict = await _judge_backend().judge(
        turn_id=turn_id,
        user_input=user_input,
        agent_response=agent_response,
        tool_calls=body.get("tool_calls") or [],
        thinking_trace=body.get("thinking_trace"),
        categories=body.get("categories"),
        mode=body.get("mode", "judge"),
    )
    return JSONResponse(asdict(verdict))


async def _redteam_session(request: Request) -> Response:
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)

    target_model_id = body.get("target_model_id")
    if not target_model_id:
        return JSONResponse({"error": "target_model_id is required"}, status_code=400)

    # signing_secret is bytes (never serialised over the wire) — the service
    # generates its own per session inside run_session when None.
    report = await _redteam_backend().run_session(
        target_model_id=target_model_id,
        categories=body.get("categories") or [],
        n_probes=int(body.get("n_probes", 50)),
    )
    return JSONResponse(asdict(report))


def create_app(base_url: str | None = None) -> Starlette:
    """Build the Sheila A2A Starlette app (used by the CLI and by tests).

    `base_url` (or SHEILA_A2A_PUBLIC_URL) is the service's public URL — it fixes
    the did:web identifier and the card's endpoints. The signed card + DID
    document are built once here (one P-384 key shared with attestations).
    """
    base_url = base_url or os.getenv("SHEILA_A2A_PUBLIC_URL") or "http://localhost:8100"

    from agents.sheila.agent_card import build_agent_card, build_did_document
    signer = None
    try:
        from src.crypto.attestation import AttestationSigner, CRYPTO_AVAILABLE
        if CRYPTO_AVAILABLE:
            signer = AttestationSigner()  # one key for card + did doc
    except Exception as exc:
        logger.warning("Agent card unsigned — signer unavailable (%s)", exc)

    card = build_agent_card(base_url, signer=signer)
    did_doc = build_did_document(base_url, signer=signer)

    # Conformant A2A v0.3.0 card — this is what third-party A2A clients fetch at
    # the well-known path. The bespoke card is retained at a `.legacy.json` path.
    from agents.sheila.a2a_conformant import (
        build_conformant_agent_card,
        dispatch_jsonrpc,
    )
    conformant_card = build_conformant_agent_card(base_url, signer=signer)

    async def _agent_card(request: Request) -> Response:
        return JSONResponse(conformant_card)

    async def _legacy_agent_card(request: Request) -> Response:
        return JSONResponse(card)

    async def _did_json(request: Request) -> Response:
        return JSONResponse(did_doc)

    # ── A2A task lifecycle (Slice 3) — one evaluation = one task ──────────────
    from agents.sheila.a2a_tasks import TaskStore, TaskState, process_task, VALID_KINDS
    from agents.sheila.a2a_turns import SessionConfig, TurnEngine, run_simulated
    store = TaskStore()
    # Hold strong refs to in-flight background tasks so the event loop can't GC
    # them mid-run (asyncio.create_task keeps only a weak ref otherwise).
    bg_tasks: set = set()
    # Live turn-session engines (Slice 4), keyed by task_id — in-process state
    # for the resumable input-required loop. `session_locks` serialises the
    # check-state → close_turn → open_turn → update sequence so concurrent
    # /input calls for the same task can't corrupt the (signed) transcript.
    sessions: dict = {}
    session_locks: dict = {}

    def _session_result(engine) -> dict:
        """Serializable session view: the transcript + the prompt awaiting input."""
        result = engine.transcript.to_dict()
        result["pending_prompt"] = engine.pending_prompt
        return result

    _REQUIRED = {
        "judge": ("turn_id", "user_input", "agent_response"),
        "redteam": ("target_model_id",),
    }

    async def _create_task(request: Request) -> Response:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON"}, status_code=400)
        kind = body.get("kind")
        task_input = body.get("input") or {}

        # ── Slice 4: multi-turn red-team session ──────────────────────────────
        if kind == "turn_session":
            if not task_input.get("target_model_id"):
                return JSONResponse({"error": "input.target_model_id is required"}, status_code=400)
            try:
                max_turns = int(task_input.get("max_turns", 6))
            except (TypeError, ValueError):
                max_turns = 0
            if max_turns < 1:
                return JSONResponse({"error": "max_turns must be >= 1"}, status_code=400)
            config = SessionConfig(
                target_model_id=task_input["target_model_id"],
                categories=task_input.get("categories") or [],
                max_turns=max_turns,
                mode=task_input.get("mode", "input-required"),
                stop_on_bypass=bool(task_input.get("stop_on_bypass", True)),
            )
            try:
                engine = TurnEngine(config, _judge_backend, _redteam_backend, signer=signer)
            except Exception as exc:
                return JSONResponse({"error": f"could not start session: {exc}"}, status_code=500)
            task = store.create(kind, task_input)
            sessions[task.task_id] = engine

            if config.mode == "simulated":
                async def _run_sim(tid=task.task_id, eng=engine):
                    store.update(tid, state=TaskState.working.value)
                    await run_simulated(eng)
                    store.update(tid, state=TaskState.completed.value, result=_session_result(eng))
                bg = asyncio.create_task(_run_sim())
                bg_tasks.add(bg); bg.add_done_callback(bg_tasks.discard)
                return JSONResponse({"task_id": task.task_id, "state": TaskState.working.value}, status_code=202)

            # input-required: emit the first attacker prompt and pause
            await engine.open_turn()
            store.update(task.task_id, state=TaskState.input_required.value, result=_session_result(engine))
            return JSONResponse({
                "task_id": task.task_id,
                "state": TaskState.input_required.value,
                "pending_prompt": engine.pending_prompt,
            }, status_code=202)

        if kind not in VALID_KINDS:
            return JSONResponse({"error": f"kind must be one of {sorted(VALID_KINDS)}"}, status_code=400)
        missing = [f for f in _REQUIRED[kind] if not task_input.get(f) and task_input.get(f) != ""]
        if missing:
            return JSONResponse({"error": f"input missing required fields: {missing}"}, status_code=400)

        # Normalise optional args the local backends require positionally, so the
        # task path matches the synchronous endpoints' defaults.
        if kind == "redteam":
            task_input.setdefault("categories", [])
            task_input.setdefault("n_probes", 50)

        task = store.create(kind, task_input)
        bg = asyncio.create_task(
            process_task(store, task.task_id, _judge_backend, _redteam_backend)
        )
        bg_tasks.add(bg)
        bg.add_done_callback(bg_tasks.discard)
        return JSONResponse({"task_id": task.task_id, "state": task.state}, status_code=202)

    async def _get_task(request: Request) -> Response:
        task = store.get(request.path_params["task_id"])
        if task is None:
            return JSONResponse({"error": "task not found"}, status_code=404)
        return JSONResponse(task.to_dict())

    async def _cancel_task(request: Request) -> Response:
        task = store.cancel(request.path_params["task_id"])
        if task is None:
            return JSONResponse({"error": "task not found"}, status_code=404)
        return JSONResponse({"task_id": task.task_id, "state": task.state})

    async def _task_input(request: Request) -> Response:
        """Supply the target's response for a turn session's pending turn (Slice 4)."""
        task_id = request.path_params["task_id"]
        task = store.get(task_id)
        if task is None:
            return JSONResponse({"error": "task not found"}, status_code=404)
        if task.state != TaskState.input_required.value:
            return JSONResponse(
                {"error": f"task not awaiting input (state={task.state})"}, status_code=409)
        engine = sessions.get(task_id)
        if engine is None:
            return JSONResponse({"error": "session state lost"}, status_code=410)
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON"}, status_code=400)
        target_response = body.get("target_response")
        if target_response is None:
            return JSONResponse({"error": "target_response is required"}, status_code=400)

        # Serialise the whole advance so two concurrent /input calls for the same
        # pending turn can't both close+open it (which would corrupt the transcript).
        lock = session_locks.setdefault(task_id, asyncio.Lock())
        async with lock:
            task = store.get(task_id)
            if task is None or task.state != TaskState.input_required.value:
                return JSONResponse(
                    {"error": f"task not awaiting input (state={task.state if task else 'gone'})"},
                    status_code=409)
            await engine.close_turn(target_response)
            if not engine.done:
                await engine.open_turn()
            new_state = TaskState.completed.value if engine.done else TaskState.input_required.value
            store.update(task_id, state=new_state, result=_session_result(engine))
        return JSONResponse({"task_id": task_id, "state": new_state,
                             "pending_prompt": engine.pending_prompt})

    async def _a2a_jsonrpc(request: Request) -> Response:
        """Conformant A2A JSON-RPC 2.0 endpoint (message/send, tasks/get,
        tasks/cancel). Reuses the same TaskStore + backends as the bespoke path."""
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(
                {"jsonrpc": "2.0", "id": None,
                 "error": {"code": -32700, "message": "Parse error"}},
                status_code=200,
            )
        response = await dispatch_jsonrpc(body, store, _judge_backend, _redteam_backend)
        return JSONResponse(response)

    return Starlette(routes=[
        Route("/.well-known/agent-card.json", _agent_card, methods=["GET"]),
        Route("/.well-known/agent-card.legacy.json", _legacy_agent_card, methods=["GET"]),
        Route("/.well-known/did.json", _did_json, methods=["GET"]),
        Route("/health", _health, methods=["GET"]),
        Route("/a2a/v1", _a2a_jsonrpc, methods=["POST"]),
        Route("/judge", _judge, methods=["POST"]),
        Route("/redteam/session", _redteam_session, methods=["POST"]),
        Route("/tasks", _create_task, methods=["POST"]),
        Route("/tasks/{task_id}", _get_task, methods=["GET"]),
        Route("/tasks/{task_id}/cancel", _cancel_task, methods=["POST"]),
        Route("/tasks/{task_id}/input", _task_input, methods=["POST"]),
    ])
