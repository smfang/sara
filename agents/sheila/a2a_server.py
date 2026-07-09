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

    async def _agent_card(request: Request) -> Response:
        return JSONResponse(card)

    async def _did_json(request: Request) -> Response:
        return JSONResponse(did_doc)

    return Starlette(routes=[
        Route("/.well-known/agent-card.json", _agent_card, methods=["GET"]),
        Route("/.well-known/did.json", _did_json, methods=["GET"]),
        Route("/health", _health, methods=["GET"]),
        Route("/judge", _judge, methods=["POST"]),
        Route("/redteam/session", _redteam_session, methods=["POST"]),
    ])
