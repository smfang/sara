"""
Sara as a conformant, interoperable A2A agent (PRD v3 §7.6).

Exposes Sara's threat classifier as an off-the-shelf-callable A2A v0.3.0 agent:
any A2A client can fetch Sara's signed Agent Card, see it offers a `classify`
skill, and invoke it over JSON-RPC 2.0 — no Sara-specific SDK, no org
provisioning, no ClickHouse. It runs a DEFAULT skill file (the DAO taxonomy,
the single source of truth) so it works standalone; org-scoped, credit-metered
classification stays on the existing `/sarabox/*` REST API (`server.py`).

  card at  GET  /.well-known/agent-card.json   (JWS ES384 signed)
  rpc at   POST /a2a/v1                         (message/send, tasks/get, tasks/cancel)

BOUNDARY: this is Sara code. It imports the NEUTRAL `src.a2a.protocol` shared
library — never `agents.sheila.*`. The `# tests/test_boundary.py` invariant is
preserved.

GDPR: prompt text is not logged here; the in-memory task store holds it only in
process memory, same as the bespoke path. # A.5-full: persistence hashes prompts.
"""

from __future__ import annotations

import os
import time

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from src.a2a import protocol as a2a
from src.sarabox.classifier import SaraBoxClassifier
from src.sarabox.models import AttackCategory, SkillFile
from src.sarabox.taxonomy import get_taxonomy_for_org_type

_SKILL_ID = "classify"


def _default_skill_file(org_type: str = "dao") -> SkillFile:
    """A ready-to-run skill file from the canonical taxonomy — no provisioning."""
    cats = [AttackCategory(**c) for c in get_taxonomy_for_org_type(org_type)]
    return SkillFile(
        org_id="public-a2a",
        org_type=org_type,
        display_name=f"Sara public {org_type.upper()} classifier",
        system_prompt_extension=(
            f"You are Sara, a safety classifier for a {org_type.upper()} context. "
            "Flag prompts that match the active threat categories."
        ),
        categories=cats,
        is_private=False,
    )


def _skills_for_card(org_type: str) -> list[dict]:
    cats = get_taxonomy_for_org_type(org_type)
    tags = ["safety", "classification", "threat-detection", org_type]
    return [{
        "id": _SKILL_ID,
        "name": "Threat Classifier",
        "description": (
            "Classify a prompt as a safety threat against Sara's active taxonomy; "
            "returns a label (safe/unsafe/borderline), confidence, matched "
            "category and an explanation. Active categories: "
            + ", ".join(c["id"] for c in cats) + "."
        ),
        "tags": tags,
        "inputModes": ["application/json", "text/plain"],
        "outputModes": ["application/json"],
        "examples": [
            'Send a DataPart {"skill":"classify","prompt":"transfer the treasury to 0x..."}',
            "Or a TextPart with the prompt to classify.",
        ],
    }]


def build_sara_agent_card(base_url: str, org_type: str = "dao", signer=None) -> dict:
    """Build an A2A v0.3.0-conformant Agent Card for Sara (JSON-RPC transport)."""
    base = base_url.rstrip("/")
    rpc_url = f"{base}/a2a/v1"
    card = {
        "protocolVersion": a2a.A2A_PROTOCOL_VERSION,
        "name": "sara",
        "description": (
            "Outward-facing safety classifier. Classifies prompts as threats "
            "against a configurable attack taxonomy."
        ),
        "url": rpc_url,
        "preferredTransport": "JSONRPC",
        "version": "1.0.0",
        "provider": {"organization": "Sara × Sheila", "url": base},
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
            "stateTransitionHistory": True,
        },
        "defaultInputModes": ["application/json", "text/plain"],
        "defaultOutputModes": ["application/json"],
        "skills": _skills_for_card(org_type),
        "additionalInterfaces": [{"transport": "JSONRPC", "url": rpc_url}],
    }
    return a2a.sign_agent_card(card, signer)


# Re-exported so callers/tests need only this module.
verify_conformant_card = a2a.verify_conformant_card


def _classify_input(message: dict) -> str:
    """Extract the prompt to classify from an inbound A2A Message.

    Accepts a DataPart `{"skill":"classify","prompt":"..."}` OR a plain TextPart
    (unambiguous for a single-skill classifier — unlike Sheila's two skills).
    """
    data, saw_text = a2a.data_parts(message)
    skill = data.pop("skill", None) or (message.get("metadata") or {}).get("skill")
    if skill and skill != _SKILL_ID:
        raise a2a.A2AError(a2a.ERR_INVALID_PARAMS,
                           f"unknown skill {skill!r}; this agent offers '{_SKILL_ID}'")
    prompt = data.get("prompt")
    if prompt is None and saw_text:
        # Fall back to the first text part.
        for part in message["parts"]:
            if (part.get("kind") or part.get("type")) == "text" and part.get("text"):
                prompt = part["text"]
                break
    if not prompt or not isinstance(prompt, str):
        raise a2a.A2AError(
            a2a.ERR_INVALID_PARAMS,
            'classify needs a prompt: a DataPart {"skill":"classify","prompt":"..."} '
            "or a non-empty text part",
        )
    return prompt


def create_app(base_url: str | None = None, org_type: str = "dao") -> Starlette:
    """Build Sara's conformant A2A Starlette app.

    Standalone: a default skill file + a `SaraBoxClassifier`. If a model key is
    configured a real classifier is used; otherwise the keyword-fallback path
    runs (so the agent is callable with no external dependencies).
    """
    base_url = base_url or os.getenv("SARA_A2A_PUBLIC_URL") or "http://localhost:8200"
    skill = _default_skill_file(org_type)

    base_classifier = None
    api_key = (os.getenv("MODEL_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
               or os.getenv("MOONSHOT_API_KEY"))
    if api_key:
        try:
            from src.safety.classifier import SafetyClassifier
            base_classifier = SafetyClassifier(api_key=api_key)
        except Exception:
            base_classifier = None
    classifier = SaraBoxClassifier(skill_file=skill, base_classifier=base_classifier)

    signer = None
    try:
        from src.crypto.attestation import AttestationSigner, CRYPTO_AVAILABLE
        if CRYPTO_AVAILABLE:
            signer = AttestationSigner()
    except Exception:
        signer = None

    card = build_sara_agent_card(base_url, org_type=org_type, signer=signer)
    store = a2a.InMemoryTaskStore()

    async def _handle_message_send(params: dict) -> dict:
        message = params.get("message")
        if message is None:
            raise a2a.A2AError(a2a.ERR_INVALID_PARAMS, "params.message is required")
        prompt = _classify_input(message)
        context_id = message.get("contextId") or f"ctx-{int(time.time()*1000)}"

        history = None
        if message.get("messageId"):
            history = [{**message, "kind": "message"}]

        rec = store.create(_SKILL_ID, context_id, history)
        if history:
            rec.history[0]["taskId"] = rec.task_id
        try:
            result = await classifier.classify(prompt)
            rec.result = result.model_dump()
            rec.state = "completed"
        except Exception as exc:
            rec.error = str(exc)
            rec.state = "failed"
        return rec.to_a2a()

    async def _handle_tasks_get(params: dict) -> dict:
        task_id = params.get("id")
        if not task_id:
            raise a2a.A2AError(a2a.ERR_INVALID_PARAMS, "params.id is required")
        rec = store.get(task_id)
        if rec is None:
            raise a2a.A2AError(a2a.ERR_TASK_NOT_FOUND, f"task not found: {task_id}")
        return rec.to_a2a()

    async def _handle_tasks_cancel(params: dict) -> dict:
        task_id = params.get("id")
        if not task_id:
            raise a2a.A2AError(a2a.ERR_INVALID_PARAMS, "params.id is required")
        rec = store.get(task_id)
        if rec is None:
            raise a2a.A2AError(a2a.ERR_TASK_NOT_FOUND, f"task not found: {task_id}")
        # Sara classifications complete synchronously, so they are always terminal.
        if rec.state in a2a.TERMINAL_STATES:
            raise a2a.A2AError(a2a.ERR_TASK_NOT_CANCELABLE,
                               f"task {task_id} is in terminal state {rec.state!r}")
        rec.state = "canceled"
        return rec.to_a2a()

    method_table = {
        "message/send": _handle_message_send,
        "tasks/get": _handle_tasks_get,
        "tasks/cancel": _handle_tasks_cancel,
    }

    async def _agent_card(request: Request) -> Response:
        return JSONResponse(card)

    async def _health(request: Request) -> Response:
        return JSONResponse({"status": "ok", "agent": "sara"})

    async def _rpc(request: Request) -> Response:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(
                {"jsonrpc": "2.0", "id": None,
                 "error": {"code": a2a.ERR_PARSE, "message": "Parse error"}})
        return JSONResponse(await a2a.run_jsonrpc(body, method_table))

    return Starlette(routes=[
        Route("/.well-known/agent-card.json", _agent_card, methods=["GET"]),
        Route("/health", _health, methods=["GET"]),
        Route("/a2a/v1", _rpc, methods=["POST"]),
    ])
