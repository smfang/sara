"""
Conformant A2A surface for Sheila (PRD v3 §7.6 — real third-party interop).

The rest of `agents/sheila/a2a_*` speaks a *bespoke* HTTP dialect that is fine
for the internal Sara↔Sheila seam but does NOT interoperate with third-party
A2A agents. This module adds a **spec-conformant** surface alongside it
(A2A v0.3.0 — https://a2a-protocol.org/): a conformant signed Agent Card and a
JSON-RPC 2.0 endpoint (`message/send`, `tasks/get`, `tasks/cancel`) exchanging
real Message / Part / Task / Artifact objects.

The wire contract (card signing, JSON-RPC envelope, error codes, Task
serialization) lives in the neutral `src.a2a.protocol` shared library, so Sara
and Sheila speak identical A2A without importing each other. This module keeps
only Sheila's agent-specific mapping: which skills exist and how a Message maps
to a judge / red-team backend call.

BOUNDARY: part of the Sheila agent; MAY import Sheila internals. Sara code
(`src/safety/`, `src/sarabox/`) must NEVER import it.

GDPR: no message/prompt text is logged here.

# A.5-full: streaming (message/stream, SSE), pushNotifications, and did:web key
resolution are advertised as unsupported and left for the hardening pass.
"""

from __future__ import annotations

from src.a2a import protocol as a2a
from src.a2a.protocol import (  # re-exported for existing importers/tests
    A2A_PROTOCOL_VERSION,
    A2AError,
    ERR_CONTENT_TYPE_NOT_SUPPORTED,
    ERR_INVALID_PARAMS,
    ERR_METHOD_NOT_FOUND,
    ERR_TASK_NOT_CANCELABLE,
    ERR_TASK_NOT_FOUND,
    ERR_UNSUPPORTED_OPERATION,
    verify_conformant_card,
)
from agents.sheila.a2a_tasks import TaskStore, TERMINAL, process_task

# ── Sheila's advertised skills ({id,name,description,tags,...}) ────────────────
_SKILLS = [
    {
        "id": "judge",
        "name": "Safety Judge",
        "description": (
            "Evaluate an agent interaction (user input + agent response, optional "
            "tool calls / thinking trace) and return a safety verdict with a "
            "category, confidence and evidence."
        ),
        "tags": ["safety", "moderation", "judge", "evaluation"],
        "inputModes": ["application/json", "text/plain"],
        "outputModes": ["application/json"],
        "examples": [
            'Send a DataPart {"skill":"judge","turn_id":"t1",'
            '"user_input":"...","agent_response":"..."}'
        ],
    },
    {
        "id": "redteam",
        "name": "Adversarial Red-Team",
        "description": (
            "Run adversarial probes against a target model and return a report "
            "with evasion rate and ATLAS coverage."
        ),
        "tags": ["safety", "red-team", "adversarial", "atlas"],
        "inputModes": ["application/json"],
        "outputModes": ["application/json"],
        "examples": [
            'Send a DataPart {"skill":"redteam","target_model_id":"gpt-x",'
            '"categories":["jailbreak"],"n_probes":20}'
        ],
    },
]


def build_conformant_agent_card(base_url: str, signer=None) -> dict:
    """Build an A2A v0.3.0-conformant Agent Card for Sheila (JSON-RPC transport)."""
    base = base_url.rstrip("/")
    rpc_url = f"{base}/a2a/v1"
    card = {
        "protocolVersion": A2A_PROTOCOL_VERSION,
        "name": "sheila",
        "description": (
            "Purple-team red-team + safety judge. Judges agent interactions and "
            "runs adversarial probes against target models."
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
        "skills": [dict(s) for s in _SKILLS],
        "additionalInterfaces": [{"transport": "JSONRPC", "url": rpc_url}],
    }
    return a2a.sign_agent_card(card, signer)


# ── Message → backend invocation ──────────────────────────────────────────────

def _extract_invocation(message: dict) -> tuple[str, dict]:
    """Map an inbound A2A Message to (skill, backend_input) for judge/redteam."""
    data, text_seen = a2a.data_parts(message)
    skill = data.pop("skill", None) or (message.get("metadata") or {}).get("skill")
    if not skill:
        raise A2AError(
            ERR_INVALID_PARAMS,
            'no skill selected: include a DataPart {"skill":"judge"|"redteam", ...} '
            "or metadata.skill" + (" (a lone text part is ambiguous)" if text_seen else ""),
        )
    if skill not in ("judge", "redteam"):
        raise A2AError(ERR_INVALID_PARAMS, f"unknown skill {skill!r}; expected judge|redteam")

    if skill == "judge":
        missing = [f for f in ("turn_id", "user_input", "agent_response")
                   if data.get(f) is None]
        if missing:
            raise A2AError(ERR_INVALID_PARAMS, f"judge requires fields: {missing}")
        backend_input = {
            "turn_id": data["turn_id"],
            "user_input": data["user_input"],
            "agent_response": data["agent_response"],
            "tool_calls": data.get("tool_calls") or [],
            "thinking_trace": data.get("thinking_trace"),
            "categories": data.get("categories"),
            "mode": data.get("mode", "judge"),
        }
    else:  # redteam
        if not data.get("target_model_id"):
            raise A2AError(ERR_INVALID_PARAMS, "redteam requires field: target_model_id")
        backend_input = {
            "target_model_id": data["target_model_id"],
            "categories": data.get("categories") or [],
            "n_probes": int(data.get("n_probes", 50)),
        }
    return skill, backend_input


def _task_to_a2a(task, context_id: str, history=None) -> dict:
    return a2a.task_object(
        task.task_id, context_id, task.state, task.kind,
        artifact_name=f"{task.kind}-result", artifact_data=task.result,
        error_text=task.error, history=history,
    )


async def dispatch_jsonrpc(request_obj, store: TaskStore, judge_backend, redteam_backend) -> dict:
    """Dispatch a JSON-RPC 2.0 request for Sheila (message/send, tasks/get,
    tasks/cancel). Reuses the shared envelope + the Slice-3 TaskStore/backends."""
    import time

    async def _message_send(params: dict) -> dict:
        message = params.get("message")
        if message is None:
            raise A2AError(ERR_INVALID_PARAMS, "params.message is required")
        skill, backend_input = _extract_invocation(message)
        blocking = (params.get("configuration") or {}).get("blocking", True)
        context_id = message.get("contextId") or f"ctx-{int(time.time()*1000)}"
        task = store.create(skill, backend_input)
        history = None
        if message.get("messageId"):
            history = [{**message, "taskId": task.task_id, "kind": "message"}]
        if not blocking:
            import asyncio
            asyncio.create_task(process_task(store, task.task_id, judge_backend, redteam_backend))
            return _task_to_a2a(store.get(task.task_id), context_id, history)
        await process_task(store, task.task_id, judge_backend, redteam_backend)
        return _task_to_a2a(store.get(task.task_id), context_id, history)

    async def _tasks_get(params: dict) -> dict:
        task_id = params.get("id")
        if not task_id:
            raise A2AError(ERR_INVALID_PARAMS, "params.id is required")
        task = store.get(task_id)
        if task is None:
            raise A2AError(ERR_TASK_NOT_FOUND, f"task not found: {task_id}")
        return _task_to_a2a(task, params.get("contextId") or "ctx")

    async def _tasks_cancel(params: dict) -> dict:
        task_id = params.get("id")
        if not task_id:
            raise A2AError(ERR_INVALID_PARAMS, "params.id is required")
        task = store.get(task_id)
        if task is None:
            raise A2AError(ERR_TASK_NOT_FOUND, f"task not found: {task_id}")
        if task.state in TERMINAL:
            raise A2AError(ERR_TASK_NOT_CANCELABLE,
                           f"task {task_id} is in terminal state {task.state!r}")
        store.cancel(task_id)
        return _task_to_a2a(store.get(task_id), params.get("contextId") or "ctx")

    method_table = {
        "message/send": _message_send,
        "tasks/get": _tasks_get,
        "tasks/cancel": _tasks_cancel,
    }
    return await a2a.run_jsonrpc(request_obj, method_table)
