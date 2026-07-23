"""
Shared A2A v0.3.0 protocol primitives (agent-agnostic).

Single source of truth for the A2A *wire contract* used by both Sara and Sheila:
  - Agent Card detached **JWS ES384** signing + verification (JWK in header),
    verifiable by any JOSE library from the card alone.
  - JSON-RPC 2.0 envelope + standard A2A error codes.
  - Task / Artifact / Message serialization helpers.
  - A generic in-memory task store + method dispatcher.

Agent-specific bits (which skills exist, how a Message maps to a backend call)
live in each agent's own module — this file knows nothing about judging,
red-teaming, or classifying. Reference: https://a2a-protocol.org/ (v0.3.0).
"""

from __future__ import annotations

import base64
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional

A2A_PROTOCOL_VERSION = "0.3.0"

# ── JSON-RPC 2.0 + A2A error codes ────────────────────────────────────────────
ERR_PARSE = -32700
ERR_INVALID_REQUEST = -32600
ERR_METHOD_NOT_FOUND = -32601
ERR_INVALID_PARAMS = -32602
ERR_INTERNAL = -32603
# A2A-specific (spec error mapping, -32001..-32099):
ERR_TASK_NOT_FOUND = -32001
ERR_TASK_NOT_CANCELABLE = -32002
ERR_PUSH_NOT_SUPPORTED = -32003
ERR_UNSUPPORTED_OPERATION = -32004
ERR_CONTENT_TYPE_NOT_SUPPORTED = -32005

TERMINAL_STATES = {"completed", "failed", "canceled", "rejected"}
# Methods every conformant server recognises but this build does not implement:
UNSUPPORTED_METHODS = (
    "message/stream",
    "tasks/resubscribe",
    "tasks/pushNotificationConfig/set",
    "tasks/pushNotificationConfig/get",
)


class A2AError(Exception):
    """A JSON-RPC error carrying an A2A error code and optional data."""

    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(v: str) -> bytes:
    return base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))


def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ── Agent Card signing (detached JWS ES384) ───────────────────────────────────

def _public_jwk(signer) -> Optional[dict]:
    """Extract an ES384 (P-384) public JWK from the signer, for JWS verification."""
    try:
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization

        pub = serialization.load_pem_public_key(
            signer.public_key_pem().encode(), backend=default_backend()
        )
        nums = pub.public_numbers()
        return {
            "kty": "EC",
            "crv": "P-384",
            "x": _b64url(nums.x.to_bytes(48, "big")),
            "y": _b64url(nums.y.to_bytes(48, "big")),
            "kid": signer.key_id,
        }
    except Exception:
        return None


def _der_to_jose(der_hex: str, size: int = 48) -> bytes:
    """Convert a DER ECDSA signature (hex) to JOSE raw R||S of `2*size` bytes."""
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    r, s = decode_dss_signature(bytes.fromhex(der_hex))
    return r.to_bytes(size, "big") + s.to_bytes(size, "big")


def _canonical_card_bytes(card_without_sig: dict) -> bytes:
    """Canonical bytes of a card (RFC 8785 JCS via the repo encoder if available)."""
    try:
        from src.crypto.canonical import canonical_bytes

        signable = dict(card_without_sig)
        signable["schema_version"] = 1  # required by canonical_bytes; not part of A2A
        return canonical_bytes(signable)
    except Exception:
        return json.dumps(card_without_sig, sort_keys=True, separators=(",", ":")).encode()


def sign_agent_card(card: dict, signer) -> dict:
    """Attach a detached JWS ES384 signature (spec `signatures[]`) to `card`.

    Standard detached JWS (default b64=true): signing input is
    `b64url(protected) . b64url(payload)`, payload = canonical card bytes. The
    verifier reconstructs the payload from the card, so it is not transmitted.
    Returns the card unchanged if crypto/JWK is unavailable (unsigned cards are
    spec-valid — `signatures` is optional).
    """
    if signer is None:
        return card
    jwk = _public_jwk(signer)
    if jwk is None:
        return card
    payload = _canonical_card_bytes(card)
    protected = {"alg": "ES384", "kid": signer.key_id, "jwk": jwk}
    protected_b64 = _b64url(json.dumps(protected, separators=(",", ":")).encode())
    signing_input = protected_b64.encode("ascii") + b"." + _b64url(payload).encode("ascii")
    try:
        jose_sig = _b64url(_der_to_jose(signer.sign_bytes(signing_input)))
        card["signatures"] = [{"protected": protected_b64, "signature": jose_sig}]
    except Exception:
        pass
    return card


def verify_conformant_card(card: dict) -> bool:
    """Verify a conformant card's detached JWS ES384 signature (JWK in header).

    Self-contained: needs only the card. Returns False if unsigned, tampered, or
    crypto unavailable. Mirrors what a third-party JOSE verifier would do.
    """
    sigs = card.get("signatures")
    if not sigs:
        return False
    try:
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import (
            encode_dss_signature,
        )

        payload = _canonical_card_bytes({k: v for k, v in card.items() if k != "signatures"})
        entry = sigs[0]
        header = json.loads(_b64url_decode(entry["protected"]))
        jwk = header["jwk"]
        pub = ec.EllipticCurvePublicNumbers(
            int.from_bytes(_b64url_decode(jwk["x"]), "big"),
            int.from_bytes(_b64url_decode(jwk["y"]), "big"),
            ec.SECP384R1(),
        ).public_key(default_backend())
        signing_input = entry["protected"].encode("ascii") + b"." + _b64url(payload).encode("ascii")
        raw = _b64url_decode(entry["signature"])
        sig = encode_dss_signature(int.from_bytes(raw[:48], "big"),
                                   int.from_bytes(raw[48:], "big"))
        pub.verify(sig, signing_input, ec.ECDSA(hashes.SHA384()))
        return True
    except Exception:
        return False


# ── Message / Task / Artifact serialization ───────────────────────────────────

def agent_text_message(text: str, context_id: str, task_id: str) -> dict:
    return {
        "role": "agent",
        "messageId": f"msg-{int(time.time()*1000)}",
        "contextId": context_id,
        "taskId": task_id,
        "parts": [{"kind": "text", "text": text}],
        "kind": "message",
    }


def task_object(
    task_id: str,
    context_id: str,
    state: str,
    skill: str,
    *,
    artifact_name: Optional[str] = None,
    artifact_data: Any = None,
    error_text: Optional[str] = None,
    history: Optional[list] = None,
) -> dict:
    """Serialize into a conformant A2A Task object."""
    obj: dict = {
        "id": task_id,
        "contextId": context_id,
        "kind": "task",
        "status": {"state": state, "timestamp": iso_now()},
        "metadata": {"skill": skill},
    }
    if error_text:
        obj["status"]["message"] = agent_text_message(error_text, context_id, task_id)
    if artifact_data is not None:
        obj["artifacts"] = [{
            "artifactId": f"{task_id}-result",
            "name": artifact_name or "result",
            "parts": [{"kind": "data", "data": artifact_data}],
        }]
    if history:
        obj["history"] = history
    return obj


def data_parts(message: dict) -> tuple[dict, bool]:
    """Merge all DataParts of an inbound Message into one dict.

    Returns (merged_data, saw_text_part). Rejects file/raw parts with
    ContentTypeNotSupported. Raises A2AError on a malformed message.
    """
    if not isinstance(message, dict):
        raise A2AError(ERR_INVALID_PARAMS, "params.message must be an object")
    parts = message.get("parts")
    if not isinstance(parts, list) or not parts:
        raise A2AError(ERR_INVALID_PARAMS, "message.parts must be a non-empty array")
    data: dict = {}
    text_seen = False
    for part in parts:
        kind = part.get("kind") or part.get("type")
        if kind == "data":
            payload = part.get("data")
            if isinstance(payload, dict):
                data.update(payload)
        elif kind == "text":
            text_seen = True
        elif kind in ("file", "raw"):
            raise A2AError(ERR_CONTENT_TYPE_NOT_SUPPORTED,
                           "file/raw parts are not supported; use a DataPart")
    return data, text_seen


# ── Generic in-memory task store ──────────────────────────────────────────────

class TaskRecord:
    __slots__ = ("task_id", "skill", "state", "context_id", "result", "error", "history")

    def __init__(self, task_id, skill, state, context_id, history=None):
        self.task_id = task_id
        self.skill = skill
        self.state = state
        self.context_id = context_id
        self.result = None
        self.error = None
        self.history = history

    def to_a2a(self) -> dict:
        return task_object(
            self.task_id, self.context_id, self.state, self.skill,
            artifact_name=f"{self.skill}-result", artifact_data=self.result,
            error_text=self.error, history=self.history,
        )


class InMemoryTaskStore:
    """Minimal in-memory store for conformant Tasks. # A.5-full: persistence."""

    def __init__(self) -> None:
        self._tasks: dict[str, TaskRecord] = {}

    def create(self, skill: str, context_id: str, history=None) -> TaskRecord:
        rec = TaskRecord(uuid.uuid4().hex[:16], skill, "submitted", context_id, history)
        self._tasks[rec.task_id] = rec
        return rec

    def get(self, task_id: str) -> Optional[TaskRecord]:
        return self._tasks.get(task_id)


# ── JSON-RPC dispatch ─────────────────────────────────────────────────────────

Handler = Callable[[dict], Awaitable[dict]]


async def run_jsonrpc(request_obj: Any, method_table: dict[str, Handler]) -> dict:
    """Dispatch one JSON-RPC 2.0 request against `method_table` (method -> async
    handler taking params, returning result). Errors become JSON-RPC error
    objects with A2A codes — never raised. Unknown-but-standard methods return
    UnsupportedOperationError; anything else, MethodNotFound.
    """
    req_id = request_obj.get("id") if isinstance(request_obj, dict) else None
    try:
        if not isinstance(request_obj, dict):
            raise A2AError(ERR_INVALID_REQUEST, "request must be a JSON object")
        if request_obj.get("jsonrpc") != "2.0":
            raise A2AError(ERR_INVALID_REQUEST, "jsonrpc must be '2.0'")
        method = request_obj.get("method")
        params = request_obj.get("params") or {}
        if not isinstance(params, dict):
            raise A2AError(ERR_INVALID_PARAMS, "params must be an object")

        handler = method_table.get(method)
        if handler is None:
            if method in UNSUPPORTED_METHODS:
                raise A2AError(ERR_UNSUPPORTED_OPERATION, f"{method} is not supported")
            raise A2AError(ERR_METHOD_NOT_FOUND, f"method not found: {method}")
        result = await handler(params)
        return {"jsonrpc": "2.0", "id": req_id, "result": result}
    except A2AError as exc:
        err: dict = {"code": exc.code, "message": exc.message}
        if exc.data is not None:
            err["data"] = exc.data
        return {"jsonrpc": "2.0", "id": req_id, "error": err}
    except Exception as exc:  # defensive: never leak a 500 through JSON-RPC
        return {"jsonrpc": "2.0", "id": req_id,
                "error": {"code": ERR_INTERNAL, "message": f"internal error: {exc}"}}
