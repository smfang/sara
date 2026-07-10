"""
Sheila A2A (Agent-to-Agent) HTTP client.

Implements the same interface as SheilaJudgeLocal / SheilaRedTeamLocal but
dispatches over HTTP to a remote Sheila service (`agents/sheila/a2a_server.py`).

When SHEILA_A2A_URL is set, SheilaJudge / SheilaRedTeam (agents/sheila/api.py)
use these backends instead of the local ones — zero changes to call sites, so
Sara never knows whether Sheila is local or remote.

Two call styles:
  - synchronous:  .judge(...) / .run_session(...)  (Slice 1)
  - task-based:   .submit_task / .get_task / .cancel_task / .run_task  (Slice 3)
"""

import asyncio
from typing import List, Literal, Optional

import httpx

_TIMEOUT = 300.0


class _A2ABase:
    """Shared HTTP dispatch + A2A task lifecycle helpers.

    `http_client` may be injected (tests / connection reuse); when omitted a
    short-lived AsyncClient is created and closed per call.
    """

    def __init__(self, a2a_url: str, http_client: Optional[httpx.AsyncClient] = None):
        self._url = a2a_url.rstrip("/")
        self._http = http_client

    async def _post(self, path: str, payload: dict) -> dict:
        if self._http is not None:
            resp = await self._http.post(f"{self._url}{path}", json=payload, timeout=_TIMEOUT)
            resp.raise_for_status()
            return resp.json()
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(f"{self._url}{path}", json=payload)
            resp.raise_for_status()
            return resp.json()

    async def _get(self, path: str) -> dict:
        if self._http is not None:
            resp = await self._http.get(f"{self._url}{path}", timeout=_TIMEOUT)
            resp.raise_for_status()
            return resp.json()
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(f"{self._url}{path}")
            resp.raise_for_status()
            return resp.json()

    # ── A2A task lifecycle (Slice 3) ─────────────────────────────────────────
    async def submit_task(self, kind: str, task_input: dict) -> str:
        """Create a task (one evaluation = one task); returns its task_id."""
        data = await self._post("/tasks", {"kind": kind, "input": task_input})
        return data["task_id"]

    async def get_task(self, task_id: str) -> dict:
        return await self._get(f"/tasks/{task_id}")

    async def cancel_task(self, task_id: str) -> dict:
        return await self._post(f"/tasks/{task_id}/cancel", {})

    async def run_task(self, kind: str, task_input: dict,
                       poll_interval: float = 0.1, timeout: float = _TIMEOUT) -> dict:
        """Submit a task and poll until a terminal state; returns the final task."""
        task_id = await self.submit_task(kind, task_input)
        waited = 0.0
        while True:
            task = await self.get_task(task_id)
            if task["state"] in ("completed", "failed", "canceled"):
                return task
            if waited >= timeout:
                return task
            await asyncio.sleep(poll_interval)
            waited += poll_interval

    # ── A2A turn protocol (Slice 4) ──────────────────────────────────────────
    async def submit_turn_session(self, config: dict) -> str:
        """Start a multi-turn red-team session; returns its task_id."""
        data = await self._post("/tasks", {"kind": "turn_session", "input": config})
        return data["task_id"]

    async def provide_turn_input(self, task_id: str, target_response: str) -> dict:
        """Supply the target's response for the pending turn; returns the task."""
        return await self._post(f"/tasks/{task_id}/input", {"target_response": target_response})

    async def run_turn_session(self, config: dict, target_caller,
                               poll_interval: float = 0.1, timeout: float = _TIMEOUT) -> dict:
        """Drive a full input-required session: for each pending attacker prompt,
        call `target_caller(prompt)` (async → target response) and feed it back.
        Returns the terminal task (its result holds the signed transcript)."""
        task_id = await self.submit_turn_session(config)
        waited = 0.0
        while True:
            task = await self.get_task(task_id)
            state = task["state"]
            if state in ("completed", "failed", "canceled"):
                return task
            if state == "input-required":
                prompt = (task.get("result") or {}).get("pending_prompt")
                response = await target_caller(prompt)
                await self.provide_turn_input(task_id, response)
                continue
            if waited >= timeout:
                return task
            await asyncio.sleep(poll_interval)
            waited += poll_interval


class SheilaA2AClient(_A2ABase):
    """HTTP A2A backend for SheilaJudge — POSTs judge() calls to the enclave."""

    async def judge(
        self,
        turn_id: str,
        user_input: str,
        agent_response: str,
        tool_calls: list = None,
        thinking_trace: str = None,
        categories: List[str] = None,
        mode: Literal["judge", "redteam", "admin"] = "judge",
    ):
        payload = {
            "turn_id": turn_id,
            "user_input": user_input,
            "agent_response": agent_response,
            "tool_calls": tool_calls or [],
            "thinking_trace": thinking_trace,
            "categories": categories,
            "mode": mode,
        }
        data = await self._post("/judge", payload)
        from agents.sheila.api import SheilaVerdict
        return SheilaVerdict(**data)


class SheilaA2ARedTeamClient(_A2ABase):
    """HTTP A2A backend for SheilaRedTeam — POSTs run_session() to the enclave."""

    async def run_session(
        self,
        target_model_id: str,
        categories: List[str],
        n_probes: int = 50,
        signing_secret: bytes = None,
    ):
        # signing_secret is bytes and is NEVER sent over the wire — the remote
        # service generates its own per session.
        payload = {
            "target_model_id": target_model_id,
            "categories": categories,
            "n_probes": n_probes,
        }
        data = await self._post("/redteam/session", payload)
        from agents.sheila.api import RedTeamReport
        return RedTeamReport(**data)
