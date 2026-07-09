"""
Sheila A2A (Agent-to-Agent) HTTP client.

These classes implement the same interface as SheilaJudgeLocal and
SheilaRedTeamLocal but dispatch over HTTP to a remote Sheila service
(`agents/sheila/a2a_server.py`, typically running in a TEE enclave in Phase 5).

When SHEILA_A2A_URL is set, SheilaJudge / SheilaRedTeam (agents/sheila/api.py)
use these backends instead of the local implementations — zero changes to call
sites. The interface is identical, so Sara never knows whether Sheila is local
or remote.
"""

from typing import List, Literal, Optional

import httpx

_TIMEOUT = 300.0


class SheilaA2AClient:
    """HTTP A2A backend for SheilaJudge — POSTs judge() calls to the enclave.

    `http_client` may be injected (tests / connection reuse); when omitted a
    short-lived AsyncClient is created and closed per call.
    """

    def __init__(self, a2a_url: str, http_client: Optional[httpx.AsyncClient] = None):
        self._url = a2a_url.rstrip("/")
        self._http = http_client

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

    async def _post(self, path: str, payload: dict) -> dict:
        if self._http is not None:
            resp = await self._http.post(f"{self._url}{path}", json=payload, timeout=_TIMEOUT)
            resp.raise_for_status()
            return resp.json()
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(f"{self._url}{path}", json=payload)
            resp.raise_for_status()
            return resp.json()


class SheilaA2ARedTeamClient:
    """HTTP A2A backend for SheilaRedTeam — POSTs run_session() to the enclave."""

    def __init__(self, a2a_url: str, http_client: Optional[httpx.AsyncClient] = None):
        self._url = a2a_url.rstrip("/")
        self._http = http_client

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

    async def _post(self, path: str, payload: dict) -> dict:
        if self._http is not None:
            resp = await self._http.post(f"{self._url}{path}", json=payload, timeout=_TIMEOUT)
            resp.raise_for_status()
            return resp.json()
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(f"{self._url}{path}", json=payload)
            resp.raise_for_status()
            return resp.json()
