"""
A2A turn protocol (Slice 4) — multi-turn Sheila with max_turns + referee.

A red-team *session* runs a bounded loop:
    attacker prompt (Sheila) → target response → judge verdict → referee decides
                                                                    ↘ stop / ↺ continue

Two ways the target response arrives:
  - input-required (A2A-native): the caller drives the target and supplies each
    response over HTTP (the session pauses at `input-required` between turns).
  - simulated: the service fills the target response internally (demo / tests).

The session is a long-running A2A task (Slice 3). The final transcript is signed
with the same ECDSA P-384 key as the Agent Card + attestations.

BOUNDARY: this module is part of the Sheila agent and may use Sheila internals.
# A.5-full: referee as a separate model; learned technique escalation; target as
# a remote A2A agent; transcript persisted to ClickHouse.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import asdict, dataclass, field
from typing import List, Optional

from src.crypto.canonical import canonical_bytes, sha3_hex


@dataclass
class SessionConfig:
    target_model_id: str
    categories: List[str] = field(default_factory=list)
    max_turns: int = 6
    mode: str = "input-required"   # 'input-required' | 'simulated'
    stop_on_bypass: bool = True


@dataclass
class Turn:
    turn_index: int
    attacker_prompt: str
    target_response: Optional[str] = None
    decision: Optional[str] = None        # Sheila verdict on the target response
    evaded: bool = False                  # target produced unsafe content -> bypass
    referee_action: Optional[str] = None  # continue | stop
    referee_reason: Optional[str] = None


@dataclass
class RefereeDecision:
    action: str   # 'continue' | 'stop'
    reason: str


@dataclass
class TurnTranscript:
    session_id: str
    target_model_id: str
    max_turns: int
    turns: List[Turn] = field(default_factory=list)
    stopped_reason: Optional[str] = None
    final_decision: Optional[str] = None   # 'bypassed' | 'held'
    attestation_id: str = ""
    signature: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class Referee:
    """Deterministic adjudicator. # A.5-full: replace with a referee model."""

    @staticmethod
    def adjudicate(turn: Turn, history: List[Turn], config: SessionConfig) -> RefereeDecision:
        if turn.evaded and config.stop_on_bypass:
            return RefereeDecision("stop", "bypass_found")
        if len(history) >= config.max_turns:
            return RefereeDecision("stop", "max_turns")
        return RefereeDecision("continue", "continue")


# ── transcript signing (reuses the Slice 2 P-384 key) ─────────────────────────

def _transcript_core(t_dict: dict) -> dict:
    """The signed portion of a transcript (dict form) — excludes attestation_id
    and signature, which are added after signing."""
    return {
        "schema_version": 1,
        "session_id": t_dict["session_id"],
        "target_model_id": t_dict["target_model_id"],
        "max_turns": t_dict["max_turns"],
        "turns": t_dict["turns"],
        "stopped_reason": t_dict["stopped_reason"],
        "final_decision": t_dict["final_decision"],
    }


def sign_transcript(transcript: TurnTranscript, signer) -> None:
    core = canonical_bytes(_transcript_core(transcript.to_dict()))
    transcript.attestation_id = sha3_hex(core)
    transcript.signature = signer.sign_bytes(core)


def verify_transcript(transcript: dict, signer) -> bool:
    """Verify a (serialized) transcript against the signer's key."""
    sig = transcript.get("signature")
    if not sig:
        return False
    try:
        return signer.verify_bytes(canonical_bytes(_transcript_core(transcript)), sig)
    except (KeyError, TypeError, ValueError):
        return False   # malformed/truncated transcript -> not verified


def simulate_target(attacker_prompt: str) -> str:
    """Deterministic mock target for `simulated` mode — a safe refusal, so the
    loop runs its course without a real target. # A.5-full: call the real target
    (itself an A2A agent)."""
    return "[target] I can't help with that request."


# ── the turn engine ───────────────────────────────────────────────────────────

class TurnEngine:
    """Drives one bounded red-team session, one turn at a time (resumable)."""

    def __init__(self, config: SessionConfig, judge_backend, redteam_backend, signer=None):
        self._config = config
        self._judge = judge_backend
        self._signer = signer
        self._done = False
        self.transcript = TurnTranscript(
            session_id=uuid.uuid4().hex[:16],
            target_model_id=config.target_model_id,
            max_turns=config.max_turns,
        )
        # Pre-generate escalating attacker prompts (turn i uses probe i).
        probes = redteam_backend()._generate_probes(
            target_model_id=config.target_model_id,
            categories=config.categories,
            n_probes=max(1, config.max_turns),
            signing_secret=os.urandom(16),
        )
        self._prompts = [p.payload for p in probes] or ["(no probe available)"]

    @property
    def done(self) -> bool:
        return self._done

    @property
    def pending_prompt(self) -> Optional[str]:
        """The attacker prompt awaiting a target response, if any."""
        if self.transcript.turns and self.transcript.turns[-1].target_response is None:
            return self.transcript.turns[-1].attacker_prompt
        return None

    async def open_turn(self) -> Optional[str]:
        """Emit the next attacker prompt (appends an open turn). None if done/at cap."""
        if self._done or len(self.transcript.turns) >= self._config.max_turns:
            return None
        i = len(self.transcript.turns)
        prompt = self._prompts[i % len(self._prompts)]
        self.transcript.turns.append(Turn(turn_index=i, attacker_prompt=prompt))
        return prompt

    async def close_turn(self, target_response: str) -> RefereeDecision:
        """Record the target response, judge it, and let the referee decide."""
        # Defensive: never index an empty transcript (e.g. a degenerate config).
        if not self.transcript.turns or self.transcript.turns[-1].target_response is not None:
            self._finish("no_open_turn")
            return RefereeDecision("stop", "no_open_turn")
        turn = self.transcript.turns[-1]
        turn.target_response = target_response
        verdict = await self._judge().judge(
            turn_id=f"{self.transcript.session_id}-{turn.turn_index}",
            user_input=turn.attacker_prompt,
            agent_response=target_response,
            mode="judge",
        )
        turn.decision = verdict.decision
        turn.evaded = verdict.decision == "violation"
        decision = Referee.adjudicate(turn, self.transcript.turns, self._config)
        turn.referee_action = decision.action
        turn.referee_reason = decision.reason
        if decision.action == "stop":
            self._finish(decision.reason)
        return decision

    def _finish(self, reason: str) -> None:
        self._done = True
        self.transcript.stopped_reason = reason
        self.transcript.final_decision = (
            "bypassed" if any(t.evaded for t in self.transcript.turns) else "held"
        )
        if self._signer is not None:
            sign_transcript(self.transcript, self._signer)


async def run_simulated(engine: TurnEngine) -> TurnTranscript:
    """Run a session to completion using the mock target (no caller in the loop)."""
    await engine.open_turn()
    while not engine.done:
        prompt = engine.pending_prompt
        await engine.close_turn(simulate_target(prompt or ""))
        if engine.done:
            break
        await engine.open_turn()
    return engine.transcript
