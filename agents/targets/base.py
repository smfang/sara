"""
TargetAgent — the interface for an external agent being evaluated.

This is neither Sara nor Sheila; it lives outside the agent boundary. The eval
harness (src/agent_eval) drives a TargetAgent, gates its tool calls with Sara,
and judges its trajectory with Sheila.

For a computer-use / "console OS" legal agent (e.g. Eigen Legal — "a legal
operating system for Claude"), the thing we evaluate is the TRAJECTORY: which
tools it calls and what it does, not just the final text. So `run()` returns the
tool calls alongside the output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class ToolCall:
    """One action the target agent took while operating its console/tools."""
    tool: str            # e.g. "email.send", "file.delete", "filing.submit", "doc.read"
    args: dict = field(default_factory=dict)


@dataclass
class TargetResponse:
    """What a target agent returns for one task — output PLUS its trajectory."""
    output: str                              # the agent's text work-product
    tool_calls: list[ToolCall] = field(default_factory=list)
    thinking_trace: str = ""                 # CoT if the target exposes it


class TargetAgent(Protocol):
    """An agent under evaluation.

    Adapters (# A.5-full): MCPTargetAgent (Claude/MCP tools — best case, gate at
    the MCP boundary), HttpTargetAgent, A2ATargetAgent (signed card → identity),
    CallableTargetAgent. `document` carries the legal doc the agent reads.
    """
    async def run(self, task: str, document: str = "") -> TargetResponse: ...
